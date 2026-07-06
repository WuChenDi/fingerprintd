//! Passive network-signal extraction (PRD §4.2 / §4.4 / §6).
//!
//! Client-reported `components` are forgeable: a headless browser can self-report
//! any `userAgent` it likes. This module derives the signals a client **cannot**
//! self-report — the real network IP (via `CF-Connecting-IP`) and the TLS
//! JA3/JA4 stack (via an edge-injected header) — and cross-checks the TLS stack
//! against the JS/UA-claimed browser. The result feeds `/identify` **confidence
//! only**, never the `visitorId` (JA4 is low-entropy and forgeable, PRD §4.2).
//!
//! Three shapes of outcome, mirroring the confidence fusion T7 applies (§6):
//! - [`TlsConsistency::Consistent`] — UA and TLS stack agree → small boost.
//! - [`TlsConsistency::Mismatch`] — Chrome UA over a Python/Go TLS stack → strong
//!   downgrade (the core anti-forgery signal, §4.2).
//! - [`TlsConsistency::Degraded`] — no JA3/JA4 available (Bot Management absent,
//!   or an unparseable value) → neutral, neither boost nor penalty. This is the
//!   mandated **auto-degrade** path: a missing connection-layer signal must not
//!   block or penalise the request (§4.2).
//!
//! **Trust boundary (PRD §4.2 security requirement):** the JA4 header is trusted
//! only when injected by the Cloudflare edge; the origin must strip any
//! client-supplied copy before this module runs. Enforcing that strip is handler
//! /edge wiring (T7); this module only parses whatever trusted headers it is given.
//!
//! **Scope caveats:** headers here are mocked. Real JA4 needs Cloudflare Bot
//! Management (may be absent → degrade), and the [`IpIntel`] static classifier is
//! a coarse illustrative placeholder — a production deployment swaps it for a real
//! ASN / proxy / reputation feed (see [`StaticIpIntel`]). No real-data detection
//! rate is claimed here.

use std::net::{IpAddr, Ipv4Addr};

use axum::http::HeaderMap;

/// Trusted request header carrying the real client IP, injected by the Cloudflare
/// edge. Standard Cloudflare header (PRD §4.2).
pub const CF_CONNECTING_IP: &str = "cf-connecting-ip";

/// Trusted request header carrying the client TLS JA4 fingerprint, injected by
/// the Cloudflare edge (Bot Management → Transform Rule). The origin MUST strip
/// any client-supplied copy and trust only the edge-injected value (PRD §4.2);
/// that strip is wired at the handler/edge layer (T7), not here.
pub const JA4_HEADER: &str = "cf-bot-management-ja4";

/// Minimum cipher count in a JA4 fingerprint for the stack to read as a real
/// browser. Browsers advertise a broad cipher list; minimal automation stacks
/// (curl/python/go defaults) advertise few. Coarse structural heuristic, not a
/// fingerprint database (see [`classify_ja4`]).
const BROWSER_MIN_CIPHERS: u32 = 10;
/// Minimum TLS extension count in a JA4 fingerprint for a real-browser read.
/// Browsers carry GREASE + ALPN + `key_share` + `supported_versions` + … ;
/// automation stacks carry far fewer.
const BROWSER_MIN_EXTENSIONS: u32 = 10;

/// Confidence boost when the UA claim and the observed TLS stack agree — a small
/// positive nudge toward "real browser" (design §6, "一致 → 加成").
const CONSISTENT_BOOST: f64 = 0.05;
/// Confidence penalty when the UA claim contradicts the observed TLS stack — the
/// strong anti-forgery downgrade (design §6 / PRD §4.2, "不一致 → 大幅下调").
const MISMATCH_PENALTY: f64 = 0.5;

/// Coarse IP reputation band surfaced to downstream risk consumers (PRD §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRisk {
    /// Residential / unknown / internal address — no adverse signal.
    Low,
    /// Ambiguous (shared proxy / mixed-use range). Reserved for real feeds; the
    /// static classifier never emits it.
    Medium,
    /// Datacenter / hosting space — a real browser rarely originates here.
    High,
}

impl IpRisk {
    /// Stable wire label for the response body (`"low"|"medium"|"high"`).
    pub fn as_str(self) -> &'static str {
        match self {
            IpRisk::Low => "low",
            IpRisk::Medium => "medium",
            IpRisk::High => "high",
        }
    }
}

/// Verdict of cross-checking the JS/UA-claimed browser against the passively
/// observed TLS (JA3/JA4) stack (PRD §4.2 / §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsConsistency {
    /// UA and TLS stack agree — a plausibly real browser (confidence boost).
    Consistent,
    /// UA claims one stack, the TLS fingerprint reveals another (e.g. a Chrome
    /// UA riding a Python/Go TLS stack) — strong anomaly (confidence downgrade).
    Mismatch,
    /// No usable JA3/JA4 (Bot Management absent or the value is unparseable) —
    /// connection layer degraded; neither boost nor penalty (auto-degrade, §4.2).
    Degraded,
}

impl TlsConsistency {
    /// Stable wire label for logging / diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            TlsConsistency::Consistent => "consistent",
            TlsConsistency::Mismatch => "mismatch",
            TlsConsistency::Degraded => "degraded",
        }
    }

    /// The boolean `ua_tls_consistent` flag for the response body (PRD §5).
    ///
    /// Only an outright [`Mismatch`] flags as inconsistent; a [`Degraded`] read
    /// carries no evidence of forgery, so it reports consistent-by-default and
    /// must not be treated as a red flag (§4.2 auto-degrade).
    ///
    /// [`Mismatch`]: TlsConsistency::Mismatch
    /// [`Degraded`]: TlsConsistency::Degraded
    pub fn ua_tls_consistent(self) -> bool {
        !matches!(self, TlsConsistency::Mismatch)
    }
}

/// The passive signals extracted for one request (PRD §5 `signals`), fed to the
/// confidence fusion (§6) — never to the `visitorId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassiveSignals {
    /// Coarse IP reputation band.
    pub ip_risk: IpRisk,
    /// UA-vs-TLS-stack cross-check verdict.
    pub tls_consistency: TlsConsistency,
}

impl PassiveSignals {
    /// The passive-signal confidence adjustment fused into `/identify` confidence
    /// (design §6). The caller adds this to the engine's base confidence and
    /// clamps to `[0, 1]`; positive boosts, negative downgrades.
    ///
    /// Only the UA-vs-TLS consistency verdict moves confidence: agreement gives a
    /// small [`CONSISTENT_BOOST`], an outright [`TlsConsistency::Mismatch`] gives
    /// the strong [`MISMATCH_PENALTY`] downgrade (the anti-forgery core, PRD §4.2),
    /// and a [`TlsConsistency::Degraded`] read is neutral — a missing connection
    /// signal never penalises (auto-degrade, §4.2). The [`IpRisk`] band is
    /// auxiliary and surfaced to downstream risk consumers (§5), not folded into
    /// confidence.
    pub fn confidence_adjustment(self) -> f64 {
        match self.tls_consistency {
            TlsConsistency::Consistent => CONSISTENT_BOOST,
            TlsConsistency::Mismatch => -MISMATCH_PENALTY,
            TlsConsistency::Degraded => 0.0,
        }
    }
}

/// Coarse client-stack family, inferred independently from a UA string and from a
/// JA4 fingerprint; the two are compared to detect forgery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientStack {
    /// Looks like a real interactive browser.
    Browser,
    /// Looks like an automation / scripting HTTP stack (curl/python/go/…).
    Automation,
    /// Not classifiable from the available evidence.
    Unknown,
}

/// IP reputation lookup: maps a real client IP to a coarse [`IpRisk`] band.
///
/// The passive IP signal is auxiliary, not decisive (PRD §4.2). Implementations
/// are the seam for a real ASN / proxy / reputation feed; [`StaticIpIntel`] is the
/// dependency-free placeholder.
pub trait IpIntel: Send + Sync {
    /// Classify one client IP into its reputation band.
    fn assess(&self, ip: IpAddr) -> IpRisk;
}

/// Static, dependency-free [`IpIntel`] — flags a small built-in set of datacenter
/// IPv4 ranges as [`IpRisk::High`] and treats everything else (including all IPv6)
/// as [`IpRisk::Low`].
///
/// The built-in ranges are **illustrative**, not authoritative; a real deployment
/// replaces this with an ASN / proxy reputation feed. (future TODO — real feed.)
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticIpIntel;

impl StaticIpIntel {
    /// Construct the static classifier.
    pub fn new() -> Self {
        Self
    }
}

/// `(network, prefix_len)` IPv4 CIDR blocks the static classifier treats as
/// datacenter / hosting space. Coarse and illustrative (see [`StaticIpIntel`]).
const DATACENTER_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(34, 0, 0, 0), 8),   // Google Cloud
    (Ipv4Addr::new(35, 0, 0, 0), 8),   // Google Cloud
    (Ipv4Addr::new(52, 0, 0, 0), 8),   // AWS
    (Ipv4Addr::new(13, 64, 0, 0), 11), // Azure
];

impl IpIntel for StaticIpIntel {
    fn assess(&self, ip: IpAddr) -> IpRisk {
        match ip {
            IpAddr::V4(v4) => {
                // Internal / non-routable space is not a hosting signal.
                if v4.is_loopback() || v4.is_private() || v4.is_link_local() {
                    return IpRisk::Low;
                }
                if DATACENTER_V4
                    .iter()
                    .any(|&(net, prefix)| ipv4_in_block(v4, net, prefix))
                {
                    IpRisk::High
                } else {
                    IpRisk::Low
                }
            }
            // No IPv6 datacenter table yet; a real feed covers both families.
            IpAddr::V6(_) => IpRisk::Low,
        }
    }
}

/// Extract the passive signals for a request from its trusted headers.
///
/// - IP band: `CF-Connecting-IP` → [`IpIntel::assess`]; a missing/unparseable IP
///   defaults to [`IpRisk::Low`] (no adverse evidence).
/// - TLS consistency: the JA4 header is classified and cross-checked against
///   `claimed_ua` (the JS/UA-reported user agent). A missing or unparseable JA4
///   yields [`TlsConsistency::Degraded`] — the auto-degrade path (§4.2).
///
/// `claimed_ua` is the client-reported UA (from `stable_components` / the HTTP
/// `User-Agent`); it is the value under suspicion, cross-checked against the
/// unforgeable TLS stack.
pub fn extract(
    headers: &HeaderMap,
    claimed_ua: Option<&str>,
    intel: &dyn IpIntel,
) -> PassiveSignals {
    let ip_risk = client_ip(headers).map_or(IpRisk::Low, |ip| intel.assess(ip));

    let tls_consistency = match header_str(headers, JA4_HEADER) {
        Some(ja4) => consistency(claimed_ua.map(classify_ua), classify_ja4(ja4)),
        None => TlsConsistency::Degraded, // Bot Management absent → auto-degrade.
    };

    PassiveSignals {
        ip_risk,
        tls_consistency,
    }
}

/// Parse the real client IP from the trusted `CF-Connecting-IP` header.
fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    header_str(headers, CF_CONNECTING_IP)?.trim().parse().ok()
}

/// Borrow one header's value as a trimmed `&str`, or `None` if absent or non-ASCII.
fn header_str<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers.get(name)?.to_str().ok().map(str::trim)
}

/// Reconcile the UA-claimed stack against the TLS-observed stack (§4.2 / §6).
///
/// An unclassifiable TLS stack degrades (no basis to cross-check). Otherwise a
/// **contradiction** between a browser claim and an automation stack (either
/// direction) is a mismatch; anything else — including a missing/unknown UA claim
/// — is consistent, so a degraded UA never manufactures a penalty.
fn consistency(claimed: Option<ClientStack>, observed: ClientStack) -> TlsConsistency {
    match observed {
        ClientStack::Unknown => TlsConsistency::Degraded,
        ClientStack::Browser => match claimed {
            Some(ClientStack::Automation) => TlsConsistency::Mismatch,
            _ => TlsConsistency::Consistent,
        },
        ClientStack::Automation => match claimed {
            Some(ClientStack::Browser) => TlsConsistency::Mismatch,
            _ => TlsConsistency::Consistent,
        },
    }
}

/// Classify a UA string into a coarse [`ClientStack`] by token markers.
///
/// Automation markers win over browser markers, so a bare `curl/8.0` reads as
/// automation while a spoofed `Mozilla/5.0 … Chrome/120` reads as a browser claim
/// (the value the TLS stack then contradicts on a mismatch).
fn classify_ua(ua: &str) -> ClientStack {
    /// Automation / scripting HTTP client markers.
    const AUTOMATION: &[&str] = &[
        "curl",
        "wget",
        "python",
        "go-http",
        "java",
        "okhttp",
        "libwww",
        "node-fetch",
        "axios",
    ];
    /// Real-browser markers.
    const BROWSER: &[&str] = &["mozilla", "chrome", "firefox", "safari", "edg", "opera"];

    let ua = ua.to_ascii_lowercase();
    if AUTOMATION.iter().any(|m| ua.contains(m)) {
        ClientStack::Automation
    } else if BROWSER.iter().any(|m| ua.contains(m)) {
        ClientStack::Browser
    } else {
        ClientStack::Unknown
    }
}

/// Classify a JA4 fingerprint into a coarse [`ClientStack`] from its structure.
///
/// The `JA4_a` prefix (before the first `_`) encodes, at fixed offsets:
/// `protocol(1) tls_version(2) sni(1) cipher_count(2) extension_count(2)
/// alpn(2)`. A real browser advertises many ciphers and extensions; a minimal
/// automation stack advertises few. We read the two 2-digit counts and threshold
/// them ([`BROWSER_MIN_CIPHERS`] / [`BROWSER_MIN_EXTENSIONS`]).
///
/// This is a coarse structural heuristic, **not** a JA4→client fingerprint
/// database; a malformed or too-short prefix reads as [`ClientStack::Unknown`]
/// (→ degrade). (future TODO — real JA4 fingerprint database.)
fn classify_ja4(ja4: &str) -> ClientStack {
    let a = ja4.split('_').next().unwrap_or(ja4);
    let ciphers = a.get(4..6).and_then(|s| s.parse::<u32>().ok());
    let extensions = a.get(6..8).and_then(|s| s.parse::<u32>().ok());
    match (ciphers, extensions) {
        (Some(c), Some(e)) if c >= BROWSER_MIN_CIPHERS && e >= BROWSER_MIN_EXTENSIONS => {
            ClientStack::Browser
        }
        (Some(_), Some(_)) => ClientStack::Automation,
        _ => ClientStack::Unknown,
    }
}

/// Whether IPv4 `ip` falls in the CIDR block `net/prefix`.
fn ipv4_in_block(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

#[cfg(test)]
mod tests {
    use super::{
        CF_CONNECTING_IP, ClientStack, IpIntel, IpRisk, JA4_HEADER, PassiveSignals, StaticIpIntel,
        TlsConsistency, classify_ja4, extract,
    };
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    /// A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext).
    const BROWSER_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    /// A JA4 whose structural counts read as a minimal automation stack (3/4).
    const AUTOMATION_JA4: &str = "t13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb";
    /// A spoofed browser UA (headless automation self-reporting Chrome).
    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";

    /// Build a header map from `(name, value)` pairs.
    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
            map.insert(name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn static_intel_flags_datacenter_high_and_residential_low() {
        let intel = StaticIpIntel::new();
        // 34.0.0.0/8 is in the built-in datacenter set.
        assert_eq!(intel.assess("34.120.5.6".parse().unwrap()), IpRisk::High);
        // TEST-NET-2, outside every datacenter block.
        assert_eq!(intel.assess("198.51.100.7".parse().unwrap()), IpRisk::Low);
        // Private / loopback are internal, never a hosting signal.
        assert_eq!(intel.assess("10.1.2.3".parse().unwrap()), IpRisk::Low);
        assert_eq!(intel.assess("127.0.0.1".parse().unwrap()), IpRisk::Low);
        // IPv6 has no table yet → low.
        assert_eq!(intel.assess("2001:db8::1".parse().unwrap()), IpRisk::Low);
    }

    #[test]
    fn cf_connecting_ip_drives_the_ip_band() {
        let intel = StaticIpIntel::new();
        let hdrs = headers(&[(CF_CONNECTING_IP, "34.120.5.6"), (JA4_HEADER, BROWSER_JA4)]);
        let sig = extract(&hdrs, Some(CHROME_UA), &intel);
        assert_eq!(sig.ip_risk, IpRisk::High);
    }

    #[test]
    fn missing_client_ip_defaults_low() {
        let intel = StaticIpIntel::new();
        // No CF-Connecting-IP header at all.
        let sig = extract(
            &headers(&[(JA4_HEADER, BROWSER_JA4)]),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(sig.ip_risk, IpRisk::Low);
    }

    #[test]
    fn absent_ja4_auto_degrades_without_penalty() {
        let intel = StaticIpIntel::new();
        // Bot Management absent: only the IP header is present.
        let sig = extract(
            &headers(&[(CF_CONNECTING_IP, "198.51.100.7")]),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(sig.tls_consistency, TlsConsistency::Degraded);
        // Degrade is neutral: it must not read as an inconsistency (§4.2).
        assert!(sig.tls_consistency.ua_tls_consistent());
    }

    #[test]
    fn browser_ua_over_browser_stack_is_consistent() {
        let intel = StaticIpIntel::new();
        let hdrs = headers(&[
            (CF_CONNECTING_IP, "198.51.100.7"),
            (JA4_HEADER, BROWSER_JA4),
        ]);
        let sig = extract(&hdrs, Some(CHROME_UA), &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
        assert!(sig.tls_consistency.ua_tls_consistent());
    }

    #[test]
    fn spoofed_browser_ua_over_automation_stack_is_mismatch() {
        let intel = StaticIpIntel::new();
        // The core anti-forgery case: JS self-reports Chrome, the TLS stack is a
        // minimal automation client.
        let hdrs = headers(&[
            (CF_CONNECTING_IP, "34.120.5.6"),
            (JA4_HEADER, AUTOMATION_JA4),
        ]);
        let sig = extract(&hdrs, Some(CHROME_UA), &intel);
        assert_eq!(
            sig,
            PassiveSignals {
                ip_risk: IpRisk::High,
                tls_consistency: TlsConsistency::Mismatch,
            }
        );
        assert!(!sig.tls_consistency.ua_tls_consistent());
    }

    #[test]
    fn honest_curl_ua_over_automation_stack_is_consistent() {
        let intel = StaticIpIntel::new();
        // An un-spoofed automation client: UA and stack agree, so no mismatch.
        let hdrs = headers(&[(JA4_HEADER, AUTOMATION_JA4)]);
        let sig = extract(&hdrs, Some("curl/8.4.0"), &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
    }

    #[test]
    fn unparseable_ja4_degrades() {
        let intel = StaticIpIntel::new();
        let sig = extract(
            &headers(&[(JA4_HEADER, "garbage")]),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(sig.tls_consistency, TlsConsistency::Degraded);
    }

    #[test]
    fn missing_ua_never_manufactures_a_mismatch() {
        // No UA claim to contradict → the strongest verdict is consistent.
        let intel = StaticIpIntel::new();
        let sig = extract(&headers(&[(JA4_HEADER, AUTOMATION_JA4)]), None, &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
    }

    #[test]
    fn ja4_structural_classification() {
        assert_eq!(classify_ja4(BROWSER_JA4), ClientStack::Browser);
        assert_eq!(classify_ja4(AUTOMATION_JA4), ClientStack::Automation);
        // Too short to hold the count fields.
        assert_eq!(classify_ja4("t13d"), ClientStack::Unknown);
    }

    #[test]
    fn confidence_adjustment_boosts_consistent_penalises_mismatch_neutral_degrade() {
        let mk = |ip, c| PassiveSignals {
            ip_risk: ip,
            tls_consistency: c,
        };
        let boost = mk(IpRisk::Low, TlsConsistency::Consistent).confidence_adjustment();
        let penalty = mk(IpRisk::Low, TlsConsistency::Mismatch).confidence_adjustment();
        let degrade = mk(IpRisk::Low, TlsConsistency::Degraded).confidence_adjustment();
        assert!(boost > 0.0);
        assert!(penalty < 0.0);
        assert!(degrade.abs() < f64::EPSILON); // neutral
        // The mismatch downgrade dominates the consistency boost (anti-forgery core).
        assert!(penalty.abs() > boost);
        // The IP band is auxiliary — it never moves the adjustment.
        let degrade_high_ip = mk(IpRisk::High, TlsConsistency::Degraded).confidence_adjustment();
        assert!((degrade - degrade_high_ip).abs() < f64::EPSILON);
    }

    #[test]
    fn ip_risk_wire_labels() {
        assert_eq!(IpRisk::Low.as_str(), "low");
        assert_eq!(IpRisk::Medium.as_str(), "medium");
        assert_eq!(IpRisk::High.as_str(), "high");
    }
}
