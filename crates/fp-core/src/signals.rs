//! Passive network-signal compute (architecture §4.2 / §4.4 / §6).
//!
//! Client-reported `components` are forgeable: a headless browser can self-report
//! any `userAgent` it likes. This module derives the signals a client **cannot**
//! self-report — the real network IP and the TLS JA3/JA4 stack — and cross-checks
//! the TLS stack against the JS/UA-claimed browser. The result feeds `/identify`
//! **confidence only**, never the `visitorId` (JA4 is low-entropy and forgeable,
//! architecture §4.2).
//!
//! This is the framework-free compute: it takes plain values (the JA4 string, the
//! client IP string, the claimed UA), never an HTTP framework type, so every
//! deployment target — the native Axum server and the WebAssembly edge build —
//! reuses it unchanged. The HTTP-layer adapter (`crates/fingerprintd`) pulls the
//! trusted headers and delegates to [`compute`].
//!
//! Three shapes of outcome, mirroring the confidence fusion applied downstream (§6):
//! - [`TlsConsistency::Consistent`] — UA and TLS stack agree → small boost.
//! - [`TlsConsistency::Mismatch`] — Chrome UA over a Python/Go TLS stack → strong
//!   downgrade (the core anti-forgery signal, §4.2).
//! - [`TlsConsistency::Degraded`] — no JA3/JA4 available (Bot Management absent,
//!   or an unparseable value) → neutral, neither boost nor penalty. This is the
//!   mandated **auto-degrade** path: a missing connection-layer signal must not
//!   block or penalise the request (§4.2).
//!
//! **Trust boundary (architecture §4.2 security requirement):** the JA4 signal is trusted
//! only when injected by the Cloudflare edge; the origin must strip any
//! client-supplied copy before this module runs. Enforcing that strip is handler
//! /edge wiring; this module only consumes whatever trusted values it is given.
//!
//! **Scope caveats:** inputs here are mocked. Real JA4 needs Cloudflare Bot
//! Management (may be absent → degrade), and the [`IpIntel`] static classifier is
//! a coarse illustrative placeholder — a production deployment swaps it for a real
//! ASN / proxy / reputation feed (see [`StaticIpIntel`]). No real-data detection
//! rate is claimed here.

use std::net::{IpAddr, Ipv4Addr};

/// Minimum cipher count in a JA4 fingerprint for the stack to read as a real
/// browser. Browsers advertise a broad cipher list; minimal automation stacks
/// (curl/python/go defaults) advertise few. Coarse structural heuristic, not a
/// fingerprint database (see [`classify_ja4`]).
const BROWSER_MIN_CIPHERS: u32 = 10;
/// Minimum TLS extension count in a JA4 fingerprint for a real-browser read.
/// Browsers carry GREASE + ALPN + `key_share` + `supported_versions` + … ;
/// automation stacks carry far fewer.
const BROWSER_MIN_EXTENSIONS: u32 = 10;

/// Curated set of `JA4_a` structural shapes that real browsers share, each a
/// `(protocol, tls_version, sni, alpn)` tuple — the coarse structural signature
/// deliberately *without* the exact cipher/extension counts (which an automation
/// stack can pad). Modern Chrome/Firefox/Edge/Safari all negotiate TLS 1.3
/// (`tls_version = 13`), send the SNI (`sni = d`), and advertise HTTP/2
/// (`alpn = h2`) over TCP (`protocol = t`). This is a coarse curated placeholder
/// in the spirit of [`StaticIpIntel`], **not** a real JA4 fingerprint database
/// (future TODO — real JA4 fingerprint database, see [`classify_ja4`]).
const BROWSER_JA4_SHAPES: &[(&str, &str, &str, &str)] = &[("t", "13", "d", "h2")];

/// Confidence boost when the UA claim and the observed TLS stack agree — a small
/// positive nudge toward "real browser" (fuzzy-matching §6, "一致 → 加成").
const CONSISTENT_BOOST: f64 = 0.05;
/// Confidence penalty when the UA claim contradicts the observed TLS stack — the
/// strong anti-forgery downgrade (fuzzy-matching §6 / architecture §4.2, "不一致 → 大幅下调").
const MISMATCH_PENALTY: f64 = 0.5;

/// Coarse IP reputation band surfaced to downstream risk consumers (architecture §5).
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
/// observed TLS (JA3/JA4) stack (architecture §4.2 / §6).
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

    /// The boolean `ua_tls_consistent` flag for the response body (architecture §5).
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

/// The passive signals extracted for one request (architecture §5 `signals`), fed to the
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
    /// (fuzzy-matching §6). The caller adds this to the engine's base confidence and
    /// clamps to `[0, 1]`; positive boosts, negative downgrades.
    ///
    /// Only the UA-vs-TLS consistency verdict moves confidence: agreement gives a
    /// small [`CONSISTENT_BOOST`], an outright [`TlsConsistency::Mismatch`] gives
    /// the strong [`MISMATCH_PENALTY`] downgrade (the anti-forgery core, architecture §4.2),
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
/// The passive IP signal is auxiliary, not decisive (architecture §4.2). Implementations
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

/// Compute the passive signals for a request from its trusted, framework-free values.
///
/// - IP band: `client_ip` is trimmed and parsed, then classified via
///   [`IpIntel::assess`]; a missing/unparseable IP defaults to [`IpRisk::Low`]
///   (no adverse evidence).
/// - TLS consistency: `ja4` is classified and cross-checked against `claimed_ua`
///   (the JS/UA-reported user agent). A missing (`None`) or unparseable JA4 yields
///   [`TlsConsistency::Degraded`] — the auto-degrade path (§4.2).
///
/// `claimed_ua` is the client-reported UA (from `stable_components` / the HTTP
/// `User-Agent`); it is the value under suspicion, cross-checked against the
/// unforgeable TLS stack.
pub fn compute(
    ja4: Option<&str>,
    client_ip: Option<&str>,
    claimed_ua: Option<&str>,
    intel: &dyn IpIntel,
) -> PassiveSignals {
    let ip_risk = client_ip
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .map_or(IpRisk::Low, |ip| intel.assess(ip));

    let tls_consistency = match ja4 {
        Some(ja4) => consistency(claimed_ua.map(classify_ua), classify_ja4(ja4)),
        None => TlsConsistency::Degraded, // Bot Management absent → auto-degrade.
    };

    PassiveSignals {
        ip_risk,
        tls_consistency,
    }
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

/// The parsed fields of a `JA4_a` prefix at their fixed offsets.
struct Ja4Shape<'a> {
    protocol: &'a str,
    tls_version: &'a str,
    sni: &'a str,
    ciphers: u32,
    extensions: u32,
    alpn: &'a str,
}

/// Parse a `JA4_a` prefix into its [`Ja4Shape`] fields, or `None` if any field is
/// missing / too short / not a valid count. Offsets follow the JA4 layout:
/// `protocol(1) tls_version(2) sni(1) cipher_count(2) extension_count(2) alpn(2)`.
fn parse_ja4_shape(a: &str) -> Option<Ja4Shape<'_>> {
    Some(Ja4Shape {
        protocol: a.get(0..1)?,
        tls_version: a.get(1..3)?,
        sni: a.get(3..4)?,
        ciphers: a.get(4..6)?.parse().ok()?,
        extensions: a.get(6..8)?.parse().ok()?,
        alpn: a.get(8..10)?,
    })
}

/// Classify a JA4 fingerprint into a coarse [`ClientStack`] from its structure.
///
/// The `JA4_a` prefix (before the first `_`) encodes, at fixed offsets:
/// `protocol(1) tls_version(2) sni(1) cipher_count(2) extension_count(2)
/// alpn(2)`. We parse the *full* prefix (via [`parse_ja4_shape`]) and combine two
/// checks rather than thresholding the counts alone:
///
/// - **counts** — a real browser advertises many ciphers and extensions; a
///   minimal automation stack advertises few ([`BROWSER_MIN_CIPHERS`] /
///   [`BROWSER_MIN_EXTENSIONS`]). Counts below the bar read as automation.
/// - **shape** — the structural `(protocol, tls_version, sni, alpn)` tuple must
///   match a known real-browser signature ([`BROWSER_JA4_SHAPES`]). This closes
///   the count-padding bypass: an automation stack that merely inflates its
///   cipher/extension lists past the thresholds but keeps a non-browser shape
///   (wrong ALPN / TLS-version pattern) reads as [`ClientStack::Automation`],
///   not `Browser`.
///
/// This is a coarse structural heuristic, **not** a JA4→client fingerprint
/// database; a malformed or too-short prefix reads as [`ClientStack::Unknown`]
/// (→ degrade). (future TODO — real JA4 fingerprint database.)
fn classify_ja4(ja4: &str) -> ClientStack {
    let a = ja4.split('_').next().unwrap_or(ja4);
    let Some(shape) = parse_ja4_shape(a) else {
        return ClientStack::Unknown;
    };
    // Counts below the browser bar are a minimal automation stack (unchanged).
    if shape.ciphers < BROWSER_MIN_CIPHERS || shape.extensions < BROWSER_MIN_EXTENSIONS {
        return ClientStack::Automation;
    }
    // Counts clear the bar; only a known real-browser shape confirms Browser.
    // Padded counts on a non-browser shape are the forgery case we now catch.
    let is_browser_shape = BROWSER_JA4_SHAPES
        .iter()
        .any(|&(protocol, tls, sni, alpn)| {
            shape.protocol == protocol
                && shape.tls_version == tls
                && shape.sni == sni
                && shape.alpn == alpn
        });
    if is_browser_shape {
        ClientStack::Browser
    } else {
        ClientStack::Automation
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
        ClientStack, IpIntel, IpRisk, PassiveSignals, StaticIpIntel, TlsConsistency, classify_ja4,
        compute,
    };

    /// A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext).
    const BROWSER_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    /// A JA4 whose structural counts read as a minimal automation stack (3/4).
    const AUTOMATION_JA4: &str = "t13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb";
    /// A JA4 whose counts are padded past the browser thresholds (15/16) but whose
    /// shape is non-browser: HTTP/1.1 ALPN (`h1`) where a real browser sends `h2`.
    /// The count-only heuristic misread this as `Browser`; the shape check catches
    /// it (RT-002 — closes the count-padding bypass).
    const PADDED_AUTOMATION_JA4: &str = "t13d1516h1_cccccccccccc_dddddddddddd";
    /// A spoofed browser UA (headless automation self-reporting Chrome).
    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";

    /// `CloakBrowser` adversary profile — a real stealth Chromium, not an automation
    /// stack. Its TLS handshake is a genuine Chrome handshake, so its JA4 counts
    /// read as a browser (15 ciphers / 16 extensions, ≥ the browser thresholds).
    const CLOAK_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
    /// A genuine, current Chrome desktop UA — a real browser string with no
    /// automation markers (the stealth build ships the honest UA of its engine).
    const CLOAK_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
    /// A residential (non-datacenter) IPv4 reached over the adversary's residential
    /// proxy. TEST-NET-3, outside every `DATACENTER_V4` block and not private.
    const CLOAK_IP: &str = "203.0.113.55";

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
    fn client_ip_drives_the_ip_band() {
        let intel = StaticIpIntel::new();
        let sig = compute(
            Some(BROWSER_JA4),
            Some("34.120.5.6"),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(sig.ip_risk, IpRisk::High);
    }

    #[test]
    fn missing_client_ip_defaults_low() {
        let intel = StaticIpIntel::new();
        // No client IP at all.
        let sig = compute(Some(BROWSER_JA4), None, Some(CHROME_UA), &intel);
        assert_eq!(sig.ip_risk, IpRisk::Low);
    }

    #[test]
    fn absent_ja4_auto_degrades_without_penalty() {
        let intel = StaticIpIntel::new();
        // Bot Management absent: only the IP is present.
        let sig = compute(None, Some("198.51.100.7"), Some(CHROME_UA), &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Degraded);
        // Degrade is neutral: it must not read as an inconsistency (§4.2).
        assert!(sig.tls_consistency.ua_tls_consistent());
    }

    #[test]
    fn browser_ua_over_browser_stack_is_consistent() {
        let intel = StaticIpIntel::new();
        let sig = compute(
            Some(BROWSER_JA4),
            Some("198.51.100.7"),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
        assert!(sig.tls_consistency.ua_tls_consistent());
    }

    #[test]
    fn spoofed_browser_ua_over_automation_stack_is_mismatch() {
        let intel = StaticIpIntel::new();
        // The core anti-forgery case: JS self-reports Chrome, the TLS stack is a
        // minimal automation client.
        let sig = compute(
            Some(AUTOMATION_JA4),
            Some("34.120.5.6"),
            Some(CHROME_UA),
            &intel,
        );
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
        let sig = compute(Some(AUTOMATION_JA4), None, Some("curl/8.4.0"), &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
    }

    #[test]
    fn unparseable_ja4_degrades() {
        let intel = StaticIpIntel::new();
        let sig = compute(Some("garbage"), None, Some(CHROME_UA), &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Degraded);
    }

    #[test]
    fn missing_ua_never_manufactures_a_mismatch() {
        // No UA claim to contradict → the strongest verdict is consistent.
        let intel = StaticIpIntel::new();
        let sig = compute(Some(AUTOMATION_JA4), None, None, &intel);
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
    fn padded_counts_with_non_browser_shape_reads_as_automation() {
        // An automation stack inflates its cipher/extension lists past the browser
        // thresholds (15/16) but still negotiates HTTP/1.1 (`h1`) — a shape no real
        // browser presents. Count-only thresholding misread this as `Browser`; the
        // full-shape check classifies it as automation.
        assert_eq!(classify_ja4(PADDED_AUTOMATION_JA4), ClientStack::Automation);
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

    /// KNOWN SINGLE-REQUEST BYPASS — pinned regression baseline, NOT the desired
    /// end state. A `CloakBrowser` (real stealth Chromium: genuine Chrome-shaped TLS,
    /// honest Chrome UA, residential-proxy IP) passes *every* per-request passive
    /// signal: its TLS stack matches its UA (a consistency boost, not a mismatch
    /// penalty) and its residential IP reads as low risk. Nothing in a single
    /// request distinguishes it from an honest user. This is intentional and
    /// documented so any future change that closes or reopens the gap shows up as a
    /// visible test diff rather than folklore. The signal that actually catches this
    /// adversary is the cross-session velocity check (RT-003), not this module.
    #[test]
    fn cloak_browser_passes_every_single_request_signal() {
        let intel = StaticIpIntel::new();
        let sig = compute(Some(CLOAK_JA4), Some(CLOAK_IP), Some(CLOAK_UA), &intel);
        // UA and TLS agree → the per-request check hands out a confidence boost.
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
        assert!(sig.confidence_adjustment() > 0.0);
        // Residential proxy IP is indistinguishable from an honest user's.
        assert_eq!(sig.ip_risk, IpRisk::Low);
    }

    #[test]
    fn ip_risk_wire_labels() {
        assert_eq!(IpRisk::Low.as_str(), "low");
        assert_eq!(IpRisk::Medium.as_str(), "medium");
        assert_eq!(IpRisk::High.as_str(), "high");
    }
}
