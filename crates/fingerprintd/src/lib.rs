//! `fingerprintd` — server-side device fingerprinting service.
//!
//! This crate hosts the HTTP surface. The router is built by [`build_router`]
//! and exposes the challenge/response identification flow (PRD §5):
//! `GET /challenge` mints a one-time nonce and `POST /identify` consumes it,
//! rejecting expired or replayed nonces before running the weighted fuzzy
//! matching engine (design §4/§5) to resolve the device.

#![forbid(unsafe_code)]

pub mod config;
pub mod fingerprint;
pub mod fuzzy;
pub mod nonce;
pub mod signals;
pub mod state;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    nonce::NonceOutcome,
    signals::{PassiveSignals, StaticIpIntel},
    state::AppState,
};

/// Build the application router with shared [`AppState`].
///
/// Mounts:
/// - `GET /health` — liveness probe, always `200 OK`.
/// - `GET /challenge` — issue a one-time nonce (PRD §5).
/// - `POST /identify` — consume the nonce and resolve the device.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/challenge", get(challenge))
        .route("/identify", post(identify))
        .with_state(state)
}

/// Liveness handler: reports that the process is up.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// `GET /challenge` — mint a one-time nonce and return the collection plan.
async fn challenge(State(state): State<AppState>) -> Json<ChallengeResponse> {
    let nonce = state.nonce_store.issue().await;
    Json(ChallengeResponse {
        collect: Collect {
            stable: STABLE_PROBES.iter().map(|s| (*s).to_string()).collect(),
            challenge: ChallengeProbe {
                seed: nonce.clone(),
                targets: CHALLENGE_TARGETS.iter().map(|s| (*s).to_string()).collect(),
            },
        },
        expires_in: state.nonce_ttl_secs,
        nonce,
    })
}

/// `POST /identify` — consume the nonce (anti-replay) then match the device.
///
/// A non-[`NonceOutcome::Valid`] nonce (expired, reused, or unknown) yields
/// `401` before any matching runs. On success the response carries the resolved
/// `visitorId` and the weighted engine's computed `confidence`, decision, and
/// collision flag (design §5/§6).
///
/// The `headers` are read for the edge-injected passive signals (real client IP
/// and TLS JA4, PRD §4.2). They fuse into `confidence` **only** — never the
/// `visitorId` — and are trusted only behind a trusted edge (see
/// [`AppState::trust_edge_headers`]); a directly-reachable origin ignores any
/// client-supplied copy.
async fn identify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IdentifyRequest>,
) -> Response {
    match state.nonce_store.consume(&req.nonce).await {
        NonceOutcome::Valid => {
            let outcome = state.matcher.identify(&req.stable_components, now_ms());

            // Cross-check the client-reported UA against the unforgeable
            // edge-observed TLS stack / IP. Trust edge headers only behind a
            // trusted edge; otherwise ignore any client-supplied copy (PRD §4.2
            // trusted-header requirement) — an untrusted request auto-degrades.
            let intel = StaticIpIntel::new();
            let claimed_ua = claimed_ua(&req.stable_components);
            let empty = HeaderMap::new();
            let trusted_headers = if state.trust_edge_headers {
                &headers
            } else {
                &empty
            };
            let signals = signals::extract(trusted_headers, claimed_ua, &intel);

            // Fuse the passive adjustment into confidence, clamped to [0, 1]
            // (design §6). The visitorId and decision are unchanged.
            let confidence = (outcome.confidence + signals.confidence_adjustment()).clamp(0.0, 1.0);

            tracing::debug!(
                visitor_id = %outcome.visitor_id,
                is_new_device = outcome.is_new_device,
                decision = outcome.decision.as_str(),
                score = ?outcome.score,
                compared = outcome.compared_components,
                collision_risk = outcome.collision_risk,
                base_confidence = outcome.confidence,
                confidence,
                tls_consistency = signals.tls_consistency.as_str(),
                ip_risk = signals.ip_risk.as_str(),
                "identified device",
            );
            Json(IdentifyResponse {
                visitor_id: outcome.visitor_id,
                confidence,
                is_new_device: outcome.is_new_device,
                decision: outcome.decision.as_str(),
                collision_risk: outcome.collision_risk,
                signals: Signals::from(signals),
            })
            .into_response()
        }
        rejected => {
            tracing::debug!(?rejected, "rejected identify: nonce not valid");
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

/// Extract the client-reported user agent from the stable components, trying the
/// common key spellings. This is the JS/UA-claimed browser the passive TLS
/// cross-check tests for forgery (signals §4.2); it is deliberately taken from
/// the client-reported body, not a trusted source.
fn claimed_ua(components: &Value) -> Option<&str> {
    ["userAgent", "user_agent", "ua"]
        .iter()
        .find_map(|k| components.get(k).and_then(Value::as_str))
}

/// Current Unix time in milliseconds, saturating to `0` before the epoch — the
/// timestamp the matcher stamps onto observations.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Stable probe identifiers advertised in `GET /challenge` (static P0 plan).
const STABLE_PROBES: &[&str] = &["userAgent", "languages", "timezone", "platform"];
/// Active challenge targets seeded with the nonce.
const CHALLENGE_TARGETS: &[&str] = &["canvas", "audio"];

/// `GET /challenge` response body (PRD §5).
#[derive(Debug, Serialize)]
struct ChallengeResponse {
    /// The one-time nonce the client must echo on `identify`.
    nonce: String,
    /// Nonce lifetime in seconds.
    expires_in: u64,
    /// Client-side collection plan.
    collect: Collect,
}

/// Collection plan carried in a challenge response.
#[derive(Debug, Serialize)]
struct Collect {
    /// Stable probe identifiers to gather.
    stable: Vec<String>,
    /// Nonce-seeded active challenge.
    challenge: ChallengeProbe,
}

/// Active challenge descriptor (canvas/audio seeded with the nonce).
#[derive(Debug, Serialize)]
struct ChallengeProbe {
    /// Nonce used to seed the rendered challenge.
    seed: String,
    /// Probe targets to render.
    targets: Vec<String>,
}

/// `POST /identify` request body.
///
/// Only the fields P0 acts on are declared; the PRD's `ts` and
/// `challenge_response` are accepted but ignored (serde drops unknown fields),
/// as passive signals and challenge verification are out of scope for P0.
#[derive(Debug, Deserialize)]
struct IdentifyRequest {
    /// The nonce previously minted by `GET /challenge`.
    nonce: String,
    /// Raw stable components (no nonce mixed in).
    stable_components: Value,
}

/// `POST /identify` success body (PRD §5).
#[derive(Debug, Serialize)]
struct IdentifyResponse {
    /// Stable device identifier.
    #[serde(rename = "visitorId")]
    visitor_id: String,
    /// Fused match confidence in `[0.0, 1.0]` (design §6).
    confidence: f64,
    /// Whether this device was newly recorded.
    is_new_device: bool,
    /// Verdict from the weighted engine: `match`, `review`, or `new_device`
    /// (design §5.4).
    decision: &'static str,
    /// Set when a runner-up candidate also cleared the match threshold within
    /// the collision margin (design §5.4).
    collision_risk: bool,
    /// Passive network-signal risk summary for downstream consumers (PRD §5).
    signals: Signals,
}

/// Passive-signal risk summary surfaced to consumers (PRD §5): the UA/TLS
/// consistency verdict and the coarse IP reputation band, derived from the
/// edge-observed signals (`crate::signals`).
#[derive(Debug, Serialize)]
struct Signals {
    /// Whether the UA and TLS fingerprint agree.
    ua_tls_consistent: bool,
    /// Coarse IP risk band.
    ip_risk: &'static str,
}

impl From<PassiveSignals> for Signals {
    fn from(signals: PassiveSignals) -> Self {
        Self {
            ua_tls_consistent: signals.tls_consistency.ua_tls_consistent(),
            ip_risk: signals.ip_risk.as_str(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build_router;
    use crate::{config::Config, nonce::InMemoryNonceStore, state::AppState};
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::{Value, json};
    use std::{sync::Arc, time::Duration};
    use tower::ServiceExt;

    /// Build a router over default in-memory state.
    fn test_router() -> Router {
        build_router(AppState::from_config(&Config::default()))
    }

    /// GET a URI and return the response.
    async fn get(router: &Router, uri: &str) -> axum::response::Response {
        router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// POST `/identify` with a JSON body and return the response.
    async fn post_identify(router: &Router, body: Value) -> axum::response::Response {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/identify")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// POST `/identify` with a JSON body and extra request headers.
    async fn post_identify_headers(
        router: &Router,
        body: Value,
        headers: &[(&str, &str)],
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/identify")
            .header(header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        router
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    /// Read a response body into a JSON value.
    async fn json_body(resp: axum::response::Response) -> Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// GET `/challenge` and return its issued nonce.
    async fn fresh_nonce(router: &Router) -> String {
        let resp = get(router, "/challenge").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["expires_in"], json!(30));
        assert_eq!(body["collect"]["challenge"]["seed"], body["nonce"]);
        body["nonce"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = get(&test_router(), "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn happy_path_identifies_new_device() {
        let router = test_router();
        let nonce = fresh_nonce(&router).await;

        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": 1, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert!(body["visitorId"].as_str().is_some());
        // A first-ever probe has no candidate: it is a new device with a
        // computed (no longer hardcoded) confidence in [0, 1].
        let confidence = body["confidence"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&confidence));
        assert_eq!(body["is_new_device"], json!(true));
        assert_eq!(body["decision"], json!("new_device"));
    }

    #[tokio::test]
    async fn unknown_nonce_rejected() {
        let resp = post_identify(
            &test_router(),
            json!({ "nonce": "never-issued", "ts": 1, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn reused_nonce_rejected() {
        let router = test_router();
        let nonce = fresh_nonce(&router).await;
        let body = json!({ "nonce": nonce, "ts": 1, "stable_components": {"ua": "x"} });

        let first = post_identify(&router, body.clone()).await;
        assert_eq!(first.status(), StatusCode::OK);

        // Same nonce a second time: replay is rejected.
        let second = post_identify(&router, body).await;
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_nonce_rejected() {
        // Build state with a store holding an already-expired nonce (zero TTL),
        // so expiry is exercised deterministically without sleeping.
        let store = Arc::new(InMemoryNonceStore::new(Duration::from_secs(30)));
        let nonce = store.issue_with_ttl(Duration::ZERO);
        let state = AppState {
            nonce_store: store,
            matcher: Arc::new(crate::fuzzy::FuzzyStore::new()),
            nonce_ttl_secs: 30,
            trust_edge_headers: false,
        };
        let router = build_router(state);

        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": 1, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// A rich, realistic stable-component probe the fuzzy engine can score.
    fn probe_components() -> Value {
        json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "audio": "124.04",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Arial", "Helvetica", "Courier", "Times", "Verdana"],
            "user_agent": "Chrome/120",
        })
    }

    /// POST `/identify` for `components` under a fresh nonce, returning the body.
    async fn identify_with(router: &Router, components: Value) -> Value {
        let nonce = fresh_nonce(router).await;
        json_body(
            post_identify(
                router,
                json!({ "nonce": nonce, "ts": 1, "stable_components": components }),
            )
            .await,
        )
        .await
    }

    #[tokio::test]
    async fn fuzzy_match_across_requests() {
        let router = test_router();

        // Same rich components, two fresh nonces -> same visitor, second matched.
        let first = identify_with(&router, probe_components()).await;
        let second = identify_with(&router, probe_components()).await;

        assert_eq!(first["visitorId"], second["visitorId"]);
        assert_eq!(first["is_new_device"], json!(true));
        assert_eq!(second["is_new_device"], json!(false));
        assert_eq!(second["decision"], json!("match"));

        // A disjoint device -> different visitor, marked new.
        let other = json!({
            "webgl": "Apple GPU",
            "platform": "iPhone",
            "timezone": "America/New_York",
            "audio": "35.7",
            "cpu_cores": 6,
            "device_memory": 4,
            "fonts": ["SF Pro", "Menlo", "Georgia", "Palatino"],
            "user_agent": "Safari/17",
        });
        let third = identify_with(&router, other).await;
        assert_ne!(third["visitorId"], first["visitorId"]);
        assert_eq!(third["is_new_device"], json!(true));
    }

    // --- Passive-signal fusion (T7 / design §6, PRD §4.2) ---

    use crate::signals::{CF_CONNECTING_IP, JA4_HEADER};

    /// A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext).
    const BROWSER_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    /// A JA4 whose structural counts read as a minimal automation stack (3/4).
    const AUTOMATION_JA4: &str = "t13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb";
    /// A spoofed browser UA (headless automation self-reporting Chrome).
    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";

    /// Build a router whose state trusts (or not) edge-injected headers.
    fn router_with_trust(trust_edge_headers: bool) -> Router {
        build_router(AppState::from_config(&Config {
            trust_edge_headers,
            ..Config::default()
        }))
    }

    /// Identify a fixed single-device probe (claimed UA = Chrome) on a **fresh**
    /// router with the given trust setting and edge headers, returning the body.
    ///
    /// A fresh store per call keeps the probe a first-ever new device, so the
    /// engine's base confidence is identical across calls and only the passive
    /// fusion differs — letting the tests compare adjustments directly.
    async fn identify_signals(trust_edge_headers: bool, headers: &[(&str, &str)]) -> Value {
        let router = router_with_trust(trust_edge_headers);
        let nonce = fresh_nonce(&router).await;
        let body = json!({
            "nonce": nonce,
            "ts": 1,
            "stable_components": { "userAgent": CHROME_UA },
        });
        json_body(post_identify_headers(&router, body, headers).await).await
    }

    /// Read the `confidence` field as an `f64`.
    fn confidence(body: &Value) -> f64 {
        body["confidence"].as_f64().unwrap()
    }

    #[tokio::test]
    async fn passive_consistent_ua_tls_boosts_confidence() {
        // Baseline: trusted edge but Bot Management absent → degraded (neutral).
        let base = identify_signals(true, &[(CF_CONNECTING_IP, "198.51.100.7")]).await;
        // A browser JA4 consistent with the Chrome UA lifts confidence.
        let boosted = identify_signals(
            true,
            &[
                (CF_CONNECTING_IP, "198.51.100.7"),
                (JA4_HEADER, BROWSER_JA4),
            ],
        )
        .await;
        assert!(confidence(&boosted) > confidence(&base));
        assert_eq!(boosted["signals"]["ua_tls_consistent"], json!(true));
    }

    #[tokio::test]
    async fn passive_ua_tls_mismatch_downgrades_confidence() {
        // Baseline: no JA4 → degraded (neutral).
        let base = identify_signals(true, &[]).await;
        // Chrome UA riding a minimal automation TLS stack → strong downgrade.
        let downgraded = identify_signals(true, &[(JA4_HEADER, AUTOMATION_JA4)]).await;
        assert!(confidence(&downgraded) < confidence(&base));
        assert_eq!(downgraded["signals"]["ua_tls_consistent"], json!(false));
    }

    #[tokio::test]
    async fn absent_ja4_degrades_gracefully_without_penalty() {
        // Bot Management absent (no JA4 header) behind a trusted edge.
        let degraded = identify_signals(true, &[(CF_CONNECTING_IP, "198.51.100.7")]).await;
        let mismatched = identify_signals(true, &[(JA4_HEADER, AUTOMATION_JA4)]).await;
        let boosted = identify_signals(true, &[(JA4_HEADER, BROWSER_JA4)]).await;

        // Neutral: strictly above a forgery downgrade, strictly below a boost —
        // a missing connection signal neither penalises nor rewards (§4.2).
        assert!(confidence(&degraded) > confidence(&mismatched));
        assert!(confidence(&degraded) < confidence(&boosted));
        // Still a clean success, and degrade is not flagged as an inconsistency.
        assert_eq!(degraded["is_new_device"], json!(true));
        assert_eq!(degraded["signals"]["ua_tls_consistent"], json!(true));
        assert_eq!(degraded["signals"]["ip_risk"], json!("low"));
    }

    #[tokio::test]
    async fn client_supplied_edge_headers_are_ignored_when_untrusted() {
        // A direct client self-injects a browser-looking JA4 and a datacenter IP
        // to forge consistency and a clean IP band.
        let forged = &[(CF_CONNECTING_IP, "34.120.5.6"), (JA4_HEADER, BROWSER_JA4)];

        // Default (untrusted) origin: the client-supplied headers are ignored.
        let untrusted = identify_signals(false, forged).await;
        // The same headers behind a trusted edge would boost and flag the IP.
        let trusted = identify_signals(true, forged).await;

        // No forged boost: the untrusted request stays at the degraded baseline.
        assert!(confidence(&untrusted) < confidence(&trusted));
        // The client IP header is ignored → band stays low (edge-trusted: high).
        assert_eq!(untrusted["signals"]["ip_risk"], json!("low"));
        assert_eq!(trusted["signals"]["ip_risk"], json!("high"));
        // The forged JA4 buys no evidence-based consistency (degrade default).
        assert_eq!(untrusted["signals"]["ua_tls_consistent"], json!(true));
    }
}
