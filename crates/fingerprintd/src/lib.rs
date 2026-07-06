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
pub mod state;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{nonce::NonceOutcome, state::AppState};

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
async fn identify(State(state): State<AppState>, Json(req): Json<IdentifyRequest>) -> Response {
    match state.nonce_store.consume(&req.nonce).await {
        NonceOutcome::Valid => {
            let outcome = state.matcher.identify(&req.stable_components, now_ms());
            tracing::debug!(
                visitor_id = %outcome.visitor_id,
                is_new_device = outcome.is_new_device,
                decision = outcome.decision.as_str(),
                score = ?outcome.score,
                compared = outcome.compared_components,
                collision_risk = outcome.collision_risk,
                confidence = outcome.confidence,
                "identified device",
            );
            Json(IdentifyResponse {
                visitor_id: outcome.visitor_id,
                confidence: outcome.confidence,
                is_new_device: outcome.is_new_device,
                decision: outcome.decision.as_str(),
                collision_risk: outcome.collision_risk,
                signals: Signals::stub(),
            })
            .into_response()
        }
        rejected => {
            tracing::debug!(?rejected, "rejected identify: nonce not valid");
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
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
    /// Risk signals for downstream consumers (static stub; passive signals P2).
    signals: Signals,
}

/// Risk signals surfaced to consumers. P0 emits a fixed stub — passive signal
/// collection (JA3/JA4/IP, UA/TLS consistency) is P2.
#[derive(Debug, Serialize)]
struct Signals {
    /// Whether the UA and TLS fingerprint agree.
    ua_tls_consistent: bool,
    /// Coarse IP risk band.
    ip_risk: &'static str,
}

impl Signals {
    /// The P0 placeholder signal set.
    fn stub() -> Self {
        Self {
            ua_tls_consistent: true,
            ip_risk: "low",
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
}
