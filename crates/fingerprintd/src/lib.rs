//! `fingerprintd` — server-side device fingerprinting service.
//!
//! This crate hosts the HTTP surface for the P0 skeleton. The router is built
//! by [`build_router`], which currently exposes only a liveness endpoint. The
//! `/challenge` and `/identify` endpoints (nonce issuance and identification,
//! PRD §5) are layered on top of this extension point in a later task.

#![forbid(unsafe_code)]

pub mod config;

use axum::{Router, http::StatusCode, routing::get};

/// Build the application router.
///
/// This is the single extension point for HTTP routes: additional endpoints
/// (`/challenge`, `/identify`) are mounted here by chaining `.route(...)` on the
/// returned [`Router`]. When request-scoped state is introduced, this function
/// gains an `AppState` parameter and switches to `Router::with_state`.
///
/// The skeleton mounts:
/// - `GET /health` — liveness probe, always returns `200 OK`.
pub fn build_router() -> Router {
    Router::new().route("/health", get(health))
}

/// Liveness handler: reports that the process is up.
async fn health() -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::build_router;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_200() {
        let response = build_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
