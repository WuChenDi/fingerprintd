//! `fingerprintd` binary entry point: initialize tracing, load configuration,
//! bind the listener, and serve the router with graceful shutdown.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use fingerprintd::{build_router, config::Config, state::AppState};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "fingerprintd exited with error");
            ExitCode::FAILURE
        }
    }
}

/// Wire configuration, the listener, and the server together.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    tracing::info!(bind_addr = %config.bind_addr, "starting fingerprintd");

    let state = AppState::from_config(&config);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!(local_addr = %listener.local_addr()?, "listening");

    axum::serve(listener, build_router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Initialize the tracing subscriber (pretty in dev; level via `RUST_LOG`).
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

/// Resolve when the process receives Ctrl-C (SIGINT), triggering graceful shutdown.
async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %err, "failed to install Ctrl-C handler");
    }
    tracing::info!("shutdown signal received");
}
