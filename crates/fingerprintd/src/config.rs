//! Runtime configuration for the `fingerprintd` service.
//!
//! Configuration is layered: built-in defaults are overlaid by an optional
//! `fingerprintd.toml` file, then by `FINGERPRINTD_`-prefixed environment
//! variables. The merged result is validated by `serde` during extraction.

use std::net::SocketAddr;

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

/// Default file consulted by [`Config::load`] when present.
const CONFIG_FILE: &str = "fingerprintd.toml";
/// Prefix for environment overrides, e.g. `FINGERPRINTD_BIND_ADDR`.
const ENV_PREFIX: &str = "FINGERPRINTD_";

/// Service configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Socket address the HTTP server binds to.
    pub bind_addr: SocketAddr,
    /// Lifetime, in seconds, of a challenge nonce before it expires. Reported
    /// to clients as `expires_in`; overridable via `FINGERPRINTD_NONCE_TTL_SECS`.
    pub nonce_ttl_secs: u64,
    /// Whether to trust edge-injected passive-signal headers (`CF-Connecting-IP`,
    /// `cf-bot-management-ja4`). Enable **only** when the service sits behind a
    /// trusted edge (Cloudflare) that injects these headers and an origin IP
    /// allowlist rejects direct client connections (PRD §4.2). Left `false` by
    /// default (fail-closed): a directly-reachable origin must not trust
    /// client-supplied copies of these headers, or a client could self-inject a
    /// browser-looking JA4 to forge consistency. Overridable via
    /// `FINGERPRINTD_TRUST_EDGE_HEADERS`.
    pub trust_edge_headers: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            nonce_ttl_secs: 30,
            trust_edge_headers: false,
        }
    }
}

impl Config {
    /// Load configuration from defaults, an optional `fingerprintd.toml`, and
    /// `FINGERPRINTD_`-prefixed environment variables (in increasing priority).
    pub fn load() -> Result<Self, Box<figment::Error>> {
        Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(CONFIG_FILE))
            .merge(Env::prefixed(ENV_PREFIX))
            .extract()
            .map_err(Box::new)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::net::SocketAddr;

    #[test]
    fn default_binds_localhost_8080() {
        let cfg = Config::default();
        assert_eq!(
            cfg.bind_addr,
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    // `Jail::expect_with` fixes the closure error type to `figment::Error`.
    #[allow(clippy::result_large_err)]
    fn env_overrides_bind_addr() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("FINGERPRINTD_BIND_ADDR", "0.0.0.0:9000");
            let cfg = Config::load().unwrap();
            assert_eq!(cfg.bind_addr, "0.0.0.0:9000".parse::<SocketAddr>().unwrap());
            Ok(())
        });
    }
}
