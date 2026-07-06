//! Runtime configuration for the `fingerprintd` service.
//!
//! Configuration is layered: built-in defaults are overlaid by an optional
//! `fingerprintd.toml` file, then by `FINGERPRINTD_`-prefixed environment
//! variables. The merged result is validated by `serde` during extraction.

use std::{fmt, net::SocketAddr};

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

/// A secret key loaded from configuration (the nonce-probe HMAC key, T8).
///
/// Wraps the raw key so it is never accidentally logged: its [`fmt::Debug`] is
/// redacted, so `Debug`-printing the containing [`Config`] does not leak it. It
/// serializes transparently (as the bare string) so figment can layer it from a
/// file or `FINGERPRINTD_PROBE_KEY`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretKey(String);

impl SecretKey {
    /// The raw key bytes, for HMAC keying (`crate::probe`).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether a non-empty key is present. An empty string is treated as "no
    /// probe configured", so enforcement stays off (fail-closed only once a real
    /// key is provisioned).
    pub(crate) fn is_configured(&self) -> bool {
        !self.0.is_empty()
    }
}

impl From<&str> for SecretKey {
    fn from(key: &str) -> Self {
        Self(key.to_string())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(REDACTED)")
    }
}

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
    /// Optional pre-shared HMAC key for nonce-probe verification (T8, PRD §4.1
    /// pt 3). When set (and non-empty), `GET /challenge` advertises the probe
    /// transform and `POST /identify` requires a correct `probe` field, rejecting
    /// a missing or forged one with `401`. Left unset by default: the probe is
    /// depth on top of the one-time nonce and needs a probe-capable client (WASM
    /// collector, deferred), so enforcing it before that ships would reject all
    /// legitimate traffic. Overridable via `FINGERPRINTD_PROBE_KEY`.
    #[serde(default)]
    pub probe_key: Option<SecretKey>,
    /// Optional pre-shared HMAC key for signing `/identify` responses (T9, PRD
    /// §4.1). When set (and non-empty), each success carries `x-fp-timestamp`
    /// and `x-fp-signature` headers so a consumer can detect a tampered or forged
    /// response (`crate::signing`). Left unset by default (fail-open on an absent
    /// key): the response body is unchanged, so a non-verifying client is
    /// unaffected. Overridable via `FINGERPRINTD_RESPONSE_SIGNING_KEY`.
    #[serde(default)]
    pub response_signing_key: Option<SecretKey>,
    /// Whether to enforce the request timestamp window on `/identify` (T9, PRD
    /// §4.1). When `true`, a request whose `ts` (Unix milliseconds) is absent or
    /// more than `ts_skew_secs` from server time is rejected with `401`, bounding
    /// how long a captured payload stays replayable on top of the one-time nonce.
    /// Left `false` by default (fail-open): a client that does not send a `ts` is
    /// unaffected. Overridable via `FINGERPRINTD_ENFORCE_TS_WINDOW`.
    pub enforce_ts_window: bool,
    /// Allowed clock skew, in seconds, for the request timestamp window when
    /// `enforce_ts_window` is on (T9). A request is accepted iff its `ts` is
    /// within `±ts_skew_secs` of server time. Overridable via
    /// `FINGERPRINTD_TS_SKEW_SECS`.
    pub ts_skew_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            nonce_ttl_secs: 30,
            trust_edge_headers: false,
            probe_key: None,
            response_signing_key: None,
            enforce_ts_window: false,
            ts_skew_secs: 30,
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
    use super::{Config, SecretKey};
    use std::net::SocketAddr;

    #[test]
    fn secret_key_debug_is_redacted() {
        let key = SecretKey::from("super-secret-probe-key");
        // Neither the wrapped key nor a `Config` carrying it may leak the value.
        assert!(!format!("{key:?}").contains("super-secret-probe-key"));
        let cfg = Config {
            probe_key: Some(key),
            ..Config::default()
        };
        assert!(!format!("{cfg:?}").contains("super-secret-probe-key"));
    }

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
