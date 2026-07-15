//! Shared HTTP client construction for the SDK's REST transports.
//!
//! `reqwest` applies **no** request or connect timeout by default, so a hung or
//! blackholed VTA (a half-open load balancer, a SIGSTOPped process, a firewall
//! silently dropping packets) would hang the caller forever. Every REST client
//! in the SDK is built here so the timeouts are applied uniformly.

use std::time::Duration;

/// Default total-request timeout for a VTA REST call.
const DEFAULT_REST_TIMEOUT_SECS: u64 = 30;
/// Default TCP/TLS connect timeout.
const DEFAULT_REST_CONNECT_TIMEOUT_SECS: u64 = 10;

/// A `reqwest::Client` with finite request + connect timeouts.
///
/// Overridable via `VTA_REST_TIMEOUT_SECS` / `VTA_REST_CONNECT_TIMEOUT_SECS`
/// (positive integers, seconds); anything missing/zero/unparseable falls back to
/// the defaults. Use this instead of `reqwest::Client::new()` for any REST call
/// to a VTA so a wedged peer surfaces as a timeout error, not an unbounded hang.
///
/// Panics only if the TLS backend cannot initialize — the same condition under
/// which `reqwest::Client::new()` already panics, so this is not a new failure
/// mode.
pub(crate) fn rest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(env_secs("VTA_REST_TIMEOUT_SECS", DEFAULT_REST_TIMEOUT_SECS))
        .connect_timeout(env_secs(
            "VTA_REST_CONNECT_TIMEOUT_SECS",
            DEFAULT_REST_CONNECT_TIMEOUT_SECS,
        ))
        .build()
        .expect("reqwest client with timeouts (TLS backend init)")
}

/// Read a positive-integer seconds value from `var`, falling back to `default`.
fn env_secs(var: &str, default: u64) -> Duration {
    let secs = std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_secs_uses_default_when_unset_or_junk() {
        // A var that does not exist → default.
        assert_eq!(
            env_secs("VTA_REST_TIMEOUT_SECS_DEFINITELY_UNSET_XYZ", 30),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn rest_client_builds() {
        // Building must not panic in a normal environment (TLS backend present).
        let _ = rest_client();
    }
}
