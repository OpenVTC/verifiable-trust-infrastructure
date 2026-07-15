//! Shared HTTP client construction for the SDK's REST transports.
//!
//! `reqwest` applies **no** request or connect timeout by default, so a hung or
//! blackholed VTA (a half-open load balancer, a SIGSTOPped process, a firewall
//! silently dropping packets) would hang the caller forever. Every REST client
//! in the SDK is built here so the timeouts are applied uniformly.

use std::sync::LazyLock;
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

// ── Foreign fetch: attacker-influenceable URLs (status lists, etc.) ──────────
//
// Fetching a URL a third party controls (an issuer-supplied status-list URL on
// the credential-present path) is a privileged operation. It needs strictly
// more hardening than an ordinary REST call to our own VTA — no redirect
// following (CWE-918 SSRF-via-redirect), a response-body cap (a hostile host
// can otherwise stream a multi-GB body to OOM the process), and a URL guard
// that refuses non-public targets. This is the single shared implementation so
// every consumer (VTA vault-present, VTC recognise/present) gets the same
// chokepoint rather than each rolling its own.

/// Timeout for a foreign fetch — deliberately tighter than the REST default.
const FOREIGN_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Default cap on a fetched foreign body. The spec-minimum status list is
/// ~16 KiB; 2 MiB is generous headroom while refusing an OOM-sized stream.
pub const DEFAULT_MAX_FOREIGN_BODY: usize = 2 * 1024 * 1024;

/// Errors from the foreign-fetch helpers. Callers map these into their own
/// error types (e.g. `AppError`, `RecognitionError`).
#[derive(Debug, thiserror::Error)]
pub enum ForeignFetchError {
    /// The URL failed [`guard_public_url`] (bad scheme, userinfo, non-public IP).
    #[error("{0}")]
    Blocked(String),
    /// The response body exceeded the caller's cap.
    #[error("response body exceeds the {max}-byte cap")]
    BodyTooLarge { max: usize },
    /// Reading the response body failed mid-stream.
    #[error("reading response body failed: {0}")]
    Read(String),
}

/// One shared, hardened client for every outbound foreign fetch. `reqwest::Client`
/// is internally ref-counted, so cloning reuses the connection pool.
///
/// - **`redirect(none)`** — [`guard_public_url`] runs once, on the *original*
///   URL. Following redirects would let a public URL `302` to an internal target
///   (`127.0.0.1`, `169.254.169.254`) past the guard. With no follow, a
///   redirecting host yields a non-2xx the caller treats as failure.
/// - **`timeout` / `connect_timeout`** — bounded so a hung host can't pin a
///   request open.
///
/// Body size is capped per-fetch by [`read_body_capped`] (reqwest has none).
static FOREIGN_FETCH_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(FOREIGN_FETCH_TIMEOUT)
        .connect_timeout(FOREIGN_FETCH_TIMEOUT)
        .build()
        .expect("hardened foreign-fetch client builds from static config")
});

/// A clone of the shared hardened foreign-fetch client. Use this — never
/// `reqwest::Client::new()` — for any fetch of an attacker-influenceable URL.
pub fn foreign_fetch_client() -> reqwest::Client {
    FOREIGN_FETCH_CLIENT.clone()
}

/// Read a response body into memory, refusing anything larger than `max` bytes.
/// Reads chunk-by-chunk and aborts the moment the cap is crossed — the oversized
/// body is never fully buffered.
pub async fn read_body_capped(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, ForeignFetchError> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ForeignFetchError::Read(e.to_string()))?
    {
        if buf.len() + chunk.len() > max {
            return Err(ForeignFetchError::BodyTooLarge { max });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Refuse a URL that isn't a plain public HTTPS target before fetching it.
///
/// Rejects: non-`https` schemes, embedded userinfo, and IP-literal hosts in
/// loopback / private / link-local / unspecified / multicast / documentation
/// ranges (IPv4) or loopback / unspecified / multicast / ULA `fc00::/7` /
/// link-local `fe80::/10` (IPv6) — including cloud-metadata `169.254.169.254`.
///
/// Reaching an internal service by *DNS name* can't be prevented here without a
/// TOCTOU-prone resolve-at-parse-time; operators behind internal DNS need a
/// network-level egress filter for full protection. This cuts off the
/// bulk-attack vectors.
pub fn guard_public_url(url: &str) -> Result<(), ForeignFetchError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| ForeignFetchError::Blocked(format!("invalid url {url}: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(ForeignFetchError::Blocked(format!(
            "url must be https (got scheme {})",
            parsed.scheme()
        )));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(ForeignFetchError::Blocked(
            "url must not contain userinfo".into(),
        ));
    }
    let host_str = parsed
        .host_str()
        .ok_or_else(|| ForeignFetchError::Blocked("url missing host".into()))?;
    // `host_str()` returns IPv6 hosts bracketed (`[::1]`); strip before parsing.
    // Domain hosts don't parse as an IP and correctly fall through to allow.
    let host_normalised = host_str
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_str);
    if let Ok(ip) = host_normalised.parse::<std::net::IpAddr>() {
        use std::net::IpAddr;
        let private = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    || v4.is_documentation()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (v6.segments()[0] & 0xfe00 == 0xfc00) // ULA fc00::/7
                    || (v6.segments()[0] & 0xffc0 == 0xfe80) // link-local fe80::/10
            }
        };
        if private {
            return Err(ForeignFetchError::Blocked(format!(
                "url points at non-public IP {ip}"
            )));
        }
    }
    Ok(())
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

    #[test]
    fn guard_allows_public_https() {
        guard_public_url("https://example.com/status/list").expect("public https ok");
    }

    #[test]
    fn guard_blocks_plain_http() {
        guard_public_url("http://example.com/status").expect_err("http blocked");
    }

    #[test]
    fn guard_blocks_loopback() {
        guard_public_url("https://127.0.0.1/x").expect_err("loopback blocked");
        guard_public_url("https://127.1/x").expect_err("loopback short form blocked");
    }

    #[test]
    fn guard_blocks_private_v4() {
        guard_public_url("https://10.0.0.1/x").expect_err("10/8 blocked");
        guard_public_url("https://192.168.1.5/x").expect_err("192.168 blocked");
        guard_public_url("https://172.16.0.1/x").expect_err("172.16 blocked");
    }

    #[test]
    fn guard_blocks_cloud_metadata() {
        guard_public_url("https://169.254.169.254/latest/meta-data/")
            .expect_err("link-local metadata blocked");
    }

    #[test]
    fn guard_blocks_v6_internal() {
        guard_public_url("https://[::1]/x").expect_err("v6 loopback blocked");
        guard_public_url("https://[fc00::1]/x").expect_err("v6 ULA blocked");
        guard_public_url("https://[fe80::1]/x").expect_err("v6 link-local blocked");
    }

    #[test]
    fn guard_blocks_userinfo() {
        guard_public_url("https://user:pass@example.com/x").expect_err("userinfo blocked");
    }

    #[test]
    fn guard_blocks_garbage() {
        guard_public_url("not a url").expect_err("garbage blocked");
    }
}
