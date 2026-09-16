//! Rate-limit attribution: which service refused a request, how long to wait,
//! and which knob to turn.
//!
//! A `429` is not a server fault, and "the VTA rate-limited you" is not the only
//! way to get one. A request from a VTA client can be refused by the VTA's own
//! limiter, by a reverse proxy or load balancer in front of it, by the DIDComm
//! mediator, or by a DID host while resolving a `did:webvh`. Each is tuned in a
//! different place, and an operator who cannot tell them apart tunes the wrong
//! one — or reads a `429` as the service being down.
//!
//! [`crate::error::VtaError::RateLimited`] carries the attribution as a
//! [`RateLimitSource`]. This module owns everything that attribution needs:
//! the header contract, `Retry-After` parsing, and — deliberately in one place,
//! so a renamed config key is a one-line change — the names of the knobs the
//! operator guidance points at.
//!
//! # The attribution contract
//!
//! A VTA marks every `429` its own limiter emits with
//! [`SOURCE_HEADER`]`: vta` and a `Retry-After` in seconds. A `429` *without*
//! that header, received from a VTA URL, is unattributable: a proxy or load
//! balancer in front of the VTA, or a VTA older than the header. The client
//! reports that honestly as [`RateLimitSource::Upstream`] rather than guessing.

use chrono::{DateTime, Utc};

/// Response header naming the service whose limiter refused the request.
///
/// Values: `vta`, `vtc`, `mediator`, `did-host`. Absent, or any other value,
/// reads as [`RateLimitSource::Upstream`].
pub const SOURCE_HEADER: &str = "x-rate-limit-source";

/// Standard `Retry-After` (RFC 9110 §10.2.3): delta-seconds or an HTTP-date.
pub const RETRY_AFTER_HEADER: &str = "retry-after";

/// `tower-governor`'s own wait hint, in seconds. Sent by VTAs that predate
/// [`SOURCE_HEADER`]; read only when `Retry-After` is absent.
pub const LEGACY_RETRY_AFTER_HEADER: &str = "x-ratelimit-after";

/// Which service's rate limiter refused the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RateLimitSource {
    /// The VTA's own limiter (labelled with [`SOURCE_HEADER`]`: vta`).
    Vta,
    /// A VTC's limiter (labelled `vtc`). Kept distinct from [`Self::Vta`]: the
    /// VTC is a different service with a different audience and different
    /// knobs, and the SDK's auth helpers are used against both.
    Vtc,
    /// The DIDComm / TSP mediator.
    Mediator,
    /// A DID host (e.g. `did-hosting-control`, or the host serving a
    /// `did:webvh` log during resolution).
    DidHost,
    /// Unattributable: the `429` carried no recognised [`SOURCE_HEADER`]. A
    /// reverse proxy / load balancer in front of the service, or a service old
    /// enough not to label its limits.
    Upstream,
}

impl RateLimitSource {
    /// Read [`SOURCE_HEADER`]. Absent or unrecognised is
    /// [`Self::Upstream`] — the one answer that does not claim to know more
    /// than the response said.
    #[must_use]
    pub fn from_source_header(value: Option<&str>) -> Self {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("vta") => Self::Vta,
            Some("vtc") => Self::Vtc,
            Some("mediator") => Self::Mediator,
            Some("did-host") => Self::DidHost,
            _ => Self::Upstream,
        }
    }

    /// Human label for the refusing party, used in error messages.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Vta => "the VTA",
            Self::Vtc => "the VTC",
            Self::Mediator => "the mediator",
            Self::DidHost => "the DID host",
            Self::Upstream => "an unidentified service (proxy, load balancer, or older VTA)",
        }
    }
}

impl std::fmt::Display for RateLimitSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Parse a `Retry-After` value into an absolute instant.
///
/// Accepts both RFC 9110 forms: delta-seconds (`"4"`) and an HTTP-date
/// (`"Wed, 21 Oct 2015 07:28:00 GMT"`). Anything else is `None` — an
/// unparseable hint is no hint, not an error.
///
/// Absolute rather than a `Duration` to match
/// [`crate::error::VtaError::Unavailable`], so the retry owner treats both hints
/// the same way; `now` is a parameter so the conversion is testable.
#[must_use]
pub fn parse_retry_after(value: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        // Clamp before converting: a hostile `u64::MAX` must not overflow.
        let secs = i64::try_from(secs).unwrap_or(i64::MAX).min(86_400 * 365);
        return now.checked_add_signed(chrono::Duration::seconds(secs));
    }
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

// ── Operator guidance ───────────────────────────────────────────────
//
// Every config key, CLI flag and doc path the rate-limit guidance names lives
// here, once. `macro_rules!` rather than `const` because the SDK's
// `suggested_fix` returns `&'static str` and so has to be built with
// `concat!`, which only takes literals; the `pub const`s re-expose the same
// literals for the CLI renderer, which substitutes the binary name.

macro_rules! vta_interval_key {
    () => {
        "rate_limit_interval_secs"
    };
}
macro_rules! vta_burst_key {
    () => {
        "rate_limit_burst"
    };
}
macro_rules! vta_did_log_interval_key {
    () => {
        "did_log_rate_limit_interval_secs"
    };
}
macro_rules! vta_did_log_burst_key {
    () => {
        "did_log_rate_limit_burst"
    };
}
macro_rules! vta_trust_xff_key {
    () => {
        "trust_xff"
    };
}
macro_rules! vta_docs {
    () => {
        "docs/02-vta/rate-limiting.md"
    };
}
macro_rules! mediator_keys {
    () => {
        "`[limits] rate_limit_per_ip` / `rate_limit_burst` (per client IP), \
         `did_rate_limit_per_second` / `did_rate_limit_burst` (per DID)"
    };
}

/// VTA `[server]` key: seconds per token for the auth / bootstrap limiter.
pub const VTA_INTERVAL_KEY: &str = vta_interval_key!();
/// VTA `[server]` key: burst for the auth / bootstrap limiter.
pub const VTA_BURST_KEY: &str = vta_burst_key!();
/// VTA `[server]` key: seconds per token for the limiter on the VTA's own
/// `did.jsonl`.
pub const VTA_DID_LOG_INTERVAL_KEY: &str = vta_did_log_interval_key!();
/// VTA `[server]` key: burst for the limiter on the VTA's own `did.jsonl`.
pub const VTA_DID_LOG_BURST_KEY: &str = vta_did_log_burst_key!();
/// VTA `[server]` key that decides whether the limiter keys on
/// `X-Forwarded-For` (behind a proxy) or on the TCP peer.
pub const VTA_TRUST_XFF_KEY: &str = vta_trust_xff_key!();
/// Operator guide for the VTA's limiters.
pub const VTA_DOCS: &str = vta_docs!();
/// `config update` flags that retune the VTA's auth / bootstrap limiter at
/// runtime, without the binary name.
pub const VTA_RUNTIME_FLAGS: &str =
    "config update --rate-limit-interval-secs <N> --rate-limit-burst <N>";
/// `config update` flags that retune the VTA's `did.jsonl` limiter at runtime.
pub const VTA_DID_LOG_RUNTIME_FLAGS: &str =
    "config update --did-log-rate-limit-interval-secs <N> --did-log-rate-limit-burst <N>";
/// The mediator's limiter keys.
pub const MEDIATOR_KEYS: &str = mediator_keys!();

/// The static hint for a refusal from `source`. Backs
/// [`crate::error::VtaError::suggested_fix`]; the CLI renders a richer,
/// binary-aware version from the constants above.
#[must_use]
pub fn suggested_fix(source: RateLimitSource) -> &'static str {
    match source {
        RateLimitSource::Vta => concat!(
            "The VTA's own rate limiter refused this request — the VTA is not down. Wait \
             for the retry-after period and try again. To loosen it, raise `[server] ",
            vta_burst_key!(),
            "` or lower `",
            vta_interval_key!(),
            "` (seconds per token: lower is looser) for the auth / bootstrap endpoints, or `",
            vta_did_log_interval_key!(),
            "` / `",
            vta_did_log_burst_key!(),
            "` for the VTA's own did.jsonl; at runtime use `config update`. Behind a reverse \
             proxy with `",
            vta_trust_xff_key!(),
            " = false` every client shares one bucket. See ",
            vta_docs!(),
            "."
        ),
        RateLimitSource::Vtc => {
            "The VTC's rate limiter refused this request — the VTC is not down. Wait for the \
             retry-after period and try again. The VTC's unauthenticated-route limiter is not \
             configurable; behind a proxy, check the VTC's trust_xff setting so clients do not \
             share one bucket."
        }
        RateLimitSource::Mediator => concat!(
            "The DIDComm/TSP mediator rate-limited this request — neither it nor the VTA is \
             down. Wait and retry. The mediator operator tunes ",
            mediator_keys!(),
            "; those are requests per second, so higher is looser."
        ),
        RateLimitSource::DidHost => {
            "A DID host rate-limited this request (e.g. while resolving a did:webvh, or \
             did-hosting-control's per-IP challenge limit). It is not tunable from the VTA: wait \
             and retry, or ask the host's operator."
        }
        RateLimitSource::Upstream => concat!(
            "A 429 arrived without an `x-rate-limit-source` header, so the SDK cannot say who \
             sent it: a reverse proxy or load balancer in front of the service, or a VTA older \
             than the header. Check the proxy / load balancer's limits and logs, or upgrade the \
             VTA so its own refusals are labelled. See ",
            vta_docs!(),
            "."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn source_header_is_read_case_insensitively_and_absent_is_upstream() {
        assert_eq!(
            RateLimitSource::from_source_header(Some("vta")),
            RateLimitSource::Vta
        );
        assert_eq!(
            RateLimitSource::from_source_header(Some(" VTA ")),
            RateLimitSource::Vta
        );
        assert_eq!(
            RateLimitSource::from_source_header(Some("vtc")),
            RateLimitSource::Vtc
        );
        assert_eq!(
            RateLimitSource::from_source_header(Some("mediator")),
            RateLimitSource::Mediator
        );
        assert_eq!(
            RateLimitSource::from_source_header(Some("did-host")),
            RateLimitSource::DidHost
        );
        assert_eq!(
            RateLimitSource::from_source_header(None),
            RateLimitSource::Upstream
        );
        assert_eq!(
            RateLimitSource::from_source_header(Some("nginx")),
            RateLimitSource::Upstream,
            "an unknown label must not be promoted to a service we can name"
        );
    }

    #[test]
    fn retry_after_delta_seconds() {
        let now = at("2026-09-16T12:00:00Z");
        assert_eq!(
            parse_retry_after("4", now),
            Some(at("2026-09-16T12:00:04Z"))
        );
        assert_eq!(parse_retry_after(" 0 ", now), Some(now));
    }

    #[test]
    fn retry_after_http_date() {
        let now = at("2026-09-16T12:00:00Z");
        assert_eq!(
            parse_retry_after("Wed, 16 Sep 2026 12:00:30 GMT", now),
            Some(at("2026-09-16T12:00:30Z"))
        );
    }

    #[test]
    fn retry_after_garbage_and_hostile_values() {
        let now = at("2026-09-16T12:00:00Z");
        assert_eq!(parse_retry_after("soon", now), None);
        assert_eq!(parse_retry_after("-3", now), None);
        // Must not panic or overflow.
        assert!(parse_retry_after(&u64::MAX.to_string(), now).is_some());
    }

    #[test]
    fn every_source_has_a_hint_naming_where_to_look() {
        let vta = suggested_fix(RateLimitSource::Vta);
        for needle in [
            VTA_INTERVAL_KEY,
            VTA_BURST_KEY,
            VTA_DID_LOG_INTERVAL_KEY,
            VTA_DID_LOG_BURST_KEY,
            VTA_TRUST_XFF_KEY,
            VTA_DOCS,
            "lower is looser",
        ] {
            assert!(
                vta.contains(needle),
                "VTA hint must mention {needle}: {vta}"
            );
        }
        assert!(suggested_fix(RateLimitSource::Mediator).contains(MEDIATOR_KEYS));
        assert!(suggested_fix(RateLimitSource::Upstream).contains(SOURCE_HEADER));
        assert!(suggested_fix(RateLimitSource::DidHost).contains("not tunable"));
        assert!(suggested_fix(RateLimitSource::Vtc).contains("VTC"));
    }
}
