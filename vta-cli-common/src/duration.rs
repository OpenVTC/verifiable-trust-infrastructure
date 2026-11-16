//! Short duration parsing for CLI flags like `--admin-expires 7d`, plus
//! user-facing display helpers.
//!
//! Internally we always store and transmit times as **UTC unix-epoch
//! seconds**. Anything shown to the operator is converted to their local
//! timezone for readability.
//!
//! Duration parsing accepts `N[s|m|h|d|w]` — seconds, minutes, hours,
//! days, weeks — or a plain integer which is interpreted as seconds.
//! Whitespace is trimmed.

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, Utc};

/// Parse a duration string into seconds.
///
/// Recognised suffixes: `s` (seconds), `m` (minutes), `h` (hours),
/// `d` (days), `w` (weeks). An unsuffixed value is seconds.
///
/// Examples: `"30s" → 30`, `"5m" → 300`, `"24h" → 86400`, `"7d" → 604800`,
/// `"2w" → 1209600`, `"3600" → 3600`.
pub fn parse_duration_secs(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration value".into());
    }
    let (num_str, mult) = match s.as_bytes().last().copied() {
        Some(b's') => (&s[..s.len() - 1], 1u64),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        Some(b'd') => (&s[..s.len() - 1], 86_400),
        Some(b'w') => (&s[..s.len() - 1], 604_800),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return Err(format!("invalid duration '{s}' (use N[s|m|h|d|w])").into()),
    };
    let n: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration number in '{s}'"))?;
    if n == 0 {
        return Err("duration must be positive".into());
    }
    Ok(n.saturating_mul(mult))
}

/// A clap `value_parser` for a flag measured in seconds (#2589): `N[s|m|h|d|w]`,
/// or a bare integer, which stays seconds — so every existing `--ttl 900`
/// still means what it did, and `--ttl 15m` now works too. `0` is accepted
/// (some flags give it a meaning, e.g. an immediate drain).
///
/// ```
/// # use vta_cli_common::duration::secs_arg;
/// assert_eq!(secs_arg("900"), Ok(900));
/// assert_eq!(secs_arg("15m"), Ok(900));
/// assert_eq!(secs_arg("0"), Ok(0));
/// assert!(secs_arg("15x").is_err());
/// ```
pub fn secs_arg(s: &str) -> Result<u64, String> {
    if s.trim() == "0" {
        return Ok(0);
    }
    parse_duration_secs(s).map_err(|e| e.to_string())
}

/// [`secs_arg`] for a `u32` flag.
pub fn secs_arg_u32(s: &str) -> Result<u32, String> {
    let n = secs_arg(s)?;
    u32::try_from(n).map_err(|_| format!("{s} is too long ({n} seconds)"))
}

/// [`secs_arg`] for an `i64` flag.
pub fn secs_arg_i64(s: &str) -> Result<i64, String> {
    let n = secs_arg(s)?;
    i64::try_from(n).map_err(|_| format!("{s} is too long ({n} seconds)"))
}

/// Parse a duration and return the absolute unix-epoch expiry time
/// (`now + duration`).
pub fn duration_to_expires_at(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let secs = parse_duration_secs(s)?;
    let now = now_unix();
    Ok(now.saturating_add(secs))
}

/// Current unix-epoch seconds (UTC, monotonic with the system wall clock).
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a unix-epoch seconds value as a readable local-timezone string
/// with an ISO-style offset, suitable for operator-facing output.
///
/// Example: `2026-04-20 15:32:17 +08:00`.
pub fn format_local_time(unix_secs: u64) -> String {
    match DateTime::from_timestamp(unix_secs as i64, 0) {
        Some(utc) => format_local_datetime(utc),
        None => unix_secs.to_string(),
    }
}

/// Format a `DateTime<Utc>` (the protocol-level wire format) as a readable
/// local-timezone string with an ISO-style offset.
///
/// Example: `2026-04-20 15:32:17 +08:00`.
pub fn format_local_datetime(dt: DateTime<Utc>) -> String {
    dt.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

/// Format a relative-time string showing how long until `unix_secs` from
/// `now_unix()`. Handles both future (`in 1h 0m`) and past (`expired 5m
/// ago`) cases. Picks the largest sensible unit pair and rounds toward
/// the nearest integer in each.
///
/// Uses full seconds internally so small intervals (a few minutes or
/// less) don't collapse to "0h" via truncating integer division.
pub fn format_remaining(unix_secs: u64) -> String {
    let now = now_unix();
    let (secs, expired) = if unix_secs >= now {
        (unix_secs - now, false)
    } else {
        (now - unix_secs, true)
    };

    let pretty = humanize_duration(secs);
    if expired {
        format!("expired {pretty} ago")
    } else {
        format!("in {pretty}")
    }
}

/// Format a duration in seconds as a compact two-part human string:
/// "1h 30m", "5d 12h", "45s", "0s". Picks the largest unit that fits
/// and adds one smaller unit when it helps readability.
pub fn humanize_duration(secs: u64) -> String {
    const MIN: u64 = 60;
    const HOUR: u64 = 60 * MIN;
    const DAY: u64 = 24 * HOUR;
    const WEEK: u64 = 7 * DAY;

    if secs >= WEEK {
        let weeks = secs / WEEK;
        let days = (secs % WEEK) / DAY;
        if days == 0 {
            format!("{weeks}w")
        } else {
            format!("{weeks}w {days}d")
        }
    } else if secs >= DAY {
        let days = secs / DAY;
        let hours = (secs % DAY) / HOUR;
        if hours == 0 {
            format!("{days}d")
        } else {
            format!("{days}d {hours}h")
        }
    } else if secs >= HOUR {
        let hours = secs / HOUR;
        let mins = (secs % HOUR) / MIN;
        if mins == 0 {
            format!("{hours}h")
        } else {
            format!("{hours}h {mins}m")
        }
    } else if secs >= MIN {
        let mins = secs / MIN;
        let s = secs % MIN;
        if s == 0 {
            format!("{mins}m")
        } else {
            format!("{mins}m {s}s")
        }
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_unit() {
        assert_eq!(parse_duration_secs("30s").unwrap(), 30);
        assert_eq!(parse_duration_secs("5m").unwrap(), 300);
        assert_eq!(parse_duration_secs("2h").unwrap(), 7200);
        assert_eq!(parse_duration_secs("7d").unwrap(), 604_800);
        assert_eq!(parse_duration_secs("2w").unwrap(), 1_209_600);
        assert_eq!(parse_duration_secs("3600").unwrap(), 3600);
        assert_eq!(parse_duration_secs("  24h  ").unwrap(), 86_400);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_duration_secs("").is_err());
        assert!(parse_duration_secs("abc").is_err());
        assert!(parse_duration_secs("7x").is_err());
        assert!(parse_duration_secs("0h").is_err());
    }

    #[test]
    fn expiry_is_in_the_future() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = duration_to_expires_at("60s").unwrap();
        assert!(expiry >= before + 60);
        assert!(expiry <= before + 65);
    }

    #[test]
    fn humanize_picks_the_right_unit_pair() {
        assert_eq!(humanize_duration(0), "0s");
        assert_eq!(humanize_duration(45), "45s");
        assert_eq!(humanize_duration(60), "1m");
        assert_eq!(humanize_duration(125), "2m 5s");
        assert_eq!(humanize_duration(3600), "1h");
        assert_eq!(humanize_duration(3660), "1h 1m");
        assert_eq!(humanize_duration(86400), "1d");
        assert_eq!(humanize_duration(90000), "1d 1h");
        assert_eq!(humanize_duration(604_800), "1w");
        assert_eq!(humanize_duration(691_200), "1w 1d");
    }

    #[test]
    fn format_remaining_handles_future_and_past() {
        let now = now_unix();
        assert!(format_remaining(now + 3600).starts_with("in "));
        assert!(format_remaining(now - 3600).starts_with("expired "));
        assert!(format_remaining(now - 3600).ends_with("ago"));
    }

    #[test]
    fn format_local_time_is_nonempty() {
        let s = format_local_time(1776600737);
        assert!(s.len() > 10, "unexpectedly short: {s}");
        // Should contain a colon from HH:MM:SS
        assert!(s.contains(':'));
    }
}
