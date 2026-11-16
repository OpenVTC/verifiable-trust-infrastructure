//! Reading a generated Trust Task payload's members as this crate's own types.
//!
//! The operations take the generated `vti_specs` payloads (#2574), whose enum
//! and string members are their own types (`PayloadRole`, `PayloadStatus`, …).
//! Where an operation works in a domain type with the same wire form
//! (`VtcRole`, `JoinStatus`, `Disposition`), the member is read through that
//! wire form — never by a second, hand-written payload struct.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::AppError;

/// `value` read as `T` through their shared wire form. `field` names the
/// member in the refusal when the two disagree — which a schema-checked
/// payload makes a programming error, not a caller's.
pub(crate) fn read_as<T: DeserializeOwned>(
    field: &str,
    value: &impl Serialize,
) -> Result<T, AppError> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(|e| AppError::Validation(format!("{field}: {e}")))
}

/// `value` — a member the generated type defaults when absent — only if the
/// received document carried it (`payload` is the payload as received).
///
/// Some generated members fold "absent" and "empty" into one default (an
/// object member with `default`), where the operation keeps them apart: an
/// absent `extensions` leaves a member's extensions as they are, an empty one
/// replaces them. Only the JSON shows which was sent (root `CLAUDE.md`: read
/// received JSON before trusting a generated parse).
pub(crate) fn sent<T>(payload: &serde_json::Value, member: &str, value: T) -> Option<T> {
    payload.get(member).map(|_| value)
}

/// [`read_as`] for an optional member.
pub(crate) fn read_opt<T: DeserializeOwned>(
    field: &str,
    value: Option<&impl Serialize>,
) -> Result<Option<T>, AppError> {
    value.map(|v| read_as(field, v)).transpose()
}

/// A generated `limit` (`1..`, when given) as a page size: `default` when
/// absent, clamped to `1..=max`.
pub(crate) fn page_limit(limit: Option<std::num::NonZeroU64>, default: usize, max: usize) -> usize {
    limit
        .map_or(default, |l| usize::try_from(l.get()).unwrap_or(max))
        .clamp(1, max)
}
