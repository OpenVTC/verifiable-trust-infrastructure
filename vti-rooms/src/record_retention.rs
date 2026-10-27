//! A room's **record retention** and the prunes made under it (`rooms/records/prune/0.1`,
//! `rooms/records/retention/set/0.1`, `rooms/_shared/0.1` `RecordRetention` and
//! `RecordPrune`; trust-tasks-tf #868).
//!
//! # Two halves, both required
//!
//! The **rule** is the room's: how long it keeps retracted records' tombstones
//! (`tombstoneDays`) and how long it keeps records at all (`recordDays`), by the age a host
//! can measure — `updatedAt`. It is stated in advance and every member can read it
//! (`rooms/info` 0.2). The **act** is an administrator's: a prune, with a reason, which
//! removes only what the rule in force makes eligible at that moment. A host never prunes on
//! its own, on a timer or at a quota.
//!
//! # Not `retentionPolicy`, not `retentionDays`
//!
//! [`crate::RetentionPolicy`] is whether the *key chain* reaches back (fixed at creation);
//! `Room::retention_days` is how long a host keeps a *whole room* after it lapses. This is a
//! third question — how long the room keeps its *records* while it is live — and unlike the
//! first it can change.
//!
//! # What a prune leaves
//!
//! A [`RecordPrune`] mark — the version it took, when, how many — and never which records
//! or what they said. A reader synced below the mark's version rebuilds its copy from a full
//! listing (`rooms/records/list` 0.3 *After a prune*).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{Record, RecordStatus};

/// Seconds in a day, the unit retention is stated in.
const DAY: u64 = 24 * 60 * 60;

/// The room's record retention (`RecordRetention`).
///
/// **Absent, or every member absent, means no record is ever eligible by age** — and that is
/// the reading a host applies whenever it cannot read one: removing data under a rule nobody
/// stated is the failure this exists to prevent. `ext` is kept and echoed as given, and never
/// widens what is eligible.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordRetention {
    /// Days a retracted record's tombstone is kept after its retraction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_days: Option<u32>,
    /// Days a record is kept after it last changed, whatever its standing — pinned records
    /// excepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_days: Option<u32>,
    /// Ecosystem-defined extension members, as given. Never makes more records eligible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Map<String, Value>>,
}

/// The schema's bound on either member: 1 to 36 500 days.
pub const MAX_RETENTION_DAYS: u32 = 36_500;

impl RecordRetention {
    /// Read one from the wire, checked against the schema's bounds. `{}` is a valid
    /// retention that states nothing.
    pub fn from_wire(value: &Value) -> Result<Self, String> {
        let r: Self = serde_json::from_value(value.clone())
            .map_err(|e| format!("`recordRetention` is not a record retention: {e}"))?;
        for (name, days) in [
            ("tombstoneDays", r.tombstone_days),
            ("recordDays", r.record_days),
        ] {
            if let Some(d) = days
                && !(1..=MAX_RETENTION_DAYS).contains(&d)
            {
                return Err(format!(
                    "`recordRetention.{name}` is {d}; it is 1 to {MAX_RETENTION_DAYS} days"
                ));
            }
        }
        Ok(r)
    }

    /// Whether it states no rule at all — `{}`, or `ext` alone.
    pub fn is_empty(&self) -> bool {
        self.tombstone_days.is_none() && self.record_days.is_none()
    }

    /// The retention as the wire carries it: `{}` for none.
    pub fn to_wire(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| Value::Object(Map::new()))
    }

    /// Whether it states a rule for `kind` — `tombstoneDays` for [`PruneKind::Retracted`],
    /// `recordDays` for [`PruneKind::Aged`].
    pub fn states(&self, kind: PruneKind) -> bool {
        match kind {
            PruneKind::Retracted => self.tombstone_days.is_some(),
            PruneKind::Aged => self.record_days.is_some(),
        }
    }

    /// The wire form of an optional retention: absent and `{}` are both "none".
    pub fn wire_of(r: Option<&Self>) -> Value {
        r.map_or_else(|| Value::Object(Map::new()), Self::to_wire)
    }

    /// Compared member by member, `{}` standing for none (`retention/set` item 2).
    pub fn same_as(a: Option<&Self>, b: Option<&Self>) -> bool {
        Self::wire_of(a) == Self::wire_of(b)
    }
}

/// What a prune removes (`rooms/records/prune/0.1` `kinds`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PruneKind {
    /// Retracted records' tombstones older than `tombstoneDays`.
    Retracted,
    /// Records of any standing, pinned ones excepted, older than `recordDays`.
    Aged,
}

impl PruneKind {
    /// The wire value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Retracted => "retracted",
            Self::Aged => "aged",
        }
    }
}

/// Whether `record` is eligible for removal by a prune of `kinds` performed at `now` (unix
/// seconds) under `retention` (`rooms/records/prune/0.1` Conformance item 3) — and decided
/// from these and nothing else.
///
/// - `retracted`: retracted, and its `updatedAt` **more than** `tombstoneDays` days before
///   `now`;
/// - `aged`: **not pinned**, and its `updatedAt` more than `recordDays` days before `now`,
///   whatever its standing.
///
/// A kind the retention states no rule for makes nothing eligible.
pub fn is_eligible(
    record: &Record,
    retention: &RecordRetention,
    kinds: &[PruneKind],
    now: u64,
) -> bool {
    let older_than = |days: u32| now.saturating_sub(record.updated_at) > u64::from(days) * DAY;
    kinds.iter().any(|kind| match kind {
        PruneKind::Retracted => {
            matches!(record.status, RecordStatus::Retracted)
                && retention.tombstone_days.is_some_and(older_than)
        }
        PruneKind::Aged => !record.pinned && retention.record_days.is_some_and(older_than),
    })
}

/// The mark a prune leaves (`RecordPrune`): **that** records were removed, when and how many
/// — never which, never anything they said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordPrune {
    /// The version the prune took from the room's counter. No record carries it; it moves
    /// `headVersion` past the removal.
    pub version: u64,
    /// When the host performed it, unix seconds.
    pub at: u64,
    /// How many records were removed, tombstones included. Never 0: a prune that removed
    /// nothing leaves no mark.
    pub removed: u64,
}

impl RecordPrune {
    /// The wire form: `at` as RFC 3339, as every timestamp on the wire is.
    pub fn to_wire(&self) -> Value {
        serde_json::json!({
            "version": self.version,
            "at": crate::rfc3339(self.at),
            "removed": self.removed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: u64 = 20_000 * DAY;

    fn record(status: RecordStatus, pinned: bool, age_days: u64) -> Record {
        Record {
            key: "k".into(),
            version: 1,
            epoch: None,
            status,
            pinned,
            sealed: None,
            nonce: None,
            sealed_version: None,
            cleartext: None,
            author: None,
            updated_at: NOW - age_days * DAY,
        }
    }

    fn retention(tombstone: Option<u32>, records: Option<u32>) -> RecordRetention {
        RecordRetention {
            tombstone_days: tombstone,
            record_days: records,
            ext: None,
        }
    }

    /// Item 3: "more than" — a tombstone exactly `tombstoneDays` old is kept.
    #[test]
    fn a_tombstone_is_eligible_only_once_older_than_its_days() {
        let r = retention(Some(30), None);
        let k = [PruneKind::Retracted];
        assert!(!is_eligible(
            &record(RecordStatus::Retracted, false, 30),
            &r,
            &k,
            NOW
        ));
        let mut just_over = record(RecordStatus::Retracted, false, 30);
        just_over.updated_at -= 1;
        assert!(is_eligible(&just_over, &r, &k, NOW));
        // Active records are never tombstones.
        assert!(!is_eligible(
            &record(RecordStatus::Active, false, 99),
            &r,
            &k,
            NOW
        ));
        // A pinned tombstone still goes as a tombstone.
        assert!(is_eligible(
            &record(RecordStatus::Retracted, true, 31),
            &r,
            &k,
            NOW
        ));
    }

    /// `aged` takes any standing but never a pinned record.
    #[test]
    fn aged_takes_every_standing_but_pinned() {
        let r = retention(None, Some(365));
        let k = [PruneKind::Aged];
        for status in [
            RecordStatus::Active,
            RecordStatus::Deprecated,
            RecordStatus::Retracted,
        ] {
            assert!(is_eligible(&record(status, false, 366), &r, &k, NOW));
            assert!(!is_eligible(&record(status, true, 366), &r, &k, NOW));
            assert!(!is_eligible(&record(status, false, 365), &r, &k, NOW));
        }
    }

    /// A kind the retention states no rule for makes nothing eligible; absent is none.
    #[test]
    fn no_rule_no_eligibility() {
        let old = record(RecordStatus::Retracted, false, 9_999);
        let none = RecordRetention::default();
        assert!(none.is_empty());
        for k in [[PruneKind::Retracted], [PruneKind::Aged]] {
            assert!(!is_eligible(&old, &none, &k, NOW));
        }
        assert!(!is_eligible(
            &old,
            &retention(Some(1), None),
            &[PruneKind::Aged],
            NOW
        ));
        // A retracted record past `recordDays` is eligible as `aged`, never as `retracted`
        // when no `tombstoneDays` is stated.
        assert!(!is_eligible(
            &old,
            &retention(None, Some(1)),
            &[PruneKind::Retracted],
            NOW
        ));
        assert!(is_eligible(
            &old,
            &retention(None, Some(1)),
            &[PruneKind::Aged],
            NOW
        ));
    }

    #[test]
    fn the_wire_form_is_the_schemas() {
        let r =
            RecordRetention::from_wire(&json!({ "tombstoneDays": 30, "recordDays": 730 })).unwrap();
        assert_eq!(
            r.to_wire(),
            json!({ "tombstoneDays": 30, "recordDays": 730 })
        );
        assert!(RecordRetention::from_wire(&json!({ "tombstoneDays": 0 })).is_err());
        assert!(RecordRetention::from_wire(&json!({ "recordDays": 36_501 })).is_err());
        assert!(RecordRetention::from_wire(&json!({ "days": 3 })).is_err());
        assert!(RecordRetention::same_as(
            None,
            Some(&RecordRetention::default())
        ));
        let mark = RecordPrune {
            version: 413,
            at: 0,
            removed: 14,
        };
        assert_eq!(
            mark.to_wire(),
            json!({ "version": 413, "at": "1970-01-01T00:00:00Z", "removed": 14 })
        );
    }
}
