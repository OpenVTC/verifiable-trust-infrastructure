//! Shared did:webvh versionTime policy.

/// A synthetic, strictly-increasing, backdated `versionTime` for the VTA's next
/// did:webvh log entry. did:webvh serialises `versionTime` at second granularity
/// and requires each entry to be strictly later than the previous and not in the
/// future; the real wall-clock value is irrelevant for resolution. We backdate a
/// day and space entries a minute apart by their index, so the VTA can create
/// then update its DID back-to-back (e.g. `setup` then `services didcomm enable`)
/// without producing same-second timestamps that serialise identically and make
/// the DID unresolvable. `existing_entry_count` is the number of log entries
/// already in the chain (0 for the genesis entry).
pub fn backdated_version_time(
    existing_entry_count: usize,
) -> chrono::DateTime<chrono::FixedOffset> {
    use chrono::{Duration, Utc};
    Utc::now().fixed_offset() - Duration::days(1) + Duration::minutes(existing_entry_count as i64)
}

#[cfg(test)]
mod tests {
    use super::backdated_version_time;
    use chrono::Utc;

    /// `backdated_version_time` must yield timestamps that are (a) in
    /// the past (did:webvh rejects future `versionTime`) and (b)
    /// strictly increasing by entry index at *second* granularity, so
    /// a genesis-create and a follow-on update minted in the same
    /// wall-clock second don't collide. This is the helper behind the
    /// `services didcomm enable`-right-after-`setup` fix (PR #600).
    #[test]
    fn backdated_version_time_is_past_and_strictly_increasing() {
        let now = Utc::now();

        let t0 = backdated_version_time(0);
        let t1 = backdated_version_time(1);
        let t2 = backdated_version_time(2);

        // Backdated — comfortably in the past (roughly a day).
        assert!(
            t0 < now.fixed_offset(),
            "genesis timestamp must be in the past"
        );
        assert!(
            t2 < now.fixed_offset(),
            "later timestamps must still be in the past"
        );

        // Strictly increasing by index …
        assert!(t0 < t1, "entry 1 must be strictly after entry 0");
        assert!(t1 < t2, "entry 2 must be strictly after entry 1");

        // … and distinct even after did:webvh's second-granularity
        // truncation — index spacing (a minute apart) guarantees a
        // whole-second gap, which is what the same-second collision
        // needed. Compare truncated-to-second Unix timestamps.
        assert_ne!(
            t0.timestamp(),
            t1.timestamp(),
            "entries must differ at second precision"
        );
        assert_ne!(t1.timestamp(), t2.timestamp());
    }
}
