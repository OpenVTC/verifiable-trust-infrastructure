//! Shared did:webvh `versionTime` policy.
//!
//! `did:webvh` serialises `versionTime` at whole-second granularity, and a
//! resolver rejects a log entry whose timestamp is in the future or is not
//! strictly later than the previous entry's
//! (`didwebvh-rs::log_entry::read::verify_version_time`).
//!
//! Neither check runs when an entry is *written*: `create_log_entry` signs and
//! appends whatever timestamp it is handed. A bad one is therefore discovered
//! only at resolution — by which point the log is append-only, no later entry
//! can repair it, and the DID is permanently unresolvable. That is the whole
//! reason this policy is centralised here rather than open-coded at each
//! builder: a call site that gets it wrong does not fail, it bricks an
//! identity.
//!
//! Every `versionTime` this workspace stamps goes through
//! [`next_version_time`].

use chrono::{DateTime, Duration, FixedOffset, Timelike, Utc};

/// How far in the past a chain's first entry is stamped.
///
/// A whole day of headroom, so a VTA can create then update its DID
/// back-to-back (`setup`, then `services didcomm enable`) without the two
/// entries landing in the same second and serialising identically.
const BACKDATE_DAYS: i64 = 1;

/// Spacing between consecutive entries, by index.
///
/// A minute rather than a second so that a backwards clock step smaller than
/// a minute — an NTP correction on the host a Nitro enclave took its clock
/// from, say — cannot make entry N+1 land at or before entry N.
const SPACING_MINUTES: i64 = 1;

/// Ceiling on the index-derived offset.
///
/// Without it the offset eventually overtakes the backdate and the timestamp
/// lands in the *future*, which a resolver rejects just as firmly as a
/// non-increasing one — the same brick, approached from the other side. One
/// minute short of the backdate keeps the result strictly in the past at
/// every index; past the ceiling, strict increase is carried by the
/// previous-entry clamp in [`next_version_time`] instead of by the index.
const MAX_OFFSET_MINUTES: i64 = BACKDATE_DAYS * 24 * 60 - SPACING_MINUTES;

/// The `versionTime` to stamp on the next did:webvh log entry of a chain.
///
/// `existing_entry_count` is the number of entries already in the chain (0 for
/// genesis). `previous` is the preceding entry's `versionTime`, or `None` for
/// genesis.
///
/// The result is always strictly later than `previous`, and — except in the
/// narrow case below — comfortably in the past.
///
/// **Always pass `previous` when the chain has entries.** The index alone is
/// not enough: it assumes every earlier entry was stamped by this same policy.
/// A chain whose genesis carries a real wall-clock timestamp (a TEE VTA
/// provisioned before the genesis path was fixed, or any log minted by another
/// implementation) would otherwise get a *backdated* second entry, i.e. one
/// earlier than its genesis, and be bricked by the very helper meant to
/// prevent that.
///
/// The one case where the result may be in the future is a chain whose
/// previous entry is stamped within the last second — only reachable on a log
/// not stamped by this policy. `previous + 1s` is still the right answer
/// there: a timestamp a second ahead is rejected until the clock reaches it
/// and then resolves forever, whereas a non-increasing one is fatal and
/// permanent. Transient beats terminal.
pub fn next_version_time(
    existing_entry_count: usize,
    previous: Option<DateTime<FixedOffset>>,
) -> DateTime<FixedOffset> {
    // Work in whole seconds throughout, because that is the only precision
    // that survives serialisation. Comparing the sub-second values would let
    // two entries a few microseconds apart look strictly increasing here and
    // serialise to the identical timestamp on the wire — which is the exact
    // collision this helper exists to prevent.
    let now = truncate_to_second(Utc::now().fixed_offset());

    let offset_minutes = i64::try_from(existing_entry_count)
        .unwrap_or(i64::MAX)
        .saturating_mul(SPACING_MINUTES)
        .min(MAX_OFFSET_MINUTES);
    let backdated = now - Duration::days(BACKDATE_DAYS) + Duration::minutes(offset_minutes);

    match previous.map(truncate_to_second) {
        // Strict increase is the invariant that must not bend; the backdate is
        // only a means to it. Where they conflict, the clamp wins.
        Some(prev) if backdated <= prev => prev + Duration::seconds(1),
        _ => backdated,
    }
}

/// Drop sub-second precision, matching what `did:webvh` serialises.
fn truncate_to_second(t: DateTime<FixedOffset>) -> DateTime<FixedOffset> {
    t.with_nanosecond(0)
        .expect("zero is always a valid nanosecond")
}

#[cfg(test)]
mod tests {
    use super::{MAX_OFFSET_MINUTES, next_version_time};
    use chrono::{Duration, Utc};

    /// `next_version_time` must yield timestamps that are (a) in
    /// the past (did:webvh rejects future `versionTime`) and (b)
    /// strictly increasing by entry index at *second* granularity, so
    /// a genesis-create and a follow-on update minted in the same
    /// wall-clock second don't collide. This is the helper behind the
    /// `services didcomm enable`-right-after-`setup` fix (PR #600).
    #[test]
    fn is_past_and_strictly_increasing() {
        let now = Utc::now();

        let t0 = next_version_time(0, None);
        let t1 = next_version_time(1, None);
        let t2 = next_version_time(2, None);

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

    /// A chain whose previous entry was **not** stamped by this policy —
    /// a TEE VTA provisioned before the genesis path was fixed carries a
    /// real `Utc::now()` genesis — must still get a strictly later
    /// timestamp for its next entry. Backdating blindly here is what
    /// bricked those DIDs on their first update: `didwebvh-rs` does not
    /// check monotonicity at write time, so the entry is signed, appended
    /// and published before anyone finds out.
    #[test]
    fn clamps_against_a_non_backdated_previous_entry() {
        let genesis = Utc::now().fixed_offset() - Duration::seconds(30);

        let next = next_version_time(1, Some(genesis));

        assert!(
            next > genesis,
            "entry after a wall-clock genesis must be strictly later: \
             next={next}, genesis={genesis}"
        );
        assert_ne!(
            next.timestamp(),
            genesis.timestamp(),
            "must also differ after second-granularity truncation"
        );
    }

    /// The clamp must survive a run of entries on such a chain, not just
    /// the first one — each subsequent entry keeps clamping off its
    /// predecessor rather than falling back to the backdated value.
    #[test]
    fn stays_increasing_across_a_run_after_a_clamp() {
        let mut prev = Utc::now().fixed_offset() - Duration::seconds(5);

        for index in 1..=5 {
            let next = next_version_time(index, Some(prev));
            assert!(
                next > prev,
                "entry {index} must be strictly after its predecessor"
            );
            assert_ne!(next.timestamp(), prev.timestamp());
            prev = next;
        }
    }

    /// Past the offset ceiling the timestamp must stay in the past. Without
    /// the cap, `now - 1 day + N minutes` overtakes `now` at N = 1440 and the
    /// entry is rejected as future-dated — the same unresolvable DID, reached
    /// from the other direction, and arriving silently at write time.
    #[test]
    fn saturates_instead_of_drifting_into_the_future() {
        let long_chain = usize::try_from(MAX_OFFSET_MINUTES).unwrap() * 10;

        for count in [
            usize::try_from(MAX_OFFSET_MINUTES).unwrap(),
            usize::try_from(MAX_OFFSET_MINUTES).unwrap() + 1,
            long_chain,
            usize::MAX,
        ] {
            let t = next_version_time(count, None);
            assert!(
                t < Utc::now().fixed_offset(),
                "entry {count} must still be in the past, got {t}"
            );
        }
    }

    /// Saturation must not cost strict increase: once two adjacent indices
    /// clamp to the same offset, the previous-entry clamp has to carry the
    /// invariant instead — and it has to carry it at *second* granularity.
    ///
    /// This case caught a real defect while this helper was being written. The
    /// clamp originally compared full-precision timestamps, so two saturated
    /// entries computed microseconds apart compared as strictly increasing,
    /// took the un-clamped path, and then serialised to the same second. The
    /// assertion that fails without the fix is the `timestamp()` one, not the
    /// ordering one — which is precisely why both are here.
    #[test]
    fn saturated_entries_are_still_strictly_increasing() {
        let count = usize::try_from(MAX_OFFSET_MINUTES).unwrap() + 1;

        let prev = next_version_time(count, None);
        let next = next_version_time(count + 1, Some(prev));

        assert!(next > prev, "saturated entries must still increase");
        assert_ne!(next.timestamp(), prev.timestamp());
    }
}
