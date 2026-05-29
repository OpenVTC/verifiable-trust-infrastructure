//! Random-with-decoys slot allocator + bit-flip helpers.
//!
//! Spec §6.2 requires:
//!
//! - **Random allocation** so the slot index can't be
//!   correlated with credential issuance order.
//! - **Decoys** flipped on unassigned slots so external
//!   verifiers can't infer occupancy from the bitstring's
//!   Hamming weight.
//! - **Flipped indices never reallocated** so a departing
//!   member's slot index can't be reused to correlate the
//!   new holder with the departed one.
//!
//! The allocator works against a [`StatusListState`] passed by
//! `&mut`: the caller is responsible for persisting the row
//! after a mutation (the storage layer doesn't auto-write on
//! every operation; that's the route handler's job, ideally
//! inside the same fjall transaction as the credential row).
//!
//! Allocation uses a uniform RNG over the unassigned-slot index
//! list (same approach `affinidi-status-list`'s
//! `BitstringStatusList::allocate_index` uses, but we own the
//! `assigned` mask so we can persist it across daemon
//! restarts).

use rand::RngExt;

use super::storage::StatusListState;

/// Allocate a fresh slot for a member. Returns `Some(index)` on
/// success, `None` if the list is full.
///
/// Side-effects: sets `assigned[index] = true`. Does **not**
/// touch the bitstring — the bit stays `0` (= "valid") until a
/// subsequent [`flip`] revokes / suspends.
///
/// A candidate slot must be **both** unassigned **and** have its
/// bit currently clear. The second condition matters because
/// [`add_initial_decoys`] flips bits on *unassigned* slots: without
/// the `!is_set` filter the allocator could hand a member a decoy
/// slot whose bit already reads `1`, so the member's credential
/// would resolve as *revoked from the moment of issuance*. Decoy
/// slots are therefore skipped and remain permanent noise.
pub fn allocate(state: &mut StatusListState) -> Option<u32> {
    let available: Vec<usize> = (0..state.capacity)
        .filter(|&i| !state.assigned[i] && !state.is_set(i))
        .collect();
    if available.is_empty() {
        return None;
    }
    let mut rng = rand::rng();
    let pick = rng.random_range(0..available.len());
    let index = available[pick];
    state.assigned[index] = true;
    Some(index as u32)
}

/// Flip the bit for `index` to `revoked`. Caller is responsible
/// for ensuring `index` was previously [`allocate`]d to a real
/// member — flipping a decoy slot is harmless but the audit
/// trail won't make sense.
///
/// **Critical invariant**: `assigned[index]` stays `true` after
/// this call. The allocator skips assigned slots regardless of
/// their bit value, so a flipped (revoked) slot is permanently
/// reserved.
pub fn flip(state: &mut StatusListState, index: u32, revoked: bool) -> Result<(), &'static str> {
    let i = index as usize;
    if i >= state.capacity {
        return Err("index out of bounds for status list");
    }
    let byte = i / 8;
    let bit = 7 - (i % 8);
    if revoked {
        state.bits[byte] |= 1 << bit;
    } else {
        state.bits[byte] &= !(1 << bit);
    }
    // Note: assigned[i] is intentionally untouched. Flipping
    // back to `revoked = false` (e.g. un-suspend) leaves the
    // slot still owned by the same member.
    Ok(())
}

/// Seed `count` decoy bits — bit flips on unassigned slots.
/// Used once at first-init. Random collisions are skipped, so
/// the actual decoy count may be slightly lower than requested
/// if `count` approaches `capacity`.
pub fn add_initial_decoys(state: &mut StatusListState, count: usize) {
    let mut rng = rand::rng();
    let mut added = 0_usize;
    // Bounded attempts so a near-full list can't spin forever.
    let mut attempts = 0_usize;
    let max_attempts = count.saturating_mul(8).max(1024);
    while added < count && attempts < max_attempts {
        attempts += 1;
        let idx = rng.random_range(0..state.capacity);
        if state.assigned[idx] {
            continue;
        }
        let byte = idx / 8;
        let bit = 7 - (idx % 8);
        if state.bits[byte] & (1 << bit) != 0 {
            // Already set — try again.
            continue;
        }
        state.bits[byte] |= 1 << bit;
        added += 1;
    }
}

/// Occupancy fraction in `[0.0, 1.0]`. Defined as the larger of
/// "assigned slots" and "bits set", divided by capacity. This
/// matches spec §6.2's "live + reserved" wording: assigned
/// slots that haven't been flipped yet count toward the warning
/// threshold too.
pub fn occupancy(state: &StatusListState) -> f64 {
    let assigned = state.count_assigned();
    let set = state.count_set();
    let max = assigned.max(set);
    max as f64 / state.capacity as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_status_list::StatusPurpose;

    fn fresh_state(capacity_hint: Option<usize>) -> StatusListState {
        let mut s = StatusListState::new(
            StatusPurpose::Revocation,
            "https://vtc.example.com/v1/status-lists/revocation".into(),
        );
        if let Some(cap) = capacity_hint {
            // Shrink the state for fast tests. The production
            // size is 131K — slow to iterate in a unit test.
            s.capacity = cap;
            s.bits = vec![0u8; cap.div_ceil(8)];
            s.assigned = vec![false; cap];
        }
        s
    }

    /// Allocator returns each unassigned slot exactly once + then
    /// returns `None` when the list is full.
    #[test]
    fn allocator_exhausts_capacity_then_returns_none() {
        let mut state = fresh_state(Some(16));
        let mut seen = [false; 16];
        for _ in 0..16 {
            let idx = allocate(&mut state).expect("slot available");
            assert!(!seen[idx as usize], "slot {idx} returned twice");
            seen[idx as usize] = true;
        }
        assert!(allocate(&mut state).is_none(), "list is full");
        assert!(seen.iter().all(|s| *s), "every slot must be returned once");
    }

    /// The critical invariant: a flipped slot is never returned
    /// again by the allocator, even after many subsequent
    /// allocations.
    #[test]
    fn allocator_never_returns_a_flipped_slot() {
        let mut state = fresh_state(Some(64));
        // Allocate 10 slots, flip them, deallocate the rest.
        let mut flipped = Vec::new();
        for _ in 0..10 {
            let idx = allocate(&mut state).unwrap();
            flip(&mut state, idx, true).unwrap();
            flipped.push(idx);
        }
        // Drain the remaining capacity; none of the new
        // allocations may collide with a flipped slot.
        while let Some(idx) = allocate(&mut state) {
            assert!(
                !flipped.contains(&idx),
                "allocator returned previously-flipped slot {idx}"
            );
        }
        // Every flipped bit is still set.
        for idx in flipped {
            assert!(state.is_set(idx as usize));
        }
    }

    /// Flipping `revoked = false` un-sets the bit but keeps the
    /// slot assigned (useful for the suspension list's
    /// reactivation path).
    #[test]
    fn flip_back_to_zero_keeps_slot_assigned() {
        let mut state = fresh_state(Some(16));
        let idx = allocate(&mut state).unwrap();
        flip(&mut state, idx, true).unwrap();
        assert!(state.is_set(idx as usize));
        flip(&mut state, idx, false).unwrap();
        assert!(!state.is_set(idx as usize));
        assert!(state.assigned[idx as usize], "slot stays assigned");
    }

    #[test]
    fn flip_out_of_bounds_returns_err() {
        let mut state = fresh_state(Some(16));
        let err = flip(&mut state, 99, true).expect_err("oob must fail");
        assert!(err.contains("out of bounds"));
    }

    /// Occupancy hits the warning threshold once enough slots
    /// are assigned. Drive against an artificially small list so
    /// the test runs fast.
    #[test]
    fn occupancy_crosses_threshold_at_75_percent() {
        let mut state = fresh_state(Some(100));
        assert!(occupancy(&state) < 0.75);
        // Allocate 75 slots → 75% occupancy → at the threshold.
        for _ in 0..75 {
            allocate(&mut state).unwrap();
        }
        assert!(
            occupancy(&state) >= 0.75,
            "expected occupancy >= 0.75, got {}",
            occupancy(&state)
        );
    }

    /// Regression (deterministic): when every unassigned slot
    /// already carries a bit (all decoys, nothing assigned), the
    /// allocator must refuse rather than hand one out. The old
    /// allocator filtered on `assigned` alone and returned a
    /// decoy slot here — which in production gives a member a
    /// credential that reads as revoked at issuance.
    #[test]
    fn allocate_refuses_when_all_free_slots_are_decoys() {
        let mut state = fresh_state(Some(8));
        // Flip a bit on every slot; leave all of them unassigned.
        for i in 0..8 {
            flip(&mut state, i as u32, true).unwrap();
        }
        assert!(
            allocate(&mut state).is_none(),
            "allocate must not return a slot whose bit is already set"
        );
    }

    /// Regression: under a realistic decoy load, every slot the
    /// allocator hands out has a clear bit. Drains the list to be
    /// sure no decoy slot ever slips through.
    #[test]
    fn allocate_never_returns_a_set_slot_under_decoys() {
        let mut state = fresh_state(Some(256));
        add_initial_decoys(&mut state, 200);
        let mut handed_out = 0usize;
        while let Some(idx) = allocate(&mut state) {
            assert!(
                !state.is_set(idx as usize),
                "allocate returned slot {idx} whose bit was already set (decoy)"
            );
            handed_out += 1;
        }
        // Only the non-decoy slots are allocatable.
        assert!(handed_out > 0, "expected some allocatable slots");
        assert!(
            handed_out <= 256 - state.count_set(),
            "allocated more slots than there were clear ones"
        );
    }

    /// Decoys land on unassigned slots only.
    #[test]
    fn add_initial_decoys_only_touches_unassigned_slots() {
        let mut state = fresh_state(Some(64));
        // Allocate slot 0 first.
        let owned = allocate(&mut state).unwrap();
        // Sprinkle some decoys.
        add_initial_decoys(&mut state, 30);
        // The owned slot's bit is still 0 (decoys don't touch
        // assigned slots), unless we explicitly flip it.
        if !state.assigned.iter().filter(|a| **a).count() == 1 {
            // Sanity — only one slot is assigned.
        }
        assert!(
            !state.is_set(owned as usize),
            "decoy must not flip an assigned slot"
        );
    }
}
