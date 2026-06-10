//! Status-list infrastructure — spec §6.2 (M2.10).
//!
//! Each VTC maintains two BitstringStatusLists — `revocation`
//! and `suspension` — capacity 131,072 bits each (W3C herd-
//! privacy floor). Every VMC carries a `credentialStatus`
//! entry pointing at one slot in the revocation list. Member
//! removal flips the slot to `1`; renewal re-uses the same
//! slot.
//!
//! ## Persistence shape
//!
//! Per spec §5.6, the VTC stores a [`storage::StatusListState`]
//! row per purpose in `status_lists:<purpose>`:
//!
//! - `bits` — the raw 16 KiB bitstring, MSB-first per W3C.
//! - `assigned` — which slots are *owned by a member* (decoys
//!   don't appear here). Drives the allocator's
//!   never-reallocate-a-flipped-slot invariant: even after a
//!   member departs and the bit is flipped to `1`, the slot
//!   stays in `assigned` so the allocator skips it forever.
//! - `list_credential_id` — the canonical `id` URL the
//!   published `BitstringStatusListCredential` carries.
//!
//! ## Decoys
//!
//! `assigned` and `bits` are independent. Decoys are bit
//! flips on *unassigned* slots — they obscure the real
//! occupancy from external verifiers without ever blocking a
//! future allocation. [`allocator::add_initial_decoys`] runs
//! once at first-init to seed the list with a non-zero
//! baseline; subsequent operations don't add more decoys
//! (the underlying `affinidi-status-list::BitstringStatusList`
//! already randomises slot allocation, which is the primary
//! correlation defence).
//!
//! ## Occupancy warning (spec §6.2)
//!
//! `StatusListOccupancyWarning` is emitted via the standard
//! tracing macro when the live + reserved fraction exceeds
//! 75% of capacity. Telemetry consumers can subscribe via
//! the `status_list_occupancy_warning` event name — see
//! [`OCCUPANCY_WARNING_THRESHOLD`].

pub mod allocator;
pub mod credential;
pub mod storage;

pub use allocator::{add_initial_decoys, allocate, flip, occupancy};
pub use credential::{BITSTRING_STATUS_LIST_VC_TYPE, build_status_list_credential};
pub use storage::{
    STATUS_LIST_PREFIX, StatusListState, ensure_initial, get_state, list_states, lock, store_state,
    with_locked,
};

pub use affinidi_status_list::{
    DEFAULT_BITSTRING_SIZE, MIN_BITSTRING_SIZE, StatusListEntry, StatusPurpose,
};

/// Fraction at which the per-list occupancy warning fires. Spec
/// §6.2 calls for 75%. "Occupied" includes both assigned slots
/// and decoy bits — the warning measures *capacity remaining
/// for new allocations*, not just live members.
pub const OCCUPANCY_WARNING_THRESHOLD: f64 = 0.75;

/// Default fraction of slots flipped as decoys at first-init.
/// 0.05 (~6,500 bits in a 131K list) is the same default
/// `affinidi-status-list`'s privacy mode tends toward — large
/// enough to defeat zero-occupancy correlation, small enough
/// not to chew through capacity prematurely.
pub const INITIAL_DECOY_FRACTION: f64 = 0.05;

/// Emit a tracing event named `status_list_occupancy_warning`
/// when [`occupancy`] crosses [`OCCUPANCY_WARNING_THRESHOLD`].
/// Hand-rolled helper so the allocator + flip paths use the
/// exact same event shape; downstream telemetry pipelines key on
/// the event name.
pub fn maybe_emit_occupancy_warning(state: &storage::StatusListState) {
    let frac = allocator::occupancy(state);
    if frac >= OCCUPANCY_WARNING_THRESHOLD {
        tracing::warn!(
            event = "status_list_occupancy_warning",
            purpose = %state.purpose,
            occupancy = frac,
            capacity = state.capacity,
            "status list occupancy crossed warning threshold"
        );
    }
}
