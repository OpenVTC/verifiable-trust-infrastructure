//! `status_lists:` keyspace — persistence for the two
//! BitstringStatusList state rows (revocation + suspension).
//!
//! Spec §5.6 + §6.2. One row per [`StatusPurpose`] keyed by the
//! purpose's wire form. The row carries the raw bitstring + the
//! `assigned` mask that drives the allocator's
//! never-reuse-a-flipped-slot invariant.

use std::sync::LazyLock;

use affinidi_status_list::{DEFAULT_BITSTRING_SIZE, StatusPurpose};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, MutexGuard};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::INITIAL_DECOY_FRACTION;

/// Prefix every status-list row sits under. Exposed so the
/// boot path + admin tooling can prefix-iterate.
pub const STATUS_LIST_PREFIX: &[u8] = b"status_lists:";

/// Persisted state for one BitstringStatusList. Stored under
/// `status_lists:<purpose>` (one row per purpose) and loaded on
/// every allocate / flip.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusListState {
    /// Purpose this list serves (`revocation` / `suspension`).
    pub purpose: StatusPurpose,
    /// Total number of bits in the list. Defaults to
    /// [`DEFAULT_BITSTRING_SIZE`] (131,072) per spec §6.2's
    /// herd-privacy floor; immutable after creation.
    pub capacity: usize,
    /// Raw bitstring, MSB-first per W3C
    /// `BitstringStatusListCredential`.
    #[serde(with = "hex_bytes")]
    pub bits: Vec<u8>,
    /// Slot ownership. `assigned[i] == true` iff slot `i` has
    /// been handed out by [`super::allocate`] for a real
    /// member. Decoys don't show up here. Drives
    /// "flipped indices are never reallocated" — a departed
    /// member's slot keeps `assigned[i] == true` even after
    /// the bit flips, so the allocator skips it.
    #[serde(with = "compact_bool_vec")]
    pub assigned: Vec<bool>,
    /// Canonical `id` URL the published
    /// `BitstringStatusListCredential` carries. The VMC's
    /// `credentialStatus.statusListCredential` field also
    /// references this URL.
    pub list_credential_id: String,
}

impl StatusListState {
    /// Fresh state — all bits zero, nothing assigned. Caller
    /// is responsible for seeding decoys via
    /// [`super::add_initial_decoys`].
    pub fn new(purpose: StatusPurpose, list_credential_id: String) -> Self {
        let capacity = DEFAULT_BITSTRING_SIZE;
        Self {
            purpose,
            capacity,
            bits: vec![0u8; capacity.div_ceil(8)],
            assigned: vec![false; capacity],
            list_credential_id,
        }
    }

    /// `true` iff bit `index` is set (revoked / suspended).
    pub fn is_set(&self, index: usize) -> bool {
        let byte = index / 8;
        let bit = 7 - (index % 8);
        (self.bits[byte] >> bit) & 1 == 1
    }

    /// Count of bits set to `1` across the whole list (live
    /// flips + decoys).
    pub fn count_set(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Number of slots currently assigned to a real member
    /// (excluding decoys).
    pub fn count_assigned(&self) -> usize {
        self.assigned.iter().filter(|a| **a).count()
    }

    /// Suggested initial decoy count derived from
    /// [`INITIAL_DECOY_FRACTION`].
    pub fn initial_decoy_count(&self) -> usize {
        (self.capacity as f64 * INITIAL_DECOY_FRACTION) as usize
    }
}

fn purpose_key(purpose: StatusPurpose) -> Vec<u8> {
    let mut k = STATUS_LIST_PREFIX.to_vec();
    k.extend_from_slice(purpose.to_string().as_bytes());
    k
}

/// Retrieve a state row by purpose. `Ok(None)` if absent.
pub async fn get_state(
    ks: &KeyspaceHandle,
    purpose: StatusPurpose,
) -> Result<Option<StatusListState>, AppError> {
    let raw = ks.get_raw(purpose_key(purpose)).await?;
    match raw {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
            AppError::Internal(format!("StatusListState decode: {e}"))
        })?)),
        None => Ok(None),
    }
}

/// Persist a state row (create or overwrite).
pub async fn store_state(ks: &KeyspaceHandle, state: &StatusListState) -> Result<(), AppError> {
    ks.insert(
        String::from_utf8(purpose_key(state.purpose)).expect("status-list key is ASCII"),
        state,
    )
    .await
}

/// List every persisted state row. Used at boot to materialise
/// the live status-list set into memory.
pub async fn list_states(ks: &KeyspaceHandle) -> Result<Vec<StatusListState>, AppError> {
    let pairs = ks.prefix_iter_raw(STATUS_LIST_PREFIX.to_vec()).await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (_k, v) in pairs {
        match serde_json::from_slice::<StatusListState>(&v) {
            Ok(s) => out.push(s),
            Err(err) => tracing::warn!(error = %err, "skipping unparseable status-list row"),
        }
    }
    Ok(out)
}

/// Idempotent first-init helper. If `purpose` has no row yet,
/// create one with [`StatusListState::new`] and seed decoys via
/// [`super::add_initial_decoys`]. Returns the state regardless
/// (boot path can act on it without a second `get_state` call).
pub async fn ensure_initial(
    ks: &KeyspaceHandle,
    purpose: StatusPurpose,
    list_credential_id: String,
) -> Result<StatusListState, AppError> {
    if let Some(existing) = get_state(ks, purpose).await? {
        return Ok(existing);
    }
    let mut state = StatusListState::new(purpose, list_credential_id);
    let decoy_count = state.initial_decoy_count();
    super::allocator::add_initial_decoys(&mut state, decoy_count);
    store_state(ks, &state).await?;
    Ok(state)
}

// ---------------------------------------------------------------------------
// Concurrency control for the read-modify-write of a status-list row.
// ---------------------------------------------------------------------------

/// Process-wide lock serializing every status-list row mutation.
///
/// A mutation is `get_state` → mutate in memory (`allocate` / `flip`) →
/// `store_state`, and `store_state` overwrites the whole row. Without a
/// lock, two concurrent mutations on the same purpose both read the row
/// before either stores, so the second store clobbers the first —
/// silently dropping a revocation flip (a credential the operator
/// believes revoked then resolves *valid*) or aliasing two members onto
/// one slot (the correlation harm the `assigned` mask exists to prevent).
///
/// One process-wide lock (not per-purpose) is the right grain, mirroring
/// `ceremony::execute::LAST_ADMIN_LOCK`: status-list writes are
/// infrequent admin operations, and the public serve route reads
/// `get_state` directly and never takes the lock — so read throughput is
/// unaffected and cross-purpose contention is negligible.
static STATUS_LIST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Acquire the status-list write lock. Hold the returned guard across the
/// entire `get_state` → mutate → `store_state` sequence.
///
/// Most callers want [`with_locked`]. Reach for the raw guard only when
/// async work must sit between the allocate and the store while still
/// excluding other writers — e.g. the admit path builds the VMC/VEC
/// between allocating a slot and persisting it, so a build failure
/// doesn't burn the slot.
///
/// Not re-entrant: never call [`with_locked`] (or `lock` again) while
/// already holding the guard — it would deadlock.
pub async fn lock() -> MutexGuard<'static, ()> {
    STATUS_LIST_LOCK.lock().await
}

/// Run a status-list row mutation atomically under [`lock`]: load the
/// row, apply the in-memory mutation `f` (`allocate` / `flip`), persist
/// it, and emit the occupancy warning — with no interleaving writer.
/// `f`'s return value is propagated to the caller (e.g. the allocated
/// slot index).
///
/// Returns `AppError::Internal` if the row hasn't been initialised
/// (`ensure_initial` runs at boot for each purpose once `public_url` is
/// configured).
pub async fn with_locked<F, T>(
    ks: &KeyspaceHandle,
    purpose: StatusPurpose,
    f: F,
) -> Result<T, AppError>
where
    F: FnOnce(&mut StatusListState) -> Result<T, AppError>,
{
    let _guard = lock().await;
    let mut state = get_state(ks, purpose)
        .await?
        .ok_or_else(|| AppError::Internal(format!("status list for {purpose} not initialised")))?;
    let out = f(&mut state)?;
    store_state(ks, &state).await?;
    super::maybe_emit_occupancy_warning(&state);
    Ok(out)
}

// ---------------------------------------------------------------------------
// serde adapters
// ---------------------------------------------------------------------------

/// Hex-encode `Vec<u8>` on the wire. 16 KiB of bits is 16 KiB
/// of base16 = 32 KiB string — fine for a once-per-flip persist
/// of a fjall row, and operators reading the JSON see something
/// inspectable.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Compact `Vec<bool>` serializer. Packs 8 booleans per byte
/// and hex-encodes. Keeps the persisted row a manageable size
/// (a 131K-slot `Vec<bool>` would be 131K * 1 byte = 128 KiB
/// of JSON otherwise).
mod compact_bool_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Packed {
        len: usize,
        #[serde(with = "super::hex_bytes")]
        bits: Vec<u8>,
    }

    pub fn serialize<S>(v: &[bool], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bits = vec![0u8; v.len().div_ceil(8)];
        for (i, b) in v.iter().enumerate() {
            if *b {
                bits[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        Packed { len: v.len(), bits }.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Packed { len, bits } = Packed::deserialize(d)?;
        let mut v = vec![false; len];
        for (i, slot) in v.iter_mut().enumerate() {
            let byte = bits.get(i / 8).copied().unwrap_or(0);
            *slot = (byte >> (7 - (i % 8))) & 1 == 1;
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let ks = store.keyspace("status_lists").expect("ks");
        (ks, dir)
    }

    #[tokio::test]
    async fn round_trip_through_keyspace_preserves_bits_and_assigned() {
        let (ks, _dir) = temp_ks().await;
        let mut state = StatusListState::new(
            StatusPurpose::Revocation,
            "https://vtc.example.com/v1/status-lists/revocation".into(),
        );
        // Flip + assign a handful of slots.
        state.bits[0] = 0b10101010;
        state.assigned[3] = true;
        state.assigned[5] = true;

        store_state(&ks, &state).await.unwrap();
        let got = get_state(&ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.purpose, StatusPurpose::Revocation);
        assert_eq!(got.capacity, state.capacity);
        assert_eq!(got.bits[0], 0b10101010);
        assert!(got.assigned[3]);
        assert!(got.assigned[5]);
        assert!(!got.assigned[4]);
        assert_eq!(got.list_credential_id, state.list_credential_id);
    }

    #[tokio::test]
    async fn ensure_initial_is_idempotent() {
        let (ks, _dir) = temp_ks().await;
        let a = ensure_initial(
            &ks,
            StatusPurpose::Revocation,
            "https://vtc.example.com/v1/status-lists/revocation".into(),
        )
        .await
        .unwrap();
        let b = ensure_initial(
            &ks,
            StatusPurpose::Revocation,
            "https://vtc.example.com/v1/status-lists/revocation".into(),
        )
        .await
        .unwrap();
        // Same bitstring + assigned mask back from both calls
        // (re-init must not re-seed decoys).
        assert_eq!(a.bits, b.bits);
        assert_eq!(a.assigned, b.assigned);
    }

    #[tokio::test]
    async fn ensure_initial_seeds_decoys() {
        let (ks, _dir) = temp_ks().await;
        let state = ensure_initial(
            &ks,
            StatusPurpose::Revocation,
            "https://vtc.example.com/v1/status-lists/revocation".into(),
        )
        .await
        .unwrap();
        // Initial decoy count is INITIAL_DECOY_FRACTION * capacity.
        // The bit count won't be exactly that because random
        // collisions skip duplicates, but it's at least 90% of the
        // target.
        let expected = state.initial_decoy_count();
        let actual = state.count_set();
        assert!(
            actual >= (expected * 9) / 10,
            "expected at least ~{expected} decoys, got {actual}"
        );
        // No slots assigned yet — decoys never touch `assigned`.
        assert_eq!(state.count_assigned(), 0);
    }

    #[test]
    fn count_set_matches_bit_arithmetic() {
        let mut state = StatusListState::new(StatusPurpose::Revocation, "id".into());
        state.bits[0] = 0b11110000;
        state.bits[1] = 0b00000011;
        assert_eq!(state.count_set(), 6);
    }

    #[test]
    fn compact_bool_vec_round_trips() {
        let mut state = StatusListState::new(StatusPurpose::Revocation, "id".into());
        // Touch slots 0, 7, 8, 9 (cross-byte) + a far-right slot.
        for idx in [0usize, 7, 8, 9, state.capacity - 1] {
            state.assigned[idx] = true;
        }
        let s = serde_json::to_string(&state).unwrap();
        let back: StatusListState = serde_json::from_str(&s).unwrap();
        assert_eq!(back.assigned, state.assigned);
    }

    /// Spec §6.2: a status-list bit that's been flipped (revocation
    /// or suspension) is never reallocated to a new member.
    /// Otherwise the new holder's status would alias the departed
    /// one — an external observer with both DIDs could correlate
    /// them on the bitstring.
    ///
    /// The `assigned` mask is the invariant's enforcement
    /// mechanism: the allocator filters on `!state.assigned[i]`
    /// (`allocator.rs:38`) and `flip` deliberately leaves
    /// `assigned[i] = true` (`allocator.rs:71-73`). This test
    /// covers the boundary the prior unit test missed — the mask
    /// survives a `store_state` / `get_state` round-trip and
    /// continues to lock the slot out of future allocations.
    #[tokio::test]
    async fn revoked_index_survives_restart_and_is_not_reallocated() {
        use crate::status_list::allocator::{allocate, flip};

        let (ks, _dir) = temp_ks().await;
        let mut state = StatusListState::new(
            StatusPurpose::Revocation,
            "https://vtc.example.com/v1/status-lists/revocation".into(),
        );
        // The production-default 131_072-bit capacity would make
        // the drain loop below O(N²) and take ~5 minutes on CI.
        // Shrink to 256 slots — still proves the invariant, runs
        // in milliseconds. Re-size both backing vecs so the
        // allocator's `assigned.len() == capacity` precondition
        // still holds.
        state.capacity = 256;
        state.bits = vec![0u8; state.capacity.div_ceil(8)];
        state.assigned = vec![false; state.capacity];

        // Allocate one slot, flip it (revoke), persist + reload.
        let revoked = allocate(&mut state).expect("first allocate");
        flip(&mut state, revoked, true).expect("flip");
        store_state(&ks, &state).await.unwrap();

        // Simulate restart — read the row from disk into a fresh
        // state value. The in-memory `state` from before would
        // already remember the assigned mask; reloading proves
        // the mask is preserved across persistence.
        let mut reloaded = get_state(&ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap();
        let revoked_idx = revoked as usize;
        assert!(
            reloaded.assigned[revoked_idx],
            "reloaded state lost the assigned mark for revoked slot"
        );
        let byte = revoked_idx / 8;
        let bit = 7 - (revoked_idx % 8);
        assert!(
            reloaded.bits[byte] & (1 << bit) != 0,
            "reloaded state lost the flipped revocation bit"
        );

        // Drain every remaining slot. The allocator must never
        // hand back `revoked` — even with random selection, after
        // capacity-1 more `allocate` calls the unassigned set is
        // empty and the next call returns `None`. If `revoked`
        // ever surfaces, the test fails immediately.
        let mut handed_out = Vec::with_capacity(reloaded.capacity);
        while let Some(idx) = allocate(&mut reloaded) {
            assert_ne!(
                idx, revoked,
                "allocator reallocated the revoked slot — invariant broken"
            );
            handed_out.push(idx);
        }
        assert_eq!(
            handed_out.len(),
            reloaded.capacity - 1,
            "expected to fill every slot except the revoked one"
        );

        // Bit is still set after the drain.
        assert!(
            reloaded.bits[byte] & (1 << bit) != 0,
            "revocation bit was cleared during reallocation drain"
        );
    }

    /// Small-capacity state persisted to `ks`, ready for the concurrency
    /// tests (the production 131_072-bit default makes `allocate`'s
    /// available-slot scan needlessly heavy per call).
    async fn seed_small_list(ks: &KeyspaceHandle, capacity: usize) -> StatusListState {
        let mut state = StatusListState::new(
            StatusPurpose::Revocation,
            "https://vtc.example.com/v1/status-lists/revocation".into(),
        );
        state.capacity = capacity;
        state.bits = vec![0u8; capacity.div_ceil(8)];
        state.assigned = vec![false; capacity];
        store_state(ks, &state).await.unwrap();
        state
    }

    /// Regression for the P0.1 status-list race: N concurrent `allocate`
    /// calls through [`with_locked`] over the same keyspace must each get
    /// a *distinct* slot and persist *all* N — none clobbered.
    ///
    /// Without the lock, the `get_state` → `allocate` → `store_state` RMW
    /// races: concurrent writers read the same row and the last
    /// `store_state` overwrites the others, so fewer than N slots persist
    /// (and `allocate` can hand the same index to two members — the
    /// correlation harm the `assigned` mask exists to prevent). Removing
    /// the `lock().await` inside `with_locked` makes this test fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_allocate_under_lock_loses_no_slots() {
        use crate::status_list::allocator::allocate;

        let (ks, _dir) = temp_ks().await;
        seed_small_list(&ks, 64).await;

        const N: u32 = 16;
        let mut handles = Vec::with_capacity(N as usize);
        for _ in 0..N {
            let ks = ks.clone();
            handles.push(tokio::spawn(async move {
                with_locked(&ks, StatusPurpose::Revocation, |row| {
                    allocate(row).ok_or_else(|| AppError::Internal("status list full".into()))
                })
                .await
            }));
        }

        let mut slots = std::collections::HashSet::new();
        for h in handles {
            slots.insert(h.await.unwrap().unwrap());
        }
        assert_eq!(
            slots.len(),
            N as usize,
            "concurrent allocations collided or were lost (got {} distinct slots)",
            slots.len()
        );

        let final_state = get_state(&ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            final_state.count_assigned(),
            N as usize,
            "persisted assigned-count dropped allocations to a racing writer"
        );
    }

    /// Regression for the P0.1 status-list race: a revocation `flip`
    /// running concurrently with an `allocate` (a join admit / endorsement
    /// issue) must keep the revocation bit — the allocate's whole-row
    /// `store_state` must not clobber it. Both [`with_locked`] mutations
    /// apply; order is irrelevant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn revoke_under_lock_survives_concurrent_allocate() {
        use crate::status_list::allocator::{allocate, flip};

        let (ks, _dir) = temp_ks().await;
        let mut state = seed_small_list(&ks, 64).await;
        // Pre-allocate the slot we'll revoke, persist it.
        let victim = allocate(&mut state).expect("pre-allocate victim");
        store_state(&ks, &state).await.unwrap();

        let ks_revoke = ks.clone();
        let ks_alloc = ks.clone();
        let revoke = tokio::spawn(async move {
            with_locked(&ks_revoke, StatusPurpose::Revocation, move |row| {
                flip(row, victim, true).map_err(|e| AppError::Internal(e.to_string()))
            })
            .await
        });
        let alloc = tokio::spawn(async move {
            with_locked(&ks_alloc, StatusPurpose::Revocation, |row| {
                allocate(row).ok_or_else(|| AppError::Internal("status list full".into()))
            })
            .await
        });
        revoke.await.unwrap().unwrap();
        let new_slot = alloc.await.unwrap().unwrap();

        let final_state = get_state(&ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap();
        assert!(
            final_state.is_set(victim as usize),
            "revocation bit was lost to a racing allocate"
        );
        assert!(
            final_state.assigned[victim as usize],
            "assigned mark on the revoked slot was lost"
        );
        assert!(
            final_state.assigned[new_slot as usize],
            "the concurrent allocation was lost"
        );
        assert_ne!(new_slot, victim, "allocate handed back the revoked slot");
    }
}
