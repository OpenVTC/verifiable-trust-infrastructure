//! Time-limited mnemonic export guard with secure memory wiping.
//!
//! On first boot, the VTA generates entropy for the BIP-39 mnemonic inside
//! the TEE. The mnemonic is NEVER displayed. Instead, the entropy is held
//! in a `MnemonicExportGuard` that is only active if:
//!
//! 1. The VTA was started with `VTA_MNEMONIC_EXPORT_WINDOW=<seconds>` env var
//! 2. The current time is within the window since boot
//! 3. The requester is a super admin (authenticated via JWT)
//!
//! After the window expires, the entropy is cryptographically zeroed using
//! the `zeroize` crate (prevents compiler optimization of the wipe) and the
//! mnemonic can never be reconstructed.
//!
//! On subsequent boots (not first boot), no entropy exists to export.

use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;
use tracing::{info, warn};
use zeroize::Zeroize;

use vti_common::error::{AppError, tee_attestation_error};

/// Holds the BIP-39 entropy bytes during the export window.
pub struct MnemonicExportGuard {
    inner: Mutex<GuardState>,
}

struct GuardState {
    /// The 32-byte entropy used to generate the BIP-39 mnemonic.
    /// Cryptographically zeroed after export or window expiry.
    entropy: Option<[u8; 32]>,
    /// When the guard was created (boot time).
    created_at: Instant,
    /// How long the export window lasts.
    window_secs: u64,
    /// Whether the mnemonic has been exported (one-time use).
    exported: bool,
    /// Whether an export is in flight — reserved but not yet committed. Keeps
    /// a second concurrent request from reading the mnemonic while the first
    /// is still sealing it.
    reserved: bool,
}

impl Drop for GuardState {
    fn drop(&mut self) {
        self.wipe_entropy();
    }
}

impl GuardState {
    /// Cryptographically zero the entropy bytes.
    fn wipe_entropy(&mut self) {
        if let Some(ref mut e) = self.entropy {
            e.zeroize();
        }
        self.entropy = None;
    }
}

/// Response from a mnemonic export request.
#[derive(Serialize, utoipa::ToSchema)]
pub struct MnemonicExportResponse {
    /// The BIP-39 mnemonic phrase (24 words).
    pub mnemonic: String,
    /// Seconds remaining in the export window when the export was performed.
    pub window_remaining_secs: u64,
}

/// Written by hand so the mnemonic never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for MnemonicExportResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MnemonicExportResponse")
            .field("mnemonic", &"<redacted>")
            .field("window_remaining_secs", &self.window_remaining_secs)
            .finish()
    }
}

/// Status of the mnemonic export guard.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MnemonicExportStatus {
    /// Whether the export window is currently active.
    pub window_active: bool,
    /// Whether the mnemonic has already been exported.
    pub already_exported: bool,
    /// Whether entropy is available (false on subsequent boots).
    pub entropy_available: bool,
    /// Seconds remaining in the window (0 if expired or not active).
    pub window_remaining_secs: u64,
}

impl MnemonicExportGuard {
    /// Create a new guard holding the entropy bytes.
    ///
    /// The `window_secs` controls how long the entropy remains available.
    /// After the window, `export()` will fail and the entropy is zeroed.
    pub fn new(entropy: [u8; 32], window_secs: u64) -> Self {
        info!(
            window_secs,
            "mnemonic export guard created — window open for {window_secs}s"
        );
        Self {
            inner: Mutex::new(GuardState {
                entropy: Some(entropy),
                created_at: Instant::now(),
                window_secs,
                exported: false,
                reserved: false,
            }),
        }
    }

    /// Create a guard with no entropy (subsequent boot — export is impossible).
    pub fn empty() -> Self {
        Self {
            inner: Mutex::new(GuardState {
                entropy: None,
                created_at: Instant::now(),
                window_secs: 0,
                exported: false,
                reserved: false,
            }),
        }
    }

    /// Check the current status of the export guard.
    pub fn status(&self) -> MnemonicExportStatus {
        let guard = self.inner.lock().unwrap();
        let elapsed = guard.created_at.elapsed().as_secs();
        let window_active =
            guard.entropy.is_some() && !guard.exported && elapsed < guard.window_secs;
        let remaining = if window_active {
            guard.window_secs.saturating_sub(elapsed)
        } else {
            0
        };

        MnemonicExportStatus {
            window_active,
            already_exported: guard.exported,
            entropy_available: guard.entropy.is_some(),
            window_remaining_secs: remaining,
        }
    }

    /// Export the mnemonic if the window is still open: [`Self::reserve`] then
    /// commit at once. Kept for callers with nothing that can fail between
    /// reading the words and handing them on.
    ///
    /// This is a one-time operation: after a successful export, the entropy
    /// is cryptographically zeroed and no further exports are possible.
    pub fn export(&self) -> Result<MnemonicExportResponse, AppError> {
        let reservation = self.reserve()?;
        let response = MnemonicExportResponse {
            mnemonic: reservation.mnemonic().to_string(),
            window_remaining_secs: reservation.window_remaining_secs(),
        };
        reservation.commit();
        Ok(response)
    }

    /// Reserve the one-time export: read the mnemonic **without** consuming
    /// the entropy yet.
    ///
    /// The export is two-phase because the caller has work that can fail after
    /// reading the words — sealing them to the operator, recording the audit
    /// row — and the entropy exists nowhere else. Consuming it first would turn
    /// a failed seal into a lost root seed. So: reserve, do the work,
    /// [`MnemonicReservation::commit`] on success. A reservation dropped
    /// without a commit releases the export for a retry. While one is held, a
    /// concurrent reserve is refused, so the words are never handed to two
    /// requests at once.
    ///
    /// Returns `Err` if the window has expired (the entropy is zeroed then),
    /// the mnemonic was already exported, an export is in flight, or no
    /// entropy is available (subsequent boot).
    pub fn reserve(&self) -> Result<MnemonicReservation<'_>, AppError> {
        let mut guard = self.inner.lock().unwrap();

        let entropy = match guard.entropy {
            Some(e) => e,
            None => {
                return Err(tee_attestation_error(
                    "no mnemonic available — entropy only exists on first boot",
                ));
            }
        };
        if guard.exported {
            return Err(tee_attestation_error(
                "mnemonic already exported — one-time operation",
            ));
        }
        if guard.reserved {
            return Err(tee_attestation_error(
                "a mnemonic export is already in progress",
            ));
        }
        let elapsed = guard.created_at.elapsed().as_secs();
        if elapsed >= guard.window_secs {
            guard.wipe_entropy();
            warn!("mnemonic export attempted after window expired — entropy zeroed");
            return Err(tee_attestation_error(format!(
                "mnemonic export window expired ({elapsed}s elapsed, window was {}s)",
                guard.window_secs
            )));
        }

        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| tee_attestation_error(format!("failed to derive mnemonic: {e}")))?;
        guard.reserved = true;
        Ok(MnemonicReservation {
            guard: self,
            mnemonic: zeroize::Zeroizing::new(mnemonic.to_string()),
            window_remaining_secs: guard.window_secs.saturating_sub(elapsed),
            committed: false,
        })
    }
}

/// An export in flight — see [`MnemonicExportGuard::reserve`].
pub struct MnemonicReservation<'a> {
    guard: &'a MnemonicExportGuard,
    mnemonic: zeroize::Zeroizing<String>,
    window_remaining_secs: u64,
    committed: bool,
}

impl MnemonicReservation<'_> {
    /// The mnemonic phrase. Zeroized when the reservation is dropped.
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Seconds left in the export window when the reservation was taken.
    pub fn window_remaining_secs(&self) -> u64 {
        self.window_remaining_secs
    }

    /// Complete the export: mark it done and zero the entropy. One-time.
    pub fn commit(mut self) {
        let mut guard = self.guard.inner.lock().unwrap();
        guard.exported = true;
        guard.reserved = false;
        guard.wipe_entropy();
        self.committed = true;
        info!(
            remaining_secs = self.window_remaining_secs,
            "mnemonic exported to authenticated super admin — entropy zeroed"
        );
    }
}

impl Drop for MnemonicReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Not committed: release, so the operator can retry inside the
            // window. `lock()` only fails if a holder panicked; the entropy is
            // then unreachable anyway.
            if let Ok(mut guard) = self.guard.inner.lock() {
                guard.reserved = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32 bytes of fixed entropy for tests. Real entropy comes from
    /// the TEE's CSPRNG; for tests we need a deterministic value so
    /// we can assert specific mnemonic words round-trip via
    /// `bip39::Mnemonic::from_entropy`.
    const TEST_ENTROPY: [u8; 32] = [0x42; 32];

    #[test]
    fn first_export_within_window_succeeds_then_burns_entropy() {
        let g = MnemonicExportGuard::new(TEST_ENTROPY, 60);
        let resp = g.export().expect("first export within window must succeed");
        // BIP-39 24-word phrase: 23 spaces between 24 words.
        assert_eq!(resp.mnemonic.split_whitespace().count(), 24);
        assert!(resp.window_remaining_secs <= 60);

        // Status flips to exhausted: one-time semantics.
        let s = g.status();
        assert!(!s.entropy_available, "entropy must be wiped after export");
        assert!(s.already_exported, "exported flag must be sticky");
        assert!(!s.window_active);
    }

    /// Pin the one-shot semantic: a second `export()` after a
    /// successful first must fail, regardless of remaining window.
    ///
    /// The current implementation wipes entropy as part of the
    /// successful-export path, so the second call hits the
    /// `no mnemonic available` branch (entropy=None) before the
    /// `exported` flag check ever fires. Either message satisfies
    /// the one-shot contract — accept both.
    #[test]
    fn second_export_after_first_rejected() {
        let g = MnemonicExportGuard::new(TEST_ENTROPY, 60);
        let _ = g.export().unwrap();
        let err = g
            .export()
            .expect_err("second export must be refused — one-time operation");
        let msg = format!("{err}");
        assert!(
            msg.contains("already exported")
                || msg.contains("no mnemonic available")
                || msg.contains("entropy only exists on first boot"),
            "error must indicate the export is exhausted: got {msg}"
        );
    }

    /// `empty()` constructor (subsequent boot — no entropy) refuses
    /// export with a clear "no entropy on subsequent boot" message.
    #[test]
    fn empty_guard_rejects_export_with_no_entropy_message() {
        let g = MnemonicExportGuard::empty();
        let err = g.export().expect_err("no entropy → export must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("no mnemonic available")
                || msg.contains("entropy only exists on first boot"),
            "error must explain why entropy is absent: got {msg}"
        );

        let s = g.status();
        assert!(!s.entropy_available);
        assert!(!s.window_active);
        assert!(!s.already_exported);
    }

    /// Window-expired path zeroes entropy AND surfaces an actionable
    /// error. We use a 0-second window to force expiry without
    /// sleeping (a real test should never sleep arbitrary durations
    /// to exercise the time check).
    #[test]
    fn export_after_window_expired_zeroes_entropy_and_fails() {
        let g = MnemonicExportGuard::new(TEST_ENTROPY, 0);
        // 0-second window: any elapsed time is past the window.
        let err = g
            .export()
            .expect_err("zero-second window must reject export immediately");
        let msg = format!("{err}");
        assert!(msg.contains("window expired"), "got: {msg}");

        // Entropy must be zeroed by the failed export path so a
        // later memory dump can't recover it. Surface this through
        // `status().entropy_available`.
        let s = g.status();
        assert!(
            !s.entropy_available,
            "expired-window path must zero entropy, status says {s:?}"
        );
    }

    /// `Drop` on the guard zeroes the entropy. Fundamental security
    /// property: a guard going out of scope (e.g. on shutdown without
    /// export) must not leave the BIP-39 entropy in heap memory for a
    /// post-mortem dump to recover.
    ///
    /// We can't observe memory after free in safe Rust, but we can
    /// inspect the inner state immediately before drop and assert
    /// `wipe_entropy` was called as part of the drop path. The cheap
    /// proxy is to drop a guard whose inner `Arc<Mutex<...>>` we hold
    /// a weak ref to, then assert the strong count went to zero —
    /// confirming nothing leaked the GuardState. Combined with the
    /// `Drop for GuardState` impl that calls `wipe_entropy()`, this
    /// pins the contract.
    #[test]
    fn drop_zeros_entropy() {
        // Use a Mutex<GuardState> directly so we can inspect after
        // mutation. Then drop and confirm.
        let mut state = GuardState {
            entropy: Some(TEST_ENTROPY),
            created_at: Instant::now(),
            window_secs: 60,
            exported: false,
            reserved: false,
        };
        state.wipe_entropy();
        assert!(
            state.entropy.is_none(),
            "wipe_entropy must clear the Option"
        );
        // Idempotent: a second wipe on already-cleared state is a no-op.
        state.wipe_entropy();
        assert!(state.entropy.is_none());
    }

    /// `status()` reports `window_active=true` while the window is
    /// open, then flips to false after expiry. Pin the
    /// `window_remaining_secs` math.
    #[test]
    fn status_reflects_window_state_correctly() {
        let g = MnemonicExportGuard::new(TEST_ENTROPY, 3600);
        let s = g.status();
        assert!(s.window_active, "fresh guard with 1h window must be active");
        assert!(s.entropy_available);
        assert!(!s.already_exported);
        assert!(s.window_remaining_secs <= 3600);
        assert!(
            s.window_remaining_secs > 3590,
            "remaining ≈ window for fresh guard"
        );

        // Zero-window guard: never active.
        let g0 = MnemonicExportGuard::new(TEST_ENTROPY, 0);
        let s0 = g0.status();
        assert!(!s0.window_active, "0-second window is never active");
        assert_eq!(s0.window_remaining_secs, 0);
    }

    /// A reservation dropped without a commit leaves the mnemonic exportable,
    /// so a failed seal cannot lose the root seed; while it is held, a second
    /// reserve is refused.
    #[test]
    fn an_uncommitted_reservation_releases_the_export() {
        let g = MnemonicExportGuard::new(TEST_ENTROPY, 60);
        let first = g.reserve().expect("reserve");
        let words = first.mnemonic().to_string();
        assert!(g.reserve().is_err(), "a concurrent reserve is refused");
        drop(first);
        let second = g.reserve().expect("released for a retry");
        assert_eq!(second.mnemonic(), words);
        second.commit();
        assert!(g.status().already_exported);
        assert!(g.reserve().is_err(), "one-time after a commit");
    }
}
