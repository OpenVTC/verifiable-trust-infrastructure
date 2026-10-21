//! The guess limit behind a `vtaPin` UV key.
//!
//! A `vtaPin` device proves its PIN with `HMAC-SHA256(K, message)`, where `K`
//! is the PBKDF2 output the browser enrolled as the key's `verifier`. The
//! PBKDF2 cost alone does not protect a six-digit PIN from a copied browser
//! profile — a million guesses is an afternoon offline — so the only defence is
//! that every guess has to come **here**, and here it is counted:
//!
//! - five consecutive wrong proofs lock the PIN for 15 minutes;
//! - each wrong proof after a lock has expired locks it again for twice as
//!   long as the last (15 min, 30 min, 1 h, … capped at 24 h);
//! - while locked, a proof is refused without being checked;
//! - a correct proof resets the count and the doubling.
//!
//! The count is persisted in the ACL keyspace beside the device's row, under
//! `uv-pin:<did>` (outside the `acl:` prefix, so nothing that enumerates ACL
//! entries sees it), and every update is a conditional write against the row as
//! read: two guesses racing each other both count. It is keyed to the PIN's
//! enrolment instant, so a new PIN starts from a clean record.
//!
//! Nothing here logs, audits or returns the verifier or a proof.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vta_sdk::protocols::device_management::{UV_PIN_CHANGE_PREFIX, UvKeyMaterial};
use vti_common::acl::UvKey;
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

/// Consecutive wrong proofs before the first lock.
pub const MAX_ATTEMPTS: u32 = 5;
/// Length of the first lock.
pub const FIRST_LOCK_SECS: i64 = 15 * 60;
/// Longest lock.
pub const MAX_LOCK_SECS: i64 = 24 * 60 * 60;

/// How many times a conditional update re-reads after losing a race.
const WRITE_ATTEMPTS: usize = 32;

fn guard_key(device_did: &str) -> String {
    format!("uv-pin:{device_did}")
}

/// The persisted guess-limit state of one device's PIN.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinGuard {
    /// `enrolledAt` of the PIN this record counts for. A record for another
    /// enrolment is stale and reads as fresh.
    pub enrolled_at: String,
    /// Consecutive wrong proofs since the last correct one.
    pub failed_attempts: u32,
    /// Locks imposed since the last correct proof; sets the next lock's length.
    pub locks: u32,
    /// Unix seconds until which proofs are refused unchecked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<i64>,
}

impl PinGuard {
    fn fresh(enrolled_at: &str) -> Self {
        Self {
            enrolled_at: enrolled_at.to_string(),
            ..Self::default()
        }
    }

    /// The lock in force at `now`, if any.
    #[must_use]
    pub fn locked_at(&self, now: i64) -> Option<i64> {
        self.locked_until.filter(|t| *t > now)
    }

    /// Wrong proofs left before the next lock, at `now`.
    #[must_use]
    pub fn attempts_remaining(&self) -> u32 {
        if self.locks > 0 {
            // A lock has been served: the next wrong proof locks again.
            0
        } else {
            MAX_ATTEMPTS.saturating_sub(self.failed_attempts)
        }
    }

    /// The state after one more wrong proof at `now`.
    fn after_wrong(&self, now: i64) -> Self {
        let mut next = self.clone();
        next.failed_attempts = next.failed_attempts.saturating_add(1);
        let lock_now = next.locks > 0 || next.failed_attempts >= MAX_ATTEMPTS;
        if lock_now {
            next.locks = next.locks.saturating_add(1);
            next.locked_until = Some(now + lock_secs(next.locks));
        }
        next
    }
}

/// Length of the `n`th lock (1-based): 15 min doubling, capped at 24 h.
#[must_use]
pub fn lock_secs(n: u32) -> i64 {
    let shift = n.saturating_sub(1).min(16);
    FIRST_LOCK_SECS
        .saturating_mul(1i64 << shift)
        .min(MAX_LOCK_SECS)
}

/// What the device sees of its PIN's guard: for the uv-key summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PinStatus {
    pub failed_attempts: u32,
    pub locked_until: Option<i64>,
}

/// Why a PIN proof was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum PinRefusal {
    /// Locked until this unix second; the proof was not checked.
    Locked {
        locked_until: i64,
    },
    /// The proof is wrong. `locked_until` is set when this proof imposed a
    /// lock.
    Wrong {
        attempts_remaining: u32,
        failed_attempts: u32,
        locked_until: Option<i64>,
    },
    /// The proof is not a 32-byte base64url HMAC. Not counted: it says nothing
    /// about the PIN.
    Malformed,
    /// The key is not a `vtaPin` key, or its stored verifier is unreadable.
    NotAPin,
    App(AppError),
}

impl From<AppError> for PinRefusal {
    fn from(e: AppError) -> Self {
        PinRefusal::App(e)
    }
}

/// The message a PIN change proof covers: [`UV_PIN_CHANGE_PREFIX`] and the
/// lowercase hex SHA-256 of the RFC 8785 form of the new enrolment as sent.
pub fn change_message(new_enrolment: &Value) -> Result<String, AppError> {
    let canonical = serde_json_canonicalizer::to_string(new_enrolment)
        .map_err(|e| AppError::Internal(format!("uv-key JCS canonicalization failed: {e}")))?;
    Ok(format!(
        "{UV_PIN_CHANGE_PREFIX}{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    ))
}

async fn read(
    acl_ks: &KeyspaceHandle,
    device_did: &str,
    enrolled_at: &str,
) -> Result<(Option<Vec<u8>>, PinGuard), AppError> {
    let raw = acl_ks.get_raw(guard_key(device_did)).await?;
    let guard = match raw.as_deref().map(serde_json::from_slice::<PinGuard>) {
        Some(Ok(g)) if g.enrolled_at == enrolled_at => g,
        // Absent, unreadable, or for an earlier PIN: a fresh record.
        _ => PinGuard::fresh(enrolled_at),
    };
    Ok((raw, guard))
}

/// Write `next` only while the row is still `expected`. `false` on a lost race.
async fn write_if_unchanged(
    acl_ks: &KeyspaceHandle,
    device_did: &str,
    expected: Option<Vec<u8>>,
    next: &PinGuard,
) -> Result<bool, AppError> {
    let key = guard_key(device_did);
    let mut batch = Batch::new();
    match expected {
        Some(raw) => batch.require_unchanged(key.clone(), raw),
        None => batch.require_absent(key.clone()),
    };
    batch.insert(key, next)?;
    Ok(acl_ks.apply_batch(batch).await?.is_applied())
}

/// The guard's state for the summary. Never fails the caller: an unreadable
/// record reads as a clean one.
pub async fn status(acl_ks: &KeyspaceHandle, device_did: &str, key: &UvKey, now: i64) -> PinStatus {
    match read(acl_ks, device_did, &key.enrolled_at).await {
        Ok((_, g)) => PinStatus {
            failed_attempts: g.failed_attempts,
            locked_until: g.locked_at(now),
        },
        Err(_) => PinStatus::default(),
    }
}

/// Check `proof_b64` — `HMAC-SHA256(K, message)` — against the device's
/// `vtaPin` key, counting it against the guess limit. Locked: refused
/// unchecked. Correct: the count resets.
pub async fn check(
    acl_ks: &KeyspaceHandle,
    device_did: &str,
    key: &UvKey,
    message: &str,
    proof_b64: &str,
    now: i64,
) -> Result<(), PinRefusal> {
    let UvKeyMaterial::VtaPin { verifier, .. } = &key.enrolment.key else {
        return Err(PinRefusal::NotAPin);
    };
    let k = verifier.key_bytes().ok_or(PinRefusal::NotAPin)?;

    for _ in 0..WRITE_ATTEMPTS {
        let (raw, guard) = read(acl_ks, device_did, &key.enrolled_at).await?;
        if let Some(locked_until) = guard.locked_at(now) {
            return Err(PinRefusal::Locked { locked_until });
        }
        // Checked inside the loop, after the lock: a locked PIN is refused
        // whatever was sent.
        use base64::Engine as _;
        let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(proof_b64.trim_end_matches('='))
            .ok()
            .filter(|p| p.len() == 32)
            .ok_or(PinRefusal::Malformed)?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&k)
            .map_err(|e| AppError::Internal(format!("hmac key: {e}")))?;
        mac.update(message.as_bytes());
        // Constant time.
        if mac.verify_slice(&proof).is_ok() {
            let clean = PinGuard::fresh(&key.enrolled_at);
            if guard == clean {
                // Nothing to reset (an absent or stale row already reads clean).
                return Ok(());
            }
            if write_if_unchanged(acl_ks, device_did, raw, &clean).await? {
                return Ok(());
            }
            // Lost a race with another proof: re-read, so a lock it imposed
            // in the meantime holds.
            continue;
        }
        let next = guard.after_wrong(now);
        if write_if_unchanged(acl_ks, device_did, raw, &next).await? {
            return Err(PinRefusal::Wrong {
                attempts_remaining: next.attempts_remaining(),
                failed_attempts: next.failed_attempts,
                locked_until: next.locked_at(now),
            });
        }
    }
    Err(PinRefusal::App(AppError::Conflict(format!(
        "the PIN guard for {device_did} kept changing; retry"
    ))))
}

/// Audit a refused proof: `device.uv-pin.failed` for a wrong one,
/// `device.uv-pin.locked` when it imposed a lock or met one. Counts and
/// instants only — never the proof or the verifier.
pub async fn audit_refusal(
    audit: &vta_audit::SharedAuditSink,
    device_did: &str,
    purpose: &str,
    refusal: &PinRefusal,
) {
    let (action, outcome, detail) = match refusal {
        PinRefusal::Wrong {
            attempts_remaining,
            failed_attempts,
            locked_until,
        } => {
            let detail = serde_json::json!({
                "purpose": purpose,
                "failedAttempts": failed_attempts,
                "attemptsRemaining": attempts_remaining,
                "lockedUntil": locked_until,
            })
            .to_string();
            vta_audit::record_with_detail_best_effort(
                audit,
                "device.uv-pin.failed",
                device_did,
                Some(device_did),
                "denied",
                None,
                None,
                Some(&detail),
            )
            .await;
            match locked_until {
                Some(_) => ("device.uv-pin.locked", "locked", detail),
                None => return,
            }
        }
        PinRefusal::Locked { locked_until } => (
            "device.uv-pin.locked",
            "denied",
            serde_json::json!({ "purpose": purpose, "lockedUntil": locked_until }).to_string(),
        ),
        _ => return,
    };
    vta_audit::record_with_detail_best_effort(
        audit,
        action,
        device_did,
        Some(device_did),
        outcome,
        None,
        None,
        Some(&detail),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_double_from_fifteen_minutes_to_a_day() {
        assert_eq!(lock_secs(1), 15 * 60);
        assert_eq!(lock_secs(2), 30 * 60);
        assert_eq!(lock_secs(3), 60 * 60);
        assert_eq!(lock_secs(7), 16 * 60 * 60);
        assert_eq!(lock_secs(8), 24 * 60 * 60);
        assert_eq!(lock_secs(40), 24 * 60 * 60);
    }

    #[test]
    fn five_wrong_lock_and_each_wrong_after_a_lock_locks_again_for_longer() {
        let mut g = PinGuard::fresh("t");
        for n in 1..=4 {
            g = g.after_wrong(1_000);
            assert_eq!(g.locked_until, None);
            assert_eq!(g.attempts_remaining(), MAX_ATTEMPTS - n);
        }
        g = g.after_wrong(1_000);
        assert_eq!(g.locked_until, Some(1_000 + 15 * 60));
        assert_eq!(g.attempts_remaining(), 0);
        // After the lock expires one wrong proof re-locks, doubled.
        let later = 1_000 + 15 * 60 + 1;
        assert_eq!(g.locked_at(later), None);
        g = g.after_wrong(later);
        assert_eq!(g.locked_until, Some(later + 30 * 60));
    }
}
