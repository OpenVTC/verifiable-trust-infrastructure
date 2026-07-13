//! Task-execution consent — the data layer behind the PDP's `requireConsent`
//! disposition.
//!
//! When a policy returns `requireConsent`, a privileged task can't proceed until
//! one or more named approvers have signed off on **this exact payload**. The
//! binding is a deterministic digest of the payload (RFC 8785 JCS + SHA-256), so
//! the approval a re-submitted task consumes provably concerns the same request
//! — an approver can't be tricked into signing one payload while a different one
//! executes.
//!
//! Two records in the `task_consent` keyspace:
//! - [`PendingTaskConsent`] (`pending:<digest>`) — an in-flight request
//!   accumulating approver signatures.
//! - [`TaskConsentGrant`] (`grant:<requester>:<digest>`) — a completed
//!   authorization the re-submitting requester consumes single-use.
//!
//! This mirrors the step-up "reject → approve → re-submit" loop, but the
//! authorization is bound to the payload digest rather than the session.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

const PENDING_PREFIX: &[u8] = b"pending:";
const GRANT_PREFIX: &[u8] = b"grant:";

/// Deterministic digest of a task payload: hex SHA-256 over the RFC 8785 (JCS)
/// canonical form. Stable across serializers, so the requester's re-submit and
/// the approver's signed decision agree on what was authorized.
pub fn payload_digest(payload: &serde_json::Value) -> Result<String, AppError> {
    let canonical = serde_json_canonicalizer::to_string(payload)
        .map_err(|e| AppError::Internal(format!("payload JCS canonicalization failed: {e}")))?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// An in-flight consent request accumulating approver signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTaskConsent {
    /// `payload_digest` of the task awaiting consent.
    pub digest: String,
    /// Type URI of the task (for the approver's display + audit).
    pub type_uri: String,
    /// The DID that submitted the task.
    pub requester_did: String,
    /// Named approver set the policy required (resolved to members at check time).
    pub approver_set: String,
    /// Distinct approvals needed before a grant is issued.
    pub min_approvals: u32,
    /// When true, the requester's own DID cannot count toward the threshold.
    pub exclude_requester: bool,
    /// Nonce the approver echoes + signs, binding the decision to this request.
    pub challenge: String,
    /// Distinct approver DIDs who have approved so far.
    pub approvals: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

/// A completed authorization a re-submitted task consumes (single-use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskConsentGrant {
    pub digest: String,
    pub requester_did: String,
    pub type_uri: String,
    /// The approver DIDs whose signatures produced this grant.
    pub approvers: Vec<String>,
    pub granted_at: u64,
    pub expires_at: u64,
}

fn pending_key(digest: &str) -> Vec<u8> {
    [PENDING_PREFIX, digest.as_bytes()].concat()
}

fn grant_key(requester_did: &str, digest: &str) -> Vec<u8> {
    // `:` can't appear in a hex digest; the requester DID may contain `:`, so put
    // it last after the fixed-shape prefix+digest to keep the key unambiguous.
    [
        GRANT_PREFIX,
        digest.as_bytes(),
        b":",
        requester_did.as_bytes(),
    ]
    .concat()
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("task-consent decode: {e}")))
}

// ── Pending ────────────────────────────────────────────────────────────────

pub async fn store_pending(ks: &KeyspaceHandle, p: &PendingTaskConsent) -> Result<(), AppError> {
    let key = String::from_utf8(pending_key(&p.digest))
        .map_err(|e| AppError::Internal(format!("pending key not utf-8: {e}")))?;
    ks.insert(key, p).await
}

pub async fn get_pending(
    ks: &KeyspaceHandle,
    digest: &str,
) -> Result<Option<PendingTaskConsent>, AppError> {
    match ks.get_raw(pending_key(digest)).await? {
        Some(b) => Ok(Some(decode(&b)?)),
        None => Ok(None),
    }
}

pub async fn delete_pending(ks: &KeyspaceHandle, digest: &str) -> Result<(), AppError> {
    ks.remove(pending_key(digest)).await
}

/// Record an approval (idempotent per approver) and return the updated pending.
/// `Ok(None)` if there is no pending consent for the digest. The caller decides
/// whether `approvals.len() >= min_approvals` and, if so, issues a grant.
pub async fn add_approval(
    ks: &KeyspaceHandle,
    digest: &str,
    approver_did: &str,
) -> Result<Option<PendingTaskConsent>, AppError> {
    let Some(mut p) = get_pending(ks, digest).await? else {
        return Ok(None);
    };
    if !p.approvals.iter().any(|a| a == approver_did) {
        p.approvals.push(approver_did.to_string());
        store_pending(ks, &p).await?;
    }
    Ok(Some(p))
}

// ── Grant ──────────────────────────────────────────────────────────────────

pub async fn store_grant(ks: &KeyspaceHandle, g: &TaskConsentGrant) -> Result<(), AppError> {
    let key = String::from_utf8(grant_key(&g.requester_did, &g.digest))
        .map_err(|e| AppError::Internal(format!("grant key not utf-8: {e}")))?;
    ks.insert(key, g).await
}

/// Consume a valid grant for `(requester, digest)` — single-use: on a hit the
/// grant is removed before returning. Returns `None` if absent or expired (an
/// expired grant is also removed). This is the gate's allow-path check.
pub async fn consume_grant(
    ks: &KeyspaceHandle,
    requester_did: &str,
    digest: &str,
    now: u64,
) -> Result<Option<TaskConsentGrant>, AppError> {
    let key = grant_key(requester_did, digest);
    let Some(bytes) = ks.get_raw(key.clone()).await? else {
        return Ok(None);
    };
    let grant: TaskConsentGrant = decode(&bytes)?;
    // Remove either way: a hit is single-use, an expired grant is swept.
    ks.remove(key).await?;
    if grant.expires_at <= now {
        return Ok(None);
    }
    Ok(Some(grant))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;
    use serde_json::json;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (store.keyspace(crate::keyspaces::TASK_CONSENT).unwrap(), dir)
    }

    #[test]
    fn digest_is_deterministic_and_key_order_independent() {
        let a = payload_digest(&json!({ "b": 2, "a": 1 })).unwrap();
        let b = payload_digest(&json!({ "a": 1, "b": 2 })).unwrap();
        assert_eq!(a, b, "JCS canonicalization must ignore key order");
        assert_ne!(a, payload_digest(&json!({ "a": 1, "b": 3 })).unwrap());
        assert_eq!(a.len(), 64, "hex sha-256 is 64 chars");
    }

    fn pending(digest: &str, min: u32) -> PendingTaskConsent {
        PendingTaskConsent {
            digest: digest.into(),
            type_uri: "https://…/dids/update/1.0".into(),
            requester_did: "did:key:zReq".into(),
            approver_set: "operators".into(),
            min_approvals: min,
            exclude_requester: true,
            challenge: "nonce123".into(),
            approvals: vec![],
            created_at: 100,
            expires_at: 1000,
        }
    }

    #[tokio::test]
    async fn approvals_accumulate_idempotently() {
        let (ks, _d) = temp_ks().await;
        store_pending(&ks, &pending("deadbeef", 2)).await.unwrap();

        let p = add_approval(&ks, "deadbeef", "did:key:zA")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.approvals.len(), 1);
        // Same approver again → no double count.
        let p = add_approval(&ks, "deadbeef", "did:key:zA")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.approvals.len(), 1);
        // Second distinct approver reaches the threshold.
        let p = add_approval(&ks, "deadbeef", "did:key:zB")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.approvals.len(), 2);
        assert!(p.approvals.len() as u32 >= p.min_approvals);

        // No pending for an unknown digest.
        assert!(
            add_approval(&ks, "nope", "did:key:zA")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn grant_is_single_use_and_expiry_checked() {
        let (ks, _d) = temp_ks().await;
        let g = TaskConsentGrant {
            digest: "d1".into(),
            requester_did: "did:key:zReq".into(),
            type_uri: "t".into(),
            approvers: vec!["did:key:zA".into()],
            granted_at: 100,
            expires_at: 500,
        };
        store_grant(&ks, &g).await.unwrap();

        // First consume within validity → hit.
        assert!(
            consume_grant(&ks, "did:key:zReq", "d1", 200)
                .await
                .unwrap()
                .is_some()
        );
        // Second consume → gone (single-use).
        assert!(
            consume_grant(&ks, "did:key:zReq", "d1", 200)
                .await
                .unwrap()
                .is_none()
        );

        // Expired grant → None, and swept.
        store_grant(&ks, &g).await.unwrap();
        assert!(
            consume_grant(&ks, "did:key:zReq", "d1", 999)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            consume_grant(&ks, "did:key:zReq", "d1", 200)
                .await
                .unwrap()
                .is_none()
        );

        // Wrong requester never matches.
        store_grant(&ks, &g).await.unwrap();
        assert!(
            consume_grant(&ks, "did:key:zOther", "d1", 200)
                .await
                .unwrap()
                .is_none()
        );
    }
}
