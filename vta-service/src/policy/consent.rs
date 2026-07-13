//! Task-execution consent — the data layer behind the PDP's `requireConsent`
//! disposition.
//!
//! When a policy returns `requireConsent`, a privileged task can't proceed until
//! one or more named approvers have signed off on **this exact task**. The
//! binding is a deterministic digest of the task URI and its payload (RFC 8785
//! JCS + SHA-256), so the approval a re-submitted task consumes provably
//! concerns the same request — an approver can't be tricked into signing one
//! payload while a different one executes, nor into approving a benign task URI
//! whose payload happens to canonicalize like a destructive one's.
//!
//! Two records in the `task_consent` keyspace:
//! - [`PendingTaskConsent`] (`pending:<digest>`) — an in-flight request
//!   accumulating approver signatures.
//! - [`TaskConsentGrant`] (`grant:<digest>:<requester>`) — a completed
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
const WIRE_INDEX_PREFIX: &[u8] = b"wire:";

/// Domain-separation tag: keeps these digests from colliding with any other
/// SHA-256 over a canonical payload elsewhere in the system.
const DIGEST_DOMAIN: &[u8] = b"vta/task-consent/v1\0";

/// Deterministic digest of a task: hex SHA-256 over the type URI and the RFC
/// 8785 (JCS) canonical payload. Stable across serializers, so the requester's
/// re-submit and the approver's signed decision agree on what was authorized.
///
/// The type URI is **part of the digest**, and is length-prefixed so the
/// URI/payload boundary can't be shifted. Without it, two tasks whose payloads
/// canonicalize identically — `{"did":…,"contextId":…}` is a plausible payload
/// for `dids/update`, `dids/rotate-keys` *and* a deactivate — would share a
/// digest, and an approval for the benign one would authorize the destructive
/// one. The approver only ever sees an opaque digest, so nothing downstream
/// could catch the substitution.
/// This digest is **executor-internal**. It never leaves the process: it is the
/// key under which a pending request and its grant are stored, and the gate must
/// be able to recompute it on a re-submit *before* it knows the challenge — which
/// is precisely why it cannot be the salted one. See [`wire_digest`].
pub fn payload_digest(type_uri: &str, payload: &serde_json::Value) -> Result<String, AppError> {
    digest_with(type_uri, payload, None)
}

/// The digest the approver signs, the requester echoes, and the two screens
/// match: [`payload_digest`] salted with the per-request `challenge`.
///
/// Salted because an unsalted digest over a low-entropy payload is a confirmation
/// oracle. "Deactivate `did:webvh:abc…`" has essentially one canonical form, so
/// anyone who observes the digest in transit — a compromised, subpoenaed, or
/// retrospectively-decrypted mediator — can guess the operation and hash to check.
/// Both screens still derive the same value because both hold the challenge.
///
/// The salt is why there are two digests rather than one. Keying storage by the
/// salted value would be circular: the gate would need the challenge to compute
/// the key under which the challenge is stored.
pub fn wire_digest(
    type_uri: &str,
    payload: &serde_json::Value,
    challenge: &str,
) -> Result<String, AppError> {
    digest_with(type_uri, payload, Some(challenge))
}

fn digest_with(
    type_uri: &str,
    payload: &serde_json::Value,
    challenge: Option<&str>,
) -> Result<String, AppError> {
    let canonical = serde_json_canonicalizer::to_string(payload)
        .map_err(|e| AppError::Internal(format!("payload JCS canonicalization failed: {e}")))?;
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update((type_uri.len() as u64).to_be_bytes());
    h.update(type_uri.as_bytes());
    h.update((canonical.len() as u64).to_be_bytes());
    h.update(canonical.as_bytes());
    if let Some(c) = challenge {
        h.update(c.as_bytes());
    }
    Ok(hex::encode(h.finalize()))
}

/// An in-flight consent request accumulating approver signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTaskConsent {
    /// Internal [`payload_digest`] of the task awaiting consent.
    pub digest: String,
    /// The salted [`wire_digest`] the approver signs. Stored so a decision can be
    /// matched without re-deriving it from a payload we deliberately do not keep.
    pub wire_digest: String,
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
    /// The prior state the effects shown to the approver were computed against.
    ///
    /// The payload itself is **not** stored — the requester re-submits it, and the
    /// digest proves it is the same one. What must be kept is the state the
    /// effects were computed against, because that is what execution has to
    /// re-assert: a human in the loop makes the window minutes wide, so the world
    /// can move underneath an approval.
    #[serde(default)]
    pub state_pin: Option<crate::policy::effects::StatePin>,
    /// Executor-internal preconditions to re-assert at execution.
    #[serde(default)]
    pub guards: crate::trust_tasks::planner::Guards,
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
    /// Carried from the pending request: what the approvers were shown, and what
    /// execution must still find true.
    #[serde(default)]
    pub state_pin: Option<crate::policy::effects::StatePin>,
    #[serde(default)]
    pub guards: crate::trust_tasks::planner::Guards,
    pub granted_at: u64,
    pub expires_at: u64,
}

fn pending_key(digest: &str) -> Vec<u8> {
    [PENDING_PREFIX, digest.as_bytes()].concat()
}

/// Index from the salted wire digest back to the internal one.
///
/// The approver's decision carries only the wire digest — it is the only digest
/// that ever left the process — but the pending request is keyed by the internal
/// one, because the gate has to find it on a re-submit before it knows the
/// challenge. This index closes that loop.
fn wire_index_key(wire_digest: &str) -> Vec<u8> {
    [WIRE_INDEX_PREFIX, wire_digest.as_bytes()].concat()
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
    ks.insert(key, p).await?;
    // Index the wire digest, since that is the only one an approver's decision
    // can carry back to us.
    ks.insert_raw(
        String::from_utf8(wire_index_key(&p.wire_digest))
            .map_err(|e| AppError::Internal(format!("wire index key not utf-8: {e}")))?,
        p.digest.as_bytes().to_vec(),
    )
    .await
}

/// Resolve the salted wire digest an approver signed back to the internal digest
/// the pending request is keyed by.
pub async fn pending_by_wire_digest(
    ks: &KeyspaceHandle,
    wire_digest: &str,
    now: u64,
) -> Result<Option<PendingTaskConsent>, AppError> {
    let Some(bytes) = ks.get_raw(wire_index_key(wire_digest)).await? else {
        return Ok(None);
    };
    let internal = String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("wire index value not utf-8: {e}")))?;
    get_pending(ks, &internal, now).await
}

/// Fetch a live pending consent. An expired one is treated as absent and swept
/// — its TTL is what bounds how long an approver's signature can authorize a
/// request, so it has to be enforced on the read path, not only by the sweeper.
pub async fn get_pending(
    ks: &KeyspaceHandle,
    digest: &str,
    now: u64,
) -> Result<Option<PendingTaskConsent>, AppError> {
    let key = pending_key(digest);
    let Some(b) = ks.get_raw(key.clone()).await? else {
        return Ok(None);
    };
    let p: PendingTaskConsent = decode(&b)?;
    if p.expires_at <= now {
        ks.remove(key).await?;
        ks.remove(wire_index_key(&p.wire_digest)).await?;
        return Ok(None);
    }
    Ok(Some(p))
}

/// Delete a pending request and its wire index. Takes the record rather than a
/// digest so both keys are always removed together — an orphaned index would
/// resolve to a pending that no longer exists.
pub async fn delete_pending(ks: &KeyspaceHandle, p: &PendingTaskConsent) -> Result<(), AppError> {
    ks.remove(pending_key(&p.digest)).await?;
    ks.remove(wire_index_key(&p.wire_digest)).await
}

/// Record an approval (idempotent per approver) and return the updated pending.
/// `Ok(None)` if there is no live pending consent for the digest. The caller
/// decides whether `approvals.len() >= min_approvals` and, if so, issues a grant.
pub async fn add_approval(
    ks: &KeyspaceHandle,
    digest: &str,
    approver_did: &str,
    now: u64,
) -> Result<Option<PendingTaskConsent>, AppError> {
    let Some(mut p) = get_pending(ks, digest, now).await? else {
        return Ok(None);
    };
    if !p.approvals.iter().any(|a| a == approver_did) {
        p.approvals.push(approver_did.to_string());
        store_pending(ks, &p).await?;
    }
    Ok(Some(p))
}

/// Prune expired pendings and lapsed grants. Both paths already expire lazily on
/// read; this bounds the space an unanswered request can hold indefinitely.
pub async fn sweep_expired(ks: &KeyspaceHandle, now: u64) -> Result<usize, AppError> {
    let mut pruned = 0usize;

    for (key, value) in ks.prefix_iter_raw("pending:").await? {
        match serde_json::from_slice::<PendingTaskConsent>(&value) {
            Ok(p) if p.expires_at <= now => {
                ks.remove(key).await?;
                ks.remove(wire_index_key(&p.wire_digest)).await?;
                pruned += 1;
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(error = %e, "task-consent sweeper: unreadable pending row"),
        }
    }

    for (key, value) in ks.prefix_iter_raw("grant:").await? {
        match serde_json::from_slice::<TaskConsentGrant>(&value) {
            Ok(g) if g.expires_at <= now => {
                ks.remove(key).await?;
                pruned += 1;
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(error = %e, "task-consent sweeper: unreadable grant row"),
        }
    }

    Ok(pruned)
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
///
/// `type_uri` is re-asserted against the grant even though [`payload_digest`]
/// already folds it in: the digest binding is the load-bearing defence, and this
/// is the assertion that fails loudly if that ever regresses.
pub async fn consume_grant(
    ks: &KeyspaceHandle,
    requester_did: &str,
    type_uri: &str,
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
    if grant.type_uri != type_uri {
        return Err(AppError::Internal(format!(
            "task-consent grant type mismatch: granted for '{}', presented for '{type_uri}'",
            grant.type_uri
        )));
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

    const T_UPDATE: &str = "https://trusttasks.org/spec/webvh/dids/update/1.0";
    const T_ROTATE: &str = "https://trusttasks.org/spec/webvh/dids/rotate-keys/1.0";

    #[test]
    fn digest_is_deterministic_and_key_order_independent() {
        let a = payload_digest(T_UPDATE, &json!({ "b": 2, "a": 1 })).unwrap();
        let b = payload_digest(T_UPDATE, &json!({ "a": 1, "b": 2 })).unwrap();
        assert_eq!(a, b, "JCS canonicalization must ignore key order");
        assert_ne!(
            a,
            payload_digest(T_UPDATE, &json!({ "a": 1, "b": 3 })).unwrap()
        );
        assert_eq!(a.len(), 64, "hex sha-256 is 64 chars");
    }

    /// The bypass this binding exists to close: an identical payload under two
    /// different task URIs must not share a digest, or an approval for the
    /// benign task authorizes the destructive one.
    #[test]
    fn digest_binds_the_type_uri() {
        let payload = json!({ "did": "did:webvh:example.com:abc", "contextId": "default" });
        assert_ne!(
            payload_digest(T_UPDATE, &payload).unwrap(),
            payload_digest(T_ROTATE, &payload).unwrap(),
            "same payload under a different task URI must not collide"
        );
    }

    /// The wire digest is the one that leaves the process, and it is salted with
    /// the challenge so it cannot be used as a confirmation oracle: a payload
    /// like "deactivate did:webvh:abc…" has essentially one canonical form, so an
    /// unsalted digest is guessable by anyone who observes it in transit.
    #[test]
    fn wire_digest_is_salted_and_distinct_from_the_internal_one() {
        let p = json!({ "did": "did:webvh:example.com:acme" });
        let internal = payload_digest(T_UPDATE, &p).unwrap();
        let a = wire_digest(T_UPDATE, &p, "challenge-aaaa").unwrap();
        let b = wire_digest(T_UPDATE, &p, "challenge-bbbb").unwrap();

        assert_ne!(
            internal, a,
            "the wire digest must not equal the storage key"
        );
        assert_ne!(
            a, b,
            "a different challenge must yield a different wire digest"
        );
        // …and it is still deterministic for a given challenge, or the approver's
        // echo could never be matched.
        assert_eq!(a, wire_digest(T_UPDATE, &p, "challenge-aaaa").unwrap());
    }

    /// The wire digest binds the type URI too — the same reason the internal one
    /// does, and the approver only ever sees this one.
    #[test]
    fn wire_digest_binds_the_type_uri() {
        let p = json!({ "did": "did:webvh:example.com:acme" });
        assert_ne!(
            wire_digest(T_UPDATE, &p, "c").unwrap(),
            wire_digest(T_ROTATE, &p, "c").unwrap()
        );
    }

    /// The decision an approver signs carries only the wire digest, so the
    /// pending request has to be reachable from it.
    #[tokio::test]
    async fn a_decision_resolves_its_pending_by_wire_digest() {
        let (ks, _d) = temp_ks().await;
        let p = pending("deadbeef", 1);
        store_pending(&ks, &p).await.unwrap();

        let found = pending_by_wire_digest(&ks, &p.wire_digest, 200)
            .await
            .unwrap()
            .expect("resolved via the wire index");
        assert_eq!(found.digest, "deadbeef");

        assert!(
            pending_by_wire_digest(&ks, "not-a-digest", 200)
                .await
                .unwrap()
                .is_none()
        );

        // Deleting the pending must take its index with it — an orphaned index
        // would resolve to a request that no longer exists.
        delete_pending(&ks, &p).await.unwrap();
        assert!(
            pending_by_wire_digest(&ks, &p.wire_digest, 200)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Length-prefixing the URI stops a boundary shift between the URI and the
    /// canonical payload from producing the same preimage.
    #[test]
    fn digest_uri_payload_boundary_is_unambiguous() {
        assert_ne!(
            payload_digest("ab", &json!("c")).unwrap(),
            payload_digest("a", &json!("bc")).unwrap(),
        );
    }

    fn pending(digest: &str, min: u32) -> PendingTaskConsent {
        PendingTaskConsent {
            digest: digest.into(),
            wire_digest: format!("wire-{digest}"),
            state_pin: None,
            guards: Default::default(),
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

        let p = add_approval(&ks, "deadbeef", "did:key:zA", 200)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.approvals.len(), 1);
        // Same approver again → no double count.
        let p = add_approval(&ks, "deadbeef", "did:key:zA", 200)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.approvals.len(), 1);
        // Second distinct approver reaches the threshold.
        let p = add_approval(&ks, "deadbeef", "did:key:zB", 200)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.approvals.len(), 2);
        assert!(p.approvals.len() as u32 >= p.min_approvals);

        // No pending for an unknown digest.
        assert!(
            add_approval(&ks, "nope", "did:key:zA", 200)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// `expires_at` was previously written but never read, so a pending consent
    /// could be approved indefinitely.
    #[tokio::test]
    async fn expired_pending_reads_as_absent_and_cannot_be_approved() {
        let (ks, _d) = temp_ks().await;
        store_pending(&ks, &pending("deadbeef", 1)).await.unwrap();

        // expires_at = 1000
        assert!(get_pending(&ks, "deadbeef", 999).await.unwrap().is_some());
        assert!(get_pending(&ks, "deadbeef", 1000).await.unwrap().is_none());
        assert!(
            add_approval(&ks, "deadbeef", "did:key:zA", 1001)
                .await
                .unwrap()
                .is_none(),
            "an expired pending must not accept approvals"
        );
        // …and the lapsed row is swept on the way out.
        assert!(get_pending(&ks, "deadbeef", 500).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sweeper_prunes_lapsed_pendings_and_grants() {
        let (ks, _d) = temp_ks().await;
        store_pending(&ks, &pending("d1", 1)).await.unwrap(); // expires_at 1000
        store_grant(&ks, &grant("d2", 500)).await.unwrap();

        assert_eq!(
            sweep_expired(&ks, 400).await.unwrap(),
            0,
            "nothing lapsed yet"
        );
        assert_eq!(sweep_expired(&ks, 2000).await.unwrap(), 2, "both lapsed");
        assert_eq!(sweep_expired(&ks, 2000).await.unwrap(), 0, "idempotent");
    }

    fn grant(digest: &str, expires_at: u64) -> TaskConsentGrant {
        TaskConsentGrant {
            digest: digest.into(),
            state_pin: None,
            guards: Default::default(),
            requester_did: "did:key:zReq".into(),
            type_uri: T_UPDATE.into(),
            approvers: vec!["did:key:zA".into()],
            granted_at: 100,
            expires_at,
        }
    }

    #[tokio::test]
    async fn grant_is_single_use_and_expiry_checked() {
        let (ks, _d) = temp_ks().await;
        let g = grant("d1", 500);
        store_grant(&ks, &g).await.unwrap();

        // First consume within validity → hit.
        assert!(
            consume_grant(&ks, "did:key:zReq", T_UPDATE, "d1", 200)
                .await
                .unwrap()
                .is_some()
        );
        // Second consume → gone (single-use).
        assert!(
            consume_grant(&ks, "did:key:zReq", T_UPDATE, "d1", 200)
                .await
                .unwrap()
                .is_none()
        );

        // Expired grant → None, and swept.
        store_grant(&ks, &g).await.unwrap();
        assert!(
            consume_grant(&ks, "did:key:zReq", T_UPDATE, "d1", 999)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            consume_grant(&ks, "did:key:zReq", T_UPDATE, "d1", 200)
                .await
                .unwrap()
                .is_none()
        );

        // Wrong requester never matches.
        store_grant(&ks, &g).await.unwrap();
        assert!(
            consume_grant(&ks, "did:key:zOther", T_UPDATE, "d1", 200)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Belt-and-braces on the type binding: even if a digest for one task URI
    /// were somehow presented for another, consumption must refuse it rather
    /// than silently authorize.
    #[tokio::test]
    async fn grant_refuses_a_different_task_uri() {
        let (ks, _d) = temp_ks().await;
        store_grant(&ks, &grant("d1", 500)).await.unwrap();

        let err = consume_grant(&ks, "did:key:zReq", T_ROTATE, "d1", 200)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("type mismatch"),
            "expected a type-mismatch refusal, got: {err}"
        );
    }
}
