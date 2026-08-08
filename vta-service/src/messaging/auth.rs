use affinidi_tdk::didcomm::Message;

use crate::acl::check_acl_full;
use crate::auth::AuthClaims;
use crate::auth::session::{now_epoch, resolve_did_session};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Extract sender DID from a DIDComm message and look up their ACL entry,
/// returning unified `AuthClaims`.
///
/// Routes through [`check_acl_full`] (rather than the lower-level
/// `get_acl_entry`) so that `expires_at` is enforced identically to the
/// REST path. A time-bounded ACL grant must stop working over both
/// transports the moment it lapses; previously the DIDComm-side lookup
/// skipped the expiry check, leaving expired credentials live for any
/// caller still talking via DIDComm.
pub async fn auth_from_message(
    msg: &Message,
    acl_ks: &KeyspaceHandle,
    sessions_ks: &KeyspaceHandle,
) -> Result<AuthClaims, AppError> {
    let did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("message has no sender (from)".into()))?;

    auth_from_did(did, acl_ks, sessions_ks).await
}

/// Resolve claims for a **Trust-Task envelope** arriving on an intrinsic-sender
/// transport (DIDComm authcrypt, raw TSP).
///
/// This is [`auth_from_did`] plus one carve-out, and it is the only entry point
/// the two transports should use for the trust-task surface.
///
/// ## The carve-out
///
/// A ceremony task — a `task-consent/decision`, a step-up `approve-response` —
/// is authorized by the **document**: the approver's Data-Integrity proof
/// establishes who signed, and the handler checks that signer against the
/// policy-named approver set (or the pending step-up it echoes). The submitting
/// peer's standing at this VTA decides nothing; `task_consent::handle_decision`
/// does not read its `AuthClaims` at all.
///
/// Yet the ACL lookup ran first and refused those senders outright, which meant
/// the least-privilege approver the `approve_scope` axis exists to serve — a
/// device that may *confer* a context and *act* in none, and which therefore has
/// no reason to hold an ACL entry — could never deliver its answer. The
/// surrounding consent code already assumes such an approver can appear:
/// `compute_delegated_contexts` and the gate's eligibility count both treat
/// "absent from the ACL" as *confers nothing*, not *cannot speak*. Only this
/// gate disagreed, and it disagreed first.
///
/// So when — and only when — the ACL turns a sender away (`Forbidden`: unknown
/// DID, or a lapsed grant) **and** the envelope names a ceremony task, dispatch
/// proceeds on [`ceremony_claims`]: the proven sender DID over a role and
/// context list that reach nothing. Every other failure, and every other task,
/// is refused exactly as before.
///
/// An expired grant falls through the same way on purpose. Approve-authority
/// comes from the approver set, not from an ACL row; and where a grant's
/// *delegation* does depend on live ACL state, `compute_delegated_contexts`
/// re-reads it and refuses the expired entry there — at the point where it
/// actually confers something.
///
/// [`ceremony_claims`]: crate::trust_tasks::ceremony::ceremony_claims
pub async fn auth_for_trust_task_envelope(
    sender_did: &str,
    body: &[u8],
    acl_ks: &KeyspaceHandle,
    sessions_ks: &KeyspaceHandle,
) -> Result<AuthClaims, AppError> {
    use crate::trust_tasks::ceremony;

    let denial = match auth_from_did(sender_did, acl_ks, sessions_ks).await {
        Ok(auth) => return Ok(auth),
        // Only an authorization denial is eligible. A store or session failure
        // is an infrastructure fault, and quietly downgrading it to a
        // zero-authority dispatch would hide it behind a task that then fails
        // for some unrelated-looking reason.
        Err(AppError::Forbidden(why)) => why,
        Err(e) => return Err(e),
    };

    let type_uri = ceremony::peek_type_uri(body);
    match type_uri.as_deref() {
        Some(uri) if ceremony::is_ceremony_task(uri) => {
            tracing::info!(
                sender = %sender_did,
                type_uri = %uri,
                acl = %denial,
                "ceremony task from a sender with no ACL standing — dispatching on a \
                 zero-authority claim; the document's own proof is the authority"
            );
            Ok(ceremony::ceremony_claims(sender_did))
        }
        // Named so the operator can tell a refused task from one that never
        // arrived. Without this the reply is a `permissionDenied` envelope the
        // peer may not surface, and the VTA logs nothing at all — which is how a
        // consent ceremony that was answered by a human looked, from both ends,
        // exactly like one that was never delivered.
        other => {
            tracing::warn!(
                sender = %sender_did,
                type_uri = other.unwrap_or("<unparseable>"),
                "refusing trust task: {denial}"
            );
            Err(AppError::Forbidden(denial))
        }
    }
}

/// Resolve an envelope-authenticated sender DID into unified `AuthClaims`.
///
/// This is the DID-based core shared by every intrinsic-sender transport
/// (DIDComm authcrypt via [`auth_from_message`], raw-TSP via
/// `messaging::tsp_inbound`). The caller has *already* proven the sender
/// DID cryptographically — by unpacking an authcrypt envelope, or by
/// TSP unpack returning the verified `sender_vid` — so this function only
/// performs ACL lookup + session resolution + claim construction, never
/// signature verification.
///
/// Routes through [`check_acl_full`] (rather than the lower-level
/// `get_acl_entry`) so that `expires_at` is enforced identically to the
/// REST path. A time-bounded ACL grant must stop working over every
/// transport the moment it lapses.
///
/// Resolves (get-or-creates) the caller's **canonical, DID-keyed session** via
/// [`resolve_did_session`] and returns the session's *persisted* `acr`/`amr`
/// rather than a hardcoded `aal1`. This is what makes intrinsic-sender callers
/// first-class in the step-up flow: a step-up elevation recorded on this
/// session while handling one message is observed by the caller's subsequent
/// messages, instead of being reset to `aal1` every time.
pub async fn auth_from_did(
    did: &str,
    acl_ks: &KeyspaceHandle,
    sessions_ks: &KeyspaceHandle,
) -> Result<AuthClaims, AppError> {
    // Strip any fragment (e.g. did:key:z6Mk...#z6Mk... → did:key:z6Mk...)
    let base_did = did.split('#').next().unwrap_or(did);

    let (role, allowed_contexts) = check_acl_full(acl_ks, base_did).await?;

    // Get-or-create the persistent session keyed on the DID. The session_id
    // *is* the DID, so the delegated step-up records this id and elevates this
    // exact row; a later message resolves the same row and sees the raised acr
    // (or the post-window downgrade back to aal1, applied inside the resolver).
    let session = resolve_did_session(sessions_ks, base_did, now_epoch()).await?;

    Ok(AuthClaims {
        did: base_did.to_string(),
        role,
        allowed_contexts,
        session_id: session.session_id,
        // Intrinsic-sender auth carries no JWT, hence no access-token expiry.
        access_expires_at: 0,
        // Trust the session's persisted assurance level. A freshly-created
        // session is `aal1` with a single `did` factor; an elevated one reports
        // `aal2` until its window lapses.
        amr: session.amr,
        acr: session.acr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclEntry, Role, store_acl_entry};
    use crate::auth::session::now_epoch;
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    fn message_from(did: &str) -> Message {
        // Builds the minimal message shape `auth_from_message` consumes —
        // only `from` is read by the function under test.
        Message::build(
            "test-id".to_string(),
            "https://example.com/test/1.0/ping".to_string(),
            serde_json::json!({}),
        )
        .from(did.to_string())
        .finalize()
    }

    async fn fresh_acl_ks() -> (Store, KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        let sessions_ks = store.keyspace(crate::keyspaces::SESSIONS).unwrap();
        (store, acl_ks, sessions_ks, dir)
    }

    /// An expired ACL entry must be rejected over DIDComm with the same
    /// `Forbidden` outcome the REST `check_acl_full` path produces. This
    /// pins the cross-transport invariant the previous direct-lookup
    /// implementation broke.
    #[tokio::test]
    async fn rejects_expired_entry() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zExpired";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test")
                .with_contexts(vec!["ctx-a".into()])
                .with_created_at(now_epoch().saturating_sub(7200))
                .with_expires_at(Some(now_epoch().saturating_sub(60))), // expired one minute ago
        )
        .await
        .unwrap();

        let msg = message_from(did);
        let err = auth_from_message(&msg, &acl_ks, &sessions_ks)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(ref m) if m.contains("expired")),
            "expected Forbidden(expired), got {err:?}"
        );
    }

    /// A current (non-expired) entry resolves to the right role + contexts.
    /// Ensures the refactor didn't accidentally break the happy path.
    #[tokio::test]
    async fn accepts_unexpired_entry_with_role_and_contexts() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zLive";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test")
                .with_contexts(vec!["ctx-a".into(), "ctx-b".into()])
                .with_expires_at(Some(now_epoch() + 3600)),
        )
        .await
        .unwrap();

        let msg = message_from(did);
        let claims = auth_from_message(&msg, &acl_ks, &sessions_ks)
            .await
            .unwrap();
        assert_eq!(claims.did, did);
        assert_eq!(claims.role, Role::Admin);
        assert_eq!(claims.allowed_contexts, vec!["ctx-a", "ctx-b"]);
    }

    /// DID-fragment senders (e.g. `did:key:z…#z…`) must collapse to the
    /// base DID for the ACL lookup. Pre-existing behaviour preserved.
    #[tokio::test]
    async fn fragment_in_sender_collapses_to_base_did() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let base = "did:key:zBase";
        store_acl_entry(&acl_ks, &AclEntry::new(base, Role::Reader, "test"))
            .await
            .unwrap();

        let msg = message_from(&format!("{base}#zBase"));
        let claims = auth_from_message(&msg, &acl_ks, &sessions_ks)
            .await
            .unwrap();
        assert_eq!(claims.did, base);
    }

    /// `auth_from_did` (the transport-neutral core) resolves a DID with a
    /// live ACL entry to the right role + contexts. This is the path the
    /// TSP inbound loop drives directly (sender DID, no DIDComm message).
    #[tokio::test]
    async fn auth_from_did_resolves_role_and_contexts() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zDidCore";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test")
                .with_contexts(vec!["ctx-a".into(), "ctx-b".into()])
                .with_expires_at(Some(now_epoch() + 3600)),
        )
        .await
        .unwrap();

        let claims = auth_from_did(did, &acl_ks, &sessions_ks).await.unwrap();
        assert_eq!(claims.did, did);
        assert_eq!(claims.role, Role::Admin);
        assert_eq!(claims.allowed_contexts, vec!["ctx-a", "ctx-b"]);
    }

    /// A DID with no ACL entry errors (peer not authorized) — the TSP loop
    /// relies on this to drop unknown senders.
    #[tokio::test]
    async fn auth_from_did_unknown_did_errors() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let err = auth_from_did("did:key:zUnknownPeer", &acl_ks, &sessions_ks)
            .await
            .unwrap_err();
        // No ACL entry → check_acl_full surfaces a not-found / forbidden
        // class error; the exact variant is the ACL layer's, we just pin
        // that it is an error (never silently authorized).
        assert!(
            matches!(err, AppError::Forbidden(_) | AppError::NotFound(_)),
            "expected unauthorized-class error, got {err:?}"
        );
    }

    /// Fragmented DID collapses to base for the core too.
    #[tokio::test]
    async fn auth_from_did_fragment_collapses() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let base = "did:key:zCoreBase";
        store_acl_entry(&acl_ks, &AclEntry::new(base, Role::Reader, "test"))
            .await
            .unwrap();

        let claims = auth_from_did(&format!("{base}#zCoreBase"), &acl_ks, &sessions_ks)
            .await
            .unwrap();
        assert_eq!(claims.did, base);
    }

    #[tokio::test]
    async fn missing_sender_is_authentication_error() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let mut msg = message_from("did:key:zAnything");
        msg.from = None;
        let err = auth_from_message(&msg, &acl_ks, &sessions_ks)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Authentication(_)), "got {err:?}");
    }

    // ── The ceremony carve-out ───────────────────────────────────────────
    //
    // An approver device holds no authority to *act* — that is the entire point
    // of the `approve_scope` axis — so it has no reason to hold an ACL entry.
    // Before these, the transport gate refused it before any of the consent code
    // written to accommodate it could run, and the operator saw an approval that
    // a human gave, the wallet sent, and the VTA silently discarded.

    const DECISION: &str = vta_sdk::trust_tasks::TASK_TASK_CONSENT_DECISION_0_1;
    const ORDINARY: &str = "https://trusttasks.org/spec/vta/webvh/dids/update/1.0";

    fn envelope(type_uri: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": type_uri,
            "issuer": "did:key:zApproverDevice",
            "recipient": "did:example:vta",
            "issuedAt": "2026-08-08T21:56:00Z",
            "payload": { "challenge": "n", "payloadDigest": "d", "decision": "approve" },
        }))
        .unwrap()
    }

    /// The case from the field: an approver in the VTA's `approver_set` but not
    /// in its ACL. Its decision must reach the dispatcher.
    #[tokio::test]
    async fn a_ceremony_task_from_an_unenrolled_approver_is_dispatched() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let approver = "did:key:zApproverNotInAcl";

        let claims =
            auth_for_trust_task_envelope(approver, &envelope(DECISION), &acl_ks, &sessions_ks)
                .await
                .expect("an unenrolled approver must be able to deliver its decision");

        // The proven DID rides through — replay dedup, the audit trail and
        // `handle_approve_response`'s issuer check all key on it.
        assert_eq!(claims.did, approver);
        // …carrying no authority whatsoever.
        assert_eq!(claims.role, Role::Monitor);
        assert!(claims.allowed_contexts.is_empty());
        assert!(!claims.is_super_admin());
    }

    /// The carve-out is for ceremony tasks and nothing else. The same
    /// unenrolled DID submitting the operation the ceremony *authorizes* is
    /// refused exactly as before — otherwise this would be a hole, not a gate.
    #[tokio::test]
    async fn the_same_unenrolled_sender_cannot_submit_an_ordinary_task() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let err = auth_for_trust_task_envelope(
            "did:key:zApproverNotInAcl",
            &envelope(ORDINARY),
            &acl_ks,
            &sessions_ks,
        )
        .await
        .expect_err("a webvh update from an unenrolled DID must still be refused");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    /// A body we cannot read is not a ceremony task. Nothing may talk its way
    /// past the ACL by being unparseable.
    #[tokio::test]
    async fn an_unreadable_envelope_from_an_unenrolled_sender_is_refused() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        for body in [b"not json".as_slice(), b"{}".as_slice(), b"".as_slice()] {
            let err =
                auth_for_trust_task_envelope("did:key:zStranger", body, &acl_ks, &sessions_ks)
                    .await
                    .expect_err("an unparseable body must not reach the carve-out");
            assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
        }
    }

    /// The carve-out is a *fallback*, not an override. An approver that IS
    /// enrolled keeps the claims its ACL entry earns it — a co-located approver
    /// which is also an admin must not be silently downgraded.
    #[tokio::test]
    async fn an_enrolled_sender_keeps_its_real_claims_on_a_ceremony_task() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zEnrolledApprover";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test").with_contexts(vec!["ctx-a".into()]),
        )
        .await
        .unwrap();

        let claims = auth_for_trust_task_envelope(did, &envelope(DECISION), &acl_ks, &sessions_ks)
            .await
            .unwrap();
        assert_eq!(claims.role, Role::Admin);
        assert_eq!(claims.allowed_contexts, vec!["ctx-a"]);
    }

    /// A lapsed ACL grant must not strand a decision either. Approve-authority
    /// comes from the approver set, not from an ACL row; where a grant's
    /// *delegation* does depend on live ACL state, `compute_delegated_contexts`
    /// re-reads it and refuses the expired entry at the point it would actually
    /// confer something.
    #[tokio::test]
    async fn an_expired_grant_still_lets_a_ceremony_task_through_with_nothing() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zLapsedApprover";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test")
                .with_contexts(vec!["ctx-a".into()])
                .with_created_at(now_epoch().saturating_sub(7200))
                .with_expires_at(Some(now_epoch().saturating_sub(60))),
        )
        .await
        .unwrap();

        let claims = auth_for_trust_task_envelope(did, &envelope(DECISION), &acl_ks, &sessions_ks)
            .await
            .expect("a lapsed grant must not strand an approval");
        assert_eq!(
            claims.role,
            Role::Monitor,
            "the lapsed entry's admin role must NOT be resurrected by the carve-out"
        );
        assert!(claims.allowed_contexts.is_empty());
    }

    /// No session row is minted for an unenrolled approver. Otherwise any DID
    /// that can reach the mediator could write one.
    #[tokio::test]
    async fn the_carve_out_does_not_mint_a_session_for_an_unenrolled_did() {
        use crate::auth::session::get_session;
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let approver = "did:key:zNoSessionPlease";

        auth_for_trust_task_envelope(approver, &envelope(DECISION), &acl_ks, &sessions_ks)
            .await
            .unwrap();

        assert!(
            get_session(&sessions_ks, approver).await.unwrap().is_none(),
            "a ceremony dispatch must not create session state for an unenrolled DID"
        );
    }

    /// First contact reports `aal1`, keyed on the DID. After a step-up elevates
    /// that same `session:{did}` row, the *next* message reports the elevated
    /// acr — the whole point of a persistent, transport-agnostic session. Before
    /// this change `auth_from_did` hardcoded `aal1`, so a verified elevation was
    /// invisible and the caller could never clear a step-up gate over DIDComm.
    #[tokio::test]
    async fn auth_from_did_reports_persisted_elevated_acr() {
        use crate::auth::session::{get_session, update_session};

        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zElevatedCaller";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test").with_expires_at(Some(now_epoch() + 3600)),
        )
        .await
        .unwrap();

        // First contact → aal1, session_id is the DID.
        let first = auth_from_did(did, &acl_ks, &sessions_ks).await.unwrap();
        assert_eq!(first.acr, "aal1");
        assert_eq!(first.session_id, did);

        // Elevate the row as the step-up handler does.
        let mut s = get_session(&sessions_ks, did).await.unwrap().unwrap();
        s.acr = "aal2".into();
        s.acr_expires_at = Some(now_epoch() + 900);
        update_session(&sessions_ks, &s).await.unwrap();

        // Next message observes the elevation.
        let next = auth_from_did(did, &acl_ks, &sessions_ks).await.unwrap();
        assert_eq!(next.acr, "aal2");
    }
}
