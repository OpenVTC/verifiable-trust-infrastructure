//! The vetting verbs: statement withdrawal, the vetter grant and the vetter
//! profile reads and writes (`vtc/vetting/*`).
//!
//! Moved out of `trust_tasks/mod.rs` (#2579); the spine glue and the router
//! stay there.

use super::*;

// ─── vetting statement withdrawal ──────────────────────────────────────────

/// `vtc/vetting/revoke-statement/0.1` — a vetter withdraws a statement.
///
/// The sender is the proven signer (REST document proof or DIDComm authcrypt).
/// What a notice may do, and who may send one, is decided in
/// [`crate::vetting::revocation::withdraw`].
pub(super) async fn handle_revoke_statement(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let vetter_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: revoke_statement::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let answer = crate::vetting::revocation::withdraw(state, &vetter_did, &body)
        .await
        .and_then(|notice| {
            revoke_statement::Response::try_from(
                revoke_statement::Response::builder().recorded_at(notice.recorded_at),
            )
            .map_err(|e| AppError::Internal(format!("revoke-statement response: {e}")).into())
        });
    match answer {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/grant/0.1` — an admin names a member a vetter.
///
/// The acting administrator is resolved as for every other administrative
/// task — the proven signer, or the administrator a console key acts for
/// ([`admin_signer`]) — and held to `vtc.vetting.manage` (VTI-ACL-030).
/// Whom (a current member) is decided in [`crate::vetting::vetters::grant`],
/// the same path `POST /v1/vetting/vetters` takes. Resolving the bare signer
/// here, as this handler once did, refused every grant the console made: the
/// console signs with its own `did:key`, which holds no entry of its own.
pub(super) async fn handle_vetter_grant(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let admin_did = match capable_signer(
        state,
        ctx,
        &doc,
        crate::acl::Capability::VettingManage,
        None,
    )
    .await
    {
        Ok(claims) => claims.did,
        Err(reject) => return reject,
    };
    let body: vetting_wire::vetters::grant::v0_1::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::vetting::vetters::grant(state, &admin_did, &body).await {
        Ok(grant) => success_response(&doc, grant.response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// Parse a published task's payload as received: the JSON is validated against
/// the published schema before it is parsed — a generated constructor can
/// normalise what it reads — and then the rules no schema can state are applied
/// ([`vetting_wire::read_checked`]). A payload failing any of it is
/// `malformedRequest`.
pub(super) fn parse_checked_payload<P>(doc: &TrustTask<Value>) -> Result<P, TrustTaskOutcome>
where
    P: trust_tasks_rs::Payload + serde::de::DeserializeOwned + vetting_wire::CheckShape,
{
    vetting_wire::read_checked::<P>(&doc.payload).map_err(|e| {
        reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("payload: {e}"),
            },
        )
    })
}

/// `vtc/vetting/vetters/profile/0.1` — a vetter publishes their profile.
///
/// The sender is the proven signer and the only vetter whose profile it can
/// write. Who may publish is decided in [`crate::vetting::profiles::publish`];
/// a sender without a live grant is refused with the task's `notEligible`.
pub(super) async fn handle_vetter_profile(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let vetter_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: vetting_wire::vetters::profile::v0_1::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::vetting::profiles::publish(state, &vetter_did, &body, doc.issued_at).await {
        Ok(response) => success_response(&doc, response),
        Err(AppError::Forbidden(reason)) => reject_with_code(
            &doc,
            extended_code(vetting_wire::VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE),
            reason,
            None,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/list/0.1` — find listed vetters.
///
/// Any identified caller, member or applicant. [`resolve_holder`] is what
/// refuses an unidentified one — no proof over REST, no authenticated sender
/// otherwise — with `permissionDenied`, before anything is read.
pub(super) async fn handle_vetter_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = resolve_holder(state, ctx, &doc).await {
        return reject;
    }
    let body: vetting_wire::vetters::list::v0_1::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::vetting::profiles::list(state, &body).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/show/0.1` — one vetter's grant status, by DID.
///
/// Identified callers only, like the listing: the answer is about a named
/// third party's standing in this community.
pub(super) async fn handle_vetter_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = resolve_holder(state, ctx, &doc).await {
        return reject;
    }
    let body: vetting_wire::vetters::show::v0_1::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::vetting::profiles::show(state, &body).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/resend/0.2` — a vetter asks for their grant credential
/// again, or an administrator asks on a named vetter's behalf.
///
/// Absent `memberDid`, this is `0.1`'s behaviour, which it replaces: the
/// sender identified by the document's own proof (`resolve_holder`),
/// resending their own grant. Present, [`admin_signer`] establishes the
/// sender holds the community-administrator capability — refusing with
/// `permissionDenied` otherwise, per the specification's Conformance item 2 —
/// and honours a console-key delegation exactly as the other admin verbs do;
/// the resend then concerns `memberDid`'s grant, not the sender's own. Either
/// way the actor recorded on the `VetterGrantResent` audit entry is the
/// sender, never the subject, so an administrator's resend is attributable to
/// the administrator who asked for it.
pub(super) async fn handle_vetter_resend(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use trust_tasks_rs::{StandardCode, TrustTaskCode};

    let body: vetting_wire::vetters::resend::v0_2::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let (actor_did, subject_did) = match body.member_did.as_ref() {
        Some(member_did) => {
            let admin = match capable_signer(
                state,
                ctx,
                &doc,
                crate::acl::Capability::VettingManage,
                None,
            )
            .await
            {
                Ok(a) => a,
                Err(reject) => return reject,
            };
            (admin.did, member_did.to_string())
        }
        None => {
            let vetter_did = match resolve_holder(state, ctx, &doc).await {
                Ok(did) => did,
                Err(reject) => return reject,
            };
            (vetter_did.clone(), vetter_did)
        }
    };
    match crate::vetting::vetters::resend(state, &actor_did, &subject_did).await {
        // `notGranted` is a `NotFound` underneath, and its local part is not
        // `notFound`, so #1602's client-side rule does not recover it — the
        // marker is the only thing that does.
        Err(AppError::NotFound(reason)) => reject_with_code_because(
            &doc,
            extended_code(vetting_wire::VETTING_VETTER_RESEND_ERR_NOT_GRANTED),
            reason,
            None,
            reasons::NOT_FOUND,
        ),
        Err(AppError::ServiceError { status, message })
            if status == axum::http::StatusCode::SERVICE_UNAVAILABLE =>
        {
            reject_with_code(
                &doc,
                TrustTaskCode::Standard(StandardCode::Unavailable),
                message,
                None,
            )
        }
        Err(e) => app_error_to_reject(&doc, &e),
        Ok(response) => success_response(&doc, response),
    }
}

/// `vtc/vetting/vetters/grant/0.1` signed by a console key: the grant is the
/// administrator's, as for every other administrative task (VTI-ACL-030).
#[cfg(test)]
mod vetter_grant_console_key_tests {
    use super::*;
    use crate::acl::console_key::{ConsoleKeyDelegation, DelegationScope, store_delegation};
    use crate::acl::{AdminAuthority, VtcAclEntry, VtcRole, store_acl_entry};
    use crate::members::{Member, store_member};
    use crate::test_support::TestVtc;
    use crate::trust_tasks::test_fixtures::{dispatch, error_code, signed};
    use serde_json::json;
    use vti_rooms_dtg::test_support::Party;

    const MEMBER: &str = "did:key:zVetterGrantConsoleKeyMember";

    async fn seed(vtc: &TestVtc, did: &str, role: VtcRole, admin: AdminAuthority) {
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: did.into(),
                role,
                label: None,
                admin,
                delegated_by: None,
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
                resource_grants: Vec::new(),
                group_grants: Vec::new(),
                label_set_by_subject: false,
                suspension: None,
            },
        )
        .await
        .expect("seed ACL row");
    }

    async fn delegate(vtc: &TestVtc, console: &Party, admin_did: &str) {
        store_delegation(
            &vtc.state.console_keys_ks,
            &ConsoleKeyDelegation {
                console_did: console.did.clone(),
                admin_did: admin_did.to_string(),
                scope: DelegationScope::Console,
                label: None,
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(1),
                last_used_at: None,
                revoked_at: None,
                revoked_by: None,
            },
        )
        .await
        .expect("store delegation");
    }

    /// A community with one community-admin and one member to name a vetter.
    async fn community() -> (TestVtc, Party) {
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .build()
            .await;
        let admin = Party::new();
        seed(
            &vtc,
            &admin.did,
            VtcRole::Admin,
            AdminAuthority::community_admin(),
        )
        .await;
        seed(&vtc, MEMBER, VtcRole::Member, AdminAuthority::none()).await;
        store_member(&vtc.state.members_ks, &Member::fresh(MEMBER))
            .await
            .expect("store member");
        // A grant issues a revocable vetter role credential.
        for purpose in [
            affinidi_status_list::StatusPurpose::Revocation,
            affinidi_status_list::StatusPurpose::Suspension,
        ] {
            crate::status_list::ensure_initial(
                &vtc.state.status_lists_ks,
                purpose,
                format!("https://vtc.example.com/v1/status-lists/{purpose}"),
            )
            .await
            .expect("provision status list");
        }
        (vtc, admin)
    }

    fn grant() -> Value {
        json!({ "memberDid": MEMBER })
    }

    #[tokio::test]
    async fn vti_acl_030_a_console_key_grants_a_vetter_as_its_community_admin() {
        let (vtc, admin) = community().await;
        let console = Party::new();
        delegate(&vtc, &console, &admin.did).await;
        let doc = signed(&console, vetting_wire::VETTING_VETTER_GRANT_TYPE, grant()).await;
        let out = dispatch(&vtc, &doc).await;
        assert_eq!(error_code(&out), None, "{out:?}");
        let rows = crate::vetting::vetters::grant_rows(&vtc.state)
            .await
            .expect("grant rows");
        assert!(
            rows.iter().any(|r| r.member_did == MEMBER && !r.revoked),
            "the member is a vetter: {rows:?}"
        );
    }

    #[tokio::test]
    async fn vti_acl_030_a_console_key_with_no_delegation_grants_nothing() {
        let (vtc, _admin) = community().await;
        let console = Party::new();
        let doc = signed(&console, vetting_wire::VETTING_VETTER_GRANT_TYPE, grant()).await;
        let out = dispatch(&vtc, &doc).await;
        assert!(error_code(&out).is_some(), "refused: {out:?}");
        let rows = crate::vetting::vetters::grant_rows(&vtc.state)
            .await
            .expect("grant rows");
        assert!(rows.is_empty(), "nothing granted: {rows:?}");
    }

    #[tokio::test]
    async fn vti_acl_030_a_console_key_of_an_admin_without_vetting_manage_grants_nothing() {
        let (vtc, _admin) = community().await;
        let moderator = Party::new();
        seed(
            &vtc,
            &moderator.did,
            VtcRole::Admin,
            AdminAuthority::for_role(crate::acl::AdminRole::Moderator),
        )
        .await;
        let console = Party::new();
        delegate(&vtc, &console, &moderator.did).await;
        let doc = signed(&console, vetting_wire::VETTING_VETTER_GRANT_TYPE, grant()).await;
        let out = dispatch(&vtc, &doc).await;
        assert!(error_code(&out).is_some(), "refused: {out:?}");
    }
}
