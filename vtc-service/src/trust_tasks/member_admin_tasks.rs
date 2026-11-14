//! The administrator's member verbs (`vtc/members/{credentials,update,
//! admin-remove,purge}`) and a member's reciprocal VMC (`members/vmc`).
//!
//! Moved out of `trust_tasks/mod.rs` (#2579); the spine glue and the router
//! stay there.

use super::routing::{Routes, on};
use super::*;

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    let routes = on!(routes, vti_specs::vtc::members::vmc::v0_1::Payload => handle_member_vmc);
    let routes = on!(routes, vti_specs::vtc::members::credentials::v0_1::Payload => handle_member_credentials);
    let routes =
        on!(routes, vti_specs::vtc::members::update::v0_1::Payload => handle_member_update);
    let routes = on!(routes, vti_specs::vtc::members::admin_remove::v0_1::Payload => handle_member_admin_remove);
    on!(routes, vti_specs::vtc::members::purge::v0_1::Payload => handle_member_purge)
}

/// `vtc/members/credentials/0.1` — the membership pair's bodies for one member.
///
/// Administrator only. The read is audited against the **signer**, which is the
/// point of the task declaring a proof: the specification's own rationale is
/// that "the record of who read a member's credentials is the only thing that
/// makes the disclosure accountable afterwards", and a bearer token names a
/// session rather than a key.
pub(super) async fn handle_member_credentials(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(
        state,
        ctx,
        &doc,
        crate::acl::Capability::MembersManage,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let body: member_credentials::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::members::ops::credentials::read_member_credentials(
        state,
        &actor.did,
        body.did.as_str(),
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        // The task's one declared code, carried as a code rather than flattened
        // into `taskFailed` (SPEC §8.5) — the same distinction the REST route's
        // `CredentialsError` makes in its body.
        Err(crate::members::ops::credentials::CredentialsError::NotFound(message)) => {
            task_error_to_reject(
                &doc,
                &crate::error::TaskError::declared(
                    crate::members::ops::credentials::MEMBER_CREDENTIALS_ERR_NOT_FOUND,
                    AppError::NotFound(message),
                ),
            )
        }
        Err(crate::members::ops::credentials::CredentialsError::Other(e)) => {
            app_error_to_reject(&doc, &e)
        }
    }
}

/// `vtc/members/update/0.1` — update a member's role or metadata.
///
/// Administrator only, and `role: admin` is refused with the task's own
/// `adminRoleForbidden` — the gate is on the transition, not on the route, so
/// it holds identically on both doors.
///
/// # An absent `extensions`
///
/// The generated `Payload` types `extensions` as a plain map with `default`, so
/// an absent `extensions` and an empty one are the same value once parsed —
/// and the operation's rule is that an absent field leaves the member's
/// extensions **unchanged** while an empty object replaces them. Whether it was
/// sent is read from the document as received ([`crate::wire::sent`]).
pub(super) async fn handle_member_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(
        state,
        ctx,
        &doc,
        crate::acl::Capability::MembersManage,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: member_update::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let extensions = crate::wire::sent(
        &doc.payload,
        "extensions",
        Value::Object(checked.extensions.clone()),
    );
    match crate::members::ops::update::update_member_inner(
        state,
        &actor,
        checked.did.as_str(),
        &checked,
        extensions,
    )
    .await
    {
        Ok(envelope) => success_response(&doc, envelope),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/admin-remove/0.1` — an administrator removes another member.
pub(super) async fn handle_member_admin_remove(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(
        state,
        ctx,
        &doc,
        crate::acl::Capability::MembersManage,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: member_admin_remove::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::members::ops::remove::admin_remove_inner(
        state,
        &actor,
        checked.did.as_str(),
        &checked,
        crate::acl::admin_consent::Operation {
            type_uri: &doc.type_uri.for_routing().to_string(),
            payload: &doc.payload,
        },
    )
    .await
    {
        Ok(outcome) => success_response(
            &doc,
            crate::members::ops::remove::RemoveResponse::from(outcome),
        ),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/purge/0.1` — irreversibly erase a member record.
///
/// **Super-administrator only**, which is a stricter gate than the other three
/// and must stay one: the bearer route takes `SuperAdminAuth`, so the signed
/// door asks [`AuthClaims::require_super_admin`] the same question —
/// `Role::Admin` **and** an unrestricted [`vti_common::acl::ActScope`]. Reading
/// `allowed_contexts.is_empty()` here instead would be the exact inversion
/// `CLAUDE.md` names: empty means *unrestricted* for an admin and *authorized
/// nowhere* for anybody else.
pub(super) async fn handle_member_purge(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(
        state,
        ctx,
        &doc,
        crate::acl::Capability::MembersManage,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: member_purge::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // The REST route validates the path segment; here the DID rides the
    // payload, and `purge_member` does not validate it for us.
    if let Err(e) = vti_common::identifier::validate_did("did", checked.did.as_str()) {
        return app_error_to_reject(&doc, &e);
    }
    match crate::ceremony::purge_member(state, &actor.did, checked.did.as_str()).await {
        Ok(outcome) => success_response(
            &doc,
            crate::members::ops::remove::RemoveResponse::from(outcome),
        ),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `members/vmc/0.1` as a Trust Task document — a member submits their
/// reciprocal VMC (the member → community half of the membership pair),
/// optionally closing an approved join request via `requestId` (the retired
/// `join-requests/accept` semantics).
///
/// Same spine as the DIDComm handler: `receive_member_vmc_inner` verifies the
/// issuer / subject binding and the DI proof before storing it on the member
/// row. The proven member comes from [`resolve_holder`], so the authenticated
/// identity is the transport's (DIDComm authcrypt sender / TSP sender VID) or
/// the document proof signer — never a self-asserted `issuer`.
pub(super) async fn handle_member_vmc(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let member_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: MemberVmcBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // `request_id` travels as a string (the SDK's `members` module compiles
    // featureless, without `uuid`); a malformed id is a framework reject, not
    // a lookup miss.
    let request_id = match body
        .request_id
        .as_deref()
        .map(uuid::Uuid::parse_str)
        .transpose()
    {
        Ok(r) => r,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("requestId is not a UUID: {e}"),
                },
            );
        }
    };

    match crate::members::inbound_vmc::receive_member_vmc_inner(
        state, member_did, body.vc, request_id,
    )
    .await
    {
        Ok(outcome) => success_response(
            &doc,
            MemberVmcReceiptBody {
                member_did: outcome.member_did,
                vmc_id: outcome.vmc_id,
                status: "stored".to_string(),
                request_id: outcome.request_id.map(|u| u.to_string()),
            },
        ),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// The helpers below are `pub(super)` so [`join_decide_profile_tests`] — batch
/// 2's tests — build and dispatch documents exactly as these do. Two harnesses
/// for one binding would diverge, and the first thing to drift would be what
/// "signed" means.
///
/// The admin-facing member verbs, served as signed Trust Task documents —
/// **#1641 phase 2, batch 1**.
///
/// Four tasks (`vtc/members/{credentials,update,admin-remove,purge}`) whose
/// specifications declare `proof` REQUIRED were served only as flat-payload
/// REST behind a bearer JWT, so they got none of what the spine enforces: no
/// proof, no recipient binding, no acceptance window, and nothing in the
/// accepted-id record. They are now bound here as well.
///
/// What these tests hold, and why each one is here:
///
/// - **VTI-OPS-020** — the document carries a proof by its issuer, and that
///   issuer's **ACL entry** is what authorizes the operation. A bearer token is
///   not read on this endpoint at all.
/// - **VTI-OPS-025 / -026 / -027** — a redelivered document is answered with
///   the recorded outcome rather than executed again, a *different* document
///   under a spent `id` is `idConflict`, and the record is the shared
///   store-backed one. All three come from the spine's claim; these drive them
///   through a real admin verb, because the failure they guard against
///   ("purge executed twice") is only visible at a verb with an effect.
/// - **The gate the bearer route applied must still refuse what it refused.**
///   Losing one silently is the risk in the whole migration, so each refusal
///   the REST extractors made has a test here: not an admin (`AdminAuth`), and
///   for `purge` a context-scoped admin who is not a super-admin
///   (`SuperAdminAuth`). Plus the operations' own refusals — unknown member,
///   `role: admin`.
#[cfg(test)]
mod members_admin_tests {
    use super::*;
    use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
    use crate::members::{Member, get_member, store_member};
    use crate::test_support::TestVtc;
    use crate::trust_tasks::test_fixtures::*;
    use serde_json::json;
    use vti_rooms_dtg::test_support::Party;

    /// The member these documents act on. Never one of the signers, so an
    /// `admin-remove` cannot collide with the "use /members/me" guard.
    const TARGET: &str = "did:key:zTargetMember";

    struct Fixture {
        vtc: TestVtc,
        /// `VtcRole::Admin`, unrestricted — a super-admin, so every verb here
        /// including `purge` is open to them.
        admin: Party,
        /// `VtcRole::Admin` **scoped to one context** — an admin, but not a
        /// super-admin. `SuperAdminAuth` refuses this caller and `AdminAuth`
        /// does not, which is the distinction `purge` rests on.
        scoped_admin: Party,
        /// `VtcRole::Member` — authenticated, authorized for none of this.
        member: Party,
    }

    async fn fixture() -> Fixture {
        // `with_audit` because every one of these verbs writes an audit row and
        // refuses rather than acting when it cannot; `with_signers` because the
        // removal ceremony re-mints credentials and the spine signs its replies.
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .build()
            .await;
        crate::policy::default::install_defaults(
            &vtc.state.policies_ks,
            &vtc.state.active_policies_ks,
        )
        .await
        .expect("install default policies");

        let admin = Party::new();
        let scoped_admin = Party::new();
        let member = Party::new();
        seed_acl(&vtc, &admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(
            &vtc,
            &scoped_admin.did,
            VtcRole::Admin,
            vec!["ctx-a".to_string()],
        )
        .await;
        seed_acl(&vtc, &member.did, VtcRole::Member, vec![]).await;

        // The subject these documents name: a member row *and* an ACL row,
        // which is what `members/credentials` means by "is a member".
        seed_acl(&vtc, TARGET, VtcRole::Member, vec![]).await;
        store_member(&vtc.state.members_ks, &Member::fresh(TARGET))
            .await
            .expect("seed target member");

        Fixture {
            vtc,
            admin,
            scoped_admin,
            member,
        }
    }

    // ─── the premise ─────────────────────────────────────────────────────

    /// If the registry ever relaxed one of these declarations, every test below
    /// would be asserting nothing. This one says so first.
    #[test]
    fn every_moved_task_declares_the_proof_these_tests_assume() {
        for uri in [
            MEMBER_CREDENTIALS_TYPE,
            MEMBER_UPDATE_TYPE,
            MEMBER_ADMIN_REMOVE_TYPE,
            MEMBER_PURGE_TYPE,
        ] {
            let policy = vti_specs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published spec policy"));
            assert!(
                policy.is_proof_required,
                "{uri} no longer declares proof REQUIRED — these tests now assert \
                 nothing, and the design note should be re-read"
            );
        }
    }

    // ─── VTI-OPS-020: a proof by the issuer, authorized from their ACL ────

    /// **VTI-OPS-020.** A signed document from an admin is accepted and
    /// answered with the task's own response shape.
    #[tokio::test]
    async fn vti_ops_020_a_signed_admin_document_reads_member_credentials() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_CREDENTIALS_TYPE,
            json!({ "did": TARGET }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "a signed admin document must be accepted: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["did"], TARGET);
        assert_eq!(payload_of(&out)["memberVmcBound"], false);
        assert_conforms::<member_credentials::Response>(&out);
    }

    /// **VTI-OPS-020.** The *same* document with its proof stripped is refused
    /// with the framework's own code — the transport proved nothing and there
    /// is nothing else to authorize against.
    #[tokio::test]
    async fn vti_ops_020_an_unsigned_admin_document_is_refused() {
        let fix = fixture().await;
        for uri in [
            MEMBER_CREDENTIALS_TYPE,
            MEMBER_UPDATE_TYPE,
            MEMBER_ADMIN_REMOVE_TYPE,
            MEMBER_PURGE_TYPE,
        ] {
            let doc = unsigned(&fix.admin, uri, json!({ "did": TARGET }));
            let out = dispatch(&fix.vtc, &doc).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("proofRequired"),
                "{uri}: SPEC §7.2 item 7 names the code: {}",
                String::from_utf8_lossy(&out.body)
            );
        }
        // …and nothing was removed by the unsigned `admin-remove` / `purge`.
        assert!(
            get_member(&fix.vtc.state.members_ks, TARGET)
                .await
                .expect("read member")
                .is_some(),
            "an unsigned document must not have had an effect"
        );
    }

    /// Authorization is the **signer's ACL entry**, not a bearer token: a
    /// correctly signed document from a DID with no admin row is refused, which
    /// is what `AdminAuth` refused on the REST route.
    #[tokio::test]
    async fn a_non_admin_signer_is_refused_every_admin_member_verb() {
        let fix = fixture().await;
        for uri in [
            MEMBER_CREDENTIALS_TYPE,
            MEMBER_UPDATE_TYPE,
            MEMBER_ADMIN_REMOVE_TYPE,
            MEMBER_PURGE_TYPE,
        ] {
            let doc = signed(&fix.member, uri, json!({ "did": TARGET })).await;
            let out = dispatch(&fix.vtc, &doc).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{uri}: a member is not an administrator: {}",
                String::from_utf8_lossy(&out.body)
            );
        }
    }

    /// A DID with **no ACL row at all** is refused the same way — the signature
    /// verifies, and verifying a signature is not authorization.
    #[tokio::test]
    async fn a_signer_with_no_acl_row_is_refused() {
        let fix = fixture().await;
        let stranger = Party::new();
        let doc = signed(&stranger, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
    }

    /// An **expired** ACL row no longer authorizes, which the bearer route
    /// could not notice: its JWT was minted while the row was live and nothing
    /// re-reads it. This is the one place the signed door is strictly stricter.
    #[tokio::test]
    async fn an_expired_admin_acl_row_no_longer_authorizes() {
        let fix = fixture().await;
        let lapsed = Party::new();
        store_acl_entry(
            &fix.vtc.state.acl_ks,
            &VtcAclEntry {
                did: lapsed.did.clone(),
                role: VtcRole::Admin,
                label: None,
                admin: VtcRole::Admin.implied_authority(),
                delegated_by: None,
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: Some(1),
                resource_grants: Vec::new(),
                group_grants: Vec::new(),
                label_set_by_subject: false,
                suspension: None,
            },
        )
        .await
        .expect("seed a lapsed admin row");

        let doc = signed(&lapsed, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
    }

    // ─── the scope gate `purge` rests on ─────────────────────────────────

    // ─── the capability `purge` rests on ─────────────────────────────────

    /// An administrator of this community, with a role, who does not hold
    /// `vtc.members.manage`: an auditor.
    async fn auditor(vtc: &TestVtc) -> Party {
        let p = Party::new();
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                admin: crate::acl::AdminAuthority::for_role(crate::acl::AdminRole::Auditor),
                ..VtcAclEntry::new(
                    &p.did,
                    VtcRole::Member,
                    crate::acl::AdminAuthority::none(),
                    "test",
                )
            },
        )
        .await
        .expect("seed an auditor");
        p
    }

    /// **`purge` takes `vtc.members.manage`** (`vtc-admin-roles.md` §4). An
    /// administrator without it — an auditor — is refused, and nothing is
    /// erased (VTI-ACL-030).
    #[tokio::test]
    async fn vti_acl_030_purge_needs_vtc_members_manage() {
        let fix = fixture().await;
        let auditor = auditor(&fix.vtc).await;
        let doc = signed(&auditor, MEMBER_PURGE_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some("permissionDenied"),
            "purge takes vtc.members.manage: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(
            get_member(&fix.vtc.state.members_ks, TARGET)
                .await
                .expect("read member")
                .is_some(),
            "the refused purge must not have erased the member"
        );
    }

    /// …and the same caller *is* an administrator for the other three, exactly
    /// as `AdminAuth` admitted them. A gate copied one notch too tight is as
    /// much a regression as one copied too loose.
    #[tokio::test]
    async fn a_context_scoped_admin_may_still_read_credentials() {
        let fix = fixture().await;
        let doc = signed(
            &fix.scoped_admin,
            MEMBER_CREDENTIALS_TYPE,
            json!({ "did": TARGET }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "a context-scoped admin passes AdminAuth and must pass here: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    // ─── console-key delegations: acting as, and the four ways it stops ──
    //
    // #1684. A console signing key is a credential of an admin DID, not an
    // identity — it holds no ACL row and confers nothing. These drive the one
    // property that makes that safe: the delegation is *only* a name lookup,
    // and everything that decides authority is still the ACL row, read at
    // execution time. Four separate levers must each stop it dead.

    /// Enrol a console key for an admin directly in the store, the way
    /// `POST /v1/admin/console-keys` does behind its step-up. The route's own
    /// gates are exercised in `tests/admin_console_keys.rs`; these tests are
    /// about what the *verifier* does with the record afterwards.
    async fn delegate(vtc: &TestVtc, console: &Party, admin_did: &str) {
        crate::acl::console_key::enrol_delegation(
            &vtc.state.console_keys_ks,
            &vtc.state.acl_ks,
            &console.did,
            admin_did,
            Some("test browser".into()),
            None,
        )
        .await
        .expect("enrol the delegation");
    }

    /// The point of the whole change: a document signed by a key with **no ACL
    /// row of its own** is accepted, because the key is enrolled as a
    /// credential of a DID that has one.
    #[tokio::test]
    async fn a_delegated_console_key_acts_as_its_admin() {
        let fix = fixture().await;
        let console = Party::new();
        delegate(&fix.vtc, &console, &fix.admin.did).await;

        let doc = signed(&console, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "a delegated console key must authorize as its admin: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["did"], TARGET);
    }

    /// Lever 1 — **revocation, effective on the next document.** Nothing is
    /// cached, so there is no window in which a revoked browser still works.
    #[tokio::test]
    async fn a_revoked_delegation_stops_authorizing_immediately() {
        let fix = fixture().await;
        let console = Party::new();
        delegate(&fix.vtc, &console, &fix.admin.did).await;

        // It works…
        let first = signed(&console, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        assert!(dispatch(&fix.vtc, &first).await.status.is_success());

        crate::acl::console_key::revoke_delegation(
            &fix.vtc.state.console_keys_ks,
            &console.did,
            &fix.admin.did,
        )
        .await
        .expect("revoke");

        // …and then it does not, with no restart, no re-login and no sweep.
        let second = signed(&console, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &second).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("permissionDenied"),
            "a revoked console key must be refused: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// Lever 2 — **the delegating admin's ACL row is removed.** The row was
    /// always the authority; dropping it kills every key delegated from it at
    /// once, which is why a delegation needs no separate cascade.
    #[tokio::test]
    async fn removing_the_admins_acl_row_stops_the_delegated_key() {
        let fix = fixture().await;
        let console = Party::new();
        delegate(&fix.vtc, &console, &fix.admin.did).await;

        crate::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &fix.admin.did)
            .await
            .expect("remove the admin row");

        let doc = signed(&console, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        assert_eq!(
            error_code(&dispatch(&fix.vtc, &doc).await).as_deref(),
            Some("permissionDenied")
        );
    }

    /// Lever 3 — **the delegating admin is demoted.** `resolve_auth_role`
    /// admits only `VtcRole::Admin`, and it runs against the row as it is now,
    /// not as it was when the key was enrolled.
    #[tokio::test]
    async fn demoting_the_admin_stops_the_delegated_key() {
        let fix = fixture().await;
        let console = Party::new();
        delegate(&fix.vtc, &console, &fix.admin.did).await;

        seed_acl(&fix.vtc, &fix.admin.did, VtcRole::Member, vec![]).await;

        let doc = signed(&console, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        assert_eq!(
            error_code(&dispatch(&fix.vtc, &doc).await).as_deref(),
            Some("permissionDenied")
        );
    }

    /// Lever 4 — **the delegating admin's row expires.** Same read, same
    /// instant, same refusal.
    #[tokio::test]
    async fn an_expired_admin_row_stops_the_delegated_key() {
        let fix = fixture().await;
        let console = Party::new();
        delegate(&fix.vtc, &console, &fix.admin.did).await;

        store_acl_entry(
            &fix.vtc.state.acl_ks,
            &VtcAclEntry {
                did: fix.admin.did.clone(),
                role: VtcRole::Admin,
                label: None,
                admin: VtcRole::Admin.implied_authority(),
                delegated_by: None,
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: Some(1),
                resource_grants: Vec::new(),
                group_grants: Vec::new(),
                label_set_by_subject: false,
                suspension: None,
            },
        )
        .await
        .expect("expire the admin row");

        let doc = signed(&console, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        assert_eq!(
            error_code(&dispatch(&fix.vtc, &doc).await).as_deref(),
            Some("permissionDenied")
        );
    }

    /// **A delegation cannot reach further than the admin it acts for.** A key
    /// delegated by an auditor is refused `purge` exactly as the auditor is —
    /// the delegation is a name lookup, not a widening.
    #[tokio::test]
    async fn a_delegation_inherits_its_admins_ceiling_and_no_more() {
        let fix = fixture().await;
        let auditor = auditor(&fix.vtc).await;
        let console = Party::new();
        delegate(&fix.vtc, &console, &auditor.did).await;

        let purge = signed(&console, MEMBER_PURGE_TYPE, json!({ "did": TARGET })).await;
        assert_eq!(
            error_code(&dispatch(&fix.vtc, &purge).await).as_deref(),
            Some("permissionDenied"),
            "purge takes vtc.members.manage, delegation or not"
        );
        // …and a moderator's delegation reaches what the moderator holds.
        let moderating = Party::new();
        delegate(&fix.vtc, &moderating, &fix.scoped_admin.did).await;
        let read = signed(
            &moderating,
            MEMBER_CREDENTIALS_TYPE,
            json!({ "did": TARGET }),
        )
        .await;
        assert!(dispatch(&fix.vtc, &read).await.status.is_success());
    }

    /// **A signer with a row of its own is answered by that row, even when the
    /// row refuses.** This is where the implementation is deliberately tighter
    /// than the design note's sketch: falling through to a delegation on
    /// `Forbidden` would let a stale delegation route around a demotion, which
    /// is the exact thing "authority is the ACL row" exists to prevent. Paired
    /// with `console_key`'s enrolment refusal, so the two halves cannot drift.
    #[tokio::test]
    async fn a_signer_holding_its_own_row_is_never_answered_by_a_delegation() {
        let fix = fixture().await;
        let console = Party::new();
        delegate(&fix.vtc, &console, &fix.admin.did).await;
        // Someone gives the console DID a row of its own, at a role that
        // authorizes nothing here.
        seed_acl(&fix.vtc, &console.did, VtcRole::Member, vec![]).await;

        let doc = signed(&console, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        assert_eq!(
            error_code(&dispatch(&fix.vtc, &doc).await).as_deref(),
            Some("permissionDenied"),
            "the row is the answer, and it says no"
        );
    }

    /// An *undelegated* stranger is refused with the same code a delegated one
    /// gets after revocation — so the refusal is not an oracle for which DIDs
    /// are, or once were, console keys.
    #[tokio::test]
    async fn an_undelegated_signer_is_refused_indistinguishably() {
        let fix = fixture().await;
        let stranger = Party::new();
        let doc = signed(&stranger, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        assert_eq!(
            error_code(&dispatch(&fix.vtc, &doc).await).as_deref(),
            Some("permissionDenied")
        );
    }

    // ─── the operations' own refusals ────────────────────────────────────

    /// The declared `notFound`, carried as a code rather than flattened into
    /// `taskFailed` — the same code the REST route puts in its body.
    #[tokio::test]
    async fn an_unknown_member_is_the_declared_not_found() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_CREDENTIALS_TYPE,
            json!({ "did": "did:key:zNobodyAtAll" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(crate::members::ops::credentials::MEMBER_CREDENTIALS_ERR_NOT_FOUND),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// `role: admin` is refused with the task's `adminRoleForbidden` on this
    /// door too. The gate is on the transition, not on the route (#1645), so
    /// adding a second door must not add a second way past it.
    #[tokio::test]
    async fn update_still_refuses_promotion_to_admin() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "role": "admin" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some(crate::members::ops::update::UPDATE_ERR_ADMIN_ROLE_FORBIDDEN),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        let acl = get_acl_entry(&fix.vtc.state.acl_ks, TARGET)
            .await
            .expect("read ACL")
            .expect("the target still has a row");
        assert_eq!(acl.role, VtcRole::Member, "and nothing was changed");
    }

    /// Registry consent is the member's to give: an administrator's
    /// `publishConsent: true` for a member who has not consented is refused
    /// with `consentGrantForbidden`, and nothing in the request is applied.
    #[tokio::test]
    async fn update_refuses_to_grant_registry_consent() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "publishConsent": true, "label": "Ada Lovelace" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(crate::members::ops::update::UPDATE_ERR_CONSENT_GRANT_FORBIDDEN),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        let member = get_member(&fix.vtc.state.members_ks, TARGET)
            .await
            .expect("read member")
            .expect("row");
        assert!(!member.publish_consent, "consent was not granted");
        let acl = get_acl_entry(&fix.vtc.state.acl_ks, TARGET)
            .await
            .expect("read ACL")
            .expect("row");
        assert_eq!(
            acl.label, None,
            "and nothing else in the request was applied"
        );
    }

    /// Withdrawing consent (`true → false`) is an administrator's to make, and
    /// re-stating the current value is a no-op rather than a grant.
    #[tokio::test]
    async fn update_withdraws_registry_consent_and_accepts_a_no_op() {
        let fix = fixture().await;
        let mut member = Member::fresh(TARGET);
        member.publish_consent = true;
        store_member(&fix.vtc.state.members_ks, &member)
            .await
            .expect("seed consent");

        // `true → true`: nothing changes, nothing is refused.
        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "publishConsent": true }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        // `true → false`: the takedown.
        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "publishConsent": false }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        let after = get_member(&fix.vtc.state.members_ks, TARGET)
            .await
            .expect("read member")
            .expect("row");
        assert!(!after.publish_consent, "consent was withdrawn");

        // `false → false`: still a no-op.
        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "publishConsent": false }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// A metadata update a signed document really does apply.
    #[tokio::test]
    async fn update_applies_a_metadata_change_from_a_signed_document() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "label": "Ada Lovelace", "departurePreference": "purge" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        assert_conforms::<member_update::Response>(&out);

        let acl = get_acl_entry(&fix.vtc.state.acl_ks, TARGET)
            .await
            .expect("read ACL")
            .expect("row");
        assert_eq!(acl.label.as_deref(), Some("Ada Lovelace"));
        // The ACL row records *the signer* as the author of the change, which
        // is the attribution the task's proof requirement exists for.
        assert_eq!(acl.updated_by.as_deref(), Some(fix.admin.did.as_str()));
    }

    /// An **omitted** `extensions` leaves the member's own extensions alone.
    ///
    /// The generated payload types `extensions` as a plain map with `default`,
    /// so absent and empty are one value once parsed — and mapping that
    /// straight through would silently clear the bag on every update that did
    /// not mention it. The handler reads the raw payload for exactly this.
    #[tokio::test]
    async fn an_omitted_extensions_member_does_not_clear_the_bag() {
        let fix = fixture().await;
        let mut member = Member::fresh(TARGET);
        member.extensions = json!({ "org": "acme" });
        store_member(&fix.vtc.state.members_ks, &member)
            .await
            .expect("seed extensions");

        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "departurePreference": "purge" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        let after = get_member(&fix.vtc.state.members_ks, TARGET)
            .await
            .expect("read member")
            .expect("row");
        assert_eq!(after.extensions, json!({ "org": "acme" }));
    }

    /// An administrator removing another member, over the signed door.
    #[tokio::test]
    async fn admin_remove_departs_the_member_from_a_signed_document() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_ADMIN_REMOVE_TYPE,
            json!({ "did": TARGET, "reason": "ToS violation" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["did"], TARGET);
        assert_eq!(payload_of(&out)["removed"], true);
        assert_conforms::<member_admin_remove::Response>(&out);
        assert!(
            get_acl_entry(&fix.vtc.state.acl_ks, TARGET)
                .await
                .expect("read ACL")
                .is_none(),
            "the departed member keeps no authorization"
        );
    }

    /// A super-admin purging a member, over the signed door.
    #[tokio::test]
    async fn purge_erases_the_member_from_a_signed_document() {
        let fix = fixture().await;
        let doc = signed(&fix.admin, MEMBER_PURGE_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_conforms::<member_purge::Response>(&out);
        assert!(
            get_member(&fix.vtc.state.members_ks, TARGET)
                .await
                .expect("read member")
                .is_none(),
            "purge erases the row"
        );
    }

    // ─── VTI-OPS-025 / -026 / -027: the accepted-id record ───────────────

    /// **VTI-OPS-025.** A redelivered document is answered with the outcome
    /// already recorded for it, not executed a second time.
    ///
    /// Driven through `purge`, because that is where a second execution would
    /// actually show: the member is gone after the first, so re-running would
    /// answer the declared `notFound` instead of the original success.
    #[tokio::test]
    async fn vti_ops_025_a_redelivered_document_is_answered_not_re_executed() {
        let fix = fixture().await;
        let doc = signed(&fix.admin, MEMBER_PURGE_TYPE, json!({ "did": TARGET })).await;

        let first = dispatch(&fix.vtc, &doc).await;
        assert!(
            first.status.is_success(),
            "{}",
            String::from_utf8_lossy(&first.body)
        );

        let second = dispatch(&fix.vtc, &doc).await;
        assert!(
            second.status.is_success(),
            "the redelivery must be answered, not refused: {}",
            String::from_utf8_lossy(&second.body)
        );
        assert_eq!(
            payload_of(&second),
            payload_of(&first),
            "the recorded outcome is what a redelivery is answered with"
        );
    }

    /// **VTI-OPS-026.** A *different* document under an already-spent `id` is
    /// `idConflict` — not absorbed as a retry, and not executed.
    #[tokio::test]
    async fn vti_ops_026_a_different_document_under_a_spent_id_conflicts() {
        let fix = fixture().await;
        let second_target = "did:key:zSecondTarget";
        seed_acl(&fix.vtc, second_target, VtcRole::Member, vec![]).await;
        store_member(&fix.vtc.state.members_ks, &Member::fresh(second_target))
            .await
            .expect("seed second member");

        let first = signed(&fix.admin, MEMBER_PURGE_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &first).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        // Same `id`, different subject — the shape the record exists to catch.
        let mut collider = unsigned(
            &fix.admin,
            MEMBER_PURGE_TYPE,
            json!({ "did": second_target }),
        );
        collider.id.clone_from(&first.id);
        let collider = sign(&fix.admin, collider).await;
        let out = dispatch(&fix.vtc, &collider).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some("idConflict"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(
            get_member(&fix.vtc.state.members_ks, second_target)
                .await
                .expect("read member")
                .is_some(),
            "the conflicting document must not have executed"
        );
    }

    /// **VTI-OPS-027.** The record these verbs consult is the shared,
    /// store-backed one, reachable from any binding — not a map private to this
    /// dispatcher. Read back through `AppState::accepted_ids`, which is the
    /// handle a second binding would use.
    #[tokio::test]
    async fn vti_ops_027_the_spent_id_is_visible_to_any_binding() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_CREDENTIALS_TYPE,
            json!({ "did": TARGET }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        let now = chrono::Utc::now();
        let again = fix
            .vtc
            .state
            .accepted_ids()
            .claim(&doc, retain_until(&doc, now), now)
            .await
            .expect("the record is readable");
        assert!(
            matches!(again, accepted_ids::Acceptance::Duplicate { .. }),
            "a second binding must see the id the dispatcher spent"
        );
    }
}
