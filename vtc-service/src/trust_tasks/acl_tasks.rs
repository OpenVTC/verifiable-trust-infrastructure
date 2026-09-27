//! The canonical `acl/*` family on the signed-document spine:
//! `acl/{show,list,update,revoke}/0.1`, and the operation-bound gate
//! `acl/grant` and `acl/update` share.
//!
//! `acl/grant` and `acl/change-role` were the first two members served here
//! (#1641). Until these four joined them, reading and removing an entry were
//! bearer-REST only — `routes::acl::{list_acl, get_acl, delete_acl}` — so a
//! community could be administered over DIDComm or TSP right up to the point of
//! taking authority away, and the VTI-ACL-050 full-cover check on revoke lived
//! on one door.
//!
//! Every handler here is the same shape: authority from the **verified
//! signer's ACL row**, read now ([`super::admin_signer`]); the payload held to
//! its published schema ([`super::parse_spec_payload`]); then the one shared
//! operation in [`crate::routes::acl`], which the bearer route calls too. No
//! check lives in this file that the REST adapter does not also reach, and
//! none lives in the adapter that this file does not.
//!
//! What differs by door is only where a passkey gesture is read from: a live
//! session on REST, a gesture **bound to this document's payload** here
//! ([`settle_signed_gate`]).

use serde_json::Value;
use trust_tasks_rs::specs::acl::{
    list::v0_1 as acl_list, revoke::v0_1 as acl_revoke, show::v0_1 as acl_show,
    update::v0_1 as acl_update,
};
use trust_tasks_rs::{StandardCode, TrustTask, TrustTaskCode};
use vti_common::auth::extractor::AuthClaims;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with_code, success_response,
    task_error_to_reject,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::error::{AppError, TaskError};
use crate::routes::acl as ops;
use crate::server::AppState;

/// `acl/show/0.1` — one entry, as the caller may see it.
///
/// Manage authority, the bearer route's `ManageAuth`. An entry outside the
/// caller's visibility is answered exactly as an absent one.
pub(super) async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match manager(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: acl_show::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match ops::show_entry(state, &actor, checked.subject.as_str()).await {
        Ok(envelope) => success_response(&doc, envelope),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `acl/list/0.1` — the entries the caller may see, filtered and paged.
///
/// The payload's members are the bearer route's query parameters by name
/// (`role`, `scope`, `direction`, `subjectPrefix`, `pageSize`, `cursor`), so
/// it is read into the route's own [`ops::ListAclQuery`] and the cursor a page
/// returns resumes on either door under the same filters.
pub(super) async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match manager(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let _checked: acl_list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let query: ops::ListAclQuery = match parse_payload(&doc) {
        Ok(q) => q,
        Err(reject) => return reject,
    };
    match ops::list_entries(state, &actor, &query).await {
        Ok(page) => success_response(&doc, page),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `acl/update/0.1` — amend an existing entry's label, scopes or expiry.
///
/// Administrator only, as `acl/change-role` and `acl/revoke` are: an
/// amendment can rewrite another administrator's entry. Planned by
/// [`ops::plan_update`], which is [`ops::plan_grant`] with the existing role
/// held fixed — so self-modification (VTI-ACL-052), full cover (VTI-ACL-050)
/// and the granter's bound (VTI-ACL-053) are the grant's own checks. A widening
/// of administrator authority — a scope added, or an expiry lifted or pushed
/// out — needs a passkey gesture bound to this document; widening to
/// community-wide needs another administrator's consent too.
pub(super) async fn handle_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use acl_update::error_codes;

    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(e) = actor.require_admin() {
        return app_error_to_reject(&doc, &e);
    }
    // Named before the schema check, which would otherwise answer "unknown
    // field" for the one mistake this task declares a code for.
    if doc.payload.get("role").is_some() {
        return task_error_to_reject(
            &doc,
            &TaskError::declared(
                error_codes::ROLE_CHANGE_NOT_PERMITTED.code,
                AppError::Validation(
                    "acl/update does not change a role — use acl/change-role, which takes the \
                     current role as a compare-and-swap"
                        .into(),
                ),
            ),
        );
    }
    let _checked: acl_update::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    // Canonical members a VTC entry has no field for. Refused by name rather
    // than dropped: an update that silently kept a key filter or approver the
    // caller meant to set is the failure this surface exists to prevent.
    for member in ["allowedKeys", "approve", "stepUp"] {
        if doc.payload.get(member).is_some() {
            return app_error_to_reject(
                &doc,
                &AppError::Validation(format!(
                    "a VTC ACL entry has no `{member}` — this community's entries are a role, \
                     scopes, a label and an expiry"
                )),
            );
        }
    }
    let req: ops::UpdateEntryRequest = match parse_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let plan = match ops::plan_update(state, &actor, req).await {
        Ok(p) => p,
        Err(e) => return task_error_to_reject(&doc, &e),
    };
    if let Err(refusal) = settle_signed_gate(state, &actor, &doc, &plan).await {
        return refusal;
    }
    match ops::commit_grant(state, &actor, plan).await {
        Ok((_status, envelope)) => success_response(&doc, envelope),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `acl/revoke/0.1` — remove an entry, or reduce its scopes.
///
/// Administrator only, the bearer route's `AdminAuth`. No gesture: removing
/// authority confers none. The last unrestricted administrator is protected
/// (`acl/revoke:lastAuthorityProtected`, VTI-APV-009), and a member's entry is
/// refused in favour of the leave ceremony, exactly as on the bearer route.
pub(super) async fn handle_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(e) = actor.require_admin() {
        return app_error_to_reject(&doc, &e);
    }
    let req: acl_revoke::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    // The schema gives `scopes` at least one member when present, so an empty
    // list is an absent one: remove the entry rather than reduce it.
    let scopes: Vec<String> = req.scopes.iter().map(|s| s.to_string()).collect();
    let reason = req.reason.as_ref().map(|r| r.to_string());
    match ops::revoke_entry(
        state,
        &actor,
        &req.subject,
        (!scopes.is_empty()).then_some(scopes.as_slice()),
        reason.as_deref(),
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// The signer's claims, held to manage authority — the bearer routes'
/// `ManageAuth` for the two reads.
async fn manager(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<AuthClaims, TrustTaskOutcome> {
    let actor = admin_signer(state, ctx, doc).await?;
    actor
        .require_manage()
        .map_err(|e| app_error_to_reject(doc, &e))?;
    Ok(actor)
}

/// Settle what a planned `acl/grant` or `acl/update` needs before it may be
/// written, on the signed door.
///
/// A write that confers administrator authority needs a passkey gesture; one
/// that confers **unrestricted** authority needs the gesture and another
/// unrestricted administrator's consent (VTI-APV-014). The bearer route reads
/// the gesture from the session's live elevation. A document has no session, so
/// here both are **bound to this document's type and payload** and spent by
/// it — a gesture recorded for one grant cannot be spent on another, nor on an
/// update that says something different
/// ([`crate::acl::bound_step_up`], [`crate::acl::admin_consent`]).
///
/// Called after every check that decides whether the write may happen and
/// before any write: a gesture must never be asked for an act that would be
/// refused anyway, and one that has been spent must not be spent on a write
/// that then fails a check. Without a recorded gesture the refusal is
/// `permissionDenied` with the ceremony inline in `details.stepUpRequest`; the
/// spine releases the refused document's `id`, so once the admin has answered,
/// the *same* document is sent again and succeeds.
pub(super) async fn settle_signed_gate(
    state: &AppState,
    actor: &AuthClaims,
    doc: &TrustTask<Value>,
    plan: &ops::GrantPlan,
) -> Result<(), TrustTaskOutcome> {
    use crate::acl::bound_step_up::{self, Gate};

    let type_uri = doc.type_uri.to_string();
    let step_up_refusal =
        |request: &trust_tasks_rs::specs::auth::step_up::approve_request::v0_3::Payload| {
            reject_with_code(
                doc,
                TrustTaskCode::Standard(StandardCode::PermissionDenied),
                "a passkey gesture bound to this operation is required",
                Some(bound_step_up::refusal_details(request)),
            )
        };
    let subject = &plan.entry.did;

    if plan.confers_unrestricted {
        use crate::acl::admin_consent::{self, Operation, SignedGate};
        let gate = admin_consent::gesture_then_consent(
            state,
            &actor.did,
            subject,
            Operation {
                type_uri: &type_uri,
                payload: &doc.payload,
            },
            &format!("Grant community-wide administrator authority to {subject}"),
            &ops::unrestricted_grant_summary(subject),
        )
        .await;
        let ready = match gate {
            Ok(SignedGate::Ready(ready)) => ready,
            Ok(SignedGate::StepUpRequired(request)) => return Err(step_up_refusal(&request)),
            Err(e) => return Err(app_error_to_reject(doc, &e)),
        };
        ready
            .spend(state)
            .await
            .map_err(|e| app_error_to_reject(doc, &e))?;
    } else if plan.confers_admin {
        let reason = format!(
            "Grant administrator authority over {} to {subject}",
            plan.entry.allowed_contexts.join(", "),
        );
        match bound_step_up::redeem_or_request(state, &actor.did, &type_uri, &doc.payload, &reason)
            .await
        {
            Ok(Gate::Satisfied) => {}
            Ok(Gate::Required(request)) => return Err(step_up_refusal(&request)),
            Err(e) => return Err(app_error_to_reject(doc, &e)),
        }
    }
    Ok(())
}

/// Each `acl/*` task through the spine, as every transport hands it over.
///
/// The spine is the single place REST, DIDComm and TSP meet, so each task is
/// driven through [`super::dispatch_trust_task_core`] once per
/// [`crate::join::JoinTransport`] — with the context each transport builds.
/// The live-mediator round trip is `tests/acl_trust_tasks.rs`; the bearer
/// route's parity with this door is `tests/acl_canonical.rs`.
#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use vti_rooms_dtg::test_support::Party;

    use super::super::members_admin_tests::{
        assert_conforms, error_code, payload_of, seed_acl, signed, unsigned,
    };
    use super::super::{
        ACL_LIST_TYPE, ACL_REVOKE_TYPE, ACL_SHOW_TYPE, ACL_UPDATE_TYPE, JoinAuthCtx,
        TrustTaskOutcome, dispatch_trust_task_core,
    };
    use super::{acl_list, acl_revoke, acl_show, acl_update};
    use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
    use crate::join::JoinTransport;
    use crate::test_support::TestVtc;
    use trust_tasks_rs::TrustTask;

    /// Every transport the spine is reached from.
    const TRANSPORTS: [JoinTransport; 3] = [
        JoinTransport::Rest,
        JoinTransport::DIDComm,
        JoinTransport::Tsp,
    ];

    /// A subject every test acts on: a moderator in `ctx-a`.
    const TARGET: &str = "did:key:zAclTaskTarget";
    /// A subject whose entry reaches outside `ctx-a`.
    const STRADDLER: &str = "did:key:zAclTaskStraddler";

    struct Fixture {
        vtc: TestVtc,
        /// Unrestricted admin.
        admin: Party,
        /// Admin of `ctx-a` only.
        scoped: Party,
        /// A member: authenticated, authorized for none of this.
        member: Party,
    }

    async fn fixture() -> Fixture {
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
        let (admin, scoped, member) = (Party::new(), Party::new(), Party::new());
        seed_acl(&vtc, &admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(&vtc, &scoped.did, VtcRole::Admin, vec!["ctx-a".into()]).await;
        seed_acl(&vtc, &member.did, VtcRole::Member, vec![]).await;
        seed_acl(&vtc, TARGET, VtcRole::Moderator, vec!["ctx-a".into()]).await;
        seed_acl(
            &vtc,
            STRADDLER,
            VtcRole::Member,
            vec!["ctx-a".into(), "ctx-b".into()],
        )
        .await;
        Fixture {
            vtc,
            admin,
            scoped,
            member,
        }
    }

    /// The context `transport` builds: over DIDComm and TSP the sender is the
    /// transport's claim, which the spine binds to the document's proof.
    fn ctx(transport: JoinTransport, from: &Party) -> JoinAuthCtx {
        match transport {
            JoinTransport::Rest => JoinAuthCtx::rest(),
            _ => JoinAuthCtx {
                transport,
                sender_did: Some(from.did.clone()),
                verified_signer: None,
            },
        }
    }

    async fn dispatch_doc(
        vtc: &TestVtc,
        transport: JoinTransport,
        from: &Party,
        doc: &TrustTask<Value>,
    ) -> TrustTaskOutcome {
        let body = serde_json::to_vec(doc).expect("a document serialises");
        dispatch_trust_task_core(&vtc.state, &ctx(transport, from), &body).await
    }

    async fn send(
        vtc: &TestVtc,
        transport: JoinTransport,
        from: &Party,
        uri: &str,
        payload: Value,
    ) -> TrustTaskOutcome {
        let doc = signed(from, uri, payload).await;
        dispatch_doc(vtc, transport, from, &doc).await
    }

    fn ok(out: &TrustTaskOutcome, what: &str) {
        assert!(
            out.status.is_success(),
            "{what}: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    async fn stored(vtc: &TestVtc, did: &str) -> Option<VtcAclEntry> {
        get_acl_entry(&vtc.state.acl_ks, did)
            .await
            .expect("read ACL")
    }

    /// Whether an audit row of `variant` names `actor` and `target`.
    async fn audited(vtc: &TestVtc, variant: &str, actor: &str, target: &str) -> bool {
        let writer = vtc.state.audit_writer.as_ref().expect("audit is on");
        let rows = vtc
            .state
            .audit_ks
            .prefix_iter_raw(Vec::new())
            .await
            .expect("read audit");
        for (_, value) in rows {
            let Ok(env) = serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&value) else {
                continue;
            };
            if env.event.variant_name() == variant
                && writer.verify_actor(&env, actor).await.unwrap_or(false)
                && writer.verify_target(&env, target).await.unwrap_or(false)
            {
                return true;
            }
        }
        false
    }

    // ── the premise ──────────────────────────────────────────────────────

    /// What the specifications declare, which the unsigned-document tests
    /// below rest on. `show` and `list` declare no proof; their handlers
    /// authorize from the signer's ACL row, so they refuse one regardless.
    #[test]
    fn update_and_revoke_declare_a_proof_and_the_reads_do_not() {
        let required = |uri| {
            trust_tasks_rs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published policy"))
                .is_proof_required
        };
        assert!(required(ACL_UPDATE_TYPE));
        assert!(required(ACL_REVOKE_TYPE));
        assert!(!required(ACL_SHOW_TYPE));
        assert!(!required(ACL_LIST_TYPE));
    }

    // ── acl/show ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn acl_show_answers_an_admin_with_the_entry() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let out = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_SHOW_TYPE,
                json!({ "subject": TARGET }),
            )
            .await;
            ok(&out, &format!("{t:?}"));
            assert_eq!(payload_of(&out)["entry"]["subject"], TARGET, "{t:?}");
            assert_eq!(payload_of(&out)["entry"]["role"], "moderator", "{t:?}");
            assert_conforms::<acl_show::Response>(&out);
        }
    }

    #[tokio::test]
    async fn acl_show_refuses_a_member_and_hides_what_a_scoped_admin_cannot_see() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let out = send(
                &fix.vtc,
                t,
                &fix.member,
                ACL_SHOW_TYPE,
                json!({ "subject": TARGET }),
            )
            .await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{t:?}"
            );

            // An entry wholly outside the caller's contexts reads as absent.
            seed_acl(
                &fix.vtc,
                "did:key:zElsewhere",
                VtcRole::Member,
                vec!["ctx-z".into()],
            )
            .await;
            let hidden = send(
                &fix.vtc,
                t,
                &fix.scoped,
                ACL_SHOW_TYPE,
                json!({ "subject": "did:key:zElsewhere" }),
            )
            .await;
            let absent = send(
                &fix.vtc,
                t,
                &fix.scoped,
                ACL_SHOW_TYPE,
                json!({ "subject": "did:key:zNobody" }),
            )
            .await;
            assert!(!hidden.status.is_success(), "{t:?}");
            assert_eq!(
                payload_of(&hidden)["details"],
                payload_of(&absent)["details"],
                "{t:?}: an invisible entry must answer as an absent one"
            );
        }
    }

    // ── acl/list ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn acl_list_filters_to_what_the_caller_may_see() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            seed_acl(
                &fix.vtc,
                "did:key:zElsewhere",
                VtcRole::Member,
                vec!["ctx-z".into()],
            )
            .await;

            let out = send(&fix.vtc, t, &fix.admin, ACL_LIST_TYPE, json!({})).await;
            ok(&out, &format!("{t:?}"));
            assert_conforms::<acl_list::Response>(&out);
            let subjects = |out: &TrustTaskOutcome| -> Vec<String> {
                payload_of(out)["entries"]
                    .as_array()
                    .expect("entries")
                    .iter()
                    .map(|e| e["subject"].as_str().unwrap().to_string())
                    .collect()
            };
            assert!(subjects(&out).contains(&"did:key:zElsewhere".to_string()));

            let scoped = send(&fix.vtc, t, &fix.scoped, ACL_LIST_TYPE, json!({})).await;
            ok(&scoped, &format!("{t:?}"));
            assert!(
                !subjects(&scoped).contains(&"did:key:zElsewhere".to_string()),
                "{t:?}: a ctx-a admin must not see a ctx-z entry"
            );

            // The filters are the bearer route's, by name.
            let moderators = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_LIST_TYPE,
                json!({ "role": "moderator", "scope": "ctx-a" }),
            )
            .await;
            assert_eq!(subjects(&moderators), vec![TARGET.to_string()], "{t:?}");

            let refused = send(&fix.vtc, t, &fix.member, ACL_LIST_TYPE, json!({})).await;
            assert_eq!(error_code(&refused).as_deref(), Some("permissionDenied"));
        }
    }

    /// `subtree` answers the revocation sweep's question — grants at or
    /// beneath a context — which `acting-in` cannot.
    #[tokio::test]
    async fn acl_list_reads_the_hierarchy_in_the_direction_asked() {
        let fix = fixture().await;
        seed_acl(
            &fix.vtc,
            "did:key:zLeaf",
            VtcRole::Member,
            vec!["ctx-a/leaf".into()],
        )
        .await;
        let subjects = |out: &TrustTaskOutcome| -> Vec<String> {
            payload_of(out)["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["subject"].as_str().unwrap().to_string())
                .collect()
        };
        let acting = send(
            &fix.vtc,
            JoinTransport::Rest,
            &fix.admin,
            ACL_LIST_TYPE,
            json!({ "scope": "ctx-a" }),
        )
        .await;
        assert!(!subjects(&acting).contains(&"did:key:zLeaf".to_string()));
        let subtree = send(
            &fix.vtc,
            JoinTransport::Rest,
            &fix.admin,
            ACL_LIST_TYPE,
            json!({ "scope": "ctx-a", "direction": "subtree" }),
        )
        .await;
        assert!(subjects(&subtree).contains(&"did:key:zLeaf".to_string()));
        assert!(subjects(&subtree).contains(&TARGET.to_string()));
    }

    // ── acl/update ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn acl_update_amends_label_scopes_and_expiry_and_is_audited() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let out = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_UPDATE_TYPE,
                json!({
                    "subject": TARGET,
                    "label": "ops",
                    "scopes": ["ctx-a", "ctx-b"],
                    "expiresAt": "2099-01-01T00:00:00Z",
                }),
            )
            .await;
            ok(&out, &format!("{t:?}"));
            assert_conforms::<acl_update::Response>(&out);
            let entry = stored(&fix.vtc, TARGET).await.expect("still there");
            assert_eq!(
                entry.role,
                VtcRole::Moderator,
                "{t:?}: the role never moves"
            );
            assert_eq!(entry.label.as_deref(), Some("ops"));
            assert_eq!(entry.allowed_contexts, vec!["ctx-a", "ctx-b"]);
            assert!(entry.expires_at.is_some());
            assert_eq!(entry.updated_by.as_deref(), Some(fix.admin.did.as_str()));
            assert!(
                audited(&fix.vtc, "AclUpdated", &fix.admin.did, TARGET).await,
                "{t:?}: an update is audited as one, by its actor"
            );

            // `null` clears; absent leaves alone.
            let out = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_UPDATE_TYPE,
                json!({ "subject": TARGET, "label": null }),
            )
            .await;
            ok(&out, &format!("{t:?}"));
            let entry = stored(&fix.vtc, TARGET).await.unwrap();
            assert_eq!(entry.label, None);
            assert_eq!(entry.allowed_contexts, vec!["ctx-a", "ctx-b"]);
        }
    }

    #[tokio::test]
    async fn acl_update_refuses_what_it_does_not_do() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let code = |out: &TrustTaskOutcome| error_code(out);

            let narrowing = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_UPDATE_TYPE,
                json!({ "subject": STRADDLER, "scopes": ["ctx-a"] }),
            )
            .await;
            assert_eq!(
                code(&narrowing).as_deref(),
                Some(acl_update::error_codes::NARROWING_NOT_PERMITTED.code),
                "{t:?}: narrowing is a revocation"
            );

            let role = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_UPDATE_TYPE,
                json!({ "subject": TARGET, "role": "admin" }),
            )
            .await;
            assert_eq!(
                code(&role).as_deref(),
                Some(acl_update::error_codes::ROLE_CHANGE_NOT_PERMITTED.code),
                "{t:?}"
            );

            let missing = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_UPDATE_TYPE,
                json!({ "subject": "did:key:zNobody", "label": "x" }),
            )
            .await;
            assert_eq!(
                code(&missing).as_deref(),
                Some(acl_update::error_codes::NOT_FOUND.code),
                "{t:?}: update never creates"
            );
            assert!(stored(&fix.vtc, "did:key:zNobody").await.is_none());

            let keys = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_UPDATE_TYPE,
                json!({ "subject": TARGET, "allowedKeys": [] }),
            )
            .await;
            assert_eq!(code(&keys).as_deref(), Some("malformedRequest"), "{t:?}");

            let member = send(
                &fix.vtc,
                t,
                &fix.member,
                ACL_UPDATE_TYPE,
                json!({ "subject": TARGET, "label": "x" }),
            )
            .await;
            assert_eq!(code(&member).as_deref(), Some("permissionDenied"), "{t:?}");

            // Nothing above wrote anything.
            let entry = stored(&fix.vtc, TARGET).await.unwrap();
            assert_eq!(entry.label, None);
            assert_eq!(entry.allowed_contexts, vec!["ctx-a"]);
        }
    }

    /// VTI-ACL-052: no principal amends its own entry.
    #[tokio::test]
    async fn vti_acl_052_acl_update_refuses_the_callers_own_entry() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let out = send(
                &fix.vtc,
                t,
                &fix.scoped,
                ACL_UPDATE_TYPE,
                json!({ "subject": fix.scoped.did, "scopes": ["ctx-a", "ctx-b"] }),
            )
            .await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{t:?}"
            );
            let own = stored(&fix.vtc, &fix.scoped.did).await.unwrap();
            assert_eq!(own.allowed_contexts, vec!["ctx-a"], "{t:?}: self-widening");
        }
    }

    /// VTI-ACL-050: an entry acting outside the caller's contexts is not the
    /// caller's to amend. VTI-ACL-053: nor may the caller confer a context it
    /// does not hold.
    #[tokio::test]
    async fn vti_acl_050_053_acl_update_is_bounded_by_the_callers_own_authority() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let straddle = send(
                &fix.vtc,
                t,
                &fix.scoped,
                ACL_UPDATE_TYPE,
                json!({ "subject": STRADDLER, "label": "mine now" }),
            )
            .await;
            assert_eq!(
                error_code(&straddle).as_deref(),
                Some("permissionDenied"),
                "{t:?}: full cover"
            );

            let wider = send(
                &fix.vtc,
                t,
                &fix.scoped,
                ACL_UPDATE_TYPE,
                json!({ "subject": TARGET, "scopes": ["ctx-a", "ctx-b"] }),
            )
            .await;
            assert_eq!(
                error_code(&wider).as_deref(),
                Some("permissionDenied"),
                "{t:?}: bounded by the granter"
            );
            assert_eq!(
                stored(&fix.vtc, TARGET).await.unwrap().allowed_contexts,
                vec!["ctx-a"]
            );
        }
    }

    /// VTI-ACL-053: an expiring caller cannot make an entry permanent, nor
    /// outlive itself.
    #[tokio::test]
    async fn vti_acl_053_acl_update_cannot_outlive_the_caller() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let expiring = Party::new();
            let soon = vti_common::auth::session::now_epoch() + 3600;
            store_acl_entry(
                &fix.vtc.state.acl_ks,
                &VtcAclEntry {
                    did: expiring.did.clone(),
                    role: VtcRole::Admin,
                    label: None,
                    allowed_contexts: vec![],
                    created_at: 0,
                    created_by: "did:key:vtc-install".into(),
                    updated_at: None,
                    updated_by: None,
                    expires_at: Some(soon),
                },
            )
            .await
            .unwrap();
            let out = send(
                &fix.vtc,
                t,
                &expiring,
                ACL_UPDATE_TYPE,
                json!({ "subject": TARGET, "expiresAt": null }),
            )
            .await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{t:?}"
            );
            assert_eq!(stored(&fix.vtc, TARGET).await.unwrap().expires_at, None);
        }
    }

    /// Widening an administrator's entry — here, lifting its expiry — asks for
    /// a passkey gesture, and writes nothing without it.
    #[tokio::test]
    async fn acl_update_asks_for_a_bound_gesture_to_widen_an_admin() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let later = vti_common::auth::session::now_epoch() + 86_400;
            let admin_b = "did:key:zAclTaskAdminB";
            store_acl_entry(
                &fix.vtc.state.acl_ks,
                &VtcAclEntry {
                    did: admin_b.into(),
                    role: VtcRole::Admin,
                    label: None,
                    allowed_contexts: vec!["ctx-a".into()],
                    created_at: 0,
                    created_by: "did:key:vtc-install".into(),
                    updated_at: None,
                    updated_by: None,
                    expires_at: Some(later),
                },
            )
            .await
            .unwrap();
            let out = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_UPDATE_TYPE,
                json!({ "subject": admin_b, "expiresAt": null }),
            )
            .await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{t:?}"
            );
            // This fixture enrols no passkey, so the refusal says one is
            // needed rather than carrying a ceremony to answer
            // (`tests/signed_step_up.rs` drives the ceremony end to end).
            assert!(
                payload_of(&out)["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("passkey")),
                "{t:?}: the refusal names the gesture: {}",
                payload_of(&out)
            );
            assert_eq!(
                stored(&fix.vtc, admin_b).await.unwrap().expires_at,
                Some(later)
            );

            // A label edit on the same admin widens nothing and needs no gesture.
            let label = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_UPDATE_TYPE,
                json!({ "subject": admin_b, "label": "ops" }),
            )
            .await;
            ok(&label, &format!("{t:?}"));
        }
    }

    // ── acl/revoke ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn acl_revoke_reduces_or_removes_and_is_audited() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let reduced = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_REVOKE_TYPE,
                json!({ "subject": STRADDLER, "scopes": ["ctx-b"] }),
            )
            .await;
            ok(&reduced, &format!("{t:?}"));
            assert_conforms::<acl_revoke::Response>(&reduced);
            assert_eq!(payload_of(&reduced)["entry"]["scopes"], json!(["ctx-a"]));
            assert_eq!(
                stored(&fix.vtc, STRADDLER).await.unwrap().allowed_contexts,
                vec!["ctx-a"]
            );

            let removed = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_REVOKE_TYPE,
                json!({ "subject": TARGET, "reason": "rotation" }),
            )
            .await;
            ok(&removed, &format!("{t:?}"));
            assert_conforms::<acl_revoke::Response>(&removed);
            assert!(payload_of(&removed)["entry"].is_null(), "{t:?}");
            assert!(stored(&fix.vtc, TARGET).await.is_none(), "{t:?}");
            assert!(
                audited(&fix.vtc, "AclRevoked", &fix.admin.did, TARGET).await,
                "{t:?}"
            );
        }
    }

    #[tokio::test]
    async fn acl_revoke_refuses_absent_own_uncovered_and_unauthorized() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let absent = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_REVOKE_TYPE,
                json!({ "subject": "did:key:zNobody" }),
            )
            .await;
            assert_eq!(
                error_code(&absent).as_deref(),
                Some(acl_revoke::error_codes::SUBJECT_NOT_PRESENT.code),
                "{t:?}"
            );

            let own = send(
                &fix.vtc,
                t,
                &fix.scoped,
                ACL_REVOKE_TYPE,
                json!({ "subject": fix.scoped.did }),
            )
            .await;
            assert!(!own.status.is_success(), "{t:?}: own entry");

            // VTI-ACL-050: overlap is not cover.
            let uncovered = send(
                &fix.vtc,
                t,
                &fix.scoped,
                ACL_REVOKE_TYPE,
                json!({ "subject": STRADDLER, "scopes": ["ctx-a"] }),
            )
            .await;
            assert_eq!(
                error_code(&uncovered).as_deref(),
                Some("permissionDenied"),
                "{t:?}"
            );

            let member = send(
                &fix.vtc,
                t,
                &fix.member,
                ACL_REVOKE_TYPE,
                json!({ "subject": TARGET }),
            )
            .await;
            assert_eq!(error_code(&member).as_deref(), Some("permissionDenied"));

            for did in [TARGET, STRADDLER, fix.scoped.did.as_str()] {
                assert!(
                    stored(&fix.vtc, did).await.is_some(),
                    "{t:?}: {did} untouched"
                );
            }
            assert_eq!(
                stored(&fix.vtc, STRADDLER).await.unwrap().allowed_contexts,
                vec!["ctx-a", "ctx-b"]
            );
        }
    }

    /// VTI-APV-009: revoking an unrestricted admin that the consent threshold
    /// still needs is the task's declared `lastAuthorityProtected`.
    #[tokio::test]
    async fn vti_apv_009_acl_revoke_protects_the_last_authority() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let other = "did:key:zAclTaskSecondAdmin";
            seed_acl(&fix.vtc, other, VtcRole::Admin, vec![]).await;
            fix.vtc
                .state
                .config
                .write()
                .await
                .acl
                .unrestricted_admin_consent_threshold = 2;
            let out = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_REVOKE_TYPE,
                json!({ "subject": other }),
            )
            .await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some(acl_revoke::error_codes::LAST_AUTHORITY_PROTECTED.code),
                "{t:?}: {}",
                payload_of(&out)
            );
            assert!(stored(&fix.vtc, other).await.is_some());
        }
    }

    // ── the document gate ────────────────────────────────────────────────

    /// VTI-OPS-020 / -021: `update` and `revoke` declare a proof, and a
    /// document without one is refused on every transport before it reaches
    /// the ACL. The reads declare none, and are refused anyway — authority is
    /// the signer's ACL row, and an unsigned document has no signer.
    #[tokio::test]
    async fn vti_ops_020_an_unsigned_acl_document_is_refused() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            for (uri, payload) in [
                (ACL_UPDATE_TYPE, json!({ "subject": TARGET, "label": "x" })),
                (ACL_REVOKE_TYPE, json!({ "subject": TARGET })),
                (ACL_SHOW_TYPE, json!({ "subject": TARGET })),
                (ACL_LIST_TYPE, json!({})),
            ] {
                let doc = unsigned(&fix.admin, uri, payload);
                let out = dispatch_doc(&fix.vtc, t, &fix.admin, &doc).await;
                assert_eq!(
                    error_code(&out).as_deref(),
                    Some("proofRequired"),
                    "{t:?} {uri}: {}",
                    String::from_utf8_lossy(&out.body)
                );
            }
            let entry = stored(&fix.vtc, TARGET).await.expect("not revoked");
            assert_eq!(entry.label, None, "{t:?}: not updated");
        }
    }

    /// Over DIDComm and TSP the transport's sender must be the signer: a
    /// member relaying an admin's signed revoke is not the admin.
    #[tokio::test]
    async fn an_acl_document_relayed_by_another_sender_is_refused() {
        for t in [JoinTransport::DIDComm, JoinTransport::Tsp] {
            let fix = fixture().await;
            let doc = signed(&fix.admin, ACL_REVOKE_TYPE, json!({ "subject": TARGET })).await;
            let out = dispatch_doc(&fix.vtc, t, &fix.member, &doc).await;
            assert!(!out.status.is_success(), "{t:?}");
            assert!(stored(&fix.vtc, TARGET).await.is_some(), "{t:?}");
        }
    }
}
