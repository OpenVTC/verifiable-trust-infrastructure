//! Members' step-up passkeys on the signed-document spine —
//! `auth/passkey/enroll/invite/0.2` (`purpose: stepUp`),
//! `auth/passkey/enroll/redeem/{start,finish}/0.1` and
//! `auth/passkey/revoke/{start,finish}/0.2` for a member revoking their own,
//! or an administrator revoking one on a member's behalf, and
//! `auth/passkey/admin-list/0.1` for an administrator listing them. The
//! operations are [`crate::step_up_passkey`]'s; this file decides only who is
//! asking.
//!
//! Every one arrives here the same way over TSP, DIDComm or HTTPS, and there is
//! no other door: no REST route issues, redeems, revokes or lists one.
//!
//! | task | signed by | authority |
//! |---|---|---|
//! | `enroll/invite` | a community administrator ([`admin_signer`]) | their ACL row, **and** a passkey gesture of theirs bound to this document ([`crate::acl::bound_step_up`]) |
//! | `enroll/redeem/start` | the member the invite names — required here, although the specification makes the proof optional | the invite token, the claim code and the signer, together |
//! | `enroll/redeem/finish` | the member, or nobody (the browser that ran the ceremony) | the ceremony a signed start opened |
//! | `revoke/start`, `revoke/finish` | the member revoking their own step-up passkey, or a community administrator revoking one for a member | a user-verified assertion from the producer's own passkeys — the subject's remaining step-up passkeys for a self-revoke, the administrator's session passkeys otherwise — plus, for an administrator, their ACL row |
//! | `admin-list` | an administrator with authority over the member — community-wide, or scoped to a context the member's entry names | their ACL row |

use serde_json::Value;
use trust_tasks_rs::specs::auth::passkey::admin_list::v0_1 as admin_list;
use trust_tasks_rs::specs::auth::passkey::enroll::invite::v0_2 as invite;
use trust_tasks_rs::specs::auth::passkey::enroll::redeem::finish::v0_1 as redeem_finish;
use trust_tasks_rs::specs::auth::passkey::enroll::redeem::start::v0_1 as redeem_start;
use trust_tasks_rs::specs::auth::passkey::revoke::finish::v0_2 as revoke_finish;
use trust_tasks_rs::specs::auth::passkey::revoke::start::v0_2 as revoke_start;
use trust_tasks_rs::{RejectReason, StandardCode, TrustTask, TrustTaskCode};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, reject_with, reject_with_code, success_response,
    task_error_to_reject,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::server::AppState;

pub(crate) const INVITE_TYPE: &str = <invite::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const REDEEM_START_TYPE: &str =
    <redeem_start::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const REDEEM_FINISH_TYPE: &str =
    <redeem_finish::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const REVOKE_START_TYPE: &str =
    <revoke_start::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const REVOKE_FINISH_TYPE: &str =
    <revoke_finish::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const ADMIN_LIST_TYPE: &str = <admin_list::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    INVITE_TYPE,
    REDEEM_START_TYPE,
    REDEEM_FINISH_TYPE,
    REVOKE_START_TYPE,
    REVOKE_FINISH_TYPE,
    ADMIN_LIST_TYPE,
];

/// Tasks whose response carries a bearer secret — the invite's token and
/// claim code, a redemption's `enrollmentId`. The duplicate-execution record
/// keeps no copy of these responses: a redelivered document is answered
/// without them rather than have the secret sit in `accepted_ids` for the
/// acceptance window.
pub(crate) const SECRET_RESPONSES: &[&str] = &[INVITE_TYPE, REDEEM_START_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        INVITE_TYPE => handle_invite(state, ctx, doc).await,
        REDEEM_START_TYPE => handle_redeem_start(state, ctx, doc).await,
        REDEEM_FINISH_TYPE => handle_redeem_finish(state, ctx, doc).await,
        REVOKE_START_TYPE => handle_revoke_start(state, ctx, doc).await,
        REVOKE_FINISH_TYPE => handle_revoke_finish(state, ctx, doc).await,
        ADMIN_LIST_TYPE => handle_admin_list(state, ctx, doc).await,
        _ => return None,
    })
}

/// `auth/passkey/enroll/invite/0.2`. Letting a member bind a second factor is
/// an act of authority, so beyond the administrator's signature it takes a
/// passkey gesture of theirs **bound to this document**: without one the
/// answer is `permissionDenied` with the ceremony inline as
/// `details.stepUpRequest`, and the identical document succeeds once the
/// gesture is recorded.
async fn handle_invite(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::acl::bound_step_up::{self, Gate};

    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let payload: invite::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    // Everything that decides whether the invite may be issued, before the
    // administrator is asked for a gesture over it.
    if let Err(e) = crate::step_up_passkey::check_invite(state, &actor.did, &payload).await {
        return task_error_to_reject(&doc, &e);
    }
    let reason = format!(
        "Invite {} to enrol a step-up passkey",
        payload.subject.as_str()
    );
    match bound_step_up::redeem_or_request(
        state,
        &actor.did,
        &doc.type_uri.to_string(),
        &doc.payload,
        &reason,
    )
    .await
    {
        Ok(Gate::Satisfied) => {}
        Ok(Gate::Required(request)) => {
            return reject_with_code(
                &doc,
                TrustTaskCode::Standard(StandardCode::PermissionDenied),
                "a passkey gesture bound to this invite is required",
                Some(bound_step_up::refusal_details(&request)),
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    match crate::step_up_passkey::issue_invite(state, &actor.did, &payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `auth/passkey/enroll/redeem/start/0.1`, which must be signed by the member
/// the invite names. The specification lets the proof be absent because an
/// invitee may hold no key the service trusts; a member of this community
/// always does, and the proof is what stops anyone else who holds the two
/// messages — another member, or the administrator who wrote them — from
/// binding a passkey to the member's DID.
async fn handle_redeem_start(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let Some(signer) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let payload: redeem_start::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::step_up_passkey::redeem_start(state, &signer, &payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `auth/passkey/enroll/redeem/finish/0.1`. May arrive unsigned, from the
/// browser the member opened the ceremony in; a signed one must be the
/// member's.
async fn handle_redeem_finish(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: redeem_finish::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::step_up_passkey::redeem_finish(state, ctx.verified_signer.as_deref(), &payload)
        .await
    {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// Who may act for `revoke/start` and `revoke/finish`: the verified signer,
/// or — when that signer holds no ACL row of their own and signed through a
/// delegated console key — the administrator that key acts for.
///
/// Unlike [`admin_signer`], this never refuses a signer for lacking
/// administrator standing: a member revoking their own step-up passkey needs
/// none, and [`crate::step_up_passkey::revoke_start`] is where "acting for
/// someone else needs administrator standing" is actually enforced, against
/// this service's own state rather than anything the document claims.
async fn revoke_producer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<String, TrustTaskOutcome> {
    let Some(signer) = ctx.verified_signer.clone() else {
        return Err(reject_with(doc, RejectReason::ProofRequired));
    };
    let has_own_row = crate::acl::get_acl_entry(&state.acl_ks, &signer)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?
        .is_some();
    if !has_own_row
        && let Some(delegation) =
            crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, &signer)
                .await
                .map_err(|e| app_error_to_reject(doc, &e))?
    {
        crate::acl::console_key::touch_last_used(&state.console_keys_ks, &delegation).await;
        tracing::info!(
            console_did = %signer,
            admin_did = %delegation.admin_did,
            task = %doc.type_uri,
            "authorizing a signed document under a console-key delegation"
        );
        return Ok(delegation.admin_did);
    }
    Ok(signer)
}

/// `auth/passkey/revoke/start/0.2`: the member revoking their own step-up
/// passkey (`payload.subject` absent), or a community administrator revoking
/// one for a member (`payload.subject` present, naming someone else).
async fn handle_revoke_start(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let producer = match revoke_producer(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let payload: revoke_start::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::step_up_passkey::revoke_start(state, &producer, &payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `auth/passkey/revoke/finish/0.2`, by the producer who started it.
async fn handle_revoke_finish(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let producer = match revoke_producer(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let payload: revoke_finish::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::step_up_passkey::revoke_finish(state, &producer, &payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `auth/passkey/admin-list/0.1`: an administrator lists one member's step-up
/// passkeys. The specification declares its proof REQUIRED, and the spine's
/// policy check (`dispatch_trust_task_validated`, off the published registry)
/// refuses an unsigned document before this handler runs.
///
/// A signer that does not resolve to an administrator — no ACL row, an
/// expired one, or a role other than admin — is `notAdministrator`, decided
/// before the subject is looked at.
async fn handle_admin_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        // A storage failure is not a refusal of standing.
        Err(reject) if reject.status.is_server_error() => return reject,
        Err(_) => {
            return reject_with_code(
                &doc,
                super::helpers::extended_code(admin_list::error_codes::NOT_ADMINISTRATOR.code),
                "only an administrator lists a member's passkeys",
                None,
            );
        }
    };
    let payload: admin_list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::step_up_passkey::admin_list(state, &actor, &payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// Each task through the spine, as every transport hands it over: REST (the
/// holder proven by the document's proof) and DIDComm and TSP (the sender a
/// claim the proof must bind). The live-mediator round trip is
/// `tests/step_up_passkeys.rs`.
#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::{Value, json};
    use uuid::Uuid;
    use vti_common::audit::AuditEvent;
    use vti_common::auth::passkey::store::{
        PasskeyUser, get_all_passkeys, store_credential_mapping, store_passkey_user,
    };
    use vti_rooms_dtg::test_support::Party;
    use webauthn_rs::prelude::{
        CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse,
    };

    use super::super::members_admin_tests::{error_code, payload_of, seed_acl, signed, unsigned};
    use super::super::soft_authenticator::SoftEd25519Authenticator;
    use super::super::{
        JoinAuthCtx, STEP_UP_APPROVE_RESPONSE_TYPE, STEP_UP_APPROVE_RESPONSE_V0_5_TYPE,
        TrustTaskOutcome, dispatch_trust_task_core,
    };
    use super::revoke_start;
    use super::{ADMIN_LIST_TYPE, admin_list};
    use super::{INVITE_TYPE, REDEEM_FINISH_TYPE, REDEEM_START_TYPE, REVOKE_FINISH_TYPE};
    use super::{REVOKE_START_TYPE, invite, redeem_finish, redeem_start, revoke_finish};
    use crate::acl::VtcRole;
    use crate::acl::bound_step_up::{self, Gate};
    use crate::join::JoinTransport;
    use crate::step_up_passkey::MAX_WRONG_CODES;
    use crate::test_support::TestVtc;
    use trust_tasks_rs::TrustTask;
    use trust_tasks_rs::validate::ValidatedPayload;

    const RP_ORIGIN: &str = "https://vtc.example.com";
    const BREAK_GLASS: &str = "https://trusttasks.org/spec/git-ns/right/break-glass/0.1";

    const TRANSPORTS: [JoinTransport; 3] = [
        JoinTransport::Rest,
        JoinTransport::DIDComm,
        JoinTransport::Tsp,
    ];

    struct Fixture {
        vtc: TestVtc,
        /// A community administrator, holding a session passkey.
        admin: Party,
        admin_key: SoftEd25519Authenticator,
        /// The member invited to enrol.
        member: Party,
        member_key: SoftEd25519Authenticator,
        /// Another member.
        other: Party,
    }

    async fn fixture() -> Fixture {
        let vtc = TestVtc::builder()
            .with_public_url(RP_ORIGIN)
            .with_audit(true)
            .with_signers(true)
            .build()
            .await;
        let (admin, member, other) = (Party::new(), Party::new(), Party::new());
        seed_acl(&vtc, &admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(&vtc, &member.did, VtcRole::Member, vec![]).await;
        seed_acl(&vtc, &other.did, VtcRole::Member, vec![]).await;
        let mut fix = Fixture {
            vtc,
            admin,
            admin_key: SoftEd25519Authenticator::new(),
            member,
            member_key: SoftEd25519Authenticator::new(),
            other,
        };
        // The administrator's own session passkey, as the console enrols it.
        let did = fix.admin.did.clone();
        let webauthn = fix
            .vtc
            .state
            .webauthn
            .clone()
            .expect("webauthn is configured");
        let user_uuid = Uuid::new_v4();
        let (ccr, reg) =
            crate::webauthn::start_passkey_registration(&webauthn, user_uuid, &did, &did, None)
                .unwrap();
        let (cred, _) = fix.admin_key.register(&ccr, RP_ORIGIN);
        let passkey = crate::webauthn::finish_passkey_registration(&webauthn, &cred, &reg).unwrap();
        let hex_id = hex::encode(<_ as AsRef<[u8]>>::as_ref(passkey.cred_id()));
        let ks = &fix.vtc.state.passkey_ks;
        store_passkey_user(
            ks,
            &PasskeyUser {
                user_uuid,
                did: did.clone(),
                display_name: did,
                credentials: vec![passkey],
            },
        )
        .await
        .unwrap();
        store_credential_mapping(ks, &hex_id, user_uuid)
            .await
            .unwrap();
        fix
    }

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
        fix: &Fixture,
        transport: JoinTransport,
        from: &Party,
        doc: &TrustTask<Value>,
    ) -> TrustTaskOutcome {
        let body = serde_json::to_vec(doc).expect("a document serialises");
        dispatch_trust_task_core(&fix.vtc.state, &ctx(transport, from), &body).await
    }

    async fn send(
        fix: &Fixture,
        transport: JoinTransport,
        from: &Party,
        uri: &str,
        payload: Value,
    ) -> TrustTaskOutcome {
        let doc = signed(from, uri, payload).await;
        dispatch_doc(fix, transport, from, &doc).await
    }

    fn ok(out: &TrustTaskOutcome, what: &str) -> Value {
        assert!(
            out.status.is_success(),
            "{what}: {}",
            String::from_utf8_lossy(&out.body)
        );
        payload_of(out)
    }

    fn assert_code(out: &TrustTaskOutcome, code: &str, what: &str) {
        assert_eq!(
            error_code(out).as_deref(),
            Some(code),
            "{what}: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// A webauthn-rs result as the published `AttestationResponse` /
    /// `AssertionResponse` — what a browser's `navigator.credentials` result
    /// serialises to.
    fn published(v: impl serde::Serialize) -> Value {
        fn strip_nulls(v: &mut Value) {
            if let Value::Object(map) = v {
                map.retain(|_, v| !v.is_null());
                map.values_mut().for_each(strip_nulls);
            }
        }
        let mut v = serde_json::to_value(v).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("extensions");
        obj.insert("clientExtensionResults".into(), json!({}));
        strip_nulls(&mut v);
        v
    }

    fn creation(options: &Value) -> CreationChallengeResponse {
        serde_json::from_value(json!({ "publicKey": options })).unwrap()
    }

    fn request_options(options: &Value) -> RequestChallengeResponse {
        serde_json::from_value(json!({ "publicKey": options })).unwrap()
    }

    fn step_up_request(out: &TrustTaskOutcome) -> Value {
        payload_of(out)
            .pointer("/details/stepUpRequest")
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "no step-up was asked for: {}",
                    String::from_utf8_lossy(&out.body)
                )
            })
    }

    /// [`approve`], against whichever approve-response version `uri` names.
    async fn approve_as(
        fix: &Fixture,
        transport: JoinTransport,
        uri: &str,
        signer: &Party,
        request: &Value,
        assertion: &PublicKeyCredential,
    ) -> TrustTaskOutcome {
        send(
            fix,
            transport,
            signer,
            uri,
            json!({
                "subject": request["subject"],
                "challenge": request["challenge"],
                "decision": "approved",
                "evidence": { "kind": "webauthn", "assertion": published(assertion) },
            }),
        )
        .await
    }

    /// The `auth/step-up/approve-response/0.4` `signer` sends for `request`,
    /// carrying an assertion from `key`.
    async fn approve(
        fix: &Fixture,
        transport: JoinTransport,
        signer: &Party,
        request: &Value,
        assertion: &PublicKeyCredential,
    ) -> TrustTaskOutcome {
        approve_as(
            fix,
            transport,
            STEP_UP_APPROVE_RESPONSE_TYPE,
            signer,
            request,
            assertion,
        )
        .await
    }

    /// Issue an invite for `subject` over `transport`: the administrator's
    /// document, refused for a gesture, answered with their passkey, and sent
    /// again unchanged.
    async fn invite_over(fix: &mut Fixture, transport: JoinTransport, subject: &str) -> Value {
        let doc = signed(
            &fix.admin,
            INVITE_TYPE,
            json!({ "subject": subject, "purpose": "stepUp", "deviceLabel": "Carol's laptop" }),
        )
        .await;
        let first = dispatch_doc(fix, transport, &fix.admin, &doc).await;
        assert_code(
            &first,
            "permissionDenied",
            "an invite needs a gesture first",
        );
        let request = step_up_request(&first);
        assert_eq!(request["subject"], fix.admin.did);
        let assertion = fix
            .admin_key
            .authenticate(&request_options(&request["webauthn"]), RP_ORIGIN);
        let recorded = approve(fix, transport, &fix.admin, &request, &assertion).await;
        assert_eq!(ok(&recorded, "the gesture")["status"], "recorded");
        let issued = dispatch_doc(fix, transport, &fix.admin, &doc).await;
        let issued_payload = ok(&issued, "the invite");
        invite::Response::validate_value(&issued_payload).expect("conforms");
        // A redelivery of the same document is not answered with the secret.
        let again = dispatch_doc(fix, transport, &fix.admin, &doc).await;
        assert_eq!(again.status, StatusCode::NO_CONTENT, "{transport:?}");
        assert!(again.body.is_empty(), "the claim code is not replayed");
        issued_payload
    }

    /// Redeem `issued` as `fix.member` over `transport`; the credential id.
    async fn redeem_over(fix: &mut Fixture, transport: JoinTransport, issued: &Value) -> String {
        let started = send(
            fix,
            transport,
            &fix.member,
            REDEEM_START_TYPE,
            json!({
                "token": issued["invite"]["token"],
                "claimCode": issued["claimCode"].as_str().unwrap().to_lowercase(),
            }),
        )
        .await;
        let started = ok(&started, "redeem/start");
        redeem_start::Response::validate_value(&started).expect("conforms");
        assert_eq!(started["subject"], fix.member.did);
        let (cred, _) = fix
            .member_key
            .register(&creation(&started["options"]), RP_ORIGIN);
        let mut payload = json!({
            "enrollmentId": started["enrollmentId"],
            "credential": published(&cred),
        });
        if let Some(uv) = started.get("uvOptions") {
            let a = fix.member_key.authenticate(&request_options(uv), RP_ORIGIN);
            payload["uvCredential"] = published(&a);
        }
        let finished = send(fix, transport, &fix.member, REDEEM_FINISH_TYPE, payload).await;
        let finished = ok(&finished, "redeem/finish");
        redeem_finish::Response::validate_value(&finished).expect("conforms");
        assert_eq!(finished["subject"], fix.member.did);
        assert_eq!(finished["purpose"], "stepUp");
        assert_eq!(finished["deviceLabel"], "Carol's laptop");
        finished["credentialId"].as_str().unwrap().to_string()
    }

    fn break_glass() -> Value {
        json!({
            "right": "git.repo.own",
            "resource": "github.com/acme/widgets",
            "justification": "Both owners unreachable; the fix must ship tonight",
        })
    }

    /// A bound step-up asked of `did`, as a break-glass would ask it.
    async fn bound_request(fix: &Fixture, did: &str) -> Value {
        match bound_step_up::redeem_or_request(
            &fix.vtc.state,
            did,
            BREAK_GLASS,
            &break_glass(),
            "break the glass",
        )
        .await
        .unwrap()
        {
            Gate::Required(r) => serde_json::to_value(*r).unwrap(),
            Gate::Satisfied => panic!("no gesture was recorded yet"),
        }
    }

    /// The `stage`s of the step-up passkey audit rows, in the order written.
    async fn audited_stages(fix: &Fixture) -> Vec<String> {
        let rows = fix
            .vtc
            .state
            .audit_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap();
        let mut out: Vec<(chrono::DateTime<chrono::Utc>, String)> = Vec::new();
        for (_, value) in rows {
            if let Ok(env) = serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&value)
                && let AuditEvent::StepUpPasskeyChanged(d) = env.event
            {
                out.push((env.timestamp, d.stage));
            }
        }
        out.sort();
        out.into_iter().map(|(_, s)| s).collect()
    }

    // ── the premise ──────────────────────────────────────────────────────

    /// The declarations the tests below lean on: invite and revoke need a
    /// proof by the specification; redemption does not, and this service
    /// requires it on `start` regardless.
    #[test]
    fn what_the_specifications_declare() {
        let required = |uri| {
            trust_tasks_rs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published policy"))
                .is_proof_required
        };
        assert!(required(INVITE_TYPE));
        assert!(required(REVOKE_START_TYPE));
        assert!(required(REVOKE_FINISH_TYPE));
        assert!(!required(REDEEM_START_TYPE));
        assert!(!required(REDEEM_FINISH_TYPE));
    }

    // ── enroll/invite ────────────────────────────────────────────────────

    #[tokio::test]
    async fn enroll_invite_takes_the_administrators_bound_gesture_then_issues() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            let url = issued["invite"]["url"].as_str().unwrap();
            let code = issued["claimCode"].as_str().unwrap();
            assert!(
                url.starts_with(&format!("{RP_ORIGIN}/admin/enrol-step-up#token=")),
                "{url}"
            );
            assert!(!url.contains(code), "the claim code never rides in the URL");
            assert_eq!(issued["subject"], member);
            assert_eq!(issued["purpose"], "stepUp");
            assert_eq!(audited_stages(&fix).await, ["invited"], "{t:?}");
        }
    }

    #[tokio::test]
    async fn enroll_invite_refuses_before_asking_for_any_gesture() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let cases = [
                (
                    &fix.member,
                    json!({ "subject": fix.other.did, "purpose": "stepUp" }),
                    // Refused as every admin verb refuses a non-admin signer.
                    "permissionDenied",
                    "a member invites nobody",
                ),
                (
                    &fix.admin,
                    json!({ "subject": fix.admin.did, "purpose": "stepUp" }),
                    "auth/passkey/enroll/invite:roleNotPermitted",
                    "nobody invites themselves",
                ),
                (
                    &fix.admin,
                    json!({ "subject": "did:key:z6MkNotAMember", "purpose": "stepUp" }),
                    "auth/passkey/enroll/invite:subjectUnknown",
                    "only a current member is invited",
                ),
                (
                    &fix.admin,
                    json!({ "subject": fix.member.did }),
                    "auth/passkey/enroll/invite:purposeNotSupported",
                    "no session credential by invite",
                ),
                (
                    &fix.admin,
                    json!({ "subject": fix.member.did, "purpose": "stepUp", "role": "admin" }),
                    "malformedRequest",
                    "a step-up credential confers no role",
                ),
                (
                    &fix.admin,
                    json!({ "subject": fix.member.did, "purpose": "stepUp", "ttl": 86401 }),
                    "malformedRequest",
                    "an invite lives at most a day",
                ),
            ];
            for (from, payload, code, what) in cases {
                let out = send(&fix, t, from, INVITE_TYPE, payload).await;
                assert_code(&out, code, what);
                assert!(
                    payload_of(&out).pointer("/details/stepUpRequest").is_none(),
                    "{what}: no gesture is asked for an act that is refused anyway"
                );
            }
            let unsigned_doc = unsigned(
                &fix.admin,
                INVITE_TYPE,
                json!({ "subject": fix.member.did, "purpose": "stepUp" }),
            );
            let out = dispatch_doc(&fix, t, &fix.admin, &unsigned_doc).await;
            assert_code(&out, "proofRequired", "an invite is signed");
            assert!(audited_stages(&fix).await.is_empty(), "{t:?}");
        }
    }

    // ── enroll/redeem/start ──────────────────────────────────────────────

    #[tokio::test]
    async fn enroll_redeem_start_is_the_invited_members_alone() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            let payload =
                json!({ "token": issued["invite"]["token"], "claimCode": issued["claimCode"] });

            // Another member holding both messages binds nothing.
            let out = send(&fix, t, &fix.other, REDEEM_START_TYPE, payload.clone()).await;
            assert_code(
                &out,
                "auth/passkey/enroll/redeem/start:inviteInvalid",
                "another member",
            );
            // Nor does the administrator who wrote them.
            let out = send(&fix, t, &fix.admin, REDEEM_START_TYPE, payload.clone()).await;
            assert_code(
                &out,
                "auth/passkey/enroll/redeem/start:inviteInvalid",
                "the inviter",
            );
            // Unsigned is no redemption at all.
            let out = dispatch_doc(
                &fix,
                t,
                &fix.member,
                &unsigned(&fix.member, REDEEM_START_TYPE, payload.clone()),
            )
            .await;
            assert_code(&out, "proofRequired", "unsigned");
            // The member still can: those were refusals, not consumption.
            let out = send(&fix, t, &fix.member, REDEEM_START_TYPE, payload).await;
            ok(&out, "the invited member");
        }
    }

    #[tokio::test]
    async fn enroll_redeem_start_voids_an_invite_after_five_wrong_attempts() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            let wrong = json!({ "token": issued["invite"]["token"], "claimCode": "WRONGCODE99" });
            for _ in 1..MAX_WRONG_CODES {
                let out = send(&fix, t, &fix.member, REDEEM_START_TYPE, wrong.clone()).await;
                assert_code(
                    &out,
                    "auth/passkey/enroll/redeem/start:inviteInvalid",
                    "wrong code",
                );
            }
            let out = send(&fix, t, &fix.member, REDEEM_START_TYPE, wrong).await;
            assert_code(
                &out,
                "auth/passkey/enroll/redeem/start:tooManyAttempts",
                "the fifth",
            );
            let right =
                json!({ "token": issued["invite"]["token"], "claimCode": issued["claimCode"] });
            let out = send(&fix, t, &fix.member, REDEEM_START_TYPE, right).await;
            assert_code(
                &out,
                "auth/passkey/enroll/redeem/start:inviteInvalid",
                "voided",
            );
            assert_eq!(audited_stages(&fix).await, ["invited", "inviteInvalidated"]);
        }
    }

    // ── enroll/redeem/finish ─────────────────────────────────────────────

    #[tokio::test]
    async fn enroll_redeem_finish_binds_a_passkey_that_never_signs_in() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            let cred = redeem_over(&mut fix, t, &issued).await;

            // In its own store; login reads `passkey`, which never sees it.
            let sessions = get_all_passkeys(&fix.vtc.state.passkey_ks).await.unwrap();
            assert!(
                sessions
                    .iter()
                    .all(|p| hex::encode(<_ as AsRef<[u8]>>::as_ref(p.cred_id())) != cred),
                "a step-up passkey is never a sign-in credential"
            );
            let held = crate::step_up_passkey::credentials_of(&fix.vtc.state, &member)
                .await
                .unwrap();
            assert_eq!(held.len(), 1);

            // Single use.
            let again = send(
                &fix,
                t,
                &fix.member,
                REDEEM_START_TYPE,
                json!({ "token": issued["invite"]["token"], "claimCode": issued["claimCode"] }),
            )
            .await;
            assert_code(
                &again,
                "auth/passkey/enroll/redeem/start:inviteInvalid",
                "spent",
            );
            assert_eq!(
                audited_stages(&fix).await,
                ["invited", "registered"],
                "{t:?}"
            );
        }
    }

    /// The browser that ran `navigator.credentials.create` holds no key of the
    /// member's, so over HTTPS the finish may come unsigned — its authority
    /// is the ceremony the member's signed start opened. A signed finish must
    /// be the member's.
    #[tokio::test]
    async fn enroll_redeem_finish_may_come_unsigned_from_the_browser_but_never_from_another_signer()
    {
        let mut fix = fixture().await;
        let member = fix.member.did.clone();
        let issued = invite_over(&mut fix, JoinTransport::Rest, &member).await;
        let started = send(
            &fix,
            JoinTransport::Rest,
            &fix.member,
            REDEEM_START_TYPE,
            json!({ "token": issued["invite"]["token"], "claimCode": issued["claimCode"] }),
        )
        .await;
        let started = ok(&started, "redeem/start");
        let (cred, _) = fix
            .member_key
            .register(&creation(&started["options"]), RP_ORIGIN);
        let payload = json!({
            "enrollmentId": started["enrollmentId"],
            "credential": published(&cred),
        });
        let out = send(
            &fix,
            JoinTransport::Rest,
            &fix.other,
            REDEEM_FINISH_TYPE,
            payload.clone(),
        )
        .await;
        assert_code(
            &out,
            "auth/passkey/enroll/redeem/finish:enrollmentNotFound",
            "another signer",
        );
        // Left for the member, who finishes from the browser, unsigned.
        let browser = unsigned(&fix.member, REDEEM_FINISH_TYPE, payload);
        let out = dispatch_doc(&fix, JoinTransport::Rest, &fix.member, &browser).await;
        assert_eq!(ok(&out, "unsigned finish")["subject"], member);
    }

    #[tokio::test]
    async fn a_second_step_up_passkey_needs_a_gesture_from_the_first() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let first = invite_over(&mut fix, t, &member).await;
            redeem_over(&mut fix, t, &first).await;

            let second = invite_over(&mut fix, t, &member).await;
            let started = send(
                &fix,
                t,
                &fix.member,
                REDEEM_START_TYPE,
                json!({ "token": second["invite"]["token"], "claimCode": second["claimCode"] }),
            )
            .await;
            let started = ok(&started, "second redeem/start");
            assert!(started.get("uvOptions").is_some(), "the first is asked for");
            let (cred, _) = fix
                .member_key
                .register(&creation(&started["options"]), RP_ORIGIN);
            let out = send(
                &fix,
                t,
                &fix.member,
                REDEEM_FINISH_TYPE,
                json!({ "enrollmentId": started["enrollmentId"], "credential": published(&cred) }),
            )
            .await;
            assert_code(
                &out,
                "auth/passkey/enroll/redeem/finish:userVerificationFailed",
                "a missing gesture is never consent",
            );
            // The ceremony was spent; the invite was not.
            redeem_over(&mut fix, t, &second).await;
            let held = crate::step_up_passkey::credentials_of(&fix.vtc.state, &member)
                .await
                .unwrap();
            assert_eq!(held.len(), 2, "{t:?}");
        }
    }

    // ── use: auth/step-up/approve-response ───────────────────────────────

    /// The passkey is in addition to the member's `assertionMethod` proof,
    /// never instead of it (approve-response 0.5).
    #[tokio::test]
    async fn approve_response_with_a_step_up_passkey_still_needs_the_members_own_proof() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            redeem_over(&mut fix, t, &issued).await;

            let request = bound_request(&fix, &member).await;
            let assertion = fix
                .member_key
                .authenticate(&request_options(&request["webauthn"]), RP_ORIGIN);
            let evidence = json!({
                "subject": request["subject"],
                "challenge": request["challenge"],
                "decision": "approved",
                "evidence": { "kind": "webauthn", "assertion": published(&assertion) },
            });

            let bare = unsigned(&fix.member, STEP_UP_APPROVE_RESPONSE_TYPE, evidence.clone());
            let out = dispatch_doc(&fix, t, &fix.member, &bare).await;
            assert_code(&out, "proofRequired", "the passkey alone");
            for (signer, what) in [(&fix.other, "another member"), (&fix.admin, "an admin")] {
                let out = approve(&fix, t, signer, &request, &assertion).await;
                assert_code(
                    &out,
                    "auth/step-up/approve-response:subjectMismatch",
                    &format!("{what} signing the member's gesture"),
                );
            }
            // The refusals left the challenge unspent.
            let out = approve(&fix, t, &fix.member, &request, &assertion).await;
            assert_eq!(ok(&out, "the member's own")["status"], "recorded", "{t:?}");
            let spent = bound_step_up::redeem_or_request(
                &fix.vtc.state,
                &member,
                BREAK_GLASS,
                &break_glass(),
                "break the glass",
            )
            .await
            .unwrap();
            assert!(matches!(spent, Gate::Satisfied), "{t:?}");
        }
    }

    /// `auth/step-up/approve-response/0.5`, served alongside 0.4: a webauthn
    /// gate alone is never enough — unlike 0.4, which still admits an
    /// unsigned console-passkey answer, 0.5 requires the approver's proof on
    /// every response, so an unsigned 0.5 document is refused before its
    /// evidence is even looked at. Signed by the subject, it is recorded
    /// exactly as 0.4 records it.
    #[tokio::test]
    async fn approve_response_0_5_requires_the_subjects_proof_even_for_a_webauthn_gate() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            redeem_over(&mut fix, t, &issued).await;

            let request = bound_request(&fix, &member).await;
            let assertion = fix
                .member_key
                .authenticate(&request_options(&request["webauthn"]), RP_ORIGIN);
            let evidence = json!({
                "subject": request["subject"],
                "challenge": request["challenge"],
                "decision": "approved",
                "evidence": { "kind": "webauthn", "assertion": published(&assertion) },
            });

            let bare = unsigned(&fix.member, STEP_UP_APPROVE_RESPONSE_V0_5_TYPE, evidence);
            let out = dispatch_doc(&fix, t, &fix.member, &bare).await;
            assert_code(
                &out,
                "proofRequired",
                "0.5 admits no unsigned answer, webauthn evidence or not",
            );

            let out = approve_as(
                &fix,
                t,
                STEP_UP_APPROVE_RESPONSE_V0_5_TYPE,
                &fix.member,
                &request,
                &assertion,
            )
            .await;
            assert_eq!(
                ok(&out, "0.5, signed by the subject")["status"],
                "recorded",
                "{t:?}"
            );
            let spent = bound_step_up::redeem_or_request(
                &fix.vtc.state,
                &member,
                BREAK_GLASS,
                &break_glass(),
                "break the glass",
            )
            .await
            .unwrap();
            assert!(matches!(spent, Gate::Satisfied), "{t:?}");
        }
    }

    /// A step-up passkey answers only its own member's step-ups: the ceremony
    /// an administrator is asked for never offers it, and an assertion from it
    /// over the administrator's challenge does not verify.
    #[tokio::test]
    async fn an_administrator_cannot_answer_with_a_members_step_up_passkey() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            let cred = redeem_over(&mut fix, t, &issued).await;

            let admin = fix.admin.did.clone();
            let mut request = bound_request(&fix, &admin).await;
            let offered: Vec<String> = request["webauthn"]["allowCredentials"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    let id = base64::Engine::decode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        c["id"].as_str().unwrap(),
                    )
                    .unwrap();
                    hex::encode(id)
                })
                .collect();
            assert!(!offered.contains(&cred), "never offered for someone else");

            let member_cred_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                hex::decode(&cred).unwrap(),
            );
            request["webauthn"]["allowCredentials"] =
                json!([{ "type": "public-key", "id": member_cred_b64 }]);
            let assertion = fix
                .member_key
                .authenticate(&request_options(&request["webauthn"]), RP_ORIGIN);
            let out = approve(&fix, t, &fix.admin, &request, &assertion).await;
            assert_code(
                &out,
                "auth/step-up/approve-response:assertionInvalid",
                "a member's passkey over an admin's challenge",
            );
        }
    }

    #[tokio::test]
    async fn a_former_members_step_up_passkey_is_offered_for_nothing() {
        let mut fix = fixture().await;
        let member = fix.member.did.clone();
        let issued = invite_over(&mut fix, JoinTransport::Rest, &member).await;
        redeem_over(&mut fix, JoinTransport::Rest, &issued).await;
        crate::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &member)
            .await
            .unwrap();
        let asked = bound_step_up::redeem_or_request(
            &fix.vtc.state,
            &member,
            BREAK_GLASS,
            &break_glass(),
            "break the glass",
        )
        .await;
        assert!(asked.is_err(), "no passkey counts for a DID that has left");
    }

    // ── revoke/start + revoke/finish ─────────────────────────────────────

    #[tokio::test]
    async fn revoke_removes_it_and_a_step_up_already_pending_cannot_be_answered() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            let cred = redeem_over(&mut fix, t, &issued).await;
            let pending = bound_request(&fix, &member).await;

            // Nobody but the owner or a community administrator starts one.
            let out = send(
                &fix,
                t,
                &fix.other,
                REVOKE_START_TYPE,
                json!({ "credentialId": cred, "subject": member }),
            )
            .await;
            assert_code(
                &out,
                "auth/passkey/revoke/start:notAuthorized",
                "neither the owner nor an admin",
            );
            let out = send(
                &fix,
                t,
                &fix.admin,
                REVOKE_START_TYPE,
                json!({ "credentialId": cred, "subject": fix.other.did }),
            )
            .await;
            assert_code(
                &out,
                "auth/passkey/revoke/start:credentialNotFound",
                "someone else's credential",
            );

            let started = send(
                &fix,
                t,
                &fix.admin,
                REVOKE_START_TYPE,
                json!({ "credentialId": cred, "subject": member }),
            )
            .await;
            let started = ok(&started, "revoke/start");
            revoke_start::Response::validate_value(&started).expect("conforms");
            let uv = fix
                .admin_key
                .authenticate(&request_options(&started["uvOptions"]), RP_ORIGIN);
            let finish = json!({
                "revocationId": started["revocationId"],
                "uvCredential": published(&uv),
            });
            // Only the administrator who started it finishes it.
            let out = send(&fix, t, &fix.other, REVOKE_FINISH_TYPE, finish.clone()).await;
            assert!(error_code(&out).is_some(), "{t:?}");
            let done = send(&fix, t, &fix.admin, REVOKE_FINISH_TYPE, finish).await;
            let done = ok(&done, "revoke/finish");
            revoke_finish::Response::validate_value(&done).expect("conforms");
            assert_eq!(done["remaining"], 0);

            let assertion = fix
                .member_key
                .authenticate(&request_options(&pending["webauthn"]), RP_ORIGIN);
            let out = approve(&fix, t, &fix.member, &pending, &assertion).await;
            assert_code(
                &out,
                "auth/step-up/approve-response:assertionInvalid",
                "a revoked passkey answers nothing",
            );
            assert_eq!(
                audited_stages(&fix).await,
                ["invited", "registered", "revoked"],
                "{t:?}"
            );
        }
    }

    /// A member revokes their own step-up passkey: no `subject` in the
    /// payload, no administrator standing needed, verified with the
    /// credential being revoked itself — the only one they hold.
    #[tokio::test]
    async fn a_member_revokes_their_own_step_up_passkey() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            let cred = redeem_over(&mut fix, t, &issued).await;

            let started = send(
                &fix,
                t,
                &fix.member,
                REVOKE_START_TYPE,
                json!({ "credentialId": cred }),
            )
            .await;
            let started = ok(&started, "self revoke/start");
            revoke_start::Response::validate_value(&started).expect("conforms");
            let uv = fix
                .member_key
                .authenticate(&request_options(&started["uvOptions"]), RP_ORIGIN);
            let finish = json!({
                "revocationId": started["revocationId"],
                "uvCredential": published(&uv),
            });
            let done = send(&fix, t, &fix.member, REVOKE_FINISH_TYPE, finish).await;
            let done = ok(&done, "self revoke/finish");
            revoke_finish::Response::validate_value(&done).expect("conforms");
            assert_eq!(done["subject"], member);
            assert_eq!(done["purpose"], "stepUp");
            assert_eq!(done["remaining"], 0);

            let held = crate::step_up_passkey::credentials_of(&fix.vtc.state, &member)
                .await
                .unwrap();
            assert!(held.is_empty(), "{t:?}");
            assert_eq!(
                audited_stages(&fix).await,
                ["invited", "registered", "revoked"],
                "{t:?}"
            );
        }
    }

    /// A member with no step-up passkey of their own cannot start a
    /// self-revoke against someone else's, and a member who holds two cannot
    /// verify a revocation of the first with a gesture from the second alone
    /// — `revoke_start` offers exactly the subject's own credentials, which
    /// here is just the one being revoked.
    #[tokio::test]
    async fn self_revoke_is_refused_for_a_credential_the_producer_does_not_own() {
        let mut fix = fixture().await;
        let member = fix.member.did.clone();
        let issued = invite_over(&mut fix, JoinTransport::Rest, &member).await;
        let cred = redeem_over(&mut fix, JoinTransport::Rest, &issued).await;

        // `fix.other` holds no step-up passkey at all, let alone this one.
        let out = send(
            &fix,
            JoinTransport::Rest,
            &fix.other,
            REVOKE_START_TYPE,
            json!({ "credentialId": cred }),
        )
        .await;
        assert_code(
            &out,
            "auth/passkey/revoke/start:credentialNotFound",
            "not the owner",
        );
    }

    // ── admin-list ───────────────────────────────────────────────────────

    /// `payload.subject` / `payload.purpose`, as the console sends them.
    fn list_of(subject: &str) -> Value {
        json!({ "subject": subject, "purpose": "stepUp" })
    }

    /// The listing's credentials, checked against the published response
    /// shape (the generated `Response`'s `deny_unknown_fields` is the
    /// schema's `additionalProperties: false`).
    fn listed(out: &TrustTaskOutcome, what: &str) -> Vec<admin_list::ListedCredential> {
        let payload = ok(out, what);
        let response: admin_list::Response =
            serde_json::from_value(payload).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(
            response.purpose,
            admin_list::ResponsePurpose::StepUp,
            "{what}"
        );
        response.credentials
    }

    /// Re-seed `did`'s ACL row scoped to `contexts`, keeping its role.
    async fn scope(fix: &Fixture, did: &str, role: VtcRole, contexts: &[&str]) {
        seed_acl(
            &fix.vtc,
            did,
            role,
            contexts.iter().map(|c| c.to_string()).collect(),
        )
        .await;
    }

    #[tokio::test]
    async fn admin_list_by_an_administrator_with_authority_lists_metadata_and_changes_nothing() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            let cred = redeem_over(&mut fix, t, &issued).await;

            let out = send(&fix, t, &fix.admin, ADMIN_LIST_TYPE, list_of(&member)).await;
            let payload = ok(&out, "the listing");
            assert_eq!(payload["subject"], member, "{t:?}");
            let listed_now = listed(&out, "the listing");
            assert_eq!(listed_now.len(), 1, "{t:?}");
            let c = &listed_now[0];
            assert_eq!(c.credential_id.as_str(), cred);
            assert_eq!(
                c.device_label.as_deref().map(String::as_str),
                Some("Carol's laptop")
            );
            assert!(c.last_used_at.is_none(), "never used yet");
            let enrolled_count = c.sign_count.expect("the counter is disclosed");
            // Nothing but metadata: no public key, no user handle, no ceremony.
            let keys: Vec<&String> = payload["credentials"][0]
                .as_object()
                .unwrap()
                .keys()
                .collect();
            assert!(
                keys.iter().all(|k| [
                    "credentialId",
                    "deviceLabel",
                    "registeredAt",
                    "lastUsedAt",
                    "signCount"
                ]
                .contains(&k.as_str())),
                "{keys:?}"
            );

            // No side effects: listing again answers the same, and wrote no
            // audit row.
            let again = send(&fix, t, &fix.admin, ADMIN_LIST_TYPE, list_of(&member)).await;
            assert_eq!(
                serde_json::to_value(listed(&again, "again")).unwrap(),
                serde_json::to_value(&listed_now).unwrap(),
                "{t:?}"
            );
            assert_eq!(audited_stages(&fix).await, ["invited", "registered"]);

            // A use shows up: last used, and the counter moved.
            let request = bound_request(&fix, &member).await;
            let assertion = fix
                .member_key
                .authenticate(&request_options(&request["webauthn"]), RP_ORIGIN);
            let out = approve(&fix, t, &fix.member, &request, &assertion).await;
            ok(&out, "the gesture");
            let after = send(&fix, t, &fix.admin, ADMIN_LIST_TYPE, list_of(&member)).await;
            let after = listed(&after, "after a use");
            assert!(after[0].last_used_at.is_some(), "{t:?}");
            assert!(after[0].sign_count.unwrap() > enrolled_count, "{t:?}");
        }
    }

    /// An administrator holding `vtc.members.manage` — a moderator — has
    /// standing over a member's factors and lists them like anyone else.
    #[tokio::test]
    async fn admin_list_by_a_moderator_holding_vtc_members_manage() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            let cred = redeem_over(&mut fix, t, &issued).await;
            let scoped = Party::new();
            scope(&fix, &scoped.did, VtcRole::Admin, &["team-a"]).await;
            scope(&fix, &member, VtcRole::Member, &["team-a"]).await;

            let out = send(&fix, t, &scoped, ADMIN_LIST_TYPE, list_of(&member)).await;
            let got = listed(&out, "a moderator holds vtc.members.manage");
            assert_eq!(got.len(), 1, "{t:?}");
            assert_eq!(got[0].credential_id.as_str(), cred);
        }
    }

    #[tokio::test]
    async fn admin_list_refuses_a_signer_who_is_not_an_administrator() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let member = fix.member.did.clone();
            for (from, what) in [
                (&fix.member, "a member, about themselves"),
                (&fix.other, "another member"),
            ] {
                let out = send(&fix, t, from, ADMIN_LIST_TYPE, list_of(&member)).await;
                assert_code(&out, admin_list::error_codes::NOT_ADMINISTRATOR.code, what);
            }
            // Decided before the subject: a non-administrator asking about
            // nobody gets the same answer.
            let out = send(
                &fix,
                t,
                &fix.other,
                ADMIN_LIST_TYPE,
                list_of("did:key:z6MkNotAMember"),
            )
            .await;
            assert_code(
                &out,
                admin_list::error_codes::NOT_ADMINISTRATOR.code,
                "no oracle",
            );
            let stranger = Party::new();
            let out = send(&fix, t, &stranger, ADMIN_LIST_TYPE, list_of(&member)).await;
            assert_code(
                &out,
                admin_list::error_codes::NOT_ADMINISTRATOR.code,
                "no ACL row",
            );
        }
    }

    /// A member outside the administrator's authority — an administrator
    /// without `vtc.members.manage`, here an auditor — is answered exactly as
    /// one that does not exist.
    #[tokio::test]
    async fn admin_list_refuses_a_member_outside_the_administrators_authority() {
        for t in TRANSPORTS {
            let mut fix = fixture().await;
            let member = fix.member.did.clone();
            let issued = invite_over(&mut fix, t, &member).await;
            redeem_over(&mut fix, t, &issued).await;
            let scoped = Party::new();
            crate::acl::store_acl_entry(
                &fix.vtc.state.acl_ks,
                &crate::acl::VtcAclEntry::new(
                    &scoped.did,
                    VtcRole::Member,
                    crate::acl::AdminAuthority::for_role(crate::acl::AdminRole::Auditor),
                    "test",
                ),
            )
            .await
            .unwrap();

            let outside = send(&fix, t, &scoped, ADMIN_LIST_TYPE, list_of(&member)).await;
            assert_code(
                &outside,
                admin_list::error_codes::SUBJECT_UNKNOWN.code,
                "a member in another context",
            );
            let nobody = send(
                &fix,
                t,
                &scoped,
                ADMIN_LIST_TYPE,
                list_of("did:key:z6MkNotAMember"),
            )
            .await;
            assert_code(
                &nobody,
                admin_list::error_codes::SUBJECT_UNKNOWN.code,
                "nobody at all",
            );
            // Neither later code is ever an answer about them.
            let session = send(
                &fix,
                t,
                &scoped,
                ADMIN_LIST_TYPE,
                json!({ "subject": member, "purpose": "session" }),
            )
            .await;
            assert_code(
                &session,
                admin_list::error_codes::SUBJECT_UNKNOWN.code,
                "authority before purpose",
            );
        }
    }

    #[tokio::test]
    async fn admin_list_refuses_an_unknown_or_former_member_and_session_credentials() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let member = fix.member.did.clone();
            let out = send(
                &fix,
                t,
                &fix.admin,
                ADMIN_LIST_TYPE,
                list_of("did:key:z6MkNotAMember"),
            )
            .await;
            assert_code(
                &out,
                admin_list::error_codes::SUBJECT_UNKNOWN.code,
                "unknown",
            );

            let out = send(
                &fix,
                t,
                &fix.admin,
                ADMIN_LIST_TYPE,
                json!({ "subject": member, "purpose": "session" }),
            )
            .await;
            assert_code(
                &out,
                admin_list::error_codes::PURPOSE_NOT_SUPPORTED.code,
                "session credentials are their owner's to list",
            );

            let mut departed = crate::members::Member::fresh(&fix.other.did);
            departed.removed_at = Some(chrono::Utc::now());
            crate::members::store_member(&fix.vtc.state.members_ks, &departed)
                .await
                .unwrap();
            let out = send(
                &fix,
                t,
                &fix.admin,
                ADMIN_LIST_TYPE,
                list_of(&fix.other.did),
            )
            .await;
            assert_code(
                &out,
                admin_list::error_codes::SUBJECT_NOT_MEMBER.code,
                "a member who has left",
            );

            // An empty inventory is an answer, not a refusal.
            let out = send(&fix, t, &fix.admin, ADMIN_LIST_TYPE, list_of(&member)).await;
            assert!(listed(&out, "none enrolled").is_empty(), "{t:?}");
        }
    }

    #[tokio::test]
    async fn admin_list_refuses_an_unsigned_document() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let doc = unsigned(&fix.admin, ADMIN_LIST_TYPE, list_of(&fix.member.did));
            let out = dispatch_doc(&fix, t, &fix.admin, &doc).await;
            assert_code(&out, "proofRequired", "a listing is signed");
        }
    }

    #[tokio::test]
    async fn admin_list_refuses_a_payload_the_schema_refuses() {
        let fix = fixture().await;
        for bad in [
            json!({ "subject": fix.member.did }),
            json!({ "subject": fix.member.did, "purpose": "stepUp", "includePublicKeys": true }),
        ] {
            let out = send(&fix, JoinTransport::Rest, &fix.admin, ADMIN_LIST_TYPE, bad).await;
            assert_code(&out, "malformedRequest", "schema");
        }
    }
}
