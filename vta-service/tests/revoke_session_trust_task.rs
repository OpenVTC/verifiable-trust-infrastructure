//! Integration test for `auth/revoke-session/0.2` — ending sessions over the
//! trust-task dispatcher (bearer-authed, signed).
//!
//! The interesting behaviour is not the happy path; it is what the caller is
//! told when nothing is revoked. 0.2 settles what 0.1 left in conflict: a
//! session that is not there and a session outside the caller's authority must
//! be answered identically (consumer rule 2), and this VTA answers both with
//! the RECOMMENDED `revokedCount: 0`. The `subject` form refuses a subject
//! outside the caller's authority with `permissionDenied`, the same whether or
//! not the VTA knows the subject (rule 4). These tests pin both: same status,
//! same payload, byte for byte.
//!
//! The authority rule is VTI-SES-043 / VTI-ACL-050: a caller may end another
//! subject's sessions exactly when it could remove that subject's ACL entry.
//! [`context_admin_reaches_only_sessions_it_may_manage`] is the port of the
//! test that held it over the removed `/auth/sessions` REST routes.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{Session, SessionState, get_session, now_epoch, store_session};

/// The caller's signing seed. `auth/revoke-session/0.2` declares `proof`
/// REQUIRED, so the DID and the key behind it have to come from one place —
/// item 6 rejects a document whose issuer disagrees with the identity its token
/// authenticates.
const CALLER_SEED: u8 = 0x70;

fn caller() -> String {
    vta_service::test_support::did_for_seed(CALLER_SEED).0
}
const STRANGER: &str = "did:key:z6MkRevokeStranger";

async fn seed_session(ctx: &TestAppContext, session_id: &str, did: &str) {
    let session = Session {
        session_id: session_id.into(),
        did: did.into(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: Some(format!("rt-{session_id}")),
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into()],
        acr: "aal1".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();
}

/// Dispatch a `revoke-session` for `target`, authenticated as `caller().as_str()` on
/// `caller_session` with `role`. Returns `(status, response document)`.
async fn revoke(
    router: &axum::Router,
    ctx: &TestAppContext,
    caller_session: &str,
    role: &str,
    target: &str,
    doc_id: &str,
) -> (StatusCode, Value) {
    let claims = ctx.jwt_keys.new_claims(
        caller(),
        caller_session.into(),
        role.into(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();
    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{doc_id}"),
        "type": vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_2,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": &caller(),
        "recipient": "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        "payload": { "sessionId": target },
    }))
    .expect("envelope deserialises");
    vta_service::test_support::sign_as(CALLER_SEED, &mut typed);
    let doc = serde_json::to_value(&typed).expect("envelope serialises");
    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The happy path, and then the retry of it.
#[tokio::test]
async fn revoking_own_session_counts_one_then_zero() {
    let (router, ctx) = build_test_app().await;
    seed_session(&ctx, "sess-here", &caller()).await;
    seed_session(&ctx, "sess-other-device", caller().as_str()).await;

    let (status, v) = revoke(
        &router,
        &ctx,
        "sess-here",
        "reader",
        "sess-other-device",
        "revoke-1",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["payload"]["revokedCount"], 1, "{v}");
    assert!(
        get_session(&ctx.sessions_ks, "sess-other-device")
            .await
            .unwrap()
            .is_none(),
        "the session must actually be gone, not merely reported gone"
    );

    // The retry. `vta-sdk`'s `retry_safety` table calls this task `RetrySafe`,
    // and the response schema names this exact case — "Zero is a valid outcome
    // (e.g. the named sessionId was already revoked)". It used to reject.
    let (status, v) = revoke(
        &router,
        &ctx,
        "sess-here",
        "reader",
        "sess-other-device",
        "revoke-2",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a retried revoke is not an error: {v}"
    );
    assert_eq!(v["payload"]["revokedCount"], 0, "{v}");
}

/// The disclosure rule, which is the whole reason zero is ambiguous: a session
/// belonging to someone else must be indistinguishable from one that was never
/// there.
#[tokio::test]
async fn a_stranger_session_and_a_missing_one_answer_identically() {
    let (router, ctx) = build_test_app().await;
    seed_session(&ctx, "sess-here", &caller()).await;
    seed_session(&ctx, "sess-not-yours", STRANGER).await;

    let (exists_status, exists) = revoke(
        &router,
        &ctx,
        "sess-here",
        "reader",
        "sess-not-yours",
        "revoke-3",
    )
    .await;
    let (absent_status, absent) = revoke(
        &router,
        &ctx,
        "sess-here",
        "reader",
        "sess-never-existed",
        "revoke-4",
    )
    .await;

    assert_eq!(exists_status, absent_status, "status must not disclose");
    assert_eq!(
        exists["payload"], absent["payload"],
        "payload must not disclose: a caller who is not the owner learns \
         nothing about whether the session exists"
    );
    assert_eq!(exists["payload"]["revokedCount"], 0, "{exists}");

    // And the stranger's session is untouched — non-disclosure is not a licence
    // to revoke it.
    assert!(
        get_session(&ctx.sessions_ks, "sess-not-yours")
            .await
            .unwrap()
            .is_some(),
        "answering zero must not have deleted a session the caller cannot touch"
    );
}

/// An admin does reach another subject's session — the authorisation rule is
/// unchanged, only what a *refusal* discloses.
#[tokio::test]
async fn an_admin_revokes_another_subjects_session() {
    let (router, ctx) = build_test_app().await;
    seed_session(&ctx, "sess-here", &caller()).await;
    seed_session(&ctx, "sess-not-yours", STRANGER).await;

    let (status, v) = revoke(
        &router,
        &ctx,
        "sess-here",
        "admin",
        "sess-not-yours",
        "revoke-5",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["payload"]["revokedCount"], 1, "{v}");
    assert!(
        get_session(&ctx.sessions_ks, "sess-not-yours")
            .await
            .unwrap()
            .is_none()
    );
}

// ── the subject form, and the authority rule (VTI-SES-043 / VTI-ACL-050) ─────

/// Post `payload` as a Trust Task of `type_uri`, signed as `seed`'s DID and
/// carried on `token` (a session of that same DID — the VTA acts on a document
/// only when its issuer is the authenticated caller).
async fn post_signed(
    router: &axum::Router,
    ctx: &TestAppContext,
    token: &str,
    seed: u8,
    type_uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let (did, _) = vta_service::test_support::did_for_seed(seed);
    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": did,
        "recipient": ctx.vta_did,
        "payload": payload,
    }))
    .expect("envelope deserialises");
    vta_service::test_support::sign_as(seed, &mut typed);
    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&typed).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Every live session row of `did`.
async fn sessions_of(ctx: &TestAppContext, did: &str) -> Vec<String> {
    vti_common::auth::session::list_sessions(&ctx.sessions_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|s| s.did == did)
        .map(|s| s.session_id)
        .collect()
}

const SUPER: u8 = 0x71;
const TENANT: u8 = 0x72;
const MEMBER_A: u8 = 0x73;
const MEMBER_B: u8 = 0x74;

fn did(seed: u8) -> String {
    vta_service::test_support::did_for_seed(seed).0
}

/// VTI-SES-043 / VTI-ACL-050, ported from the removed `/auth/sessions` REST
/// routes to `auth/sessions/list/0.1` + `auth/revoke-session/0.2`: a
/// context-scoped admin ends only the sessions of subjects it could remove
/// from the ACL. The admin role alone used to reach every session on the VTA,
/// a super-admin's included.
///
/// One difference from the REST original, by specification: the list is the
/// caller's own sessions only, whatever its role — `auth/sessions/list/0.1`
/// enumerates "every active session the auth service holds for the producer's
/// subject", and no published task enumerates another subject's.
#[tokio::test]
async fn context_admin_reaches_only_sessions_it_may_manage() {
    let (router, ctx) = build_test_app().await;
    let _super = ctx.mint_token(&did(SUPER), "admin", vec![]).await;
    let tenant = ctx
        .mint_token(&did(TENANT), "admin", vec!["ctx-a".into()])
        .await;
    let _a = ctx
        .mint_token(&did(MEMBER_A), "reader", vec!["ctx-a".into()])
        .await;
    let _b = ctx
        .mint_token(&did(MEMBER_B), "reader", vec!["ctx-b".into()])
        .await;
    // `mint_token` writes sessions with no `amr`, which the session schema
    // (`amr` minItems 1) refuses in a sessions/list answer. Real sessions carry
    // the method they were authenticated with.
    for subject in [did(SUPER), did(TENANT), did(MEMBER_A), did(MEMBER_B)] {
        for id in sessions_of(&ctx, &subject).await {
            let mut s = get_session(&ctx.sessions_ks, &id).await.unwrap().unwrap();
            s.amr = vec!["did".into()];
            store_session(&ctx.sessions_ks, &s).await.unwrap();
        }
    }

    // The list holds the tenant's own session, and nobody else's.
    let (status, body) = post_signed(
        &router,
        &ctx,
        &tenant,
        TENANT,
        vta_sdk::trust_tasks::TASK_AUTH_SESSIONS_LIST_0_1,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let subjects: Vec<&str> = body["payload"]["sessions"]
        .as_array()
        .expect("a session array")
        .iter()
        .map(|s| s["subject"].as_str().unwrap())
        .collect();
    assert_eq!(subjects, [did(TENANT).as_str()], "{body}");

    // Collective termination: refused for a super-admin and for another
    // context's member — and a subject the VTA has never heard of is refused
    // in exactly the same words (consumer rule 4).
    let mut refusals = Vec::new();
    for target in [
        did(SUPER),
        did(MEMBER_B),
        "did:key:z6MkNobodyKnowsThisOne".into(),
    ] {
        let (status, body) = post_signed(
            &router,
            &ctx,
            &tenant,
            TENANT,
            vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_2,
            json!({ "subject": target }),
        )
        .await;
        assert_eq!(
            body["payload"]["code"], "permissionDenied",
            "{target}: {body}"
        );
        // Everything but `inResponseTo`, which names this request.
        let mut payload = body["payload"].clone();
        payload.as_object_mut().unwrap().remove("inResponseTo");
        refusals.push((status, payload));
    }
    assert!(
        refusals.windows(2).all(|w| w[0] == w[1]),
        "a refusal must not disclose whether the subject exists: {refusals:#?}"
    );
    assert_eq!(sessions_of(&ctx, &did(SUPER)).await.len(), 1);
    assert_eq!(sessions_of(&ctx, &did(MEMBER_B)).await.len(), 1);

    // Its own context's member is within reach.
    let (status, body) = post_signed(
        &router,
        &ctx,
        &tenant,
        TENANT,
        vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_2,
        json!({ "subject": did(MEMBER_A), "reason": "access-withdrawn" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["revokedCount"], 1, "{body}");
    assert!(sessions_of(&ctx, &did(MEMBER_A)).await.is_empty());

    // Single-session termination follows the same rule — answered as a
    // missing session, and the super-admin's session is untouched.
    let super_session = sessions_of(&ctx, &did(SUPER)).await.remove(0);
    let (status, body) = post_signed(
        &router,
        &ctx,
        &tenant,
        TENANT,
        vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_2,
        json!({ "sessionId": super_session }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["revokedCount"], 0, "{body}");
    assert_eq!(sessions_of(&ctx, &did(SUPER)).await, [super_session]);
}

/// A super-admin reaches any subject, including one with no ACL entry at all —
/// which belongs to no context, so only unrestricted authority reaches it.
#[tokio::test]
async fn a_super_admin_ends_every_session_of_any_subject() {
    let (router, ctx) = build_test_app().await;
    let admin = ctx.mint_token(&did(SUPER), "admin", vec![]).await;
    seed_session(&ctx, "sess-orphan-1", STRANGER).await;
    seed_session(&ctx, "sess-orphan-2", STRANGER).await;

    let (status, body) = post_signed(
        &router,
        &ctx,
        &admin,
        SUPER,
        vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_2,
        json!({ "subject": STRANGER }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["revokedCount"], 2, "{body}");
    assert!(sessions_of(&ctx, STRANGER).await.is_empty());
}

/// `subject` naming the caller is `all: true`: ownership is the authority, so
/// even a reader may sign itself out everywhere.
#[tokio::test]
async fn a_reader_signs_itself_out_everywhere() {
    let (router, ctx) = build_test_app().await;
    let token = ctx
        .mint_token(&did(MEMBER_A), "reader", vec!["ctx-a".into()])
        .await;
    seed_session(&ctx, "sess-laptop", &did(MEMBER_A)).await;

    let (status, body) = post_signed(
        &router,
        &ctx,
        &token,
        MEMBER_A,
        vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_2,
        json!({ "subject": did(MEMBER_A) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["revokedCount"], 2, "{body}");
    assert!(sessions_of(&ctx, &did(MEMBER_A)).await.is_empty());
}

/// 0.1 is not served any more: 0.2 accepts every 0.1 payload, so a client
/// moves by changing the URI, and there is no second version to keep in step.
#[tokio::test]
async fn revoke_session_0_1_is_not_served() {
    let (router, ctx) = build_test_app().await;
    let token = ctx.mint_token(&did(SUPER), "admin", vec![]).await;
    let (_, body) = post_signed(
        &router,
        &ctx,
        &token,
        SUPER,
        "https://trusttasks.org/spec/auth/revoke-session/0.1",
        json!({ "all": true }),
    )
    .await;
    assert!(
        body["type"]
            .as_str()
            .is_some_and(|t| t.contains("trust-task-error")),
        "{body}"
    );
    assert_eq!(sessions_of(&ctx, &did(SUPER)).await.len(), 1);
}

/// Exactly one form (producer rule 2). Two forms at once, or none, is
/// `malformedRequest` — refused before anything is revoked, over the wire.
#[tokio::test]
async fn two_forms_at_once_or_no_form_is_malformed() {
    let (router, ctx) = build_test_app().await;
    let token = ctx.mint_token(&did(SUPER), "admin", vec![]).await;
    seed_session(&ctx, "sess-kept", STRANGER).await;
    for payload in [
        json!({ "sessionId": "sess-kept", "all": true }),
        json!({ "sessionId": "sess-kept", "subject": STRANGER }),
        json!({ "all": true, "subject": STRANGER }),
        json!({ "sessionId": "sess-kept", "all": true, "subject": STRANGER }),
        json!({}),
        json!({ "reason": "no target at all" }),
    ] {
        let (_, body) = post_signed(
            &router,
            &ctx,
            &token,
            SUPER,
            vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_2,
            payload.clone(),
        )
        .await;
        assert_eq!(
            body["payload"]["code"], "malformedRequest",
            "{payload}: {body}"
        );
    }
    assert_eq!(sessions_of(&ctx, STRANGER).await.len(), 1);
    assert_eq!(sessions_of(&ctx, &did(SUPER)).await.len(), 1);
}
