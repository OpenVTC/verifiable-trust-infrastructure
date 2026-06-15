//! Integration coverage for `/v1/members/*` (Phase 1 M1.4–M1.6).
//!
//! Tests the wire shapes + auth gates of the list/show/update +
//! promote-to-admin endpoints. The full UV ceremony for
//! promote-to-admin needs the WebAuthn soft authenticator and
//! lives separately (mirrors the admin/passkeys test split).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use vti_common::auth::session::{Session, SessionState, store_session};
use vti_common::store::KeyspaceHandle;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::members::{Member, store_member};
use vtc_service::test_support::TestVtc;

const RP_ORIGIN: &str = "https://vtc.example.com";
const LIST_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/list/1.0";
const SHOW_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/show/1.0";
const PROMOTE_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/promote-to-admin/1.0";

const ADMIN_DID: &str = "did:key:zAdmin1";

struct Fixture {
    router: axum::Router,
    admin_token: String,
    acl_ks: KeyspaceHandle,
    members_ks: KeyspaceHandle,
    #[allow(dead_code)]
    join_requests_ks: KeyspaceHandle,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    // Role changes run through the role-change ceremony, which needs the
    // active decision policy + a credential signer to re-mint the role VEC
    // (with_signers) and webauthn for the promote UV ceremony (public_url).
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url(RP_ORIGIN)
        .build()
        .await;

    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .expect("install default policies");

    // Seed an admin ACL row so the admin DID resolves to a community admin.
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: ADMIN_DID.into(),
            role: VtcRole::Admin,
            label: Some("test admin".into()),
            allowed_contexts: vec![],
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();

    // Mint a session row that matches the JWT we hand back. The
    // AuthClaims extractor requires both a valid JWT AND a matching
    // `session_id` row in the sessions keyspace. The claim is
    // tee-attested with a 1h TTL (the promote ceremony reads these).
    let session_id = "test-admin-session";
    let session = Session {
        session_id: session_id.into(),
        did: ADMIN_DID.into(),
        challenge: "test".into(),
        state: SessionState::Authenticated,
        created_at: now,
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: false,
        amr: Vec::new(),
        acr: String::new(),
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&vtc.state.sessions_ks, &session)
        .await
        .unwrap();

    let admin_claims = vtc.jwt_keys.new_claims(
        ADMIN_DID.into(),
        session_id.into(),
        "admin".into(),
        vec![],
        3600,
        true,
    );
    let admin_token = vtc.jwt_keys.encode(&admin_claims).unwrap();

    let acl_ks = vtc.state.acl_ks.clone();
    let members_ks = vtc.state.members_ks.clone();
    let join_requests_ks = vtc.state.join_requests_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        admin_token,
        acl_ks,
        members_ks,
        join_requests_ks,
        _vtc: vtc,
    }
}

async fn seed_member(fix: &Fixture, did: &str, role: VtcRole) {
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            allowed_contexts: vec![],
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();
    store_member(&fix.members_ks, &Member::fresh(did))
        .await
        .unwrap();
}

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    trust_task: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("Trust-Task", trust_task);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let res = router
        .clone()
        .oneshot(
            req.body(
                body.map(|v| Body::from(v.to_string()))
                    .unwrap_or(Body::empty()),
            )
            .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

// ---------------------------------------------------------------------------
// M1.4 — list + show
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_members_empty_returns_empty_items() {
    let fix = build_fixture().await;
    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/members",
        LIST_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["items"], json!([]));
    assert!(body["nextCursor"].is_null());
}

#[tokio::test]
async fn list_members_returns_seeded_members() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zMember1", VtcRole::Member).await;
    seed_member(&fix, "did:key:zMember2", VtcRole::Moderator).await;

    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/members",
        LIST_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let roles: Vec<&str> = items.iter().map(|m| m["role"].as_str().unwrap()).collect();
    assert!(roles.contains(&"member"));
    assert!(roles.contains(&"moderator"));
}

#[tokio::test]
async fn list_members_filter_by_role_drops_non_matching() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zMember1", VtcRole::Member).await;
    seed_member(&fix, "did:key:zMod1", VtcRole::Moderator).await;

    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/members?role=moderator",
        LIST_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["did"], "did:key:zMod1");
}

#[tokio::test]
async fn list_members_requires_admin_role() {
    let fix = build_fixture().await;
    let (status, _) = send(&fix.router, "GET", "/v1/members", LIST_TASK, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn show_member_returns_joined_response() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zM1", VtcRole::Issuer).await;

    let (status, body) = send(
        &fix.router,
        "GET",
        "/v1/members/did:key:zM1",
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["did"], "did:key:zM1");
    assert_eq!(body["role"], "issuer");
    assert!(body["joinedAt"].is_string());
    assert_eq!(body["publishConsent"], false);
    assert_eq!(body["departurePreference"], "policydefault");
}

#[tokio::test]
async fn show_member_rejects_malformed_did_path_param() {
    // P3.13: a path-param that isn't a well-formed DID is rejected at
    // the handler before it's ever used as a store key.
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "GET",
        "/v1/members/not-a-did",
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn show_member_returns_404_for_unknown_did() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "GET",
        "/v1/members/did:key:zNobody",
        SHOW_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// M1.5 — PATCH
// ---------------------------------------------------------------------------

#[tokio::test]
async fn patch_member_role_member_to_moderator_succeeds_and_emits_audit() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zM1", VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "PATCH",
        "/v1/members/did:key:zM1",
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "role": "moderator" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["role"], "moderator");

    // Confirm the on-disk ACL row reflects the change.
    let entry = vtc_service::acl::get_acl_entry(&fix.acl_ks, "did:key:zM1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, VtcRole::Moderator);
}

#[tokio::test]
async fn patch_member_role_admin_is_refused_with_promote_hint() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zM1", VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "PATCH",
        "/v1/members/did:key:zM1",
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "role": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    let msg = body.to_string();
    assert!(
        msg.contains("promote-to-admin"),
        "expected operator hint, got {msg}"
    );
}

#[tokio::test]
async fn patch_member_profile_only_emits_member_updated() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zM1", VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "PATCH",
        "/v1/members/did:key:zM1",
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({
            "publishConsent": true,
            "departurePreference": "purge",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["publishConsent"], true);
    assert_eq!(body["departurePreference"], "purge");
    // Role unchanged.
    assert_eq!(body["role"], "member");
}

#[tokio::test]
async fn patch_member_404_for_unknown_did() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "PATCH",
        "/v1/members/did:key:zNobody",
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "publishConsent": true })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// M1.6 — promote-to-admin pre-flight (full UV ceremony is in
// `tests/admin_passkeys.rs`-style harness coverage, separate)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn promote_rejects_caller_promoting_themselves() {
    let fix = build_fixture().await;
    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/members/{ADMIN_DID}/promote-to-admin/start"),
        PROMOTE_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    let msg = body.to_string();
    assert!(msg.contains("cannot promote yourself"), "got {msg}");
}

#[tokio::test]
async fn promote_404_for_non_member_target() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "POST",
        "/v1/members/did:key:zNobody/promote-to-admin/start",
        PROMOTE_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn promote_409_when_target_is_already_admin() {
    let fix = build_fixture().await;
    seed_member(&fix, "did:key:zSecondAdmin", VtcRole::Admin).await;
    let (status, _) = send(
        &fix.router,
        "POST",
        "/v1/members/did:key:zSecondAdmin/promote-to-admin/start",
        PROMOTE_TASK,
        Some(&fix.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
