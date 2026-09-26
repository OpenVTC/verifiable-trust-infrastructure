//! Integration coverage for the canonical `acl/*` surface (phase 2d).
//!
//! The URI swap is the least interesting part. What needs pinning is
//! the behaviour the canonical tasks promise and VTC did not previously
//! implement: a compare-and-swap on role changes, scope *reduction*
//! that isn't a full removal, and a grant that refuses to be used as a
//! back door for role changes.
//!
//! Since #1645 `acl/change-role` is also **the** admin-promotion path, and
//! carries the gates that used to live on `vtc/members/update` alone: a live
//! step-up (VTI-OPS-051), no self-promotion (VTI-OPS-050), the operator's
//! `role_change.rego`, and the role-VEC re-mint.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

use vtc_service::test_support::TestVtc;

const LIST: &str = "https://trusttasks.org/spec/acl/list/0.1";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const SHOW: &str = "https://trusttasks.org/spec/acl/show/0.1";
const CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";

const ADMIN: &str = "did:key:z6MkAdmin";

struct Fixture {
    router: axum::Router,
    vtc: TestVtc,
}

async fn build() -> Fixture {
    // A role change is the role-change ceremony, so the fixture needs the
    // active decision policy and a credential signer to re-mint a member's
    // role VEC — the same thing `members_crud`'s fixture builds.
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url("https://vtc.example.com")
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .expect("install default policies");
    Fixture {
        router: vtc.router.clone(),
        vtc,
    }
}

async fn admin_token(fix: &Fixture) -> String {
    fix.vtc.token(ADMIN, "admin", vec![]).await
}

/// An admin bearer whose **session** carries a live step-up elevation — what
/// `auth/passkey/login/finish/0.2` with `purpose: stepUp` leaves behind, and
/// the only thing that can confer admin.
///
/// `remaining_secs` is the window's lifetime; pass a past instant for a lapsed
/// one.
async fn stepped_up_admin_token(fix: &Fixture, remaining_secs: i64) -> String {
    let session_id = format!("stepped-up-{remaining_secs}-{}", uuid::Uuid::new_v4());
    store_session(
        &fix.vtc.state.sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: ADMIN.into(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec!["passkey".into()],
            acr: "aal2".into(),
            acr_expires_at: Some(now_epoch().saturating_add_signed(remaining_secs)),
            token_id: None,
            session_pubkey_b58btc: None,
        },
    )
    .await
    .unwrap();
    let claims = fix
        .vtc
        .jwt_keys
        .new_claims(ADMIN.into(), session_id, "admin".into(), vec![], 900, false)
        .with_aal(vec!["passkey".into()], "aal2");
    fix.vtc.jwt_keys.encode(&claims).unwrap()
}

/// Seed a member: an ACL entry **and** the member row a role VEC is repointed
/// on. Promotion targets are members; ACL-only subjects are covered separately.
async fn seed_member(fix: &Fixture, did: &str, role: &str) {
    let token = admin_token(fix).await;
    assert_eq!(
        grant(fix, &token, did, role, json!([])).await,
        StatusCode::CREATED
    );
    make_member(fix, did).await;
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

async fn call(
    fix: &Fixture,
    method: &str,
    uri: &str,
    task: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("Trust-Task", task)
        .header("Authorization", format!("Bearer {token}"));
    if body.is_some() {
        b = b.header("Content-Type", "application/json");
    }
    let req = b
        .body(body.map_or(Body::empty(), |v| Body::from(v.to_string())))
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

async fn grant(fix: &Fixture, token: &str, subject: &str, role: &str, scopes: Value) -> StatusCode {
    call(
        fix,
        "POST",
        "/v1/acl",
        GRANT,
        token,
        Some(json!({ "entry": { "subject": subject, "role": role, "scopes": scopes } })),
    )
    .await
    .0
}

#[tokio::test]
async fn entries_use_canonical_names_and_rfc3339_timestamps() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    assert_eq!(
        grant(
            &fix,
            &token,
            "did:key:z6MkAlice",
            "member",
            json!(["ctx-a"])
        )
        .await,
        StatusCode::CREATED
    );

    let (status, body) = call(&fix, "GET", "/v1/acl", LIST, &token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("truncated").is_some(),
        "truncated required: {body}"
    );

    let entry = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["subject"] == "did:key:z6MkAlice")
        .expect("granted entry present");
    assert_eq!(entry["scopes"], json!(["ctx-a"]));
    assert!(
        entry["createdAt"].as_str().unwrap().contains('T'),
        "createdAt must be RFC3339: {entry}"
    );
    for old in ["did", "allowed_contexts", "created_at"] {
        assert!(entry.get(old).is_none(), "{old} must be gone: {entry}");
    }
}

/// Canonical: a grant against an existing subject with a *different*
/// role must be refused and point at change-role. Otherwise grant is a
/// silent bypass of the compare-and-swap guard.
#[tokio::test]
async fn grant_refuses_to_change_an_existing_role() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    assert_eq!(
        grant(&fix, &token, "did:key:z6MkBob", "member", json!(["ctx-a"])).await,
        StatusCode::CREATED
    );

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": "did:key:z6MkBob", "role": "moderator", "scopes": ["ctx-a"] } })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("change-role"),
        "the refusal should name the right task: {body}"
    );
}

/// Re-granting the *same* role is how canonical expresses "the entry
/// the maintainer should hold" — it rewrites scopes/label.
#[tokio::test]
async fn grant_with_the_same_role_rewrites_the_entry() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(
        &fix,
        &token,
        "did:key:z6MkCarol",
        "member",
        json!(["ctx-a"]),
    )
    .await;

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": "did:key:z6MkCarol", "role": "member", "scopes": ["ctx-a", "ctx-b"] } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rewrite, not create: {body}");
    // `{entry: …}` — the shape these tasks publish (#1109).
    assert_eq!(body["entry"]["scopes"], json!(["ctx-a", "ctx-b"]));
    assert!(
        body["entry"]["updatedAt"].as_str().is_some(),
        "a rewrite must stamp updatedAt: {body}"
    );
    assert_eq!(body["entry"]["updatedBy"], "did:key:z6MkAdmin");
}

#[tokio::test]
async fn change_role_enforces_the_from_role_guard() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(&fix, &token, "did:key:z6MkDan", "member", json!(["ctx-a"])).await;

    // Stale read: caller believes Dan is a moderator.
    let (status, body) = call(
        &fix,
        "PATCH",
        "/v1/acl/did:key:z6MkDan",
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "moderator", "toRole": "admin" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a mismatched fromRole must not apply: {body}"
    );

    // Correct fromRole applies.
    let (status, body) = call(
        &fix,
        "PATCH",
        "/v1/acl/did:key:z6MkDan",
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "moderator" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // `{entry: …}` — the shape these tasks publish (#1109).
    assert_eq!(body["entry"]["role"], "moderator");
    assert!(body["entry"]["updatedAt"].as_str().is_some(), "{body}");
}

/// Canonical revoke has two modes. `scopes` reduces; omitting it
/// removes. Conflating them would strip more authority than asked.
#[tokio::test]
async fn revoke_with_scopes_reduces_rather_than_removes() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(
        &fix,
        &token,
        "did:key:z6MkErin",
        "member",
        json!(["ctx-a", "ctx-b"]),
    )
    .await;

    let (status, _) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkErin?scopes=ctx-a",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The entry must survive, minus that one scope.
    let (status, body) = call(&fix, "GET", "/v1/acl/did:key:z6MkErin", SHOW, &token, None).await;
    assert_eq!(status, StatusCode::OK, "entry must survive: {body}");
    // `{entry: …}` — the shape these tasks publish (#1109).
    assert_eq!(body["entry"]["scopes"], json!(["ctx-b"]));
}

#[tokio::test]
async fn revoke_without_scopes_removes_the_entry() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(&fix, &token, "did:key:z6MkFred", "member", json!(["ctx-a"])).await;

    let (status, _) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkFred",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = call(&fix, "GET", "/v1/acl/did:key:z6MkFred", SHOW, &token, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Emptying an entry's scope set would leave an *unscoped* entry —
/// which is how a community-wide (super) grant is spelled. Revoking
/// must never widen authority.
#[tokio::test]
async fn revoking_every_scope_is_refused_rather_than_unscoping() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(&fix, &token, "did:key:z6MkGina", "member", json!(["ctx-a"])).await;

    let (status, body) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkGina?scopes=ctx-a",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (status, body) = call(&fix, "GET", "/v1/acl/did:key:z6MkGina", SHOW, &token, None).await;
    assert_eq!(status, StatusCode::OK, "entry must be untouched: {body}");
    // `{entry: …}` — the shape these tasks publish (#1109).
    assert_eq!(body["entry"]["scopes"], json!(["ctx-a"]));
}

#[tokio::test]
async fn each_verb_rejects_a_siblings_task() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    // GET /v1/acl bound to acl/list must not accept acl/grant.
    let (status, _) = call(&fix, "GET", "/v1/acl", GRANT, &token, None).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn list_filters_and_paginates() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    for who in ["did:key:z6MkP1", "did:key:z6MkP2", "did:key:z6MkP3"] {
        grant(&fix, &token, who, "member", json!(["ctx-a"])).await;
    }
    grant(
        &fix,
        &token,
        "did:key:z6MkQ1",
        "moderator",
        json!(["ctx-b"]),
    )
    .await;

    // Role filter actually filters.
    let (_, body) = call(&fix, "GET", "/v1/acl?role=moderator", LIST, &token, None).await;
    let subjects: Vec<&str> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["subject"].as_str().unwrap())
        .collect();
    assert_eq!(subjects, vec!["did:key:z6MkQ1"], "{body}");

    // Paging, and the cursor must not survive a filter change.
    let (_, page1) = call(
        &fix,
        "GET",
        "/v1/acl?scope=ctx-a&pageSize=1",
        LIST,
        &token,
        None,
    )
    .await;
    assert_eq!(page1["truncated"], true, "{page1}");
    let cursor = page1["cursor"].as_str().expect("cursor").to_string();

    let (status, _) = call(
        &fix,
        "GET",
        &format!("/v1/acl?scope=ctx-a&pageSize=1&cursor={cursor}"),
        LIST,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "same filters resume");

    let (status, body) = call(
        &fix,
        "GET",
        &format!("/v1/acl?scope=ctx-b&pageSize=1&cursor={cursor}"),
        LIST,
        &token,
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a cursor must not carry across a filter change: {body}"
    );
}

// ---------------------------------------------------------------------------
// Revoking a *member's* ACL entry would orphan their member row.
//
// Two surfaces own the ACL row and only one knows membership exists. The leave
// ceremony deletes the ACL, tombstones the member row, and revokes the
// credentials; this route deleted the ACL and stopped — leaving a live member
// row with no authorization and a VMC that still verified for anyone holding
// it. `members::read` called the result "genuine out-of-band corruption (e.g.
// an interrupted purge)" and warned on every list; it was not corruption, it
// was this route doing what it was asked.
// ---------------------------------------------------------------------------

/// Store a live member row for `did` — what admission leaves behind.
async fn make_member(fix: &Fixture, did: &str) {
    vtc_service::members::store_member(
        &fix.vtc.state.members_ks,
        &vtc_service::members::Member::fresh(did),
    )
    .await
    .expect("store member row");
}

#[tokio::test]
async fn revoking_a_members_acl_is_refused_and_names_the_removal_command() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    const DID: &str = "did:key:z6MkHurdle";
    grant(&fix, &token, DID, "member", json!(["ctx-a"])).await;
    make_member(&fix, DID).await;

    let (status, body) = call(
        &fix,
        "DELETE",
        &format!("/v1/acl/{DID}"),
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // "Operator errors should suggest the fix" — the message must carry the
    // command that actually removes a member, not just refuse.
    let msg = body.to_string();
    assert!(
        msg.contains("/v1/members/"),
        "the refusal must name the leave ceremony: {msg}"
    );

    // And the entry must survive: a refusal that already deleted the row would
    // be the same bug wearing a 409.
    let (status, body) = call(&fix, "GET", &format!("/v1/acl/{DID}"), SHOW, &token, None).await;
    assert_eq!(status, StatusCode::OK, "entry must be untouched: {body}");
}

/// A *departed* member row does not block the revoke. Tombstone and historical
/// departures keep the row as a "who was a member" record, and cleaning up a
/// stray ACL entry beside one is a legitimate admin action — the guard is about
/// orphaning a live membership, not about the row existing.
#[tokio::test]
async fn revoking_the_acl_of_a_departed_member_is_allowed() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    const DID: &str = "did:key:z6MkDeparted";
    grant(&fix, &token, DID, "member", json!(["ctx-a"])).await;

    let mut member = vtc_service::members::Member::fresh(DID);
    member.tombstone();
    vtc_service::members::store_member(&fix.vtc.state.members_ks, &member)
        .await
        .expect("store tombstoned member");

    let (status, body) = call(
        &fix,
        "DELETE",
        &format!("/v1/acl/{DID}"),
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

/// Scope *reduction* orphans nothing — the entry survives, minus those scopes —
/// so the guard must sit after that branch has returned. Putting it earlier
/// would block an ordinary privilege reduction on every member in the
/// community.
#[tokio::test]
async fn reducing_a_members_scopes_is_still_allowed() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    const DID: &str = "did:key:z6MkScoped";
    grant(&fix, &token, DID, "member", json!(["ctx-a", "ctx-b"])).await;
    make_member(&fix, DID).await;

    let (status, body) = call(
        &fix,
        "DELETE",
        &format!("/v1/acl/{DID}?scopes=ctx-a"),
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, body) = call(&fix, "GET", &format!("/v1/acl/{DID}"), SHOW, &token, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["entry"]["scopes"], json!(["ctx-b"]));
}

// ---------------------------------------------------------------------------
// Admin promotion (#1645). `acl/change-role` is the task the specification
// defines for role transitions, and since promotion moved here it carries the
// gates `vtc/members/update` used to hold alone.
// ---------------------------------------------------------------------------

/// VTI-OPS-051: conferring admin demands a *fresh* reauthentication.
///
/// This is the security fix, not a refactor. Before #1645 this exact request
/// promoted, with no second factor and no ceremony, while the equivalent
/// request on `vtc/members/update` was refused — so the gate could simply be
/// walked around.
#[tokio::test]
async fn vti_ops_051_change_role_to_admin_without_a_live_step_up_is_refused() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    seed_member(&fix, "did:key:z6MkCandidate", "member").await;

    let (status, body) = call(
        &fix,
        "PATCH",
        "/v1/acl/did:key:z6MkCandidate",
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "step_up_required", "{body}");

    // A refused promotion writes nothing.
    let entry = vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, "did:key:z6MkCandidate")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, vtc_service::acl::VtcRole::Member);
}

/// The window is the point: an elevation from an hour ago is no elevation.
#[tokio::test]
async fn vti_ops_051_a_lapsed_step_up_does_not_promote() {
    let fix = build().await;
    let token = stepped_up_admin_token(&fix, -1).await;
    seed_member(&fix, "did:key:z6MkLapsed", "member").await;

    let (status, body) = call(
        &fix,
        "PATCH",
        "/v1/acl/did:key:z6MkLapsed",
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "step_up_required", "{body}");
}

/// With a live elevation the promotion goes through — and brings the whole
/// role-change pipeline with it: the ACL row moves, the member's role VEC is
/// re-minted, and the admin sister record that lets the new admin enrol a
/// passkey is created.
#[tokio::test]
async fn vti_ops_051_a_live_step_up_promotes_and_runs_the_role_change_pipeline() {
    let fix = build().await;
    let token = stepped_up_admin_token(&fix, 900).await;
    const DID: &str = "did:key:z6MkPromoted";
    // Scoped, so the promotion lands a scoped admin and the step-up is the
    // whole gate. Promoting a scopeless member makes an *unrestricted* admin,
    // which also needs another admin's consent (VTI-APV-014) — covered in
    // `unrestricted_admin_consent.rs`.
    let admin = admin_token(&fix).await;
    assert_eq!(
        grant(&fix, &admin, DID, "member", json!(["ctx-a"])).await,
        StatusCode::CREATED
    );
    make_member(&fix, DID).await;

    let (status, body) = call(
        &fix,
        "PATCH",
        &format!("/v1/acl/{DID}"),
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["entry"]["role"], "admin");
    assert!(body["entry"]["updatedAt"].as_str().is_some(), "{body}");

    let entry = vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, DID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, vtc_service::acl::VtcRole::Admin);

    // The pipeline's effect, not just the ACL write: the role assertion was
    // re-issued at the new role and the member repointed at it.
    let member = vtc_service::members::get_member(&fix.vtc.state.members_ks, DID)
        .await
        .unwrap()
        .unwrap();
    assert!(
        member.current_role_vec_id.is_some(),
        "the role VEC must be re-minted by the ceremony, got {member:?}"
    );

    // And the sister record, without which the promotion produces an admin
    // who cannot sign in to the console.
    assert!(
        vtc_service::acl::admin::get_admin_entry(&fix.vtc.state.passkey_ks, DID)
            .await
            .unwrap()
            .is_some(),
        "a promotion must leave an admin record to enrol a passkey against"
    );
}

/// VTI-OPS-050: a second factor proves who is at the keyboard, never that a
/// second person agreed. A token minted while the caller was an admin must not
/// be usable to put their own demoted entry back.
#[tokio::test]
async fn vti_ops_050_self_promotion_is_refused_on_the_change_role_path() {
    let fix = build().await;
    let token = stepped_up_admin_token(&fix, 900).await;
    // The caller's own ACL row now says `member` — the bearer outlived the
    // demotion, which is exactly when self-promotion is reachable.
    seed_member(&fix, ADMIN, "member").await;

    let (status, body) = call(
        &fix,
        "PATCH",
        &format!("/v1/acl/{ADMIN}"),
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("cannot promote yourself") && msg.contains("acl/change-role"),
        "the refusal must say why and name the fix: {body}"
    );

    let entry = vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, ADMIN)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, vtc_service::acl::VtcRole::Member);
}

/// An ordinary role change is unaffected — the gate is on conferring admin,
/// not on touching a role.
#[tokio::test]
async fn a_non_admin_role_change_needs_no_step_up() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    seed_member(&fix, "did:key:z6MkLateral", "member").await;

    let (status, body) = call(
        &fix,
        "PATCH",
        "/v1/acl/did:key:z6MkLateral",
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "moderator" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["entry"]["role"], "moderator");
}

/// The other door onto the same authority. `acl/grant` writes an entry rather
/// than moving one, so it has no ceremony to hang an invariant on — but the
/// predicate is the same one, and it is checked.
#[tokio::test]
async fn vti_ops_051_granting_the_admin_role_without_a_step_up_is_refused() {
    let fix = build().await;
    let token = admin_token(&fix).await;

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": "did:key:z6MkFreshAdmin", "role": "admin", "scopes": ["ctx-a"] } })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "step_up_required", "{body}");
    assert!(
        vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, "did:key:z6MkFreshAdmin")
            .await
            .unwrap()
            .is_none(),
        "a refused grant must write nothing"
    );
}

#[tokio::test]
async fn granting_the_admin_role_with_a_step_up_succeeds() {
    let fix = build().await;
    let token = stepped_up_admin_token(&fix, 900).await;

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": "did:key:z6MkFreshAdmin", "role": "admin", "scopes": ["ctx-a"] } })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["entry"]["role"], "admin");
}

/// A re-grant that does not widen is not a conferral, and must not demand a
/// passkey. This is how the console edits an admin's label — `acl/change-role`
/// is role-only and would reject it — so gating every rewrite would have made
/// correcting a typo a second-factor ceremony.
#[tokio::test]
async fn re_granting_an_admin_at_the_same_scopes_needs_no_step_up() {
    let fix = build().await;
    let stepped_up = stepped_up_admin_token(&fix, 900).await;
    const DID: &str = "did:key:z6MkScopedAdmin";
    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &stepped_up,
        Some(json!({ "entry": { "subject": DID, "role": "admin", "scopes": ["ctx-a"] } })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Same role, same scopes, new label — on an *un*-elevated session.
    let plain = admin_token(&fix).await;
    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &plain,
        Some(
            json!({ "entry": { "subject": DID, "role": "admin", "scopes": ["ctx-a"],
                                "label": "Ops on-call" } }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a label edit is not a conferral: {body}"
    );
    assert_eq!(body["entry"]["label"], "Ops on-call");

    // Widening the same entry *is* a conferral, and is refused without one.
    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &plain,
        Some(json!({ "entry": { "subject": DID, "role": "admin", "scopes": [] } })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "step_up_required", "{body}");
}

/// Minting yourself an admin entry is self-promotion by another name.
#[tokio::test]
async fn vti_ops_050_granting_yourself_the_admin_role_is_refused() {
    let fix = build().await;
    let token = stepped_up_admin_token(&fix, 900).await;

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": ADMIN, "role": "admin", "scopes": [] } })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot grant yourself"),
        "{body}"
    );
}

/// A context admin may not mint an admin over a context it does not hold.
///
/// Found while moving the promotion here, and closed with it. `create_acl` has
/// always run `validate_acl_modification`; `update_acl` never did, and the
/// existing `caller_covers_admin_target` guard only fires on an entry that is
/// *already* admin — so a ctx-a admin could not demote a peer scoped to
/// `[ctx-a, ctx-b]`, but could promote a **member** with those scopes into
/// exactly that entry.
#[tokio::test]
async fn a_context_admin_cannot_promote_across_a_context_it_does_not_hold() {
    let fix = build().await;
    let super_token = admin_token(&fix).await;
    const DID: &str = "did:key:z6MkCrossScope";
    assert_eq!(
        grant(&fix, &super_token, DID, "member", json!(["ctx-a", "ctx-b"])).await,
        StatusCode::CREATED
    );
    make_member(&fix, DID).await;

    // An admin of ctx-a only. The entry is *visible* to them (the scopes
    // overlap), which is exactly what makes this reachable.
    let ctx_admin = fix
        .vtc
        .token("did:key:z6MkCtxAdmin", "admin", vec!["ctx-a".into()])
        .await;

    let (status, body) = call(
        &fix,
        "PATCH",
        &format!("/v1/acl/{DID}"),
        CHANGE_ROLE,
        &ctx_admin,
        Some(json!({ "fromRole": "member", "toRole": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let entry = vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, DID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, vtc_service::acl::VtcRole::Member);
}

/// A grant that does not confer admin is untouched by any of this.
#[tokio::test]
async fn granting_a_non_admin_role_needs_no_step_up() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    assert_eq!(
        grant(
            &fix,
            &token,
            "did:key:z6MkPlain",
            "member",
            json!(["ctx-a"])
        )
        .await,
        StatusCode::CREATED
    );
}
