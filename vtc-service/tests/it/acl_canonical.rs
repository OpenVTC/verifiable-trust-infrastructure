//! Integration coverage for the canonical `acl/*` surface (phase 2d).
//!
//! The ACL has no REST route: every verb is a signed Trust Task document at
//! `POST /v1/trust-tasks`, authorized by the signer's ACL row. Each test below
//! names its request by the route it once had — `call` sends it as the signed
//! document that replaced it — so the properties read as they always did.
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
//! `role_change.rego`, and the role-VAC re-mint.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

use vti_common::auth::session::now_epoch;
use vti_rooms_dtg::test_support::Party;

use vtc_service::test_support::TestVtc;

const LIST: &str = "https://trusttasks.org/spec/acl/list/0.1";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const SHOW: &str = "https://trusttasks.org/spec/acl/show/0.1";
const CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";

struct Fixture {
    router: axum::Router,
    vtc: TestVtc,
    /// The unrestricted admin every test acts as unless it says otherwise.
    admin: Arc<Party>,
    /// Every signer a test made, by DID — what `call`'s `token` names.
    signers: Mutex<HashMap<String, Arc<Party>>>,
}

impl Fixture {
    fn party(&self, did: &str) -> Arc<Party> {
        self.signers
            .lock()
            .unwrap()
            .get(did)
            .cloned()
            .unwrap_or_else(|| panic!("no signer {did}"))
    }

    /// A signer holding an ACL row of `role` over `scopes`; its DID.
    async fn signer(
        &self,
        role: vtc_service::acl::VtcRole,
        scopes: Vec<String>,
        expires_at: Option<u64>,
    ) -> String {
        let who = Arc::new(Party::new());
        seed_entry(&self.vtc, &who.did, role, scopes, expires_at).await;
        self.signers
            .lock()
            .unwrap()
            .insert(who.did.clone(), who.clone());
        who.did.clone()
    }
}

async fn build() -> Fixture {
    // A role change is the role-change ceremony, so the fixture needs the
    // active decision policy and a credential signer to re-mint a member's
    // role VAC — the same thing `members_crud`'s fixture builds.
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
    // The caller every test acts as. Its entry is what bounds the entries it
    // may write (VTI-ACL-053), and what authorizes every document it signs.
    let admin = Arc::new(Party::new());
    seed_entry(
        &vtc,
        &admin.did,
        vtc_service::acl::VtcRole::Admin,
        vec![],
        None,
    )
    .await;
    let signers = Mutex::new(HashMap::from([(admin.did.clone(), admin.clone())]));
    Fixture {
        router: vtc.router.clone(),
        vtc,
        admin,
        signers,
    }
}

async fn seed_entry(
    vtc: &TestVtc,
    did: &str,
    role: vtc_service::acl::VtcRole,
    scopes: Vec<String>,
    expires_at: Option<u64>,
) {
    vtc_service::acl::store_acl_entry(
        &vtc.state.acl_ks,
        &vtc_service::acl::VtcAclEntry {
            did: did.into(),
            admin: vtc_service::acl::legacy_seed_authority(&role, &scopes),
            delegated_by: None,
            role,
            label: None,
            created_at: now_epoch(),
            created_by: "test".into(),
            updated_at: None,
            updated_by: None,
            expires_at,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
    )
    .await
    .unwrap();
}

/// The fixture admin's DID — the `token` `call` signs as.
async fn admin_token(fix: &Fixture) -> String {
    fix.admin.did.clone()
}

/// Seed a member: an ACL entry **and** the member row a role VAC is repointed
/// on. Promotion targets are members; ACL-only subjects are covered separately.
async fn seed_member(fix: &Fixture, did: &str, role: &str) {
    let token = admin_token(fix).await;
    assert_eq!(
        grant(fix, &token, did, role, json!([])).await,
        StatusCode::OK
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

/// Send the request once made to `method uri` as the signed `acl/*`
/// document that replaced it, signed by `token`'s party; the reply's status
/// and payload. `task` is the task the route was bound to — asserted, so a
/// test cannot drift from the verb it names.
async fn call(
    fix: &Fixture,
    method: &str,
    uri: &str,
    task: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    let params: Vec<(&str, &str)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    let subject = path.strip_prefix("/v1/acl/").map(|s| s.replace("%3A", ":"));
    let (sent, payload) = match (method, subject) {
        ("GET", None) => {
            let mut filter = serde_json::Map::new();
            for (k, v) in &params {
                let v = if *k == "pageSize" {
                    json!(v.parse::<u64>().unwrap())
                } else {
                    json!(v)
                };
                filter.insert((*k).to_string(), v);
            }
            (LIST, Value::Object(filter))
        }
        ("POST", None) => (GRANT, body.expect("a grant carries an entry")),
        ("GET", Some(subject)) => (SHOW, json!({ "subject": subject })),
        ("PATCH", Some(subject)) => {
            let mut payload = body.expect("a role change carries its roles");
            payload["subject"] = json!(subject);
            (CHANGE_ROLE, payload)
        }
        ("DELETE", Some(subject)) => {
            let mut payload = json!({ "subject": subject });
            for (k, v) in &params {
                match *k {
                    "scopes" => {
                        payload["scopes"] =
                            json!(v.split(',').filter(|s| !s.is_empty()).collect::<Vec<_>>())
                    }
                    other => payload[other] = json!(v),
                }
            }
            (REVOKE, payload)
        }
        other => panic!("no acl verb for {other:?}"),
    };
    assert_eq!(sent, task, "{method} {uri} is {sent}");
    let signer = fix.party(token);
    let (status, doc) = post_doc(fix, &signed_doc(&signer, task, payload).await).await;
    (status, doc["payload"].clone())
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
        grant(&fix, &token, "did:key:z6MkAlice", "member", json!([])).await,
        StatusCode::OK
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
    assert_eq!(entry["scopes"], json!([]));
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
        grant(&fix, &token, "did:key:z6MkBob", "member", json!([])).await,
        StatusCode::OK
    );

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(
            json!({ "entry": { "subject": "did:key:z6MkBob", "role": "moderator", "scopes": [] } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let msg = body["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("change-role"),
        "the refusal should name the right task: {body}"
    );
}

/// Re-granting the *same* role is how canonical expresses "the entry
/// the maintainer should hold" — it rewrites the label.
#[tokio::test]
async fn grant_with_the_same_role_rewrites_the_entry() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(&fix, &token, "did:key:z6MkCarol", "member", json!([])).await;

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": "did:key:z6MkCarol", "role": "member", "scopes": [], "label": "Carol" } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rewrite, not create: {body}");
    // `{entry: …}` — the shape these tasks publish (#1109).
    assert_eq!(body["entry"]["label"], "Carol");
    assert!(
        body["entry"]["updatedAt"].as_str().is_some(),
        "a rewrite must stamp updatedAt: {body}"
    );
    assert_eq!(body["entry"]["updatedBy"], fix.admin.did);
}

#[tokio::test]
async fn change_role_enforces_the_from_role_guard() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(&fix, &token, "did:key:z6MkDan", "member", json!([])).await;

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
        StatusCode::UNPROCESSABLE_ENTITY,
        "a mismatched fromRole must not apply: {body}"
    );

    // Correct fromRole applies (to a community role that confers no
    // administrative authority, so no gesture is asked).
    let (status, body) = call(
        &fix,
        "PATCH",
        "/v1/acl/did:key:z6MkDan",
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "custom:editor" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // `{entry: …}` — the shape these tasks publish (#1109).
    assert_eq!(body["entry"]["role"], "custom:editor");
    assert!(body["entry"]["updatedAt"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn revoke_without_scopes_removes_the_entry() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(&fix, &token, "did:key:z6MkFred", "member", json!([])).await;

    let (status, body) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkFred",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A full removal leaves nothing: `entry` is `null`, not absent.
    assert!(body.get("entry").is_some_and(Value::is_null), "{body}");

    let (status, _) = call(&fix, "GET", "/v1/acl/did:key:z6MkFred", SHOW, &token, None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

/// The ACL has no REST route, under any method.
#[tokio::test]
async fn the_acl_has_no_rest_route() {
    let fix = build().await;
    let bearer = fix.vtc.token(&fix.admin.did, "admin", vec![]).await;
    for (method, uri) in [
        ("GET", "/v1/acl"),
        ("POST", "/v1/acl"),
        ("GET", "/v1/acl/did:key:z6MkAnyone"),
        ("PATCH", "/v1/acl/did:key:z6MkAnyone"),
        ("DELETE", "/v1/acl/did:key:z6MkAnyone"),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("Trust-Task", LIST)
            .header("Authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap();
        // Unrouted under the API mount, a GET falls through to the website's
        // fallback page; nothing answers as the ACL.
        let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
        assert!(
            body.get("entries").is_none()
                && body.get("entry").is_none()
                && !status.is_server_error(),
            "{method} {uri} answered {status}: {body}"
        );
        if method != "GET" {
            assert!(
                status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
                "{method} {uri} answered {status}"
            );
        }
    }
}

#[tokio::test]
async fn list_filters_and_paginates() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    for who in ["did:key:z6MkP1", "did:key:z6MkP2", "did:key:z6MkP3"] {
        grant(&fix, &token, who, "member", json!([])).await;
    }
    grant(&fix, &token, "did:key:z6MkQ1", "custom:editor", json!([])).await;

    // Role filter actually filters.
    let (_, body) = call(
        &fix,
        "GET",
        "/v1/acl?role=custom:editor",
        LIST,
        &token,
        None,
    )
    .await;
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
        "/v1/acl?role=member&pageSize=1",
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
        &format!("/v1/acl?role=member&pageSize=1&cursor={cursor}"),
        LIST,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "same filters resume");

    let (status, body) = call(
        &fix,
        "GET",
        &format!("/v1/acl?role=moderator&pageSize=1&cursor={cursor}"),
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
    grant(&fix, &token, DID, "member", json!([])).await;
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
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // "Operator errors should suggest the fix" — the message must carry the
    // command that actually removes a member, not just refuse.
    let msg = body.to_string();
    assert!(
        msg.contains("vtc/members/admin-remove"),
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
    grant(&fix, &token, DID, "member", json!([])).await;

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
    assert_eq!(status, StatusCode::OK, "{body}");
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
async fn vti_ops_051_change_role_conferring_authority_without_a_live_step_up_is_refused() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    // To moderator, which implies the moderator administrative role, so the
    // gesture is the whole gate (a community administrator also needs another
    // holder's consent, `unrestricted_admin_consent.rs`).
    assert_eq!(
        grant(&fix, &token, "did:key:z6MkCandidate", "member", json!([])).await,
        StatusCode::OK
    );
    make_member(&fix, "did:key:z6MkCandidate").await;

    let (status, body) = call(
        &fix,
        "PATCH",
        "/v1/acl/did:key:z6MkCandidate",
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "moderator" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // The fixture's admin has no passkey, so the refusal names the gesture it
    // cannot give (with one, it carries the ceremony as
    // `details.stepUpRequest` — `signed_step_up.rs`).
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("step-up required")),
        "refused pending a passkey gesture: {body}"
    );

    // A refused promotion writes nothing.
    let entry = vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, "did:key:z6MkCandidate")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, vtc_service::acl::VtcRole::Member);
}

/// A role change brings the whole role-change pipeline with it: the ACL row
/// moves and the member's role VAC is re-minted at the new role. (A move that
/// confers administrative authority runs the same pipeline behind an
/// operation-bound passkey gesture, driven end to end in `signed_step_up.rs`.)
#[tokio::test]
async fn a_role_change_runs_the_role_change_pipeline() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    const DID: &str = "did:key:z6MkPromoted";
    assert_eq!(
        grant(&fix, &token, DID, "member", json!([])).await,
        StatusCode::OK
    );
    make_member(&fix, DID).await;

    let (status, body) = call(
        &fix,
        "PATCH",
        &format!("/v1/acl/{DID}"),
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "custom:editor" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["entry"]["role"], "custom:editor");
    assert!(body["entry"]["updatedAt"].as_str().is_some(), "{body}");

    let entry = vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, DID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.role,
        vtc_service::acl::VtcRole::Custom("editor".into())
    );

    // The pipeline's effect, not just the ACL write: the role assertion was
    // re-issued at the new role and the member repointed at it.
    let member = vtc_service::members::get_member(&fix.vtc.state.members_ks, DID)
        .await
        .unwrap()
        .unwrap();
    assert!(
        member.current_role_vac_id.is_some(),
        "the role VAC must be re-minted by the ceremony, got {member:?}"
    );
}

/// VTI-OPS-050: a second factor proves who is at the keyboard, never that a
/// second person agreed. A signer who has been demoted cannot put their own
/// entry back: authority is read from the ACL row when the document executes.
#[tokio::test]
async fn vti_ops_050_self_promotion_is_refused_on_the_change_role_path() {
    let fix = build().await;
    let me = fix
        .signer(vtc_service::acl::VtcRole::Admin, vec![], None)
        .await;
    // The signer's own ACL row now says `member`. Written directly: the
    // signer cannot rewrite its own entry through `acl/grant` (VTI-ACL-052).
    seed_entry(
        &fix.vtc,
        &me,
        vtc_service::acl::VtcRole::Member,
        vec![],
        None,
    )
    .await;
    make_member(&fix, &me).await;

    let (status, body) = call(
        &fix,
        "PATCH",
        &format!("/v1/acl/{me}"),
        CHANGE_ROLE,
        &me,
        Some(json!({ "fromRole": "member", "toRole": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let entry = vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, &me)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, vtc_service::acl::VtcRole::Member);
}

/// A role change that confers no administrative authority is unaffected —
/// the gate is on conferring authority, not on touching a role. A custom
/// community role implies no administrative role.
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
        Some(json!({ "fromRole": "member", "toRole": "custom:editor" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["entry"]["role"], "custom:editor");
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
        Some(json!({ "entry": { "subject": "did:key:z6MkFreshAdmin", "role": "moderator", "scopes": [] } })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // The fixture's admin has no passkey, so the refusal names the gesture it
    // cannot give (with one, it carries the ceremony as
    // `details.stepUpRequest` — `signed_step_up.rs`).
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("step-up required")),
        "refused pending a passkey gesture: {body}"
    );
    assert!(
        vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, "did:key:z6MkFreshAdmin")
            .await
            .unwrap()
            .is_none(),
        "a refused grant must write nothing"
    );
}

/// A re-grant that does not widen is not a conferral, and must not demand a
/// passkey. This is how the console edits an admin's label — `acl/change-role`
/// is role-only and would reject it — so gating every rewrite would have made
/// correcting a typo a second-factor ceremony.
#[tokio::test]
async fn re_granting_an_admin_at_the_same_scopes_needs_no_step_up() {
    let fix = build().await;
    const DID: &str = "did:key:z6MkScopedAdmin";
    let expires = now_epoch() + 3600;
    seed_entry(
        &fix.vtc,
        DID,
        vtc_service::acl::VtcRole::Moderator,
        vec![],
        Some(expires),
    )
    .await;
    let at = chrono::DateTime::from_timestamp(expires as i64, 0)
        .unwrap()
        .to_rfc3339();

    // Same role, same scopes, new label — with no gesture.
    let plain = admin_token(&fix).await;
    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &plain,
        Some(
            json!({ "entry": { "subject": DID, "role": "moderator", "scopes": [],
                                "label": "Ops on-call", "expiresAt": at } }),
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
        // Lifting the expiry: a longer life is authority never granted, and a
        // moderator confers nothing authority-conferring, so the gesture is
        // the whole gate.
        Some(json!({ "entry": { "subject": DID, "role": "moderator", "scopes": [] } })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // The fixture's admin has no passkey, so the refusal names the gesture it
    // cannot give (with one, it carries the ceremony as
    // `details.stepUpRequest` — `signed_step_up.rs`).
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("step-up required")),
        "refused pending a passkey gesture: {body}"
    );
}

/// Minting yourself an admin entry is self-promotion by another name.
#[tokio::test]
async fn vti_ops_050_granting_yourself_the_admin_role_is_refused() {
    let fix = build().await;
    let token = admin_token(&fix).await;

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": fix.admin.did, "role": "admin", "scopes": [] } })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // The caller already holds an entry, so this is a rewrite of it and is
    // refused as one (VTI-ACL-052); a caller with no entry is refused with
    // "cannot grant yourself" before anything else.
    let msg = body["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("cannot grant yourself") || msg.contains("your own ACL entry"),
        "{body}"
    );
}

/// A grant that does not confer admin is untouched by any of this.
#[tokio::test]
async fn granting_a_non_admin_role_needs_no_step_up() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    assert_eq!(
        grant(&fix, &token, "did:key:z6MkPlain", "member", json!([])).await,
        StatusCode::OK
    );
}

// ─── VTI-ACL-052 / VTI-ACL-053: no self-widening, no grant past the granter ──

/// VTI-ACL-052: a rewrite of your own entry is a modification of it. Before
/// this, an administrator could re-grant itself at the same role with the
/// expiry dropped (time-boxed → permanent) or the scopes moved.
#[tokio::test]
async fn vti_acl_052_an_admin_cannot_rewrite_its_own_entry() {
    let fix = build().await;
    let expires = now_epoch() + 3600;
    let token = fix
        .signer(vtc_service::acl::VtcRole::Moderator, vec![], Some(expires))
        .await;
    let me = token.as_str();

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": me, "role": "moderator", "scopes": [] } })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let entry = vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, me)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.expires_at, Some(expires), "expiry must be untouched");
}

/// VTI-ACL-052 on the role path: demoting yourself is a modification of
/// your own entry too (the ceremony only refused self-*promotion*).
#[tokio::test]
async fn vti_acl_052_an_admin_cannot_change_its_own_role() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    let (status, body) = call(
        &fix,
        "PATCH",
        &format!("/v1/acl/{}", fix.admin.did),
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "admin", "toRole": "moderator" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// VTI-ACL-053: an administrator whose entry expires cannot write an entry
/// that outlives it — the way it would otherwise widen itself, by granting a
/// second DID it controls.
#[tokio::test]
async fn vti_acl_053_an_expiring_admin_cannot_grant_past_its_own_expiry() {
    let fix = build().await;
    let expires = now_epoch() + 3600;
    let token = fix
        .signer(vtc_service::acl::VtcRole::Admin, vec![], Some(expires))
        .await;
    let at = |secs: u64| {
        chrono::DateTime::from_timestamp(secs as i64, 0)
            .unwrap()
            .to_rfc3339()
    };

    for (what, entry) in [
        (
            "permanent",
            json!({ "subject": "did:key:z6MkSib1", "role": "member", "scopes": [] }),
        ),
        (
            "later",
            json!({ "subject": "did:key:z6MkSib2", "role": "member", "scopes": [],
                    "expiresAt": at(expires + 60) }),
        ),
    ] {
        let (status, body) = call(
            &fix,
            "POST",
            "/v1/acl",
            GRANT,
            &token,
            Some(json!({ "entry": entry })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {body}");
    }

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(
            json!({ "entry": { "subject": "did:key:z6MkSib3", "role": "member",
                                "scopes": [], "expiresAt": at(expires) } }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "within the granter's expiry: {body}"
    );
}

// ---------------------------------------------------------------------------
// One operation, whichever way it is asked.
//
// Written when the ACL still had bearer routes, to pin that both doors gave
// one answer. Both halves are signed documents now; the tests still pin that
// the operation answers the same request the same way — the same body on
// success, the same declared refusal on failure.
// ---------------------------------------------------------------------------

const UPDATE: &str = "https://trusttasks.org/spec/acl/update/0.1";

/// A signed document from `from`, addressed to the test VTC.
async fn signed_doc(from: &vti_rooms_dtg::test_support::Party, uri: &str, payload: Value) -> Value {
    let mut doc = vta_sdk::trust_task_sign::build_unsigned(
        uri,
        payload,
        &from.did,
        vtc_service::test_support::TEST_VTC_DID,
    )
    .unwrap();
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
        .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    serde_json::to_value(doc).unwrap()
}

/// POST a document; the reply's status and whole document.
async fn post_doc(fix: &Fixture, doc: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

/// An admin with a real key over `scopes`, and its DID (`call`'s `token`).
async fn two_door_admin(fix: &Fixture, scopes: Vec<String>) -> (Arc<Party>, String) {
    let did = fix
        .signer(vtc_service::acl::VtcRole::Admin, scopes, None)
        .await;
    (fix.party(&did), did)
}

/// Drop what legitimately differs between two answers to the same question:
/// the provenance stamps of a write made a moment apart.
fn without_stamps(mut v: Value) -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(map) => {
                map.remove("updatedAt");
                map.remove("createdAt");
                map.values_mut().for_each(strip);
            }
            Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut v);
    v
}

#[tokio::test]
async fn acl_show_and_list_answer_the_same_on_both_doors() {
    let fix = build().await;
    let (admin, token) = two_door_admin(&fix, vec![]).await;
    seed_entry(
        &fix.vtc,
        "did:key:z6MkParityShow",
        vtc_service::acl::VtcRole::Moderator,
        vec![],
        None,
    )
    .await;

    let (status, rest) = call(
        &fix,
        "GET",
        "/v1/acl/did:key:z6MkParityShow",
        SHOW,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rest}");
    let (status, doc) = post_doc(
        &fix,
        &signed_doc(&admin, SHOW, json!({ "subject": "did:key:z6MkParityShow" })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"], rest, "acl/show: one operation, one answer");

    let (status, rest) = call(&fix, "GET", "/v1/acl?role=moderator", LIST, &token, None).await;
    assert_eq!(status, StatusCode::OK, "{rest}");
    let (status, doc) = post_doc(
        &fix,
        &signed_doc(&admin, LIST, json!({ "role": "moderator" })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"], rest, "acl/list: one operation, one answer");

    // The same absence, the same way.
    let (status, _) = call(
        &fix,
        "GET",
        "/v1/acl/did:key:z6MkNobody",
        SHOW,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (_, doc) = post_doc(
        &fix,
        &signed_doc(&admin, SHOW, json!({ "subject": "did:key:z6MkNobody" })).await,
    )
    .await;
    assert_eq!(doc["payload"]["details"]["reason"], "not_found", "{doc}");
}

#[tokio::test]
async fn acl_revoke_answers_the_same_on_both_doors() {
    let fix = build().await;
    let (admin, token) = two_door_admin(&fix, vec![]).await;
    for did in ["did:key:z6MkParityRest", "did:key:z6MkParityDoc"] {
        seed_entry(
            &fix.vtc,
            did,
            vtc_service::acl::VtcRole::Member,
            vec![],
            None,
        )
        .await;
    }

    // Removal.
    let (status, rest) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkParityRest",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rest}");
    let (status, doc) = post_doc(
        &fix,
        &signed_doc(
            &admin,
            REVOKE,
            json!({ "subject": "did:key:z6MkParityDoc" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"], rest, "acl/revoke (remove)");
    assert_eq!(rest, json!({ "entry": null }));

    // The same absence carries the task's declared code on both doors.
    let (status, rest) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkParityRest",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{rest}");
    assert_eq!(rest["code"], "acl/revoke:subjectNotPresent", "{rest}");
    let (_, doc) = post_doc(
        &fix,
        &signed_doc(
            &admin,
            REVOKE,
            json!({ "subject": "did:key:z6MkParityDoc" }),
        )
        .await,
    )
    .await;
    assert_eq!(
        doc["payload"]["code"], "acl/revoke:subjectNotPresent",
        "{doc}"
    );
}

/// The refusals #1738 added — full cover to revoke (VTI-ACL-050: an
/// administrator without `vtc.roles.assign` covers nobody), no
/// self-modification — are the operation's, so both doors give them.
#[tokio::test]
async fn acl_revoke_refuses_the_same_on_both_doors() {
    let fix = build().await;
    let (scoped, token) = two_door_admin(&fix, vec!["ctx-a".into()]).await;
    seed_entry(
        &fix.vtc,
        "did:key:z6MkParityStraddle",
        vtc_service::acl::VtcRole::Member,
        vec![],
        None,
    )
    .await;

    let (status, rest) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkParityStraddle",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{rest}");
    let (_, doc) = post_doc(
        &fix,
        &signed_doc(
            &scoped,
            REVOKE,
            json!({ "subject": "did:key:z6MkParityStraddle" }),
        )
        .await,
    )
    .await;
    assert_eq!(doc["payload"]["code"], "permissionDenied", "{doc}");
    for said in [doc["payload"]["message"].as_str(), rest["message"].as_str()] {
        assert!(
            said.is_some_and(|m| m.contains("holds authority outside yours")),
            "the same refusal on both doors: {doc} / {rest}"
        );
    }

    let (status, rest) = call(
        &fix,
        "DELETE",
        &format!("/v1/acl/{}", scoped.did),
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{rest}");
    let (_, doc) = post_doc(
        &fix,
        &signed_doc(&scoped, REVOKE, json!({ "subject": scoped.did })).await,
    )
    .await;
    for said in [doc["payload"]["message"].as_str(), rest["message"].as_str()] {
        assert!(
            said.is_some_and(|m| m.contains("cannot delete your own ACL entry")),
            "the same refusal on both doors: {doc} / {rest}"
        );
    }

    let entry =
        vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, "did:key:z6MkParityStraddle")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(entry.role, vtc_service::acl::VtcRole::Member, "untouched");
}

/// `?scopes=` naming nothing is refused, not read as "remove the entry":
/// canonical `acl/revoke` declares `minItems: 1`, and the signed door refuses
/// the empty array on the schema.
#[tokio::test]
async fn acl_revoke_with_an_empty_scope_list_removes_nothing() {
    let fix = build().await;
    let (admin, token) = two_door_admin(&fix, vec![]).await;
    seed_entry(
        &fix.vtc,
        "did:key:z6MkParityEmpty",
        vtc_service::acl::VtcRole::Member,
        vec![],
        None,
    )
    .await;
    let (status, rest) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkParityEmpty?scopes=",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rest}");
    let (_, doc) = post_doc(
        &fix,
        &signed_doc(
            &admin,
            REVOKE,
            json!({ "subject": "did:key:z6MkParityEmpty", "scopes": [] }),
        )
        .await,
    )
    .await;
    assert_eq!(doc["payload"]["code"], "malformedRequest", "{doc}");
    assert!(
        vtc_service::acl::get_acl_entry(&fix.vtc.state.acl_ks, "did:key:z6MkParityEmpty")
            .await
            .unwrap()
            .is_some()
    );
}

/// An update and the grant that restates the same entry are one operation
/// planned by one function, so they land the same row.
#[tokio::test]
async fn acl_update_writes_what_the_equivalent_grant_writes() {
    let fix = build().await;
    let (admin, token) = two_door_admin(&fix, vec![]).await;
    for did in ["did:key:z6MkParityGrant", "did:key:z6MkParityUpdate"] {
        seed_entry(
            &fix.vtc,
            did,
            vtc_service::acl::VtcRole::Member,
            vec![],
            None,
        )
        .await;
    }
    let (status, rest) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": {
            "subject": "did:key:z6MkParityGrant", "role": "member",
            "scopes": [], "label": "ops",
        } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rest}");
    let (status, doc) = post_doc(
        &fix,
        &signed_doc(
            &admin,
            UPDATE,
            json!({ "subject": "did:key:z6MkParityUpdate", "label": "ops" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let mut from_doc = without_stamps(doc["payload"].clone());
    from_doc["entry"]["subject"] = json!("did:key:z6MkParityGrant");
    assert_eq!(from_doc, without_stamps(rest));
}
