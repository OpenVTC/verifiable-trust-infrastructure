//! `/v1/admin/console-keys` — the enrolment, listing and revocation of the
//! admin console's signing keys (#1684).
//!
//! The delegation's *effect* — what a document signed by a console key is
//! allowed to do — is held by the `console-key delegations` tests in
//! `src/trust_tasks/mod.rs`, beside the verifier they exercise. What is held
//! here is the door: who may write one of these records, what they may say,
//! and what it costs.
//!
//! Three properties, and each one is a way the whole design fails if it slips:
//!
//! - **A stolen session alone cannot enrol a signing key.** The credential this
//!   writes outlives the session and needs no gesture at use time, so the write
//!   costs a live passkey user-verification — the one thing script in the
//!   origin cannot forge.
//! - **A delegation cannot be enrolled for another DID.** Structurally: the
//!   body has no subject member, so the record is always written against the
//!   proven caller.
//! - **Revocation is immediate, and available without a second factor.** An
//!   operator who suspects a browser is compromised must not have to reach for
//!   their authenticator before they can disown it.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vtc_service::acl::console_key::get_delegation;
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;
use vti_common::audit::{AuditEnvelope, AuditEvent};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

const CONSOLE_DID: &str = "did:key:z6MkConsoleBrowserProfileOne";
const OTHER_CONSOLE_DID: &str = "did:key:z6MkConsoleBrowserProfileTwo";

struct Fixture {
    state: AppState,
    router: axum::Router,
    jwt_keys: Arc<JwtKeys>,
    /// Unrestricted `VtcRole::Admin` — a super-admin.
    admin_did: String,
    /// A second unrestricted admin, for the "somebody else's key" cases.
    other_admin_did: String,
    /// `VtcRole::Admin` scoped to one context: an admin, not a super-admin.
    scoped_admin_did: String,
    _vtc: TestVtc,
}

async fn seed_admin(vtc: &TestVtc, did: &str, contexts: Vec<String>) {
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: contexts,
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed ACL row");
}

async fn build_fixture() -> Fixture {
    let vtc = TestVtc::builder().with_audit(true).build().await;
    let admin_did = "did:key:z6MkAdminAlpha".to_string();
    let other_admin_did = "did:key:z6MkAdminBeta".to_string();
    let scoped_admin_did = "did:key:z6MkAdminScoped".to_string();
    seed_admin(&vtc, &admin_did, vec![]).await;
    seed_admin(&vtc, &other_admin_did, vec![]).await;
    seed_admin(&vtc, &scoped_admin_did, vec!["ctx-a".into()]).await;

    Fixture {
        state: vtc.state.clone(),
        router: vtc.router.clone(),
        jwt_keys: vtc.jwt_keys.clone(),
        admin_did,
        other_admin_did,
        scoped_admin_did,
        _vtc: vtc,
    }
}

/// Mint a bearer token for `did`.
///
/// `elevated` stamps the bounded step-up window on the **session row**, which
/// is what `acl::elevation::verified` reads. A token alone cannot say a human
/// touched an authenticator recently, which is the entire reason that function
/// re-reads the session rather than trusting `acr`.
///
/// The claims' scopes are read from the DID's **ACL row**, the way
/// `/auth/` mints them, so a context-scoped admin's token says so. Hard-coding
/// `vec![]` here would quietly make every caller a super-admin and the
/// scope-sensitive cases below would assert nothing.
async fn token_for(fix: &Fixture, did: &str, elevated: bool) -> String {
    let scopes = vtc_service::acl::get_acl_entry(&fix.state.acl_ks, did)
        .await
        .expect("read ACL row")
        .expect("the caller has an ACL row")
        .allowed_contexts;
    let session_id = format!("sess-{}", Uuid::new_v4());
    store_session(
        &fix.state.sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec!["passkey".into()],
            acr: "aal2".into(),
            acr_expires_at: elevated.then(|| now_epoch() + 300),
            token_id: None,
            session_pubkey_b58btc: None,
        },
    )
    .await
    .expect("store session");

    let claims = fix
        .jwt_keys
        .new_claims(
            did.to_string(),
            session_id,
            "admin".to_string(),
            scopes,
            900,
            false,
        )
        .with_aal(vec!["passkey".into()], "aal2");
    fix.jwt_keys.encode(&claims).expect("encode")
}

async fn call(
    fix: &Fixture,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Authorization", format!("Bearer {token}"));
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let res = fix
        .router
        .clone()
        .oneshot(builder.body(body).expect("request"))
        .await
        .expect("response");
    let status = res.status();
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

async fn enrol(fix: &Fixture, token: &str, console_did: &str) -> (StatusCode, Value) {
    call(
        fix,
        "POST",
        "/v1/admin/console-keys",
        token,
        Some(json!({ "consoleDid": console_did, "label": "Work laptop" })),
    )
    .await
}

// ---------------------------------------------------------------------------
// The step-up gate
// ---------------------------------------------------------------------------

/// **A stolen session alone cannot enrol a signing key.** The caller is a
/// genuine, authenticated, `aal2` super-admin — everything an attacker riding
/// the HttpOnly cookie would hold — and is still refused, because the session
/// row carries no live elevation.
#[tokio::test]
async fn enrolment_without_a_fresh_step_up_is_refused() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, false).await;

    let (status, body) = enrol(&fix, &token, CONSOLE_DID).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"], "step_up_required",
        "the console turns this exact code into a passkey prompt: {body}"
    );
    assert!(
        get_delegation(&fix.state.console_keys_ks, CONSOLE_DID)
            .await
            .expect("read")
            .is_none(),
        "a refused enrolment must write nothing"
    );
}

/// …and with one, it works, and the record binds to the caller.
#[tokio::test]
async fn enrolment_with_a_fresh_step_up_binds_the_key_to_the_caller() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, true).await;

    let (status, body) = enrol(&fix, &token, CONSOLE_DID).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["consoleDid"], CONSOLE_DID);
    assert_eq!(body["adminDid"], fix.admin_did);
    assert_eq!(body["label"], "Work laptop");
    assert_eq!(body["active"], true);

    let stored = get_delegation(&fix.state.console_keys_ks, CONSOLE_DID)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(stored.admin_did, fix.admin_did);
}

// ---------------------------------------------------------------------------
// "for another DID" — structurally impossible, and the near misses
// ---------------------------------------------------------------------------

/// **The subject is the caller and cannot be named.** A body carrying an
/// `adminDid` is refused outright rather than silently ignored — `EnrolRequest`
/// is `deny_unknown_fields`, which is the difference between a request that
/// does not do what it says and one that does not parse.
#[tokio::test]
async fn a_body_naming_another_admin_does_not_parse() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, true).await;

    let (status, _body) = call(
        &fix,
        "POST",
        "/v1/admin/console-keys",
        &token,
        Some(json!({
            "consoleDid": CONSOLE_DID,
            "adminDid": fix.other_admin_did,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an unknown member must be refused, not dropped"
    );
    assert!(
        get_delegation(&fix.state.console_keys_ks, CONSOLE_DID)
            .await
            .expect("read")
            .is_none()
    );
}

/// **A console key gains no bearer authority, so it cannot enrol another
/// delegation.** This is the "no further delegations, no escalation" property
/// stated as the one check that actually holds it: enrolment is a bearer route
/// under `AdminAuth`, a bearer session is minted only for a DID
/// `resolve_auth_role` admits, and enrolling a delegation writes no ACL row —
/// so the console key still resolves to nothing, and the enrolment door stays
/// shut to it.
///
/// The same fact is what keeps a delegation from being a second identity at
/// all: it is reachable *only* from the signed-document path.
#[tokio::test]
async fn a_console_key_gains_no_bearer_authority() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, true).await;
    assert_eq!(
        enrol(&fix, &token, CONSOLE_DID).await.0,
        StatusCode::CREATED
    );

    assert!(
        vtc_service::acl::resolve_auth_role(&fix.state.acl_ks, CONSOLE_DID)
            .await
            .is_err(),
        "an enrolled console key must still be nobody to the bearer auth layer"
    );
}

/// The other shape of "for another DID": naming an existing **admin's** DID as
/// the console key. Refused, because the record would be inert while that DID's
/// own row answered for it and would start acting-as the enroller the moment
/// the row was demoted — a demotion that silently promotes.
#[tokio::test]
async fn a_did_that_already_holds_an_acl_row_cannot_be_enrolled() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, true).await;

    let (status, body) = enrol(&fix, &token, &fix.other_admin_did.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

/// Once enrolled, a second admin cannot re-point the same console key at
/// themselves — that is a hand-over wearing an edit's clothes.
#[tokio::test]
async fn a_second_admin_cannot_claim_an_enrolled_console_key() {
    let fix = build_fixture().await;
    let first = token_for(&fix, &fix.admin_did, true).await;
    assert_eq!(
        enrol(&fix, &first, CONSOLE_DID).await.0,
        StatusCode::CREATED
    );

    let second = token_for(&fix, &fix.other_admin_did, true).await;
    let (status, body) = enrol(&fix, &second, CONSOLE_DID).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        get_delegation(&fix.state.console_keys_ks, CONSOLE_DID)
            .await
            .expect("read")
            .expect("present")
            .admin_did,
        fix.admin_did,
        "the first enrolment stands"
    );
}

#[tokio::test]
async fn a_console_did_must_be_a_did_key_and_not_the_callers_own() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, true).await;

    assert_eq!(
        enrol(&fix, &token, "did:web:console.example.com").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        enrol(&fix, &token, &fix.admin_did.clone()).await.0,
        StatusCode::BAD_REQUEST
    );
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

/// An operator who has enrolled none gets an empty collection, not a 404 —
/// the lesson `auth/passkey/list/0.1` learned when the console rendered its
/// own, correct, empty state directly under a "failed to load" banner.
#[tokio::test]
async fn listing_with_no_keys_is_an_empty_collection() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, false).await;

    let (status, body) = call(&fix, "GET", "/v1/admin/console-keys", &token, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["consoleKeys"], json!([]));
}

/// A read of your own keys is safe and needs no gesture — and it shows only
/// your own.
#[tokio::test]
async fn listing_is_scoped_to_the_caller_and_needs_no_step_up() {
    let fix = build_fixture().await;
    let mine = token_for(&fix, &fix.admin_did, true).await;
    let theirs = token_for(&fix, &fix.other_admin_did, true).await;
    assert_eq!(enrol(&fix, &mine, CONSOLE_DID).await.0, StatusCode::CREATED);
    assert_eq!(
        enrol(&fix, &theirs, OTHER_CONSOLE_DID).await.0,
        StatusCode::CREATED
    );

    let unelevated = token_for(&fix, &fix.admin_did, false).await;
    let (status, body) = call(&fix, "GET", "/v1/admin/console-keys", &unelevated, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let keys = body["consoleKeys"].as_array().expect("array");
    assert_eq!(keys.len(), 1, "only the caller's own: {body}");
    assert_eq!(keys[0]["consoleDid"], CONSOLE_DID);
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

/// Revocation needs no second factor, tombstones the row rather than deleting
/// it, and the listing says so afterwards.
#[tokio::test]
async fn revoking_your_own_key_needs_no_step_up_and_is_visible_afterwards() {
    let fix = build_fixture().await;
    let elevated = token_for(&fix, &fix.admin_did, true).await;
    assert_eq!(
        enrol(&fix, &elevated, CONSOLE_DID).await.0,
        StatusCode::CREATED
    );

    let plain = token_for(&fix, &fix.admin_did, false).await;
    let (status, body) = call(
        &fix,
        "DELETE",
        &format!("/v1/admin/console-keys/{CONSOLE_DID}"),
        &plain,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["consoleDid"], CONSOLE_DID);
    assert_eq!(body["remainingActive"], 0);

    let (_, listed) = call(&fix, "GET", "/v1/admin/console-keys", &plain, None).await;
    let keys = listed["consoleKeys"].as_array().expect("array");
    assert_eq!(keys.len(), 1, "the tombstone stays visible: {listed}");
    assert_eq!(keys[0]["active"], false);
    assert!(keys[0]["revokedAt"].is_string());
}

/// A revoked key cannot be re-enrolled. A burned browser gets a new key, not
/// its old one back.
#[tokio::test]
async fn a_revoked_key_cannot_be_re_enrolled() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, true).await;
    assert_eq!(
        enrol(&fix, &token, CONSOLE_DID).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(
            &fix,
            "DELETE",
            &format!("/v1/admin/console-keys/{CONSOLE_DID}"),
            &token,
            None
        )
        .await
        .0,
        StatusCode::OK
    );

    let (status, body) = enrol(&fix, &token, CONSOLE_DID).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

/// A super-admin may disarm another operator's console for incident response —
/// revocation only ever removes authority, so a broad power here cannot
/// escalate.
#[tokio::test]
async fn a_super_admin_may_revoke_another_admins_key() {
    let fix = build_fixture().await;
    let owner = token_for(&fix, &fix.admin_did, true).await;
    assert_eq!(
        enrol(&fix, &owner, CONSOLE_DID).await.0,
        StatusCode::CREATED
    );

    let responder = token_for(&fix, &fix.other_admin_did, false).await;
    let (status, body) = call(
        &fix,
        "DELETE",
        &format!("/v1/admin/console-keys/{CONSOLE_DID}"),
        &responder,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// …but a **context-scoped** admin may not. It cannot escalate, but it can
/// deny service, and a scoped admin should not be able to lock a peer out of
/// the signed door.
#[tokio::test]
async fn a_context_scoped_admin_may_not_revoke_another_admins_key() {
    let fix = build_fixture().await;
    let owner = token_for(&fix, &fix.admin_did, true).await;
    assert_eq!(
        enrol(&fix, &owner, CONSOLE_DID).await.0,
        StatusCode::CREATED
    );

    let scoped = token_for(&fix, &fix.scoped_admin_did, true).await;
    let (status, body) = call(
        &fix,
        "DELETE",
        &format!("/v1/admin/console-keys/{CONSOLE_DID}"),
        &scoped,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        get_delegation(&fix.state.console_keys_ks, CONSOLE_DID)
            .await
            .expect("read")
            .expect("present")
            .revoked_at
            .is_none()
    );
}

#[tokio::test]
async fn revoking_an_unknown_key_is_a_not_found() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, true).await;
    let (status, _) = call(
        &fix,
        "DELETE",
        "/v1/admin/console-keys/did:key:z6MkNeverEnrolled",
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Both mutations are security-relevant and both leave a row. Enrolment says a
/// human touched an authenticator at that moment; revocation says a browser was
/// disowned, and by whom.
#[tokio::test]
async fn enrolment_and_revocation_are_both_audited() {
    let fix = build_fixture().await;
    let token = token_for(&fix, &fix.admin_did, true).await;
    assert_eq!(
        enrol(&fix, &token, CONSOLE_DID).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(
            &fix,
            "DELETE",
            &format!("/v1/admin/console-keys/{CONSOLE_DID}"),
            &token,
            None
        )
        .await
        .0,
        StatusCode::OK
    );

    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .expect("read audit");
    let envelopes: Vec<AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).expect("envelope"))
        .collect();

    let enrolled = envelopes.iter().find(|e| {
        matches!(&e.event, AuditEvent::AdminConsoleKeyEnrolled(d) if d.console_did == CONSOLE_DID)
    });
    let revoked = envelopes.iter().find(|e| {
        matches!(&e.event, AuditEvent::AdminConsoleKeyRevoked(d) if d.console_did == CONSOLE_DID)
    });
    let enrolled = enrolled.expect("AdminConsoleKeyEnrolled envelope missing");
    let revoked = revoked.expect("AdminConsoleKeyRevoked envelope missing");

    // The actor is the human; the console DID is the target, so an erasure can
    // reach it and a reader can tell *which browser* without re-deriving a hash.
    assert_eq!(
        enrolled.actor_did_plain.as_deref(),
        Some(&fix.admin_did[..])
    );
    assert_eq!(enrolled.target_did_plain.as_deref(), Some(CONSOLE_DID));
    assert_eq!(revoked.target_did_plain.as_deref(), Some(CONSOLE_DID));
}
