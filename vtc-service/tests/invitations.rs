//! Integration coverage for `POST /v1/invitations` — the operator-side VIC
//! issuance route (the admin UI calls this to mint an invitation).
//!
//! Covers: admin happy path (a signed, revocable VIC bound to the invitee),
//! the non-privileged caller 403, and the already-a-member 409.

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::members::{Member, store_member};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const PUBLIC_URL: &str = "https://vtc.example.com";
const ISSUE_TASK: &str = "https://trusttasks.org/spec/vtc/invitations/issue/0.1";
const LIST_TASK: &str = "https://trusttasks.org/spec/vtc/invitations/list/0.1";
const REVOKE_TASK: &str = "https://trusttasks.org/spec/vtc/invitations/revoke/0.1";
const ADMIN_DID: &str = "did:key:zInvAdmin";
const MEMBER_DID: &str = "did:key:zInvMember";
const INVITEE_DID: &str = "did:key:zInvitee";
const VTC_DID: &str = "did:web:vtc.example.com";
const DELIVER_TASK: &str = "https://trusttasks.org/spec/vtc/invitations/deliver/0.1";
const REQUEST_TASK: &str = "https://trusttasks.org/spec/credential-exchange/request/0.1";

/// The codes `vtc/invitations/deliver/0.1` declares, read from the generated
/// bindings rather than spelled out (#1600).
const INVITATION_DELIVER_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::invitations::deliver::v0_1::error_codes::NOT_FOUND.code;
const INVITATION_DELIVER_ERR_REVOKED: &str =
    trust_tasks_rs::specs::vtc::invitations::deliver::v0_1::error_codes::REVOKED.code;
const INVITATION_DELIVER_ERR_NO_ROUTE: &str =
    trust_tasks_rs::specs::vtc::invitations::deliver::v0_1::error_codes::NO_ROUTE.code;

/// The extended error code carried by a REST error body (`{"error", "code"}`).
fn rest_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

struct Fixture {
    router: axum::Router,
    admin_token: String,
    member_token: String,
    _vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url(PUBLIC_URL)
        // An offer names its issuer, and a key-binding proof must be addressed
        // to it; `deliver` refuses to make an offer without one.
        .vtc_did(VTC_DID)
        .build()
        .await;

    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    let now = now_epoch();
    for (did, role) in [(ADMIN_DID, VtcRole::Admin), (MEMBER_DID, VtcRole::Member)] {
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: did.into(),
                role,
                label: None,
                allowed_contexts: vec![],
                created_at: now,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
        store_member(&vtc.state.members_ks, &Member::fresh(did))
            .await
            .unwrap();
    }

    async fn mint(
        sessions: &vti_common::store::KeyspaceHandle,
        jwt_keys: &Arc<JwtKeys>,
        did: &str,
        role: &str,
        now: u64,
    ) -> String {
        let session_id = format!("sess-{}", Uuid::new_v4());
        store_session(
            sessions,
            &Session {
                session_id: session_id.clone(),
                did: did.into(),
                challenge: "test".into(),
                state: SessionState::Authenticated,
                created_at: now,
                last_seen: now,
                refresh_token: None,
                refresh_expires_at: None,
                tee_attested: false,
                amr: Vec::new(),
                acr: String::new(),
                acr_expires_at: None,
                token_id: None,
                session_pubkey_b58btc: None,
            },
        )
        .await
        .unwrap();
        let claims = jwt_keys.new_claims(did.into(), session_id, role.into(), vec![], 3600, true);
        jwt_keys.encode(&claims).unwrap()
    }

    let admin_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        ADMIN_DID,
        "admin",
        now,
    )
    .await;
    let member_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        MEMBER_DID,
        "reader",
        now,
    )
    .await;

    let router = vtc.router.clone();
    Fixture {
        router,
        admin_token,
        member_token,
        _vtc: vtc,
    }
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

fn issue_req(token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/invitations")
        .header("authorization", format!("Bearer {token}"))
        .header("trust-task", ISSUE_TASK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn admin_issues_a_revocable_vic_bound_to_the_invitee() {
    let fix = build().await;
    let req = issue_req(&fix.admin_token, json!({ "subjectDid": INVITEE_DID }));
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");

    assert_eq!(v["subjectDid"], INVITEE_DID);
    let vic = &v["vic"];
    assert_eq!(vic["credentialSubject"]["id"], INVITEE_DID);
    let types: Vec<String> = serde_json::from_value(vic["type"].clone()).unwrap();
    assert!(
        types.iter().any(|t| t == "InvitationCredential"),
        "issued credential is an InvitationCredential: {types:?}"
    );
    assert!(
        vic.get("credentialStatus").is_some(),
        "the VIC must be revocable"
    );
    assert!(vic.get("proof").is_some(), "the VIC must be signed");
}

#[tokio::test]
async fn non_privileged_member_cannot_issue() {
    let fix = build().await;
    let req = issue_req(&fix.member_token, json!({ "subjectDid": INVITEE_DID }));
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn inviting_an_existing_member_is_a_conflict() {
    let fix = build().await;
    // MEMBER_DID already has a member row.
    let req = issue_req(&fix.admin_token, json!({ "subjectDid": MEMBER_DID }));
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn issuing_an_invitation_emits_audit() {
    use vti_common::audit::{AuditEnvelope, AuditEvent};

    let fix = build().await;
    let req = issue_req(
        &fix.admin_token,
        json!({ "subjectDid": INVITEE_DID, "role": "moderator" }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED);

    let raw = fix
        ._vtc
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    let envelopes: Vec<AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).unwrap())
        .collect();
    let issued: Vec<&AuditEnvelope> = envelopes
        .iter()
        .filter(|e| matches!(e.event, AuditEvent::InvitationIssued(_)))
        .collect();
    assert_eq!(issued.len(), 1, "exactly one InvitationIssued envelope");
    assert_eq!(issued[0].target_did_plain.as_deref(), Some(INVITEE_DID));
    let AuditEvent::InvitationIssued(data) = &issued[0].event else {
        unreachable!()
    };
    assert_eq!(data.subject_did, INVITEE_DID);
    assert_eq!(data.role.as_deref(), Some("moderator"));
}

#[tokio::test]
async fn inviting_a_departed_tombstoned_did_is_allowed() {
    let fix = build().await;
    // A departed member: a tombstone Member row (removed_at set) with NO ACL —
    // the ACL was deleted on a Tombstone/Historical departure. Re-inviting them
    // must succeed (re-join overwrites the tombstone), not 409.
    let departed = "did:key:z6MkDeparted000000000000000000000000000000000";
    let mut gone = Member::fresh(departed);
    gone.tombstone();
    store_member(&fix._vtc.state.members_ks, &gone)
        .await
        .unwrap();

    let req = issue_req(&fix.admin_token, json!({ "subjectDid": departed }));
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a departed (tombstoned) DID can be re-invited: {v}"
    );
}

#[tokio::test]
async fn invite_can_grant_a_role_via_scopes() {
    let fix = build().await;
    let req = issue_req(
        &fix.admin_token,
        json!({ "subjectDid": INVITEE_DID, "role": "moderator" }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let scopes = v["vic"]["credentialSubject"]["scopes"]
        .as_array()
        .expect("VIC carries credentialSubject.scopes");
    assert!(
        scopes.iter().any(|s| s == "role:moderator"),
        "role rides in scopes: {scopes:?}"
    );
}

#[tokio::test]
async fn issue_list_revoke_round_trip() {
    let fix = build().await;

    // Issue → the registry lists it as live.
    let req = issue_req(&fix.admin_token, json!({ "subjectDid": INVITEE_DID }));
    let (status, v) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let vic_id = v["vic"]["id"].as_str().expect("vic id").to_string();

    let list_req = Request::builder()
        .method("GET")
        .uri("/v1/invitations")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, v) = body_value(fix.router.clone().oneshot(list_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let row = v["invitations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == json!(vic_id))
        .expect("issued invitation is listed");
    assert!(
        row.get("revokedAt").is_none(),
        "live invite has no revokedAt"
    );

    // Revoke → 200, newlyRevoked.
    let del = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/invitations/{vic_id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, v) = body_value(fix.router.clone().oneshot(del).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["newlyRevoked"], json!(true));

    // Revoking again is idempotent (newlyRevoked = false).
    let del2 = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/invitations/{vic_id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, v) = body_value(fix.router.clone().oneshot(del2).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["newlyRevoked"], json!(false));
}

#[tokio::test]
async fn revoke_unknown_invitation_is_404() {
    let fix = build().await;
    let del = Request::builder()
        .method("DELETE")
        .uri("/v1/invitations/urn:uuid:does-not-exist")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let (status, _) = body_value(fix.router.clone().oneshot(del).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invite_refuses_admin_role() {
    let fix = build().await;
    let req = issue_req(
        &fix.admin_token,
        json!({ "subjectDid": INVITEE_DID, "role": "admin" }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an invite may not grant admin"
    );
}

// ── vtc/invitations/deliver (Keyring VTI-21 / VTI-32) ──────────────────────

/// An invitee with a real key: its `did:key` and the key-binding proofs it signs.
struct Invitee {
    key: ed25519_dalek::SigningKey,
    did: String,
}

impl Invitee {
    fn new(seed: u8) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(key.verifying_key().as_bytes());
        Self { key, did }
    }

    /// An `openid4vci-proof+jwt` addressed to the community, carrying the
    /// offer's pre-authorized code as its nonce.
    fn request(&self, code: &str) -> Value {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::Signer;
        let header = json!({ "typ": "openid4vci-proof+jwt", "alg": "EdDSA",
                             "kid": format!("{}#{}", self.did,
                                            self.did.strip_prefix("did:key:").unwrap()) });
        let payload = json!({ "iss": self.did, "aud": VTC_DID,
                              "iat": chrono::Utc::now().timestamp(), "nonce": code });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig = self.key.sign(format!("{h}.{p}").as_bytes());
        json!({ "credential_request": {
            "format": "vc+sd-jwt",
            "vct": "https://openvtc.org/credentials/InvitationCredential",
            "proof": { "proof_type": "jwt",
                       "jwt": format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes())) },
        }})
    }
}

async fn post(
    fix: &Fixture,
    uri: &str,
    task: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("trust-task", task)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = fix
        .router
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    body_value(resp).await
}

async fn issue_for(fix: &Fixture, did: &str) -> String {
    let (status, v) = post(
        fix,
        "/v1/invitations",
        ISSUE_TASK,
        Some(&fix.admin_token),
        json!({ "subjectDid": did }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    v["vic"]["id"].as_str().unwrap().to_string()
}

async fn deliver(fix: &Fixture, id: &str, channel: &str) -> (StatusCode, Value) {
    post(
        fix,
        "/v1/invitations/deliver",
        DELIVER_TASK,
        Some(&fix.admin_token),
        json!({ "id": id, "channel": channel }),
    )
    .await
}

fn code_of(offer: &Value) -> String {
    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .expect("a pre-authorized code")
        .to_string()
}

/// The VTI-32 path end to end: an offer small enough for a QR code, redeemed
/// over HTTPS by the invited DID's key, releasing the invitation once.
#[tokio::test]
async fn an_offered_invitation_is_redeemed_by_the_invitee_once() {
    let fix = build().await;
    let invitee = Invitee::new(41);
    let id = issue_for(&fix, &invitee.did).await;

    let (status, v) = deliver(&fix, &id, "offer").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["channel"], "offer");
    assert_eq!(v["offer"]["credential_issuer"], VTC_DID);
    // The offer names the credential; it never carries it.
    assert!(v["offer"].get("credential").is_none() && v.get("vic").is_none());
    let code = code_of(&v["offer"]);

    let (status, issued) = post(
        &fix,
        "/v1/credential-exchange/request",
        REQUEST_TASK,
        None,
        invitee.request(&code),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let vic = &issued["credential_response"]["credential"];
    assert_eq!(vic["id"], id);
    assert_eq!(vic["credentialSubject"]["id"], invitee.did);

    // Single use.
    let (status, _) = post(
        &fix,
        "/v1/credential-exchange/request",
        REQUEST_TASK,
        None,
        invitee.request(&code),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A photographed code admits no one else: a proof by another DID's key is
/// refused, and the offer stays redeemable by the invitee.
#[tokio::test]
async fn another_dids_proof_cannot_redeem_the_offer() {
    let fix = build().await;
    let invitee = Invitee::new(42);
    let id = issue_for(&fix, &invitee.did).await;
    let (_, v) = deliver(&fix, &id, "offer").await;
    let code = code_of(&v["offer"]);

    let thief = Invitee::new(43);
    let (status, body) = post(
        &fix,
        "/v1/credential-exchange/request",
        REQUEST_TASK,
        None,
        thief.request(&code),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, _) = post(
        &fix,
        "/v1/credential-exchange/request",
        REQUEST_TASK,
        None,
        invitee.request(&code),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// At most one offer per invitation redeems: delivering again withdraws the
/// earlier code.
#[tokio::test]
async fn a_new_delivery_withdraws_the_last_offer() {
    let fix = build().await;
    let invitee = Invitee::new(44);
    let id = issue_for(&fix, &invitee.did).await;
    let (_, first) = deliver(&fix, &id, "offer").await;
    let (_, second) = deliver(&fix, &id, "offer").await;
    let (old, new) = (code_of(&first["offer"]), code_of(&second["offer"]));
    assert_ne!(old, new);

    let (status, _) = post(
        &fix,
        "/v1/credential-exchange/request",
        REQUEST_TASK,
        None,
        invitee.request(&old),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = post(
        &fix,
        "/v1/credential-exchange/request",
        REQUEST_TASK,
        None,
        invitee.request(&new),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn deliver_refuses_what_it_cannot_deliver() {
    let fix = build().await;
    let invitee = Invitee::new(45);
    let id = issue_for(&fix, &invitee.did).await;

    // No route: this invitee's DID advertises no DIDComm service.
    let (status, v) = deliver(&fix, &id, "message").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(rest_error_code(&v), INVITATION_DELIVER_ERR_NO_ROUTE, "{v}");

    // Unknown.
    let (status, v) = deliver(
        &fix,
        "urn:uuid:00000000-0000-4000-8000-000000000000",
        "offer",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(rest_error_code(&v), INVITATION_DELIVER_ERR_NOT_FOUND, "{v}");

    // Not an inviter.
    let (status, _) = post(
        &fix,
        "/v1/invitations/deliver",
        DELIVER_TASK,
        Some(&fix.member_token),
        json!({ "id": id, "channel": "offer" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Revoked.
    let resp = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/invitations/{id}"))
                .header("authorization", format!("Bearer {}", fix.admin_token))
                .header("trust-task", REVOKE_TASK)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (status, v) = deliver(&fix, &id, "offer").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(rest_error_code(&v), INVITATION_DELIVER_ERR_REVOKED, "{v}");
}
