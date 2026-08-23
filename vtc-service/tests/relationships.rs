//! Integration coverage for `/v1/relationships*` (Phase 4
//! M4.6).
//!
//! The publish happy path needs a live DID resolver to verify
//! the VRC's data-integrity proof — same constraint as M3.10
//! recognise + M4.3 personhood assert. Integration tests here
//! cover:
//! - publish: caller != issuer → 403
//! - publish: missing resolver → 500
//! - revoke: issuer revokes own row (with hand-seeded state)
//! - revoke: subject (non-issuer) → 403
//! - revoke: admin revokes any row
//! - revoke: 404 on unknown id
//! - list: pagination + §12.3 strip on Purge-removed party

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::audit::{AuditEnvelope, AuditEvent};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

use vtc_service::acl::{VtcAclEntry, VtcRole, delete_acl_entry, store_acl_entry};
use vtc_service::members::{Member, delete_member, store_member};
use vtc_service::relationships::{Relationship, store_relationship};
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const PUBLIC_URL: &str = "https://vtc.example.com";
const PUBLISH_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/publish/0.1";
const LIST_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/list/0.1";
const GRAPH_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/graph/0.1";
const REVOKE_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/revoke/0.1";
const ISSUER_DID: &str = "did:key:zVrcIssuer";
const SUBJECT_DID: &str = "did:key:zVrcSubject";
const STRANGER_DID: &str = "did:key:zStranger";
const ADMIN_DID: &str = "did:key:zVrcAdmin";

struct Fixture {
    router: axum::Router,
    issuer_token: String,
    subject_token: String,
    admin_token: String,
    relationships_ks: vti_common::store::KeyspaceHandle,
    relationships_by_did_ks: vti_common::store::KeyspaceHandle,
    acl_ks: vti_common::store::KeyspaceHandle,
    members_ks: vti_common::store::KeyspaceHandle,
    audit_ks: vti_common::store::KeyspaceHandle,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url(PUBLIC_URL)
        .build()
        .await;

    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .expect("install default policies");

    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    // Seed ACL + Member rows for issuer, subject, admin.
    let now = now_epoch();
    for (did, role) in [
        (ISSUER_DID, VtcRole::Member),
        (SUBJECT_DID, VtcRole::Member),
        (ADMIN_DID, VtcRole::Admin),
    ] {
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

    let issuer_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        ISSUER_DID,
        "reader",
        now,
    )
    .await;
    let subject_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        SUBJECT_DID,
        "reader",
        now,
    )
    .await;
    let admin_token = mint(
        &vtc.state.sessions_ks,
        &vtc.jwt_keys,
        ADMIN_DID,
        "admin",
        now,
    )
    .await;

    let relationships_ks = vtc.state.relationships_ks.clone();
    let relationships_by_did_ks = vtc.state.relationships_by_did_ks.clone();
    let acl_ks = vtc.state.acl_ks.clone();
    let members_ks = vtc.state.members_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        issuer_token,
        subject_token,
        admin_token,
        relationships_ks,
        relationships_by_did_ks,
        acl_ks,
        members_ks,
        audit_ks,
        _vtc: vtc,
    }
}

fn fake_vrc(issuer: &str, subject: &str) -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://firstperson.network/credentials/dtg/v1"
        ],
        "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
        "issuer": issuer,
        "credentialSubject": {
            "id": subject,
            "endorsement": { "type": "endorses" }
        },
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("{issuer}#key-0"),
            "proofValue": "z00"
        }
    })
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

// ─── Publish ─────────────────────────────────────────────

#[tokio::test]
async fn publish_rejects_caller_not_issuer() {
    let fix = build_fixture().await;
    // Subject member tries to publish a VRC issued by someone else.
    let vrc = fake_vrc(ISSUER_DID, SUBJECT_DID);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/relationships")
        .header("authorization", format!("Bearer {}", fix.subject_token))
        .header("trust-task", PUBLISH_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "vrc": vrc }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn publish_returns_500_when_resolver_unconfigured() {
    let fix = build_fixture().await;
    let vrc = fake_vrc(ISSUER_DID, SUBJECT_DID);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/relationships")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", PUBLISH_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "vrc": vrc }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // Caller passes the issuer == VC.issuer gate; resolver
    // path is next + the fixture has did_resolver: None.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn publish_rejects_malformed_vrc() {
    let fix = build_fixture().await;
    // No `issuer` field → 400 (Validation).
    let vrc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "credentialSubject": { "id": SUBJECT_DID }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/relationships")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", PUBLISH_TASK)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "vrc": vrc }).to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Revoke ──────────────────────────────────────────────

async fn seed_relationship(fix: &Fixture, issuer: &str, subject: &str) -> Uuid {
    let id = Uuid::new_v4();
    let rel = Relationship {
        id,
        issuer_did: issuer.into(),
        subject_did: subject.into(),
        vrc_jsonld: fake_vrc(issuer, subject),
        vrc_sha256: format!("seed-{id}"),
        created_at: chrono::Utc::now(),
        persona: None,
    };
    store_relationship(&fix.relationships_ks, &fix.relationships_by_did_ks, &rel)
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn revoke_issuer_can_retract_own() {
    let fix = build_fixture().await;
    let id = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Row gone.
    let got = vtc_service::relationships::get_relationship(&fix.relationships_ks, id)
        .await
        .unwrap();
    assert!(got.is_none());

    // Audit envelope carries revoked_by: "issuer".
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::VrcRevoked(d) = env.event
            && d.revoked_by == "issuer"
        {
            saw = true;
        }
    }
    assert!(saw, "issuer revoke must emit revoked_by=issuer");
}

#[tokio::test]
async fn revoke_subject_is_forbidden() {
    let fix = build_fixture().await;
    let id = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.subject_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_admin_can_revoke_any() {
    let fix = build_fixture().await;
    let id = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Audit reason = "admin".
    let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
    let mut saw_admin = false;
    for (_k, raw) in pairs {
        let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
        if let AuditEvent::VrcRevoked(d) = env.event
            && d.revoked_by == "admin"
        {
            saw_admin = true;
        }
    }
    assert!(saw_admin);
}

#[tokio::test]
async fn revoke_404_on_unknown() {
    let fix = build_fixture().await;
    let id = Uuid::new_v4();
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/relationships/{id}"))
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", REVOKE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── List ────────────────────────────────────────────────

#[tokio::test]
async fn list_returns_issued_and_received_edges() {
    let fix = build_fixture().await;
    let r1 = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let r2 = seed_relationship(&fix, SUBJECT_DID, ISSUER_DID).await; // reverse
    // Stranger row that shouldn't appear for the issuer's list.
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: STRANGER_DID.into(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();
    store_member(&fix.members_ks, &Member::fresh(STRANGER_DID))
        .await
        .unwrap();
    let _r3 = seed_relationship(&fix, STRANGER_DID, SUBJECT_DID).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/members/{ISSUER_DID}/relationships"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let items = v["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2, "issuer's list = own issued + received");
    let ids: Vec<_> = items
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&r1.to_string()));
    assert!(ids.contains(&r2.to_string()));
}

#[tokio::test]
async fn list_strips_rows_where_other_party_purged() {
    let fix = build_fixture().await;
    let _r = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;

    // Purge SUBJECT: delete ACL row + Member row.
    delete_acl_entry(&fix.acl_ks, SUBJECT_DID).await.unwrap();
    delete_member(&fix.members_ks, SUBJECT_DID).await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/members/{ISSUER_DID}/relationships"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert!(
        items.is_empty(),
        "Purge-removed subject must strip the edge: {v}"
    );
}

#[tokio::test]
async fn list_keeps_rows_for_tombstoned_other_party() {
    let fix = build_fixture().await;
    let _r = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;

    // Tombstone SUBJECT: stamp removed_at on the Member row.
    let mut m = vtc_service::members::get_member(&fix.members_ks, SUBJECT_DID)
        .await
        .unwrap()
        .unwrap();
    m.tombstone();
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/members/{ISSUER_DID}/relationships"))
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", LIST_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        1,
        "Tombstoned subject keeps the edge visible: {v}"
    );
}

// ─── Connections graph (admin) ────────────────────────────
//
// A DTG edge is two VRCs, one in each direction, so the graph groups by
// unordered pair and reports whether both halves arrived. It used to return one
// entry per stored VRC, which made a mutual relationship and an unanswered
// claim indistinguishable to the operator reading it (#1054).

#[tokio::test]
async fn graph_separates_complete_edges_from_half_edges() {
    let fix = build_fixture().await;
    // ISSUER ↔ SUBJECT — reciprocated, so a complete edge.
    let a_to_b = seed_relationship(&fix, ISSUER_DID, SUBJECT_DID).await;
    let b_to_a = seed_relationship(&fix, SUBJECT_DID, ISSUER_DID).await;
    // ISSUER → STRANGER — never answered, so a half-edge.
    let a_to_c = seed_relationship(&fix, ISSUER_DID, STRANGER_DID).await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/relationships/graph")
        .header("authorization", format!("Bearer {}", fix.admin_token))
        .header("trust-task", GRAPH_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    let nodes: Vec<&str> = v["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .map(|n| n["did"].as_str().unwrap())
        .collect();
    assert_eq!(nodes.len(), 3, "three endpoints appear: {v}");

    let edges = v["edges"].as_array().expect("edges array");
    assert_eq!(edges.len(), 2, "three VRCs, two pairs: {v}");

    let complete: Vec<_> = edges
        .iter()
        .filter(|e| e["complete"].as_bool().unwrap())
        .collect();
    assert_eq!(complete.len(), 1, "exactly one pair reciprocated: {v}");
    let ids: Vec<&str> = complete[0]["halves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&a_to_b.to_string().as_str()));
    assert!(ids.contains(&b_to_a.to_string().as_str()));

    let half: Vec<_> = edges
        .iter()
        .filter(|e| !e["complete"].as_bool().unwrap())
        .collect();
    assert_eq!(half.len(), 1);
    assert_eq!(half[0]["halves"].as_array().unwrap().len(), 1);
    assert_eq!(
        half[0]["halves"][0]["id"].as_str().unwrap(),
        a_to_c.to_string(),
        "the unanswered claim is the half-edge: {v}"
    );
    // Wire shape is camelCase and the pair is DID-sorted, not publish-ordered.
    let endpoints = half[0]["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    assert!(endpoints[0].as_str().unwrap() <= endpoints[1].as_str().unwrap());
}

#[tokio::test]
async fn graph_is_admin_only() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/relationships/graph")
        .header("authorization", format!("Bearer {}", fix.issuer_token))
        .header("trust-task", GRAPH_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── Publish under a pairwise relationship DID ────────────
//
// The credential's `issuer` is a relationship DID that belongs
// to no member. Membership comes from the session; control of
// the issuing key comes from a publish authorization bound to
// this request. See
// `docs/05-design-notes/vrc-publish-proof-of-possession.md`.

mod pairwise {
    use super::*;
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
    use ed25519_dalek::SigningKey;
    use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

    /// Seeds: `MEMBER` joins the community; `RDID` is the pairwise
    /// identifier they issue the VRC under; `OTHER` is an unrelated key
    /// used to forge authorizations.
    const MEMBER: u8 = 0x41;
    const RDID: u8 = 0x42;
    const PEER_RDID: u8 = 0x43;
    const OTHER: u8 = 0x44;

    fn did_for(seed: u8) -> String {
        affinidi_crypto::did_key::ed25519_pub_to_did_key(
            &SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn secret_for(seed: u8) -> affinidi_secrets_resolver::secrets::Secret {
        let did = did_for(seed);
        let vm = format!("{did}#{}", did.strip_prefix("did:key:").unwrap());
        affinidi_secrets_resolver::secrets::Secret::generate_ed25519(Some(&vm), Some(&[seed; 32]))
    }

    /// Attach an `eddsa-jcs-2022` data-integrity proof signed by `seed`.
    async fn sign(seed: u8, mut doc: Value) -> Value {
        let proof = DataIntegrityProof::sign(
            &doc,
            &secret_for(seed),
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .unwrap();
        doc["proof"] = serde_json::to_value(&proof).unwrap();
        doc
    }

    async fn vrc(issuer_seed: u8, subject_seed: u8) -> Value {
        sign(
            issuer_seed,
            json!({
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://firstperson.network/credentials/dtg/v1"
                ],
                "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
                "issuer": did_for(issuer_seed),
                "validFrom": "2020-01-01T00:00:00Z",
                "credentialSubject": {
                    "id": did_for(subject_seed),
                    "endorsement": { "type": "endorses" }
                },
            }),
        )
        .await
    }

    struct Pw {
        router: axum::Router,
        token: String,
        session_id: String,
        relationships_ks: vti_common::store::KeyspaceHandle,
        audit_ks: vti_common::store::KeyspaceHandle,
        _vtc: TestVtc,
    }

    /// A live `did:key` resolver (purely computational — no network) plus one
    /// current member whose session we publish under.
    async fn fixture() -> Pw {
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .with_did_resolver(true)
            .build()
            .await;

        vtc_service::policy::default::install_defaults(
            &vtc.state.policies_ks,
            &vtc.state.active_policies_ks,
        )
        .await
        .unwrap();

        let now = now_epoch();
        let member = did_for(MEMBER);
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: member.clone(),
                role: VtcRole::Member,
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
        store_member(&vtc.state.members_ks, &Member::fresh(&member))
            .await
            .unwrap();

        let session_id = format!("sess-{}", Uuid::new_v4());
        store_session(
            &vtc.state.sessions_ks,
            &Session {
                session_id: session_id.clone(),
                did: member.clone(),
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
        let claims = vtc.jwt_keys.new_claims(
            member,
            session_id.clone(),
            "reader".into(),
            vec![],
            3600,
            true,
        );
        let token = vtc.jwt_keys.encode(&claims).unwrap();

        Pw {
            router: vtc.router.clone(),
            token,
            session_id,
            relationships_ks: vtc.state.relationships_ks.clone(),
            audit_ks: vtc.state.audit_ks.clone(),
            _vtc: vtc,
        }
    }

    fn sha256_hex(v: &Value) -> String {
        use sha2::{Digest, Sha256};
        // Mirrors the handler's `canonicalise`: recursive key sort.
        fn sorted(v: Value) -> Value {
            match v {
                Value::Object(m) => serde_json::to_value(
                    m.into_iter()
                        .map(|(k, val)| (k, sorted(val)))
                        .collect::<std::collections::BTreeMap<_, _>>(),
                )
                .unwrap(),
                Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
                other => other,
            }
        }
        hex::encode(Sha256::digest(sorted(v.clone()).to_string().as_bytes()))
    }

    /// Publish a pairwise edge `issuer_seed -> subject_seed`, return its id.
    /// Shared by the `persona` and `revocation` suites below, both of which
    /// need an already-published pairwise edge to act on.
    async fn publish_edge(fix: &Pw, issuer_seed: u8, subject_seed: u8) -> Uuid {
        let v = vrc(issuer_seed, subject_seed).await;
        let pop = sign(
            issuer_seed,
            authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        let (status, body) = body_value(post(fix, &v, Some(pop)).await).await;
        assert_eq!(status, StatusCode::CREATED, "seed publish failed: {body}");
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
    }

    /// A well-formed publish authorization, before signing.
    fn authorization(vrc_hash: &str, aud: &str, session_id: &str) -> Value {
        json!({
            "type": "VrcPublishAuthorization",
            "vrc": vrc_hash,
            "aud": aud,
            "sessionId": session_id,
            "issuedAt": chrono::Utc::now().to_rfc3339(),
        })
    }

    async fn post(fix: &Pw, vrc: &Value, pop: Option<Value>) -> axum::response::Response {
        let mut body = json!({ "vrc": vrc });
        if let Some(p) = pop {
            body["pop"] = p;
        }
        let req = Request::builder()
            .method("POST")
            .uri("/v1/relationships")
            .header("authorization", format!("Bearer {}", fix.token))
            .header("trust-task", PUBLISH_TASK)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        fix.router.clone().oneshot(req).await.unwrap()
    }

    /// The happy path #1054 exists to enable: the published row names only
    /// pairwise identifiers, and the member's own DID appears nowhere in it.
    #[tokio::test]
    async fn publishes_under_a_relationship_did() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let pop = sign(
            RDID,
            authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id),
        )
        .await;

        let (status, body) = body_value(post(&fix, &v, Some(pop)).await).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["issuerDid"], did_for(RDID));
        assert_eq!(body["subjectDid"], did_for(PEER_RDID));

        // The stored row must carry no trace of the publishing member.
        let rows = vtc_service::relationships::list_all(&fix.relationships_ks)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let stored = serde_json::to_string(&rows[0].vrc_jsonld).unwrap();
        assert_eq!(rows[0].issuer_did, did_for(RDID));
        assert!(
            !stored.contains(&did_for(MEMBER)),
            "membership DID leaked into the stored VRC"
        );
        assert!(
            !stored.contains(&fix.session_id),
            "session id leaked into the stored VRC — this is the linkage the \
             pairwise identifier exists to remove"
        );
    }

    /// The authorization is verified and dropped. If it ever reaches the audit
    /// store, the membership-DID-to-relationship-DID linkage becomes durable
    /// and the privacy property is lost — silently.
    #[tokio::test]
    async fn authorization_is_never_persisted_to_the_audit_trail() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let pop = sign(
            RDID,
            authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        assert_eq!(
            post(&fix, &v, Some(pop)).await.status(),
            StatusCode::CREATED
        );

        let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
        let mut saw_publish = false;
        for (_k, raw) in pairs {
            let blob = String::from_utf8_lossy(&raw);
            assert!(
                !blob.contains(&fix.session_id),
                "session id reached the audit store"
            );
            let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
            if matches!(env.event, AuditEvent::VrcPublished(_)) {
                saw_publish = true;
            }
        }
        assert!(saw_publish, "expected a VrcPublished audit entry");
    }

    /// Option B on #1061: the audit trail attributes a publication to the
    /// **member**, not to the relationship DID that issued the credential.
    ///
    /// Recording the issuing R-DID as the actor would leave the trail unable
    /// to answer "which member published this edge" for anyone, at any access
    /// level. The linkage is confined to the audit store — HMAC'd actor,
    /// RTBF-nullable plaintext, admin-gated — and deliberately kept out of the
    /// credential, the stored row, and the logs.
    #[tokio::test]
    async fn audit_attributes_the_publication_to_the_member_not_the_relationship_did() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let pop = sign(
            RDID,
            authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        assert_eq!(
            post(&fix, &v, Some(pop)).await.status(),
            StatusCode::CREATED
        );

        let pairs = fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap();
        let mut saw = false;
        for (_k, raw) in pairs {
            let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
            if matches!(env.event, AuditEvent::VrcPublished(_)) {
                saw = true;
                assert_eq!(
                    env.actor_did_plain.as_deref(),
                    Some(did_for(MEMBER).as_str()),
                    "the actor must be the authenticated member"
                );
                assert_ne!(
                    env.actor_did_plain.as_deref(),
                    Some(did_for(RDID).as_str()),
                    "the relationship DID names nobody and must not be the actor"
                );
            }
        }
        assert!(saw, "expected a VrcPublished audit entry");
    }

    /// Membership is not a precondition for a VRC — DTG Credentials
    /// §Community-Anchored ZKP. The subject's consent is their own reciprocal
    /// VRC, not our roster.
    #[tokio::test]
    async fn subject_need_not_be_a_member() {
        let fix = fixture().await;
        let v = vrc(RDID, OTHER).await;
        let pop = sign(
            RDID,
            authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        let (status, body) = body_value(post(&fix, &v, Some(pop)).await).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
    }

    #[tokio::test]
    async fn same_vrc_twice_is_idempotent() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let mk = || async {
            sign(
                RDID,
                authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id),
            )
            .await
        };
        let (s1, b1) = body_value(post(&fix, &v, Some(mk().await)).await).await;
        let (s2, b2) = body_value(post(&fix, &v, Some(mk().await)).await).await;
        assert_eq!(s1, StatusCode::CREATED);
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(b1["id"], b2["id"]);
    }

    // ─── Every field of the authorization is load-bearing ───

    #[tokio::test]
    async fn rejects_missing_authorization() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        assert_eq!(post(&fix, &v, None).await.status(), StatusCode::FORBIDDEN);
    }

    /// Holding the credential is not controlling the key behind it. This is
    /// the property the old `auth.did == issuer` pin provided.
    #[tokio::test]
    async fn rejects_authorization_signed_by_another_key() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let mut pop = authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id);
        // Signed by OTHER, but claiming to authorize RDID's credential.
        pop = sign(OTHER, pop).await;
        assert_eq!(
            post(&fix, &v, Some(pop)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn rejects_authorization_bound_to_a_different_vrc() {
        let fix = fixture().await;
        let target = vrc(RDID, PEER_RDID).await;
        let decoy = vrc(RDID, OTHER).await;
        let pop = sign(
            RDID,
            authorization(&sha256_hex(&decoy), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        assert_eq!(
            post(&fix, &target, Some(pop)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn rejects_authorization_from_another_session() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let pop = sign(
            RDID,
            authorization(&sha256_hex(&v), TEST_VTC_DID, "sess-someone-else"),
        )
        .await;
        assert_eq!(
            post(&fix, &v, Some(pop)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn rejects_authorization_for_another_community() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let pop = sign(
            RDID,
            authorization(
                &sha256_hex(&v),
                "did:webvh:other-vtc.example:xyz",
                &fix.session_id,
            ),
        )
        .await;
        assert_eq!(
            post(&fix, &v, Some(pop)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn rejects_stale_authorization() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let mut a = authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id);
        a["issuedAt"] = json!((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
        let pop = sign(RDID, a).await;
        assert_eq!(
            post(&fix, &v, Some(pop)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    // ─── A relationship DID must be unique per counterparty ───

    /// DTG Credentials: "each entity MUST generate a new, unique R-DID for
    /// every single entity they connect with, even within the same community."
    ///
    /// This is type integrity rather than a privacy policy. A verifier reading
    /// a pairwise edge is entitled to conclude the identifier says nothing
    /// beyond that one relationship; a reused R-DID breaks that inference for
    /// every reader of the graph.
    #[tokio::test]
    async fn rejects_a_relationship_did_reused_with_a_second_counterparty() {
        let fix = fixture().await;

        let first = vrc(RDID, PEER_RDID).await;
        let pop = sign(
            RDID,
            authorization(&sha256_hex(&first), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        assert_eq!(
            post(&fix, &first, Some(pop)).await.status(),
            StatusCode::CREATED
        );

        // Same relationship DID, different counterparty.
        let second = vrc(RDID, OTHER).await;
        let pop2 = sign(
            RDID,
            authorization(&sha256_hex(&second), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        let (status, body) = body_value(post(&fix, &second, Some(pop2)).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    /// Uniqueness is per counterparty, not per credential — re-issuing to the
    /// *same* counterparty (a renewal, a corrected claim) is not reuse.
    #[tokio::test]
    async fn allows_reissuing_to_the_same_counterparty() {
        let fix = fixture().await;

        let first = vrc(RDID, PEER_RDID).await;
        let pop = sign(
            RDID,
            authorization(&sha256_hex(&first), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        assert_eq!(
            post(&fix, &first, Some(pop)).await.status(),
            StatusCode::CREATED
        );

        // Same parties, different credential body — a distinct VRC, so the
        // idempotency hash differs and this is a genuine second publish.
        let mut body = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://firstperson.network/credentials/dtg/v1"
            ],
            "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
            "issuer": did_for(RDID),
            "validFrom": "2021-06-01T00:00:00Z",
            "credentialSubject": { "id": did_for(PEER_RDID) },
        });
        body["validUntil"] = json!("2999-01-01T00:00:00Z");
        let second = sign(RDID, body).await;
        let pop2 = sign(
            RDID,
            authorization(&sha256_hex(&second), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        let (status, b) = body_value(post(&fix, &second, Some(pop2)).await).await;
        assert_eq!(status, StatusCode::CREATED, "body: {b}");
    }

    /// The public-community case. In an open-source community everyone is
    /// known, and a member may reasonably want one identifier across every
    /// relationship. DTG Credentials supports that — as the *attributed*
    /// form, under the membership DID — and the uniqueness rule does not
    /// apply to it, because an M-DID is not claiming to be pairwise.
    ///
    /// The member is not forced to choose between being recognised and being
    /// conformant; they choose the form that means what they intend.
    #[tokio::test]
    async fn attributed_edges_may_share_one_identifier_across_counterparties() {
        let fix = fixture().await;
        let member = did_for(MEMBER);

        for peer in [PEER_RDID, OTHER] {
            // Issued under the member's own DID, so no authorization object —
            // the session already proves control of it.
            let v = sign(
                MEMBER,
                json!({
                    "@context": [
                        "https://www.w3.org/ns/credentials/v2",
                        "https://firstperson.network/credentials/dtg/v1"
                    ],
                    "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
                    "issuer": member,
                    "validFrom": "2020-01-01T00:00:00Z",
                    "credentialSubject": { "id": did_for(peer) },
                }),
            )
            .await;
            let (status, b) = body_value(post(&fix, &v, None).await).await;
            // The default policy's attributed rule needs both parties to be
            // members; only the issuer is, so this is the policy's call, not
            // the uniqueness rule's. What matters is that it is never the
            // "relationship DID already has an edge" rejection.
            assert!(
                status != StatusCode::BAD_REQUEST
                    || !b.to_string().contains("must be unique to one counterparty"),
                "attributed edges must not be subject to R-DID uniqueness: {b}"
            );
        }
    }

    // ─── Only a conformant VRC becomes a graph edge ───

    /// Build an otherwise-valid, correctly-signed credential whose shape has
    /// been altered, and assert it cannot enter the trust graph.
    async fn assert_shape_rejected(mutate: impl Fn(&mut Value)) {
        let fix = fixture().await;
        let mut body = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://firstperson.network/credentials/dtg/v1"
            ],
            "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
            "issuer": did_for(RDID),
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": { "id": did_for(PEER_RDID) },
        });
        mutate(&mut body);
        let v = sign(RDID, body).await;
        let pop = sign(
            RDID,
            authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id),
        )
        .await;
        let (status, b) = body_value(post(&fix, &v, Some(pop)).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {b}");
    }

    #[tokio::test]
    async fn rejects_vrc_missing_the_dtg_context() {
        assert_shape_rejected(|v| {
            v["@context"] = json!(["https://www.w3.org/ns/credentials/v2"]);
        })
        .await;
    }

    #[tokio::test]
    async fn rejects_vrc_missing_the_dtg_base_type() {
        assert_shape_rejected(|v| {
            v["type"] = json!(["VerifiableCredential", "RelationshipCredential"]);
        })
        .await;
    }

    /// The relationships endpoint publishes relationship edges. A membership
    /// credential is a different edge with different issuance rules.
    #[tokio::test]
    async fn rejects_a_credential_of_another_dtg_subtype() {
        assert_shape_rejected(|v| {
            v["type"] = json!([
                "VerifiableCredential",
                "DTGCredential",
                "MembershipCredential"
            ]);
        })
        .await;
    }

    /// Regression guard. `VerifiableRecognitionCredential` was never a DTG
    /// credential type — there is no such thing as a recognition credential,
    /// only a relationship credential. It survived in this repo's fixtures and
    /// docs precisely because the publish path never inspected `type`.
    #[tokio::test]
    async fn rejects_the_invented_recognition_credential_type() {
        assert_shape_rejected(|v| {
            v["type"] = json!([
                "VerifiableCredential",
                "DTGCredential",
                "VerifiableRecognitionCredential"
            ]);
        })
        .await;
    }

    /// A signature the member legitimately made over some *other* object must
    /// not be replayable here as authorization to publish.
    #[tokio::test]
    async fn rejects_authorization_of_the_wrong_type() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let mut a = authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id);
        a["type"] = json!("SomeOtherSignedThing");
        let pop = sign(RDID, a).await;
        assert_eq!(
            post(&fix, &v, Some(pop)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    // ─── Persona annotation (VPC) — #1067 ─────────────────
    //
    // These live inside `pairwise` because that is where they
    // matter. On an attributed edge the member is already
    // correlatable and a persona changes nothing; on pairwise
    // edges the VPC is the only thing that lets a member be
    // recognised across relationships without surrendering
    // their membership DID.

    mod persona {
        use super::*;

        const PERSONA: u8 = 0x45;
        const RDID2: u8 = 0x46;
        const PEER2_RDID: u8 = 0x47;
        const GRAPH_ADMIN: u8 = 0x7A;

        const PERSONA_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/persona/0.1";
        const GRAPH_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/graph/0.1";

        /// A signed VPC: issued under `persona_seed`'s P-DID, naming
        /// `counterparty_seed` as the subject. DTG Credentials §VPC.
        async fn vpc(persona_seed: u8, counterparty_seed: u8) -> Value {
            sign(
                persona_seed,
                json!({
                    "@context": [
                        "https://www.w3.org/ns/credentials/v2",
                        "https://firstperson.network/credentials/dtg/v1"
                    ],
                    "type": ["VerifiableCredential", "DTGCredential", "PersonaCredential"],
                    "issuer": did_for(persona_seed),
                    "validFrom": "2020-01-01T00:00:00Z",
                    "credentialSubject": { "id": did_for(counterparty_seed) },
                }),
            )
            .await
        }

        fn attach_authorization(vpc_hash: &str, edge: Uuid, session_id: &str) -> Value {
            json!({
                "type": "VpcAttachAuthorization",
                "vpc": vpc_hash,
                "relationship": edge.to_string(),
                "aud": TEST_VTC_DID,
                "sessionId": session_id,
                "issuedAt": chrono::Utc::now().to_rfc3339(),
            })
        }

        fn detach_authorization(edge: Uuid, session_id: &str) -> Value {
            json!({
                "type": "VpcDetachAuthorization",
                "relationship": edge.to_string(),
                "aud": TEST_VTC_DID,
                "sessionId": session_id,
                "issuedAt": chrono::Utc::now().to_rfc3339(),
            })
        }

        async fn attach(
            fix: &Pw,
            edge: Uuid,
            vpc: &Value,
            pop: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut body = json!({ "vpc": vpc });
            if let Some(p) = pop {
                body["pop"] = p;
            }
            persona_request(fix, "POST", edge, body).await
        }

        async fn detach(fix: &Pw, edge: Uuid, pop: Option<Value>) -> (StatusCode, Value) {
            let mut body = json!({});
            if let Some(p) = pop {
                body["pop"] = p;
            }
            persona_request(fix, "DELETE", edge, body).await
        }

        async fn persona_request(
            fix: &Pw,
            method: &str,
            edge: Uuid,
            body: Value,
        ) -> (StatusCode, Value) {
            let req = Request::builder()
                .method(method)
                .uri(format!("/v1/relationships/{edge}/persona"))
                .header("authorization", format!("Bearer {}", fix.token))
                .header("trust-task", PERSONA_TASK)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            body_value(fix.router.clone().oneshot(req).await.unwrap()).await
        }

        /// The attach happy path in one call, for tests whose subject is what
        /// happens *after* a successful attach. The authorization is signed by
        /// `RDID`, so this is only for edges that `RDID` issued.
        async fn attach_ok(fix: &Pw, edge: Uuid, persona_seed: u8, counterparty_seed: u8) {
            let v = vpc(persona_seed, counterparty_seed).await;
            let pop = sign(
                RDID,
                attach_authorization(&sha256_hex(&v), edge, &fix.session_id),
            )
            .await;
            let (status, body) = attach(fix, edge, &v, Some(pop)).await;
            assert_eq!(status, StatusCode::OK, "body: {body}");
        }

        /// The admin connections graph is where the correlation a persona
        /// enables actually becomes visible, so the assertions that matter
        /// read it rather than the storage layer. Seeds its own admin because
        /// the `pairwise` fixture only has the one member session.
        async fn graph_edges(fix: &Pw) -> Vec<Value> {
            let now = now_epoch();
            let admin = did_for(GRAPH_ADMIN);
            store_acl_entry(
                &fix._vtc.state.acl_ks,
                &VtcAclEntry {
                    did: admin.clone(),
                    role: VtcRole::Admin,
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
            store_member(&fix._vtc.state.members_ks, &Member::fresh(&admin))
                .await
                .unwrap();
            let session_id = format!("sess-{}", Uuid::new_v4());
            store_session(
                &fix._vtc.state.sessions_ks,
                &Session {
                    session_id: session_id.clone(),
                    did: admin.clone(),
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
            let claims =
                fix._vtc
                    .jwt_keys
                    .new_claims(admin, session_id, "admin".into(), vec![], 3600, true);
            let token = fix._vtc.jwt_keys.encode(&claims).unwrap();

            let req = Request::builder()
                .method("GET")
                .uri("/v1/relationships/graph")
                .header("authorization", format!("Bearer {token}"))
                .header("trust-task", GRAPH_TASK)
                .body(Body::empty())
                .unwrap();
            let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
            assert_eq!(status, StatusCode::OK, "graph: {body}");
            body["edges"].as_array().cloned().unwrap_or_default()
        }

        /// The property #1067 exists to restore: a member can be recognised
        /// across relationships under a name they chose, while every edge
        /// still names only pairwise identifiers.
        #[tokio::test]
        async fn attaches_a_persona_to_a_pairwise_edge() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            attach_ok(&fix, edge, PERSONA, PEER_RDID).await;

            let edges = graph_edges(&fix).await;
            assert_eq!(edges.len(), 1);
            assert_eq!(edges[0]["personaDid"], did_for(PERSONA));
            assert_eq!(edges[0]["issuerDid"], did_for(RDID));

            // The annotation must not smuggle the member back in.
            let rows = vtc_service::relationships::list_all(&fix.relationships_ks)
                .await
                .unwrap();
            let stored = serde_json::to_string(&rows[0]).unwrap();
            assert!(
                !stored.contains(&did_for(MEMBER)),
                "membership DID leaked into the annotated row"
            );
            assert!(
                !stored.contains(&fix.session_id),
                "session id leaked into the annotated row"
            );
        }

        /// The whole point: two edges under two different relationship DIDs,
        /// correlatable because — and only because — the member said so.
        #[tokio::test]
        async fn the_same_persona_may_be_asserted_on_several_edges() {
            let fix = fixture().await;
            let e1 = publish_edge(&fix, RDID, PEER_RDID).await;
            let e2 = publish_edge(&fix, RDID2, PEER2_RDID).await;
            attach_ok(&fix, e1, PERSONA, PEER_RDID).await;

            // Second edge: same persona, different relationship DID, so the
            // authorization is signed by RDID2.
            let v = vpc(PERSONA, PEER2_RDID).await;
            let pop = sign(
                RDID2,
                attach_authorization(&sha256_hex(&v), e2, &fix.session_id),
            )
            .await;
            let (status, body) = attach(&fix, e2, &v, Some(pop)).await;
            assert_eq!(status, StatusCode::OK, "body: {body}");

            let edges = graph_edges(&fix).await;
            assert_eq!(edges.len(), 2);
            for e in &edges {
                assert_eq!(e["personaDid"], did_for(PERSONA));
            }
            // A P-DID recurring is the feature. An R-DID recurring is not:
            // the two edges must still carry distinct issuers.
            let issuers: std::collections::BTreeSet<_> = edges
                .iter()
                .map(|e| e["issuerDid"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(issuers.len(), 2);
        }

        /// Anyone who was ever handed a VPC could otherwise staple it to
        /// someone else's edge. Control of the edge's issuing key is the gate.
        #[tokio::test]
        async fn rejects_an_authorization_signed_by_another_key() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let v = vpc(PERSONA, PEER_RDID).await;
            let pop = sign(
                OTHER,
                attach_authorization(&sha256_hex(&v), edge, &fix.session_id),
            )
            .await;
            let (status, body) = attach(&fix, edge, &v, Some(pop)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
        }

        /// A pairwise edge's issuer is never the session DID, so omitting the
        /// authorization is never valid there.
        #[tokio::test]
        async fn rejects_an_attach_with_no_authorization_on_a_pairwise_edge() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let v = vpc(PERSONA, PEER_RDID).await;
            let (status, body) = attach(&fix, edge, &v, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
        }

        /// An authorization for one edge must not annotate another. Without
        /// the `relationship` binding a member could move a persona onto any
        /// edge they control.
        #[tokio::test]
        async fn rejects_an_authorization_bound_to_a_different_edge() {
            let fix = fixture().await;
            let e1 = publish_edge(&fix, RDID, PEER_RDID).await;
            let e2 = publish_edge(&fix, RDID2, PEER2_RDID).await;
            let v = vpc(PERSONA, PEER2_RDID).await;
            let pop = sign(
                RDID2,
                attach_authorization(&sha256_hex(&v), e1, &fix.session_id),
            )
            .await;
            let (status, body) = attach(&fix, e2, &v, Some(pop)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
        }

        /// This endpoint annotates; it does not publish. A VRC posted here is
        /// a caller error, not a second way to create an edge.
        #[tokio::test]
        async fn rejects_a_credential_that_is_not_a_vpc() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let not_a_vpc = vrc(PERSONA, PEER_RDID).await;
            let pop = sign(
                RDID,
                attach_authorization(&sha256_hex(&not_a_vpc), edge, &fix.session_id),
            )
            .await;
            let (status, body) = attach(&fix, edge, &not_a_vpc, Some(pop)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        }

        /// A persona is asserted *to* a counterparty. A VPC naming somebody
        /// else has nothing to say about this edge.
        #[tokio::test]
        async fn rejects_a_vpc_asserted_to_a_different_counterparty() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let v = vpc(PERSONA, OTHER).await;
            let pop = sign(
                RDID,
                attach_authorization(&sha256_hex(&v), edge, &fix.session_id),
            )
            .await;
            let (status, body) = attach(&fix, edge, &v, Some(pop)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        }

        /// Withdrawing a persona has to work, or the feature is a one-way
        /// disclosure. The edge itself survives.
        #[tokio::test]
        async fn detach_removes_the_persona_and_leaves_the_edge() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            attach_ok(&fix, edge, PERSONA, PEER_RDID).await;

            let pop = sign(RDID, detach_authorization(edge, &fix.session_id)).await;
            let (status, body) = detach(&fix, edge, Some(pop)).await;
            assert_eq!(status, StatusCode::OK, "body: {body}");
            assert!(body["personaDid"].is_null());

            let edges = graph_edges(&fix).await;
            assert_eq!(edges.len(), 1, "the edge must outlive its annotation");
            assert!(edges[0].get("personaDid").is_none());
        }

        /// The two authorization types are distinct so that one cannot stand
        /// in for the other — otherwise a captured attach authorization would
        /// let its holder strip the persona it was made to assert.
        #[tokio::test]
        async fn rejects_an_attach_authorization_replayed_as_a_detach() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let v = vpc(PERSONA, PEER_RDID).await;
            attach_ok(&fix, edge, PERSONA, PEER_RDID).await;

            let pop = sign(
                RDID,
                attach_authorization(&sha256_hex(&v), edge, &fix.session_id),
            )
            .await;
            let (status, body) = detach(&fix, edge, Some(pop)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
        }

        /// Both verbs leave a trail, and neither leaves the session id in it.
        #[tokio::test]
        async fn attach_and_detach_are_audited_without_the_session_id() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            attach_ok(&fix, edge, PERSONA, PEER_RDID).await;
            let pop = sign(RDID, detach_authorization(edge, &fix.session_id)).await;
            assert_eq!(detach(&fix, edge, Some(pop)).await.0, StatusCode::OK);

            let (mut saw_attach, mut saw_detach) = (false, false);
            for (_k, raw) in fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap() {
                assert!(
                    !String::from_utf8_lossy(&raw).contains(&fix.session_id),
                    "session id reached the audit store"
                );
                let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
                match env.event {
                    AuditEvent::VpcAttached(d) => {
                        assert_eq!(d.persona_did, did_for(PERSONA));
                        saw_attach = true;
                    }
                    AuditEvent::VpcDetached(d) => {
                        assert_eq!(d.persona_did, did_for(PERSONA));
                        saw_detach = true;
                    }
                    _ => {}
                }
            }
            assert!(saw_attach && saw_detach);
        }

        #[tokio::test]
        async fn unknown_edge_is_404() {
            let fix = fixture().await;
            let v = vpc(PERSONA, PEER_RDID).await;
            let missing = Uuid::new_v4();
            let pop = sign(
                RDID,
                attach_authorization(&sha256_hex(&v), missing, &fix.session_id),
            )
            .await;
            let (status, _) = attach(&fix, missing, &v, Some(pop)).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }

    // ─── Retracting a pairwise edge ───────────────────────
    //
    // `revoke` kept the identity equality the publish path
    // replaced — `auth.did == rel.issuer_did` — one function
    // below where it was fixed. For a pairwise edge that
    // compares a membership DID against a relationship DID and
    // is false by construction, so from #1061 until this suite
    // a member could publish an edge under a relationship DID
    // and then never take it back; only an admin could.
    //
    // `revoke_issuer_can_retract_own` (top of this file) seeds
    // the *attributed* form, where the equality still holds,
    // which is exactly why the regression shipped green.

    mod revocation {
        use super::*;

        /// A second relationship DID + counterparty, so a caller can hold two
        /// edges at once and try to retract one with the other's proof.
        const RDID_B: u8 = 0x48;
        const PEER_B_RDID: u8 = 0x49;
        /// A second community member, for the cross-session replay test.
        const OTHER_MEMBER: u8 = 0x4A;

        /// A well-formed revoke authorization, before signing. Bound to the
        /// row id, because that is what `DELETE /v1/relationships/{id}`
        /// names — there is no credential in the request to bind to.
        fn revoke_authorization(edge: Uuid, session_id: &str) -> Value {
            json!({
                "type": "VrcRevokeAuthorization",
                "relationship": edge.to_string(),
                "aud": TEST_VTC_DID,
                "sessionId": session_id,
                "issuedAt": chrono::Utc::now().to_rfc3339(),
            })
        }

        async fn delete_edge(fix: &Pw, edge: Uuid, pop: Option<Value>) -> (StatusCode, Value) {
            let mut req = Request::builder()
                .method("DELETE")
                .uri(format!("/v1/relationships/{edge}"))
                .header("authorization", format!("Bearer {}", fix.token))
                .header("trust-task", REVOKE_TASK);
            // No `pop` means no body and no content-type at all — the shape
            // every client sending this request today uses, and the shape the
            // optional extractor has to keep accepting.
            let body = match pop {
                Some(p) => {
                    req = req.header("content-type", "application/json");
                    Body::from(json!({ "pop": p }).to_string())
                }
                None => Body::empty(),
            };
            let resp = fix
                .router
                .clone()
                .oneshot(req.body(body).unwrap())
                .await
                .unwrap();
            body_value(resp).await
        }

        async fn edge_count(fix: &Pw) -> usize {
            vtc_service::relationships::list_all(&fix.relationships_ks)
                .await
                .unwrap()
                .len()
        }

        /// Seed a second current member with their own live session, and
        /// return their bearer token. Used to replay one member's
        /// authorization inside another member's session.
        async fn other_member_token(fix: &Pw) -> String {
            let now = now_epoch();
            let did = did_for(OTHER_MEMBER);
            store_acl_entry(
                &fix._vtc.state.acl_ks,
                &VtcAclEntry {
                    did: did.clone(),
                    role: VtcRole::Member,
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
            store_member(&fix._vtc.state.members_ks, &Member::fresh(&did))
                .await
                .unwrap();
            let session_id = format!("sess-{}", Uuid::new_v4());
            store_session(
                &fix._vtc.state.sessions_ks,
                &Session {
                    session_id: session_id.clone(),
                    did: did.clone(),
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
            let claims =
                fix._vtc
                    .jwt_keys
                    .new_claims(did, session_id, "reader".into(), vec![], 3600, true);
            fix._vtc.jwt_keys.encode(&claims).unwrap()
        }

        /// The regression. Fails against the pre-fix handler with 403: the
        /// session DID is the member's, the row's issuer is a relationship
        /// DID, and nothing in `revoke` could bridge them.
        #[tokio::test]
        async fn issuer_can_retract_a_pairwise_edge_with_an_authorization() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            assert_eq!(edge_count(&fix).await, 1);

            let pop = sign(RDID, revoke_authorization(edge, &fix.session_id)).await;
            let (status, body) = delete_edge(&fix, edge, Some(pop)).await;
            assert_eq!(status, StatusCode::OK, "body: {body}");
            assert_eq!(edge_count(&fix).await, 0, "the row must actually be gone");
        }

        /// Without proof of control the answer is still 403 — that part was
        /// never wrong. What was wrong was that there was no way to supply
        /// the proof.
        #[tokio::test]
        async fn a_pairwise_edge_still_needs_an_authorization() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let (status, body) = delete_edge(&fix, edge, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
            assert_eq!(edge_count(&fix).await, 1);
        }

        /// Holding a session is not holding the issuing key. Without this,
        /// any member could delete any pairwise edge in the community.
        #[tokio::test]
        async fn rejects_an_authorization_signed_by_another_key() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let pop = sign(OTHER, revoke_authorization(edge, &fix.session_id)).await;
            let (status, body) = delete_edge(&fix, edge, Some(pop)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
            assert_eq!(edge_count(&fix).await, 1);
        }

        /// An authorization naming one edge must not delete another, even
        /// when both were issued under keys the caller controls.
        #[tokio::test]
        async fn rejects_an_authorization_bound_to_a_different_edge() {
            let fix = fixture().await;
            let e1 = publish_edge(&fix, RDID, PEER_RDID).await;
            let e2 = publish_edge(&fix, RDID_B, PEER_B_RDID).await;
            let pop = sign(RDID_B, revoke_authorization(e1, &fix.session_id)).await;
            let (status, body) = delete_edge(&fix, e2, Some(pop)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
            assert_eq!(edge_count(&fix).await, 2);
        }

        /// The `type` guard on its own.
        ///
        /// Added because mutation testing showed it was untested: with the
        /// type comparison removed, every test here still passed. The replay
        /// test below was being caught by the *edge* binding — a publish
        /// authorization has no `relationship` field — so it never exercised
        /// `type` at all. This object is a valid revoke authorization in every
        /// respect except the one under test, so nothing else can catch it.
        #[tokio::test]
        async fn rejects_an_authorization_of_the_wrong_type() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let mut a = revoke_authorization(edge, &fix.session_id);
            a["type"] = json!("SomeOtherSignedThing");
            let pop = sign(RDID, a).await;
            let (status, body) = delete_edge(&fix, edge, Some(pop)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
            assert_eq!(edge_count(&fix).await, 1);
        }

        /// The `type` guard as a member would actually meet it. A member signs
        /// a publish authorization every time they lodge an edge; replaying
        /// one here must not delete it. (Belt and braces with the test above:
        /// this one is currently caught by the missing `relationship` field,
        /// which is a second reason it fails and a fine one.)
        #[tokio::test]
        async fn rejects_a_publish_authorization_replayed_as_a_revoke() {
            let fix = fixture().await;
            let v = vrc(RDID, PEER_RDID).await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let stolen = sign(
                RDID,
                authorization(&sha256_hex(&v), TEST_VTC_DID, &fix.session_id),
            )
            .await;
            let (status, body) = delete_edge(&fix, edge, Some(stolen)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
            assert_eq!(edge_count(&fix).await, 1);
        }

        /// The `sessionId` binding — the load-bearing one, per the publish
        /// design note.
        ///
        /// Added because mutation testing showed it was untested here: with
        /// the session comparison neutered, every other test still passed,
        /// because every other test happens to present the authorization in
        /// the session it was minted for. The threat is a *different* member
        /// replaying a captured authorization: the signature on it is still
        /// the issuer's and verifies, so `sessionId` is the only thing that
        /// stops them deleting an edge they do not control.
        #[tokio::test]
        async fn rejects_an_authorization_replayed_in_another_members_session() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            // Minted for — and correctly signed for — the *first* member's
            // session, then presented by someone else.
            let pop = sign(RDID, revoke_authorization(edge, &fix.session_id)).await;

            let token = other_member_token(&fix).await;
            let req = Request::builder()
                .method("DELETE")
                .uri(format!("/v1/relationships/{edge}"))
                .header("authorization", format!("Bearer {token}"))
                .header("trust-task", REVOKE_TASK)
                .header("content-type", "application/json")
                .body(Body::from(json!({ "pop": pop }).to_string()))
                .unwrap();
            let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
            assert_eq!(edge_count(&fix).await, 1);
        }

        /// The authorization carries `sessionId`, which is attributable to a
        /// membership DID. Persisting it would rebuild the durable linkage
        /// publishing under a relationship DID exists to remove — and the
        /// revoke path writes to the audit store, so it is the one place it
        /// could plausibly leak.
        #[tokio::test]
        async fn authorization_is_never_persisted_to_the_audit_trail() {
            let fix = fixture().await;
            let edge = publish_edge(&fix, RDID, PEER_RDID).await;
            let pop = sign(RDID, revoke_authorization(edge, &fix.session_id)).await;
            assert_eq!(delete_edge(&fix, edge, Some(pop)).await.0, StatusCode::OK);

            let mut saw_revoke = false;
            for (_k, raw) in fix.audit_ks.prefix_iter_raw(Vec::new()).await.unwrap() {
                assert!(
                    !String::from_utf8_lossy(&raw).contains(&fix.session_id),
                    "session id reached the audit store"
                );
                assert!(
                    !String::from_utf8_lossy(&raw).contains("VrcRevokeAuthorization"),
                    "the authorization object reached the audit store"
                );
                let env: AuditEnvelope = serde_json::from_slice(&raw).unwrap();
                if let AuditEvent::VrcRevoked(d) = env.event {
                    // Proving control of the issuing key *is* being the
                    // issuer; the trail should not call it an admin action.
                    assert_eq!(d.revoked_by, "issuer");
                    saw_revoke = true;
                }
            }
            assert!(saw_revoke, "expected a VrcRevoked audit entry");
        }
    }
}
