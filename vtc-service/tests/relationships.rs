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
}
