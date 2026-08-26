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
const PUBLISH_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/publish/0.2";
const LIST_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/list/0.2";
const GRAPH_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/graph/0.2";
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
//
// The publish tests live in the `pairwise` module below, which has real key
// material. This module's fixture uses placeholder DIDs (`did:key:zVrcIssuer`)
// that no key backs, and since #1084 the route authenticates by the Trust Task
// document's own proof — so a fixture that cannot sign cannot reach the
// handler at all.
//
// Three tests were retired rather than moved:
//
// - `publish_rejects_caller_not_issuer` asserted that a session DID differing
//   from the VRC issuer is refused. There is no session DID any more. Its
//   successor is `pairwise::rejects_a_document_signed_by_a_non_member`, which
//   tests the property that survived: a proof is not membership.
// - `publish_rejects_malformed_vrc` is covered, and more thoroughly, by the
//   shape tests in `pairwise` — they mint through the `dtg-credentials`
//   catalog and check each part of the DTG common structure separately.
// - `publish_returns_500_when_resolver_unconfigured` asserted a daemon
//   misconfiguration surfaces after caller validation. That ordering is now
//   enforced earlier and differently: the document's proof is verified before
//   anything reads the resolver, so a resolver-less daemon refuses the caller
//   before it reaches its own missing dependency. Asserting the old 500 would
//   pin an ordering the change deliberately reversed.

// ─── Revoke ──────────────────────────────────────────────

async fn seed_relationship(fix: &Fixture, issuer: &str, subject: &str) -> Uuid {
    let id = Uuid::new_v4();
    let rel = Relationship {
        id,
        issuer_did: issuer.into(),
        subject_did: subject.into(),
        vrc_jsonld: fake_vrc(issuer, subject),
        // A real multibase-wrapped multihash over the seeded credential, not
        // `seed-{id}`. The placeholder was unique per row, which is all the
        // storage layer needed — and it meant no test ever exercised a digest
        // that looked like a digest, so the response-conformance layer found
        // the format mismatch that the whole suite had been blind to.
        vrc_digest_multibase: {
            use sha2::{Digest, Sha256};
            let canonical = serde_json_canonicalizer::to_vec(&fake_vrc(issuer, subject))
                .expect("canonicalizable");
            let mut mh = vec![0x12, 0x20];
            mh.extend_from_slice(&Sha256::digest(&canonical));
            multibase::encode(multibase::Base::Base58Btc, mh)
        },
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

    /// Publish a pairwise edge `issuer_seed -> subject_seed`, return its id.
    /// Shared by the `persona` and `revocation` suites below, both of which
    /// need an already-published pairwise edge to act on.
    async fn publish_edge(fix: &Pw, issuer_seed: u8, subject_seed: u8) -> Uuid {
        let v = vrc(issuer_seed, subject_seed).await;
        let doc_id = Uuid::new_v4().to_string();
        let pop = sign(issuer_seed, authorization(&doc_id, &vrc_digest(&v))).await;
        let (status, body) = body_value(post_with(fix, &v, Some(pop), &doc_id).await).await;
        assert_eq!(status, StatusCode::CREATED, "seed publish failed: {body}");
        // The response is a `#response` document now, so the task's own
        // members live under `payload`.
        Uuid::parse_str(body["payload"]["id"].as_str().unwrap()).unwrap()
    }

    /// A well-formed publish authorization, before signing.
    /// A publish authorization, before signing. Bound to the document it will
    /// ride in and to the credential it authorizes — no session, no audience,
    /// no timestamp: the document carries all three of its own.
    fn authorization(document_id: &str, vrc_digest: &str) -> Value {
        json!({
            "type": "VrcPublishAuthorization",
            "documentId": document_id,
            "vrcDigestMultibase": vrc_digest,
        })
    }

    /// The digest the authorization binds to: SHA-256 over the RFC 8785
    /// canonicalization, as a base58btc multibase multihash. Computed here the
    /// long way rather than by calling the handler's helper, so a change to
    /// that helper has to be matched here deliberately instead of agreeing
    /// with itself.
    fn vrc_digest(v: &Value) -> String {
        use sha2::{Digest, Sha256};
        let canonical = serde_json_canonicalizer::to_vec(v).unwrap();
        let mut mh = vec![0x12u8, 0x20];
        mh.extend_from_slice(&Sha256::digest(&canonical));
        multibase::encode(multibase::Base::Base58Btc, mh)
    }

    /// Wrap a payload in a Trust Task document signed by `signer`.
    ///
    /// The route requires the document's own proof and takes the signer from
    /// it rather than from the bearer token, so every publish test now
    /// exercises two independent proofs: this one, and the authorization's.
    async fn document(signer: u8, id: &str, payload: Value) -> Value {
        // Round-trip through `TrustTask` before signing.
        //
        // The service verifies the proof over the document as *it*
        // reconstructs it — `verify_trust_task_proof` deserialises into
        // `TrustTask<Value>`, clears the proof and verifies over that
        // serialisation. Signing hand-written JSON instead would sign
        // different bytes (member order, omitted optionals) and every
        // signature would fail for a reason that has nothing to do with the
        // key. Signing the round-tripped form is what makes these tests
        // exercise the real path.
        let raw = json!({
            "id": id,
            "type": PUBLISH_TASK,
            "issuer": did_for(signer),
            "recipient": TEST_VTC_DID,
            "issuedAt": chrono::Utc::now().to_rfc3339(),
            "payload": payload,
        });
        let parsed: trust_tasks_rs::TrustTask<Value> =
            serde_json::from_value(raw).expect("a well-formed Trust Task document");
        sign(signer, serde_json::to_value(&parsed).unwrap()).await
    }

    async fn post_doc(fix: &Pw, doc: Value) -> axum::response::Response {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/relationships")
            .header("authorization", format!("Bearer {}", fix.token))
            .header("trust-task", PUBLISH_TASK)
            .header("content-type", "application/json")
            .body(Body::from(doc.to_string()))
            .unwrap();
        fix.router.clone().oneshot(req).await.unwrap()
    }

    /// Publish `vrc`, minting the document id first so an authorization can
    /// bind to it. `mk_pop` receives that id.
    async fn post_with(
        fix: &Pw,
        vrc: &Value,
        pop: Option<Value>,
        doc_id: &str,
    ) -> axum::response::Response {
        let mut payload = json!({ "vrc": vrc });
        if let Some(p) = pop {
            payload["pop"] = p;
        }
        post_doc(fix, document(MEMBER, doc_id, payload).await).await
    }

    /// The ordinary case: mint an id, authorize with the relationship key,
    /// publish.
    async fn post(fix: &Pw, vrc: &Value, with_pop: bool) -> axum::response::Response {
        let doc_id = Uuid::new_v4().to_string();
        let pop = if with_pop {
            Some(sign(RDID, authorization(&doc_id, &vrc_digest(vrc))).await)
        } else {
            None
        };
        post_with(fix, vrc, pop, &doc_id).await
    }

    /// The happy path #1054 exists to enable: the published row names only
    /// pairwise identifiers, and the member's own DID appears nowhere in it.
    #[tokio::test]
    async fn publishes_under_a_relationship_did() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let (status, body) = body_value(post(&fix, &v, true).await).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        // The response is a `#response` Trust Task document, so the task's
        // own members are under `payload`.
        assert_eq!(body["payload"]["issuerDid"], did_for(RDID));
        assert_eq!(body["payload"]["subjectDid"], did_for(PEER_RDID));
        // …and the envelope correlates the two halves of the exchange.
        assert!(body["threadId"].is_string(), "response carries a threadId");
        assert_eq!(body["issuer"], TEST_VTC_DID, "issuer and recipient swap");
        assert_eq!(body["recipient"], did_for(MEMBER));

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
        assert_eq!(post(&fix, &v, true).await.status(), StatusCode::CREATED);

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
        assert_eq!(post(&fix, &v, true).await.status(), StatusCode::CREATED);

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
        let (status, body) = body_value(post(&fix, &v, true).await).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
    }

    #[tokio::test]
    async fn same_vrc_twice_is_idempotent() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        // Two publishes, two documents, two authorizations — each bound to
        // its own document. Idempotency is keyed on the credential, so the
        // second is recognised as the same edge despite everything around it
        // differing.
        let (s1, b1) = body_value(post(&fix, &v, true).await).await;
        let (s2, b2) = body_value(post(&fix, &v, true).await).await;
        assert_eq!(s1, StatusCode::CREATED);
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(b1["payload"]["id"], b2["payload"]["id"]);
    }

    // ─── Every field of the authorization is load-bearing ───

    #[tokio::test]
    async fn rejects_missing_authorization() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        assert_eq!(post(&fix, &v, false).await.status(), StatusCode::FORBIDDEN);
    }

    /// Holding the credential is not controlling the key behind it. This is
    /// the property the issuer pin provided before #1054 replaced it.
    #[tokio::test]
    async fn rejects_authorization_signed_by_another_key() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let doc_id = Uuid::new_v4().to_string();
        // Correct in every respect except who signed it.
        let pop = sign(OTHER, authorization(&doc_id, &vrc_digest(&v))).await;
        assert_eq!(
            post_with(&fix, &v, Some(pop), &doc_id).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn rejects_authorization_bound_to_a_different_credential() {
        let fix = fixture().await;
        let target = vrc(RDID, PEER_RDID).await;
        let decoy = vrc(RDID, OTHER).await;
        let doc_id = Uuid::new_v4().to_string();
        let pop = sign(RDID, authorization(&doc_id, &vrc_digest(&decoy))).await;
        assert_eq!(
            post_with(&fix, &target, Some(pop), &doc_id).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    /// Replaces `rejects_authorization_from_another_session`.
    ///
    /// The authorization used to bind to the caller's REST session, so a
    /// captured one was unusable by another member because it named their
    /// session. It now binds to the document (#259), which is available on
    /// every transport and narrower — a session spans many documents. This is
    /// the same threat, tested where the binding now lives.
    #[tokio::test]
    async fn rejects_an_authorization_replayed_in_another_document() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        // Minted for one document...
        let minted_for = Uuid::new_v4().to_string();
        let pop = sign(RDID, authorization(&minted_for, &vrc_digest(&v))).await;
        // ...and presented inside another.
        let sent_in = Uuid::new_v4().to_string();
        assert_ne!(minted_for, sent_in);
        assert_eq!(
            post_with(&fix, &v, Some(pop), &sent_in).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    /// Replaces `rejects_authorization_for_another_community`.
    ///
    /// The authorization used to carry its own `aud`. It no longer does,
    /// because the document carries `recipient` and the framework enforces it
    /// — so this now tests that `validate_basic` is actually wired in, which
    /// nothing else does.
    #[tokio::test]
    async fn rejects_a_document_addressed_to_another_community() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let doc_id = Uuid::new_v4().to_string();
        let pop = sign(RDID, authorization(&doc_id, &vrc_digest(&v))).await;
        let mut doc = document(MEMBER, &doc_id, json!({ "vrc": v, "pop": pop })).await;
        doc["recipient"] = json!("did:webvh:other-vtc.example:xyz");
        // Re-signed, so the failure is the audience and not a broken proof.
        let doc = sign(MEMBER, {
            let mut d = doc;
            d.as_object_mut().unwrap().remove("proof");
            d
        })
        .await;
        let (status, body) = body_value(post_doc(&fix, doc).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    /// Replaces `rejects_stale_authorization`.
    ///
    /// Freshness was the authorization's own `issuedAt` with a window. The
    /// document carries `expiresAt` and the framework enforces it, so the
    /// bound moved rather than disappeared.
    #[tokio::test]
    async fn rejects_an_expired_document() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let doc_id = Uuid::new_v4().to_string();
        let pop = sign(RDID, authorization(&doc_id, &vrc_digest(&v))).await;
        let mut doc = document(MEMBER, &doc_id, json!({ "vrc": v, "pop": pop })).await;
        doc["expiresAt"] = json!((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
        let doc = sign(MEMBER, {
            let mut d = doc;
            d.as_object_mut().unwrap().remove("proof");
            d
        })
        .await;
        let (status, body) = body_value(post_doc(&fix, doc).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    /// The document's proof is what authenticates this route — there is no
    /// bearer token to fall back on (#1084).
    #[tokio::test]
    async fn rejects_a_document_with_no_proof() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let doc_id = Uuid::new_v4().to_string();
        let pop = sign(RDID, authorization(&doc_id, &vrc_digest(&v))).await;
        let mut doc = document(MEMBER, &doc_id, json!({ "vrc": v, "pop": pop })).await;
        doc.as_object_mut().unwrap().remove("proof");
        assert_eq!(post_doc(&fix, doc).await.status(), StatusCode::FORBIDDEN);
    }

    /// A document signed by someone who is not a member of this community is
    /// refused by the policy, not by the proof — the proof is perfectly good.
    #[tokio::test]
    async fn rejects_a_document_signed_by_a_non_member() {
        let fix = fixture().await;
        let v = vrc(RDID, PEER_RDID).await;
        let doc_id = Uuid::new_v4().to_string();
        let pop = sign(RDID, authorization(&doc_id, &vrc_digest(&v))).await;
        // OTHER holds no ACL row in this community.
        let doc = document(OTHER, &doc_id, json!({ "vrc": v, "pop": pop })).await;
        assert_eq!(post_doc(&fix, doc).await.status(), StatusCode::FORBIDDEN);
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
        assert_eq!(post(&fix, &first, true).await.status(), StatusCode::CREATED);

        // Same relationship DID, different counterparty.
        let second = vrc(RDID, OTHER).await;
        let (status, body) = body_value(post(&fix, &second, true).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    /// Uniqueness is per counterparty, not per credential — re-issuing to the
    /// *same* counterparty (a renewal, a corrected claim) is not reuse.
    #[tokio::test]
    async fn allows_reissuing_to_the_same_counterparty() {
        let fix = fixture().await;

        let first = vrc(RDID, PEER_RDID).await;
        assert_eq!(post(&fix, &first, true).await.status(), StatusCode::CREATED);

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
        let (status, b) = body_value(post(&fix, &second, true).await).await;
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
            let (status, b) = body_value(post(&fix, &v, false).await).await;
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
        let (status, b) = body_value(post(&fix, &v, true).await).await;
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
        let doc_id = Uuid::new_v4().to_string();
        // Valid in every respect except the one member that says what it
        // authorizes.
        let mut a = authorization(&doc_id, &vrc_digest(&v));
        a["type"] = json!("SomeOtherSignedThing");
        let pop = sign(RDID, a).await;
        assert_eq!(
            post_with(&fix, &v, Some(pop), &doc_id).await.status(),
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
        const GRAPH_TASK: &str = "https://trusttasks.org/spec/vtc/relationships/graph/0.2";

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

        fn attach_authorization(vpc_digest: &str, edge: Uuid, session_id: &str) -> Value {
            json!({
                "type": "VpcAttachAuthorization",
                // Multibase multihash over the RFC 8785 canonicalization, the
                // same digest form the publish path and the stored row use.
                "vpcDigestMultibase": vpc_digest,
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
                attach_authorization(&vrc_digest(&v), edge, &fix.session_id),
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

            // The graph groups by pair (#1073), so the per-VRC fields — and
            // the persona, which is asserted per VRC — live on the half, not
            // on the edge. Only one direction is published here, so there is
            // exactly one half.
            let edges = graph_edges(&fix).await;
            assert_eq!(edges.len(), 1);
            assert_eq!(edges[0]["halves"].as_array().unwrap().len(), 1);
            assert_eq!(edges[0]["halves"][0]["personaDid"], did_for(PERSONA));
            assert_eq!(edges[0]["halves"][0]["issuerDid"], did_for(RDID));

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
                attach_authorization(&vrc_digest(&v), e2, &fix.session_id),
            )
            .await;
            let (status, body) = attach(&fix, e2, &v, Some(pop)).await;
            assert_eq!(status, StatusCode::OK, "body: {body}");

            let edges = graph_edges(&fix).await;
            assert_eq!(edges.len(), 2);
            for e in &edges {
                assert_eq!(e["halves"][0]["personaDid"], did_for(PERSONA));
            }
            // A P-DID recurring is the feature. An R-DID recurring is not:
            // the two edges must still carry distinct issuers.
            let issuers: std::collections::BTreeSet<_> = edges
                .iter()
                .map(|e| e["halves"][0]["issuerDid"].as_str().unwrap().to_string())
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
                attach_authorization(&vrc_digest(&v), edge, &fix.session_id),
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
                attach_authorization(&vrc_digest(&v), e1, &fix.session_id),
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
                attach_authorization(&vrc_digest(&not_a_vpc), edge, &fix.session_id),
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
                attach_authorization(&vrc_digest(&v), edge, &fix.session_id),
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
                attach_authorization(&vrc_digest(&v), edge, &fix.session_id),
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
                attach_authorization(&vrc_digest(&v), missing, &fix.session_id),
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
            // A genuine publish authorization, in its current shape, offered
            // where a revoke authorization is wanted.
            let stolen = sign(
                RDID,
                authorization(&Uuid::new_v4().to_string(), &vrc_digest(&v)),
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
