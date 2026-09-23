//! Hidden vetting's community half, over the wire it actually serves.
//!
//! Three Trust Tasks, posted as signed documents to `/v1/trust-tasks` exactly as a vetter's or
//! an applicant's agent would post them, and answered by the same dispatcher every other task
//! goes through:
//!
//! 1. a vetter enrols (`vtc/vetting/vetters/pcs-root/0.1`) and unblinds what comes back;
//! 2. the same vetter draws a tick of the drip (`.../pcs-tokens/0.1`) and the tokens verify;
//! 3. an applicant asks for a challenge (`vtc/vetting/pcs-challenge/0.1`).
//!
//! Then the refusals that make each of them a rule rather than an intention: a stranger
//! enrolling, the same vetter enrolling twice under one label, a second draw for one tick, and a
//! batch over the published rate.
//!
//! Everything here runs against `vti-vetting-pcs` on the client side too, because the vetter
//! half of the crate is what an agent runs — so a mismatch between what this service signs and
//! what a vetter can use shows up as a failure here rather than in a deployment.

#![cfg(feature = "vetting-pcs")]

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use predicate_credential_system::pcs::PredicateCredentialSystem;
use vtc_service::test_support::TestVtc;
use vtc_service::vetting::pcs_tasks;
use vti_vetting_pcs::{
    rand::{SeedableRng, rngs::StdRng},
    scheme::{point_text, vetter_predicate},
    token::TokenWallet,
};

const COMMUNITY: &str = "did:key:z6MkfMhiddenVettingTasks";
const PERIOD: &str = "2026-09";
const TOKEN_LABEL: &str = "token/2026-09";
const DRIP: usize = 3;

/// A `did:key` identity from a fixed seed.
fn identity(seed: u8) -> (String, Secret) {
    let mut secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let public = secret.get_public_keymultibase().unwrap();
    secret.id = format!("did:key:{public}#{public}");
    let did = secret.id.split('#').next().unwrap().to_string();
    (did, secret)
}

struct Harness {
    tv: TestVtc,
    community: String,
}

impl Harness {
    async fn start() -> Self {
        let tv = TestVtc::builder()
            .vtc_did(COMMUNITY)
            .with_signers(true)
            .with_audit(true)
            .build()
            .await;
        let community = COMMUNITY.to_string();
        Self { tv, community }
    }

    /// Publish this community's hidden-vetting parameters on a criterion, the way an operator
    /// does: from the keys the service will actually mint under.
    async fn publish(&self) -> vtc_service::vetting::pcs::HiddenVettingConfig {
        let config = vtc_service::vetting::pcs_issue::publish(
            &self.tv.state,
            &self.community,
            vec![PERIOD.to_string()],
            vec![TOKEN_LABEL.to_string()],
            DRIP,
        )
        .expect("the community publishes the keys it mints under");
        // A criterion needs a DCQL query naming a registered evidence type; what this test is
        // about hangs off it rather than being it.
        const VCT: &str = "https://openvtc.org/credentials/MembershipCredential";
        vtc_service::schemas::store_schema(
            &self.tv.state.schemas_ks,
            &vtc_service::schemas::SchemaEntry {
                type_uri: VCT.into(),
                dtg_type: Some("MembershipCredential".into()),
                credential_schema: None,
                kind: vtc_service::schemas::SchemaKind::Accepts,
                description: None,
                created_at: Utc::now(),
                created_by_did: "did:key:zAdmin".into(),
            },
        )
        .await
        .expect("register the evidence type");
        let criterion = vtc_service::schemas::accepts::AcceptsCriterion {
            id: "hidden-criterion".into(),
            query: json!({
                "credentials": [{
                    "id": "membership",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": [VCT] },
                    "claims": [{ "path": ["givenName"] }]
                }]
            }),
            description: None,
            vetting: None,
            hidden_vetting: Some(serde_json::to_value(&config).unwrap()),
            created_at: Utc::now(),
            created_by_did: "did:key:zAdmin".into(),
        };
        vtc_service::schemas::accepts::store_accepts(&self.tv.state.schemas_ks, &criterion)
            .await
            .expect("store the criterion");
        config
    }

    /// A member of this community holding a live vetter grant — the community's own records,
    /// which is what the minting half reads. Written directly rather than through the grant
    /// task, because what is under test here is what happens *after* a grant exists.
    async fn grant_vetter(&self, did: &str) {
        let mut member = vtc_service::members::Member::fresh(did);
        member.joined_at = Utc::now() - Duration::days(1);
        vtc_service::members::store_member(&self.tv.state.members_ks, &member)
            .await
            .unwrap();
        let row = vtc_service::endorsements::Endorsement {
            id: Uuid::new_v4(),
            endorsement_type: vta_sdk::protocols::vetting::COMMUNITY_ROLE_ENDORSEMENT_TYPE
                .to_string(),
            issuer_did: self.community.clone(),
            subject_did: did.to_string(),
            claim: json!({
                "type": vta_sdk::protocols::vetting::COMMUNITY_ROLE_ENDORSEMENT_TYPE,
                "role": "vetter",
            }),
            status_list_index: 0,
            vec_id: format!("urn:uuid:{}", Uuid::new_v4()),
            created_at: Utc::now() - Duration::hours(1),
            revoked_at: None,
            valid_until: None,
            auto_granted: false,
            credential: None,
        };
        vtc_service::endorsements::store_endorsement(&self.tv.state.endorsements_ks, &row)
            .await
            .unwrap();
    }

    /// Post a signed Trust Task document, as an agent would.
    async fn post(&self, secret: &Secret, typ: &str, payload: Value) -> (StatusCode, Value) {
        let did = secret.id.split('#').next().unwrap().to_string();
        let now = Utc::now();
        let stamp = |t: chrono::DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut doc = json!({
            "type": typ,
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "issuer": did,
            "recipient": self.community,
            "issuedAt": stamp(now),
            "expiresAt": stamp(now + Duration::hours(1)),
            "payload": payload,
        });
        let proof = DataIntegrityProof::sign(&doc, secret, SignOptions::new())
            .await
            .expect("sign");
        doc["proof"] = serde_json::to_value(proof).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/v1/trust-tasks")
            .header("content-type", "application/json")
            .body(Body::from(doc.to_string()))
            .unwrap();
        let response = self.tv.router.clone().oneshot(req).await.expect("oneshot");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body)
    }
}

/// The code a refusal carries, from the framework's error document.
fn refusal_code(body: &Value) -> String {
    body.pointer("/payload/code")
        .or_else(|| body.pointer("/payload/error/code"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn a_vetter_enrols_draws_and_an_applicant_gets_a_challenge() {
    let h = Harness::start().await;
    let config = h.publish().await;
    // The same issuer the service mints with — derived from the same master secret, which is
    // what makes this a test of the wire rather than of two unrelated key pairs.
    let issuer = vtc_service::vetting::pcs_issue::derive_issuer(&h.tv.state, &h.community)
        .expect("the service's own issuer");
    let mut rng = StdRng::seed_from_u64(0x2026_0926);

    let (vetter_did, vetter_key) = identity(0xA7);
    h.grant_vetter(&vetter_did).await;

    // --- 1. enrol ---------------------------------------------------------------------------
    let (id, usk) = issuer.open().user_keygen(&mut rng).unwrap();
    let f = vetter_predicate(PERIOD);
    let (request, blinding) = issuer
        .open()
        .root_request(issuer.hvk(), &f, &id, &usk, &mut rng)
        .unwrap();
    let (status, body) = h
        .post(
            &vetter_key,
            pcs_tasks::PCS_ROOT_TYPE,
            json!({
                "label": format!("vetter/{PERIOD}"),
                "id": point_text(&id).unwrap(),
                "request": serde_json::to_value(&request).unwrap(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let pre = body
        .pointer("/payload/preCredential")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no pre-credential in {body}"));
    // What comes back unblinds into a credential the community has never seen.
    issuer
        .open()
        .unblind(
            issuer.hvk(),
            &usk,
            &f,
            &vti_vetting_pcs::scheme::dec(pre).unwrap(),
            &blinding,
        )
        .expect("the answer unblinds under the published key");

    // Twice under one label is what makes distinct tags distinct people.
    let (status, body) = h
        .post(
            &vetter_key,
            pcs_tasks::PCS_ROOT_TYPE,
            json!({
                "label": format!("vetter/{PERIOD}"),
                "id": point_text(&id).unwrap(),
                "request": serde_json::to_value(&request).unwrap(),
            }),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "a second enrolment must be refused");
    assert_eq!(refusal_code(&body), pcs_tasks::ROOT_ERR_ALREADY_ENROLLED);

    // A member with no grant is refused before any crypto happens.
    let (stranger_did, stranger_key) = identity(0xB7);
    let _ = stranger_did;
    let (status, body) = h
        .post(
            &stranger_key,
            pcs_tasks::PCS_ROOT_TYPE,
            json!({
                "label": format!("vetter/{PERIOD}"),
                "id": point_text(&id).unwrap(),
                "request": serde_json::to_value(&request).unwrap(),
            }),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(refusal_code(&body), pcs_tasks::ROOT_ERR_NOT_A_VETTER);

    // --- 2. draw ----------------------------------------------------------------------------
    let mut wallet = TokenWallet::new(&h.community).unwrap();
    let requests = wallet
        .prepare(issuer.tvk(), TOKEN_LABEL, &vetter_did, 1, DRIP, &mut rng)
        .unwrap();
    let batch = json!({
        "label": TOKEN_LABEL,
        "tick": 1,
        "requests": requests
            .iter()
            .map(|r| json!({
                "commitment": vti_vetting_pcs::scheme::enc(&r.commitment).unwrap(),
                "openingProof": vti_vetting_pcs::scheme::enc(&r.opening_proof).unwrap(),
            }))
            .collect::<Vec<_>>(),
    });
    let (status, body) = h
        .post(&vetter_key, pcs_tasks::PCS_TOKENS_TYPE, batch.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let pres: Vec<_> = body
        .pointer("/payload/preCredentials")
        .and_then(Value::as_array)
        .expect("tokens")
        .iter()
        .map(|p| vti_vetting_pcs::scheme::dec(p.as_str().unwrap()).unwrap())
        .collect();
    wallet
        .receive(issuer.tvk(), &pres)
        .expect("the tokens verify under the published token key");
    assert_eq!(wallet.free(), DRIP);

    // The same tick again is refused — the store says so, not a memory.
    let (status, body) = h.post(&vetter_key, pcs_tasks::PCS_TOKENS_TYPE, batch).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(refusal_code(&body), pcs_tasks::TOKENS_ERR_ALREADY_SERVED);

    // And more than the published rate is refused whatever the vetter asks for.
    let greedy = wallet
        .prepare(
            issuer.tvk(),
            TOKEN_LABEL,
            &vetter_did,
            2,
            DRIP + 5,
            &mut rng,
        )
        .unwrap();
    let (status, body) = h
        .post(
            &vetter_key,
            pcs_tasks::PCS_TOKENS_TYPE,
            json!({
                "label": TOKEN_LABEL,
                "tick": 2,
                "requests": greedy
                    .iter()
                    .map(|r| json!({
                        "commitment": vti_vetting_pcs::scheme::enc(&r.commitment).unwrap(),
                        "openingProof": vti_vetting_pcs::scheme::enc(&r.opening_proof).unwrap(),
                    }))
                    .collect::<Vec<_>>(),
            }),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(refusal_code(&body), pcs_tasks::TOKENS_ERR_OVER_QUOTA);

    // --- 3. the applicant's challenge -------------------------------------------------------
    let (_applicant_did, applicant_key) = identity(0xC7);
    let (status, body) = h
        .post(
            &applicant_key,
            pcs_tasks::PCS_CHALLENGE_TYPE,
            json!({ "criterionId": "hidden-criterion" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let challenge = body
        .pointer("/payload/challenge")
        .and_then(Value::as_str)
        .expect("a challenge");
    // 16 bytes of lowercase hex, as the specification says — not "a random string".
    assert_eq!(challenge.len(), 32, "{challenge}");
    assert!(
        challenge
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "{challenge}"
    );
    assert!(body.pointer("/payload/expiresAt").is_some(), "{body}");

    let _ = config;
}

/// A community that publishes no hidden-vetting criterion has no challenge to issue, and says
/// so with the declared code rather than minting one nobody can spend.
#[tokio::test]
async fn a_community_that_runs_no_hidden_criterion_refuses_a_challenge() {
    let h = Harness::start().await;
    let (_did, key) = identity(0xD7);
    let (status, body) = h.post(&key, pcs_tasks::PCS_CHALLENGE_TYPE, json!({})).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(refusal_code(&body), pcs_tasks::CHALLENGE_ERR_NOT_HIDDEN);
}
