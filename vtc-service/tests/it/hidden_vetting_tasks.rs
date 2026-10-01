//! Hidden vetting's community half, over the wire it actually serves.
//!
//! Four Trust Tasks, posted as signed documents to `/v1/trust-tasks` exactly as a vetter's or
//! an applicant's agent would post them, and answered by the same dispatcher every other task
//! goes through:
//!
//! 1. a vetter enrols (`vtc/vetting/vetters/pcs-root/0.1`) and unblinds what comes back;
//! 2. the same vetter draws a tick of the drip (`.../pcs-tokens/0.1`) and the tokens verify;
//! 3. a vetter asks to vet at an event (`.../event-mode/0.1`);
//! 4. an applicant asks for a challenge (`vtc/vetting/pcs-challenge/0.1`).
//!
//! Then the refusals that make each of them a rule rather than an intention: a stranger
//! enrolling, the same vetter enrolling twice under one label, a second draw for one tick, a
//! batch over the published rate, and — for event mode — the four conditions that stand between
//! an event being configured and its label being drawn under.
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

    /// Re-store this community's criterion with `config`.
    ///
    /// This is how an admin approves an event: by editing the criterion that publishes it. There
    /// is deliberately no Trust Task for it — a task the vetter could send is a task a vetter
    /// could be made to send — so the test does what an admin does.
    async fn store_config(&self, config: &vtc_service::vetting::pcs::HiddenVettingConfig) {
        let mut criterion = vtc_service::schemas::accepts::get_accepts(
            &self.tv.state.schemas_ks,
            "hidden-criterion",
        )
        .await
        .expect("read the criterion")
        .expect("the criterion exists");
        criterion.hidden_vetting = Some(serde_json::to_value(config).unwrap());
        vtc_service::schemas::accepts::store_accepts(&self.tv.state.schemas_ks, &criterion)
            .await
            .expect("store the criterion");
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
            endorsement_type: vtc_service::endorsements::VETTER_GRANT_ROW_TYPE.to_string(),
            issuer_did: self.community.clone(),
            subject_did: did.to_string(),
            claim: json!({ "role": "vetter" }),
            status_list_index: 0,
            credential_id: format!("urn:uuid:{}", Uuid::new_v4()),
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
fn tt_error_code(body: &Value) -> String {
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
    assert_eq!(tt_error_code(&body), pcs_tasks::ROOT_ERR_ALREADY_ENROLLED);

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
    assert_eq!(tt_error_code(&body), pcs_tasks::ROOT_ERR_NOT_A_VETTER);

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
    assert_eq!(tt_error_code(&body), pcs_tasks::TOKENS_ERR_ALREADY_SERVED);

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
    assert_eq!(tt_error_code(&body), pcs_tasks::TOKENS_ERR_OVER_QUOTA);

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
    assert_eq!(tt_error_code(&body), pcs_tasks::CHALLENGE_ERR_NOT_HIDDEN);
}

// --- event mode ---------------------------------------------------------------------------------

const EVENT: &str = "kernel-summit-2026";
const EVENT_LABEL: &str = "token/event/kernel-summit-2026";
const EVENT_DRIP: usize = 20;

/// The event as an admin configures it: a three-day summit, one tier, the floor §5.1 names.
fn summit(approved_by: Option<&str>) -> vtc_service::vetting::pcs::HiddenVettingEvent {
    vtc_service::vetting::pcs::HiddenVettingEvent {
        event_id: EVENT.into(),
        start_date: Utc::now().date_naive(),
        end_date: Utc::now().date_naive() + Duration::days(2),
        grace_days: 14,
        group_floor: 3,
        tiers: vec![vtc_service::vetting::pcs::HiddenVettingTier {
            name: "desk".into(),
            drip_per_tick: EVENT_DRIP,
        }],
        approved_by: approved_by.map(str::to_string),
    }
}

/// The window a vetter asks for: the whole event.
fn window() -> Value {
    json!({
        "startDate": Utc::now().date_naive().to_string(),
        "endDate": (Utc::now().date_naive() + Duration::days(2)).to_string(),
    })
}

/// Publish the summit on the criterion, with its label live, and grant `n` vetters.
async fn summit_harness(approved_by: Option<&str>, n: u8) -> (Harness, Vec<(String, Secret)>) {
    let h = Harness::start().await;
    let mut config = h.publish().await;
    config.live_token_labels.push(EVENT_LABEL.to_string());
    config.events.push(summit(approved_by));
    h.store_config(&config).await;

    let mut vetters = Vec::new();
    for i in 0..n {
        let (did, key) = identity(0xE0 + i);
        h.grant_vetter(&did).await;
        vetters.push((did, key));
    }
    (h, vetters)
}

/// A request is a request. It is recorded, it counts towards the floor, and it grants nothing —
/// and until the floor is met the event's label cannot be drawn under at all.
#[tokio::test]
async fn an_event_stays_shut_until_enough_vetters_have_asked() {
    let (h, vetters) = summit_harness(Some("did:key:zAdminApprover"), 2).await;

    let (status, body) = h
        .post(
            &vetters[0].1,
            pcs_tasks::EVENT_MODE_TYPE,
            json!({ "eventId": EVENT, "tier": "desk", "window": window() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body.pointer("/payload/state").unwrap(), "pending");
    assert_eq!(body.pointer("/payload/groupSize").unwrap(), 1);
    assert_eq!(body.pointer("/payload/groupFloor").unwrap(), 3);
    // The three members that would read as permission to draw are absent while it is pending.
    assert!(body.pointer("/payload/label").is_none(), "{body}");
    assert!(body.pointer("/payload/dripPerTick").is_none(), "{body}");
    assert!(body.pointer("/payload/closesAfter").is_none(), "{body}");

    // Asking again does not make the group bigger.
    let (status, body) = h
        .post(
            &vetters[0].1,
            pcs_tasks::EVENT_MODE_TYPE,
            json!({ "eventId": EVENT, "tier": "desk", "window": window() }),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::EVENT_ERR_ALREADY_REQUESTED);

    // And the label it would unlock is shut, with the code the drip declares for exactly this.
    let issuer = vtc_service::vetting::pcs_issue::derive_issuer(&h.tv.state, &h.community).unwrap();
    let mut rng = StdRng::seed_from_u64(0x2026_1012);
    let mut wallet = TokenWallet::new(&h.community).unwrap();
    let requests = wallet
        .prepare(
            issuer.tvk(),
            EVENT_LABEL,
            &vetters[0].0,
            1,
            EVENT_DRIP,
            &mut rng,
        )
        .unwrap();
    let (status, body) = h
        .post(
            &vetters[0].1,
            pcs_tasks::PCS_TOKENS_TYPE,
            json!({
                "label": EVENT_LABEL,
                "tick": 1,
                "requests": requests
                    .iter()
                    .map(|r| json!({
                        "commitment": vti_vetting_pcs::scheme::enc(&r.commitment).unwrap(),
                        "openingProof": vti_vetting_pcs::scheme::enc(&r.opening_proof).unwrap(),
                    }))
                    .collect::<Vec<_>>(),
            }),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(tt_error_code(&body), pcs_tasks::TOKENS_ERR_EVENT_REFUSED);
}

/// With an approver and the floor met, the label opens — at the tier's rate, which is the whole
/// point of it, and still capped by the community rather than by what the vetter asks for.
#[tokio::test]
async fn an_approved_event_opens_its_label_at_the_tier_rate() {
    let (h, vetters) = summit_harness(Some("did:key:zAdminApprover"), 3).await;
    let ask = json!({ "eventId": EVENT, "tier": "desk", "window": window() });

    for (n, (_, key)) in vetters.iter().enumerate() {
        let (status, body) = h.post(key, pcs_tasks::EVENT_MODE_TYPE, ask.clone()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let expected = if n + 1 >= 3 { "approved" } else { "pending" };
        assert_eq!(
            body.pointer("/payload/state").unwrap(),
            expected,
            "vetter {n} of 3: {body}"
        );
        if n + 1 >= 3 {
            assert_eq!(body.pointer("/payload/label").unwrap(), EVENT_LABEL);
            assert_eq!(body.pointer("/payload/dripPerTick").unwrap(), EVENT_DRIP);
            assert_eq!(
                body.pointer("/payload/closesAfter").unwrap(),
                &json!((Utc::now().date_naive() + Duration::days(16)).to_string()),
                "the window plus this community's grace"
            );
        }
    }

    let issuer = vtc_service::vetting::pcs_issue::derive_issuer(&h.tv.state, &h.community).unwrap();
    let mut rng = StdRng::seed_from_u64(0x2026_1013);
    let mut wallet = TokenWallet::new(&h.community).unwrap();
    let requests = wallet
        .prepare(
            issuer.tvk(),
            EVENT_LABEL,
            &vetters[0].0,
            1,
            EVENT_DRIP,
            &mut rng,
        )
        .unwrap();
    let batch = |reqs: &[vti_vetting_pcs::token::TokenRequest], tick: u32| {
        json!({
            "label": EVENT_LABEL,
            "tick": tick,
            "requests": reqs
                .iter()
                .map(|r| json!({
                    "commitment": vti_vetting_pcs::scheme::enc(&r.commitment).unwrap(),
                    "openingProof": vti_vetting_pcs::scheme::enc(&r.opening_proof).unwrap(),
                }))
                .collect::<Vec<_>>(),
        })
    };
    let (status, body) = h
        .post(
            &vetters[0].1,
            pcs_tasks::PCS_TOKENS_TYPE,
            batch(&requests, 1),
        )
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
        .expect("event tokens verify under the same published key");
    assert_eq!(wallet.free(), EVENT_DRIP, "the tier's rate, not the drip's");

    // The tier is the cap. A vetter asking for more than it is refused the batch, exactly as
    // under the monthly label.
    let greedy = wallet
        .prepare(
            issuer.tvk(),
            EVENT_LABEL,
            &vetters[0].0,
            2,
            EVENT_DRIP + 1,
            &mut rng,
        )
        .unwrap();
    let (status, body) = h
        .post(&vetters[0].1, pcs_tasks::PCS_TOKENS_TYPE, batch(&greedy, 2))
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(tt_error_code(&body), pcs_tasks::TOKENS_ERR_OVER_QUOTA);
}

/// The rule that makes the approval mean something: an approver who is in the group has approved
/// their own cap, and the label stays shut for everyone — not just for them.
#[tokio::test]
async fn an_event_approved_by_one_of_its_own_vetters_opens_nothing() {
    let (h, vetters) = summit_harness(None, 3).await;
    let ask = json!({ "eventId": EVENT, "tier": "desk", "window": window() });
    for (_, key) in &vetters {
        let (status, body) = h.post(key, pcs_tasks::EVENT_MODE_TYPE, ask.clone()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.pointer("/payload/state").unwrap(), "pending");
    }

    // The admin now approves — naming a vetter who asked to be in the group. The floor is met,
    // the window is open, everybody asked, and it still opens nothing.
    let mut config = h.publish().await;
    config.live_token_labels.push(EVENT_LABEL.to_string());
    config.events.push(summit(Some(&vetters[1].0)));
    h.store_config(&config).await;

    let issuer = vtc_service::vetting::pcs_issue::derive_issuer(&h.tv.state, &h.community).unwrap();
    let mut rng = StdRng::seed_from_u64(0x2026_1014);
    let mut wallet = TokenWallet::new(&h.community).unwrap();
    // The one who did not approve, so that what is refused is the event and not the approver.
    let requests = wallet
        .prepare(
            issuer.tvk(),
            EVENT_LABEL,
            &vetters[0].0,
            1,
            EVENT_DRIP,
            &mut rng,
        )
        .unwrap();
    let (status, body) = h
        .post(
            &vetters[0].1,
            pcs_tasks::PCS_TOKENS_TYPE,
            json!({
                "label": EVENT_LABEL,
                "tick": 1,
                "requests": requests
                    .iter()
                    .map(|r| json!({
                        "commitment": vti_vetting_pcs::scheme::enc(&r.commitment).unwrap(),
                        "openingProof": vti_vetting_pcs::scheme::enc(&r.opening_proof).unwrap(),
                    }))
                    .collect::<Vec<_>>(),
            }),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(tt_error_code(&body), pcs_tasks::TOKENS_ERR_EVENT_REFUSED);
}

/// Every refusal the request itself declares, each with the code a client switches on.
#[tokio::test]
async fn an_event_request_refuses_with_the_codes_it_declares() {
    let (h, vetters) = summit_harness(Some("did:key:zAdminApprover"), 1).await;
    let (_, vetter) = &vetters[0];

    let (status, body) = h
        .post(
            vetter,
            pcs_tasks::EVENT_MODE_TYPE,
            json!({ "eventId": "some-other-summit", "tier": "desk", "window": window() }),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::EVENT_ERR_UNKNOWN_EVENT);

    let (status, body) = h
        .post(
            vetter,
            pcs_tasks::EVENT_MODE_TYPE,
            json!({ "eventId": EVENT, "tier": "all-day-every-day", "window": window() }),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::EVENT_ERR_UNKNOWN_TIER);

    // A window wider than the event's own: the extra days would be tokens at the event's rate
    // for days that are not the event.
    let (status, body) = h
        .post(
            vetter,
            pcs_tasks::EVENT_MODE_TYPE,
            json!({
                "eventId": EVENT,
                "tier": "desk",
                "window": {
                    "startDate": Utc::now().date_naive().to_string(),
                    "endDate": (Utc::now().date_naive() + Duration::days(30)).to_string(),
                },
            }),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::EVENT_ERR_BAD_WINDOW);

    // An event whose label has already closed. Its window is still the event's own, so what
    // refuses this is the grace period running out and not the dates being wrong.
    let mut config = h.publish().await;
    let past = vtc_service::vetting::pcs::HiddenVettingEvent {
        event_id: "last-years-summit".into(),
        start_date: Utc::now().date_naive() - Duration::days(30),
        end_date: Utc::now().date_naive() - Duration::days(28),
        grace_days: 14,
        group_floor: 3,
        tiers: vec![vtc_service::vetting::pcs::HiddenVettingTier {
            name: "desk".into(),
            drip_per_tick: EVENT_DRIP,
        }],
        approved_by: Some("did:key:zAdminApprover".into()),
    };
    config.live_token_labels.push(EVENT_LABEL.to_string());
    config.events.push(summit(Some("did:key:zAdminApprover")));
    config.events.push(past.clone());
    h.store_config(&config).await;
    let (status, body) = h
        .post(
            vetter,
            pcs_tasks::EVENT_MODE_TYPE,
            json!({
                "eventId": past.event_id,
                "tier": "desk",
                "window": {
                    "startDate": past.start_date.to_string(),
                    "endDate": past.end_date.to_string(),
                },
            }),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(tt_error_code(&body), pcs_tasks::EVENT_ERR_EVENT_CLOSED);

    // A member with no vetter grant is refused before anything is recorded.
    let (_, stranger) = identity(0xEF);
    let (status, body) = h
        .post(
            &stranger,
            pcs_tasks::EVENT_MODE_TYPE,
            json!({ "eventId": EVENT, "tier": "desk", "window": window() }),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::EVENT_ERR_NOT_A_VETTER);
}

/// The enrolment and drip refusals nothing above reaches, each with its declared code: a label
/// the community is not issuing, a request that does not verify, a second identifier after the
/// label rotates, a token label that is not live, an opening proof made for someone else, and a
/// draw by someone who is not a vetter.
#[tokio::test]
async fn the_enrolment_and_the_drip_refuse_with_the_codes_they_declare() {
    const NEXT: &str = "2026-10";
    let h = Harness::start().await;
    h.publish().await;
    let issuer = vtc_service::vetting::pcs_issue::derive_issuer(&h.tv.state, &h.community)
        .expect("the service's own issuer");
    let mut rng = StdRng::seed_from_u64(0x2026_0927);
    let (vetter_did, vetter_key) = identity(0xC7);
    h.grant_vetter(&vetter_did).await;

    let (id, usk) = issuer.open().user_keygen(&mut rng).unwrap();
    let root = |label: &str, id: &vti_vetting_pcs::scheme::G1, request: &Value| json!({ "label": label, "id": point_text(id).unwrap(), "request": request });
    let request_for = |period: &str, rng: &mut StdRng| {
        let (request, _) = issuer
            .open()
            .root_request(issuer.hvk(), &vetter_predicate(period), &id, &usk, rng)
            .unwrap();
        serde_json::to_value(&request).unwrap()
    };

    // A label this community is not issuing under.
    let good = request_for(PERIOD, &mut rng);
    let (status, body) = h
        .post(
            &vetter_key,
            pcs_tasks::PCS_ROOT_TYPE,
            root("vetter/1999-01", &id, &good),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::ROOT_ERR_WRONG_LABEL);

    // The right label, but a request proved for another period's predicate: it does not verify.
    let stale = request_for("1999-01", &mut rng);
    let label = format!("vetter/{PERIOD}");
    let (status, body) = h
        .post(
            &vetter_key,
            pcs_tasks::PCS_ROOT_TYPE,
            root(&label, &id, &stale),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::ROOT_ERR_BAD_REQUEST);

    // Enrol, then rotate the label: the member is bound to the identifier they enrolled with,
    // and a second one is refused rather than counted as a second vetter.
    let (status, body) = h
        .post(
            &vetter_key,
            pcs_tasks::PCS_ROOT_TYPE,
            root(&label, &id, &good),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rotated = vtc_service::vetting::pcs_issue::publish(
        &h.tv.state,
        &h.community,
        vec![NEXT.to_string(), PERIOD.to_string()],
        vec![TOKEN_LABEL.to_string()],
        DRIP,
    )
    .expect("the community rotates its vetter label");
    h.store_config(&rotated).await;
    let (other_id, _) = issuer.open().user_keygen(&mut rng).unwrap();
    let (status, body) = h
        .post(
            &vetter_key,
            pcs_tasks::PCS_ROOT_TYPE,
            root(&format!("vetter/{NEXT}"), &other_id, &good),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::ROOT_ERR_IDENTIFIER_REBOUND);

    // The drip: a token label that is not live.
    let mut wallet = TokenWallet::new(&h.community).unwrap();
    let batch = |label: &str, requests: &[vti_vetting_pcs::token::TokenRequest]| {
        json!({
            "label": label,
            "tick": 1,
            "requests": requests
                .iter()
                .map(|r| json!({
                    "commitment": vti_vetting_pcs::scheme::enc(&r.commitment).unwrap(),
                    "openingProof": vti_vetting_pcs::scheme::enc(&r.opening_proof).unwrap(),
                }))
                .collect::<Vec<_>>(),
        })
    };
    let requests = wallet
        .prepare(issuer.tvk(), TOKEN_LABEL, &vetter_did, 1, 1, &mut rng)
        .unwrap();
    let (status, body) = h
        .post(
            &vetter_key,
            pcs_tasks::PCS_TOKENS_TYPE,
            batch("token/1999-01", &requests),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::TOKENS_ERR_LABEL_NOT_LIVE);

    // Opening proofs bind who asks: ones made for another member do not verify for this one.
    let borrowed = wallet
        .prepare(
            issuer.tvk(),
            TOKEN_LABEL,
            "did:key:z6MkSomeoneElse",
            1,
            1,
            &mut rng,
        )
        .unwrap();
    let (status, body) = h
        .post(
            &vetter_key,
            pcs_tasks::PCS_TOKENS_TYPE,
            batch(TOKEN_LABEL, &borrowed),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(
        tt_error_code(&body),
        pcs_tasks::TOKENS_ERR_BAD_OPENING_PROOF
    );

    // And a member with no grant draws nothing, whatever it sends.
    let (_, stranger_key) = identity(0xD7);
    let (status, body) = h
        .post(
            &stranger_key,
            pcs_tasks::PCS_TOKENS_TYPE,
            batch(TOKEN_LABEL, &requests),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(tt_error_code(&body), pcs_tasks::TOKENS_ERR_NOT_A_VETTER);
}

/// `vtc/vetting/hidden/publish/0.1`, refused for the two reasons its specification declares: a
/// criterion that does not exist, and one asking for no vetting for the parameters to qualify.
#[tokio::test]
async fn publishing_hidden_vetting_refuses_with_the_codes_it_declares() {
    let h = Harness::start().await;
    let (admin_did, admin) = identity(0x70);
    crate::common::signed::seed_role(&h.tv, &admin_did, vtc_service::acl::VtcRole::Admin, &[])
        .await;

    let (status, body) = h
        .post(
            &admin,
            pcs_tasks::HIDDEN_PUBLISH_TYPE,
            json!({ "criterionId": "no-such-criterion" }),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        tt_error_code(&body),
        pcs_tasks::HIDDEN_PUBLISH_ERR_NO_SUCH_CRITERION,
        "{body}"
    );

    // The harness's criterion carries hidden-vetting parameters but no `vetting` requirements.
    h.publish().await;
    let (status, body) = h
        .post(
            &admin,
            pcs_tasks::HIDDEN_PUBLISH_TYPE,
            json!({ "criterionId": "hidden-criterion" }),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        tt_error_code(&body),
        pcs_tasks::HIDDEN_PUBLISH_ERR_NO_VETTING,
        "{body}"
    );
}
