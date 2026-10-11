//! OpenID4VP wallet sessions end to end (#1988):
//! `vtc/join-requests/wallet-session/{start,status}/0.1` on the signed door,
//! and a wallet's two calls — `request_uri` and `response_uri` — over HTTPS.
//!
//! The wallet here is the test: it fetches the request object, checks it is
//! signed by the verifier identity's published key, builds an SD-JWT VC
//! presentation bound to the request's nonce and `client_id`, encrypts the
//! response to the key the request published, and posts it.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_oid4vc_core::jwe::{ContentEncryption, encrypt_compact};
use affinidi_sd_jwt::error::SdJwtError;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use vta_sdk::protocols::join_requests as jr;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_WALLET_SESSION_START_TYPE as START,
    JOIN_REQUEST_WALLET_SESSION_STATUS_TYPE as STATUS,
    wallet_session::{start::v0_1 as start, status::v0_1 as status},
};
use vtc_service::join::JoinStatus;
use vtc_service::schemas::accepts::{AcceptsCriterion, Admission, CredentialIssuers};
use vtc_service::test_support::{TEST_VERIFIER_DID, TestVtc, oid4vp_test_identity};

const PUBLIC_URL: &str = "https://vtc.example";
const VCT: &str = "https://example.org/credentials/residence-permit";
const APPLICANT_SEED: [u8; 32] = [0x41; 32];

struct Fixture {
    vtc: TestVtc,
    /// The `requirementsDigest` of the `residence` criterion.
    digest: String,
}

async fn fixture_with(identity: bool) -> Fixture {
    let mut builder = TestVtc::builder().with_public_url(PUBLIC_URL);
    if identity {
        builder = builder.with_oid4vp_identity(oid4vp_test_identity("swiyu", 0x31));
    }
    let vtc = builder.build().await;
    vtc_service::schemas::store_schema(
        &vtc.state.schemas_ks,
        &vtc_service::schemas::SchemaEntry {
            type_uri: VCT.into(),
            dtg_type: None,
            credential_schema: None,
            kind: vtc_service::schemas::SchemaKind::Accepts,
            description: None,
            created_at: Utc::now(),
            created_by_did: "did:key:zAdmin".into(),
        },
    )
    .await
    .expect("register the credential type");
    let mut criterion = AcceptsCriterion::new("residence", Admission::Review, "did:key:zAdmin");
    criterion.query = Some(json!({
        "credentials": [{
            "id": "residence",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": [VCT] },
            "claims": [{ "path": ["givenName"] }]
        }]
    }));
    criterion.credential_issuers = Some(CredentialIssuers::Any);
    let stored = vtc_service::schemas::accepts::store_accepts(&vtc.state.schemas_ks, &criterion)
        .await
        .expect("store the criterion");
    let digest = vtc_service::routes::join_requests::manifest::manifest_criterion(stored)
        .expect("served criterion")
        .digest;
    Fixture { vtc, digest }
}

async fn fixture() -> Fixture {
    fixture_with(true).await
}

/// A signed Trust Task document from the applicant key `seed`.
async fn signed(seed: &[u8; 32], typ: &str, payload: Value) -> Value {
    let mut secret = Secret::generate_ed25519(None, Some(seed));
    let pub_mb = secret.get_public_keymultibase().unwrap();
    let did = format!("did:key:{pub_mb}");
    secret.id = format!("{did}#{pub_mb}");
    let mut doc = json!({
        "type": typ,
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "issuer": did,
        "recipient": vtc_service::test_support::TEST_VTC_DID,
        "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "expiresAt": "2099-01-01T00:00:00Z",
        "payload": payload,
    });
    let proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new())
        .await
        .unwrap();
    doc.as_object_mut()
        .unwrap()
        .insert("proof".into(), serde_json::to_value(proof).unwrap());
    doc
}

fn applicant_did(seed: &[u8; 32]) -> String {
    let secret = Secret::generate_ed25519(None, Some(seed));
    format!("did:key:{}", secret.get_public_keymultibase().unwrap())
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, String, Vec<u8>) {
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, content_type, bytes)
}

async fn post_tt(f: &Fixture, doc: Value) -> (StatusCode, Value) {
    let req = Request::post("/v1/trust-tasks")
        .header("content-type", "application/json")
        .body(Body::from(doc.to_string()))
        .unwrap();
    let (status, _, bytes) = send(&f.vtc.router, req).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn tt_error_code(doc: &Value) -> &str {
    doc.pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no payload.code in {doc}"))
}

async fn start_session(f: &Fixture, seed: &[u8; 32], payload: Value) -> (StatusCode, Value) {
    let doc = signed(seed, START, payload).await;
    post_tt(f, doc).await
}

async fn session_status(f: &Fixture, seed: &[u8; 32], session_id: &str) -> (StatusCode, Value) {
    let doc = signed(seed, STATUS, json!({ "sessionId": session_id })).await;
    post_tt(f, doc).await
}

async fn get_request_object(f: &Fixture, session_id: &str) -> (StatusCode, String, Vec<u8>) {
    let req = Request::get(format!("/v1/oid4vp/request/{session_id}"))
        .body(Body::empty())
        .unwrap();
    send(&f.vtc.router, req).await
}

async fn post_response(f: &Fixture, session_id: &str, form: String) -> (StatusCode, Value) {
    let req = Request::post(format!("/v1/oid4vp/response/{session_id}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    let (status, _, bytes) = send(&f.vtc.router, req).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn decode_segment(jws: &str, n: usize) -> Value {
    let segment = jws.split('.').nth(n).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
}

// ── the wallet ──

struct Es256Signer {
    private: Vec<u8>,
}
impl affinidi_sd_jwt::signer::JwtSigner for Es256Signer {
    fn algorithm(&self) -> &str {
        "ES256"
    }
    fn key_id(&self) -> Option<&str> {
        None
    }
    fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        let input = format!("{}.{}", enc(header), enc(payload));
        let sig = affinidi_crypto::p256::sign(&self.private, input.as_bytes())
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }
}

fn p256(seed: u8) -> (Vec<u8>, Value, String) {
    let kp = affinidi_crypto::p256::generate(Some(&[seed; 32])).unwrap();
    let mut jwk = serde_json::to_value(&kp.jwk).unwrap();
    jwk.as_object_mut().unwrap().remove("d");
    let did = vta_sdk::jws::JwsKey::from_jwk(&jwk).unwrap().did_key();
    (kp.private_bytes, jwk, did)
}

/// An SD-JWT VC of type `vct` from a P-256 `did:key` issuer, bound to a P-256
/// holder, presented to `aud` under `nonce`. Returns `(holder_did, presentation)`.
fn presentation(vct: &str, aud: &str, nonce: &str) -> (String, String) {
    use affinidi_sd_jwt::holder::{KbJwtInput, present, select_disclosures};
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let (issuer_priv, _, issuer_did) = p256(0x51);
    let (holder_priv, holder_jwk, holder_did) = p256(0x52);
    let claims = json!({
        "iss": issuer_did, "vct": vct, "iat": iat,
        "exp": (now + Duration::hours(1)).timestamp(), "givenName": "Alice"
    });
    let hasher = Sha256Hasher;
    let sd = affinidi_sd_jwt::issuer::issue(
        &claims,
        &json!({ "_sd": ["givenName"] }),
        &Es256Signer {
            private: issuer_priv,
        },
        &hasher,
        Some(&holder_jwk),
    )
    .unwrap();
    let selected = select_disclosures(&sd, &["givenName"]);
    let holder = Es256Signer {
        private: holder_priv,
    };
    let kb = KbJwtInput {
        audience: aud,
        nonce,
        signer: &holder,
        iat,
    };
    let p = present(&sd, &selected, Some(&kb), &hasher).unwrap();
    (holder_did, p.serialize())
}

/// What a wallet posts: the authorization response encrypted to the request
/// object's response key.
fn encrypted_response(request: &Value, plaintext: &Value) -> String {
    let key = &request["client_metadata"]["jwks"]["keys"][0];
    let jwe = encrypt_compact(
        &serde_json::to_vec(plaintext).unwrap(),
        key,
        ContentEncryption::A256Gcm,
        b"",
        b"",
    )
    .unwrap();
    // A compact JWE is base64url and dots: nothing to percent-encode.
    format!("response={jwe}")
}

/// The whole round trip: an applicant opens a session, a wallet fetches the
/// signed request and answers it, and the applicant reads the evidence —
/// which names the wallet's key beside the applicant and carries no claim.
#[tokio::test]
async fn a_wallet_presentation_becomes_evidence_the_applicant_can_read() {
    let f = fixture().await;

    let (code, body) = start_session(&f, &APPLICANT_SEED, json!({ "criterion": f.digest })).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let started: start::Response = serde_json::from_value(body["payload"].clone()).unwrap();
    let client_id = format!("decentralized_identifier:{TEST_VERIFIER_DID}");
    assert_eq!(started.client_id.as_str(), client_id);
    let session_id = started.session_id.to_string();
    let request_uri = format!("{PUBLIC_URL}/v1/oid4vp/request/{session_id}");
    let expected_uri = format!(
        "swiyu-verify://?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &client_id)
            .append_pair("request_uri", &request_uri)
            .finish()
    );
    assert_eq!(started.wallet_uri, expected_uri);
    // Consumer rule 6: the criterion's query, unchanged.
    assert_eq!(
        Value::Object(started.dcql_query.clone())["credentials"][0]["meta"]["vct_values"][0],
        VCT
    );

    let (code, _) = session_status(&f, &APPLICANT_SEED, &session_id).await;
    assert_eq!(code, StatusCode::OK);

    // The wallet fetches the request object: a JAR signed by the identity's
    // published key, in swiyu's profile.
    let (code, content_type, bytes) = get_request_object(&f, &session_id).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(content_type, "application/oauth-authz-req+jwt");
    let jar = String::from_utf8(bytes).unwrap();
    let header = decode_segment(&jar, 0);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "oauth-authz-req+jwt");
    assert_eq!(header["kid"], format!("{TEST_VERIFIER_DID}#verifier-key-1"));
    assert_eq!(
        header["profile_version"],
        "swiss-profile-verification:1.0.0"
    );
    let identity = oid4vp_test_identity("swiyu", 0x31);
    let request = vta_sdk::jws::JwsKey::from_jwk(&identity.public_jwk)
        .unwrap()
        .verify_compact(&jar)
        .expect("the request object verifies under the published key");
    assert_eq!(request["client_id"], client_id);
    assert_eq!(request["response_mode"], "direct_post.jwt");
    assert_eq!(
        request["response_uri"],
        format!("{PUBLIC_URL}/v1/oid4vp/response/{session_id}")
    );
    assert_eq!(request["aud"], "https://self-issued.me/v2");
    assert_eq!(
        request["client_metadata"]["encrypted_response_enc_values_supported"],
        json!(["A256GCM"])
    );

    // Answered once (consumer rule 7).
    let (code, _, _) = get_request_object(&f, &session_id).await;
    assert_eq!(code, StatusCode::NOT_FOUND);

    let (code, body) = session_status(&f, &APPLICANT_SEED, &session_id).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["payload"]["state"], "requestRetrieved");

    // The wallet answers.
    let nonce = request["nonce"].as_str().unwrap();
    let (holder_did, vp) = presentation(VCT, &client_id, nonce);
    let form = encrypted_response(
        &request,
        &json!({ "vp_token": { "residence": [vp] }, "state": request["state"] }),
    );
    let (code, body) = post_response(&f, &session_id, form.clone()).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body, json!({}));

    // One response per session.
    let (code, body) = post_response(&f, &session_id, form).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");

    // The applicant reads the evidence.
    let (code, body) = session_status(&f, &APPLICANT_SEED, &session_id).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let read: status::Response = serde_json::from_value(body["payload"].clone()).unwrap();
    assert_eq!(read.state, status::ResponseState::Presented);
    let evidence = read.evidence.expect("evidence when presented");
    assert!(evidence.satisfied);
    assert_eq!(evidence.holder.as_str(), holder_did);
    assert_ne!(evidence.holder.as_str(), applicant_did(&APPLICANT_SEED));
    assert_eq!(evidence.credentials.len(), 1);
    assert_eq!(
        evidence.credentials[0].credential_query_id.as_str(),
        "residence"
    );
    assert_eq!(evidence.credentials[0].format.as_str(), "dc+sd-jwt");
    assert_eq!(
        evidence.credentials[0].vct.as_deref().map(|v| v.as_str()),
        Some(VCT)
    );
    assert!(
        evidence.held_until.is_some(),
        "no requestId: held for a submission"
    );
    // Status consumer rule 4: no claim value, anywhere.
    assert!(!body.to_string().contains("Alice"), "{body}");

    // Somebody else holding the session id learns nothing.
    let (code, body) = session_status(&f, &[0x42; 32], &session_id).await;
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        tt_error_code(&body),
        jr::WALLET_SESSION_STATUS_ERR_NOT_FOUND
    );
}

/// A wallet whose holder declines answers with an OpenID4VP error; that is
/// received, and the session ends `refused` with `walletDeclined`.
#[tokio::test]
async fn a_declining_wallet_ends_the_session_refused() {
    let f = fixture().await;
    let (_, body) = start_session(&f, &APPLICANT_SEED, json!({ "criterion": f.digest })).await;
    let session_id = body["payload"]["sessionId"].as_str().unwrap().to_string();
    let (code, body) = post_response(
        &f,
        &session_id,
        "error=access_denied&error_description=declined".into(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let (_, body) = session_status(&f, &APPLICANT_SEED, &session_id).await;
    assert_eq!(body["payload"]["state"], "refused");
    assert_eq!(body["payload"]["reason"], "walletDeclined");
    assert!(body["payload"].get("evidence").is_none());
}

/// A presentation bound to another nonce, or that does not answer the query,
/// is refused — and says which, to the applicant only.
#[tokio::test]
async fn a_presentation_that_does_not_verify_or_satisfy_is_refused() {
    let f = fixture().await;
    let client_id = format!("decentralized_identifier:{TEST_VERIFIER_DID}");

    for (vct, nonce_override, reason) in [
        (VCT, Some("another-nonce"), "presentationInvalid"),
        (
            "https://example.org/credentials/other",
            None,
            "queryNotSatisfied",
        ),
    ] {
        let (_, body) = start_session(&f, &APPLICANT_SEED, json!({ "criterion": f.digest })).await;
        let session_id = body["payload"]["sessionId"].as_str().unwrap().to_string();
        let (_, _, bytes) = get_request_object(&f, &session_id).await;
        let request = decode_segment(&String::from_utf8(bytes).unwrap(), 1);
        let nonce = nonce_override.unwrap_or(request["nonce"].as_str().unwrap());
        let (_, vp) = presentation(vct, &client_id, nonce);
        let form = encrypted_response(
            &request,
            &json!({ "vp_token": { "residence": [vp] }, "state": request["state"] }),
        );
        let (code, _) = post_response(&f, &session_id, form).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{reason}");
        let (_, body) = session_status(&f, &APPLICANT_SEED, &session_id).await;
        assert_eq!(body["payload"]["state"], "refused", "{reason}");
        assert_eq!(body["payload"]["reason"], reason);
    }
}

/// Every code `wallet-session/start/0.1` declares, in the circumstance it
/// names.
#[tokio::test]
async fn the_start_task_answers_with_the_codes_its_spec_declares() {
    let f = fixture().await;
    let refused = |body: &Value| tt_error_code(body).to_string();

    // criterionNotFound
    let (code, body) = start_session(
        &f,
        &APPLICANT_SEED,
        json!({ "criterion": "zQmaf3wtkysZWg8vCzdetBwzjiHACZz8JAxTVr4W66chiXV" }),
    )
    .await;
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        refused(&body),
        jr::WALLET_SESSION_START_ERR_CRITERION_NOT_FOUND
    );

    // noWalletPresentation: a criterion asking for no credential.
    let stored = vtc_service::schemas::accepts::store_accepts(
        &f.vtc.state.schemas_ks,
        &AcceptsCriterion::new("by-review", Admission::Review, "did:key:zAdmin"),
    )
    .await
    .unwrap();
    let plain = vtc_service::routes::join_requests::manifest::manifest_criterion(stored)
        .unwrap()
        .digest;
    let (_, body) = start_session(&f, &APPLICANT_SEED, json!({ "criterion": plain })).await;
    assert_eq!(
        refused(&body),
        jr::WALLET_SESSION_START_ERR_NO_WALLET_PRESENTATION
    );

    // verifierNotConfigured: no identity for the prefix asked for.
    let (_, body) = start_session(
        &f,
        &APPLICANT_SEED,
        json!({ "criterion": f.digest, "clientIdPrefix": "x509_hash" }),
    )
    .await;
    assert_eq!(
        refused(&body),
        jr::WALLET_SESSION_START_ERR_VERIFIER_NOT_CONFIGURED
    );

    // requestNotFound: no such request, and somebody else's.
    let (_, body) = start_session(
        &f,
        &APPLICANT_SEED,
        json!({ "criterion": f.digest, "requestId": Uuid::new_v4().to_string() }),
    )
    .await;
    assert_eq!(
        refused(&body),
        jr::WALLET_SESSION_START_ERR_REQUEST_NOT_FOUND
    );
    let theirs = seed_request(&f, "did:key:zSomebodyElse", JoinStatus::Deferred).await;
    let (_, body) = start_session(
        &f,
        &APPLICANT_SEED,
        json!({ "criterion": f.digest, "requestId": theirs.to_string() }),
    )
    .await;
    assert_eq!(
        refused(&body),
        jr::WALLET_SESSION_START_ERR_REQUEST_NOT_FOUND
    );

    // requestClosed: the applicant's own, decided.
    let decided = seed_request(&f, &applicant_did(&APPLICANT_SEED), JoinStatus::Rejected).await;
    let (_, body) = start_session(
        &f,
        &APPLICANT_SEED,
        json!({ "criterion": f.digest, "requestId": decided.to_string() }),
    )
    .await;
    assert_eq!(refused(&body), jr::WALLET_SESSION_START_ERR_REQUEST_CLOSED);

    // A deferred request of their own takes evidence, and status names it.
    let deferred = seed_request(&f, &applicant_did(&APPLICANT_SEED), JoinStatus::Deferred).await;
    let (code, body) = start_session(
        &f,
        &APPLICANT_SEED,
        json!({ "criterion": f.digest, "requestId": deferred.to_string() }),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let session_id = body["payload"]["sessionId"].as_str().unwrap().to_string();
    let (_, body) = session_status(&f, &APPLICANT_SEED, &session_id).await;
    assert_eq!(body["payload"]["requestId"], deferred.to_string());
}

/// `tooManySessions`: the default bound is three open sessions per applicant.
/// (Its own fixture: the unauthenticated budget is ten documents a burst.)
#[tokio::test]
async fn the_start_task_bounds_an_applicants_open_sessions() {
    let f = fixture().await;
    for _ in 0..3 {
        let (code, body) =
            start_session(&f, &APPLICANT_SEED, json!({ "criterion": f.digest })).await;
        assert_eq!(code, StatusCode::OK, "{body}");
    }
    let (code, body) = start_session(&f, &APPLICANT_SEED, json!({ "criterion": f.digest })).await;
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        tt_error_code(&body),
        jr::WALLET_SESSION_START_ERR_TOO_MANY_SESSIONS
    );
    // Another applicant is not counted against.
    let (code, _) = start_session(&f, &[0x43; 32], json!({ "criterion": f.digest })).await;
    assert_eq!(code, StatusCode::OK);
}

/// A community with no verifier identity installed refuses every session.
#[tokio::test]
async fn a_community_with_no_verifier_identity_opens_no_session() {
    let f = fixture_with(false).await;
    let (code, body) = start_session(&f, &APPLICANT_SEED, json!({ "criterion": f.digest })).await;
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        tt_error_code(&body),
        jr::WALLET_SESSION_START_ERR_VERIFIER_NOT_CONFIGURED
    );
}

/// The wallet endpoints name no session for an id that is not one.
#[tokio::test]
async fn the_wallet_endpoints_refuse_an_unknown_session() {
    let f = fixture().await;
    let (code, _, _) = get_request_object(&f, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    let (code, body) =
        post_response(&f, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "response=x".into()).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

async fn seed_request(f: &Fixture, applicant: &str, status: JoinStatus) -> Uuid {
    let mut request =
        vtc_service::join::JoinRequest::new(applicant.to_string(), json!({"vp": "x"}));
    request.status = status;
    vtc_service::join::storage::store_join_request(&f.vtc.state.join_requests_ks, &request)
        .await
        .unwrap();
    request.id
}
