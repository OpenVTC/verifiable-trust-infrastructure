//! Integration coverage for the cross-community recognise flow.
//!
//! The HTTP `/v1/auth/recognise` route hard-wires a live
//! `DIDCacheClient` for foreign-issuer key resolution, which
//! is impractical to fake in a unit test. We exercise
//! `routes::recognise::mint_recognised_session` directly —
//! it takes an already-`VerifiedForeignCredential` (typestate
//! proof of "this passed the four hardening checks") and is
//! the load-bearing route-level surface. The M3.9 verifier
//! itself has 9 unit tests in `recognition::verify::tests` that
//! cover the four fail-closed checks against
//! mock/stub-backed credentials.
//!
//! Phase 3 M3.10.

use axum::Json;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;

use vtc_service::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
use vtc_service::recognition::VerifiedForeignCredential;
use vtc_service::routes::recognise::{RecogniseResponse, mint_recognised_session};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

struct Fixture {
    state: AppState,
    // Owns the temp data dir + backs `state`; must outlive it.
    _vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().build().await;
    Fixture {
        state: vtc.state.clone(),
        _vtc: vtc,
    }
}

async fn install_cross_community_policy(state: &AppState, source: &str) {
    use sha2::{Digest, Sha256};
    let sha: [u8; 32] = Sha256::digest(source.as_bytes()).into();
    let id = uuid::Uuid::new_v4();
    let policy = Policy {
        id,
        purpose: PolicyPurpose::CrossCommunityRoles,
        rego_source: source.into(),
        sha256: sha,
        activated_at: Some(Utc::now()),
        author_did: "did:key:test".into(),
        created_at: Utc::now(),
        version: 1,
    };
    store_policy(&state.policies_ks, &policy).await.unwrap();
    set_active_policy_id(
        &state.active_policies_ks,
        PolicyPurpose::CrossCommunityRoles,
        id,
    )
    .await
    .unwrap();
}

fn verified(
    issuer: &str,
    subject: &str,
    foreign_role: &str,
    valid_minutes: i64,
) -> VerifiedForeignCredential {
    VerifiedForeignCredential {
        foreign_issuer_did: issuer.into(),
        subject_did: subject.into(),
        foreign_role: foreign_role.into(),
        earliest_valid_until: Utc::now() + Duration::minutes(valid_minutes),
    }
}

async fn body_value(resp: Json<RecogniseResponse>) -> RecogniseResponse {
    resp.0
}

#[tokio::test]
async fn default_deny_policy_rejects_every_mapping() {
    let fix = build().await;
    // Default policy: allow := false, no mapped_role rule.
    let src = "\
package vtc.cross_community_roles
import rego.v1
default allow := false
";
    install_cross_community_policy(&fix.state, src).await;

    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 60);
    let err = mint_recognised_session(&fix.state, v)
        .await
        .expect_err("default deny must reject");
    let resp = err.into_response();
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let resp = resp.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn permissive_policy_mints_session_with_mapped_role() {
    let fix = build().await;
    // Map every foreign role to local `monitor`.
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    let v = verified("did:webvh:peer.example", "did:key:zSub", "admin", 60);
    let resp = mint_recognised_session(&fix.state, v).await.expect("mint");
    let resp = body_value(resp).await;
    assert!(resp.session_id.starts_with("xc-"));
    assert_eq!(resp.data.mapped_role, "monitor");
    assert_eq!(resp.data.foreign_issuer_did, "did:webvh:peer.example");
    assert!(!resp.data.access_token.is_empty());
}

#[tokio::test]
async fn ttl_clamps_to_credentials_when_shorter_than_default() {
    let fix = build().await;
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    // Default access_token_expiry = 900s (15m); credentials
    // only valid for 5 more minutes → clamp to credentials.
    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 5);
    let resp = mint_recognised_session(&fix.state, v).await.expect("mint");
    let resp = body_value(resp).await;
    let now_secs = chrono::Utc::now().timestamp() as u64;
    let ttl = resp.data.access_expires_at - now_secs;
    assert!(
        (260..=305).contains(&ttl),
        "TTL ({ttl}s) should be ~300s (clamped to 5-min credential window)"
    );
}

#[tokio::test]
async fn ttl_clamps_to_default_when_credentials_longer() {
    let fix = build().await;
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    // Credentials valid 1 hour; default expiry 15 min →
    // clamp to default.
    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 60);
    let resp = mint_recognised_session(&fix.state, v).await.expect("mint");
    let resp = body_value(resp).await;
    let now_secs = chrono::Utc::now().timestamp() as u64;
    let ttl = resp.data.access_expires_at - now_secs;
    assert!(
        (880..=905).contains(&ttl),
        "TTL ({ttl}s) should be ~900s (default access_token_expiry)"
    );
}

#[tokio::test]
async fn expired_credentials_rejected_with_zero_window() {
    let fix = build().await;
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    // earliest_valid_until in the past → 0 window → reject.
    let v = VerifiedForeignCredential {
        foreign_issuer_did: "did:webvh:peer.example".into(),
        subject_did: "did:key:zSub".into(),
        foreign_role: "moderator".into(),
        earliest_valid_until: Utc::now() - Duration::seconds(1),
    };
    let err = mint_recognised_session(&fix.state, v)
        .await
        .expect_err("expired credentials must reject");
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        body.contains("expire") || body.contains("validity"),
        "error body should mention expiry: {body}"
    );
}

#[tokio::test]
async fn allow_true_but_no_mapped_role_is_treated_as_deny() {
    let fix = build().await;
    // Operator typo: allows but forgets to set mapped_role.
    // Fail-closed per spec wording.
    let src = "\
package vtc.cross_community_roles
import rego.v1
default allow := true
";
    install_cross_community_policy(&fix.state, src).await;

    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 60);
    let err = mint_recognised_session(&fix.state, v)
        .await
        .expect_err("missing mapped_role must reject even when allow=true");
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn session_row_is_persisted_with_xc_prefix() {
    use vti_common::auth::session::{get_session, list_sessions};
    let fix = build().await;
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    let subject = "did:key:zSessionTest";
    let v = verified("did:webvh:peer.example", subject, "moderator", 60);
    let resp = mint_recognised_session(&fix.state, v).await.expect("mint");
    let resp = body_value(resp).await;

    // Direct read-back: confirm the session row landed in fjall
    // with the xc- prefix and no refresh token.
    let session = get_session(&fix.state.sessions_ks, &resp.session_id)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(session.did, subject);
    assert!(session.session_id.starts_with("xc-"));
    assert!(session.refresh_token.is_none(), "no refresh token");
    // Total sessions in the keyspace should also be 1.
    let all = list_sessions(&fix.state.sessions_ks).await.unwrap();
    assert_eq!(all.len(), 1);
}

#[tokio::test]
async fn missing_active_policy_surfaces_as_internal_error() {
    // No cross_community_roles policy installed at all.
    let fix = build().await;
    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 60);
    let err = mint_recognised_session(&fix.state, v)
        .await
        .expect_err("no active policy must reject");
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let resp = err.into_response();
    // No active policy = 500: this is a misconfigured-daemon
    // path (M2.5 should have installed the default), not a
    // caller-fixable input.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// Route-level coverage for the P0.2-part-2 holder-binding rewrite: the
/// `/v1/auth/recognise` route now demands a holder-signed VP (challenge nonce +
/// audience bound) embedding the VEC + VMC, and refuses unless the VP holder is
/// the credential subject. These drive the real HTTP stack via `oneshot` and a
/// holder-signed `eddsa-jcs-2022` VP, exercising everything up to (but not
/// through) the registry-gated `verify_foreign_vec` — `TestVtc` wires no
/// registry client, so a VP that clears the holder-binding gate fails next at
/// the registry pre-flight, which is exactly how we assert the gate let it pass.
mod holder_binding {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use vta_sdk::protocols::members::VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE;
    use vtc_service::test_support::TestVtc;

    const VTC_DID: &str = "did:key:z6MkTestVTC";
    const RECOGNISE_TASK: &str = "https://trusttasks.org/openvtc/vtc/auth/recognise/1.0";
    const CHALLENGE_TASK: &str = "https://trusttasks.org/openvtc/vtc/auth/recognise/challenge/1.0";

    async fn test_vtc() -> TestVtc {
        // `with_did_resolver` so the route's VP holder/issuer `did:key`
        // resolution is wired; `vtc_did` sets the audience the holder binds.
        TestVtc::builder()
            .vtc_did(VTC_DID)
            .with_did_resolver(true)
            .build()
            .await
    }

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

    async fn sign_vc(issuer_seed: u8, vc_type: &str, subject_did: &str) -> Value {
        use affinidi_data_integrity::{
            DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite,
        };
        let issuer_did = did_for(issuer_seed);
        let mut vc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", vc_type],
            "issuer": issuer_did,
            "validFrom": "2020-01-01T00:00:00Z",
            "validUntil": "2999-01-01T00:00:00Z",
            "credentialSubject": {
                "id": subject_did,
                "endorsement": { "role": "moderator", "communityDid": issuer_did },
            },
        });
        let proof = DataIntegrityProof::sign(
            &vc,
            &secret_for(issuer_seed),
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .unwrap();
        vc["proof"] = serde_json::to_value(&proof).unwrap();
        vc
    }

    /// Build a holder-signed DI VP embedding a foreign VEC + VMC (both issued by
    /// `issuer_seed`, subject `subject_seed`), holder-signed by `holder_seed`
    /// with `proofPurpose: authentication` over `nonce` + `domain = VTC_DID`.
    /// Returns the VP object. When `holder_seed == subject_seed` the holder is
    /// the credential subject (the legitimate case).
    async fn build_vp(issuer_seed: u8, holder_seed: u8, subject_seed: u8, nonce: &str) -> Value {
        use affinidi_data_integrity::{
            DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite,
        };
        let subject_did = did_for(subject_seed);
        let holder_did = did_for(holder_seed);
        let vec = sign_vc(issuer_seed, "VerifiableEndorsementCredential", &subject_did).await;
        // The VMC's wire tag is `MembershipCredential` — NOT
        // `VerifiableMembershipCredential`. The `VERIFIABLE_` prefix lives in the
        // constant's *name* only (it's historical); the tag is what
        // `dtg-credentials` emits and what the VTC stamps, and it's what
        // `routes::recognise` matches on. Hand-rolling the wrong string here made
        // every VP that got as far as the credential lookup 400 with
        // "presentation has no MembershipCredential" — so the three holder-binding
        // assertions below could never be reached. Use the constant, not a literal.
        let vmc = sign_vc(
            issuer_seed,
            VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE,
            &subject_did,
        )
        .await;
        let mut vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [vec, vmc],
            "nonce": nonce,
            "domain": VTC_DID,
        });
        let proof = DataIntegrityProof::sign(
            &vp,
            &secret_for(holder_seed),
            SignOptions::new()
                .with_proof_purpose("authentication")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .unwrap();
        vp["proof"] = serde_json::to_value(&proof).unwrap();
        vp
    }

    async fn post_recognise(router: &axum::Router, vp: &Value) -> (StatusCode, String) {
        let body = json!({ "presentation": vp });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/recognise")
            .header("Trust-Task", RECOGNISE_TASK)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.expect("request");
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Fetch a fresh challenge nonce through the real `/challenge` endpoint.
    async fn fetch_nonce(router: &axum::Router) -> String {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/recognise/challenge")
            .header("Trust-Task", CHALLENGE_TASK)
            .body(Body::empty())
            .unwrap();
        let resp = router
            .clone()
            .oneshot(req)
            .await
            .expect("challenge request");
        assert_eq!(resp.status(), StatusCode::OK, "challenge endpoint must 200");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        v["nonce"].as_str().expect("nonce in response").to_string()
    }

    #[tokio::test]
    async fn challenge_endpoint_issues_a_nonce() {
        let vtc = test_vtc().await;
        let nonce = fetch_nonce(&vtc.router).await;
        assert!(!nonce.is_empty(), "challenge must return a non-empty nonce");
    }

    #[tokio::test]
    async fn presentation_without_a_nonce_is_rejected() {
        let vtc = test_vtc().await;
        // Build a VP then strip its nonce — the handler can't even look up a
        // challenge, so it refuses before any verification.
        let mut vp = build_vp(9, 5, 5, "irrelevant").await;
        vp.as_object_mut().unwrap().remove("nonce");
        let (status, body) = post_recognise(&vtc.router, &vp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("nonce"), "{body}");
    }

    #[tokio::test]
    async fn presentation_with_an_unissued_nonce_is_rejected() {
        let vtc = test_vtc().await;
        // A VP carrying a nonce we never issued: the challenge consume finds
        // nothing. This is the captured-credential replay an attacker would try
        // without first fetching a live challenge.
        let vp = build_vp(9, 5, 5, "never-issued-by-this-vtc").await;
        let (status, body) = post_recognise(&vtc.router, &vp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body.contains("unknown or already consumed"),
            "expected challenge-miss, got: {body}"
        );
    }

    #[tokio::test]
    async fn holder_that_is_not_the_subject_is_rejected() {
        // The headline. Attacker (holder seed 7) captured a victim's (subject
        // seed 5) VEC + VMC and re-wraps them in a VP signed with the
        // attacker's own holder key over a freshly-fetched challenge. The
        // holder proof verifies — but the holder is not the credential subject,
        // so the route must refuse before minting.
        let vtc = test_vtc().await;
        let nonce = fetch_nonce(&vtc.router).await;
        let vp = build_vp(9, 7, 5, &nonce).await;
        let (status, body) = post_recognise(&vtc.router, &vp).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body.contains("holder") && body.contains("subject"),
            "expected holder-binding refusal, got: {body}"
        );
    }

    #[tokio::test]
    async fn matching_holder_clears_the_binding_gate() {
        // The legitimate case: holder == subject (seed 5). The holder-binding
        // gate must let it through — it then fails at the registry pre-flight
        // (TestVtc wires no registry client), proving the request got *past*
        // the binding gate rather than being wrongly 403'd.
        let vtc = test_vtc().await;
        let nonce = fetch_nonce(&vtc.router).await;
        let vp = build_vp(9, 5, 5, &nonce).await;
        let (status, body) = post_recognise(&vtc.router, &vp).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "a matching holder must not be refused by the binding gate: {body}"
        );
        assert!(
            body.contains("trust-registry client not configured"),
            "expected to reach the registry gate, got {status}: {body}"
        );
    }

    #[tokio::test]
    async fn a_consumed_challenge_cannot_be_replayed() {
        // Single-use: present the same (attacker) VP twice on one nonce. The
        // first consumes the challenge (and is refused at the holder-binding
        // gate); the replay finds the nonce already consumed.
        let vtc = test_vtc().await;
        let nonce = fetch_nonce(&vtc.router).await;
        let vp = build_vp(9, 7, 5, &nonce).await;

        let (first, _) = post_recognise(&vtc.router, &vp).await;
        assert_eq!(
            first,
            StatusCode::FORBIDDEN,
            "first present: holder-binding"
        );

        let (second, body) = post_recognise(&vtc.router, &vp).await;
        assert_eq!(second, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body.contains("unknown or already consumed"),
            "replay must hit the single-use challenge guard: {body}"
        );
    }

    #[tokio::test]
    async fn a_tampered_holder_proof_is_rejected() {
        // Mutate a credential claim after the VP was signed: the embedded VC is
        // covered by the holder's VP proof, so the holder-proof verification
        // fails — no presentation with any altered byte survives.
        let vtc = test_vtc().await;
        let nonce = fetch_nonce(&vtc.router).await;
        let mut vp = build_vp(9, 5, 5, &nonce).await;
        vp["verifiableCredential"][0]["credentialSubject"]["endorsement"]["role"] = json!("admin");
        let (status, body) = post_recognise(&vtc.router, &vp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body.contains("verify"),
            "expected proof-failure, got: {body}"
        );
    }
}
