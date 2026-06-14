//! Tests for the credential-exchange submodules. Driven through the
//! re-exported public surface (`use super::*`).

use super::*;
// Names the original single-file test module reached via `use super::*` when
// the parent (exchange.rs) still held all the imports + private consts.
use super::issue::{OID4VCI_PROOF_TYP, PROOF_MAX_AGE_SECS};
use affinidi_openid4vci::{CredentialRequest, CredentialRequestProof, FORMAT_SD_JWT_VC};
use affinidi_sd_jwt::error::SdJwtError;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

const ISSUER: &str = "did:web:vtc.example";

/// A holder identity: an Ed25519 key + its `did:key`.
struct Holder {
    key: SigningKey,
    did: String,
}
impl Holder {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(key.verifying_key().as_bytes());
        Self { key, did }
    }

    /// Build an OID4VCI proof JWT (`openid4vci-proof+jwt`) signed by this
    /// holder, with the given `aud` / `iat` / `nonce`.
    fn proof_jwt(&self, aud: &str, iat: i64, nonce: Option<&str>) -> String {
        let header = json!({
            "typ": OID4VCI_PROOF_TYP,
            "alg": "EdDSA",
            "kid": format!("{}#key-0", self.did),
        });
        let mut payload = json!({ "iss": self.did, "aud": aud, "iat": iat });
        if let Some(n) = nonce {
            payload["nonce"] = json!(n);
        }
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
}

fn request_with(proof_jwt: String) -> CredentialRequest {
    CredentialRequest {
        format: FORMAT_SD_JWT_VC.to_string(),
        vct: Some("https://openvtc.org/credentials/MembershipCredential".into()),
        doctype: None,
        proof: Some(CredentialRequestProof {
            proof_type: "jwt".into(),
            jwt: proof_jwt,
        }),
        credential_identifier: None,
    }
}

fn a_credential() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "MembershipCredential"],
        "issuer": ISSUER,
        "credentialSubject": { "id": "did:example:member" }
    })
}

#[test]
fn verifies_a_fresh_holder_proof() {
    let holder = Holder::new(7);
    let now = Utc::now();
    let jwt = holder.proof_jwt(ISSUER, now.timestamp(), Some("n-1"));
    let proven = verify_oid4vci_proof(&jwt, ISSUER, now).expect("verify proof");
    assert_eq!(proven.holder_did, holder.did);
    assert_eq!(proven.nonce.as_deref(), Some("n-1"));
}

#[test]
fn issues_to_the_bound_holder() {
    let holder = Holder::new(11);
    let now = Utc::now();
    let req = request_with(holder.proof_jwt(ISSUER, now.timestamp(), None));
    let resp = issue_on_request(&req, a_credential(), &holder.did, ISSUER, now)
        .expect("issue to bound holder");
    assert_eq!(resp.credential, Some(a_credential()));
}

#[test]
fn refuses_when_the_proof_binds_a_different_holder() {
    let bound = Holder::new(1);
    let attacker = Holder::new(2);
    let now = Utc::now();
    // The attacker signs a perfectly valid proof — for *their own* DID.
    let req = request_with(attacker.proof_jwt(ISSUER, now.timestamp(), None));
    let err = issue_on_request(&req, a_credential(), &bound.did, ISSUER, now).unwrap_err();
    assert!(
        matches!(err, AppError::Forbidden(_)),
        "wrong-holder redemption must be Forbidden, got {err:?}"
    );
}

#[test]
fn refuses_a_proof_for_another_audience() {
    let holder = Holder::new(3);
    let now = Utc::now();
    let jwt = holder.proof_jwt("did:web:other.example", now.timestamp(), None);
    let err = verify_oid4vci_proof(&jwt, ISSUER, now).unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("aud")),
        "{err:?}"
    );
}

#[test]
fn refuses_a_stale_proof() {
    let holder = Holder::new(4);
    let now = Utc::now();
    let stale = now.timestamp() - (PROOF_MAX_AGE_SECS + 60);
    let err =
        verify_oid4vci_proof(&holder.proof_jwt(ISSUER, stale, None), ISSUER, now).unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("stale")),
        "{err:?}"
    );
}

#[test]
fn refuses_a_tampered_signature() {
    let holder = Holder::new(5);
    let now = Utc::now();
    let mut jwt = holder.proof_jwt(ISSUER, now.timestamp(), None);
    // Flip the last signature character.
    let last = jwt.pop().unwrap();
    jwt.push(if last == 'A' { 'B' } else { 'A' });
    let err = verify_oid4vci_proof(&jwt, ISSUER, now).unwrap_err();
    assert!(matches!(err, AppError::Validation(_)), "{err:?}");
}

#[test]
fn refuses_a_request_with_no_proof() {
    let now = Utc::now();
    let req = CredentialRequest {
        format: FORMAT_SD_JWT_VC.to_string(),
        vct: Some("https://openvtc.org/credentials/MembershipCredential".into()),
        doctype: None,
        proof: None,
        credential_identifier: None,
    };
    let err = issue_on_request(&req, a_credential(), "did:key:zHolder", ISSUER, now).unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("no key-binding proof")),
        "{err:?}"
    );
}

#[test]
fn refuses_a_non_did_key_holder_proof_for_now() {
    // A structurally-valid proof whose kid is a did:web — resolver deferred.
    let now = Utc::now();
    let header =
        json!({ "typ": OID4VCI_PROOF_TYP, "alg": "EdDSA", "kid": "did:web:holder.example#k" });
    let payload = json!({ "aud": ISSUER, "iat": now.timestamp() });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    // Signature is irrelevant — the kid is rejected before verification.
    let jwt = format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode([0u8; 64]));
    let err = verify_oid4vci_proof(&jwt, ISSUER, now).unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("did:key")),
        "{err:?}"
    );
}

#[test]
fn offer_is_pre_authorized() {
    let offer = credential_offer(
        ISSUER,
        vec!["MembershipCredential".into()],
        "code-xyz".into(),
    );
    assert_eq!(offer.credential_issuer, ISSUER);
    assert_eq!(
        offer.credential_configuration_ids,
        vec!["MembershipCredential"]
    );
    let grant = offer.grants.unwrap().pre_authorized_code.unwrap();
    assert_eq!(grant.pre_authorized_code, "code-xyz");
}

// ── pending-offer store + redeem flow ──

fn fresh_ks() -> (tempfile::TempDir, vti_common::store::Store, KeyspaceHandle) {
    let dir = tempfile::tempdir().unwrap();
    let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .unwrap();
    let ks = store.keyspace("join_requests").unwrap();
    (dir, store, ks)
}

#[tokio::test]
async fn make_offer_then_redeem_delivers_and_consumes() {
    let (_d, _s, ks) = fresh_ks();
    let holder = Holder::new(30);
    let now = Utc::now();

    let (offer, code) = make_offer(
        &ks,
        ISSUER,
        vec!["MembershipCredential".into()],
        a_credential(),
        &holder.did,
        DEFAULT_OFFER_TTL,
        now,
    )
    .await
    .expect("make offer");
    // The offer advertises the same pre-authorized code we persisted.
    assert_eq!(
        offer
            .grants
            .unwrap()
            .pre_authorized_code
            .unwrap()
            .pre_authorized_code,
        code
    );

    // Holder redeems: proof nonce == the pre-authorized code.
    let req = request_with(holder.proof_jwt(ISSUER, now.timestamp(), Some(&code)));
    let resp = redeem(&ks, &req, now).await.expect("redeem");
    assert_eq!(resp.credential, Some(a_credential()));

    // Single-use: the offer is consumed.
    let again = redeem(&ks, &req, now).await.unwrap_err();
    assert!(matches!(again, AppError::NotFound(_)), "{again:?}");
}

#[tokio::test]
async fn sweep_expired_pending_removes_only_expired() {
    let (_d, _s, ks) = fresh_ks();
    let holder = Holder::new(40);
    let now = Utc::now();
    // Expired offer: made an hour ago with the 30-min TTL.
    make_offer(
        &ks,
        ISSUER,
        vec!["MembershipCredential".into()],
        a_credential(),
        &holder.did,
        DEFAULT_OFFER_TTL,
        now - Duration::hours(1),
    )
    .await
    .expect("expired offer");
    // Fresh offer: made now → survives.
    make_offer(
        &ks,
        ISSUER,
        vec!["MembershipCredential".into()],
        a_credential(),
        &holder.did,
        DEFAULT_OFFER_TTL,
        now,
    )
    .await
    .expect("fresh offer");

    let purged = sweep_expired_pending(&ks, now).await.unwrap();
    assert_eq!(purged, 1, "only the expired offer should be purged");

    let remaining = ks
        .prefix_iter_raw(b"credx-pending:".to_vec())
        .await
        .unwrap()
        .len();
    assert_eq!(remaining, 1, "the fresh offer survives");
}

#[tokio::test]
async fn redeem_rejects_unknown_code() {
    let (_d, _s, ks) = fresh_ks();
    let holder = Holder::new(31);
    let now = Utc::now();
    let req = request_with(holder.proof_jwt(ISSUER, now.timestamp(), Some("pac_missing")));
    let err = redeem(&ks, &req, now).await.unwrap_err();
    assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
}

#[tokio::test]
async fn redeem_rejects_an_expired_offer() {
    let (_d, _s, ks) = fresh_ks();
    let holder = Holder::new(32);
    let issued = Utc::now();
    let (_offer, code) = make_offer(
        &ks,
        ISSUER,
        vec!["m".into()],
        a_credential(),
        &holder.did,
        Duration::seconds(1),
        issued,
    )
    .await
    .unwrap();

    let later = issued + Duration::seconds(30);
    let req = request_with(holder.proof_jwt(ISSUER, later.timestamp(), Some(&code)));
    let err = redeem(&ks, &req, later).await.unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("expired")),
        "{err:?}"
    );
}

#[tokio::test]
async fn redeem_refuses_wrong_holder_without_burning_the_offer() {
    let (_d, _s, ks) = fresh_ks();
    let bound = Holder::new(33);
    let attacker = Holder::new(34);
    let now = Utc::now();
    let (_offer, code) = make_offer(
        &ks,
        ISSUER,
        vec!["m".into()],
        a_credential(),
        &bound.did,
        DEFAULT_OFFER_TTL,
        now,
    )
    .await
    .unwrap();

    // Attacker signs a valid proof for *their own* DID, echoing the code.
    let bad = request_with(attacker.proof_jwt(ISSUER, now.timestamp(), Some(&code)));
    let err = redeem(&ks, &bad, now).await.unwrap_err();
    assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");

    // The legitimate offer was NOT consumed — the real holder still redeems.
    let good = request_with(bound.proof_jwt(ISSUER, now.timestamp(), Some(&code)));
    assert!(redeem(&ks, &good, now).await.is_ok());
}

// ── verify_presentation (task 3.4) ──

const MEMBERSHIP_VCT: &str = "https://openvtc.org/credentials/MembershipCredential";

/// An Ed25519 SD-JWT signer (issuer or holder).
struct SdSigner {
    key: SigningKey,
    kid: String,
}
impl affinidi_sd_jwt::signer::JwtSigner for SdSigner {
    fn algorithm(&self) -> &str {
        "EdDSA"
    }
    fn key_id(&self) -> Option<&str> {
        Some(&self.kid)
    }
    fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
        let h = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(header).map_err(|e| SdJwtError::Verification(e.to_string()))?,
        );
        let p = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(payload).map_err(|e| SdJwtError::Verification(e.to_string()))?,
        );
        let input = format!("{h}.{p}");
        let sig: Signature = self.key.sign(input.as_bytes());
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        ))
    }
}

fn okp_jwk(vk: &VerifyingKey) -> Value {
    json!({ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()) })
}

/// Issue an SD-JWT-VC (issuer seed 9, holder seed 5, `givenName` disclosable)
/// and present it. Returns `(issuer_did, vp_token)`. With `with_kb`, the
/// presentation carries a holder kb-jwt bound to `aud` + `nonce`.
fn make_presentation(aud: &str, nonce: &str, iat: u64, exp: i64, with_kb: bool) -> (String, Value) {
    use affinidi_sd_jwt::holder::{KbJwtInput, present, select_disclosures};

    let issuer = SigningKey::from_bytes(&[9u8; 32]);
    let issuer_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(issuer.verifying_key().as_bytes());
    let issuer_signer = SdSigner {
        key: SigningKey::from_bytes(&[9u8; 32]),
        kid: format!("{issuer_did}#key-0"),
    };

    let holder = SigningKey::from_bytes(&[5u8; 32]);
    let holder_vk = holder.verifying_key();
    let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(holder_vk.as_bytes());
    let holder_signer = SdSigner {
        key: SigningKey::from_bytes(&[5u8; 32]),
        kid: format!(
            "{holder_did}#{}",
            holder_did.strip_prefix("did:key:").unwrap()
        ),
    };

    let claims = json!({
        "iss": issuer_did, "sub": holder_did, "vct": MEMBERSHIP_VCT,
        "iat": iat, "exp": exp, "givenName": "Alice"
    });
    let frame = json!({ "_sd": ["givenName"] });
    let hasher = Sha256Hasher;
    let holder_jwk = okp_jwk(&holder_vk);
    let sd =
        affinidi_sd_jwt::issuer::issue(&claims, &frame, &issuer_signer, &hasher, Some(&holder_jwk))
            .unwrap();
    let selected = select_disclosures(&sd, &["givenName"]);
    let kb = KbJwtInput {
        audience: aud,
        nonce,
        signer: &holder_signer,
        iat,
    };
    let presentation = present(
        &sd,
        &selected,
        if with_kb { Some(&kb) } else { None },
        &hasher,
    )
    .unwrap();
    (issuer_did, json!(presentation.serialize()))
}

/// Like [`make_presentation`] but parameterized on the holder seed + `vct`,
/// returning the holder DID too. Lets a test build a multi-credential
/// `vp_token` and exercise the holder-consistency check.
fn make_presentation_holder(
    holder_seed: u8,
    vct: &str,
    aud: &str,
    nonce: &str,
    iat: u64,
    exp: i64,
) -> (String, String, Value) {
    use affinidi_sd_jwt::holder::{KbJwtInput, present, select_disclosures};

    let issuer = SigningKey::from_bytes(&[9u8; 32]);
    let issuer_did =
        affinidi_crypto::did_key::ed25519_pub_to_did_key(issuer.verifying_key().as_bytes());
    let issuer_signer = SdSigner {
        key: SigningKey::from_bytes(&[9u8; 32]),
        kid: format!("{issuer_did}#key-0"),
    };

    let holder = SigningKey::from_bytes(&[holder_seed; 32]);
    let holder_vk = holder.verifying_key();
    let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(holder_vk.as_bytes());
    let holder_signer = SdSigner {
        key: SigningKey::from_bytes(&[holder_seed; 32]),
        kid: format!(
            "{holder_did}#{}",
            holder_did.strip_prefix("did:key:").unwrap()
        ),
    };

    let claims = json!({
        "iss": issuer_did, "sub": holder_did, "vct": vct,
        "iat": iat, "exp": exp, "givenName": "Alice"
    });
    let frame = json!({ "_sd": ["givenName"] });
    let hasher = Sha256Hasher;
    let holder_jwk = okp_jwk(&holder_vk);
    let sd =
        affinidi_sd_jwt::issuer::issue(&claims, &frame, &issuer_signer, &hasher, Some(&holder_jwk))
            .unwrap();
    let selected = select_disclosures(&sd, &["givenName"]);
    let kb = KbJwtInput {
        audience: aud,
        nonce,
        signer: &holder_signer,
        iat,
    };
    let presentation = present(&sd, &selected, Some(&kb), &hasher).unwrap();
    (issuer_did, holder_did, json!(presentation.serialize()))
}

/// Emit valid seed-corpus fixtures for the credential-exchange parser fuzz
/// targets (issue #439, item 6): an SD-JWT-VC presentation, the OID4VP DCQL
/// `vp_token` shapes (bare string + map), and an OID4VCI key-binding proof
/// JWT. The sealed-transfer-armor + bootstrap-request seeds come from the
/// sibling `vta-sdk/examples/gen_fuzz_seeds.rs` generator.
///
/// `#[ignore]`d so it never runs in normal CI — invoke it on demand to
/// regenerate the committed seeds:
/// ```bash
/// VTC_SKIP_ADMIN_UI_BUILD=1 cargo test -p vtc-service \
///     --lib credentials::exchange::tests::gen_fuzz_seed_corpus -- --ignored
/// ```
#[test]
#[ignore = "fixture generator — run on demand to refresh fuzz/seeds"]
fn gen_fuzz_seed_corpus() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vtc-service has a parent (the workspace root)")
        .join("fuzz")
        .join("seeds");
    let sd_dir = root.join("sd-jwt-presentation");
    let vp_dir = root.join("vp-token");
    let proof_dir = root.join("oid4vci-proof");
    for d in [&sd_dir, &vp_dir, &proof_dir] {
        std::fs::create_dir_all(d).unwrap();
    }

    let aud = "did:web:vtc.example";
    let nonce = "fuzz-seed-nonce";
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();

    // A single SD-JWT-VC presentation: the compact string (for the
    // `parse_sd_jwt_presentation` target) and the bare-string `vp_token`
    // JSON (for the `flatten_vp_token` / `verify_vp_token` target).
    let (_issuer, vp) = make_presentation(aud, nonce, iat, exp, true);
    let compact = vp.as_str().unwrap();
    std::fs::write(sd_dir.join("membership.sdjwt"), compact).unwrap();
    std::fs::write(
        vp_dir.join("single-presentation.json"),
        serde_json::to_vec(&vp).unwrap(),
    )
    .unwrap();

    // A DCQL `vp_token` map: two presentations from the same holder under
    // distinct query ids.
    let (_i1, _h1, vp_membership) =
        make_presentation_holder(5, MEMBERSHIP_VCT, aud, nonce, iat, exp);
    let (_i2, _h2, vp_invitation) = make_presentation_holder(
        5,
        "https://openvtc.org/credentials/Invitation",
        aud,
        nonce,
        iat,
        exp,
    );
    let dcql = json!({ "membership": vp_membership, "invitation": vp_invitation });
    std::fs::write(
        vp_dir.join("dcql-map.json"),
        serde_json::to_vec(&dcql).unwrap(),
    )
    .unwrap();

    // An OID4VCI key-binding proof JWT (the `verify_oid4vci_proof` target).
    let holder = Holder::new(7);
    let proof = holder.proof_jwt(ISSUER, now.timestamp(), Some("fuzz-seed-cnonce"));
    std::fs::write(proof_dir.join("holder-proof.jwt"), proof).unwrap();

    eprintln!(
        "wrote credential-exchange fuzz seeds under {}",
        root.display()
    );
}

#[tokio::test]
async fn verify_vp_token_verifies_a_dcql_map() {
    let aud = "did:web:vtc.example";
    let nonce = "verifier-nonce-multi";
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();

    // Two presentations from the SAME holder under different query ids.
    let (_i1, holder_did, vp_membership) =
        make_presentation_holder(5, MEMBERSHIP_VCT, aud, nonce, iat, exp);
    let (_i2, _h2, vp_invitation) = make_presentation_holder(
        5,
        "https://openvtc.org/credentials/InvitationCredential",
        aud,
        nonce,
        iat,
        exp,
    );
    let vp_token = json!({ "membership": vp_membership, "invitation": vp_invitation });

    let set = verify_vp_token(&vp_token, aud, nonce, None, now)
        .await
        .expect("verify map");
    assert_eq!(set.holder, holder_did);
    assert_eq!(set.presentations.len(), 2);
    assert_eq!(set.presentations[0].claims["givenName"], "Alice");
}

#[tokio::test]
async fn verify_vp_token_accepts_a_bare_string() {
    let aud = "did:web:vtc.example";
    let nonce = "n";
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();
    let (_did, vp) = make_presentation(aud, nonce, iat, exp, true);

    let set = verify_vp_token(&vp, aud, nonce, None, now)
        .await
        .expect("verify bare string");
    assert_eq!(set.presentations.len(), 1);
}

#[tokio::test]
async fn verify_vp_token_rejects_mixed_holders() {
    let aud = "did:web:vtc.example";
    let nonce = "n";
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();

    // Two presentations from DIFFERENT holders (seeds 5 and 6).
    let (_i1, _h1, vp_a) = make_presentation_holder(5, MEMBERSHIP_VCT, aud, nonce, iat, exp);
    let (_i2, _h2, vp_b) = make_presentation_holder(6, MEMBERSHIP_VCT, aud, nonce, iat, exp);
    let vp_token = json!({ "a": vp_a, "b": vp_b });

    let err = verify_vp_token(&vp_token, aud, nonce, None, now)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("disagree on the holder")),
        "{err:?}"
    );
}

/// Build a holder-bound W3C Data-Integrity VP (the shape the VTA's
/// `present_di_vc` produces): a single `eddsa-jcs-2022`-signed VC wrapped in a
/// VP carrying `nonce` + `domain`, signed by the holder with `proofPurpose`
/// `authentication`. Returns `(holder_did, issuer_did, vp_object)`.
async fn build_di_vp(
    holder_seed: u8,
    issuer_seed: u8,
    aud: &str,
    nonce: &str,
) -> (String, String, Value) {
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
    use affinidi_secrets_resolver::secrets::Secret;

    let issuer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
        &SigningKey::from_bytes(&[issuer_seed; 32])
            .verifying_key()
            .to_bytes(),
    );
    let issuer_vm = format!(
        "{issuer_did}#{}",
        issuer_did.strip_prefix("did:key:").unwrap()
    );
    let issuer_secret = Secret::generate_ed25519(Some(&issuer_vm), Some(&[issuer_seed; 32]));

    let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
        &SigningKey::from_bytes(&[holder_seed; 32])
            .verifying_key()
            .to_bytes(),
    );
    let holder_vm = format!(
        "{holder_did}#{}",
        holder_did.strip_prefix("did:key:").unwrap()
    );
    let holder_secret = Secret::generate_ed25519(Some(&holder_vm), Some(&[holder_seed; 32]));

    // Issuer-signed VC.
    let mut vc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "MembershipCredential"],
        "issuer": issuer_did,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": { "id": holder_did, "givenName": "Alice" }
    });
    let vc_proof = DataIntegrityProof::sign(
        &vc,
        &issuer_secret,
        SignOptions::new()
            .with_proof_purpose("assertionMethod")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .unwrap();
    vc["proof"] = serde_json::to_value(&vc_proof).unwrap();

    // Holder-signed VP carrying nonce + domain.
    let mut vp = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": [vc],
        "nonce": nonce,
        "domain": aud,
    });
    let vp_proof = DataIntegrityProof::sign(
        &vp,
        &holder_secret,
        SignOptions::new()
            .with_proof_purpose("authentication")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .unwrap();
    vp["proof"] = serde_json::to_value(&vp_proof).unwrap();

    (holder_did, issuer_did, vp)
}

#[tokio::test]
async fn verify_vp_token_verifies_a_w3c_di_vp() {
    let aud = "did:web:vtc.example";
    let nonce = "verifier-nonce-di";
    let now = Utc::now();
    let (holder_did, issuer_did, vp) = build_di_vp(5, 9, aud, nonce).await;
    let vp_token = json!({ "membership": vp });

    let set = verify_vp_token(&vp_token, aud, nonce, None, now)
        .await
        .expect("verify DI VP");
    assert_eq!(set.holder, holder_did);
    assert_eq!(set.presentations.len(), 1);
    assert_eq!(set.presentations[0].issuer_did, issuer_did);
    assert_eq!(
        set.presentations[0].vct.as_deref(),
        Some("MembershipCredential")
    );
    assert_eq!(set.presentations[0].claims["givenName"], "Alice");
}

#[tokio::test]
async fn verify_vp_token_rejects_a_di_vp_with_a_wrong_nonce() {
    let aud = "did:web:vtc.example";
    let now = Utc::now();
    let (_h, _i, vp) = build_di_vp(5, 9, aud, "right-nonce").await;
    let vp_token = json!({ "membership": vp });

    // The VP's holder proof is valid, but it binds a different nonce.
    let err = verify_vp_token(&vp_token, aud, "wrong-nonce", None, now)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("nonce")),
        "{err:?}"
    );
}

#[tokio::test]
async fn verify_vp_token_rejects_a_di_vp_with_a_tampered_claim() {
    let aud = "did:web:vtc.example";
    let nonce = "n";
    let now = Utc::now();
    let (_h, _i, mut vp) = build_di_vp(5, 9, aud, nonce).await;
    // Tamper a credential subject claim. The embedded VC is covered by the
    // holder's VP proof, so the tamper is caught at the holder-proof stage —
    // defence in depth (no presentation with any altered byte verifies).
    vp["verifiableCredential"][0]["credentialSubject"]["givenName"] = json!("Mallory");
    let vp_token = json!({ "membership": vp });

    let err = verify_vp_token(&vp_token, aud, nonce, None, now)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("did not verify")),
        "{err:?}"
    );
}

#[tokio::test]
async fn verify_vp_token_rejects_a_di_vc_signed_outside_its_issuer() {
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
    use affinidi_secrets_resolver::secrets::Secret;

    let aud = "did:web:vtc.example";
    let nonce = "n";
    let now = Utc::now();
    let (_h, _i, mut vp) = build_di_vp(5, 9, aud, nonce).await;
    // Re-label the VC `issuer` to a DID that did not sign the VC's proof, then
    // re-sign the VP so the holder proof stays valid — the issuer-binding
    // check must then refuse it.
    vp["verifiableCredential"][0]["issuer"] = json!("did:web:attacker.example");
    let holder_did = vp["holder"].as_str().unwrap().to_string();
    let holder_vm = format!(
        "{holder_did}#{}",
        holder_did.strip_prefix("did:key:").unwrap()
    );
    let holder_secret = Secret::generate_ed25519(Some(&holder_vm), Some(&[5u8; 32]));
    let mut unsigned = vp.clone();
    unsigned.as_object_mut().unwrap().remove("proof");
    let proof = DataIntegrityProof::sign(
        &unsigned,
        &holder_secret,
        SignOptions::new()
            .with_proof_purpose("authentication")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .unwrap();
    vp["proof"] = serde_json::to_value(&proof).unwrap();
    let vp_token = json!({ "membership": vp });

    let err = verify_vp_token(&vp_token, aud, nonce, None, now)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("not under the issuer")),
        "{err:?}"
    );
}

#[tokio::test]
async fn verify_vp_token_rejects_an_empty_object() {
    let now = Utc::now();
    let err = verify_vp_token(&json!({}), "did:web:vtc.example", "n", None, now)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("empty object")),
        "{err:?}"
    );
}

#[tokio::test]
async fn verify_vp_token_propagates_a_wrong_nonce() {
    let aud = "did:web:vtc.example";
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();
    let (_i, _h, vp) = make_presentation_holder(5, MEMBERSHIP_VCT, aud, "right", iat, exp);
    let vp_token = json!({ "membership": vp });

    // A presentation bound to a different nonce than the verifier expects.
    assert!(
        verify_vp_token(&vp_token, aud, "wrong", None, now)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn verifies_a_well_formed_presentation() {
    let aud = "did:web:vtc.example";
    let nonce = "verifier-nonce-1";
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();
    let (issuer_did, vp) = make_presentation(aud, nonce, iat, exp, true);

    let verified = verify_presentation(&vp, aud, nonce, None, now)
        .await
        .expect("verify");
    assert_eq!(verified.issuer_did, issuer_did);
    assert_eq!(verified.vct.as_deref(), Some(MEMBERSHIP_VCT));
    assert_eq!(verified.claims["givenName"], "Alice");
}

#[test]
fn parse_core_extracts_a_well_formed_presentation_without_io() {
    // `parse_sd_jwt_presentation` is the sync, resolver-free fuzz target —
    // it must extract the structural projection of a valid presentation
    // (the proven holder DID, issuer binding) with no clock and no network.
    let aud = "did:web:vtc.example";
    let nonce = "n";
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();
    let (issuer_did, vp) = make_presentation(aud, nonce, iat, exp, true);

    let parsed = parse_sd_jwt_presentation(vp.as_str().unwrap()).expect("parse");
    assert_eq!(parsed.issuer_did, issuer_did);
    assert!(parsed.holder_did.starts_with("did:key:"));
    // The issuer VM sits under `iss`.
    assert_eq!(
        parsed.issuer_vm.split('#').next().unwrap(),
        parsed.issuer_did
    );
}

#[test]
fn parse_core_refuses_an_unbound_presentation() {
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();
    let (_did, vp) = make_presentation("did:web:vtc.example", "n", iat, exp, false);

    let err = parse_sd_jwt_presentation(vp.as_str().unwrap()).unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("kb-jwt")),
        "{err:?}"
    );
}

#[test]
fn parse_core_rejects_garbage_without_panicking() {
    // The fuzz target's whole point: arbitrary bytes return an error, never
    // a panic.
    for junk in ["", "~", "not.a.jwt", "a~b~c", "\u{0}\u{1}\u{2}"] {
        assert!(parse_sd_jwt_presentation(junk).is_err(), "junk: {junk:?}");
    }
}

#[test]
fn flatten_vp_token_shreds_the_dcql_envelope_shapes() {
    // Bare string → one entry.
    assert_eq!(flatten_vp_token(&json!("compact-sd-jwt")).unwrap().len(), 1);
    // Object with scalar + array values → flattened across query ids.
    let dcql = json!({ "q1": "p1", "q2": ["p2", "p3"] });
    assert_eq!(flatten_vp_token(&dcql).unwrap().len(), 3);
    // Empty object and non-string/object scalars are refused.
    assert!(flatten_vp_token(&json!({})).is_err());
    assert!(flatten_vp_token(&json!(42)).is_err());
    assert!(flatten_vp_token(&json!(null)).is_err());
}

#[tokio::test]
async fn rejects_a_wrong_nonce_or_audience() {
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();
    let (_did, vp) = make_presentation("did:web:vtc.example", "right-nonce", iat, exp, true);

    assert!(
        verify_presentation(&vp, "did:web:vtc.example", "wrong-nonce", None, now)
            .await
            .is_err()
    );
    assert!(
        verify_presentation(&vp, "did:web:attacker.example", "right-nonce", None, now)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_an_expired_presentation() {
    let now = Utc::now();
    let iat = (now - Duration::hours(3)).timestamp() as u64;
    let exp = (now - Duration::hours(2)).timestamp();
    let (_did, vp) = make_presentation("did:web:vtc.example", "n", iat, exp, true);

    let err = verify_presentation(&vp, "did:web:vtc.example", "n", None, now)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("expired")),
        "{err:?}"
    );
}

#[tokio::test]
async fn rejects_an_unbound_presentation_without_a_kb_jwt() {
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();
    let (_did, vp) = make_presentation("did:web:vtc.example", "n", iat, exp, false);

    let err = verify_presentation(&vp, "did:web:vtc.example", "n", None, now)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AppError::Validation(m) if m.contains("kb-jwt")),
        "{err:?}"
    );
}

#[tokio::test]
async fn rejects_a_tampered_issuer_signature() {
    let aud = "did:web:vtc.example";
    let nonce = "n";
    let now = Utc::now();
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::hours(1)).timestamp();
    let (_did, vp) = make_presentation(aud, nonce, iat, exp, true);

    // Flip the last char of the issuer JWS (the segment before the first `~`)
    // — its signature no longer covers the header.payload bytes.
    let compact = vp.as_str().unwrap();
    let tilde = compact.find('~').unwrap();
    let mut chars: Vec<char> = compact.chars().collect();
    let i = tilde - 1;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();

    assert!(
        verify_presentation(&json!(tampered), aud, nonce, None, now)
            .await
            .is_err()
    );
}

// ---- bbs-2023 verifier (feature `bbs`) ------------------------------

#[cfg(feature = "bbs")]
fn bbs_derived_presentation(nonce: &str, subject: &str, disclose: &[&str]) -> (Value, String) {
    use affinidi_bbs as bbs;
    use affinidi_data_integrity::bbs_2023_transform::{create_derived_proof, sign_base_document};

    let sk = bbs::keygen(b"vtc-bbs-verify-key-material-32by", b"").unwrap();
    let pk = bbs::sk_to_pk(&sk);
    let issuer_did = affinidi_crypto::bls12381::g2_pub_to_did_key(&pk.to_bytes());
    let vc = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "type": ["VerifiableCredential", "MembershipCredential"],
        "issuer": issuer_did,
        "validFrom": "2020-01-01T00:00:00Z",
        "validUntil": "2100-01-01T00:00:00Z",
        "credentialSubject": { "id": subject, "memberLevel": "gold", "secret": "hidden" }
    });
    let mandatory = ["/@context", "/type", "/issuer", "/credentialSubject/id"];
    let base = sign_base_document(
        &vc,
        &mandatory,
        &format!("{issuer_did}#bbs-key-0"),
        "2020-01-01T00:00:00Z",
        &sk,
        &pk,
        b"vtc-bbs-test-hmac-key-32-bytes!!",
    )
    .unwrap();
    let derived = create_derived_proof(&base, disclose, nonce.as_bytes(), &pk).unwrap();
    (derived, issuer_did)
}

#[cfg(feature = "bbs")]
#[tokio::test]
async fn verify_vp_token_accepts_a_bbs_2023_presentation() {
    let nonce = "vtc-challenge-xyz";
    let subject = "did:key:zApplicant";
    let (derived, issuer_did) =
        bbs_derived_presentation(nonce, subject, &["/credentialSubject/memberLevel"]);

    // vp_token is the DCQL map keyed by query id → the derived VC.
    let vp_token = json!({ "membership": derived });
    let set = verify_vp_token(&vp_token, "did:web:vtc.example", nonce, None, Utc::now())
        .await
        .expect("a valid bbs-2023 presentation must verify");

    assert_eq!(set.holder, subject, "holder is the disclosed subject id");
    assert_eq!(set.presentations.len(), 1);
    let p = &set.presentations[0];
    assert_eq!(p.issuer_did, issuer_did);
    assert_eq!(p.vct.as_deref(), Some("MembershipCredential"));
    assert_eq!(p.claims["memberLevel"], "gold");
    assert!(
        p.claims.get("secret").is_none(),
        "an undisclosed claim must not appear"
    );
    assert!(
        !p.holder_bound,
        "a basic bbs-2023 proof is possession-based, not holder-bound"
    );
}

/// A bbs-2023 **pseudonym** (holder-bound) presentation bound to `verifier_id`.
#[cfg(feature = "bbs")]
fn bbs_pseudonym_presentation(
    nonce: &str,
    subject: &str,
    verifier_id: &str,
    disclose: &[&str],
) -> (Value, String) {
    use affinidi_bbs as bbs;
    use affinidi_data_integrity::bbs_2023_transform as tx;

    let sk = bbs::keygen(b"vtc-nym-verify-key-material-32by", b"").unwrap();
    let pk = bbs::sk_to_pk(&sk);
    let issuer_did = affinidi_crypto::bls12381::g2_pub_to_did_key(&pk.to_bytes());
    let vc = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "type": ["VerifiableCredential", "MembershipCredential"],
        "issuer": issuer_did,
        "validFrom": "2020-01-01T00:00:00Z",
        "validUntil": "2100-01-01T00:00:00Z",
        "credentialSubject": { "id": subject, "memberLevel": "gold", "secret": "hidden" }
    });
    let mandatory = ["/@context", "/type", "/issuer", "/credentialSubject/id"];

    // Holder commits a link secret; issuer blind-signs the pseudonym base.
    let prover_nym_bytes = [0x11u8; 32];
    let prover_nym = bbs::hash::scalar_from_bytes(&prover_nym_bytes).unwrap();
    let (commitment, secret_prover_blind) =
        bbs::nym_commit(prover_nym, &[], bbs::Ciphersuite::default()).unwrap();
    let blind_bytes = bbs::hash::scalar_to_bytes(&secret_prover_blind);
    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "bbs-2023",
        "created": "2020-01-01T00:00:00Z",
        "verificationMethod": format!("{issuer_did}#bbs-key-0"),
        "proofPurpose": "assertionMethod",
        "@context": vc["@context"].clone(),
    });
    let proof_value = tx::create_pseudonym_base_proof_value(
        &vc,
        &proof_config,
        &mandatory,
        &sk,
        &pk,
        b"vtc-nym-test-hmac-key-32-bytes!!",
        &commitment,
        &[0x22u8; 32],
    )
    .unwrap();
    let mut proof = proof_config;
    let obj = proof.as_object_mut().unwrap();
    obj.remove("@context");
    obj.insert("proofValue".into(), json!(proof_value));
    let mut base = vc.clone();
    base.as_object_mut().unwrap().insert("proof".into(), proof);

    // Holder derives a per-verifier pseudonym proof bound to `verifier_id`.
    let derived = tx::create_pseudonym_derived_proof(
        &base,
        disclose,
        nonce.as_bytes(),
        &pk,
        &prover_nym_bytes,
        &blind_bytes,
        verifier_id,
    )
    .unwrap();
    (derived, issuer_did)
}

#[cfg(feature = "bbs")]
#[tokio::test]
async fn verify_vp_token_accepts_a_holder_bound_bbs_pseudonym() {
    let nonce = "vtc-challenge-xyz";
    let subject = "did:key:zApplicant";
    let aud = "did:web:vtc.example";
    let (derived, _issuer) =
        bbs_pseudonym_presentation(nonce, subject, aud, &["/credentialSubject/memberLevel"]);
    let vp_token = json!({ "membership": derived });

    // Verifies and is reported as holder-bound when aud matches the verifier id.
    let set = verify_vp_token(&vp_token, aud, nonce, None, Utc::now())
        .await
        .expect("a holder-bound bbs-2023 pseudonym must verify");
    assert_eq!(set.holder, subject);
    assert!(
        set.presentations[0].holder_bound,
        "a pseudonym proof must be reported holder-bound"
    );

    // ... and is REJECTED for a different verifier (per-verifier binding):
    // `aud` is the pseudonym `verifier_id`, so a different VTC can't accept it.
    assert!(
        verify_vp_token(
            &vp_token,
            "did:web:other-vtc.example",
            nonce,
            None,
            Utc::now()
        )
        .await
        .is_err(),
        "a pseudonym proof must not verify for a different verifier id"
    );
}

#[cfg(feature = "bbs")]
#[tokio::test]
async fn verify_vp_token_rejects_a_bbs_presentation_with_a_wrong_nonce() {
    let (derived, _issuer) = bbs_derived_presentation(
        "the-real-nonce",
        "did:key:zApplicant",
        &["/credentialSubject/memberLevel"],
    );
    let vp_token = json!({ "membership": derived });
    // The verifier expects a different challenge than the proof was bound to.
    assert!(
        verify_vp_token(
            &vp_token,
            "did:web:vtc.example",
            "a-different-nonce",
            None,
            Utc::now()
        )
        .await
        .is_err()
    );
}

#[cfg(feature = "bbs")]
#[tokio::test]
async fn verify_vp_token_rejects_a_tampered_bbs_disclosed_claim() {
    let nonce = "vtc-challenge-xyz";
    let (mut derived, _issuer) = bbs_derived_presentation(
        nonce,
        "did:key:zApplicant",
        &["/credentialSubject/memberLevel"],
    );
    derived["credentialSubject"]["memberLevel"] = json!("platinum");
    let vp_token = json!({ "membership": derived });
    assert!(
        verify_vp_token(&vp_token, "did:web:vtc.example", nonce, None, Utc::now())
            .await
            .is_err()
    );
}
