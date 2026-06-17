//! Smoke test for the adopted TDK credential formats
//! (vti-credential-architecture §0.2 — "Wire the crates as VTI deps").
//!
//! This proves the SD-JWT-VC issue → verify path works end-to-end inside the
//! VTI workspace using a *real* asymmetric (EdDSA / Ed25519) signer, not the
//! upstream HMAC test helper. SD-JWT-VC is the near-term credential format
//! (runs on the existing Ed25519/JOSE stack, no new curve) and unblocks the
//! later VTA-vault / credential-exchange work.
//!
//! Security/privacy invariants this test pins (spec §14):
//!   - Claim minimisation: selectively-disclosed claims never appear in the
//!     cleartext JWT body — only their salted digests do.
//!   - Issuer authenticity: a tampered issuer signature is rejected.
//!
//! NOTE: this is an *adoption* smoke test for the dependency wiring. It does
//! not establish any VTI endpoint, does not enumerate a wallet, and does not
//! present/disclose without an explicit (here, test-driven) caller decision.

use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::signer::{JwtSigner, JwtVerifier};
use affinidi_sd_jwt::verifier::{VerificationOptions, verify};
use affinidi_sd_jwt::{SdJwt, error::SdJwtError};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};

/// A production-shape EdDSA (Ed25519) JWT signer.
///
/// Signs the compact JWS signing input (`header_b64.payload_b64`) with an
/// Ed25519 key and emits the full compact JWS. This is the same algorithm
/// (`EdDSA`) the rest of the workspace signs with, so the smoke test exercises
/// a realistic issuer rather than the HMAC test stub shipped in the TDK.
struct EddsaSigner {
    key: SigningKey,
    kid: String,
}

impl JwtSigner for EddsaSigner {
    fn algorithm(&self) -> &str {
        "EdDSA"
    }

    fn key_id(&self) -> Option<&str> {
        Some(&self.kid)
    }

    fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(header)
                .map_err(|e| SdJwtError::Verification(e.to_string()))?
                .as_bytes(),
        );
        let payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(payload)
                .map_err(|e| SdJwtError::Verification(e.to_string()))?
                .as_bytes(),
        );
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// The matching EdDSA verifier: checks the `alg` header is `EdDSA`, verifies
/// the Ed25519 signature over the signing input, and returns the decoded
/// payload. A bad signature or wrong `alg` is rejected.
struct EddsaVerifier {
    key: VerifyingKey,
}

impl JwtVerifier for EddsaVerifier {
    fn verify_jwt(&self, jws: &str) -> Result<Value, SdJwtError> {
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err(SdJwtError::Verification("malformed compact JWS".into()));
        }
        let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        // Validate the algorithm header before touching the signature.
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
            return Err(SdJwtError::Verification(
                "unexpected alg (want EdDSA)".into(),
            ));
        }

        // Verify the signature over `header_b64.payload_b64`.
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        self.key
            .verify(signing_input.as_bytes(), &sig)
            .map_err(|_| SdJwtError::Verification("Ed25519 signature invalid".into()))?;

        // Signature good — decode and return the payload.
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        serde_json::from_slice(&payload_bytes).map_err(|e| SdJwtError::Verification(e.to_string()))
    }
}

fn issuer_keypair() -> (EddsaSigner, EddsaVerifier) {
    // Deterministic key so the test is reproducible without an RNG dependency.
    let secret = [7u8; 32];
    let signing = SigningKey::from_bytes(&secret);
    let verifying = signing.verifying_key();
    (
        EddsaSigner {
            key: signing,
            kid: "did:example:community#key-0".to_string(),
        },
        EddsaVerifier { key: verifying },
    )
}

#[test]
fn issue_and_verify_sd_jwt_vc_end_to_end() {
    let hasher = Sha256Hasher;
    let (signer, verifier) = issuer_keypair();

    // A community-membership-shaped credential. Every member-identifying claim
    // is selectively disclosable so the holder can later prove "is a member of
    // community X" without leaking the rest.
    let claims = json!({
        "community": "did:web:community.example",
        "member_handle": "alice",
        "joined_at": "2026-06-03T00:00:00Z",
        "tier": "founding",
    });
    let frame = json!({
        "_sd": ["community", "member_handle", "joined_at", "tier"],
    });

    let vc = affinidi_sd_jwt_vc::issue(
        "https://openvtc.org/credentials/MembershipCredential",
        "did:example:community",
        Some("did:example:alice"),
        &claims,
        &frame,
        &signer,
        &hasher,
        None,
        1_700_000_000,
        Some(1_900_000_000),
    )
    .expect("issue SD-JWT-VC");

    // The protected VC claims live in cleartext in the JWT body...
    let body = vc.payload().expect("decode payload");
    assert_eq!(
        body["vct"],
        "https://openvtc.org/credentials/MembershipCredential"
    );
    assert_eq!(body["iss"], "did:example:community");
    assert_eq!(body["sub"], "did:example:alice");
    assert_eq!(body["iat"], 1_700_000_000);
    assert_eq!(body["exp"], 1_900_000_000);

    // ...but the selectively-disclosed member claims MUST NOT (claim
    // minimisation, spec §14.3). Only their salted digests are in `_sd`.
    for hidden in ["community", "member_handle", "joined_at", "tier"] {
        assert!(
            body.get(hidden).is_none(),
            "disclosable claim `{hidden}` leaked into the cleartext JWT body"
        );
    }
    assert_eq!(vc.sd_jwt.disclosures.len(), 4);

    // Round-trip through the compact serialization a real holder would store.
    let serialized = vc.serialize();
    let parsed = SdJwt::parse(&serialized, &hasher).expect("parse serialized SD-JWT-VC");

    // Issuer-side verification: check the Ed25519 signature and reconstruct
    // the full claim set from the disclosures the holder chose to present.
    let opts = VerificationOptions::default();
    let result = verify(&parsed, &verifier, &hasher, &opts, None).expect("verify issuer signature");
    assert!(result.is_verified());

    // Every disclosed claim is recovered with its original value.
    assert_eq!(result.claims["community"], "did:web:community.example");
    assert_eq!(result.claims["member_handle"], "alice");
    assert_eq!(result.claims["tier"], "founding");
    assert_eq!(
        result.claims["vct"],
        "https://openvtc.org/credentials/MembershipCredential"
    );

    // Temporal validity holds inside the window and is rejected outside it.
    affinidi_sd_jwt_vc::verify_temporal(&result.claims, 1_800_000_000)
        .expect("inside validity window");
    assert!(
        affinidi_sd_jwt_vc::verify_temporal(&result.claims, 2_000_000_000).is_err(),
        "expired credential must fail temporal verification"
    );
}

#[test]
fn tampered_issuer_signature_is_rejected() {
    let hasher = Sha256Hasher;
    let (signer, verifier) = issuer_keypair();

    let claims = json!({ "tier": "founding" });
    let frame = json!({ "_sd": ["tier"] });

    let vc = affinidi_sd_jwt_vc::issue(
        "https://openvtc.org/credentials/MembershipCredential",
        "did:example:community",
        None,
        &claims,
        &frame,
        &signer,
        &hasher,
        None,
        1_700_000_000,
        None,
    )
    .expect("issue SD-JWT-VC");

    // Flip the final signature byte of the issuer JWS — verification must fail.
    let mut jws = vc.sd_jwt.jws.clone();
    let last = jws.pop().expect("non-empty jws");
    let swapped = if last == 'A' { 'B' } else { 'A' };
    jws.push(swapped);

    let forged = SdJwt::new(jws, vc.sd_jwt.disclosures.clone(), vc.sd_jwt.kb_jwt.clone());

    let opts = VerificationOptions::default();
    let err = verify(&forged, &verifier, &hasher, &opts, None)
        .expect_err("tampered signature must be rejected");
    assert!(matches!(err, SdJwtError::Verification(_)));
}
