//! Main verification entry point.
//!
//! See `docs/05-design-notes/vti-webauthn-crate-design.md` §"Verification
//! algorithm" for the step-by-step rules this implements.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use sha2::{Digest, Sha256};

use crate::auth_data;
use crate::client_data;
use crate::config::VerifierConfig;
use crate::error::VerifyError;
use crate::payload::{AssertionPayload, VerifiedAssertion};
use crate::resolver::{ResolvedVm, VerificationAlgorithm, VmResolver};

/// Verify a WebAuthn assertion against a DID-resolved verificationMethod.
///
/// # Arguments
///
/// - `payload` — the assertion bytes the caller pulled from its
///   transport (typically a trust-task payload).
/// - `expected_challenge` — bytes the verifier expects `clientData.
///   challenge` to equal (base64url-decoded). For trust-task-bound
///   assertions, derive this via [`crate::document_binding_challenge`].
///   For server-issued nonces, pass the nonce bytes directly.
/// - `resolver` — caller-supplied resolver for the assertion's
///   `verification_method` URL.
/// - `config` — verifier policy (RP ID, expected origin, UV requirement).
///
/// # Returns
///
/// [`VerifiedAssertion`] on success — exposes the security-relevant
/// flags (`user_present`, `user_verified`, `sign_count`) so the caller
/// can apply its own policy.
///
/// # Errors
///
/// See [`VerifyError`] for the full taxonomy.
pub async fn verify_assertion(
    payload: &AssertionPayload,
    expected_challenge: &[u8],
    resolver: &dyn VmResolver,
    config: &VerifierConfig,
) -> Result<VerifiedAssertion, VerifyError> {
    // 1. Resolve the verification method.
    let resolved = resolver.resolve_vm(&payload.verification_method).await?;

    // 2. Confirm the resolved controller matches the DID portion of the
    //    verification_method URL. Defence in depth — a resolver that
    //    returns a VM under a different controller is buggy, but we
    //    catch it here rather than trust the resolver implicitly.
    let claimed_did = did_portion(&payload.verification_method);
    if claimed_did != resolved.controller {
        return Err(VerifyError::ControllerMismatch {
            expected: claimed_did.to_string(),
            found: resolved.controller,
        });
    }

    // 3. Validate clientDataJSON: type, origin, challenge.
    client_data::parse_and_validate(
        &payload.client_data_json,
        &config.expected_origin,
        expected_challenge,
    )?;

    // 4. Validate authenticatorData: length, rpIdHash, UP/UV flags.
    let auth = auth_data::parse_and_validate(
        &payload.authenticator_data,
        &config.rp_id,
        config.require_user_verification,
    )?;

    // 5. Reconstruct the signed message:
    //    message = authenticatorData ‖ SHA-256(clientDataJSON)
    let client_data_hash = Sha256::digest(&payload.client_data_json);
    let mut message = Vec::with_capacity(payload.authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(&payload.authenticator_data);
    message.extend_from_slice(&client_data_hash);

    // 6. Verify signature.
    match resolved.algorithm {
        VerificationAlgorithm::P256 => verify_p256(&resolved, &message, &payload.signature)?,
    }

    // 7. Done.
    Ok(VerifiedAssertion {
        did: claimed_did.to_string(),
        verification_method: payload.verification_method.clone(),
        user_present: auth.user_present,
        user_verified: auth.user_verified,
        sign_count: auth.sign_count,
        algorithm: resolved.algorithm,
    })
}

/// Verify a P-256 ECDSA signature using aws-lc-rs.
///
/// The Multikey holds a compressed SEC1 point (33 bytes); aws-lc-rs
/// requires uncompressed (65 bytes). We decompress via `p256` (pure
/// curve math, no cryptographic operation) and hand the uncompressed
/// bytes to aws-lc-rs's FIPS-validated verifier.
fn verify_p256(resolved: &ResolvedVm, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    let uncompressed = decompress_p256_point(&resolved.public_key_bytes)?;

    let pubkey = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &uncompressed);
    pubkey
        .verify(message, signature)
        .map_err(|_| VerifyError::SignatureInvalid)
}

/// Decompress a 33-byte SEC1 compressed P-256 point into the 65-byte
/// uncompressed form aws-lc-rs expects.
///
/// Uses the `p256` crate for the curve-point math only — no
/// cryptographic operations (signing, verifying) go through it.
fn decompress_p256_point(compressed: &[u8]) -> Result<[u8; 65], VerifyError> {
    // elliptic-curve 0.14 renamed this family: `EncodedPoint` -> `Sec1Point`,
    // `From/ToEncodedPoint` -> `From/ToSec1Point`. The old names survive as
    // deprecated stubs; these are the current ones.
    use p256::PublicKey;
    use p256::Sec1Point;
    use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};

    // Kept as parse-then-validate rather than the one-shot
    // `PublicKey::from_sec1_bytes`: that collapses both failures into a single
    // error, and the two say different things to whoever reads the log — a
    // malformed encoding is a broken client, a valid encoding off the curve is
    // a point someone chose.
    let ep = Sec1Point::from_bytes(compressed)
        .map_err(|_| VerifyError::MalformedAssertion("invalid SEC1 compressed P-256 point"))?;
    let pk: Option<PublicKey> = Option::from(PublicKey::from_sec1_point(&ep));
    let pk = pk.ok_or(VerifyError::MalformedAssertion(
        "compressed P-256 point is not on the curve",
    ))?;
    let uncompressed = pk.to_sec1_point(false);
    let bytes = uncompressed.as_bytes();
    if bytes.len() != 65 {
        return Err(VerifyError::MalformedAssertion(
            "P-256 uncompressed point did not produce 65 bytes",
        ));
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Extract the DID portion of a verificationMethod URL by trimming
/// everything from the first `#` onwards. If there's no `#`, returns
/// the whole input.
fn did_portion(vm_url: &str) -> &str {
    match vm_url.find('#') {
        Some(idx) => &vm_url[..idx],
        None => vm_url,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::{ResolverError, VerificationAlgorithm};
    use async_trait::async_trait;

    /// Test resolver — returns a hardcoded ResolvedVm for any URL we register.
    struct MockResolver {
        vm: ResolvedVm,
    }

    #[async_trait]
    impl VmResolver for MockResolver {
        async fn resolve_vm(&self, _vm_url: &str) -> Result<ResolvedVm, ResolverError> {
            Ok(self.vm.clone())
        }
    }

    /// Empty resolver — always fails.
    struct FailingResolver;

    #[async_trait]
    impl VmResolver for FailingResolver {
        async fn resolve_vm(&self, _vm_url: &str) -> Result<ResolvedVm, ResolverError> {
            Err(ResolverError::NotFound)
        }
    }

    #[tokio::test]
    async fn surfaces_resolver_failure() {
        let payload = AssertionPayload {
            credential_id: vec![],
            authenticator_data: vec![],
            client_data_json: vec![],
            signature: vec![],
            verification_method: "did:example:alice#passkey".into(),
        };
        let config = VerifierConfig::from_public_url("https://example.com", false).unwrap();

        let err = verify_assertion(&payload, b"chal", &FailingResolver, &config)
            .await
            .unwrap_err();
        assert!(matches!(err, VerifyError::VmResolution(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn detects_controller_mismatch() {
        // Resolver claims a different controller than the VM URL's DID.
        let resolver = MockResolver {
            vm: ResolvedVm {
                algorithm: VerificationAlgorithm::P256,
                public_key_bytes: vec![0x02; 33],
                controller: "did:example:eve".into(),
            },
        };
        let payload = AssertionPayload {
            credential_id: vec![],
            authenticator_data: vec![],
            client_data_json: vec![],
            signature: vec![],
            verification_method: "did:example:alice#passkey".into(),
        };
        let config = VerifierConfig::from_public_url("https://example.com", false).unwrap();

        let err = verify_assertion(&payload, b"chal", &resolver, &config)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerifyError::ControllerMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn did_portion_strips_fragment() {
        assert_eq!(
            did_portion("did:webvh:vta.example.com:alice#passkey-abc"),
            "did:webvh:vta.example.com:alice"
        );
        assert_eq!(did_portion("did:key:z6Mk..."), "did:key:z6Mk...");
    }

    #[test]
    fn rejects_wrong_length_point() {
        // 10 bytes — too short for any SEC1 encoding.
        let bytes = vec![0x02u8; 10];
        let err = decompress_p256_point(&bytes).unwrap_err();
        assert!(
            matches!(err, VerifyError::MalformedAssertion(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_point_not_on_curve() {
        // Header 0x02 + 32 bytes of 0xFF — x-coordinate exceeds the
        // P-256 field prime, so no valid y exists; PublicKey rejection.
        let mut bytes = vec![0xFFu8; 33];
        bytes[0] = 0x02;
        let err = decompress_p256_point(&bytes).unwrap_err();
        assert!(
            matches!(err, VerifyError::MalformedAssertion(_)),
            "got {err:?}"
        );
    }
}
