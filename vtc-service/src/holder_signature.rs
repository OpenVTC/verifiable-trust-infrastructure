//! Shared `did:key` Ed25519 holder-signature verification (P1.4).
//!
//! The VTC's REST holder-binding signatures — join submit / accept /
//! status and member-rotation's old/new `did:key` signatures — are all
//! an Ed25519 signature over `domain_tag || canonical_json`, verified
//! against the signer's intrinsic `did:key` public key. They differ
//! only by domain tag + canonical struct, so they all delegate to the
//! one verifier here (replacing four byte-identical copies of the
//! pubkey-resolve → sig-decode → verify crypto).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify `signature_hex` (hex Ed25519) over `domain_tag || payload`
/// against the intrinsic public key of `did` (a `did:key`).
///
/// `payload` is the canonical (key-ordered) JSON the signer produced;
/// the helper prepends `domain_tag`. Pass an **empty** `domain_tag` when
/// the caller's `payload` already includes the tag — member rotation
/// builds one combined buffer because the same bytes feed both the
/// `did:key` and `did:webvh` verification paths.
///
/// Returns a human-readable error string; callers map it into their own
/// error type (and frame *which* signature failed).
pub fn verify_domain_signed(
    did: &str,
    domain_tag: &[u8],
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), String> {
    let pub_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(did)
        .map_err(|e| format!("{did} is not a parseable did:key: {e}"))?;
    let vk = VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|e| format!("{did} decodes to an invalid Ed25519 pubkey: {e}"))?;
    let raw = hex::decode(signature_hex).map_err(|e| format!("signature is not hex: {e}"))?;
    let sig = Signature::from_slice(&raw)
        .map_err(|e| format!("signature is not a 64-byte Ed25519 value: {e}"))?;

    let mut signing_bytes = Vec::with_capacity(domain_tag.len() + payload.len());
    signing_bytes.extend_from_slice(domain_tag);
    signing_bytes.extend_from_slice(payload);

    vk.verify(&signing_bytes, &sig)
        .map_err(|e| format!("holder-binding signature failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TAG: &[u8] = b"vtc-test/v1\0";

    fn signer() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[0x11; 32]);
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&sk.verifying_key().to_bytes());
        (sk, did)
    }

    /// Helper mirroring the helper's own concatenation so the test can
    /// produce the exact bytes the signer hashes.
    fn sign_over(sk: &SigningKey, tag: &[u8], payload: &[u8]) -> String {
        let mut buf = tag.to_vec();
        buf.extend_from_slice(payload);
        hex::encode(sk.sign(&buf).to_bytes())
    }

    #[test]
    fn round_trip_verifies() {
        let (sk, did) = signer();
        let payload = b"{\"a\":1}";
        let sig = sign_over(&sk, TAG, payload);
        assert!(verify_domain_signed(&did, TAG, payload, &sig).is_ok());
    }

    #[test]
    fn empty_tag_matches_pre_prefixed_payload() {
        // The rotation path passes its tag inside `payload` + an empty
        // domain tag; verifying that against a signature over the same
        // combined bytes must succeed.
        let (sk, did) = signer();
        let mut combined = TAG.to_vec();
        combined.extend_from_slice(b"rotation-body");
        let sig = sign_over(&sk, &[], &combined);
        assert!(verify_domain_signed(&did, &[], &combined, &sig).is_ok());
    }

    #[test]
    fn wrong_domain_tag_rejected() {
        // A signature produced under one tag must not verify under
        // another — domain separation between submit/accept/status/etc.
        let (sk, did) = signer();
        let payload = b"body";
        let sig = sign_over(&sk, b"vtc-other/v1\0", payload);
        assert!(verify_domain_signed(&did, TAG, payload, &sig).is_err());
    }

    #[test]
    fn wrong_signer_rejected() {
        let (_sk, did) = signer();
        let other = SigningKey::from_bytes(&[0x22; 32]);
        let payload = b"body";
        let sig = sign_over(&other, TAG, payload);
        assert!(verify_domain_signed(&did, TAG, payload, &sig).is_err());
    }

    #[test]
    fn non_did_key_and_garbage_sig_rejected() {
        let (_sk, did) = signer();
        // Not a did:key.
        assert!(verify_domain_signed("did:web:example.com", TAG, b"x", "00").is_err());
        // Not hex / not 64 bytes.
        assert!(verify_domain_signed(&did, TAG, b"x", "not-hex").is_err());
        assert!(verify_domain_signed(&did, TAG, b"x", "0011").is_err());
    }
}
