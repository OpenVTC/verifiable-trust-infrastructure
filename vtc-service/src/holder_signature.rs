//! Shared `did:key` holder-signature verification (P1.4).
//!
//! The VTC's holder-binding signatures — join submit's REST binding and
//! member rotation's old/new `did:key` signatures — are all a signature over
//! `domain_tag || canonical_json`, verified against the signer's intrinsic
//! `did:key` public key. They differ only by domain tag + canonical struct, so
//! they all delegate to the one verifier here (replacing four byte-identical
//! copies of the pubkey-resolve → sig-decode → verify crypto).
//!
//! The key decides the algorithm (#1988): an Ed25519 `did:key` (`z6Mk…`) signs
//! EdDSA, a P-256 one (`zDn…`) ES256 and a secp256k1 one (`zQ3s…`) ES256K —
//! ECDSA as JWS encodes it, `r || s` over the SHA-256 of the bytes. The
//! signature is 64 bytes, hex, whichever it is. Nothing in the request names
//! the algorithm, so nothing in it can choose one.

use vta_sdk::jws::JwsKey;

/// Verify `signature_hex` (hex, 64 bytes) over `domain_tag || payload`
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
    let key =
        JwsKey::from_did_key(did).map_err(|e| format!("{did} is not a usable did:key: {e}"))?;
    verify_hex_signature(&key, domain_tag, payload, signature_hex)
}

/// Verify `signature_hex` over `domain_tag || payload` under `key`, by that
/// key's algorithm — for a key resolved from a DID document rather than read
/// out of a `did:key`.
pub fn verify_hex_signature(
    key: &JwsKey,
    domain_tag: &[u8],
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), String> {
    let raw = hex::decode(signature_hex).map_err(|e| format!("signature is not hex: {e}"))?;
    let mut signing_bytes = Vec::with_capacity(domain_tag.len() + payload.len());
    signing_bytes.extend_from_slice(domain_tag);
    signing_bytes.extend_from_slice(payload);

    key.verify_signature(&signing_bytes, &raw)
        .map_err(|e| format!("holder-binding signature failed ({}): {e}", key.alg()))
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

    /// A P-256 holder (`did:key:zDn…`) signs ES256 over the tagged bytes; the
    /// same signature does not verify under another tag (#1988).
    #[test]
    fn a_p256_did_key_holder_signs() {
        let kp = affinidi_crypto::p256::generate(Some(&[0x31; 32])).unwrap();
        let did = JwsKey::from_resolved(&affinidi_data_integrity::ResolvedKey::new(
            affinidi_secrets_resolver::secrets::KeyType::P256,
            kp.public_bytes.clone(),
        ))
        .unwrap()
        .did_key();
        assert!(did.starts_with("did:key:zDn"), "{did}");

        let mut buf = TAG.to_vec();
        buf.extend_from_slice(b"body");
        let sig = hex::encode(affinidi_crypto::p256::sign(&kp.private_bytes, &buf).unwrap());
        verify_domain_signed(&did, TAG, b"body", &sig).expect("ES256 verifies");
        assert!(verify_domain_signed(&did, b"vtc-other/v1\0", b"body", &sig).is_err());
    }

    /// A secp256k1 holder (`did:key:zQ3s…`) signs ES256K (#1988).
    #[test]
    fn a_secp256k1_did_key_holder_signs() {
        use k256::ecdsa::signature::Signer as _;
        let seed = [0x41; 32];
        let kp = affinidi_crypto::secp256k1::generate(Some(&seed)).unwrap();
        let did = JwsKey::from_resolved(&affinidi_data_integrity::ResolvedKey::new(
            affinidi_secrets_resolver::secrets::KeyType::Secp256k1,
            kp.public_bytes.clone(),
        ))
        .unwrap()
        .did_key();
        assert!(did.starts_with("did:key:zQ3s"), "{did}");

        let sk = k256::ecdsa::SigningKey::from_slice(&seed).unwrap();
        let mut buf = TAG.to_vec();
        buf.extend_from_slice(b"body");
        let sig: k256::ecdsa::Signature = sk.sign(&buf);
        let sig = hex::encode(sig.to_bytes());
        verify_domain_signed(&did, TAG, b"body", &sig).expect("ES256K verifies");
        assert!(verify_domain_signed(&did, TAG, b"other", &sig).is_err());
    }
}
