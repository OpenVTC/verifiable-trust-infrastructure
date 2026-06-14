//! `swap-acl` — atomic self-service ACL key rotation.
//!
//! The caller authenticates as an existing ("old") DID and presents a
//! **VP-JWT** proving control of a "new" DID; the VTA atomically moves the
//! old DID's ACL entry (same role + contexts) onto the new DID and deletes
//! the old one. The browser wallet uses this to rotate the operator-granted
//! ephemeral `did:key` onto its long-term holder `did:peer` on first connect.
//!
//! The proof is a compact Ed25519 JWS (a W3C Verifiable Presentation secured
//! as a JWT), not a JSON-LD DataIntegrityProof: it reuses the holder's
//! existing SIOP-style signing primitive and the VTA's JWS+DID verification,
//! so no JCS / data-integrity machinery is needed on either side.
//!
//! The verifier ([`AclSwapPresentation`] / [`VerifiedAclSwap`]) is gated
//! behind `provision-integration` — like [`crate::provision_integration`]'s
//! `BootstrapRequest::verify`, it needs `ed25519-dalek`. The plain wire bodies
//! ([`SwapAclBody`], [`SwapAclResultBody`]) are always available so the SDK
//! client can build a request without the verifier deps.

use serde::{Deserialize, Serialize};

pub use super::create::CreateAclResultBody;

/// Request body for the legacy `swap-acl` DIDComm message type (FPN-private,
/// retained for the deprecation window). The new DID is read from the
/// *verified* presentation, not the body, so it can't be spoofed
/// independently of the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SwapAclBody {
    /// Compact Ed25519 JWS (VP-JWT) proving control of the new DID.
    pub presentation: String,
}

/// Request body for the canonical `acl/swap-key/0.1` Trust Task. The
/// `link_proof` field is the VP-JWT that previously rode in `SwapAclBody.presentation`;
/// `current_subject` and `new_subject` are the explicit subjects the
/// Trust Task spec requires. The verifier cross-checks `new_subject` against
/// the holder DID extracted from `link_proof` and rejects on mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SwapKeyBody {
    /// The VID being swapped out — MUST equal the DIDComm sender / REST caller.
    pub current_subject: String,
    /// The VID being swapped in — MUST equal the `iss` of `link_proof`.
    pub new_subject: String,
    /// Compact Ed25519 JWS (VP-JWT) signed by `new_subject` proving consent
    /// to take over `current_subject`'s ACL entry. The spec marks this
    /// optional at the framework level, but the FPN deployment policy requires it.
    pub link_proof: String,
    /// Optional human-readable rationale recorded in the audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The swap returns the newly-created ACL entry.
pub type SwapAclResultBody = CreateAclResultBody;
/// Alias for the canonical Trust Task response — same shape as the legacy result.
pub type SwapKeyResponseBody = CreateAclResultBody;

/// Build the compact Ed25519 VP-JWT (`presentation` / `link_proof`) that
/// proves control of `holder_did` for an `acl/swap-key` request.
///
/// Signed by `signing_key` (the new DID's Ed25519 key); `aud` is the VTA DID
/// the request is bound to. The presentation expires `ttl_secs` after `now`
/// (unix seconds). The shape mirrors exactly what [`AclSwapPresentation::verify`]
/// accepts: `iss == holder == holder_did`, `vp.type` carrying
/// `VerifiablePresentation` + `AclSwapRequest`, and a `kid` resolving to the
/// `did:key` verification method.
///
/// `holder_did` MUST be a `did:key` whose multibase suffix is the Ed25519
/// public key matching `signing_key` (the form [`crate::session`] mints for
/// rotation).
#[cfg(feature = "client")]
pub fn build_swap_presentation(
    signing_key: &ed25519_dalek::SigningKey,
    holder_did: &str,
    aud: &str,
    now: u64,
    ttl_secs: u64,
    nonce: Option<&str>,
) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use ed25519_dalek::Signer;
    use serde_json::json;

    let mb = holder_did.strip_prefix("did:key:").unwrap_or(holder_did);
    let kid = format!("{holder_did}#{mb}");
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
    let mut payload = json!({
        "iss": holder_did,
        "aud": aud,
        "exp": now + ttl_secs,
        "vp": { "type": ["VerifiablePresentation", "AclSwapRequest"], "holder": holder_did },
    });
    if let Some(n) = nonce {
        payload["nonce"] = json!(n);
    }
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header).expect("serialize JWS header")),
        B64URL.encode(serde_json::to_vec(&payload).expect("serialize JWS payload")),
    );
    let sig = signing_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64URL.encode(sig.to_bytes()))
}

#[cfg(feature = "provision-integration")]
pub use verify_impl::{AclSwapError, AclSwapPresentation, VerifiedAclSwap};

#[cfg(feature = "provision-integration")]
mod verify_impl {
    use serde::Deserialize;
    use serde_json::Value;

    /// Markers the VP-JWT `vp.type` array must carry.
    const VP_TYPE: &str = "VerifiablePresentation";
    const SWAP_TYPE: &str = "AclSwapRequest";
    /// Clock-skew tolerance when checking `exp`.
    const SKEW_SECS: u64 = 300;

    #[derive(Debug, thiserror::Error)]
    pub enum AclSwapError {
        #[error("malformed VP-JWT: {0}")]
        Parse(String),
        #[error("unsupported JWS alg {0:?} (expected EdDSA)")]
        UnsupportedAlg(String),
        #[error("presentation type is not a VerifiablePresentation/AclSwapRequest")]
        WrongType,
        #[error("verificationMethod DID does not match the presentation holder")]
        HolderMismatch,
        #[error("audience {got:?} is not this VTA ({expected:?})")]
        WrongAudience { got: String, expected: String },
        #[error("presentation expired (exp {exp}, now {now})")]
        Expired { exp: u64, now: u64 },
        #[error("invalid claim: {0}")]
        InvalidClaim(String),
        #[error("signature verification failed: {0}")]
        Signature(String),
    }

    /// Claims carried by the VP-JWT payload. `iss` == `holder` == the new DID.
    #[derive(Debug, Deserialize)]
    struct SwapClaims {
        iss: String,
        aud: String,
        exp: u64,
        #[serde(default)]
        nonce: Option<String>,
        vp: VpClaim,
    }

    #[derive(Debug, Deserialize)]
    struct VpClaim {
        #[serde(rename = "type")]
        types: Vec<String>,
        #[serde(default)]
        holder: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct JwsHeader {
        alg: String,
        kid: String,
    }

    /// An unverified swap presentation (the compact JWS as received).
    #[derive(Debug, Clone)]
    pub struct AclSwapPresentation {
        jws: String,
    }

    impl AclSwapPresentation {
        pub fn new(jws: impl Into<String>) -> Self {
            Self { jws: jws.into() }
        }

        /// Peek the claimed new DID (`iss`) without verifying — the caller
        /// needs it to resolve the DID document `verify` checks against. The
        /// returned DID is **unverified** until [`Self::verify`].
        pub fn peek_holder(&self) -> Result<String, AclSwapError> {
            Ok(self.decode()?.1.iss)
        }

        fn decode(&self) -> Result<(JwsHeader, SwapClaims, Vec<u8>, Vec<u8>), AclSwapError> {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

            let mut parts = self.jws.split('.');
            let h = parts
                .next()
                .ok_or_else(|| AclSwapError::Parse("missing header".into()))?;
            let p = parts
                .next()
                .ok_or_else(|| AclSwapError::Parse("missing payload".into()))?;
            let s = parts
                .next()
                .ok_or_else(|| AclSwapError::Parse("missing signature".into()))?;
            if parts.next().is_some() {
                return Err(AclSwapError::Parse(
                    "not a compact JWS (too many segments)".into(),
                ));
            }

            let header: JwsHeader = serde_json::from_slice(
                &B64URL
                    .decode(h.as_bytes())
                    .map_err(|e| AclSwapError::Parse(format!("header b64: {e}")))?,
            )
            .map_err(|e| AclSwapError::Parse(format!("header json: {e}")))?;
            let claims: SwapClaims = serde_json::from_slice(
                &B64URL
                    .decode(p.as_bytes())
                    .map_err(|e| AclSwapError::Parse(format!("payload b64: {e}")))?,
            )
            .map_err(|e| AclSwapError::Parse(format!("payload json: {e}")))?;
            let sig = B64URL
                .decode(s.as_bytes())
                .map_err(|e| AclSwapError::Parse(format!("signature b64: {e}")))?;
            // The Ed25519 signing input is the ASCII `header.payload`.
            let signing_input = format!("{h}.{p}").into_bytes();
            Ok((header, claims, signing_input, sig))
        }

        /// Verify the presentation against the resolved DID document of its
        /// holder, binding it to this VTA (`expected_aud`) and the current
        /// time. `did_doc` must be the resolved document of
        /// [`Self::peek_holder`] (the caller resolves it; the SDK stays free
        /// of a DID resolver). Checks, in order: type markers, JWS alg, key
        /// binding (the proof's `kid` DID equals the holder), audience,
        /// expiry, then the Ed25519 signature against the holder's
        /// verification-method key.
        pub fn verify(
            self,
            did_doc: &Value,
            expected_aud: &str,
            now: u64,
        ) -> Result<VerifiedAclSwap, AclSwapError> {
            let (header, claims, signing_input, sig) = self.decode()?;

            if !claims.vp.types.iter().any(|t| t == VP_TYPE)
                || !claims.vp.types.iter().any(|t| t == SWAP_TYPE)
            {
                return Err(AclSwapError::WrongType);
            }
            if header.alg != "EdDSA" {
                return Err(AclSwapError::UnsupportedAlg(header.alg));
            }
            if let Some(h) = &claims.vp.holder
                && h != &claims.iss
            {
                return Err(AclSwapError::HolderMismatch);
            }
            // Key binding: the signing key's DID (before '#') must be the
            // holder — stops a proof made by someone else's key being accepted
            // via a forged `iss`.
            let vm_did = header.kid.split('#').next().unwrap_or("");
            if vm_did != claims.iss {
                return Err(AclSwapError::HolderMismatch);
            }
            if claims.aud != expected_aud {
                return Err(AclSwapError::WrongAudience {
                    got: claims.aud,
                    expected: expected_aud.to_string(),
                });
            }
            if now > claims.exp.saturating_add(SKEW_SECS) {
                return Err(AclSwapError::Expired {
                    exp: claims.exp,
                    now,
                });
            }

            let pubkey = extract_ed25519_pubkey_from_did_doc(did_doc, &header.kid)?;
            verify_ed25519(&signing_input, &sig, &pubkey)?;

            Ok(VerifiedAclSwap {
                holder: claims.iss,
                nonce: claims.nonce,
            })
        }
    }

    /// A swap presentation whose Ed25519 proof has been verified against the
    /// holder DID's document. Only constructable via
    /// [`AclSwapPresentation::verify`].
    #[derive(Debug, Clone)]
    pub struct VerifiedAclSwap {
        holder: String,
        nonce: Option<String>,
    }

    impl VerifiedAclSwap {
        /// The verified new DID — proven to control the signing key.
        pub fn holder(&self) -> &str {
            &self.holder
        }
        /// The presentation nonce, if any.
        pub fn nonce(&self) -> Option<&str> {
            self.nonce.as_deref()
        }
    }

    fn verify_ed25519(msg: &[u8], sig: &[u8], pubkey: &[u8; 32]) -> Result<(), AclSwapError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let signature = Signature::from_slice(sig)
            .map_err(|e| AclSwapError::Signature(format!("sig shape: {e}")))?;
        let vk = VerifyingKey::from_bytes(pubkey)
            .map_err(|e| AclSwapError::Signature(format!("pubkey shape: {e}")))?;
        vk.verify(msg, &signature)
            .map_err(|e| AclSwapError::Signature(e.to_string()))
    }

    /// Resolve a verification-method id to its Ed25519 public key within a DID
    /// document. Matches on the full id or the `#fragment`.
    fn extract_ed25519_pubkey_from_did_doc(
        doc: &Value,
        target_vm_id: &str,
    ) -> Result<[u8; 32], AclSwapError> {
        let vms = doc
            .get("verificationMethod")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                AclSwapError::InvalidClaim("DID document has no verificationMethod".into())
            })?;
        let target_fragment = target_vm_id.split_once('#').map(|(_, f)| f);

        for vm in vms {
            let id = vm.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let id_fragment = id.split_once('#').map(|(_, f)| f);
            let matches =
                id == target_vm_id || (target_fragment.is_some() && target_fragment == id_fragment);
            if !matches {
                continue;
            }
            // A resolver may emit the key as Multikey (publicKeyMultibase) or
            // as a JWK (publicKeyJwk: OKP/Ed25519). did:peer resolution in
            // particular tends to use JWK, so accept both.
            if let Some(mb) = vm.get("publicKeyMultibase").and_then(|v| v.as_str()) {
                return crate::did_key::decode_ed25519_public_key_multibase(mb).map_err(|e| {
                    AclSwapError::InvalidClaim(format!("decode publicKeyMultibase for '{id}': {e}"))
                });
            }
            if let Some(jwk) = vm.get("publicKeyJwk") {
                return ed25519_pub_from_jwk(jwk).map_err(|e| {
                    AclSwapError::InvalidClaim(format!("decode publicKeyJwk for '{id}': {e}"))
                });
            }
            return Err(AclSwapError::InvalidClaim(format!(
                "verificationMethod '{id}' has neither publicKeyMultibase nor publicKeyJwk"
            )));
        }
        Err(AclSwapError::InvalidClaim(format!(
            "verificationMethod '{target_vm_id}' not found in DID document"
        )))
    }

    /// Decode an Ed25519 public key from an OKP JWK (`{kty:OKP, crv:Ed25519,
    /// x:<base64url>}`).
    fn ed25519_pub_from_jwk(jwk: &Value) -> Result<[u8; 32], AclSwapError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

        if jwk.get("kty").and_then(|v| v.as_str()) != Some("OKP")
            || jwk.get("crv").and_then(|v| v.as_str()) != Some("Ed25519")
        {
            return Err(AclSwapError::InvalidClaim(
                "publicKeyJwk is not an OKP/Ed25519 key".into(),
            ));
        }
        let x = jwk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AclSwapError::InvalidClaim("publicKeyJwk has no 'x'".into()))?;
        let bytes = B64URL
            .decode(x.as_bytes())
            .map_err(|e| AclSwapError::InvalidClaim(format!("decode jwk 'x': {e}")))?;
        bytes
            .try_into()
            .map_err(|_| AclSwapError::InvalidClaim("jwk 'x' is not 32 bytes".into()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use ed25519_dalek::{Signer, SigningKey};
        use serde_json::json;

        const AUD: &str = "did:webvh:scid:vta.example";

        /// Build a (did:key, did-doc, signed VP-JWT) triple for a fresh key.
        /// `mutate` can tamper the payload before signing or the jws after.
        fn make_jws(aud: &str, exp: u64) -> (String, Value, SigningKey) {
            let sk = SigningKey::from_bytes(&[7u8; 32]);
            let pub_bytes = sk.verifying_key().to_bytes();
            let mb = crate::did_key::ed25519_multibase_pubkey(&pub_bytes);
            let did = format!("did:key:{mb}");
            let kid = format!("{did}#{mb}");

            let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
            let payload = json!({
                "iss": did,
                "aud": aud,
                "exp": exp,
                "nonce": "n-123",
                "vp": { "type": ["VerifiablePresentation", "AclSwapRequest"], "holder": did },
            });
            let signing_input = format!(
                "{}.{}",
                B64URL.encode(serde_json::to_vec(&header).unwrap()),
                B64URL.encode(serde_json::to_vec(&payload).unwrap())
            );
            let sig = sk.sign(signing_input.as_bytes());
            let jws = format!("{signing_input}.{}", B64URL.encode(sig.to_bytes()));

            let doc = json!({
                "id": did,
                "verificationMethod": [{ "id": kid, "publicKeyMultibase": mb }],
            });
            (jws, doc, sk)
        }

        #[cfg(feature = "client")]
        #[test]
        fn builder_round_trips_through_verifier() {
            // The client-side builder must produce a presentation the
            // server-side verifier accepts — same key, audience, and shape.
            let sk = SigningKey::from_bytes(&[9u8; 32]);
            let mb = crate::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes());
            let did = format!("did:key:{mb}");
            let kid = format!("{did}#{mb}");
            let jws =
                super::super::build_swap_presentation(&sk, &did, AUD, 1_000, 300, Some("n-1"));
            let doc = json!({
                "id": did,
                "verificationMethod": [{ "id": kid, "publicKeyMultibase": mb }],
            });
            let verified = AclSwapPresentation::new(jws)
                .verify(&doc, AUD, 1_100)
                .unwrap();
            assert_eq!(verified.holder(), did);
            assert_eq!(verified.nonce(), Some("n-1"));
        }

        #[test]
        fn verifies_a_well_formed_presentation() {
            let (jws, doc, _) = make_jws(AUD, 10_000);
            let verified = AclSwapPresentation::new(jws)
                .verify(&doc, AUD, 1_000)
                .unwrap();
            assert!(verified.holder().starts_with("did:key:z6Mk"));
            assert_eq!(verified.nonce(), Some("n-123"));
        }

        #[test]
        fn verifies_against_a_publickeyjwk_document() {
            // did:peer resolvers often emit publicKeyJwk rather than multibase.
            let (jws, _, sk) = make_jws(AUD, 10_000);
            let did = AclSwapPresentation::new(jws.clone()).peek_holder().unwrap();
            let mb = did.strip_prefix("did:key:").unwrap();
            let x = B64URL.encode(sk.verifying_key().to_bytes());
            let doc = json!({
                "id": did,
                "verificationMethod": [{
                    "id": format!("{did}#{mb}"),
                    "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
                }],
            });
            let verified = AclSwapPresentation::new(jws)
                .verify(&doc, AUD, 1_000)
                .unwrap();
            assert_eq!(verified.holder(), did);
        }

        #[test]
        fn rejects_wrong_audience() {
            let (jws, doc, _) = make_jws(AUD, 10_000);
            let err = AclSwapPresentation::new(jws)
                .verify(&doc, "did:webvh:scid:other.vta", 1_000)
                .unwrap_err();
            assert!(matches!(err, AclSwapError::WrongAudience { .. }));
        }

        #[test]
        fn rejects_expired() {
            let (jws, doc, _) = make_jws(AUD, 1_000);
            let err = AclSwapPresentation::new(jws)
                .verify(&doc, AUD, 9_999)
                .unwrap_err();
            assert!(matches!(err, AclSwapError::Expired { .. }));
        }

        #[test]
        fn rejects_tampered_signature() {
            let (jws, doc, _) = make_jws(AUD, 10_000);
            // Flip a byte in the decoded signature, then re-encode — keeps it
            // valid base64 + 64 bytes so it reaches (and fails) verification.
            let (head, sig_b64) = jws.rsplit_once('.').unwrap();
            let mut sig = B64URL.decode(sig_b64.as_bytes()).unwrap();
            sig[0] ^= 0x01;
            let tampered = format!("{head}.{}", B64URL.encode(&sig));
            let err = AclSwapPresentation::new(tampered)
                .verify(&doc, AUD, 1_000)
                .unwrap_err();
            assert!(matches!(err, AclSwapError::Signature(_)));
        }

        #[test]
        fn rejects_key_binding_mismatch() {
            // A doc whose VM key is a DIFFERENT key than the one that signed.
            let (jws, _, _) = make_jws(AUD, 10_000);
            let other = SigningKey::from_bytes(&[9u8; 32]);
            let other_mb =
                crate::did_key::ed25519_multibase_pubkey(&other.verifying_key().to_bytes());
            // Keep the same VM id (so it's "found") but a different key →
            // signature must fail against the wrong public key.
            let did = AclSwapPresentation::new(jws.clone()).peek_holder().unwrap();
            let kid = format!("{did}#{}", did.strip_prefix("did:key:").unwrap());
            let doc = json!({
                "id": did,
                "verificationMethod": [{ "id": kid, "publicKeyMultibase": other_mb }],
            });
            let err = AclSwapPresentation::new(jws)
                .verify(&doc, AUD, 1_000)
                .unwrap_err();
            assert!(matches!(err, AclSwapError::Signature(_)));
        }
    }
}
