//! VTC credential-exchange (Phase 3, spec §6) — the issuer answering an OID4VCI
//! `credential-exchange/request` by issuing a credential, and the verifier
//! checking a `credential-exchange/present` [`verify_presentation`].
//!
//! The [`vta_sdk::protocols::credential_exchange`] Trust Tasks carry OID4VCI on
//! the wire; the `affinidi-openid4vci` crate gives us the offer/response
//! builders and *structural* request validation. What it does **not** give us
//! — and what gates issuance — is the **cryptographic verification of the
//! holder's key-binding proof**. That gate lives here:
//! [`verify_oid4vci_proof`] proves the requester controls a key, and
//! [`issue_on_request`] only releases the credential when that proven key is
//! the credential's intended subject.
//!
//! This is the issuer mirror of the VTA holder-receive
//! (`vta-service/src/operations/credential_exchange.rs`, task 3.3). The core
//! [`issue_on_request`] gate is a pure operation; [`make_offer`] + [`redeem`]
//! add the persisted single-use pending-offer store, and the VTC DIDComm
//! `credential-exchange/request` handler (`messaging.rs`) drives `redeem` to
//! complete the `offer → request → issue` loop with the VTA holder side.
//!
//! ## Scope of this slice
//! - **`did:key` holders** — fully wired (the proof `kid` is a `did:key`,
//!   resolved locally, and must equal the credential's bound subject).
//! - A **`did:webvh` / `did:web`** holder proof needs resolver-based key
//!   resolution — a follow-up slice (symmetric with the receive side, which
//!   defers the same resolver path).
//! - **Sealed** issuance to an *unknown* holder (the invite / air-gap case) is
//!   the `sealed_transfer` slice (3.6); this operation is the cleartext,
//!   known-holder path.

use affinidi_openid4vci::issuer::{
    create_credential_offer, create_credential_response, validate_credential_request,
};
use affinidi_openid4vci::{CredentialOffer, CredentialRequest, CredentialResponse};
use affinidi_sd_jwt::SdJwt;
use affinidi_sd_jwt::error::SdJwtError;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::signer::JwtVerifier;
use affinidi_sd_jwt::verifier::{VerificationOptions, verify as verify_sd_jwt};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// OID4VCI proof-JWT `typ` header (OID4VCI §7.2.1).
const OID4VCI_PROOF_TYP: &str = "openid4vci-proof+jwt";

/// Freshness window for a key-binding proof — a proof whose `iat` is older than
/// this (or implausibly in the future) is rejected. Mirrors the 60s DIDComm
/// envelope window's intent with a little more slack for wallet clock drift.
const PROOF_MAX_AGE_SECS: i64 = 300;
/// Tolerance for a proof `iat` slightly ahead of the issuer's clock.
const PROOF_FUTURE_SKEW_SECS: i64 = 60;

/// A holder key-binding proof that [`verify_oid4vci_proof`] has cryptographically
/// verified: the signature checked out under the key named by the proof's `kid`.
#[derive(Debug, Clone)]
pub struct ProvenHolderProof {
    /// The `did:key` whose key signed the proof (the `kid` with any fragment
    /// stripped). The requester demonstrably controls this DID's key.
    pub holder_did: String,
    /// The issuer-supplied freshness nonce the proof committed to, if any
    /// (the OID4VCI `c_nonce`). A later wiring slice uses this to correlate the
    /// request back to a single-use pending offer.
    pub nonce: Option<String>,
}

/// Verify an OID4VCI key-binding proof JWT.
///
/// Checks, in order: the compact JWT is well-formed; `typ` is
/// `openid4vci-proof+jwt` and `alg` is `EdDSA`; the `kid` names a `did:key`;
/// the Ed25519 signature verifies under that key; the `aud` names this issuer;
/// and the `iat` is fresh. On success the proven `did:key` (and nonce) are
/// returned — only then may a credential bound to that DID be released.
///
/// `did:webvh` / `did:web` `kid`s need resolver-based key resolution and are a
/// follow-up slice; here a non-`did:key` `kid` is rejected.
pub fn verify_oid4vci_proof(
    proof_jwt: &str,
    expected_aud: &str,
    now: DateTime<Utc>,
) -> Result<ProvenHolderProof, AppError> {
    let mut parts = proof_jwt.split('.');
    let (h_b64, p_b64, s_b64) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => {
            return Err(AppError::Validation(
                "key-binding proof is not a compact JWS (header.payload.signature)".into(),
            ));
        }
    };

    let header = decode_segment(h_b64, "proof header")?;
    if header.get("typ").and_then(Value::as_str) != Some(OID4VCI_PROOF_TYP) {
        return Err(AppError::Validation(format!(
            "key-binding proof `typ` must be `{OID4VCI_PROOF_TYP}`"
        )));
    }
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(AppError::Validation(
            "key-binding proof `alg` must be `EdDSA` (Ed25519)".into(),
        ));
    }

    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("key-binding proof header has no `kid`".into()))?;
    // The holder DID is the `kid` with any VM fragment stripped.
    let holder_did = kid.split('#').next().unwrap_or(kid).to_string();
    if !holder_did.starts_with("did:key:") {
        return Err(AppError::Validation(format!(
            "key-binding proof `kid` ({holder_did}) is not a `did:key` — resolving a \
             did:webvh / did:web holder needs the DID resolver, a follow-up slice"
        )));
    }

    // Resolve the holder's Ed25519 verifying key and check the signature over
    // the JWS signing input.
    let pub_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(&holder_did).map_err(|e| {
        AppError::Validation(format!("holder `{holder_did}` is not a did:key: {e}"))
    })?;
    let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|e| AppError::Validation(format!("holder key is not a valid Ed25519 key: {e}")))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(s_b64)
        .map_err(|e| AppError::Validation(format!("proof signature is not base64url: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| AppError::Validation(format!("proof signature is malformed: {e}")))?;
    let signing_input = format!("{h_b64}.{p_b64}");
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| AppError::Validation("key-binding proof signature did not verify".into()))?;

    // Signature is good — now the bound claims.
    let payload = decode_segment(p_b64, "proof payload")?;
    if !aud_matches(payload.get("aud"), expected_aud) {
        return Err(AppError::Validation(format!(
            "key-binding proof `aud` does not name this issuer ({expected_aud})"
        )));
    }
    let iat = payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::Validation("key-binding proof has no numeric `iat`".into()))?;
    let now_secs = now.timestamp();
    if iat > now_secs + PROOF_FUTURE_SKEW_SECS {
        return Err(AppError::Validation(
            "key-binding proof `iat` is in the future".into(),
        ));
    }
    if now_secs - iat > PROOF_MAX_AGE_SECS {
        return Err(AppError::Validation(format!(
            "key-binding proof is stale (older than {PROOF_MAX_AGE_SECS}s)"
        )));
    }

    let nonce = payload
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(ProvenHolderProof { holder_did, nonce })
}

/// Issue a credential in response to an OID4VCI credential request.
///
/// `credential` is the credential the VTC has already decided to issue (a
/// minted VMC / VEC, opaque here); `expected_holder_did` is the subject it is
/// bound to. The request's key-binding proof must verify *and* prove control of
/// exactly `expected_holder_did` — so only the rightful subject, demonstrating
/// key possession, can redeem the credential. Returns the OID4VCI
/// [`CredentialResponse`] to wrap in a `credential-exchange/issue` body.
pub fn issue_on_request(
    request: &CredentialRequest,
    credential: Value,
    expected_holder_did: &str,
    issuer_id: &str,
    now: DateTime<Utc>,
) -> Result<CredentialResponse, AppError> {
    // Structural validation (format present, vct/doctype for the format,
    // proof envelope well-formed) from the OID4VCI crate.
    validate_credential_request(request)
        .map_err(|e| AppError::Validation(format!("invalid credential request: {e}")))?;

    let proof = request.proof.as_ref().ok_or_else(|| {
        AppError::Validation(
            "credential request carries no key-binding proof — issuance requires \
             proof of holder key possession"
                .into(),
        )
    })?;
    if proof.proof_type != "jwt" {
        return Err(AppError::Validation(format!(
            "unsupported key-binding proof type `{}` (expected `jwt`)",
            proof.proof_type
        )));
    }

    let proven = verify_oid4vci_proof(&proof.jwt, issuer_id, now)?;
    if proven.holder_did != expected_holder_did {
        // Forbidden, not Validation: the proof is valid, but it binds a
        // different DID than the credential's subject — a redemption-by-the-
        // wrong-party attempt, not a malformed request.
        return Err(AppError::Forbidden(format!(
            "key-binding proof proves control of {} but the credential is bound to {}",
            proven.holder_did, expected_holder_did
        )));
    }

    Ok(create_credential_response(credential, None, None))
}

/// Build an OID4VCI pre-authorized-code credential offer for `config_ids`.
///
/// Thin wrapper over [`create_credential_offer`] that documents the VTC's
/// stance: issuance is always pre-authorized (the community has already decided
/// to issue — via a ceremony / approval — before the offer goes out), never the
/// interactive OAuth authorization-code flow. `pre_authorized_code` is the
/// single-use redemption token (a later slice persists the pending offer keyed
/// by it).
pub fn credential_offer(
    issuer_id: &str,
    config_ids: Vec<String>,
    pre_authorized_code: String,
) -> CredentialOffer {
    create_credential_offer(issuer_id, config_ids, Some(pre_authorized_code))
}

// ── Verifier side: verify a presented vp_token (Phase 3, task 3.4) ──
//
// The VTC verifier emits a `credential-exchange/query` and receives a
// `credential-exchange/present` carrying a `vp_token`. This verifies that token:
// the issuer signature, the holder key-binding (bound to our nonce + identity),
// and temporal validity — so a holder can prove it holds a credential we (or a
// trusted issuer) issued, without us re-reading the wire bytes by hand.

/// A production Ed25519 verifier for the SD-JWT [`JwtVerifier`] trait: checks the
/// compact JWS signature with `verify_strict` and returns the decoded payload.
struct EdDsaJwtVerifier {
    key: VerifyingKey,
}

impl JwtVerifier for EdDsaJwtVerifier {
    fn verify_jwt(&self, jws: &str) -> Result<Value, SdJwtError> {
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err(SdJwtError::Verification("malformed JWS".into()));
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        self.key
            .verify_strict(signing_input.as_bytes(), &signature)
            .map_err(|_| SdJwtError::Verification("signature did not verify".into()))?;
        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        serde_json::from_slice(&payload).map_err(|e| SdJwtError::Verification(e.to_string()))
    }
}

/// A cryptographically-verified SD-JWT-VC presentation.
///
/// Typestate: only constructable via [`verify_presentation`], so any code that
/// takes a `VerifiedPresentation` is guaranteed to be looking at a presentation
/// whose issuer signature, holder binding, and freshness all checked out.
#[derive(Debug, Clone)]
pub struct VerifiedPresentation {
    /// The issuer DID (`iss`) whose signature verified.
    pub issuer_did: String,
    /// The proven holder DID — the `did:key` of the `cnf.jwk` key whose kb-jwt
    /// signature verified against `expected_aud` + `expected_nonce`.
    pub holder_did: String,
    /// The credential type (`vct`), if present.
    pub vct: Option<String>,
    /// The disclosed claims (issuer-protected claims + the revealed subset).
    pub claims: Value,
    /// Whether the presenter **cryptographically proved control of the holder
    /// key** (so the presenter *is* the subject), versus mere possession of the
    /// credential. True for SD-JWT-VC (`kb-jwt`), DI VP (holder proof), and
    /// holder-bound **bbs-2023 pseudonym** proofs; **false** for a basic
    /// (possession-based) bbs-2023 derived proof. A join policy can require this
    /// (see the `holder_bound` fact) for sensitive communities.
    pub holder_bound: bool,
    /// The raw `credentialStatus` entry (W3C `BitstringStatusListEntry`) or
    /// SD-JWT-VC IETF `status` object, captured at verify time so the join
    /// verifier can resolve revocation. `None` when the credential opted into no
    /// status list (treated as "not revocable"). Captured here rather than read
    /// from [`Self::claims`] because the DI path stores only `credentialSubject`
    /// in `claims`, while `credentialStatus` is a sibling top-level VC field.
    pub credential_status: Option<Value>,
}

/// Extract a credential's status entry from a verified SD-JWT-VC payload or a DI
/// VC object: the W3C `credentialStatus` (a sibling of `credentialSubject`), or
/// the SD-JWT-VC IETF `status` object (`{ status_list: { uri, idx } }`) as a
/// fallback. `None` when neither is present (the credential is not revocable).
fn extract_credential_status(source: &Value) -> Option<Value> {
    source
        .get("credentialStatus")
        .or_else(|| source.get("status"))
        .cloned()
}

/// A [`VerificationMethodResolver`] over the VTC's optional [`DIDCacheClient`].
///
/// `did:key` verification methods resolve locally (no I/O); `did:webvh` /
/// `did:web` resolve through the cache (which must then be configured). Returns
/// Ed25519 keys only — the credential-exchange formats verified here are all
/// EdDSA. The DID-document JSON navigation mirrors
/// `recognition::verify::DidResolverKeyResolver`.
pub(crate) struct DidVmResolver<'a> {
    resolver: Option<&'a affinidi_did_resolver_cache_sdk::DIDCacheClient>,
}

impl<'a> DidVmResolver<'a> {
    pub(crate) fn new(
        resolver: Option<&'a affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    ) -> Self {
        Self { resolver }
    }

    /// Resolve a verification-method URI (or a bare `did:key`) to its Ed25519
    /// public-key bytes. `did:key` is local; other methods use the cache.
    pub(crate) async fn resolve_ed25519(&self, vm: &str) -> Result<Vec<u8>, AppError> {
        let base_did = vm.split('#').next().unwrap_or(vm);
        if base_did.starts_with("did:key:") {
            return affinidi_crypto::did_key::did_key_to_ed25519_pub(base_did)
                .map(|k| k.to_vec())
                .map_err(|e| {
                    AppError::Validation(format!("`{base_did}` is not a resolvable did:key: {e}"))
                });
        }
        let resolver = self.resolver.ok_or_else(|| {
            AppError::Validation(format!(
                "resolving `{base_did}` needs a DID resolver, but none is configured — configure \
                 the DID cache to verify did:webvh / did:web issuers + holders"
            ))
        })?;
        let resolved = resolver
            .resolve(base_did)
            .await
            .map_err(|e| AppError::Validation(format!("DID `{base_did}` did not resolve: {e}")))?;
        let doc: Value = serde_json::to_value(&resolved.doc)
            .map_err(|e| AppError::Internal(format!("DID document serialise failed: {e}")))?;
        let vms = doc
            .get("verificationMethod")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                AppError::Validation(format!("DID `{base_did}` has no verificationMethod array"))
            })?;
        let relative = vm
            .split_once('#')
            .map(|(_, f)| format!("#{f}"))
            .unwrap_or_default();
        let entry = vms
            .iter()
            .find(|e| {
                let id = e.get("id").and_then(Value::as_str).unwrap_or("");
                id == vm || id == relative
            })
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "verificationMethod `{vm}` not found in DID `{base_did}`"
                ))
            })?;
        let multibase = entry
            .get("publicKeyMultibase")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "verificationMethod `{vm}` has no publicKeyMultibase (Multikey-encoded \
                     Ed25519 only)"
                ))
            })?;
        // A `z`-prefixed Ed25519 Multikey is exactly the `did:key` suffix.
        affinidi_crypto::did_key::did_key_to_ed25519_pub(&format!("did:key:{multibase}"))
            .map(|k| k.to_vec())
            .map_err(|e| {
                AppError::Validation(format!(
                    "verificationMethod `{vm}` is not an Ed25519 Multikey: {e}"
                ))
            })
    }

    /// As [`Self::resolve_ed25519`] but returns a [`VerifyingKey`] for the
    /// SD-JWT issuer-signature path.
    pub(crate) async fn resolve_verifying_key(&self, vm: &str) -> Result<VerifyingKey, AppError> {
        let bytes = self.resolve_ed25519(vm).await?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            AppError::Validation(format!("verificationMethod `{vm}` key is not 32 bytes"))
        })?;
        VerifyingKey::from_bytes(&arr).map_err(|e| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` is not a valid Ed25519 key: {e}"
            ))
        })
    }

    /// Resolve a verification-method URI (or a bare `did:key`) to its 96-byte
    /// compressed BLS12-381 G2 public key — a BBS+ issuer key. Mirrors
    /// [`Self::resolve_ed25519`] (a `z`-prefixed Multikey is exactly the
    /// `did:key` suffix), decoding via the `0xeb` multicodec.
    #[cfg(feature = "bbs")]
    pub(crate) async fn resolve_bbs_g2(&self, vm: &str) -> Result<[u8; 96], AppError> {
        let base_did = vm.split('#').next().unwrap_or(vm);
        if base_did.starts_with("did:key:") {
            return affinidi_crypto::bls12381::did_key_to_g2_pub(base_did).map_err(|e| {
                AppError::Validation(format!("`{base_did}` is not a BBS did:key: {e}"))
            });
        }
        let resolver = self.resolver.ok_or_else(|| {
            AppError::Validation(format!(
                "resolving `{base_did}` needs a DID resolver to verify did:webvh / did:web \
                 BBS issuers"
            ))
        })?;
        let resolved = resolver
            .resolve(base_did)
            .await
            .map_err(|e| AppError::Validation(format!("DID `{base_did}` did not resolve: {e}")))?;
        let doc: Value = serde_json::to_value(&resolved.doc)
            .map_err(|e| AppError::Internal(format!("DID document serialise failed: {e}")))?;
        let vms = doc
            .get("verificationMethod")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                AppError::Validation(format!("DID `{base_did}` has no verificationMethod array"))
            })?;
        let relative = vm
            .split_once('#')
            .map(|(_, f)| format!("#{f}"))
            .unwrap_or_default();
        let entry = vms
            .iter()
            .find(|e| {
                let id = e.get("id").and_then(Value::as_str).unwrap_or("");
                id == vm || id == relative
            })
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "verificationMethod `{vm}` not found in DID `{base_did}`"
                ))
            })?;
        let multibase = entry
            .get("publicKeyMultibase")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "verificationMethod `{vm}` has no publicKeyMultibase (BLS12-381 G2 Multikey)"
                ))
            })?;
        affinidi_crypto::bls12381::did_key_to_g2_pub(&format!("did:key:{multibase}")).map_err(|e| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` is not a BLS12-381 G2 Multikey: {e}"
            ))
        })
    }
}

#[async_trait::async_trait]
impl affinidi_data_integrity::VerificationMethodResolver for DidVmResolver<'_> {
    async fn resolve_vm(
        &self,
        vm: &str,
    ) -> Result<affinidi_data_integrity::ResolvedKey, affinidi_data_integrity::DataIntegrityError>
    {
        let bytes = self
            .resolve_ed25519(vm)
            .await
            .map_err(|e| affinidi_data_integrity::DataIntegrityError::Resolver(e.to_string()))?;
        Ok(affinidi_data_integrity::ResolvedKey::new(
            affinidi_secrets_resolver::secrets::KeyType::Ed25519,
            bytes,
        ))
    }
}

/// Verify an SD-JWT-VC `vp_token` received on `credential-exchange/present`.
///
/// Checks, in order: the token parses and carries a holder `kb-jwt`; the issuer
/// JWS signature (issuer key resolved from the JWS `kid`, bound to `iss` — a
/// `did:key` issuer resolves locally, a `did:webvh` / `did:web` issuer through
/// `did_resolver`); the holder key-binding JWT — bound to `expected_aud` +
/// `expected_nonce`, signed by the `cnf.jwk` key the issuer committed to (RFC
/// 9901 §8.3); and temporal validity (`nbf` / `exp`).
///
/// Deferred to follow-up slices: status-list revocation, issuer-trust (TRQP),
/// and re-checking DCQL satisfaction.
pub async fn verify_presentation(
    vp_token: &Value,
    expected_aud: &str,
    expected_nonce: &str,
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    now: DateTime<Utc>,
) -> Result<VerifiedPresentation, AppError> {
    let compact = vp_token.as_str().ok_or_else(|| {
        AppError::Validation("vp_token must be a compact SD-JWT-VC string".into())
    })?;

    let hasher = Sha256Hasher;
    let sd = SdJwt::parse(compact, &hasher)
        .map_err(|e| AppError::Validation(format!("vp_token is not a parseable SD-JWT-VC: {e}")))?;
    if sd.kb_jwt.is_none() {
        return Err(AppError::Validation(
            "presentation carries no holder kb-jwt (unbound presentation refused)".into(),
        ));
    }

    let payload = sd
        .payload()
        .map_err(|e| AppError::Validation(format!("presentation payload: {e}")))?;

    let issuer_did = payload
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("presentation has no `iss`".into()))?
        .to_string();
    // The signing key is named by the issuer JWS `kid` (fall back to `iss` for a
    // bare did:key issuer). Bind it to `iss` — a key under some *other* DID must
    // not sign a credential claiming this issuer.
    let header = sd
        .header()
        .map_err(|e| AppError::Validation(format!("presentation header: {e}")))?;
    let issuer_vm = header
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| issuer_did.clone());
    if issuer_vm.split('#').next().unwrap_or_default() != issuer_did {
        return Err(AppError::Validation(format!(
            "SD-JWT issuer kid `{issuer_vm}` is not under `iss` (`{issuer_did}`)"
        )));
    }
    let resolver = DidVmResolver::new(did_resolver);
    let issuer_verifier = EdDsaJwtVerifier {
        key: resolver.resolve_verifying_key(&issuer_vm).await?,
    };

    let cnf_jwk = payload
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .ok_or_else(|| {
            AppError::Validation("presentation has no `cnf.jwk` (holder binding)".into())
        })?;
    let holder_key = ed25519_from_okp_jwk(cnf_jwk)?;
    // The proven holder DID is the did:key of the cnf binding key.
    let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&holder_key.to_bytes());
    let holder_verifier = EdDsaJwtVerifier { key: holder_key };

    let options = VerificationOptions {
        verify_kb: true,
        expected_audience: Some(expected_aud),
        expected_nonce: Some(expected_nonce),
    };
    let result = verify_sd_jwt(
        &sd,
        &issuer_verifier,
        &hasher,
        &options,
        Some(&holder_verifier),
    )
    .map_err(|e| AppError::Validation(format!("presentation verification failed: {e}")))?;
    if !result.is_verified() {
        return Err(AppError::Validation(
            "holder key-binding (kb-jwt) did not verify".into(),
        ));
    }

    check_temporal(&result.claims, now)?;

    let vct = result
        .claims
        .get("vct")
        .and_then(Value::as_str)
        .map(str::to_string);
    let credential_status = extract_credential_status(&result.claims);
    Ok(VerifiedPresentation {
        issuer_did,
        holder_did,
        vct,
        // SD-JWT-VC carries a mandatory holder `kb-jwt` — the presenter proved
        // control of the holder key.
        holder_bound: true,
        claims: result.claims,
        credential_status,
    })
}

/// A cryptographically-verified set of presentations — the verified projection
/// of an OID4VP DCQL `vp_token`.
///
/// Typestate: only constructable via [`verify_vp_token`], so any code that takes
/// a `VerifiedPresentationSet` is guaranteed every presentation's issuer
/// signature, holder binding, and freshness checked out, **and** that every
/// presentation is bound to the same holder.
#[derive(Debug, Clone)]
pub struct VerifiedPresentationSet {
    /// The single proven holder DID — every presentation in the set is bound to
    /// it (a multi-credential `vp_token` whose entries disagree on the holder is
    /// refused; a join is one applicant).
    pub holder: String,
    /// Each verified presentation, in DCQL `credential_query_id` order.
    pub presentations: Vec<VerifiedPresentation>,
}

/// Verify an OID4VP DCQL `vp_token` — the map the VTA holder produces, keyed by
/// DCQL `credential_query_id`. Each entry is verified against `expected_aud` +
/// `expected_nonce`; every entry must bind the **same holder** (a join is one
/// applicant). Returns the verified set.
///
/// Accepts three shapes for forward/backward compatibility:
/// - a JSON **object** (the canonical DCQL `vp_token`): each value is one
///   presentation, or an **array** of presentations under one query id;
/// - a bare **string** (a single SD-JWT-VC presentation — the pre-map form).
///
/// **SD-JWT-VC** entries (compact strings) and **W3C Data-Integrity VP** entries
/// (JSON objects) are both verified. A `did:webvh` / `did:web` issuer or holder
/// is resolved through `did_resolver` (a `did:key` resolves locally).
pub async fn verify_vp_token(
    vp_token: &Value,
    expected_aud: &str,
    expected_nonce: &str,
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    now: DateTime<Utc>,
) -> Result<VerifiedPresentationSet, AppError> {
    // Flatten the vp_token into the individual presentation values to verify.
    let entries: Vec<&Value> = match vp_token {
        Value::String(_) => vec![vp_token],
        Value::Object(map) => {
            if map.is_empty() {
                return Err(AppError::Validation(
                    "vp_token is an empty object (no presentations)".into(),
                ));
            }
            let mut out = Vec::new();
            for value in map.values() {
                match value {
                    Value::Array(items) => out.extend(items.iter()),
                    other => out.push(other),
                }
            }
            out
        }
        _ => {
            return Err(AppError::Validation(
                "vp_token must be a DCQL object or a compact SD-JWT-VC string".into(),
            ));
        }
    };

    let mut presentations = Vec::with_capacity(entries.len());
    let mut holder: Option<String> = None;
    for entry in entries {
        // A JSON **object** is a W3C Data-Integrity VP (eddsa-jcs-2022 holder
        // proof, may carry several VCs) **or** a bbs-2023 derived-proof VC; a
        // **string** is one SD-JWT-VC presentation.
        let verified: Vec<VerifiedPresentation> = if entry.is_object() {
            if is_bbs_2023_presentation(entry) {
                verify_bbs_dispatch(entry, expected_aud, expected_nonce, did_resolver, now).await?
            } else {
                verify_di_vp(entry, expected_aud, expected_nonce, did_resolver, now).await?
            }
        } else {
            vec![verify_presentation(entry, expected_aud, expected_nonce, did_resolver, now).await?]
        };
        for v in verified {
            match &holder {
                None => holder = Some(v.holder_did.clone()),
                Some(h) if h != &v.holder_did => {
                    return Err(AppError::Validation(format!(
                        "vp_token presentations disagree on the holder (`{h}` vs \
                         `{}`) — a single presentation must bind one holder",
                        v.holder_did
                    )));
                }
                Some(_) => {}
            }
            presentations.push(v);
        }
    }

    let holder = holder.ok_or_else(|| {
        AppError::Validation("vp_token carried no presentations to verify".into())
    })?;
    Ok(VerifiedPresentationSet {
        holder,
        presentations,
    })
}

/// Verify a **W3C Data-Integrity VP** (the JSON object the VTA's `present_di_vc`
/// produces) and project each contained VC into a [`VerifiedPresentation`].
///
/// Checks, in order: the holder `eddsa-jcs-2022` proof over the VP (minus its
/// proof), with `proofPurpose` `authentication`; the `nonce` + `domain` bind
/// `expected_nonce` + `expected_aud`; then, for each `verifiableCredential`, the
/// issuer's `eddsa-jcs-2022` proof (verification method **bound to the VC
/// `issuer`**) and W3C temporal validity (`validFrom` / `validUntil`). Issuer
/// and holder keys resolve through `did_resolver` (`did:key` locally).
async fn verify_di_vp(
    vp: &Value,
    expected_aud: &str,
    expected_nonce: &str,
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    now: DateTime<Utc>,
) -> Result<Vec<VerifiedPresentation>, AppError> {
    use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};

    let resolver = DidVmResolver::new(did_resolver);

    // 1. Holder proof over the VP (minus its proof).
    let proof_val = vp
        .get("proof")
        .ok_or_else(|| AppError::Validation("DI VP has no `proof` (holder binding)".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_val.clone()).map_err(|e| {
        AppError::Validation(format!("DI VP proof is not a Data-Integrity proof: {e}"))
    })?;
    if proof.proof_purpose != "authentication" {
        return Err(AppError::Validation(format!(
            "DI VP holder proof purpose is `{}`, expected `authentication`",
            proof.proof_purpose
        )));
    }
    let holder_did = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default()
        .to_string();
    let mut vp_unsigned = vp.clone();
    if let Some(obj) = vp_unsigned.as_object_mut() {
        obj.remove("proof");
    }
    proof
        .verify(&vp_unsigned, &resolver, VerifyOptions::new())
        .await
        .map_err(|e| AppError::Validation(format!("DI VP holder proof did not verify: {e}")))?;

    // 2. Freshness + audience binding (both are top-level VP fields, signed).
    if vp.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
        return Err(AppError::Validation(
            "DI VP `nonce` does not match the verifier's challenge".into(),
        ));
    }
    if vp.get("domain").and_then(Value::as_str) != Some(expected_aud) {
        return Err(AppError::Validation(
            "DI VP `domain` does not name this verifier".into(),
        ));
    }

    // 3. Each contained credential: issuer proof (bound to `issuer`) + temporal.
    let vcs = vp
        .get("verifiableCredential")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            AppError::Validation("DI VP has no `verifiableCredential` to verify".into())
        })?;

    let mut out = Vec::with_capacity(vcs.len());
    for vc in vcs {
        let issuer_did = vc
            .get("issuer")
            .and_then(|i| match i {
                Value::String(s) => Some(s.clone()),
                Value::Object(o) => o.get("id").and_then(Value::as_str).map(str::to_string),
                _ => None,
            })
            .ok_or_else(|| AppError::Validation("DI VC has no `issuer`".into()))?;

        let vc_proof_val = vc
            .get("proof")
            .ok_or_else(|| AppError::Validation("DI VC has no issuer `proof`".into()))?;
        let vc_proof: DataIntegrityProof =
            serde_json::from_value(vc_proof_val.clone()).map_err(|e| {
                AppError::Validation(format!("DI VC proof is not a Data-Integrity proof: {e}"))
            })?;
        // Bind the signing key to the VC issuer.
        if vc_proof
            .verification_method
            .split('#')
            .next()
            .unwrap_or_default()
            != issuer_did
        {
            return Err(AppError::Validation(format!(
                "DI VC proof verificationMethod `{}` is not under the issuer `{issuer_did}`",
                vc_proof.verification_method
            )));
        }
        let mut vc_unsigned = vc.clone();
        if let Some(obj) = vc_unsigned.as_object_mut() {
            obj.remove("proof");
        }
        vc_proof
            .verify(&vc_unsigned, &resolver, VerifyOptions::new())
            .await
            .map_err(|e| AppError::Validation(format!("DI VC issuer proof did not verify: {e}")))?;

        check_w3c_temporal(vc, now)?;

        let vct = vc.get("type").and_then(|t| match t {
            Value::Array(a) => a
                .iter()
                .filter_map(Value::as_str)
                .find(|s| *s != "VerifiableCredential")
                .map(str::to_string),
            Value::String(s) => Some(s.clone()),
            _ => None,
        });
        // The W3C `credentialStatus` is a top-level VC field (sibling of
        // `credentialSubject`); capture it from the full VC, not the subject.
        let credential_status = extract_credential_status(vc);
        out.push(VerifiedPresentation {
            issuer_did,
            holder_did: holder_did.clone(),
            vct,
            // A DI VP carries a holder `DataIntegrityProof` — the presenter proved
            // control of the holder key.
            holder_bound: true,
            claims: vc.get("credentialSubject").cloned().unwrap_or(Value::Null),
            credential_status,
        });
    }
    Ok(out)
}

/// True iff `entry` is a `bbs-2023` derived-proof presentation — a JSON VC whose
/// `proof.cryptosuite` is `bbs-2023`. Used to route a vp_token entry to the BBS
/// verifier rather than the eddsa-jcs Data-Integrity VP path. Pure JSON
/// inspection, so it works (to produce a clean error) even without the `bbs`
/// feature.
fn is_bbs_2023_presentation(entry: &Value) -> bool {
    entry
        .get("proof")
        .and_then(|p| p.get("cryptosuite"))
        .and_then(Value::as_str)
        == Some("bbs-2023")
}

/// Dispatch a detected bbs-2023 presentation to the verifier, or fail cleanly
/// when the crate was built without the `bbs` feature.
async fn verify_bbs_dispatch(
    entry: &Value,
    expected_aud: &str,
    expected_nonce: &str,
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    now: DateTime<Utc>,
) -> Result<Vec<VerifiedPresentation>, AppError> {
    #[cfg(feature = "bbs")]
    {
        Ok(vec![
            verify_bbs_presentation(entry, expected_aud, expected_nonce, did_resolver, now).await?,
        ])
    }
    #[cfg(not(feature = "bbs"))]
    {
        let _ = (entry, expected_aud, expected_nonce, did_resolver, now);
        Err(AppError::Validation(
            "a bbs-2023 presentation was received but this VTC was built without the `bbs` \
             feature"
                .into(),
        ))
    }
}

/// Inspect a `bbs-2023` **derived** proofValue: returns its embedded
/// `presentationHeader` and whether it is a **pseudonym** (holder-bound) proof.
///
/// The standards-track `verify_derived_proof` / `verify_pseudonym_derived_proof`
/// authenticate against the header carried *inside* the proof rather than a
/// verifier-supplied one, so the verifier must extract it to bind freshness. The
/// derived proofValue is `multibase-base64url("u" || 0xd95d0{3,9} ||
/// CBOR([...]))`; `0xd95d03` is a basic derived proof and `0xd95d09` a pseudonym
/// (holder-bound) one. The presentation header is element index 4 of the CBOR
/// array in both forms.
#[cfg(feature = "bbs")]
fn bbs_inspect_derived_proof(vc: &Value) -> Result<(Vec<u8>, bool), AppError> {
    let pv = vc
        .get("proof")
        .and_then(|p| p.get("proofValue"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("bbs-2023 presentation has no `proofValue`".into()))?;
    let (_base, bytes) = multibase::decode(pv).map_err(|e| {
        AppError::Validation(format!("bbs-2023 `proofValue` is not multibase: {e}"))
    })?;
    // 0xd95d03 = basic derived, 0xd95d09 = pseudonym derived. Reject base proofs
    // (0xd95d02 / 0xd95d08) and anything else — only a *disclosure* proof is a
    // presentation.
    if bytes.len() < 3 || bytes[0] != 0xd9 || bytes[1] != 0x5d {
        return Err(AppError::Validation(
            "bbs-2023 `proofValue` is not a derived (disclosure) proof".into(),
        ));
    }
    let is_pseudonym = match bytes[2] {
        0x03 => false,
        0x09 => true,
        _ => {
            return Err(AppError::Validation(
                "bbs-2023 `proofValue` is not a derived (disclosure) proof".into(),
            ));
        }
    };
    let value: ciborium::value::Value = ciborium::from_reader(&bytes[3..]).map_err(|e| {
        AppError::Validation(format!("bbs-2023 `proofValue` CBOR is malformed: {e}"))
    })?;
    let header = value
        .as_array()
        .and_then(|arr| arr.get(4))
        .and_then(ciborium::value::Value::as_bytes)
        .ok_or_else(|| {
            AppError::Validation("bbs-2023 derived `proofValue` has no presentationHeader".into())
        })?;
    Ok((header.clone(), is_pseudonym))
}

/// Verify a **bbs-2023 derived-proof** presentation and project it into a
/// [`VerifiedPresentation`].
///
/// Requires `affinidi-data-integrity` ≥ 0.7.5 (the vc-di-bbs disclosed-value
/// soundness fix, affinidi-tdk-rs#381): every claim term in a presented VC must
/// be defined by its `@context` (JSON-LD safe mode), else verification refuses
/// it. BBS issuer *signing* remains separately audit-gated (#294).
///
/// The derived proof (the disclosed VC's `proof`) proves the holder possesses a
/// credential validly issued by the VC `issuer` and discloses only the revealed
/// claims, bound to the verifier's `expected_nonce` (the presentation header).
/// The issuer's BLS12-381 G2 key resolves from its DID (the proof's
/// `verificationMethod`, bound to `issuer`).
///
/// **Holder semantics — two modes, by proof kind:**
/// - A **basic** derived proof (`0xd95d03`) carries **no holder-key binding** —
///   it is unlinkable and possession-based. The applicant (`holder_did`) is taken
///   to be the **disclosed `credentialSubject.id`** (a mandatory-disclosed claim),
///   and [`VerifiedPresentation::holder_bound`] is `false`.
/// - A **pseudonym** derived proof (`0xd95d09`) is holder-bound: the holder proves
///   knowledge of the link secret committed at issuance, bound to a per-verifier
///   context. We verify it against `expected_aud` as the `verifier_id` (so the
///   pseudonym is stable per verifier, unlinkable across verifiers), and
///   `holder_bound` is `true`. The join policy can require this for sensitive
///   communities (see the `holder_bound` fact).
#[cfg(feature = "bbs")]
async fn verify_bbs_presentation(
    vc: &Value,
    expected_aud: &str,
    expected_nonce: &str,
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    now: DateTime<Utc>,
) -> Result<VerifiedPresentation, AppError> {
    use affinidi_bbs::PublicKey;
    use affinidi_data_integrity::bbs_2023_transform;

    let issuer_did = vc
        .get("issuer")
        .and_then(|i| match i {
            Value::String(s) => Some(s.clone()),
            Value::Object(o) => o.get("id").and_then(Value::as_str).map(str::to_string),
            _ => None,
        })
        .ok_or_else(|| AppError::Validation("bbs-2023 VC has no `issuer`".into()))?;

    // Bind the signing key to the issuer, then resolve its G2 key.
    let vm = vc
        .get("proof")
        .and_then(|p| p.get("verificationMethod"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("bbs-2023 proof has no `verificationMethod`".into()))?;
    if vm.split('#').next().unwrap_or_default() != issuer_did {
        return Err(AppError::Validation(format!(
            "bbs-2023 proof verificationMethod `{vm}` is not under the issuer `{issuer_did}`"
        )));
    }
    let g2 = DidVmResolver::new(did_resolver).resolve_bbs_g2(vm).await?;
    let pk = PublicKey::from_bytes(&g2)
        .map_err(|e| AppError::Validation(format!("bbs-2023 issuer key is invalid: {e}")))?;

    // Freshness / anti-replay: the standards-track verify authenticates the
    // presentation header *embedded* in the derived proof, not a verifier-supplied
    // one — so we read that header back out and bind it to the challenge this
    // verifier issued. Without this check a proof minted for any other challenge
    // would verify cryptographically. The same inspection tells us whether this is
    // a holder-bound *pseudonym* proof (`0xd95d09`) or a basic one (`0xd95d03`).
    let (header, holder_bound) = bbs_inspect_derived_proof(vc)?;
    if header != expected_nonce.as_bytes() {
        return Err(AppError::Validation(
            "bbs-2023 presentation header does not match the expected challenge".into(),
        ));
    }
    let verified = if holder_bound {
        // Pseudonym proof: verify the per-verifier holder binding against `aud`.
        bbs_2023_transform::verify_pseudonym_derived_proof(vc, &pk, expected_aud)
    } else {
        bbs_2023_transform::verify_derived_proof(vc, &pk)
    }
    .map_err(|e| AppError::Validation(format!("bbs-2023 presentation did not verify: {e}")))?;
    if !verified {
        return Err(AppError::Validation(
            "bbs-2023 presentation proof did not verify".into(),
        ));
    }
    check_w3c_temporal(vc, now)?;

    let holder_did = vc
        .get("credentialSubject")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            AppError::Validation(
                "bbs-2023 presentation discloses no `credentialSubject.id` (the applicant); \
                 the subject id must be a mandatory-disclosed claim"
                    .into(),
            )
        })?;
    let vct = vc.get("type").and_then(|t| match t {
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .find(|s| *s != "VerifiableCredential")
            .map(str::to_string),
        Value::String(s) => Some(s.clone()),
        _ => None,
    });
    let credential_status = extract_credential_status(vc);

    Ok(VerifiedPresentation {
        issuer_did,
        holder_did,
        vct,
        // `true` only for a pseudonym (holder-bound) proof; a basic derived proof
        // is possession-based.
        holder_bound,
        claims: vc.get("credentialSubject").cloned().unwrap_or(Value::Null),
        credential_status,
    })
}

/// Enforce W3C VCDM v2 temporal validity (`validFrom` / `validUntil`, RFC-3339).
fn check_w3c_temporal(vc: &Value, now: DateTime<Utc>) -> Result<(), AppError> {
    if let Some(vf) = vc.get("validFrom").and_then(Value::as_str) {
        let vf = DateTime::parse_from_rfc3339(vf)
            .map_err(|e| AppError::Validation(format!("DI VC `validFrom` is not RFC-3339: {e}")))?;
        if now < vf {
            return Err(AppError::Validation(
                "DI VC is not yet valid (`validFrom` in the future)".into(),
            ));
        }
    }
    if let Some(vu) = vc.get("validUntil").and_then(Value::as_str) {
        let vu = DateTime::parse_from_rfc3339(vu).map_err(|e| {
            AppError::Validation(format!("DI VC `validUntil` is not RFC-3339: {e}"))
        })?;
        if now > vu {
            return Err(AppError::Validation(
                "DI VC has expired (`validUntil` in the past)".into(),
            ));
        }
    }
    Ok(())
}

/// Build a verifying key from an RFC 8037 OKP / Ed25519 JWK (the `cnf.jwk`).
fn ed25519_from_okp_jwk(jwk: &Value) -> Result<VerifyingKey, AppError> {
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
    {
        return Err(AppError::Validation(
            "cnf.jwk is not an OKP / Ed25519 key".into(),
        ));
    }
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("cnf.jwk has no `x`".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| AppError::Validation(format!("cnf.jwk `x` is not base64url: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::Validation("cnf.jwk `x` is not 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| AppError::Validation(format!("cnf.jwk key is invalid: {e}")))
}

/// Enforce temporal validity over the presentation's protected claims.
fn check_temporal(claims: &Value, now: DateTime<Utc>) -> Result<(), AppError> {
    let now_s = now.timestamp();
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64)
        && now_s < nbf
    {
        return Err(AppError::Validation(
            "presentation is not yet valid (`nbf` in the future)".into(),
        ));
    }
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64)
        && now_s > exp
    {
        return Err(AppError::Validation(
            "presentation has expired (`exp` in the past)".into(),
        ));
    }
    Ok(())
}

/// Decode a base64url JWT segment into JSON.
fn decode_segment(segment: &str, what: &str) -> Result<Value, AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| AppError::Validation(format!("{what} is not base64url: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Validation(format!("{what} is not JSON: {e}")))
}

/// OID4VCI `aud` may be a single string or an array of strings; match either.
fn aud_matches(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

// ── Pending-issuance store + the offer→request→issue wire flow ──
//
// When the community decides to issue a credential (e.g. ceremony admit mints a
// VMC), the VTC emits a pre-authorized-code offer and persists a *pending
// issuance* keyed by that code. The holder later redeems it with a
// `credential-exchange/request` carrying a key-binding proof; the issuer looks
// the pending record up, verifies the proof binds the intended subject, and
// returns the credential. The **pre-authorized code doubles as the proof
// `nonce`** (the issuer-generated freshness value the holder commits to) — no
// separate token-endpoint round-trip in the DIDComm collapse.

/// Key prefix for pending issuances. Stored in the `join_requests` keyspace
/// (credential issuance is the terminal step of the join/admit lifecycle that
/// keyspace already tracks); the join retention sweeper walks `join_requests:`,
/// a disjoint prefix, so the two never collide. A dedicated keyspace is a clean
/// future migration — the prefix is the single source of truth for the shape.
const PENDING_PREFIX: &str = "credx-pending:";

/// Default lifetime of a pending offer before it expires unredeemed.
pub const DEFAULT_OFFER_TTL: Duration = Duration::minutes(30);

fn pending_key(code: &str) -> String {
    format!("{PENDING_PREFIX}{code}")
}

/// A credential the VTC has decided to issue, awaiting redemption by the holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingIssuance {
    /// The credential to deliver (already minted; opaque here).
    credential: Value,
    /// The subject the credential is bound to — only this DID, proving key
    /// possession, may redeem.
    expected_holder_did: String,
    /// The Credential Issuer Identifier the holder's proof `aud` must name.
    issuer_id: String,
    /// Expiry, seconds since the Unix epoch.
    expires_at: i64,
}

/// Emit a pre-authorized-code credential offer and persist the pending issuance.
///
/// Returns the [`CredentialOffer`] to send to the holder and the single-use
/// `pre_authorized_code` (which the holder echoes as the proof `nonce`). The
/// credential is bound to `expected_holder_did`; only that subject can redeem.
#[allow(clippy::too_many_arguments)]
pub async fn make_offer(
    ks: &KeyspaceHandle,
    issuer_id: &str,
    config_ids: Vec<String>,
    credential: Value,
    expected_holder_did: &str,
    ttl: Duration,
    now: DateTime<Utc>,
) -> Result<(CredentialOffer, String), AppError> {
    let code = format!("pac_{}", Uuid::new_v4().simple());
    let pending = PendingIssuance {
        credential,
        expected_holder_did: expected_holder_did.to_string(),
        issuer_id: issuer_id.to_string(),
        expires_at: (now + ttl).timestamp(),
    };
    ks.insert(pending_key(&code), &pending).await?;
    Ok((credential_offer(issuer_id, config_ids, code.clone()), code))
}

/// Redeem a credential request against a persisted pending offer.
///
/// Looks the pending issuance up by the request's proof `nonce` (the
/// pre-authorized code), checks it hasn't expired, then [`issue_on_request`]
/// verifies the key-binding proof and binds the holder. The pending record is
/// consumed (single-use) **only on success** — a forged or wrong-party request
/// returns an error without burning the legitimate holder's offer.
pub async fn redeem(
    ks: &KeyspaceHandle,
    request: &CredentialRequest,
    now: DateTime<Utc>,
) -> Result<CredentialResponse, AppError> {
    let code = proof_nonce(request)?.ok_or_else(|| {
        AppError::Validation(
            "credential request proof carries no nonce (the pre-authorized code)".into(),
        )
    })?;

    let pending = get_pending(ks, &code).await?.ok_or_else(|| {
        AppError::NotFound(
            "no pending issuance for this code (unknown, already redeemed, or expired)".into(),
        )
    })?;

    if now.timestamp() > pending.expires_at {
        // Best-effort cleanup of the expired record; ignore the result.
        let _ = ks.remove(pending_key(&code)).await;
        return Err(AppError::Validation("pending issuance has expired".into()));
    }

    // Verifies the proof signature, audience, freshness, and that the proven
    // holder DID equals the credential's bound subject (else `Forbidden`).
    let response = issue_on_request(
        request,
        pending.credential.clone(),
        &pending.expected_holder_did,
        &pending.issuer_id,
        now,
    )?;

    // Single-use: consume the offer now that issuance succeeded.
    ks.remove(pending_key(&code)).await?;
    Ok(response)
}

async fn get_pending(ks: &KeyspaceHandle, code: &str) -> Result<Option<PendingIssuance>, AppError> {
    match ks.get_raw(pending_key(code)).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppError::Internal(format!("PendingIssuance decode: {e}"))),
        None => Ok(None),
    }
}

/// Structurally read the `nonce` claim from a credential request's proof JWT —
/// the lookup key for the pending offer. This is an **unverified** peek; the
/// real cryptographic verification happens in [`issue_on_request`], and the
/// credential is only released after the holder-binding check there.
fn proof_nonce(request: &CredentialRequest) -> Result<Option<String>, AppError> {
    let Some(proof) = request.proof.as_ref() else {
        return Ok(None);
    };
    let payload_b64 = proof.jwt.split('.').nth(1).ok_or_else(|| {
        AppError::Validation("credential request proof is not a compact JWT".into())
    })?;
    let payload = decode_segment(payload_b64, "proof payload")?;
    Ok(payload
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_openid4vci::{CredentialRequestProof, FORMAT_SD_JWT_VC};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const ISSUER: &str = "did:web:vtc.example";

    /// A holder identity: an Ed25519 key + its `did:key`.
    struct Holder {
        key: SigningKey,
        did: String,
    }
    impl Holder {
        fn new(seed: u8) -> Self {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let did =
                affinidi_crypto::did_key::ed25519_pub_to_did_key(key.verifying_key().as_bytes());
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
        let err =
            issue_on_request(&req, a_credential(), "did:key:zHolder", ISSUER, now).unwrap_err();
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
    fn make_presentation(
        aud: &str,
        nonce: &str,
        iat: u64,
        exp: i64,
        with_kb: bool,
    ) -> (String, Value) {
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
        let sd = affinidi_sd_jwt::issuer::issue(
            &claims,
            &frame,
            &issuer_signer,
            &hasher,
            Some(&holder_jwk),
        )
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
        let sd = affinidi_sd_jwt::issuer::issue(
            &claims,
            &frame,
            &issuer_signer,
            &hasher,
            Some(&holder_jwk),
        )
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
        use affinidi_data_integrity::{
            DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite,
        };
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
        use affinidi_data_integrity::{
            DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite,
        };
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
        use affinidi_data_integrity::bbs_2023_transform::{
            create_derived_proof, sign_base_document,
        };

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
}
