//! OID4VP / SD-JWT-VC / W3C-DI / bbs-2023 presentation verifier stack
//! + the DID-VM key resolver (split out of `exchange.rs`, P2.3).

use super::jwt::{check_temporal, check_w3c_temporal, ed25519_from_okp_jwk};
use affinidi_sd_jwt::SdJwt;
use affinidi_sd_jwt::error::SdJwtError;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::signer::JwtVerifier;
use affinidi_sd_jwt::verifier::{VerificationOptions, verify as verify_sd_jwt};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use vti_common::error::AppError;

use crate::credentials::vm_resolver::{DidVmResolver, check_issuer_binding};

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

/// The structural, IO-free projection of an SD-JWT-VC presentation that
/// [`parse_sd_jwt_presentation`] extracts *before* any signature check or DID
/// resolution: the parsed SD-JWT, the holder-binding presence check, the
/// `iss` / JWS-`kid` binding, and the `cnf.jwk` holder key decode.
///
/// [`verify_presentation`] resolves the issuer key and runs the cryptographic
/// verification on top of this. Splitting the parse out keeps it synchronous,
/// runtime-free, and resolver-free — a libFuzzer target that drives the exact
/// parser production uses, with no tokio or network.
#[derive(Debug)]
pub struct ParsedSdJwtPresentation {
    /// The parsed SD-JWT-VC (issuer JWS + disclosures + holder `kb-jwt`).
    pub sd: SdJwt,
    /// The credential issuer DID, from the SD-JWT payload `iss`.
    pub issuer_did: String,
    /// The issuer verification-method id — the JWS `kid`, or `iss` for a bare
    /// `did:key` issuer. Already checked to sit under `issuer_did`.
    pub issuer_vm: String,
    /// The holder binding key, decoded from `cnf.jwk` (RFC 9901 §8.3).
    pub holder_key: VerifyingKey,
    /// The proven holder DID — the `did:key` of `holder_key`.
    pub holder_did: String,
}

/// Structurally parse an SD-JWT-VC presentation without verifying any
/// signature or resolving any DID.
///
/// Checks, in order: the token is a parseable SD-JWT-VC; it carries a holder
/// `kb-jwt` (an unbound presentation is refused); it has an `iss`; the issuer
/// JWS `kid` (or `iss` fallback) sits under `iss`; and it carries a decodable
/// `cnf.jwk` Ed25519 holder key. Returns the [`ParsedSdJwtPresentation`]
/// projection the cryptographic verifier builds on.
///
/// Pure and IO-free — the high-value SD-JWT-VC parser fuzz target. The
/// signature checks and issuer-key resolution live in [`verify_presentation`].
pub fn parse_sd_jwt_presentation(compact: &str) -> Result<ParsedSdJwtPresentation, AppError> {
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

    let cnf_jwk = payload
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .ok_or_else(|| {
            AppError::Validation("presentation has no `cnf.jwk` (holder binding)".into())
        })?;
    let holder_key = ed25519_from_okp_jwk(cnf_jwk)?;
    // The proven holder DID is the did:key of the cnf binding key.
    let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&holder_key.to_bytes());

    Ok(ParsedSdJwtPresentation {
        sd,
        issuer_did,
        issuer_vm,
        holder_key,
        holder_did,
    })
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
/// The IO-free structural parse is [`parse_sd_jwt_presentation`]; this adds the
/// issuer-key resolution and signature checks. Deferred to follow-up slices:
/// status-list revocation, issuer-trust (TRQP), and re-checking DCQL
/// satisfaction.
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

    let ParsedSdJwtPresentation {
        sd,
        issuer_did,
        issuer_vm,
        holder_key,
        holder_did,
    } = parse_sd_jwt_presentation(compact)?;

    let hasher = Sha256Hasher;
    let resolver = DidVmResolver::new(did_resolver.cloned());
    let issuer_verifier = EdDsaJwtVerifier {
        key: resolver.resolve_verifying_key(&issuer_vm).await?,
    };

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

/// Flatten an OID4VP DCQL `vp_token` into the individual presentation values to
/// verify, without verifying or resolving anything.
///
/// Accepts the same shapes [`verify_vp_token`] does:
/// - a JSON **object** (the canonical DCQL `vp_token`): each value is one
///   presentation, or an **array** of presentations under one query id;
/// - a bare **string** (a single SD-JWT-VC presentation — the pre-map form).
///
/// Pure and IO-free — the OID4VP DCQL envelope-shape fuzz target. The per-entry
/// signature verification is [`verify_vp_token`].
pub fn flatten_vp_token(vp_token: &Value) -> Result<Vec<&Value>, AppError> {
    match vp_token {
        Value::String(_) => Ok(vec![vp_token]),
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
            Ok(out)
        }
        _ => Err(AppError::Validation(
            "vp_token must be a DCQL object or a compact SD-JWT-VC string".into(),
        )),
    }
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
/// is resolved through `did_resolver` (a `did:key` resolves locally). The
/// IO-free envelope flatten is [`flatten_vp_token`].
pub async fn verify_vp_token(
    vp_token: &Value,
    expected_aud: &str,
    expected_nonce: &str,
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    now: DateTime<Utc>,
) -> Result<VerifiedPresentationSet, AppError> {
    // Flatten the vp_token into the individual presentation values to verify.
    let entries = flatten_vp_token(vp_token)?;

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

    let resolver = DidVmResolver::new(did_resolver.cloned());

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
        check_issuer_binding(&vc_proof.verification_method, &issuer_did)?;
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
    check_issuer_binding(vm, issuer_did)?;
    let g2 = DidVmResolver::new(did_resolver.cloned())
        .resolve_bbs_g2(vm)
        .await?;
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
