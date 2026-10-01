//! Shared Data-Integrity issuer-proof verification.
//!
//! Verifying the proofs on a W3C Data-Integrity credential — **bound to the
//! credential's stated `issuer`** — is needed in more than one place:
//! receiving a DI credential into the vault (`credential-exchange`,
//! `vault/credentials/receive`) and verifying a
//! `BitstringStatusListCredential`'s own issuer signature before trusting it
//! ([`crate::status`]). Both share the same binding rule (every signing key
//! MUST belong to the stated issuer — otherwise a key from some *other* DID
//! could sign a credential claiming a different issuer), the same proof-set
//! rule (VTI-44 — one proof or several, every checkable one verified) and the
//! same resolution path (`did:key` locally, `did:webvh` / `did:web` via the DID
//! cache).
//!
//! Consistent with the vault's dependency-injection style, the resolver is a
//! **caller-supplied parameter** — these helpers never own a network client; for
//! `did:key` issuers no I/O happens at all, and for `did:webvh` / `did:web` the
//! injected resolver does the lookup.

use serde_json::Value;
use vta_sdk::trust_task_proof::{
    ProofPurpose, PurposeVmResolver, proof_set, proof_signer_did, verify_proof_set,
};
use vti_common::error::AppError;

/// The issuer DID of a credential — its `issuer` field as a string, or the `id`
/// of an `issuer` object. Returns `None` when the credential has no `issuer`.
pub(crate) fn credential_issuer(credential: &Value) -> Option<String> {
    let issuer = credential.get("issuer")?;
    issuer
        .as_str()
        .map(str::to_string)
        .or_else(|| issuer.get("id").and_then(Value::as_str).map(str::to_string))
}

/// Verify a Data-Integrity credential's issuer proofs, **bound to the
/// credential `issuer`**, and return that issuer DID.
///
/// `proof` may be one proof object or a proof set (VTI-44): a VTC holding
/// several signing keys signs each credential once per key —
/// `[eddsa-jcs-2022 by #key-0, mldsa44-jcs-2024 by #key-2]` — and a verifier
/// that read `proof` as one object refused every such credential. The
/// acceptance rule is the workspace's one
/// ([`vta_sdk::trust_task_proof::proof_set`]):
///
/// - **issuer binding first**: every checkable proof's `verificationMethod`
///   MUST be under the credential `issuer`, checked before any key is resolved
///   — otherwise a key belonging to some *other* DID could sign a credential
///   that claims a different issuer (issuer spoofing), and a foreign DID would
///   be resolved on the holder's behalf;
/// - every proof in a suite this build implements (Ed25519 **and** ML-DSA-44)
///   MUST verify for `assertionMethod` with a key the issuer's DID document
///   authorises for that purpose (VTI-KEY-022), and at least one must be
///   checkable. A proof in a suite this build does not implement is set aside;
///   a malformed one is refused;
/// - a `bbs-2023` proof is refused here — BBS credentials take the BBS path.
///
/// `resolver` is caller-supplied (the vault owns no network client): a
/// `did:key` issuer resolves locally (its one method is `did:key:<id>#<id>`),
/// a `did:webvh` / `did:web` one needs a resolver with network resolution,
/// e.g. `TrustTaskVmResolver::from_optional(did_cache)`.
pub async fn verify_di_issuer_proofs(
    resolver: &(dyn PurposeVmResolver + '_),
    credential: &Value,
) -> Result<String, AppError> {
    let issuer_did = credential_issuer(credential)
        .ok_or_else(|| AppError::Validation("Data-Integrity credential has no `issuer`".into()))?;
    let proof_value = credential
        .get("proof")
        .ok_or_else(|| AppError::Validation("Data-Integrity credential has no `proof`".into()))?;

    let is_bbs = |p: &Value| p.get("cryptosuite").and_then(Value::as_str) == Some("bbs-2023");
    let bbs = match proof_value {
        Value::Array(items) => items.iter().any(is_bbs),
        single => is_bbs(single),
    };
    if bbs {
        return Err(AppError::Validation(
            "a bbs-2023 proof is not verified on the eddsa / ML-DSA Data-Integrity path \
             (BBS+ is audit-gated and routed separately)"
                .into(),
        ));
    }

    // Binding, before parsing or resolving anything: every proof that names a
    // key — checkable or not — MUST name one under the stated issuer.
    let raw: Vec<&Value> = match proof_value {
        Value::Array(items) => items.iter().collect(),
        single => vec![single],
    };
    if let Some(foreign) = raw
        .iter()
        .filter_map(|p| p.get("verificationMethod").and_then(Value::as_str))
        .find(|vm| vm.split('#').next().unwrap_or_default() != issuer_did)
    {
        return Err(AppError::Validation(format!(
            "DI proof verificationMethod `{foreign}` is not under the credential issuer \
             `{issuer_did}` — refusing a credential signed by a key outside the issuer DID"
        )));
    }
    let proofs = proof_set(proof_value)
        .map_err(|e| AppError::Validation(format!("unreadable Data-Integrity proof: {e}")))?;
    // The parsed form agrees (a proof without a string `verificationMethod`
    // does not parse) — checked again so the binding does not rest on that.
    if proofs.iter().any(|p| proof_signer_did(p) != issuer_did) {
        return Err(AppError::Validation(
            "DI proof is not under the credential issuer".into(),
        ));
    }

    let verified = verify_proof_set(credential, ProofPurpose::AssertionMethod, resolver)
        .await
        .map_err(|e| {
            AppError::Validation(format!(
                "issuer Data-Integrity proof verification failed: {e}"
            ))
        })?;
    if verified.signer() != issuer_did {
        // Unreachable after the binding check above; kept so the invariant does
        // not rest on two functions agreeing about DID extraction.
        return Err(AppError::Validation(
            "DI proofs are not signed by the credential issuer".into(),
        ));
    }
    Ok(issuer_did)
}
