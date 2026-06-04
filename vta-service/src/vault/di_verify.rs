//! Shared Data-Integrity issuer-key resolution.
//!
//! Resolving the Ed25519 public key that signed a W3C Data-Integrity credential
//! — **bound to the credential's stated `issuer`** — is needed in more than one
//! place: receiving a DI credential into the vault
//! ([`crate::operations::credential_exchange`]) and verifying a
//! `BitstringStatusListCredential`'s own issuer signature before trusting it
//! ([`crate::vault::status`]). Both share the same binding rule (the signing key
//! MUST belong to the stated issuer — otherwise a key from some *other* DID could
//! sign a credential claiming a different issuer) and the same resolution path
//! (`did:key` locally, `did:webvh` / `did:web` via the DID cache).
//!
//! Consistent with the vault's dependency-injection style, the DID resolver is a
//! **caller-supplied parameter** — these helpers never own a network client; for
//! `did:key` issuers no I/O happens at all, and for `did:webvh` / `did:web` the
//! injected resolver does the lookup.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value;
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

/// Resolve the Ed25519 public key a Data-Integrity VC's proof is signed with,
/// **binding it to the credential `issuer`**.
///
/// The proof's `verificationMethod` names the signing key; its base DID MUST be
/// the credential `issuer` — otherwise a key belonging to some *other* DID could
/// sign a credential that claims a different issuer (issuer spoofing). `did:key`
/// issuers resolve locally with no I/O even when a resolver is configured;
/// `did:webvh` / `did:web` issuers are resolved through `did_resolver`, which
/// must then be present.
pub(crate) async fn resolve_di_issuer_key(
    did_resolver: Option<&DIDCacheClient>,
    credential: &Value,
) -> Result<Vec<u8>, AppError> {
    let issuer_did = credential_issuer(credential)
        .ok_or_else(|| AppError::Validation("Data-Integrity credential has no `issuer`".into()))?;

    let vm = credential
        .get("proof")
        .and_then(|p| p.get("verificationMethod"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Validation("Data-Integrity proof has no `verificationMethod`".into())
        })?;

    // Binding: the signing key MUST belong to the stated issuer.
    let vm_base = vm.split('#').next().unwrap_or_default();
    if vm_base != issuer_did {
        return Err(AppError::Validation(format!(
            "DI proof verificationMethod `{vm}` is not under the credential issuer \
             `{issuer_did}` — refusing a credential signed by a key outside the issuer DID"
        )));
    }

    // `did:key` is its own key — resolve locally, no network even if configured.
    if issuer_did.starts_with("did:key:") {
        return affinidi_crypto::did_key::did_key_to_ed25519_pub(&issuer_did)
            .map(|k| k.to_vec())
            .map_err(|e| {
                AppError::Validation(format!(
                    "issuer `{issuer_did}` is not a resolvable did:key: {e}"
                ))
            });
    }

    let resolver = did_resolver.ok_or_else(|| {
        AppError::Validation(format!(
            "resolving issuer `{issuer_did}` needs a DID resolver, but none is configured — \
             configure the DID cache client to receive Data-Integrity credentials from \
             did:webvh / did:web issuers"
        ))
    })?;
    resolve_vm_ed25519(resolver, &issuer_did, vm).await
}

/// Resolve a DID's verification method to its Ed25519 public-key bytes via the
/// DID cache. Mirrors the DID-document JSON navigation in
/// [`crate::operations::passkey_login::VtaVmResolver`] but yields raw Ed25519
/// bytes for Data-Integrity verification. Only `publicKeyMultibase`
/// (Multikey-encoded) Ed25519 VMs are supported.
async fn resolve_vm_ed25519(
    resolver: &DIDCacheClient,
    did: &str,
    vm: &str,
) -> Result<Vec<u8>, AppError> {
    let resolved = resolver
        .resolve(did)
        .await
        .map_err(|e| AppError::Validation(format!("issuer DID `{did}` did not resolve: {e}")))?;

    // Serialise to JSON for shape-agnostic navigation (the DID-Core JSON shape is
    // the stable contract, decoupled from the resolver's struct version).
    let doc: Value = serde_json::to_value(&resolved.doc)
        .map_err(|e| AppError::Internal(format!("issuer DID document serialise failed: {e}")))?;

    let vms = doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "issuer DID `{did}` has no verificationMethod array"
            ))
        })?;

    // VM ids can be absolute (`did:webvh:...#key-0`) or relative (`#key-0`).
    let relative = vm
        .split_once('#')
        .map(|(_, frag)| format!("#{frag}"))
        .unwrap_or_default();
    let entry = vms
        .iter()
        .find(|e| {
            let id = e.get("id").and_then(Value::as_str).unwrap_or("");
            id == vm || id == relative
        })
        .ok_or_else(|| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` not found in issuer DID `{did}`"
            ))
        })?;

    let multibase = entry
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` has no publicKeyMultibase (only Multikey-encoded \
                 Ed25519 VMs are supported)"
            ))
        })?;

    // A `z`-prefixed Ed25519 Multikey is exactly the `did:key` suffix — reuse the
    // canonical decoder, which also rejects a non-Ed25519 multicodec.
    affinidi_crypto::did_key::did_key_to_ed25519_pub(&format!("did:key:{multibase}"))
        .map(|k| k.to_vec())
        .map_err(|e| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` is not an Ed25519 Multikey: {e}"
            ))
        })
}
