//! Holder-side credential-exchange operations (Phase 3, spec §6) — the VTA's
//! side of `credential-exchange/*`: receiving issued credentials and answering
//! a verifier's DCQL query against the held vault.
//!
//! - [`receive_issued_credential`] (task 3.3) — the **credential vault's first
//!   wire exposure**: a `credential-exchange/issue` message
//!   ([`vta_sdk::protocols::credential_exchange`]) carries an OID4VCI credential
//!   response, and this infers the format and stores it through the
//!   format-agnostic [`crate::vault::receive`] (SD-JWT-VC + W3C Data-Integrity,
//!   tasks 3.1a/3.1b).
//! - [`match_vault`] / [`match_held`] (task 3.5, query→match) — run a verifier's
//!   DCQL query locally over the held credentials ([`match_vault`] gathers them
//!   from the live vault via the type index, no enumeration; [`match_held`]
//!   matches an explicit set), returning which satisfy it and the claim paths to
//!   disclose.
//! - [`present_for_query`] (task 3.5c) — turn a match into a `vp_token`: build a
//!   consent-gated, selectively-disclosed VP of the matched credential (SD-JWT-VC
//!   in this slice).
//! - [`present_or_defer`] (task 3.5d) — apply the holder's [`ConsentPolicy`]:
//!   auto-consent + present for a **trusted** verifier, else defer with
//!   [`PresentOutcome::ConsentRequired`] for an out-of-band approval. The
//!   `credential-exchange/query → present` DIDComm handler (which sources the
//!   holder key + persists the pending approval) is the wire slice on top.
//!
//! ## Scope of this slice
//! - **SD-JWT-VC** — fully wired (the issuer `did:key` is resolved inside
//!   `receive`).
//! - **W3C Data-Integrity** from a **`did:key`** issuer — fully wired (resolved
//!   locally, no I/O).
//! - **W3C Data-Integrity** from a **`did:webvh` / `did:web`** issuer — wired via
//!   the app-state DID resolver (the VTC issues under `did:webvh`). The proof's
//!   `verificationMethod` is resolved and **bound to the credential `issuer`**.
//! - A **`sealed`** bundle (the unknown-holder / invite case) is deferred to the
//!   sealed-issuance slice (3.6).

use std::collections::BTreeSet;
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_openid4vp::{CandidateCredential, ClaimPathSegment, DcqlQuery, Oid4vpError};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;
use vta_sdk::protocols::credential_exchange::{IssueBody, PresentBody, QueryBody};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::auth::AuthClaims;
use crate::keys::seed_store::SeedStore;
use crate::operations::holder_keys::resolve_holder_keys;
use crate::vault::consent::{self, ConsentGrant};
use crate::vault::model::{CredentialFormat, StoredCredential};
use crate::vault::query::CredentialQuery as VaultQuery;
use crate::vault::{self};

/// Receive a credential delivered in a credential-exchange `issue` message into
/// the holder's `vault`. Infers the credential format from the body, resolves
/// the issuer key for the Data-Integrity path, and stores via the
/// format-agnostic [`vault::receive`]. Returns the persisted credential.
///
/// `did_resolver` resolves a `did:webvh` / `did:web` issuer's verification
/// method for the Data-Integrity path (`did:key` issuers resolve locally with no
/// I/O). Pass `None` for a resolver-less context — then only `did:key` DI
/// issuers (and all SD-JWT-VC) are accepted.
///
/// `source` is recorded as the stored credential's provenance (e.g. the exchange
/// thread id or the authenticated issuer DID). `now` anchors the temporal check.
pub async fn receive_issued_credential(
    vault_ks: &KeyspaceHandle,
    issue: &IssueBody,
    did_resolver: Option<&DIDCacheClient>,
    source: Option<String>,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    if issue.sealed.is_some() {
        return Err(AppError::Validation(
            "this issue message carries a `sealed` bundle — open it with \
             `receive_sealed_issued_credential` (the holder's X25519 key is required)"
                .into(),
        ));
    }

    let credential = issue
        .credential_response
        .as_ref()
        .and_then(|r| r.credential.as_ref())
        .ok_or_else(|| AppError::Validation("issue message carries no credential".to_string()))?;

    store_issued_credential(vault_ks, credential, did_resolver, source, now).await
}

/// Store an issued credential value (the OID4VCI `credential` field shape) into
/// the holder's vault, inferring the format from the value: a JSON **string** is
/// an SD-JWT-VC compact serialization; a JSON **object** with a `proof` is a W3C
/// Data-Integrity VC. Shared by the plaintext over-DIDComm path
/// ([`receive_issued_credential`]) and the sealed invite path
/// ([`receive_sealed_issued_credential`]).
async fn store_issued_credential(
    vault_ks: &KeyspaceHandle,
    credential: &Value,
    did_resolver: Option<&DIDCacheClient>,
    source: Option<String>,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    let id = format!("urn:uuid:{}", Uuid::new_v4());

    match credential {
        // A JSON string → SD-JWT-VC compact serialization; `receive` resolves the
        // issuer `did:key` internally.
        Value::String(compact) => {
            vault::receive(
                vault_ks,
                &id,
                &CredentialFormat::SdJwtVc,
                compact.as_bytes(),
                None,
                source,
                now,
            )
            .await
        }
        // A JSON object carrying a `proof` → a W3C Data-Integrity VC. Resolve the
        // issuer's signing key (binding it to the credential `issuer`) and store
        // via the DI path. The vault stays network-free — resolution happens here.
        Value::Object(_) if credential.get("proof").is_some() => {
            let issuer_pub = resolve_di_issuer_key(did_resolver, credential).await?;
            let body = serde_json::to_vec(credential)
                .map_err(|e| AppError::Internal(format!("credential -> bytes: {e}")))?;
            vault::receive(
                vault_ks,
                &id,
                &CredentialFormat::EddsaJcs2022,
                &body,
                Some(&issuer_pub),
                source,
                now,
            )
            .await
        }
        _ => Err(AppError::Validation(
            "unrecognised credential in issue message (expected an SD-JWT-VC string or a \
             W3C Data-Integrity VC object with a `proof`)"
                .to_string(),
        )),
    }
}

/// Open a **sealed** issued credential (the invite / unknown-holder case, spec
/// §6 task 3.6) and receive it into the holder's vault.
///
/// The issuer minted the credential bound to this holder's `did:key` and sealed
/// it to the holder's X25519 derivation via [`vta_sdk::sealed_transfer`]. The
/// holder opens it with `holder_x25519_secret` (derived from the same key the
/// invite pinned) and stores the credential through the format-agnostic path.
///
/// `expect_digest` is the out-of-band SHA-256 digest pinning (mandatory in
/// practice — see the sealed-transfer invariants): we require a pinned digest so
/// a party that merely knows the holder pubkey cannot inject a bundle.
pub async fn receive_sealed_issued_credential(
    vault_ks: &KeyspaceHandle,
    armored: &str,
    holder_x25519_secret: &[u8; 32],
    expect_digest: Option<&str>,
    did_resolver: Option<&DIDCacheClient>,
    source: Option<String>,
    now: DateTime<Utc>,
) -> Result<StoredCredential, AppError> {
    use vta_sdk::sealed_transfer::{SealedPayloadV1, armor, open_bundle};

    let bundles = armor::decode(armored)
        .map_err(|e| AppError::Validation(format!("sealed issuance armor decode failed: {e}")))?;
    let bundle = bundles.into_iter().next().ok_or_else(|| {
        AppError::Validation("sealed issuance carried no armored bundle".to_string())
    })?;

    let opened = open_bundle(holder_x25519_secret, &bundle, expect_digest)
        .map_err(|e| AppError::Validation(format!("sealed issuance open failed: {e}")))?;

    let credential_bundle = match opened.payload {
        SealedPayloadV1::IssuedCredential(boxed) => *boxed,
        other => {
            return Err(AppError::Validation(format!(
                "sealed bundle is not an issued credential (got {other:?})"
            )));
        }
    };

    // Provenance: the sealed issuer DID, unless the caller supplied one.
    let source = source.or(Some(credential_bundle.issuer_did.clone()));
    store_issued_credential(
        vault_ks,
        &credential_bundle.credential,
        did_resolver,
        source,
        now,
    )
    .await
}

/// Seal a freshly-issued credential for an invite / unknown holder (spec §6 task
/// 3.6, the **issuer** half). Mints an HPKE-sealed, armored bundle the holder
/// opens with [`receive_sealed_issued_credential`].
///
/// `holder_did` is the holder's `did:key` from the invite — the credential was
/// minted bound to it, and the bundle is sealed to its X25519 derivation.
/// `bundle_id` is the single-use nonce; `producer` asserts who issued (typically
/// `DidSigned` by the issuer). Returns `(armored_text, sha256_digest)` — the
/// digest is communicated out-of-band for the holder's `expect_digest` pin.
pub async fn seal_issued_credential(
    holder_did: &str,
    credential: Value,
    issuer_did: &str,
    label: Option<String>,
    bundle_id: [u8; 16],
    producer: vta_sdk::sealed_transfer::ProducerAssertion,
    nonce_store: &dyn vta_sdk::sealed_transfer::NonceStore,
) -> Result<(String, String), AppError> {
    use vta_sdk::sealed_transfer::{
        IssuedCredentialBundle, SealedPayloadV1, armor, bundle_digest, seal_payload,
    };

    // The holder's X25519 sealing target, derived from its Ed25519 `did:key`.
    let holder_ed = affinidi_crypto::did_key::did_key_to_ed25519_pub(holder_did)
        .map_err(|e| AppError::Validation(format!("holder DID is not an Ed25519 did:key: {e}")))?;
    let holder_x = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&holder_ed)
        .map_err(|e| AppError::Internal(format!("holder X25519 derivation failed: {e}")))?;

    let payload = SealedPayloadV1::IssuedCredential(Box::new(IssuedCredentialBundle {
        credential,
        issuer_did: issuer_did.to_string(),
        label,
    }));

    let bundle = seal_payload(&holder_x, bundle_id, producer, &payload, nonce_store)
        .await
        .map_err(|e| AppError::Internal(format!("sealing issued credential failed: {e}")))?;
    let digest = bundle_digest(&bundle);
    Ok((armor::encode(&bundle), digest))
}

/// The issuer DID from a VC `issuer` field — a string, or an object with `id`.
fn issuer_str(issuer: &Value) -> Option<String> {
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
async fn resolve_di_issuer_key(
    did_resolver: Option<&DIDCacheClient>,
    credential: &Value,
) -> Result<Vec<u8>, AppError> {
    let issuer_did = credential
        .get("issuer")
        .and_then(issuer_str)
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

// ── Holder-side DCQL match (Phase 3, task 3.5: query → match) ──
//
// A verifier's `credential-exchange/query` carries a DCQL query; the holder
// runs it **locally** over its own vault and learns which held credentials
// satisfy it (and which claim paths the query asks to disclose). This is the
// read/match half — the consent gate + selectively-disclosed `present` that
// turns a match into a `vp_token` is the next slice.

/// One held credential that satisfied a credential query, with the claim paths
/// the query asked to disclose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldMatch {
    /// The DCQL `CredentialQuery.id` that matched.
    pub credential_query_id: String,
    /// The local vault id of the [`StoredCredential`] that satisfied it.
    pub credential_id: String,
    /// The claim paths to disclose, each rendered segment-by-segment
    /// (`Name` → the name, `Index` → `[i]`, `Wildcard` → `[*]`). **Empty** when
    /// the query named no `claims` (disclose per the holder's own policy).
    pub disclosed_paths: Vec<Vec<String>>,
}

/// Run a verifier's DCQL `query` over the holder's `held` credentials, returning
/// the matches (which credential satisfied which query, and the claim paths to
/// disclose). The query is validated first (it came off the wire). Credentials
/// in a format not yet presentable via DCQL are skipped, not errored.
///
/// An **empty** result means the holder has nothing that satisfies the query —
/// a legitimate outcome (the verifier gets a "no presentation" answer), distinct
/// from an `Err` (a malformed query or an unparseable stored body).
pub fn match_held(
    query: &DcqlQuery,
    held: &[StoredCredential],
) -> Result<Vec<HeldMatch>, AppError> {
    query
        .validate()
        .map_err(|e| AppError::Validation(format!("invalid DCQL query: {e}")))?;

    let mut candidates = Vec::with_capacity(held.len());
    for stored in held {
        if let Some(candidate) = candidate_from_stored(stored)? {
            candidates.push(candidate);
        }
    }

    let matched = match query.match_credentials(&candidates) {
        Ok(matched) => matched,
        // "Nothing the holder holds satisfies the request" — not an error here.
        Err(Oid4vpError::NoMatchingCredentials(_)) => return Ok(Vec::new()),
        Err(e) => return Err(AppError::Validation(format!("DCQL match failed: {e}"))),
    };

    Ok(matched
        .matches
        .into_iter()
        .map(|m| HeldMatch {
            credential_query_id: m.credential_query_id,
            credential_id: m.candidate_id,
            disclosed_paths: m.disclosed_paths.into_iter().map(render_path).collect(),
        })
        .collect())
}

/// Build a DCQL [`CandidateCredential`] from a stored credential by parsing its
/// body for the claims tree. Returns `None` for formats not yet presentable via
/// DCQL (`Zkp` / `Other`).
fn candidate_from_stored(
    stored: &StoredCredential,
) -> Result<Option<CandidateCredential>, AppError> {
    let Some(format) = dcql_format(&stored.format) else {
        return Ok(None);
    };

    let (claims, vct, supports_holder_binding) = match stored.format {
        CredentialFormat::SdJwtVc => {
            let compact = std::str::from_utf8(&stored.body).map_err(|e| {
                AppError::Validation(format!("credential `{}` is not UTF-8: {e}", stored.id))
            })?;
            let hasher = affinidi_sd_jwt::hasher::Sha256Hasher;
            let sd = affinidi_sd_jwt::SdJwt::parse(compact, &hasher).map_err(|e| {
                AppError::Validation(format!("credential `{}` is not SD-JWT-VC: {e}", stored.id))
            })?;
            let payload = sd.payload().map_err(|e| {
                AppError::Validation(format!("credential `{}` payload: {e}", stored.id))
            })?;
            let claims = affinidi_sd_jwt::holder::resolve_claims(&payload, &sd.disclosures)
                .map_err(|e| {
                    AppError::Validation(format!("credential `{}` claims: {e}", stored.id))
                })?;
            let vct = payload
                .get("vct")
                .and_then(Value::as_str)
                .map(str::to_string);
            // SD-JWT-VC carries holder binding via the `cnf` confirmation claim.
            let holder_binding = payload.get("cnf").is_some();
            (claims, vct, holder_binding)
        }
        CredentialFormat::EddsaJcs2022 | CredentialFormat::Bbs2023 => {
            // The claims tree is the whole VC object — a verifier path walks it
            // (e.g. `["credentialSubject","givenName"]`). Our DI present builds a
            // holder-bound VP, so holder binding is supported.
            let vc: Value = serde_json::from_slice(&stored.body).map_err(|e| {
                AppError::Validation(format!("credential `{}` is not JSON: {e}", stored.id))
            })?;
            (vc, None, true)
        }
        // Unreachable: `dcql_format` returned `Some` only for the arms above.
        CredentialFormat::Zkp | CredentialFormat::Other(_) => return Ok(None),
    };

    Ok(Some(CandidateCredential {
        id: stored.id.clone(),
        format: format.to_string(),
        claims,
        vct,
        doctype: None,
        supports_holder_binding,
    }))
}

/// Run a verifier's DCQL `query` over the **live vault**: gather candidate
/// credentials via the type index (no enumeration), then [`match_held`] them.
///
/// This is [`match_held`] against the holder's own store — the entry point a
/// `credential-exchange/query` handler calls.
pub async fn match_vault(
    vault: &KeyspaceHandle,
    query: &DcqlQuery,
) -> Result<Vec<HeldMatch>, AppError> {
    let held = gather_for_query(vault, query).await?;
    match_held(query, &held)
}

/// Collect held credentials whose `type` / `vct` index matches a discriminator
/// in the DCQL query's per-credential `meta` (`vct_values` / `type_values`).
///
/// The vault has **no enumeration primitive** (`vti-credential-architecture` §14),
/// so a credential query carrying no such discriminator contributes no
/// candidates — a privacy property: the holder never blind-scans its whole
/// wallet to answer a query.
async fn gather_for_query(
    vault: &KeyspaceHandle,
    query: &DcqlQuery,
) -> Result<Vec<StoredCredential>, AppError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for cq in &query.credentials {
        for type_value in meta_type_values(cq.meta.as_ref()) {
            let descriptors = vault::search(
                vault,
                &VaultQuery {
                    r#type: Some(type_value),
                    community_did: None,
                    issuer_did: None,
                    purpose: None,
                    status: None,
                },
            )
            .await?;
            for descriptor in descriptors {
                if seen.insert(descriptor.id.clone())
                    && let Some(stored) = vault::storage::get(vault, &descriptor.id).await?
                {
                    out.push(stored);
                }
            }
        }
    }
    Ok(out)
}

/// Type discriminators from a credential query's `meta`: `vct_values`
/// (SD-JWT-VC) and `type_values` (W3C), flattened to owned strings.
fn meta_type_values(meta: Option<&serde_json::Map<String, Value>>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(meta) = meta else {
        return out;
    };
    for key in ["vct_values", "type_values"] {
        if let Some(array) = meta.get(key).and_then(Value::as_array) {
            out.extend(array.iter().filter_map(|v| v.as_str().map(str::to_string)));
        }
    }
    out
}

/// Answer a verifier's `credential-exchange/query` with a presentation: match
/// the query over the vault, then build a **consent-gated, selectively-disclosed**
/// VP of the matched credential and return it as a `vp_token`.
///
/// - `holder_signer` is the holder's SD-JWT-VC key-binding signer (the subject
///   key the VTA controls).
/// - `consent_record_id` names the [`crate::vault::consent::ConsentRecord`] that
///   authorizes disclosure to `verifier_aud`; the present gate enforces it
///   (disclose exactly the consented claims, refuse a revoked/expired credential).
/// - `verifier_aud` is the verifier identity the holder `kb-jwt` binds to (the
///   DIDComm sender); `iat_unix` stamps the kb-jwt.
///
/// `NotFound` when nothing the holder holds satisfies the query. Presents both
/// **SD-JWT-VC** (via `holder_signer`, the kb-jwt) and **W3C Data-Integrity**
/// (via `holder_secret`, the holder DI key) matches — the two abstractions of
/// the same derived holder key.
#[allow(clippy::too_many_arguments)]
pub async fn present_for_query(
    vault: &KeyspaceHandle,
    query: &QueryBody,
    holder_signer: &dyn affinidi_sd_jwt::signer::JwtSigner,
    holder_secret: &Secret,
    consent_record_id: &str,
    verifier_aud: &str,
    iat_unix: u64,
    now: DateTime<Utc>,
) -> Result<PresentBody, AppError> {
    let matched = match_vault(vault, &query.dcql_query).await?;
    // Single-credential VP for this slice; a multi-credential / credential-set
    // response is a follow-up. Take the first match in credential-query order.
    let first = matched.into_iter().next().ok_or_else(|| {
        AppError::NotFound("no held credential satisfies the verifier's query".to_string())
    })?;

    let stored = vault::storage::get(vault, &first.credential_id)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "matched credential `{}` is gone",
                first.credential_id
            ))
        })?;

    let vp_token = match stored.format {
        CredentialFormat::SdJwtVc => {
            let compact = vault::present_sd_jwt_vc(
                vault,
                &first.credential_id,
                consent_record_id,
                holder_signer,
                &query.nonce,
                verifier_aud,
                iat_unix,
                now,
            )
            .await?;
            Value::String(compact)
        }
        CredentialFormat::EddsaJcs2022 => {
            // W3C Data-Integrity VP: the holder signs an `eddsa-jcs-2022` proof
            // over the matched VC with the same derived holder key (here as a
            // raw `Secret`, not the kb-jwt abstraction). The VP is a JSON object,
            // not a compact string — carry it through as structured JSON.
            let vp = vault::present_di_vc(
                vault,
                &first.credential_id,
                consent_record_id,
                holder_secret,
                &query.nonce,
                verifier_aud,
                now,
            )
            .await?;
            serde_json::from_str(&vp).unwrap_or(Value::String(vp))
        }
        other => {
            return Err(AppError::Validation(format!(
                "present_for_query presents SD-JWT-VC and W3C Data-Integrity; presenting \
                 {other:?} via DCQL is a follow-up slice"
            )));
        }
    };

    Ok(PresentBody { vp_token })
}

/// How the holder decides consent when a verifier's query arrives.
///
/// Default behaviour is **deferred** — a query the holder hasn't pre-approved
/// returns [`PresentOutcome::ConsentRequired`] for an out-of-band approval. A
/// verifier on [`trusted_verifiers`](Self::trusted_verifiers) is auto-consented:
/// the holder mints a query-scoped consent and presents immediately (the
/// frictionless join flow, bounded to verifiers the operator trusts).
#[derive(Debug, Clone, Default)]
pub struct ConsentPolicy {
    /// Verifier DIDs the holder auto-consents to. Everything else defers.
    pub trusted_verifiers: BTreeSet<String>,
}

impl ConsentPolicy {
    /// A policy that auto-consents to the given verifier DIDs.
    pub fn trusting<I, S>(verifiers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            trusted_verifiers: verifiers.into_iter().map(Into::into).collect(),
        }
    }
}

/// The outcome of [`present_or_defer`].
#[derive(Debug)]
pub enum PresentOutcome {
    /// A consent-gated, selectively-disclosed presentation was produced.
    Presented(PresentBody),
    /// The query matched a held credential, but the verifier is not trusted and
    /// no consent has been granted — disclosure needs an out-of-band approval
    /// (which mints the consent record, after which the holder re-presents).
    ConsentRequired {
        /// The verifier asking for the presentation.
        verifier_did: String,
        /// The held credential that would satisfy the query.
        credential_id: String,
        /// The claims the query asks to disclose (what the approver authorizes).
        claims: Vec<String>,
        /// The verifier's stated purpose (shown to the approver).
        purpose: String,
    },
}

/// Answer a verifier's `credential-exchange/query` under a [`ConsentPolicy`]:
/// auto-consent + present for a trusted verifier, otherwise defer to approval.
///
/// Matches the query over the vault; for a **trusted** verifier it mints a
/// query-scoped consent (signed by `holder_consent_key`) and presents via
/// [`present_for_query`]; for any other verifier it returns
/// [`PresentOutcome::ConsentRequired`] (the wire layer turns this into a
/// "consent required" reply / pending approval). `NotFound` when nothing the
/// holder holds satisfies the query.
#[allow(clippy::too_many_arguments)]
pub async fn present_or_defer(
    vault: &KeyspaceHandle,
    query: &QueryBody,
    verifier_did: &str,
    policy: &ConsentPolicy,
    holder_signer: &dyn affinidi_sd_jwt::signer::JwtSigner,
    holder_consent_key: &Secret,
    now: DateTime<Utc>,
) -> Result<PresentOutcome, AppError> {
    let matched = match_vault(vault, &query.dcql_query).await?;
    let first = matched.into_iter().next().ok_or_else(|| {
        AppError::NotFound("no held credential satisfies the verifier's query".to_string())
    })?;

    // The claims the query asks to disclose — the leaf of each disclosed path.
    let claims: Vec<String> = first
        .disclosed_paths
        .iter()
        .filter_map(|path| path.last().cloned())
        .collect();

    if !policy.trusted_verifiers.contains(verifier_did) {
        return Ok(PresentOutcome::ConsentRequired {
            verifier_did: verifier_did.to_string(),
            credential_id: first.credential_id,
            claims,
            purpose: query.purpose.clone(),
        });
    }

    // Trusted verifier → mint a query-scoped consent record, then present.
    let stored = vault::storage::get(vault, &first.credential_id)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "matched credential `{}` is gone",
                first.credential_id
            ))
        })?;
    let subject = stored.subject_did.as_deref().ok_or_else(|| {
        AppError::Validation("matched credential has no subject DID to bind consent to".into())
    })?;

    let record = consent::create(
        vault,
        &ConsentGrant {
            holder_did: subject,
            credential_id: &first.credential_id,
            verifier_did,
            purpose: &query.purpose,
            claims: claims.clone(),
            valid_until: now + chrono::Duration::minutes(5),
        },
        holder_consent_key,
    )
    .await?;

    let present = present_for_query(
        vault,
        query,
        holder_signer,
        holder_consent_key,
        &record.identifier,
        verifier_did,
        now.timestamp() as u64,
        now,
    )
    .await?;
    Ok(PresentOutcome::Presented(present))
}

/// The full holder `query → present` path, end to end: match the verifier's
/// query over the vault, **resolve the matched credential's holder key** (the
/// ACL-gated [`resolve_holder_keys`] — the VTA's own derived subject key), then
/// [`present_or_defer`] under the consent `policy`.
///
/// This is what the `credential-exchange/query` DIDComm handler drives: it
/// composes match + key-resolution + consent into a [`PresentOutcome`] (a
/// `vp_token`, or a "consent required" deferral). `auth` gates the holder-key
/// access — the autonomous wire flow passes the VTA's own authority; an
/// operator-initiated path passes the operator's claims.
#[allow(clippy::too_many_arguments)]
pub async fn present_query(
    vault: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    query: &QueryBody,
    verifier_did: &str,
    policy: &ConsentPolicy,
    now: DateTime<Utc>,
) -> Result<PresentOutcome, AppError> {
    // Match once to learn the subject whose holder key we must resolve.
    let matched = match_vault(vault, &query.dcql_query).await?;
    let first = matched.into_iter().next().ok_or_else(|| {
        AppError::NotFound("no held credential satisfies the verifier's query".to_string())
    })?;
    let stored = vault::storage::get(vault, &first.credential_id)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "matched credential `{}` is gone",
                first.credential_id
            ))
        })?;
    let subject = stored.subject_did.as_deref().ok_or_else(|| {
        AppError::Validation("matched credential has no subject DID to present".into())
    })?;

    // Derive the holder key for that subject — ACL-gated to its context.
    let keys = resolve_holder_keys(keys_ks, seed_store, auth, subject).await?;

    present_or_defer(
        vault,
        query,
        verifier_did,
        policy,
        &keys.signer,
        &keys.consent_secret,
        now,
    )
    .await
}

/// Deferred-approval store (task 3.5d, the defer half) — when
/// [`present_or_defer`] returns [`PresentOutcome::ConsentRequired`] for an
/// untrusted verifier, the wire layer persists a [`PendingPresentation`] here.
/// An out-of-band approval ([`approve_pending_presentation`]) mints the
/// query-scoped consent and re-presents; a denial ([`deny_pending_presentation`])
/// records the refusal. The holder's own [`pending::list`] is the approval
/// surface a UI drives.
///
/// Records live in the `vault` keyspace under the disjoint `pending-present:`
/// namespace (alongside `cred:` / `consent:` / `vault:`), encrypted at rest by
/// the keyspace wrapper.
pub mod pending {
    use super::*;

    /// Primary-key prefix. Disjoint from `cred:` / `idx:` / `consent:` / `vault:`.
    const PREFIX: &str = "pending-present:";

    fn key(id: &str) -> Vec<u8> {
        format!("{PREFIX}{id}").into_bytes()
    }

    /// Where a deferred presentation stands.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum PendingStatus {
        /// Awaiting the holder's out-of-band approval.
        Pending,
        /// Approved — the `vp_token` was produced and sent.
        Approved,
        /// Denied by the holder; no presentation was made.
        Denied,
    }

    /// A verifier's query the holder deferred, persisted until an out-of-band
    /// approval mints consent and re-presents. Carries the **whole query** so the
    /// re-present is byte-faithful (same nonce, same claims).
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct PendingPresentation {
        /// The approval id — the DIDComm thread id, so the verifier can be told
        /// "your request `<id>` is pending" and a later present replies on-thread.
        pub id: String,
        /// The verifier that asked (the authcrypt sender). The presentation, once
        /// approved, binds to this audience.
        pub verifier_did: String,
        /// The held credential that would satisfy the query (informational — the
        /// approve path re-matches to be robust to vault changes).
        pub credential_id: String,
        /// The claims the query asks to disclose — what the approver authorizes.
        pub claims: Vec<String>,
        /// The verifier's stated purpose, shown to the approver.
        pub purpose: String,
        /// The full query, stored so [`approve_pending_presentation`] re-presents
        /// faithfully (same nonce + claim set).
        pub query: QueryBody,
        /// Lifecycle state.
        pub status: PendingStatus,
        /// When the deferral was recorded.
        pub created_at: DateTime<Utc>,
        /// After this the deferral is stale — approval refuses (the verifier's
        /// nonce is no longer fresh).
        pub expires_at: DateTime<Utc>,
    }

    /// Persist (or overwrite) a pending-presentation record.
    pub async fn put(vault: &KeyspaceHandle, record: &PendingPresentation) -> Result<(), AppError> {
        vault.insert(key(&record.id), record).await
    }

    /// Load one pending-presentation record.
    pub async fn get(
        vault: &KeyspaceHandle,
        id: &str,
    ) -> Result<Option<PendingPresentation>, AppError> {
        vault.get(key(id)).await
    }

    /// The holder's own local approval surface — every pending-presentation
    /// record. Scans only this VTA's `pending-present:` namespace; never a
    /// cross-trust-boundary enumeration.
    pub async fn list(vault: &KeyspaceHandle) -> Result<Vec<PendingPresentation>, AppError> {
        let raw = vault.prefix_iter_raw(PREFIX.as_bytes().to_vec()).await?;
        let mut out = Vec::with_capacity(raw.len());
        for (_k, v) in raw {
            out.push(
                serde_json::from_slice(&v)
                    .map_err(|e| AppError::Internal(format!("pending record decode: {e}")))?,
            );
        }
        Ok(out)
    }
}

/// Record a deferred presentation for later out-of-band approval. Called by the
/// wire layer when [`present_query`] returns [`PresentOutcome::ConsentRequired`].
/// `id` is the request/thread id the verifier can poll on.
pub async fn defer_presentation(
    vault: &KeyspaceHandle,
    id: &str,
    verifier_did: &str,
    credential_id: &str,
    claims: Vec<String>,
    query: &QueryBody,
    now: DateTime<Utc>,
) -> Result<pending::PendingPresentation, AppError> {
    let record = pending::PendingPresentation {
        id: id.to_string(),
        verifier_did: verifier_did.to_string(),
        credential_id: credential_id.to_string(),
        claims,
        purpose: query.purpose.clone(),
        query: query.clone(),
        status: pending::PendingStatus::Pending,
        created_at: now,
        // The verifier's nonce ages out; keep the approval window bounded.
        expires_at: now + chrono::Duration::hours(24),
    };
    pending::put(vault, &record).await?;
    Ok(record)
}

/// Approve a deferred presentation: mint the query-scoped consent the holder is
/// authorizing and **re-present**. ACL-gated via `auth` (the same holder-key
/// gate as [`present_query`]). Marks the record `Approved` and returns the
/// `vp_token`.
///
/// Refuses a record that isn't `Pending` (already approved / denied) or whose
/// deferral window has lapsed (`expires_at` past — the verifier's nonce is stale).
pub async fn approve_pending_presentation(
    vault: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    id: &str,
    now: DateTime<Utc>,
) -> Result<PresentBody, AppError> {
    let mut record = pending::get(vault, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no pending presentation `{id}`")))?;

    if record.status != pending::PendingStatus::Pending {
        return Err(AppError::Validation(format!(
            "pending presentation `{id}` is {:?}, not awaiting approval",
            record.status
        )));
    }
    if now >= record.expires_at {
        return Err(AppError::Validation(format!(
            "pending presentation `{id}` expired at {} — the verifier must re-ask",
            record.expires_at
        )));
    }

    // Re-match the stored query to find the credential + subject (robust to vault
    // changes since the deferral — mirrors `present_query`).
    let matched = match_vault(vault, &record.query.dcql_query).await?;
    let first = matched.into_iter().next().ok_or_else(|| {
        AppError::NotFound("no held credential satisfies the deferred query".to_string())
    })?;
    let stored = vault::storage::get(vault, &first.credential_id)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "matched credential `{}` is gone",
                first.credential_id
            ))
        })?;
    let subject = stored.subject_did.as_deref().ok_or_else(|| {
        AppError::Validation("matched credential has no subject DID to present".into())
    })?;

    // ACL-gated holder key for that subject.
    let keys = resolve_holder_keys(keys_ks, seed_store, auth, subject).await?;

    // Mint the query-scoped consent the approver is authorizing.
    let claims: Vec<String> = first
        .disclosed_paths
        .iter()
        .filter_map(|path| path.last().cloned())
        .collect();
    let consent_record = consent::create(
        vault,
        &ConsentGrant {
            holder_did: subject,
            credential_id: &first.credential_id,
            verifier_did: &record.verifier_did,
            purpose: &record.query.purpose,
            claims,
            valid_until: now + chrono::Duration::minutes(5),
        },
        &keys.consent_secret,
    )
    .await?;

    let present = present_for_query(
        vault,
        &record.query,
        &keys.signer,
        &keys.consent_secret,
        &consent_record.identifier,
        &record.verifier_did,
        now.timestamp() as u64,
        now,
    )
    .await?;

    record.status = pending::PendingStatus::Approved;
    pending::put(vault, &record).await?;
    Ok(present)
}

/// Deny a deferred presentation — the holder refuses disclosure. Records the
/// refusal (no presentation is made) and returns the updated record.
pub async fn deny_pending_presentation(
    vault: &KeyspaceHandle,
    id: &str,
) -> Result<pending::PendingPresentation, AppError> {
    let mut record = pending::get(vault, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no pending presentation `{id}`")))?;
    if record.status != pending::PendingStatus::Pending {
        return Err(AppError::Validation(format!(
            "pending presentation `{id}` is {:?}, not awaiting approval",
            record.status
        )));
    }
    record.status = pending::PendingStatus::Denied;
    pending::put(vault, &record).await?;
    Ok(record)
}

/// Map a stored credential format to its DCQL `format` selector, or `None` if
/// the format is not yet presentable via DCQL.
fn dcql_format(format: &CredentialFormat) -> Option<&'static str> {
    match format {
        CredentialFormat::SdJwtVc => Some("dc+sd-jwt"),
        CredentialFormat::EddsaJcs2022 | CredentialFormat::Bbs2023 => Some("ldp_vc"),
        CredentialFormat::Zkp | CredentialFormat::Other(_) => None,
    }
}

/// Render a DCQL claim path's segments as strings for [`HeldMatch`].
fn render_path(path: Vec<ClaimPathSegment>) -> Vec<String> {
    path.into_iter()
        .map(|seg| match seg {
            ClaimPathSegment::Name(name) => name,
            ClaimPathSegment::Index(i) => format!("[{i}]"),
            ClaimPathSegment::Wildcard => "[*]".to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_sd_jwt::error::SdJwtError;
    use affinidi_sd_jwt::signer::JwtSigner;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("vault").unwrap();
        (dir, store, ks)
    }

    /// A minimal Ed25519 issuer whose DID is the `did:key` for its key.
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
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_string(header)?.as_bytes());
            let p = URL_SAFE_NO_PAD.encode(serde_json::to_string(payload)?.as_bytes());
            let input = format!("{h}.{p}");
            let sig: Signature = self.key.sign(input.as_bytes());
            Ok(format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(sig.to_bytes())
            ))
        }
    }

    /// Build an `IssueBody` from JSON (avoids depending on the openid4vci crate
    /// in the test — the handler-side serde is what production exercises anyway).
    fn issue_body(credential: Value, sealed: Option<String>) -> IssueBody {
        let mut obj = serde_json::Map::new();
        match sealed {
            Some(s) => {
                obj.insert("sealed".into(), json!(s));
            }
            None => {
                obj.insert(
                    "credential_response".into(),
                    json!({ "credential": credential }),
                );
            }
        }
        serde_json::from_value(Value::Object(obj)).expect("build IssueBody")
    }

    #[tokio::test]
    async fn stores_an_issued_sd_jwt_vc() {
        let (_dir, _store, vault) = fresh_vault();

        // Mint a real SD-JWT-VC from a did:key issuer.
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(signing.verifying_key().as_bytes());
        let signer = EddsaSigner {
            key: signing,
            kid: format!("{did}#key-0"),
        };
        // The subject is a real did:key (the mint binds it as `cnf`).
        let subject = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            SigningKey::from_bytes(&[5u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let compact = crate::vault::mint::mint_sd_jwt_vc(
            &crate::vault::mint::MintRequest {
                vct: "https://openvtc.org/credentials/MembershipCredential",
                issuer_did: &did,
                subject_did: &subject,
                claims: &json!({ "givenName": "Alice" }),
                disclosable: &["givenName"],
                iat: 1_700_000_000,
                exp: Some(1_900_000_000),
            },
            &signer,
        )
        .expect("mint SD-JWT-VC");

        let body = issue_body(Value::String(compact), None);
        let cred =
            receive_issued_credential(&vault, &body, None, Some("thread-1".into()), Utc::now())
                .await
                .expect("receive issued SD-JWT-VC");
        assert_eq!(cred.format, CredentialFormat::SdJwtVc);
        assert_eq!(cred.subject_did.as_deref(), Some(subject.as_str()));
        assert!(
            crate::vault::storage::get(&vault, &cred.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn refuses_a_sealed_bundle_on_the_plaintext_path() {
        let (_dir, _store, vault) = fresh_vault();
        // The plaintext receive path now redirects a `sealed` bundle to the
        // dedicated opener rather than claiming it is unimplemented.
        let body = issue_body(Value::Null, Some("-----BEGIN VTA SEALED-----…".into()));
        let err = receive_issued_credential(&vault, &body, None, None, Utc::now())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("receive_sealed_issued_credential")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn seal_then_receive_an_issued_credential_round_trips() {
        use vta_sdk::sealed_transfer::{
            AssertionProof, InMemoryNonceStore, ProducerAssertion, ed25519_seed_to_x25519_secret,
        };

        let (_dir, _store, vault) = fresh_vault();

        // Issuer mints an SD-JWT-VC bound to the holder's did:key (seed [5;32]).
        let holder_seed = [5u8; 32];
        let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            &SigningKey::from_bytes(&holder_seed)
                .verifying_key()
                .to_bytes(),
        );
        let issuer = SigningKey::from_bytes(&[9u8; 32]);
        let issuer_did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(issuer.verifying_key().as_bytes());
        let issuer_signer = EddsaSigner {
            key: issuer,
            kid: format!("{issuer_did}#key-0"),
        };
        let compact = crate::vault::mint::mint_sd_jwt_vc(
            &crate::vault::mint::MintRequest {
                vct: MEMBERSHIP_VCT,
                issuer_did: &issuer_did,
                subject_did: &holder_did,
                claims: &json!({ "givenName": "Alice" }),
                disclosable: &["givenName"],
                iat: 1_700_000_000,
                exp: Some(1_900_000_000),
            },
            &issuer_signer,
        )
        .unwrap();

        // Issuer seals it to the holder (PinnedOnly + out-of-band digest).
        let nonce_store = InMemoryNonceStore::new();
        let producer = ProducerAssertion {
            producer_did: issuer_did.clone(),
            proof: AssertionProof::PinnedOnly,
        };
        let (armored, digest) = seal_issued_credential(
            &holder_did,
            Value::String(compact),
            &issuer_did,
            Some("Acme membership".into()),
            [7u8; 16],
            producer,
            &nonce_store,
        )
        .await
        .expect("seal issued credential");

        // Holder opens it with its X25519 derivation + the OOB digest pin.
        let holder_x = ed25519_seed_to_x25519_secret(&holder_seed);
        let stored = receive_sealed_issued_credential(
            &vault,
            &armored,
            &holder_x,
            Some(&digest),
            None,
            None,
            Utc::now(),
        )
        .await
        .expect("receive sealed issued credential");

        assert_eq!(stored.format, CredentialFormat::SdJwtVc);
        assert_eq!(stored.subject_did.as_deref(), Some(holder_did.as_str()));
        // Provenance defaults to the sealed issuer DID.
        assert_eq!(stored.source.as_deref(), Some(issuer_did.as_str()));

        // A wrong out-of-band digest is rejected (no TOFU).
        let bad = receive_sealed_issued_credential(
            &vault,
            &armored,
            &holder_x,
            Some("deadbeef"),
            None,
            None,
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(bad, AppError::Validation(_)), "{bad:?}");
    }

    #[tokio::test]
    async fn refuses_a_di_vc_from_a_did_web_issuer_without_a_resolver() {
        let (_dir, _store, vault) = fresh_vault();
        // A DI VC from a did:web issuer whose proof key is under the issuer DID
        // (binding holds), but no DID resolver is configured → graceful refusal.
        let vc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": { "id": "did:key:zMember" },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:web:issuer.example#key-0"
            }
        });
        let err = receive_issued_credential(&vault, &issue_body(vc, None), None, None, Utc::now())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("DID resolver")),
            "expected a resolver-not-configured error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn refuses_a_di_vc_whose_signing_key_is_outside_the_issuer() {
        let (_dir, _store, vault) = fresh_vault();
        // Issuer-spoofing attempt: the credential claims `issuer` A but the proof
        // is signed by a key under a *different* DID B. Must be refused before any
        // resolution — the signing key has to belong to the stated issuer.
        let vc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": { "id": "did:key:zMember" },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:web:attacker.example#key-0"
            }
        });
        let err = receive_issued_credential(&vault, &issue_body(vc, None), None, None, Utc::now())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("not under the credential issuer")),
            "expected an issuer-binding rejection, got {err:?}"
        );
    }

    #[tokio::test]
    async fn receives_a_di_vc_from_a_did_key_issuer() {
        use affinidi_data_integrity::{
            DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite,
        };
        use affinidi_secrets_resolver::secrets::Secret;

        let (_dir, _store, vault) = fresh_vault();

        // A real eddsa-jcs-2022 VC from a did:key issuer: the proof key is the
        // issuer DID itself, so the issuer-binding holds and resolution is local.
        let seed = [3u8; 32];
        let issuer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            &SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        );
        let vm = format!(
            "{issuer_did}#{}",
            issuer_did.strip_prefix("did:key:").unwrap()
        );
        let secret = Secret::generate_ed25519(Some(&vm), Some(&seed));

        let mut vc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": issuer_did,
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:key:zMember", "givenName": "Alice" }
        });
        let proof = DataIntegrityProof::sign(
            &vc,
            &secret,
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .expect("sign DI VC");
        vc["proof"] = serde_json::to_value(&proof).unwrap();

        // No resolver needed — did:key resolves locally.
        let cred = receive_issued_credential(&vault, &issue_body(vc, None), None, None, Utc::now())
            .await
            .expect("receive did:key DI VC");
        assert_eq!(cred.format, CredentialFormat::EddsaJcs2022);
        assert_eq!(cred.issuer_did.as_deref(), Some(issuer_did.as_str()));
    }

    #[tokio::test]
    async fn refuses_an_empty_issue() {
        let (_dir, _store, vault) = fresh_vault();
        let empty = IssueBody {
            credential_response: None,
            sealed: None,
        };
        let err = receive_issued_credential(&vault, &empty, None, None, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    // ── DCQL match (task 3.5) ──

    const MEMBERSHIP_VCT: &str = "https://openvtc.org/credentials/MembershipCredential";

    /// Mint a real SD-JWT-VC and store it in `vault`, returning the
    /// `StoredCredential` (the holder's vault entry).
    async fn mint_and_store(vault: &KeyspaceHandle) -> StoredCredential {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(signing.verifying_key().as_bytes());
        let signer = EddsaSigner {
            key: signing,
            kid: format!("{did}#key-0"),
        };
        let subject = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            SigningKey::from_bytes(&[5u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let compact = crate::vault::mint::mint_sd_jwt_vc(
            &crate::vault::mint::MintRequest {
                vct: MEMBERSHIP_VCT,
                issuer_did: &did,
                subject_did: &subject,
                claims: &json!({ "givenName": "Alice" }),
                disclosable: &["givenName"],
                iat: 1_700_000_000,
                exp: Some(1_900_000_000),
            },
            &signer,
        )
        .expect("mint SD-JWT-VC");
        let body = issue_body(Value::String(compact), None);
        let cred = receive_issued_credential(vault, &body, None, None, Utc::now())
            .await
            .expect("receive");
        crate::vault::storage::get(vault, &cred.id)
            .await
            .unwrap()
            .expect("stored")
    }

    #[tokio::test]
    async fn matches_a_held_sd_jwt_vc_by_vct_and_discloses_the_named_claim() {
        let (_dir, _store, vault) = fresh_vault();
        let stored = mint_and_store(&vault).await;

        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [MEMBERSHIP_VCT] },
                "claims": [{ "path": ["givenName"] }]
            }]
        }))
        .unwrap();

        let matches = match_held(&query, std::slice::from_ref(&stored)).expect("match");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].credential_query_id, "membership");
        assert_eq!(matches[0].credential_id, stored.id);
        assert_eq!(
            matches[0].disclosed_paths,
            vec![vec!["givenName".to_string()]]
        );
    }

    #[tokio::test]
    async fn does_not_match_a_different_vct() {
        let (_dir, _store, vault) = fresh_vault();
        let stored = mint_and_store(&vault).await;

        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "x",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.org/Other"] }
            }]
        }))
        .unwrap();

        assert!(match_held(&query, &[stored]).unwrap().is_empty());
    }

    #[tokio::test]
    async fn skips_not_yet_presentable_formats_without_erroring() {
        let (_dir, _store, vault) = fresh_vault();
        let mut zkp = mint_and_store(&vault).await;
        // A ZKP credential isn't presentable via DCQL yet — it must be skipped,
        // not error the whole match.
        zkp.format = CredentialFormat::Zkp;

        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [MEMBERSHIP_VCT] }
            }]
        }))
        .unwrap();

        // Skipped → no candidates → no match, but Ok (not Err).
        assert!(match_held(&query, &[zkp]).unwrap().is_empty());
    }

    #[tokio::test]
    async fn match_vault_gathers_via_the_type_index_and_matches() {
        let (_dir, _store, vault) = fresh_vault();
        let stored = mint_and_store(&vault).await;

        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [MEMBERSHIP_VCT] },
                "claims": [{ "path": ["givenName"] }]
            }]
        }))
        .unwrap();

        let matches = match_vault(&vault, &query).await.expect("match vault");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].credential_id, stored.id);
        assert_eq!(
            matches[0].disclosed_paths,
            vec![vec!["givenName".to_string()]]
        );
    }

    #[tokio::test]
    async fn match_vault_is_empty_without_a_type_discriminator() {
        let (_dir, _store, vault) = fresh_vault();
        let _stored = mint_and_store(&vault).await;

        // No `meta` → no targeted index search → no candidates (the vault has no
        // enumeration primitive, so the holder doesn't blind-scan its wallet).
        let query = DcqlQuery::from_json(&json!({
            "credentials": [{ "id": "x", "format": "dc+sd-jwt" }]
        }))
        .unwrap();

        assert!(match_vault(&vault, &query).await.unwrap().is_empty());
    }

    // ── present_for_query (task 3.5c) ──

    /// Holder key material for the credential `mint_and_store` binds (subject
    /// seed `[5;32]`): the SD-JWT-VC kb-jwt signer + the consent-record signing
    /// secret, both over the subject's `did:key`.
    fn subject_holder() -> (
        String,
        EddsaSigner,
        affinidi_secrets_resolver::secrets::Secret,
    ) {
        let seed = [5u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(signing.verifying_key().as_bytes());
        let vm = format!("{did}#{}", did.strip_prefix("did:key:").unwrap());
        let kb_signer = EddsaSigner {
            key: SigningKey::from_bytes(&seed),
            kid: vm.clone(),
        };
        let mut consent_key =
            affinidi_secrets_resolver::secrets::Secret::generate_ed25519(Some(&vm), Some(&seed));
        consent_key.id = vm;
        (did, kb_signer, consent_key)
    }

    #[tokio::test]
    async fn present_for_query_builds_a_consent_gated_selective_vp() {
        use crate::vault::consent::{ConsentGrant, create as create_consent};

        let (_dir, _store, vault) = fresh_vault();
        let stored = mint_and_store(&vault).await; // subject did:key[5], givenName disclosable
        let (subject_did, kb_signer, consent_key) = subject_holder();
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        // Consent to disclose givenName to this verifier for this credential.
        let rec = create_consent(
            &vault,
            &ConsentGrant {
                holder_did: &subject_did,
                credential_id: &stored.id,
                verifier_did: verifier,
                purpose: "join the Acme community",
                claims: vec!["givenName".into()],
                valid_until: now + chrono::Duration::hours(1),
            },
            &consent_key,
        )
        .await
        .expect("create consent");

        let query = QueryBody {
            dcql_query: DcqlQuery::from_json(&json!({
                "credentials": [{
                    "id": "membership",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": [MEMBERSHIP_VCT] },
                    "claims": [{ "path": ["givenName"] }]
                }]
            }))
            .unwrap(),
            nonce: "verifier-nonce-1".into(),
            purpose: "join the Acme community".into(),
        };

        let present = present_for_query(
            &vault,
            &query,
            &kb_signer,
            &consent_key,
            &rec.identifier,
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect("present for query");

        // vp_token is a compact SD-JWT-VC: discloses exactly givenName + a kb-jwt.
        let token = present.vp_token.as_str().expect("compact-string vp_token");
        let parsed =
            affinidi_sd_jwt::SdJwt::parse(token, &affinidi_sd_jwt::hasher::Sha256Hasher).unwrap();
        assert_eq!(parsed.disclosures.len(), 1);
        assert_eq!(
            parsed.disclosures[0].claim_name.as_deref(),
            Some("givenName")
        );
        assert!(
            parsed.kb_jwt.is_some(),
            "mandatory holder kb-jwt must be present"
        );
    }

    #[tokio::test]
    async fn present_for_query_is_not_found_when_nothing_matches() {
        let (_dir, _store, vault) = fresh_vault();
        let _stored = mint_and_store(&vault).await;
        let (_did, kb_signer, consent_key) = subject_holder();

        let query = QueryBody {
            dcql_query: DcqlQuery::from_json(&json!({
                "credentials": [{
                    "id": "x", "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://example.org/Other"] }
                }]
            }))
            .unwrap(),
            nonce: "n".into(),
            purpose: "p".into(),
        };

        let err = present_for_query(
            &vault,
            &query,
            &kb_signer,
            &consent_key,
            "consent-x",
            "did:web:v",
            0,
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
    }

    /// Store a plain W3C-DI VC (`EddsaJcs2022`) bound to `subject_did`, indexed
    /// under `MembershipCredential` so a `type_values` DCQL query gathers it.
    async fn store_di_membership(vault: &KeyspaceHandle, id: &str, subject_did: &str) {
        let vc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": { "id": subject_did, "givenName": "Alice" },
        });
        let cred = crate::vault::model::StoredCredential {
            id: id.to_string(),
            format: CredentialFormat::EddsaJcs2022,
            types: vec!["MembershipCredential".into()],
            schema_id: None,
            community_did: None,
            subject_did: Some(subject_did.to_string()),
            issuer_did: Some("did:web:issuer.example".into()),
            purpose: None,
            status: crate::vault::model::CredentialStatus::Valid,
            valid_from: None,
            valid_until: None,
            received_at: "2026-01-01T00:00:00Z".into(),
            source: None,
            tags: Default::default(),
            body: serde_json::to_vec(&vc).unwrap(),
        };
        crate::vault::storage::put(vault, &cred)
            .await
            .expect("put DI VC");
    }

    #[tokio::test]
    async fn present_for_query_presents_a_w3c_di_vc_as_a_json_vp() {
        use crate::vault::consent::{ConsentGrant, create as create_consent};

        let (_dir, _store, vault) = fresh_vault();
        let (subject_did, _kb_signer, holder_secret) = subject_holder();
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        store_di_membership(&vault, "di-membership", &subject_did).await;

        // Plain DI cannot redact, so consent must cover the whole subject.
        let rec = create_consent(
            &vault,
            &ConsentGrant {
                holder_did: &subject_did,
                credential_id: "di-membership",
                verifier_did: verifier,
                purpose: "join the Acme community",
                claims: vec!["givenName".into()],
                valid_until: now + chrono::Duration::hours(1),
            },
            &holder_secret,
        )
        .await
        .expect("create consent");

        // A `ldp_vc` DCQL query selecting the DI credential by W3C `type_values`.
        let query = QueryBody {
            dcql_query: DcqlQuery::from_json(&json!({
                "credentials": [{
                    "id": "membership",
                    "format": "ldp_vc",
                    "meta": { "type_values": ["MembershipCredential"] },
                    "claims": [{ "path": ["credentialSubject", "givenName"] }]
                }]
            }))
            .unwrap(),
            nonce: "verifier-nonce-di".into(),
            purpose: "join the Acme community".into(),
        };

        // The kb-jwt signer is unused on the DI arm — pass the subject's anyway.
        let (_d, kb_signer, _k) = subject_holder();
        let present = present_for_query(
            &vault,
            &query,
            &kb_signer,
            &holder_secret,
            &rec.identifier,
            verifier,
            now.timestamp() as u64,
            now,
        )
        .await
        .expect("present DI for query");

        // The DI vp_token is a JSON VP object (not a compact string), holder-bound.
        let vp = present.vp_token.as_object().expect("JSON-object vp_token");
        assert_eq!(vp["type"][0], "VerifiablePresentation");
        assert_eq!(vp["holder"], subject_did);
        assert_eq!(vp["nonce"], "verifier-nonce-di");
        assert_eq!(vp["domain"], verifier);
        assert_eq!(
            vp["verifiableCredential"][0]["credentialSubject"]["givenName"],
            "Alice"
        );
        assert!(vp.contains_key("proof"), "holder VP proof must be present");
    }

    // ── present_or_defer: consent policy ──

    fn membership_query() -> QueryBody {
        QueryBody {
            dcql_query: DcqlQuery::from_json(&json!({
                "credentials": [{
                    "id": "membership",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": [MEMBERSHIP_VCT] },
                    "claims": [{ "path": ["givenName"] }]
                }]
            }))
            .unwrap(),
            nonce: "verifier-nonce-1".into(),
            purpose: "join the Acme community".into(),
        }
    }

    #[tokio::test]
    async fn present_or_defer_auto_consents_for_a_trusted_verifier() {
        let (_dir, _store, vault) = fresh_vault();
        let _stored = mint_and_store(&vault).await;
        let (_did, kb_signer, consent_key) = subject_holder();
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();

        let policy = ConsentPolicy::trusting([verifier]);
        let outcome = present_or_defer(
            &vault,
            &membership_query(),
            verifier,
            &policy,
            &kb_signer,
            &consent_key,
            now,
        )
        .await
        .expect("present_or_defer");

        match outcome {
            PresentOutcome::Presented(body) => {
                let token = body.vp_token.as_str().expect("compact vp_token");
                let parsed =
                    affinidi_sd_jwt::SdJwt::parse(token, &affinidi_sd_jwt::hasher::Sha256Hasher)
                        .unwrap();
                assert_eq!(parsed.disclosures.len(), 1);
                assert!(parsed.kb_jwt.is_some());
            }
            other => panic!("expected Presented, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn present_or_defer_defers_for_an_untrusted_verifier() {
        let (_dir, _store, vault) = fresh_vault();
        let _stored = mint_and_store(&vault).await;
        let (_did, kb_signer, consent_key) = subject_holder();
        let now = Utc::now();

        // Empty policy → no verifier is trusted → defer.
        let policy = ConsentPolicy::default();
        let outcome = present_or_defer(
            &vault,
            &membership_query(),
            "did:web:stranger.example",
            &policy,
            &kb_signer,
            &consent_key,
            now,
        )
        .await
        .expect("present_or_defer");

        match outcome {
            PresentOutcome::ConsentRequired {
                verifier_did,
                claims,
                purpose,
                ..
            } => {
                assert_eq!(verifier_did, "did:web:stranger.example");
                assert_eq!(claims, vec!["givenName".to_string()]);
                assert_eq!(purpose, "join the Acme community");
            }
            other => panic!("expected ConsentRequired, got {other:?}"),
        }
    }

    // ── present_query: the full holder query→present path ──

    #[tokio::test]
    async fn present_query_runs_the_full_holder_present_path() {
        use crate::acl::Role;
        use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
        use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};

        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let vault = store.keyspace("vault").unwrap();
        let keys_ks = store.keyspace("keys").unwrap();

        // The holder subject key is a VTA-derived key (context `acme`).
        let seed = vec![42u8; 64];
        let seed_store: Arc<dyn SeedStore> =
            Arc::new(crate::test_support::TestSeedStore(seed.clone()));
        let path = "m/26'/2'/0'/0'";
        let bip32 = ExtendedSigningKey::from_seed(&seed).unwrap();
        let derived = bip32
            .derive(&path.parse::<DerivationPath>().unwrap())
            .unwrap();
        let subject_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            derived.signing_key.verifying_key().as_bytes(),
        );
        let multibase = subject_did.strip_prefix("did:key:").unwrap();
        let key_id = format!("{subject_did}#{multibase}");
        keys_ks
            .insert(
                crate::keys::store_key(&key_id),
                &KeyRecord {
                    key_id: key_id.clone(),
                    derivation_path: path.into(),
                    key_type: KeyType::Ed25519,
                    status: KeyStatus::Active,
                    public_key: multibase.into(),
                    label: None,
                    context_id: Some("acme".into()),
                    seed_id: None,
                    origin: KeyOrigin::Derived,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            )
            .await
            .unwrap();

        // Mint + store an SD-JWT-VC bound to that subject (cnf = its key).
        let issuer = SigningKey::from_bytes(&[9u8; 32]);
        let issuer_did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(issuer.verifying_key().as_bytes());
        let issuer_signer = EddsaSigner {
            key: issuer,
            kid: format!("{issuer_did}#key-0"),
        };
        let compact = crate::vault::mint::mint_sd_jwt_vc(
            &crate::vault::mint::MintRequest {
                vct: MEMBERSHIP_VCT,
                issuer_did: &issuer_did,
                subject_did: &subject_did,
                claims: &json!({ "givenName": "Alice" }),
                disclosable: &["givenName"],
                iat: 1_700_000_000,
                exp: Some(1_900_000_000),
            },
            &issuer_signer,
        )
        .unwrap();
        let cred = receive_issued_credential(
            &vault,
            &issue_body(Value::String(compact), None),
            None,
            None,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(cred.subject_did.as_deref(), Some(subject_did.as_str()));

        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();
        // The VTA acts on its own behalf (super-admin over its own contexts).
        let auth = AuthClaims {
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            ..Default::default()
        };
        let query = membership_query();

        // Trusted verifier → present, end to end (key resolved + kb-jwt signed).
        let outcome = present_query(
            &vault,
            &keys_ks,
            &seed_store,
            &auth,
            &query,
            verifier,
            &ConsentPolicy::trusting([verifier]),
            now,
        )
        .await
        .expect("present_query");
        match outcome {
            PresentOutcome::Presented(body) => {
                let token = body.vp_token.as_str().expect("compact vp_token");
                let parsed =
                    affinidi_sd_jwt::SdJwt::parse(token, &affinidi_sd_jwt::hasher::Sha256Hasher)
                        .unwrap();
                assert_eq!(parsed.disclosures.len(), 1);
                assert!(parsed.kb_jwt.is_some(), "holder kb-jwt must be present");
            }
            other => panic!("expected Presented, got {other:?}"),
        }

        // Untrusted verifier → deferral.
        let deferred = present_query(
            &vault,
            &keys_ks,
            &seed_store,
            &auth,
            &query,
            "did:web:stranger.example",
            &ConsentPolicy::default(),
            now,
        )
        .await
        .unwrap();
        assert!(matches!(deferred, PresentOutcome::ConsentRequired { .. }));
    }

    // ── deferred approval store (task 3.5d, the defer half) ──

    /// Full holder fixture: a VTA-derived subject key (context `acme`) registered
    /// in `keys_ks` + an SD-JWT-VC bound to it stored in the vault. Returns the
    /// pieces `present_query` / `approve_pending_presentation` need.
    async fn holder_fixture() -> (
        tempfile::TempDir,
        KeyspaceHandle,
        KeyspaceHandle,
        Arc<dyn SeedStore>,
        String,
    ) {
        use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
        use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};

        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let vault = store.keyspace("vault").unwrap();
        let keys_ks = store.keyspace("keys").unwrap();

        let seed = vec![42u8; 64];
        let seed_store: Arc<dyn SeedStore> =
            Arc::new(crate::test_support::TestSeedStore(seed.clone()));
        let path = "m/26'/2'/0'/0'";
        let bip32 = ExtendedSigningKey::from_seed(&seed).unwrap();
        let derived = bip32
            .derive(&path.parse::<DerivationPath>().unwrap())
            .unwrap();
        let subject_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            derived.signing_key.verifying_key().as_bytes(),
        );
        let multibase = subject_did.strip_prefix("did:key:").unwrap();
        let key_id = format!("{subject_did}#{multibase}");
        keys_ks
            .insert(
                crate::keys::store_key(&key_id),
                &KeyRecord {
                    key_id: key_id.clone(),
                    derivation_path: path.into(),
                    key_type: KeyType::Ed25519,
                    status: KeyStatus::Active,
                    public_key: multibase.into(),
                    label: None,
                    context_id: Some("acme".into()),
                    seed_id: None,
                    origin: KeyOrigin::Derived,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            )
            .await
            .unwrap();

        let issuer = SigningKey::from_bytes(&[9u8; 32]);
        let issuer_did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(issuer.verifying_key().as_bytes());
        let issuer_signer = EddsaSigner {
            key: issuer,
            kid: format!("{issuer_did}#key-0"),
        };
        let compact = crate::vault::mint::mint_sd_jwt_vc(
            &crate::vault::mint::MintRequest {
                vct: MEMBERSHIP_VCT,
                issuer_did: &issuer_did,
                subject_did: &subject_did,
                claims: &json!({ "givenName": "Alice" }),
                disclosable: &["givenName"],
                iat: 1_700_000_000,
                exp: Some(1_900_000_000),
            },
            &issuer_signer,
        )
        .unwrap();
        receive_issued_credential(
            &vault,
            &issue_body(Value::String(compact), None),
            None,
            None,
            Utc::now(),
        )
        .await
        .unwrap();

        (dir, vault, keys_ks, seed_store, subject_did)
    }

    #[tokio::test]
    async fn defer_then_approve_presents_and_marks_approved() {
        use crate::acl::Role;

        let (_dir, vault, keys_ks, seed_store, _subject) = holder_fixture().await;
        let verifier = "did:web:stranger.example";
        let now = Utc::now();
        let auth = AuthClaims {
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            ..Default::default()
        };
        let query = membership_query();

        // 1. Untrusted verifier defers → no presentation yet, but a pending record.
        let outcome = present_query(
            &vault,
            &keys_ks,
            &seed_store,
            &auth,
            &query,
            verifier,
            &ConsentPolicy::default(),
            now,
        )
        .await
        .expect("present_query");
        let credential_id = match outcome {
            PresentOutcome::ConsentRequired {
                credential_id,
                claims,
                ..
            } => {
                let rec = defer_presentation(
                    &vault,
                    "req-1",
                    verifier,
                    &credential_id,
                    claims,
                    &query,
                    now,
                )
                .await
                .expect("defer");
                assert_eq!(rec.status, pending::PendingStatus::Pending);
                credential_id
            }
            other => panic!("expected ConsentRequired, got {other:?}"),
        };

        // It shows up on the holder's local approval surface.
        let list = pending::list(&vault).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "req-1");
        assert_eq!(list[0].credential_id, credential_id);

        // 2. Out-of-band approval mints consent + re-presents.
        let present =
            approve_pending_presentation(&vault, &keys_ks, &seed_store, &auth, "req-1", now)
                .await
                .expect("approve");
        let token = present.vp_token.as_str().expect("compact vp_token");
        let parsed =
            affinidi_sd_jwt::SdJwt::parse(token, &affinidi_sd_jwt::hasher::Sha256Hasher).unwrap();
        assert_eq!(parsed.disclosures.len(), 1);
        assert!(parsed.kb_jwt.is_some(), "holder kb-jwt must be present");

        // The record is now Approved, and a second approval refuses.
        assert_eq!(
            pending::get(&vault, "req-1").await.unwrap().unwrap().status,
            pending::PendingStatus::Approved
        );
        let twice =
            approve_pending_presentation(&vault, &keys_ks, &seed_store, &auth, "req-1", now)
                .await
                .unwrap_err();
        assert!(matches!(twice, AppError::Validation(_)), "{twice:?}");
    }

    #[tokio::test]
    async fn deny_marks_denied_and_blocks_approval() {
        use crate::acl::Role;

        let (_dir, vault, keys_ks, seed_store, _subject) = holder_fixture().await;
        let verifier = "did:web:stranger.example";
        let now = Utc::now();
        let query = membership_query();

        defer_presentation(
            &vault,
            "req-2",
            verifier,
            "urn:cred:1",
            vec!["givenName".into()],
            &query,
            now,
        )
        .await
        .expect("defer");

        let denied = deny_pending_presentation(&vault, "req-2")
            .await
            .expect("deny");
        assert_eq!(denied.status, pending::PendingStatus::Denied);

        // A denied record cannot then be approved.
        let auth = AuthClaims {
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            ..Default::default()
        };
        let err = approve_pending_presentation(&vault, &keys_ks, &seed_store, &auth, "req-2", now)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    #[tokio::test]
    async fn approve_refuses_an_expired_deferral() {
        use crate::acl::Role;

        let (_dir, vault, keys_ks, seed_store, _subject) = holder_fixture().await;
        let query = membership_query();
        let created = Utc::now() - chrono::Duration::hours(48);

        // A deferral recorded 48h ago — past the 24h window.
        defer_presentation(
            &vault,
            "req-3",
            "did:web:stranger.example",
            "urn:cred:1",
            vec!["givenName".into()],
            &query,
            created,
        )
        .await
        .expect("defer");

        let auth = AuthClaims {
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            ..Default::default()
        };
        let err =
            approve_pending_presentation(&vault, &keys_ks, &seed_store, &auth, "req-3", Utc::now())
                .await
                .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }
}
