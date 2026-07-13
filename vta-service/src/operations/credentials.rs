//! Issued-credential lifecycle (operations layer) — mint a VTA-signed W3C
//! Verifiable Credential to a holder DID and revoke it by id.
//!
//! Backs the `vta/credentials/{issue,revoke}/0.1` Trust Tasks
//! (`crate::trust_tasks::credentials`). The transport/auth ceremony (step-up
//! gate, capability check, audit) stays in the trust-task handler; this module
//! owns the privileged minting + the issued-credentials store.
//!
//! ## Issuer key
//!
//! The VTA issues as its own DID. The issuer signing key is `{vta_did}#key-0`
//! — the same VC-issuance key the provision-integration flow uses
//! (`operations::provision_integration::vta_keys::load_vta_vc_issuance_secret`).
//! It's loaded via [`crate::operations::keys::get_key_secret_internal`] under an
//! [`InternalAuthority`] (route handlers can't construct one, so the elevation
//! is reachable only from the operations layer), then the VC is signed with a
//! `eddsa-jcs-2022` Data-Integrity proof (`proofPurpose = "assertionMethod"`),
//! mirroring `vault::consent::sign_with` and
//! `provision_integration::credential::issue_vta_authorization_credential`.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::AppError;
use crate::operations::internal_authority::InternalAuthority;
use crate::server::AppState;
use crate::store::KeyspaceHandle;
use vta_sdk::did_key::decode_private_key_multibase;

/// VC Data Model 2.0 base context — every issued VC carries this.
const VC_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// Storage-key prefix for an issued-credential record (`cred:<id>`).
fn store_key(id: &str) -> String {
    format!("cred:{id}")
}

/// A persisted issued-credential record. The signed VC itself is stored
/// verbatim under `credential`; revocation sets `revoked_at` (+ optional
/// `reason`) in place rather than deleting (tombstone — the audit/verifier
/// trail must survive revocation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCredentialRecord {
    pub id: String,
    pub holder: String,
    /// The full signed W3C VC (with its Data-Integrity proof).
    pub credential: Value,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}

impl IssuedCredentialRecord {
    fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Parameters for [`issue_credential`].
pub struct IssueParams<'a> {
    pub holder: &'a str,
    /// The claims merged into `credentialSubject` (must be a non-empty object).
    pub claims: &'a Value,
    /// Optional extra type appended after `VerifiableCredential`.
    pub credential_type: Option<&'a str>,
    pub validity_seconds: u64,
}

/// Mint, sign, and store a scoped, time-boxed VC for `params.holder`.
///
/// Returns the stored record (its `id`, the signed `credential`, and
/// `expires_at`). The caller (the trust-task handler) is responsible for the
/// step-up gate, the capability check, and the audit record.
pub async fn issue_credential(
    state: &AppState,
    params: IssueParams<'_>,
) -> Result<IssuedCredentialRecord, AppError> {
    // Validate claims up front: a VC with no subject claims is almost certainly
    // an operator error, and `deny_unknown_fields` already rejected typos.
    let claims_obj = params
        .claims
        .as_object()
        .ok_or_else(|| AppError::Validation("claims must be a JSON object".to_string()))?;
    if claims_obj.is_empty() {
        return Err(AppError::Validation(
            "claims must be a non-empty object".to_string(),
        ));
    }
    if params.validity_seconds == 0 {
        return Err(AppError::Validation(
            "validitySeconds must be greater than zero".to_string(),
        ));
    }

    let vta_did =
        state.config.read().await.vta_did.clone().ok_or_else(|| {
            AppError::Internal("VTA DID not configured; cannot issue".to_string())
        })?;

    let issuer_secret = load_vta_issuer_secret(state, &vta_did, "credentials-issue").await?;

    let now = Utc::now();
    let expires = now + Duration::seconds(params.validity_seconds as i64);
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());

    // Build the unsigned VC. `credentialSubject` = the caller's claims with
    // `id` set to the holder DID (an explicit `id` in claims is overridden — the
    // subject is whoever the credential is issued to).
    let mut subject = claims_obj.clone();
    subject.insert("id".to_string(), Value::String(params.holder.to_string()));

    let mut types = vec![Value::String("VerifiableCredential".to_string())];
    if let Some(ct) = params.credential_type {
        types.push(Value::String(ct.to_string()));
    }

    let mut vc = json!({
        "@context": [VC_V2_CONTEXT],
        "id": id,
        "type": types,
        "issuer": vta_did,
        "validFrom": rfc3339(now),
        "validUntil": rfc3339(expires),
        "credentialSubject": Value::Object(subject),
    });

    // Sign with the VTA issuer key (eddsa-jcs-2022, assertionMethod) — same
    // suite/purpose as `vault::consent` and the provision-integration issuer.
    let proof = DataIntegrityProof::sign(
        &vc,
        &issuer_secret,
        SignOptions::new()
            .with_proof_purpose("assertionMethod")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .map_err(|e| AppError::Internal(format!("sign issued credential: {e}")))?;
    vc.as_object_mut().expect("vc is an object").insert(
        "proof".to_string(),
        serde_json::to_value(&proof)
            .map_err(|e| AppError::Internal(format!("serialize issued-credential proof: {e}")))?,
    );

    let record = IssuedCredentialRecord {
        id: id.clone(),
        holder: params.holder.to_string(),
        credential: vc,
        issued_at: rfc3339(now),
        expires_at: rfc3339(expires),
        revoked_at: None,
        revocation_reason: None,
    };

    store_put(&state.issued_credentials_ks, &record).await?;
    Ok(record)
}

/// Revoke a previously-issued credential by id.
///
/// - `not_found` if no record exists for `id`.
/// - `already_revoked` (a [`AppError::Conflict`]) if it already carries a
///   `revoked_at`.
///
/// On success the record's `revoked_at` (+ optional `reason`) is set in place
/// and the revocation timestamp is returned.
pub async fn revoke_credential(
    state: &AppState,
    credential_id: &str,
    reason: Option<&str>,
) -> Result<String, AppError> {
    let mut record = store_get(&state.issued_credentials_ks, credential_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("credential {credential_id} not found")))?;

    if record.is_revoked() {
        return Err(AppError::Conflict(format!(
            "credential {credential_id} is already revoked"
        )));
    }

    let revoked_at = rfc3339(Utc::now());
    record.revoked_at = Some(revoked_at.clone());
    record.revocation_reason = reason.map(str::to_string);
    store_put(&state.issued_credentials_ks, &record).await?;
    Ok(revoked_at)
}

/// Load the VTA's `{vta_did}#key-0` VC-issuance key as a signing `Secret`.
///
/// Mirrors `provision_integration::vta_keys::load_vta_vc_issuance_secret`: an
/// [`InternalAuthority`]-gated `get_key_secret_internal`, then reconstruct the
/// `Secret` from the multibase private key with `id = {vta_did}#key-0` so the
/// Data-Integrity proof's `verificationMethod` resolves under the VTA DID.
pub(crate) async fn load_vta_issuer_secret(
    state: &AppState,
    vta_did: &str,
    purpose: &'static str,
) -> Result<Secret, AppError> {
    let key_id = format!("{vta_did}#key-0");
    let authority = InternalAuthority::new(purpose);
    let resp = crate::operations::keys::get_key_secret_internal(
        &state.keys_ks,
        &state.imported_ks,
        &*state.seed_store,
        &state.audit_ks,
        authority,
        &key_id,
        purpose,
    )
    .await?;
    // Validate the multibase decodes to a 32-byte Ed25519 seed before
    // constructing the Secret (a malformed record would otherwise fail opaquely
    // at sign time).
    let _seed: [u8; 32] = decode_private_key_multibase(&resp.private_key_multibase)
        .map_err(|e| AppError::Internal(format!("decode VTA issuer key {key_id}: {e}")))?;
    let mut secret = Secret::from_multibase(&resp.private_key_multibase, None)
        .map_err(|e| AppError::Internal(format!("construct issuer Secret for {key_id}: {e}")))?;
    secret.id = key_id;
    Ok(secret)
}

async fn store_put(ks: &KeyspaceHandle, record: &IssuedCredentialRecord) -> Result<(), AppError> {
    ks.insert(store_key(&record.id), record).await
}

async fn store_get(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<IssuedCredentialRecord>, AppError> {
    ks.get(store_key(id)).await
}

/// RFC 3339 with a `Z` suffix (UTC), matching the workspace's VC timestamps.
fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
