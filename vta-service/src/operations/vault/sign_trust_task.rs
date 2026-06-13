//! `vault/sign-trust-task/0.1` business logic — attach an `eddsa-jcs-2022`
//! Data-Integrity proof to a Trust Task envelope, signing as the principal DID
//! of a `did-self-issued` / `didcomm-peer` vault entry (P2.4).
//!
//! Moved out of `routes/trust_tasks/vault.rs` so the route handler is a thin
//! adapter: it keeps the capability/context/step-up gates + the audit log +
//! the wire response, and maps the typed [`SignTrustTaskError`] back to the
//! canonical spec reject codes. The signable-kind check, envelope structural
//! validation, and the signing live here.

use serde_json::Value;

use vti_common::vault::VaultSecret;

use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::store::KeyspaceHandle;

/// A signed envelope + the principal DID it was signed as (for the route's
/// audit log).
pub struct SignedEnvelope {
    pub signed: Value,
    pub principal_did: String,
}

/// Why signing failed. The route maps each onto the canonical
/// `vault/sign-trust-task/0.1` reject reason (conformance-ordered:
/// `not_signable` → `envelope_invalid` → `envelope_already_proofed` →
/// `envelope_issuer_mismatch` → `envelope_expired`).
pub enum SignTrustTaskError {
    /// Entry kind carries no DID-based signing identity.
    NotSignable { kind: &'static str },
    /// `unsignedEnvelope` is not a JSON object.
    EnvelopeNotObject,
    /// A required envelope field is missing.
    EnvelopeMissingField { field: &'static str },
    /// `issuer` is present but not a string.
    IssuerNotString,
    /// The envelope already carries a `proof`.
    AlreadyProofed,
    /// `envelope.issuer` != the entry's principal DID.
    IssuerMismatch {
        envelope_issuer: String,
        expected: String,
    },
    /// `expiresAt` is present but not an RFC-3339 timestamp.
    ExpiresAtNotRfc3339 { value: String },
    /// `expiresAt` is in the past.
    Expired { value: String },
    /// Internal failure (key load, sign, serialise).
    App(AppError),
}

impl From<AppError> for SignTrustTaskError {
    fn from(e: AppError) -> Self {
        SignTrustTaskError::App(e)
    }
}

/// Validate `unsigned_envelope` against `secret`'s principal identity and
/// attach an `eddsa-jcs-2022` proof signed as that principal.
///
/// The caller has already gated capability + context scope + step-up.
pub async fn sign_envelope(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    secret: &VaultSecret,
    unsigned_envelope: &Value,
) -> Result<SignedEnvelope, SignTrustTaskError> {
    // Only DID-anchored kinds carry a principal identity to sign as.
    let (principal_did, signing_key_id) = match secret {
        VaultSecret::DidSelfIssued {
            did,
            signing_key_id,
            ..
        }
        | VaultSecret::DidcommPeer {
            peer_did: did,
            signing_key_id,
            ..
        } => (did.clone(), signing_key_id.clone()),
        other => {
            return Err(SignTrustTaskError::NotSignable {
                kind: super::secret_kind_label(other.kind()),
            });
        }
    };

    // Structural validation. Per spec: id, type, issuer, recipient, issuedAt,
    // payload all required; proof must be absent.
    let envelope_obj = unsigned_envelope
        .as_object()
        .ok_or(SignTrustTaskError::EnvelopeNotObject)?;
    for field in ["id", "type", "issuer", "recipient", "issuedAt", "payload"] {
        if !envelope_obj.contains_key(field) {
            return Err(SignTrustTaskError::EnvelopeMissingField { field });
        }
    }
    if envelope_obj.contains_key("proof") {
        return Err(SignTrustTaskError::AlreadyProofed);
    }

    // Strict issuer match: refuse to silently rewrite the consumer's issuer.
    let envelope_issuer = envelope_obj
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or(SignTrustTaskError::IssuerNotString)?;
    if envelope_issuer != principal_did {
        return Err(SignTrustTaskError::IssuerMismatch {
            envelope_issuer: envelope_issuer.to_string(),
            expected: principal_did,
        });
    }

    // expiresAt (if present) must be a future RFC-3339 timestamp.
    if let Some(exp_v) = envelope_obj.get("expiresAt") {
        let exp_str = exp_v.as_str().unwrap_or_default();
        match chrono::DateTime::parse_from_rfc3339(exp_str) {
            Ok(exp) if exp < chrono::Utc::now() => {
                return Err(SignTrustTaskError::Expired {
                    value: exp_str.to_string(),
                });
            }
            Ok(_) => {}
            Err(_) => {
                return Err(SignTrustTaskError::ExpiresAtNotRfc3339 {
                    value: exp_str.to_string(),
                });
            }
        }
    }

    // Load the signing key as an affinidi Secret and sign. The proof's
    // verificationMethod kid IS the entry's signing_key_id — the maintainer
    // trusts the stored reference (validated at upsert time).
    let secret_key = super::load_signing_secret_by_id(
        keys_ks,
        imported_ks,
        seed_store,
        audit_ks,
        &signing_key_id,
    )
    .await?;
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        unsigned_envelope,
        &secret_key,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .map_err(|e| AppError::Internal(format!("DataIntegrityProof sign failed: {e}")))?;
    let proof_value = serde_json::to_value(&proof)
        .map_err(|e| AppError::Internal(format!("serialize proof: {e}")))?;

    // Attach the proof, preserving every other field byte-for-byte.
    let mut signed = unsigned_envelope.clone();
    signed
        .as_object_mut()
        .expect("envelope is an object — checked above")
        .insert("proof".to_string(), proof_value);

    Ok(SignedEnvelope {
        signed,
        principal_did,
    })
}
