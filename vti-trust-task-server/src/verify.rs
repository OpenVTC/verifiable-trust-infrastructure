//! Proof verification against the document **as received**.
//!
//! "As received" literally: over the JSON the inbound bytes parsed to, never a
//! re-serialisation of a typed document, which rewrites timestamps and drops
//! `null` optional members — either of which refuses a correctly signed
//! document (VTI-45).

use serde_json::Value;
use vta_sdk::trust_task_proof::{
    TrustTaskVmResolver, verify_approval_proof_value, verify_trust_task_proof_value,
};
use vti_common::error::AppError;

/// The spine's step 3: verify the proof on `received` and return the proven
/// signer DID (the base DID of the proof's `verificationMethod`).
///
/// Binding the signer to the document's `issuer` is the spine's job, not the
/// verifier's.
#[async_trait::async_trait]
pub trait ProofVerifier: Send + Sync {
    /// Verify `received`, a document of type `type_uri`. An error refuses the
    /// document (rendered through [`crate::reject::app_error_to_reject`]).
    async fn verify(&self, received: &Value, type_uri: &str) -> Result<String, AppError>;
}

/// Verify an operational document's `eddsa-jcs-2022` proof as received.
///
/// A resolver failure and a bad signature render identically
/// (`AppError::Unauthorized`), so an anonymous caller cannot learn whether a
/// DID resolves.
pub async fn verify_received_proof(
    resolver: &TrustTaskVmResolver,
    received: &Value,
) -> Result<String, AppError> {
    verify_trust_task_proof_value(received, resolver)
        .await
        .map_err(|e| AppError::Unauthorized(format!("Trust Task {e}")))
}

/// Verify a human approver's own decision as received: the proof must be made
/// for `assertionMethod`, by a key the signer lists under `assertionMethod`.
/// An approval is an attestation, not an operational message.
pub async fn verify_received_approval_proof(
    resolver: &TrustTaskVmResolver,
    received: &Value,
    type_uri: &str,
) -> Result<String, AppError> {
    verify_approval_proof_value(received, resolver)
        .await
        .map_err(|e| {
            // The cause stays in the operator's log; the wire gets `Display`.
            tracing::warn!(
                type_uri,
                error = %e,
                cause = e.cause().unwrap_or_default(),
                "approval refused at its proof"
            );
            AppError::Unauthorized(format!("Trust Task {e}"))
        })
}

/// A [`ProofVerifier`] over a [`TrustTaskVmResolver`]: approval types (as
/// `is_approval` says) are held to [`verify_received_approval_proof`], every
/// other type to [`verify_received_proof`].
pub struct ResolverProofVerifier<F> {
    resolver: TrustTaskVmResolver,
    is_approval: F,
}

impl<F> ResolverProofVerifier<F>
where
    F: Fn(&str) -> bool + Send + Sync,
{
    /// Verify through `resolver`, with `is_approval` naming the approval types.
    pub fn new(resolver: TrustTaskVmResolver, is_approval: F) -> Self {
        Self {
            resolver,
            is_approval,
        }
    }
}

impl ResolverProofVerifier<fn(&str) -> bool> {
    /// Verify through `resolver`, with no approval types.
    pub fn operational(resolver: TrustTaskVmResolver) -> Self {
        Self::new(resolver, |_| false)
    }
}

#[async_trait::async_trait]
impl<F> ProofVerifier for ResolverProofVerifier<F>
where
    F: Fn(&str) -> bool + Send + Sync,
{
    async fn verify(&self, received: &Value, type_uri: &str) -> Result<String, AppError> {
        if (self.is_approval)(type_uri) {
            verify_received_approval_proof(&self.resolver, received, type_uri).await
        } else {
            verify_received_proof(&self.resolver, received).await
        }
    }
}
