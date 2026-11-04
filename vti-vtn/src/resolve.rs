//! A [`KeyResolver`] that resolves any DID a party may have: `did:key` and `did:peer` with no
//! I/O, `did:webvh` (what a VTA-provisioned VTC or VTN is) over the network.
//!
//! A key is accepted only if the signer's DID document authorises it for the proof's
//! purpose (VTI-KEY-022), through the VTA SDK's purpose-checking resolver. A community, a
//! network and the NNM all verify through this one.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use vta_sdk::trust_task_proof::{ProofPurpose, PurposeVmResolver, TrustTaskVmResolver};

use crate::error::{Result, VtnError};
use crate::verify::{KeyFuture, KeyResolver};

/// Resolves verification methods, checked for the proof's purpose.
#[derive(Clone)]
pub struct VmKeyResolver {
    inner: TrustTaskVmResolver,
}

impl VmKeyResolver {
    /// Network resolution, through the resolver at `resolver_url` when set.
    pub async fn network(resolver_url: Option<&str>) -> Result<Self> {
        let client = DIDCacheClient::new(vta_sdk::resolver::build_verifier_did_cache_config(
            resolver_url,
            300,
            1_000,
        ))
        .await
        .map_err(|e| VtnError::Internal(format!("build the DID resolver: {e}")))?;
        Ok(Self {
            inner: TrustTaskVmResolver::new(client),
        })
    }

    /// No I/O: `did:key` and `did:peer` only.
    pub fn offline() -> Self {
        Self {
            inner: TrustTaskVmResolver::did_key_only(),
        }
    }
}

impl From<TrustTaskVmResolver> for VmKeyResolver {
    /// A resolver the caller already has, sharing its DID cache.
    fn from(inner: TrustTaskVmResolver) -> Self {
        Self { inner }
    }
}

impl KeyResolver for VmKeyResolver {
    fn resolve<'a>(&'a self, verification_method: &'a str, purpose: &'a str) -> KeyFuture<'a> {
        Box::pin(async move {
            let purpose = ProofPurpose::parse(purpose)?;
            let key = self
                .inner
                .resolve_vm_for_purpose(verification_method, purpose)
                .await?;
            Ok(key.public_key_bytes)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::verify::{ASSERTION_METHOD, AUTHENTICATION, verify_document};
    use serde_json::json;

    #[tokio::test]
    async fn offline_resolves_a_did_key_for_the_purpose_it_was_signed_for() {
        let me = Identity::generate();
        let doc = me
            .sign_document_for(json!({ "issuer": me.did() }), AUTHENTICATION)
            .await
            .unwrap();
        let resolver = VmKeyResolver::offline();
        verify_document(&doc, me.did(), AUTHENTICATION, &resolver)
            .await
            .unwrap();
        assert!(
            verify_document(&doc, me.did(), ASSERTION_METHOD, &resolver)
                .await
                .is_err()
        );
    }
}
