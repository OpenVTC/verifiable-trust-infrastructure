//! DID resolution — wraps `affinidi-did-resolver-cache-sdk`.
//!
//! **Slice 3a.** The engine's first *async* export, proving the async-over-FFI
//! path (`#[uniffi::export(async_runtime = "tokio")]`). Default config is
//! **local**: `did:key` / `did:peer` resolve offline — which already covers the
//! holder/relying-party key lookups needed to verify step-up proofs. Networked
//! methods (`did:web` / `did:webvh`) need a network-mode config and are a
//! follow-up.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use tokio::sync::OnceCell;

use crate::error::FfiError;

/// One process-wide caching resolver, lazily initialised on first use. The
/// resolver caches immutable methods (key/peer) indefinitely, so repeated
/// lookups stay cheap.
static CLIENT: OnceCell<DIDCacheClient> = OnceCell::const_new();

async fn client() -> Result<&'static DIDCacheClient, FfiError> {
    CLIENT
        .get_or_try_init(|| async {
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .map_err(|e| FfiError::InvalidInput {
                    reason: format!("DID resolver init failed: {e}"),
                })
        })
        .await
}

/// Resolve a DID to its DID Document, returned as JSON.
///
/// Used to find a peer's verification keys (to verify a relying party's step-up
/// proof) and key-agreement key (for DIDComm). `did:key` / `did:peer` resolve
/// locally; other methods will require a network-mode resolver config
/// (follow-up). The first async function exported across the FFI boundary.
#[uniffi::export(async_runtime = "tokio")]
pub async fn resolve_did(did: String) -> Result<String, FfiError> {
    let response = client()
        .await?
        .resolve(&did)
        .await
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("could not resolve {did}: {e}"),
        })?;
    serde_json::to_string(&response.doc).map_err(|e| FfiError::InvalidInput {
        reason: format!("could not serialize DID document: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test (one runtime) — the process-wide resolver is initialised and
    // used within the same runtime, avoiding cross-runtime handle issues.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolves_did_key_locally_and_rejects_garbage() {
        let did = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
        let json = resolve_did(did.to_string())
            .await
            .expect("did:key resolves locally");
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(doc["id"], did);
        assert!(
            doc.get("verificationMethod").is_some(),
            "did:key document exposes a verificationMethod"
        );

        let err = resolve_did("not-a-did".to_string())
            .await
            .expect_err("a non-DID must fail");
        assert!(matches!(err, FfiError::InvalidInput { .. }));
    }
}
