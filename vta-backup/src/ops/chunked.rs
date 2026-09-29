//! The `chunkedTrustTask` backup transfer, for the agent.
//!
//! The algorithm itself — staging, the chunk manifest, serving and accepting
//! chunks, the finalize checks — is node-neutral and lives in
//! [`vti_common::backup_transfer::chunked`], shared with the community node.
//! What is the agent's own is what a bundle holds: [`initiate_export`] serializes
//! and encrypts the agent's state and hands the bytes to the shared staging.

pub use vti_common::backup_transfer::chunked::*;

use vti_common::auth::AuthClaims;
use vti_common::error::AppError;

use super::descriptors::DescriptorDeps;

/// Mint a `chunkedTrustTask` export bundle of the agent's state.
///
/// Serializes and encrypts exactly as the `stream` op does, then stages the
/// bytes for retrieval by index instead of by URL. Needs no `public_url`: the
/// chunks travel over the transport this request arrived on.
///
/// `max_chunk_size` is the producer's `maxChunkSize`; the chunk size used is the
/// normative ceiling or that, whichever is smaller.
pub async fn initiate_export(
    deps: &DescriptorDeps<'_>,
    auth: &AuthClaims,
    password: &str,
    include_audit: bool,
    max_chunk_size: Option<u64>,
) -> Result<ChunkedBundle, ChunkedError> {
    check_initiate(deps.bundles_ks, auth).await?;

    let envelope = {
        let config_guard = deps.config.read().await;
        super::export_backup(
            &deps.target,
            deps.seed_store.as_ref(),
            &config_guard,
            auth,
            password,
            include_audit,
        )
        .await?
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|e| AppError::Internal(format!("serialize backup envelope: {e}")))?;
    stage_export(
        deps.bundles_ks,
        deps.blob_dir,
        &auth.did,
        &bytes,
        max_chunk_size,
    )
    .await
}
