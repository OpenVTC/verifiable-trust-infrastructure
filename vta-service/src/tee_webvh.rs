//! Persist the auto-generated serverless VTA did:webvh identity into the
//! `webvh` keyspace.
//!
//! In TEE mode [`vta_tee::did_autogen::maybe_generate_vta_did`] mints the VTA's
//! own did:webvh from the KMS-bootstrapped seed and stores the DID + did.jsonl
//! log under the `KEYS` / `BOOTSTRAP` keyspaces (`tee:vta_did`, `tee:did_log`).
//! It does *not* go through [`crate::operations::did_webvh`]'s create flow, so
//! the `webvh` keyspace — which `list_services`, the self-DID resolver preload
//! ([`crate::server`]'s `preload_self_did_document`) and
//! `/.well-known/did.jsonl` all read via [`crate::webvh_store`] — is left
//! empty. `GET /services` then 500s with `VtaDidRecordMissing` and the VTA's
//! own DID is unresolvable, so no client can authcrypt to it.
//!
//! This module bridges that gap: after auto-generation it idempotently
//! backfills the `webvh` keyspace with the DID *record* (`did:{did}`) and *log*
//! (`log:{did}`) so those read paths work on both fresh generation and restore,
//! without going through the full create flow (which would try to publish to a
//! hosting server the serverless VTA doesn't have).

use tracing::info;

use vta_sdk::webvh::WebvhDidRecord;
use vti_common::error::AppError;

use crate::store::{KeyspaceHandle, Store};
use crate::webvh_store;

/// The `KEYS`-keyspace key that `vta_tee::did_autogen` writes the encrypted
/// did.jsonl log under. Mirrored here (rather than imported) so this bridge
/// doesn't pull `vta-tee` into `vta-service`'s dependency graph.
const TEE_DID_LOG_STORE_KEY: &str = "tee:did_log";

/// Idempotently persist the serverless VTA did:webvh record + log into the
/// `webvh` keyspace.
///
/// No-op for non-`did:webvh` identities and whenever the records are already
/// present, so it is safe to call unconditionally on every boot after DID
/// auto-generation — a rebuild + reboot repairs an already-generated DID
/// without wiping state (which would rotate the DID).
pub async fn backfill_serverless_webvh_identity(
    store: &Store,
    storage_encryption_key: Option<[u8; 32]>,
    vta_did: &str,
) -> Result<(), AppError> {
    // Only serverless did:webvh identities live in the webvh keyspace.
    if !vta_did.starts_with("did:webvh:") {
        return Ok(());
    }

    let with_enc = |ks: KeyspaceHandle| match storage_encryption_key {
        Some(key) => ks.with_encryption(key),
        None => ks,
    };
    let webvh_ks = with_enc(store.keyspace(crate::keyspaces::WEBVH)?);

    let mut persisted = false;

    // Log (`log:{did}`): copy the did.jsonl the autogen wrote under the `KEYS`
    // keyspace. Read by the resolver preload, `list_services`, and well-known.
    if webvh_store::get_did_log(&webvh_ks, vta_did)
        .await?
        .is_none()
    {
        let keys_ks = with_enc(store.keyspace(crate::keyspaces::KEYS)?);
        if let Some(bytes) = keys_ks.get_raw(TEE_DID_LOG_STORE_KEY).await? {
            let log_content = String::from_utf8(bytes).map_err(|e| {
                AppError::Internal(format!("corrupt stored VTA did.jsonl log: {e}"))
            })?;
            webvh_store::store_did_log(&webvh_ks, vta_did, &log_content).await?;
            persisted = true;
        }
    }

    // Record (`did:{did}`): required by `list_services` and the did
    // update/rotate ops via `webvh_store::get_did`.
    if webvh_store::get_did(&webvh_ks, vta_did).await?.is_none() {
        let record = build_serverless_webvh_record(vta_did);
        webvh_store::store_did(&webvh_ks, &record).await?;
        persisted = true;
    }

    if persisted {
        store.persist().await?;
        info!(
            did = %vta_did,
            "backfilled serverless webvh DID record + log into the webvh keyspace"
        );
    }

    Ok(())
}

/// Build the [`WebvhDidRecord`] for the auto-generated serverless VTA DID.
///
/// Mirrors the production serverless builder in
/// `operations::did_webvh::create_did_webvh`: `create` mints `#key-0`
/// (signing) and `#key-1` (key-agreement) so the next `#key-{n}` fragment is
/// `2`, and TEE autogen commits exactly one pre-rotation key. Any drift is
/// self-healing — the next did update/rotate re-scans the log and persists the
/// corrected `log_entry_count` / `pre_rotation_count` / `next_fragment_id`.
fn build_serverless_webvh_record(did: &str) -> WebvhDidRecord {
    // did:webvh:{SCID}:{host}… — the SCID is the third colon-segment.
    let scid = did.split(':').nth(2).unwrap_or_default().to_string();
    let now = chrono::Utc::now();
    WebvhDidRecord {
        did: did.to_string(),
        server_id: "serverless".to_string(),
        mnemonic: String::new(),
        scid,
        context_id: "vta".to_string(),
        portable: true,
        log_entry_count: 1,
        pre_rotation_count: 1,
        next_fragment_id: 2,
        created_at: now,
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_scid_is_third_colon_segment() {
        let record = build_serverless_webvh_record("did:webvh:QmScidValue:example.com:vta");
        assert_eq!(record.scid, "QmScidValue");
        assert_eq!(record.did, "did:webvh:QmScidValue:example.com:vta");
        assert_eq!(record.server_id, "serverless");
        assert_eq!(record.next_fragment_id, 2);
        assert_eq!(record.pre_rotation_count, 1);
        assert_eq!(record.log_entry_count, 1);
        assert!(record.portable);
    }
}
