//! Shared helper: strip every passkey verificationMethod from every
//! DID this VTA controls, publishing a WebVH update per affected DID.
//!
//! Invoked by [`super::disable_webauthn`] because the operator chose
//! hard-disable semantics: when the WebAuthn-RP surface is turned
//! off, any passkey VMs that depend on it must come off too so they
//! aren't left advertising authentication against an unreachable RP.
//!
//! ## Identification
//!
//! A "passkey VM" is detected by the presence of the
//! `webauthnCredentialId` field on the verificationMethod entry.
//! That field is unique to the
//! [`vta_sdk::protocols::did_management::passkey_vms::PasskeyVerificationMethod`]
//! shape; non-passkey Multikey entries don't carry it.
//!
//! ## Best-effort, idempotent
//!
//! The cleanup iterates DIDs in the webvh keyspace. Per-DID failures
//! (publish failed, DID record not found, etc.) are logged at
//! `warn!` and counted but don't abort the sweep. The caller gets a
//! summary so it can surface to the operator. Re-running disable is
//! idempotent because removing already-absent VMs is a no-op.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use tokio::sync::RwLock;
use tracing::{info, warn};

use vti_common::seed_store::SeedStore;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::{UpdateDidWebvhOptions, update_did_webvh};
use crate::store::KeyspaceHandle;
use crate::webvh_store;

/// Per-DID outcome the sweep returns to the caller.
#[derive(Debug, Clone)]
pub struct DidCleanupOutcome {
    pub did: String,
    pub removed_vm_count: usize,
    /// `None` on success. `Some(reason)` when the per-DID update
    /// failed — the operator surfaces this so they can investigate.
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct CleanupSummary {
    /// DIDs the sweeper looked at (had at least one passkey VM).
    pub touched: Vec<DidCleanupOutcome>,
    /// Number of DIDs whose update succeeded.
    pub succeeded: usize,
    /// Number of DIDs whose update failed.
    pub failed: usize,
}

/// Iterate every DID in `webvh_ks`, find any passkey VMs on their
/// current document, and publish a WebVH update that removes them.
///
/// Returns a per-DID outcome list. The caller is responsible for
/// surfacing failures to the operator; this function never returns
/// `Err` for per-DID failures (the sweep continues), only for
/// total-failure conditions like the keyspace itself being
/// unreadable.
#[allow(clippy::too_many_arguments)]
pub async fn strip_all_passkey_vms(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    auth: &AuthClaims,
    webvh_auth_locks: &crate::operations::did_webvh::WebvhAuthLocks,
    channel: &str,
) -> Result<CleanupSummary, AppError> {
    let dids = webvh_store::list_dids(webvh_ks).await?;
    let mut summary = CleanupSummary::default();

    for record in dids {
        // Read the most recent DID document state.
        let Some(did_log) = webvh_store::get_did_log(webvh_ks, &record.did).await? else {
            // No log on disk — DID is known but not yet published.
            // Nothing to strip; skip.
            continue;
        };
        let current_doc = match super::document::current_document_from_log(&did_log) {
            Ok(doc) => doc,
            Err(e) => {
                warn!(
                    did = %record.did,
                    error = %e,
                    "passkey-vm cleanup: failed to parse current document; skipping",
                );
                summary.failed += 1;
                summary.touched.push(DidCleanupOutcome {
                    did: record.did,
                    removed_vm_count: 0,
                    error: Some(format!("parse current doc: {e}")),
                });
                continue;
            }
        };

        // Find passkey VMs and build a patched document with them
        // removed. If there are none, skip — no LogEntry needed.
        let (patched_doc, removed_count) = strip_passkey_vms_from_doc(current_doc);
        if removed_count == 0 {
            continue;
        }

        // Publish the patched document.
        let scid = &record.scid;
        let vta_did = {
            let cfg = config.read().await;
            cfg.vta_did.clone()
        };
        let deps = crate::operations::did_webvh::WebvhDeps {
            keys_ks,
            imported_ks,
            contexts_ks,
            webvh_ks,
            audit_ks,
            seed_store,
            did_resolver,
            didcomm_bridge,
            auth_locks: webvh_auth_locks,
        };
        let result = update_did_webvh(
            &deps,
            auth,
            scid,
            UpdateDidWebvhOptions {
                document: Some(patched_doc),
                ..Default::default()
            },
            vta_did.as_deref(),
            channel,
        )
        .await;

        match result {
            Ok(_) => {
                summary.succeeded += 1;
                info!(
                    did = %record.did,
                    removed = removed_count,
                    "passkey-vm cleanup: removed VMs",
                );
                summary.touched.push(DidCleanupOutcome {
                    did: record.did,
                    removed_vm_count: removed_count,
                    error: None,
                });
            }
            Err(e) => {
                summary.failed += 1;
                warn!(
                    did = %record.did,
                    removed = removed_count,
                    error = %e,
                    "passkey-vm cleanup: WebVH update failed; operator should retry",
                );
                summary.touched.push(DidCleanupOutcome {
                    did: record.did,
                    removed_vm_count: removed_count,
                    error: Some(format!("WebVH update: {e}")),
                });
            }
        }
    }

    Ok(summary)
}

/// Pure helper: take a DID document, return a copy with every
/// passkey VM stripped and a count of how many were removed.
///
/// Identifies passkey VMs by presence of `webauthnCredentialId`
/// on the entry. Also removes references to those VM ids from
/// `authentication`, `assertionMethod`, `keyAgreement`,
/// `capabilityInvocation`, `capabilityDelegation`.
pub fn strip_passkey_vms_from_doc(mut doc: JsonValue) -> (JsonValue, usize) {
    let Some(obj) = doc.as_object_mut() else {
        return (doc, 0);
    };

    let mut removed_ids: Vec<String> = Vec::new();

    // First pass: identify passkey VMs in `verificationMethod`.
    if let Some(vms) = obj
        .get_mut("verificationMethod")
        .and_then(JsonValue::as_array_mut)
    {
        vms.retain(|vm| {
            let is_passkey = vm.get("webauthnCredentialId").is_some();
            if is_passkey {
                if let Some(id) = vm.get("id").and_then(JsonValue::as_str) {
                    removed_ids.push(id.to_string());
                }
                false // drop
            } else {
                true // keep
            }
        });
    }

    if removed_ids.is_empty() {
        return (doc, 0);
    }

    // Second pass: scrub the removed-VM ids from every verification
    // relation array that may reference them.
    for relation in &[
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        if let Some(arr) = obj.get_mut(*relation).and_then(JsonValue::as_array_mut) {
            arr.retain(|entry| {
                let entry_id = match entry {
                    JsonValue::String(s) => s.as_str(),
                    JsonValue::Object(inner) => {
                        inner.get("id").and_then(JsonValue::as_str).unwrap_or("")
                    }
                    _ => "",
                };
                !removed_ids.iter().any(|rid| rid == entry_id)
            });
        }
    }

    let count = removed_ids.len();
    (doc, count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc_with(passkey_count: usize, other_vm_count: usize) -> JsonValue {
        let mut vms = Vec::new();
        for i in 0..passkey_count {
            vms.push(json!({
                "id": format!("did:webvh:test#passkey-{i}"),
                "type": "Multikey",
                "controller": "did:webvh:test",
                "publicKeyMultibase": format!("z{i}"),
                "webauthnCredentialId": format!("cred-{i}"),
            }));
        }
        for i in 0..other_vm_count {
            vms.push(json!({
                "id": format!("did:webvh:test#key-{i}"),
                "type": "Multikey",
                "controller": "did:webvh:test",
                "publicKeyMultibase": format!("z-other-{i}"),
            }));
        }
        json!({
            "id": "did:webvh:test",
            "verificationMethod": vms,
            "authentication": [
                "did:webvh:test#passkey-0",
                "did:webvh:test#key-0",
            ],
            "assertionMethod": [
                "did:webvh:test#passkey-1",
            ],
        })
    }

    #[test]
    fn strip_removes_passkey_vms_and_scrubs_relations() {
        let doc = doc_with(2, 2);
        let (patched, count) = strip_passkey_vms_from_doc(doc);
        assert_eq!(count, 2);

        let vms = patched
            .get("verificationMethod")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(vms.len(), 2);
        for vm in vms {
            assert!(vm.get("webauthnCredentialId").is_none());
            let id = vm.get("id").unwrap().as_str().unwrap();
            assert!(id.contains("#key-"));
        }

        let auth = patched.get("authentication").unwrap().as_array().unwrap();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].as_str().unwrap(), "did:webvh:test#key-0");

        let am = patched.get("assertionMethod").unwrap().as_array().unwrap();
        assert!(am.is_empty(), "passkey-1 was removed from assertionMethod");
    }

    #[test]
    fn strip_is_no_op_when_no_passkey_vms() {
        let doc = doc_with(0, 3);
        let (patched, count) = strip_passkey_vms_from_doc(doc.clone());
        assert_eq!(count, 0);
        assert_eq!(patched, doc, "byte-equivalent when no passkey VMs present");
    }

    #[test]
    fn strip_handles_doc_with_no_verification_method() {
        let doc = json!({ "id": "did:webvh:test" });
        let (patched, count) = strip_passkey_vms_from_doc(doc.clone());
        assert_eq!(count, 0);
        assert_eq!(patched, doc);
    }

    #[test]
    fn strip_handles_object_form_in_relation_arrays() {
        // Some implementations inline the VM object in the relation
        // array instead of referencing by id. Both forms should be
        // scrubbed when the inlined VM is a passkey.
        let doc = json!({
            "id": "did:webvh:test",
            "verificationMethod": [
                {
                    "id": "did:webvh:test#passkey-0",
                    "type": "Multikey",
                    "controller": "did:webvh:test",
                    "publicKeyMultibase": "z0",
                    "webauthnCredentialId": "cred-0",
                }
            ],
            "authentication": [
                { "id": "did:webvh:test#passkey-0", "type": "Multikey" },
                "did:webvh:test#some-other-key",
            ],
        });
        let (patched, count) = strip_passkey_vms_from_doc(doc);
        assert_eq!(count, 1);
        let auth = patched.get("authentication").unwrap().as_array().unwrap();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].as_str().unwrap(), "did:webvh:test#some-other-key");
    }
}
