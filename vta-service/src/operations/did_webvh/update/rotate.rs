//! `rotate_did_webvh_keys` — convenience wrapper that mints fresh
//! verificationMethod keys for the current document, bumps the
//! record's `next_fragment_id` (under a CAS guard), then delegates to
//! [`super::update_did_webvh`].

use didwebvh_rs::log_entry::LogEntryMethods;
use serde_json::Value;

use super::errors::UpdateDidWebvhError;
use super::keys::derive_webvh_keys;
use super::options::{RotateDidWebvhKeysOptions, UpdateDidWebvhOptions, UpdateDidWebvhResult};
use super::orchestrator::update_did_webvh;
use super::state::{find_record_by_scid, state_from_jsonl};
use crate::auth::AuthClaims;
use crate::webvh_store;

/// Rotate every verificationMethod's keys (preserving role/type but
/// minting fresh public-key bytes + bumping fragment ids), then drive
/// the doc-bearing [`update_did_webvh`] path. Auth keys + pre-rotation
/// rotate as a consequence of the document update.
pub async fn rotate_did_webvh_keys(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    scid: &str,
    opts: RotateDidWebvhKeysOptions,
    vta_did: Option<&str>,
    channel: &str,
) -> Result<UpdateDidWebvhResult, UpdateDidWebvhError> {
    // 1. Load record + log.
    let mut record = find_record_by_scid(deps.webvh_ks, scid)
        .await?
        .ok_or_else(|| UpdateDidWebvhError::NotFound(format!("SCID {scid} not found")))?;
    auth.require_admin()
        .map_err(|e| UpdateDidWebvhError::Forbidden(format!("admin required: {e}")))?;
    auth.require_context(&record.context_id).map_err(|_| {
        UpdateDidWebvhError::Forbidden(format!(
            "caller has no admin role in context `{}`",
            record.context_id
        ))
    })?;

    let did_log = webvh_store::get_did_log(deps.webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did_log: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!("DID log missing for {}", record.did))
        })?;
    let state = state_from_jsonl(&did_log)?;
    let last = state.log_entries().last().ok_or_else(|| {
        UpdateDidWebvhError::Library(format!("DID {} has no log entries", record.did))
    })?;
    let current_doc = last.log_entry.get_did_document().map_err(|e| {
        UpdateDidWebvhError::Library(format!("extract document from last entry: {e}"))
    })?;

    // 2. Resolve context base path.
    let context = crate::contexts::get_context(deps.contexts_ks, &record.context_id)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_context: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!(
                "context `{}` referenced by DID is missing",
                record.context_id
            ))
        })?;

    // 3. Mint fresh keys for each VM in the current document.
    //    Preserve role/type/controller; mint new fragment ids monotonically
    //    from `record.next_fragment_id`. Resulting doc has the same
    //    semantic shape with new key bytes.
    let mut new_doc = current_doc.clone();
    let vms = new_doc
        .as_object_mut()
        .and_then(|o| o.get_mut("verificationMethod"))
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| {
            UpdateDidWebvhError::Library("current doc has no verificationMethod array".into())
        })?;

    let vm_count = vms.len() as u32;
    let derived_vms =
        derive_webvh_keys(deps.keys_ks, deps.seed_store, &context.base_path, vm_count).await?;
    let first_new_fragment_id = record.next_fragment_id;
    // Snapshot the version-vector fields so the next_fragment_id bump
    // (below) can detect a concurrent rotate that would have derived
    // overlapping `#key-N` fragment ids. Without this, two parallel
    // `rotate_did_webvh_keys` calls each derive
    // [next_fragment_id, next_fragment_id + N) keys; only one
    // store_did wins, but the loser has minted keys whose ids collide
    // with the winner's published document.
    let pre_rotate_snapshot = crate::operations::did_webvh::RecordSnapshot::capture(&record);

    // Track old fragment IDs for replacing references in
    // assertionMethod / authentication / keyAgreement arrays.
    let mut frag_remap: Vec<(String, String)> = Vec::with_capacity(vm_count as usize);
    for (i, (vm, derived_key)) in vms.iter_mut().zip(derived_vms.iter()).enumerate() {
        let old_id = vm
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                UpdateDidWebvhError::Library(format!("verificationMethod[{i}] missing id"))
            })?
            .to_string();
        let new_frag_id = record.next_fragment_id + i as u32;
        let new_id = format!("{}#key-{new_frag_id}", record.did);
        frag_remap.push((old_id, new_id.clone()));

        let obj = vm.as_object_mut().unwrap();
        obj.insert("id".into(), Value::String(new_id));
        obj.insert(
            "publicKeyMultibase".into(),
            Value::String(derived_key.public_key.clone()),
        );
    }

    // Update assertion / authentication / keyAgreement arrays to point
    // at the new VM ids. The original arrays are preserved positionally;
    // we just swap each entry's id with the new one assigned to the
    // VM at that position.
    for field in ["assertionMethod", "authentication", "keyAgreement"] {
        if let Some(arr) = new_doc
            .as_object_mut()
            .and_then(|o| o.get_mut(field))
            .and_then(|v| v.as_array_mut())
        {
            for entry in arr.iter_mut() {
                if let Some(s) = entry.as_str()
                    && let Some((_, new_id)) = frag_remap.iter().find(|(old, _)| old == s)
                {
                    *entry = Value::String(new_id.clone());
                }
            }
        }
    }

    // 4. Bump next_fragment_id on the record so subsequent rotates
    //    don't collide. CAS first: if a concurrent op already touched
    //    the record between snapshot and now, refuse rather than
    //    blindly clobbering — the in-flight derived keys would
    //    overlap the winner's already-issued fragment ids.
    let current = webvh_store::get_did(deps.webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did (rotate CAS): {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::NotFound(format!("DID {} disappeared mid-rotate", record.did))
        })?;
    pre_rotate_snapshot
        .assert_unchanged(&current)
        .map_err(|race| UpdateDidWebvhError::Conflict(race.to_string()))?;
    record.next_fragment_id += vm_count;
    webvh_store::store_did(deps.webvh_ks, &record)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("store_did (frag bump): {e}")))?;

    // 5. Drive the generic update path. The doc-bearing branch will
    //    rotate auth keys + pre-rotation as a side effect.
    let label = opts
        .label
        .or_else(|| Some(format!("rotate-keys for {}", record.did)));
    let result = update_did_webvh(
        deps,
        auth,
        scid,
        UpdateDidWebvhOptions {
            document: Some(new_doc),
            pre_rotation_count: opts.pre_rotation_count,
            witnesses: None,
            watchers: None,
            ttl: None,
            label,
            // rotate_did_webvh_keys composes update_did_webvh internally;
            // it doesn't expose the precondition (rotation is not a
            // user-edited document flow), so pass None.
            expected_version_id: None,
        },
        vta_did,
        channel,
    )
    .await?;

    tracing::info!(
        channel,
        did = %record.did,
        scid = %scid,
        first_fragment = first_new_fragment_id,
        last_fragment = record.next_fragment_id - 1,
        "did:webvh keys rotated"
    );

    Ok(result)
}
