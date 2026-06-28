//! End-to-end orchestration of [`update_did_webvh`].
//!
//! Stages: SCID lookup → auth gate → input validation → load chain →
//! optimistic-concurrency precondition → derive new keys → resolve
//! signing key (pre-rotation aware) → call `didwebvh_rs::update_did`
//! → CAS check → persist log + handles → publish to host → audit.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::multibase_type::Multibase;
use didwebvh_rs::update::{UpdateDIDConfig, update_did};

use super::errors::UpdateDidWebvhError;
use super::keys::{
    derive_secret_for_handle, derive_webvh_keys, install_derived_webvh_keys,
    load_active_update_key, load_pre_rotation_signing_key,
};
use super::options::{UpdateDidWebvhOptions, UpdateDidWebvhResult};
use super::state::{find_record_by_scid, state_from_jsonl, state_to_jsonl};
use super::validate::{validate_document_for_update, validate_watchers, validate_witnesses};
use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::did_webvh::concurrency::RecordSnapshot;
use crate::operations::did_webvh::webvh_keys::{self, WebvhKeyHandle, WebvhKeyRole};
use crate::webvh_store;

/// Drive a webvh DID update end-to-end. See module docs.
///
/// New parameters compared with the pre-PR-113 signature:
/// - `imported_ks` — needed by the daemon-REST auth flow (step 13)
///   to load the VTA's signing key via `get_key_secret_internal`.
/// - `vta_did` — the running VTA's DID (read from `AppConfig::
///   vta_did` at the call site). `None` means "no VTA identity
///   configured" — server-managed DID publishes will fail loudly
///   with `Publish("…")` rather than silently 401.
/// - `auth_locks` — per-server async mutex for serialising
///   auth-cache reads. Lives on `AppState`.
pub async fn update_did_webvh(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    scid: &str,
    opts: UpdateDidWebvhOptions,
    vta_did: Option<&str>,
    channel: &str,
) -> Result<UpdateDidWebvhResult, UpdateDidWebvhError> {
    // Re-bind the bundled deps to the historical local names so the (large) body
    // below is unchanged. All fields are `Copy` references — this copies the
    // borrows out of `*deps`; `deps` itself stays usable (the publish step below
    // forwards it to `publish_log_to_server`).
    let super::super::WebvhDeps {
        keys_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        seed_store,
        did_resolver,
        ..
    } = *deps;
    // 1. Resolve SCID → record. Snapshot the version-vector fields
    //    immediately. The snapshot is consulted just before the
    //    final store (step 11) to catch any concurrent record
    //    mutation — not just log_entry_count changes (which this
    //    op makes itself) but `server_id` / `updated_at` changes
    //    too, since a concurrent `register_did_with_server` flipping
    //    `server_id` from `serverless` → `webvh-prod` is a real
    //    race that the previous ad-hoc `log_entry_count` check
    //    silently missed.
    let mut record = find_record_by_scid(webvh_ks, scid)
        .await?
        .ok_or_else(|| UpdateDidWebvhError::NotFound(format!("SCID {scid} not found")))?;
    let initial_log_entry_count = record.log_entry_count;
    let snapshot = RecordSnapshot::capture(&record);

    // 2. Auth gate. Forbidden + NotFound both surface as 404 at the
    //    wire boundary — see `From<UpdateDidWebvhError> for AppError`.
    auth.require_admin()
        .map_err(|e| UpdateDidWebvhError::Forbidden(format!("admin required: {e}")))?;
    auth.require_context(&record.context_id).map_err(|_| {
        UpdateDidWebvhError::Forbidden(format!(
            "caller has no admin role in context `{}`",
            record.context_id
        ))
    })?;

    // 3. Validate caller-supplied inputs (cheap; do before key derivation).
    let new_doc = match opts.document {
        Some(doc) => Some(validate_document_for_update(doc, &record.did)?),
        None => None,
    };
    if let Some(ref w) = opts.witnesses {
        validate_witnesses(w, did_resolver).await?;
    }
    if let Some(ref watch) = opts.watchers {
        validate_watchers(watch)?;
    }

    // 4. Load DID log → DIDWebVHState; validate the chain.
    let did_log = webvh_store::get_did_log(webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did_log: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!("DID log missing for {}", record.did))
        })?;
    let state = state_from_jsonl(&did_log)?;
    let last_state = state.log_entries().last().ok_or_else(|| {
        UpdateDidWebvhError::Library(format!("DID {} has no log entries", record.did))
    })?;
    // Index for the new entry's backdated versionTime (count already in the chain).
    let new_entry_index = state.log_entries().len();

    // 4a. Optimistic-concurrency precondition. Check BEFORE key
    //     derivation / signing so a stale `get → edit → save` cycle
    //     fails fast and cheap, with a message the operator can act
    //     on. This catches the lost-update race the within-operation
    //     `log_entry_count` check at the end does NOT — that one only
    //     covers two server calls racing each other; this one covers
    //     a client call that was authored against a stale view.
    if let Some(expected) = opts.expected_version_id.as_deref() {
        let latest = last_state.get_version_id();
        if latest != expected {
            return Err(UpdateDidWebvhError::Conflict(format!(
                "DID {} has been updated since you read it (expected versionId `{expected}`, \
                 current is `{latest}`). Re-fetch the document and re-apply your edits.",
                record.did
            )));
        }
    }

    let last_params = last_state.validated_parameters.clone();
    let last_update_keys: Vec<Multibase> = last_params
        .update_keys
        .as_ref()
        .map(|arc| (**arc).clone())
        .unwrap_or_default();
    // Pre-rotation is "active" when the previous entry committed
    // `next_key_hashes`. The library's `check_signing_key` consults
    // `previous.next_key_hashes` (not `previous.update_keys`) for the
    // signing-key authorization check in that case, so the next entry
    // MUST be signed by a key whose hash was in that commitment.
    // See didwebvh-rs::lib::DIDWebVHState::check_signing_key.
    let last_next_key_hashes: Vec<String> = last_params
        .next_key_hashes
        .as_ref()
        .map(|arc| arc.iter().map(|m| m.as_ref().to_string()).collect())
        .unwrap_or_default();
    let pre_rotation_active = !last_next_key_hashes.is_empty();

    // 5. Resolve effective pre-rotation count.
    let pre_rotation_count = opts.pre_rotation_count.unwrap_or(record.pre_rotation_count);

    // 6. Resolve context base path for BIP-32 derivation.
    let context = crate::contexts::get_context(contexts_ks, &record.context_id)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_context: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!(
                "context `{}` referenced by DID is missing",
                record.context_id
            ))
        })?;

    // 7. Derive new keys (no persist yet — version_id unknown).
    //    With pre-rotation active, the "auth" key for the new entry is
    //    the *revealed* pre-rotation candidate from the previous entry,
    //    not a freshly-minted key. We pick that handle in step 8 below.
    let derived_auth = if new_doc.is_some() && !pre_rotation_active {
        derive_webvh_keys(keys_ks, seed_store, &context.base_path, 1).await?
    } else {
        vec![]
    };
    let derived_pre_rotation =
        derive_webvh_keys(keys_ks, seed_store, &context.base_path, pre_rotation_count).await?;

    // 8. Resolve the signing key.
    //
    //    With pre-rotation active, find a handle whose hash is in
    //    `last.next_key_hashes` — that's the only key webvh will accept
    //    as a signer for the next log entry. Without pre-rotation, fall
    //    back to the pre-existing `load_active_update_key` lookup over
    //    `last.update_keys`.
    tracing::info!(
        scid,
        did = %record.did,
        pre_rotation_active,
        next_key_hashes_count = last_next_key_hashes.len(),
        update_keys_count = last_update_keys.len(),
        "update_did_webvh: resolving signing key"
    );
    let signing_handle = if pre_rotation_active {
        load_pre_rotation_signing_key(keys_ks, scid, &last_next_key_hashes).await?
    } else {
        load_active_update_key(keys_ks, scid, &last_update_keys).await?
    };
    tracing::info!(
        scid,
        signing_pubkey = %signing_handle.public_key,
        signing_hash = %signing_handle.hash,
        signing_role = ?signing_handle.role,
        signing_version = %signing_handle.version_id,
        "update_did_webvh: signing key resolved"
    );
    let signing_secret = derive_secret_for_handle(keys_ks, seed_store, &signing_handle).await?;

    // 9. Build the library config.
    let mut builder = UpdateDIDConfig::<Secret, Secret>::builder_generic()
        .state(state)
        .signing_key(signing_secret)
        // Backdated, index-spaced timestamp so a back-to-back update doesn't
        // collide with the previous entry's second — see `backdated_version_time`.
        .version_time(super::super::backdated_version_time(new_entry_index));
    if let Some(doc) = new_doc {
        builder = builder.document(doc);
        let new_keys: Vec<Multibase> = if pre_rotation_active {
            // Reveal the pre-rotation key as the new update_keys entry.
            // `validate_pre_rotation_keys` requires every key in the new
            // update_keys to have its hash committed in
            // previous.next_key_hashes — `signing_handle.public_key`
            // satisfies that by construction (we picked it BY hash).
            vec![Multibase::from(signing_handle.public_key.clone())]
        } else {
            derived_auth
                .iter()
                .map(|k| Multibase::from(k.public_key.clone()))
                .collect()
        };
        builder = builder.update_keys(new_keys);
    } else if pre_rotation_active {
        // Metadata-only update under pre-rotation: still rotate
        // update_keys to the revealed pre-rotation pubkey so the chain's
        // active update-keys keep moving forward in lockstep with the
        // signing-key reveal. Otherwise the next entry's
        // `previous.next_key_hashes` carries an unused commitment while
        // the active key on record stays stale.
        builder = builder.update_keys(vec![Multibase::from(signing_handle.public_key.clone())]);
    }
    // Always pass next_key_hashes when caller toggled pre-rotation OR
    // when the DID currently uses pre-rotation — keeps the commitment
    // chain unbroken. Empty vec disables pre-rotation going forward.
    if opts.pre_rotation_count.is_some() || record.pre_rotation_count > 0 {
        let hashes: Vec<Multibase> = derived_pre_rotation
            .iter()
            .map(|k| Multibase::from(k.hash.clone()))
            .collect();
        builder = builder.next_key_hashes(hashes);
    }
    if let Some(w) = opts.witnesses.clone() {
        builder = builder.witness(w);
    }
    if let Some(watch) = opts.watchers.clone() {
        builder = builder.watchers(watch);
    }
    if let Some(t) = opts.ttl {
        builder = builder.ttl(t);
    }

    let cfg = builder
        .build()
        .map_err(|e| UpdateDidWebvhError::Library(format!("build update config: {e}")))?;

    // 10. Append the new log entry via the library.
    let result = update_did(cfg)
        .await
        .map_err(|e| UpdateDidWebvhError::Library(format!("update_did: {e}")))?;
    let new_log_entry = result.log_entry();
    let new_version_id = new_log_entry
        .get_version_id_fields()
        .map(|(n, h)| format!("{n}-{h}"))
        .map_err(|e| UpdateDidWebvhError::Library(format!("read version id: {e}")))?;
    let new_scid = new_log_entry.get_scid().unwrap_or_default().to_string();
    let new_log_entry_str = serde_json::to_string(new_log_entry)
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("serialize new entry: {e}")))?;

    // 11. Optimistic concurrency check before persisting. Uses the
    //     shared `RecordSnapshot` machinery so we catch *every* kind
    //     of concurrent mutation (log_entry_count, updated_at, AND
    //     server_id) rather than just log_entry_count growth. The
    //     server_id case is the one the ad-hoc check missed:
    //     `register_did_with_server` flipping `server_id` from
    //     `serverless` → `webvh-prod` between step 1 and here used
    //     to slip past unchallenged, then step 12 would clobber the
    //     newer record with our stale `serverless` value.
    let current = webvh_store::get_did(webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::NotFound(format!("DID {} disappeared mid-update", record.did))
        })?;
    snapshot
        .assert_unchanged(&current)
        .map_err(|race| UpdateDidWebvhError::Conflict(race.to_string()))?;

    // 12. Persist new log + new key handles + updated record.
    let new_log_jsonl = state_to_jsonl(result.state())?;
    webvh_store::store_did_log(webvh_ks, &record.did, &new_log_jsonl)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("store_did_log: {e}")))?;

    if !derived_auth.is_empty() {
        install_derived_webvh_keys(
            keys_ks,
            scid,
            &new_version_id,
            WebvhKeyRole::UpdateKey,
            &derived_auth,
            "update key",
        )
        .await?;
    }
    if !derived_pre_rotation.is_empty() {
        install_derived_webvh_keys(
            keys_ks,
            scid,
            &new_version_id,
            WebvhKeyRole::PreRotation,
            &derived_pre_rotation,
            "pre-rotation key",
        )
        .await?;
    }
    // When we reveal a pre-rotation key, re-install it as an
    // `UpdateKey` handle under the new version_id. Without this, the
    // supersede step (below) moves the previous version's PreRotation
    // handle out of the active prefix, and the next update can't
    // resolve the now-active key by hash via the fast path. The handle
    // contents are otherwise identical to the previous PreRotation
    // entry — same derivation path, same secret.
    if pre_rotation_active {
        let revealed = WebvhKeyHandle {
            scid: scid.to_string(),
            version_id: new_version_id.clone(),
            hash: signing_handle.hash.clone(),
            public_key: signing_handle.public_key.clone(),
            derivation_path: signing_handle.derivation_path.clone(),
            seed_id: signing_handle.seed_id,
            role: WebvhKeyRole::UpdateKey,
            label: format!(
                "revealed pre-rotation key (was version {})",
                signing_handle.version_id
            ),
            created_at: Utc::now(),
        };
        webvh_keys::install(keys_ks, &revealed)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("install revealed key: {e}")))?;
    }

    // Supersede the previous version's keys (best-effort — handles that
    // never made it into webvh_keys, e.g. legacy DIDs, are silently
    // skipped by the prefix scan).
    if let Some(prev) = result
        .state()
        .log_entries()
        .iter()
        .rev()
        .nth(1)
        .map(|e| {
            e.log_entry
                .get_version_id_fields()
                .map(|(n, h)| format!("{n}-{h}"))
        })
        .transpose()
        .unwrap_or(None)
    {
        webvh_keys::supersede_keys_for_version(keys_ks, scid, &prev)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("supersede: {e}")))?;
    }

    record.log_entry_count += 1;
    record.pre_rotation_count = derived_pre_rotation.len() as u32;
    record.updated_at = Utc::now();
    webvh_store::store_did(webvh_ks, &record)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("store_did: {e}")))?;

    // 13. Publish the new log to the hosting server for non-serverless
    //     DIDs. Uses the auth-cache orchestration helper which:
    //       - loads the VTA's signing identity for the daemon REST
    //         auth handshake (no-op for DIDComm transport),
    //       - reads `server-auth:{id}` under the per-server async
    //         mutex; refreshes or re-authenticates if stale,
    //       - publishes with one-shot 401 retry (token revoked
    //         mid-window).
    //
    //     Local state is already committed, so a publish failure
    //     surfaces as `Publish` (HTTP 500) but doesn't undo the
    //     local update; operators can retry the publish out-of-band
    //     by re-issuing the same update.
    if record.server_id != "serverless" {
        let server = webvh_store::get_server(webvh_ks, &record.server_id)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_server: {e}")))?
            .ok_or_else(|| {
                UpdateDidWebvhError::Publish(format!(
                    "webvh server `{}` referenced by DID is missing",
                    record.server_id
                ))
            })?;
        let vta_did = vta_did.ok_or_else(|| {
            UpdateDidWebvhError::Publish(
                "VTA DID is not configured — cannot authenticate to webvh hosting server. \
                 Complete `vta setup` before publishing to a server-managed DID."
                    .to_string(),
            )
        })?;
        super::super::publish_log_to_server(
            deps,
            vta_did,
            &server,
            &record.mnemonic,
            &new_log_jsonl,
            // Update paths follow the slot's existing domain — the
            // remote already records it on the slot. Passing None
            // lets the remote use the recorded value; a host that
            // does per-domain mnemonic namespacing would resolve via
            // the slot lookup.
            None,
        )
        .await
        .map_err(|e| UpdateDidWebvhError::Publish(format!("publish_did: {e}")))?;
    }

    // 14. Audit emission. Best-effort — a missing audit row should
    //     not undo a successful update, so we log+swallow on error.
    let resource = format!(
        "did:webvh:{scid} v{} → v{}",
        initial_log_entry_count, record.log_entry_count
    );
    let label = opts.label.as_deref().unwrap_or("update");
    if let Err(e) = audit::record(
        audit_ks,
        &format!("did.update:{label}"),
        &auth.did,
        Some(&resource),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await
    {
        tracing::warn!(
            channel,
            did = %record.did,
            error = %e,
            "did.update audit emission failed; update committed"
        );
    }

    tracing::info!(
        channel,
        did = %record.did,
        scid = %scid,
        new_version_id = %new_version_id,
        label = ?opts.label,
        "did:webvh updated"
    );

    let update_keys_count = if !derived_auth.is_empty() {
        derived_auth.len() as u32
    } else if pre_rotation_active {
        // Reveal-only path: we set update_keys = [revealed_pubkey].
        1
    } else {
        last_update_keys.len() as u32
    };

    Ok(UpdateDidWebvhResult {
        did: record.did.clone(),
        new_version_id,
        new_scid,
        new_log_entry: new_log_entry_str,
        update_keys_count,
        pre_rotation_key_count: derived_pre_rotation.len() as u32,
        // Surface so route + DIDComm response shapes can emit the
        // "fetch did.jsonl + redeploy" hint to operators. The
        // string-equality check matches the same sentinel
        // (`SERVERLESS_MARKER`) that `register_did_with_server`
        // gates on and that step 13 above used to decide whether
        // to call the host transport.
        serverless: record.server_id == "serverless",
    })
}
