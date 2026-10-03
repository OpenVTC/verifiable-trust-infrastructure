//! The node-neutral `backup/*` family on the community node (#1641).
//!
//! `vtc/backup/import/0.1` carries the whole encrypted envelope in one document,
//! which cannot fit the 64 KiB this door accepts before it has checked a proof.
//! A community's backup is imported instead as a **bundle**: the producer
//! commits to a manifest (`initiate-import`), sends the bytes chunk by chunk
//! (`put-chunk`), and `finalize-import` checks the assembled bytes against what
//! was committed before the password is used. Export is the mirror image
//! (`initiate-export`, `get-chunk`, `complete-export`), and `abort` cancels
//! either. trustoverip/dtgwg-trust-tasks-tf#633 specifies the family; the
//! transfer itself — staging, manifest, chunk checks, sweeper — is
//! [`vti_common::backup_transfer`], the same code the agent runs.
//!
//! What is the community's own is what a bundle holds: `initiate-export`
//! serializes and encrypts the community's state exactly as
//! `vtc/backup/export` does ([`crate::routes::backup::export_inner`]), and
//! `finalize-import` applies it exactly as `vtc/backup/import` does
//! ([`crate::routes::backup::import_inner`]).
//!
//! # Only `chunkedTrustTask`
//!
//! The `stream` algorithm needs an HTTPS endpoint serving the bytes, which this
//! node does not publish. Asked for `stream` — or for nothing, which means
//! `stream` — it refuses `transportUnavailable`, as the specification requires
//! of a recipient that recognises the algorithm but cannot serve it.
//!
//! # Chunk size
//!
//! A `put-chunk` document carries its chunk base64url-encoded, and this door
//! refuses a body over its type's limit — the default,
//! [`super::size::DEFAULT_MAX_DOCUMENT_BYTES`], since `put-chunk` declares no
//! other — before parsing it. [`MAX_CHUNK_SIZE`] is the largest chunk whose document fits with room
//! for the envelope and proof; an import manifest with larger chunks is refused
//! `chunkSizeUnacceptable`, and an export never uses larger ones. At 32 KiB and
//! the family's 4096-chunk bound, a bundle may be up to 128 MiB.
//!
//! # Authority
//!
//! Every verb is an unrestricted administrator's, read from the signer's ACL
//! row ([`super::admin_signer`]), as `vtc/backup/{export,import}` are — and a
//! bundle belongs to whoever opened it: another administrator's handle is
//! `notFound`.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use trust_tasks_rs::specs::backup::{
    abort::v0_1 as abort, complete_export::v0_1 as complete_export,
    finalize_import::v0_1 as finalize_import, get_chunk::v0_1 as get_chunk,
    initiate_export::v0_1 as initiate_export, initiate_import::v0_1 as initiate_import,
    put_chunk::v0_1 as put_chunk,
};
use trust_tasks_rs::{RejectReason, TrustTask, TrustTaskCode};
use vta_sdk::protocols::backup_management::chunked::ALGORITHM_CHUNKED;
use vti_common::backup_transfer::chunked::{self, ChunkRateLimiter, ChunkWrite, ChunkedError};
use vti_common::error::AppError;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, reject_with, reject_with_code, success_response,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::error::TaskError;
use crate::server::AppState;

/// The largest chunk this node sends or accepts, in bytes. See the module docs:
/// a `put-chunk` document must fit its type's limit once its
/// chunk is base64url-encoded (×4/3) and wrapped in an envelope and a proof.
pub(crate) const MAX_CHUNK_SIZE: u64 = 32 * 1024;

/// Where staged bundle bytes live: `<data_dir>/backups`, owner-only.
pub(crate) fn blob_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("backups")
}

async fn staging_dir(state: &AppState) -> PathBuf {
    blob_dir(&state.config.read().await.store.data_dir)
}

/// `backup/initiate-export/0.1`.
pub(crate) const INITIATE_EXPORT_TYPE: &str =
    <initiate_export::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `backup/get-chunk/0.1`.
pub(crate) const GET_CHUNK_TYPE: &str = <get_chunk::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `backup/complete-export/0.1`.
pub(crate) const COMPLETE_EXPORT_TYPE: &str =
    <complete_export::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `backup/initiate-import/0.1`.
pub(crate) const INITIATE_IMPORT_TYPE: &str =
    <initiate_import::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `backup/put-chunk/0.1`.
pub(crate) const PUT_CHUNK_TYPE: &str = <put_chunk::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `backup/finalize-import/0.1`.
pub(crate) const FINALIZE_IMPORT_TYPE: &str =
    <finalize_import::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `backup/abort/0.1`.
pub(crate) const ABORT_TYPE: &str = <abort::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Every `backup/*` URI this node serves.
pub(crate) const URIS: &[&str] = &[
    INITIATE_EXPORT_TYPE,
    GET_CHUNK_TYPE,
    COMPLETE_EXPORT_TYPE,
    INITIATE_IMPORT_TYPE,
    PUT_CHUNK_TYPE,
    FINALIZE_IMPORT_TYPE,
    ABORT_TYPE,
];

/// Route one `backup/*` document. `None` when `type_uri` is not one of
/// [`URIS`].
pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    let handler = match type_uri {
        INITIATE_EXPORT_TYPE => Op::InitiateExport,
        GET_CHUNK_TYPE => Op::GetChunk,
        COMPLETE_EXPORT_TYPE => Op::CompleteExport,
        INITIATE_IMPORT_TYPE => Op::InitiateImport,
        PUT_CHUNK_TYPE => Op::PutChunk,
        FINALIZE_IMPORT_TYPE => Op::FinalizeImport,
        ABORT_TYPE => Op::Abort,
        _ => return None,
    };
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return Some(reject),
    };
    // Export is `vtc.backup.export`; import replaces the ACL and is
    // `vtc.backup.restore` (vtc-admin-roles.md §4). `abort` cancels a bundle
    // of either kind, so either suffices — and a bundle belongs to whoever
    // opened it. Checked before the payload, so a refusal is the same
    // whatever the payload says.
    {
        use crate::acl::Capability::{BackupExport, BackupRestore};
        let entry = match crate::acl::get_acl_entry(&state.acl_ks, &actor.did).await {
            Ok(e) => e,
            Err(e) => return Some(app_error_to_reject(&doc, &e)),
        };
        let can = |c| entry.as_ref().is_some_and(|e| e.can(c, None));
        let (allowed, needed) = match handler {
            Op::InitiateExport | Op::GetChunk | Op::CompleteExport => {
                (can(BackupExport), BackupExport)
            }
            Op::InitiateImport | Op::PutChunk | Op::FinalizeImport => {
                (can(BackupRestore), BackupRestore)
            }
            Op::Abort => (can(BackupExport) || can(BackupRestore), BackupExport),
        };
        if !allowed {
            return Some(app_error_to_reject(
                &doc,
                &crate::acl::capability_refusal(&actor.did, needed, None),
            ));
        }
    }
    // The verbs that carry the password, or open the bundle it unlocks, are
    // served only end to end. The chunks are ciphertext.
    let channel_bound = match handler {
        Op::InitiateExport => Some("export"),
        Op::InitiateImport | Op::FinalizeImport => Some("import"),
        _ => None,
    };
    if let Some(what) = channel_bound
        && let Err(reject) = super::refuse_hop_by_hop_backup(ctx, &doc, what)
    {
        return Some(reject);
    }
    Some(match handler {
        Op::InitiateExport => handle_initiate_export(state, &actor, doc).await,
        Op::GetChunk => handle_get_chunk(state, &actor, doc).await,
        Op::CompleteExport => handle_complete_export(state, &actor, doc).await,
        Op::InitiateImport => handle_initiate_import(state, &actor, doc).await,
        Op::PutChunk => handle_put_chunk(state, &actor, doc).await,
        Op::FinalizeImport => handle_finalize_import(state, &actor, doc).await,
        Op::Abort => handle_abort(state, &actor, doc).await,
    })
}

enum Op {
    InitiateExport,
    GetChunk,
    CompleteExport,
    InitiateImport,
    PutChunk,
    FinalizeImport,
    Abort,
}

type Actor = vti_common::auth::extractor::AuthClaims;

// ─── Export ──────────────────────────────────────────────────────────────

async fn handle_initiate_export(
    state: &AppState,
    actor: &Actor,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: initiate_export::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    if let Some(refusal) = refuse_algorithm(&doc, req.algorithm.as_ref().map(|a| a.as_str())) {
        return refusal;
    }
    if let Err(e) = chunked::check_initiate(&state.backup_bundles_ks, actor).await {
        return initiate_reject(&doc, e);
    }
    // The same export `vtc/backup/export` produces — and audits, as
    // `BackupExported`, naming this administrator.
    let exported = match crate::routes::backup::export_inner(
        state,
        &actor.did,
        req.password.as_str(),
        req.include_audit.unwrap_or(false),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return task_error_reject(&doc, e),
    };
    let bytes = match serde_json::to_vec(&exported.envelope) {
        Ok(b) => b,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                &AppError::Internal(format!("serialize backup envelope: {e}")),
            );
        }
    };
    let chunk_size = req
        .max_chunk_size
        .map(|s| s.0.max(0) as u64)
        .unwrap_or(MAX_CHUNK_SIZE)
        .min(MAX_CHUNK_SIZE);
    let bundle = match chunked::stage_export(
        &state.backup_bundles_ks,
        &staging_dir(state).await,
        &actor.did,
        &bytes,
        Some(chunk_size),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return chunked_reject(&doc, e),
    };
    respond::<initiate_export::Response>(
        &doc,
        json!({
            "descriptor": manifest_json(&bundle),
            "completionHint": format!(
                "Send get-chunk for indices 0 to {}, verify each, then send complete-export.",
                bundle.chunk_count - 1
            ),
        }),
    )
}

async fn handle_get_chunk(
    state: &AppState,
    actor: &Actor,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: get_chunk::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let served = match chunked::get_chunk(
        &state.backup_bundles_ks,
        ChunkRateLimiter::global(),
        actor,
        req.bundle_id.as_str(),
        req.index.0.max(0) as u64,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return chunked_reject(&doc, e),
    };
    use base64::Engine as _;
    respond::<get_chunk::Response>(
        &doc,
        json!({
            "bundleId": served.bundle_id.to_string(),
            "index": served.index,
            "digestMultibase": served.digest_multibase,
            "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&served.data),
            "expiresAt": served.expires_at,
        }),
    )
}

async fn handle_complete_export(
    state: &AppState,
    actor: &Actor,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: complete_export::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    match chunked::complete_export(&state.backup_bundles_ks, actor, req.bundle_id.as_str()).await {
        Ok(downloaded) => respond::<complete_export::Response>(
            &doc,
            json!({ "bundleId": req.bundle_id.as_str(), "downloaded": downloaded }),
        ),
        Err(e) => chunked_reject(&doc, e),
    }
}

// ─── Import ──────────────────────────────────────────────────────────────

async fn handle_initiate_import(
    state: &AppState,
    actor: &Actor,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: initiate_import::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    if let Some(refusal) = refuse_algorithm(&doc, req.algorithm.as_ref().map(|a| a.as_str())) {
        return refusal;
    }
    let Some(manifest) = req.chunks else {
        return chunked_reject(
            &doc,
            ChunkedError::InvalidManifest(
                "algorithm chunkedTrustTask requires a `chunks` manifest".into(),
            ),
        );
    };
    let chunk_size = manifest.chunk_size.0.max(0) as u64;
    if chunk_size > MAX_CHUNK_SIZE {
        return refuse(
            &doc,
            "chunkSizeUnacceptable",
            format!(
                "this node accepts chunks of at most {MAX_CHUNK_SIZE} bytes — a larger \
                 put-chunk document does not fit what it accepts before checking a proof"
            ),
            Some(json!({ "maxChunkSize": MAX_CHUNK_SIZE })),
        );
    }
    let slot = match chunked::initiate_import(
        &state.backup_bundles_ks,
        actor,
        req.expected_sha256.as_str(),
        req.expected_size_bytes.0.get(),
        chunk_size,
        manifest.chunk_count.0.get(),
        manifest
            .chunk_digests
            .iter()
            .map(|d| d.as_str().to_string())
            .collect(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return initiate_reject(&doc, e),
    };
    respond::<initiate_import::Response>(
        &doc,
        json!({
            "descriptor": manifest_json(&slot),
            "completionHint": format!(
                "Send put-chunk for indices 0 to {}, then send finalize-import.",
                slot.chunk_count - 1
            ),
        }),
    )
}

async fn handle_put_chunk(
    state: &AppState,
    actor: &Actor,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: put_chunk::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    use base64::Engine as _;
    let data = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(req.data.as_str()) {
        Ok(d) => d,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("`data` is not base64url: {e}"),
                },
            );
        }
    };
    let index = req.index.0.max(0) as u64;
    let outcome = match chunked::put_chunk(
        &state.backup_bundles_ks,
        &staging_dir(state).await,
        ChunkRateLimiter::global(),
        actor,
        ChunkWrite {
            bundle_id: req.bundle_id.as_str(),
            index,
            digest_multibase: req.digest_multibase.as_str(),
            data: &data,
        },
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return chunked_reject(&doc, e),
    };
    respond::<put_chunk::Response>(
        &doc,
        json!({
            "bundleId": req.bundle_id.as_str(),
            "index": index,
            "stored": outcome.stored,
            "remainingCount": outcome.remaining_count,
            "expiresAt": outcome.expires_at,
        }),
    )
}

async fn handle_finalize_import(
    state: &AppState,
    actor: &Actor,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use vti_common::backup_transfer::bundle_store::{self, BundleKind, BundleState};

    let req: finalize_import::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    // Every chunk present, and the assembled bytes the committed ones — before
    // the password is used, and before anything is decrypted.
    if let Err(e) =
        chunked::finalize_precheck(&state.backup_bundles_ks, actor, req.bundle_id.as_str()).await
    {
        return chunked_reject(&doc, e);
    }
    let id = match vti_common::backup_transfer::parse_bundle_id(req.bundle_id.as_str()) {
        Ok(i) => i,
        Err(_) => return chunked_reject(&doc, ChunkedError::NotFound),
    };
    let mut record =
        match vti_common::backup_transfer::require_owned(&state.backup_bundles_ks, &id, &actor.did)
            .await
        {
            Ok(r) => r,
            Err(e) => return chunked_reject(&doc, e.into()),
        };
    if let Err(e) = vti_common::backup_transfer::enforce_kind(&record, BundleKind::Import) {
        return chunked_reject(&doc, e.into());
    }
    match record.state {
        BundleState::ImportReceived | BundleState::ImportPreviewed => {}
        BundleState::ImportCommitted => {
            return chunked_reject(&doc, ChunkedError::TerminalState("committed".into()));
        }
        _ => return chunked_reject(&doc, ChunkedError::TerminalState("expired".into())),
    }
    let Some(path) = record.blob_path.clone() else {
        return chunked_reject(&doc, ChunkedError::TerminalState("expired".into()));
    };
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &AppError::Io(e)),
    };
    let envelope: crate::backup::BackupEnvelope = match serde_json::from_slice(&bytes) {
        Ok(e) => e,
        Err(e) => {
            return refuse(
                &doc,
                "malformedBundle",
                format!("the assembled bytes are not a community backup: {e}"),
                None,
            );
        }
    };

    let confirm = req.confirm.unwrap_or(false);
    let mut waived = false;
    if confirm {
        match restore_consent(state, actor, &doc, &envelope, req.password.as_str(), &id).await {
            Ok(w) => waived = w,
            Err(RestoreGate::Refused(reject)) => return reject,
            Err(RestoreGate::Parked(e, expires_at)) => {
                // The staged bytes must outlive the approval they wait for:
                // the bundle's own expiry is a five-minute conversation.
                if let Some(at) = expires_at
                    && at > record.expires_at
                {
                    record.expires_at = at;
                    record.state = BundleState::ImportPreviewed;
                    if let Err(e) =
                        bundle_store::store_bundle(&state.backup_bundles_ks, &record).await
                    {
                        return app_error_to_reject(&doc, &e);
                    }
                }
                return app_error_to_reject(&doc, &e);
            }
        }
    }
    let result = match crate::routes::backup::import_inner(
        state,
        &actor.did,
        &envelope,
        req.password.as_str(),
        confirm,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return task_error_reject(&doc, e),
    };

    // A preview leaves the bundle open so the producer can commit it; a commit
    // ends it and its bytes.
    if confirm {
        // An approved action executing this restore: its effect has landed.
        crate::admin_actions::record_effect(state).await;
        // The restore replaced the audit log, the waiver's `Critical` row
        // (written before the commit, so an unauditable waiver is refused)
        // with it: record it again in the log the community now has
        // (VTI-APV-022 item 4).
        if waived && let Err(e) = rerecord_waiver(state, actor, &doc).await {
            return app_error_to_reject(&doc, &e);
        }
        if let Err(e) = tokio::fs::remove_file(&path).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(bundle_id = %id, error = %e, "finalize-import: staged bytes not deleted; sweeper will retry");
        } else {
            record.blob_path = None;
        }
        record.state = BundleState::ImportCommitted;
        let _ = chunked::delete_plan(&state.backup_bundles_ks, &id).await;
    } else {
        record.state = BundleState::ImportPreviewed;
    }
    if let Err(e) = bundle_store::store_bundle(&state.backup_bundles_ks, &record).await {
        return app_error_to_reject(&doc, &e);
    }

    let mut body = json!({
        "bundleId": req.bundle_id.as_str(),
        "status": if confirm { "committed" } else { "preview" },
        "counts": result.counts,
        "message": result.message,
    });
    if let Some(source) = result.source_did {
        body["sourceDid"] = json!(source);
    }
    respond::<finalize_import::Response>(&doc, body)
}

/// Why a restore's commit did not go ahead yet.
enum RestoreGate {
    /// Refused outright: the backup does not open, or nobody could approve.
    Refused(TrustTaskOutcome),
    /// Parked for approval: the error the dispatcher answers with, and the
    /// action's expiry.
    Parked(AppError, Option<chrono::DateTime<chrono::Utc>>),
}

/// The consent a restore needs before it commits (`vtc-admin-roles.md` §4,
/// §7): it replaces the whole ACL, so `vtc.backup.restore` is
/// authority-conferring and the commit takes the requester's bound gesture
/// and the N-of-M approval of its other approvers (**VTI-APV-018**).
///
/// The backup is opened first — a preview, which writes nothing — so a wrong
/// password or an incompatible backup is refused before anyone is asked. The
/// operation the approvers are shown, and the digest they approve, is the
/// payload **without its password**: approvers see which bundle is restored,
/// never the secret that opens it. The stored document that executes keeps it,
/// in the action list, which no backup carries.
async fn restore_consent(
    state: &AppState,
    actor: &Actor,
    doc: &TrustTask<Value>,
    envelope: &crate::backup::BackupEnvelope,
    password: &str,
    bundle: &uuid::Uuid,
) -> Result<bool, RestoreGate> {
    use crate::acl::admin_consent::{self, Act, Operation, SignedGate};
    if crate::admin_actions::executing().is_none()
        && let Err(e) =
            crate::routes::backup::import_inner(state, &actor.did, envelope, password, false).await
    {
        return Err(RestoreGate::Refused(task_error_reject(doc, e)));
    }
    let mut shown = doc.payload.clone();
    if let Some(map) = shown.as_object_mut() {
        map.remove("password");
    }
    let type_uri = doc.type_uri.to_string();
    let subject = bundle.to_string();
    let gate = admin_consent::gesture_then_consent_for(
        state,
        Act::RestoreBackup,
        &[],
        &actor.did,
        &subject,
        Operation {
            type_uri: &type_uri,
            payload: &shown,
        },
        &format!("Restore this community from backup {subject}"),
        &format!("Restore this community from backup {subject}"),
    )
    .await;
    match gate {
        Ok(SignedGate::Ready(ready)) => {
            let waived = ready.is_waived();
            ready
                .spend(state)
                .await
                .map_err(|e| RestoreGate::Refused(app_error_to_reject(doc, &e)))?;
            Ok(waived)
        }
        Ok(SignedGate::StepUpRequired(request)) => Err(RestoreGate::Refused(task_error_reject(
            doc,
            TaskError::step_up(request),
        ))),
        Err(e @ AppError::ApprovalRequired { .. }) => {
            let expires = match &e {
                AppError::ApprovalRequired { details, .. } => details["expiresAt"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| t.with_timezone(&chrono::Utc)),
                _ => None,
            };
            Err(RestoreGate::Parked(e, expires))
        }
        Err(e) => Err(RestoreGate::Refused(app_error_to_reject(doc, &e))),
    }
}

/// Write a restore's single-administrator waiver into the audit log the
/// restore just installed (see the caller).
async fn rerecord_waiver(
    state: &AppState,
    actor: &Actor,
    doc: &TrustTask<Value>,
) -> Result<(), AppError> {
    use crate::acl::admin_consent::Act;
    let Some(writer) = state.audit_writer.as_ref() else {
        return Ok(());
    };
    let mut shown = doc.payload.clone();
    if let Some(map) = shown.as_object_mut() {
        map.remove("password");
    }
    let type_uri = doc.type_uri.to_string();
    writer
        .write(
            &actor.did,
            shown["bundleId"].as_str(),
            vti_common::audit::AuditEvent::SingleAdminMode(
                vti_common::audit::SingleAdminModeData {
                    event: "consentWaived".into(),
                    requirement: Some(Act::RestoreBackup.requirement().into()),
                    task: Some(type_uri.clone()),
                    digest: Some(vti_common::task_consent::payload_digest(&type_uri, &shown)?),
                    kind: Some(Act::RestoreBackup.kind(&type_uri).into()),
                },
            ),
        )
        .await?;
    Ok(())
}

async fn handle_abort(state: &AppState, actor: &Actor, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let req: abort::Payload = match parse_spec_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let id = match vti_common::backup_transfer::parse_bundle_id(req.bundle_id.as_str()) {
        Ok(i) => i,
        Err(_) => return chunked_reject(&doc, ChunkedError::NotFound),
    };
    match vti_common::backup_transfer::abort(&state.backup_bundles_ks, &actor.did, &id).await {
        Ok(aborted) => respond::<abort::Response>(
            &doc,
            json!({ "bundleId": req.bundle_id.as_str(), "aborted": aborted }),
        ),
        Err(e) => chunked_reject(&doc, e.into()),
    }
}

// ─── Rendering ───────────────────────────────────────────────────────────

/// `stream` (named, or meant by absence) and unknown algorithms are refused
/// before anything is staged or serialized.
fn refuse_algorithm(doc: &TrustTask<Value>, algorithm: Option<&str>) -> Option<TrustTaskOutcome> {
    match algorithm {
        Some(ALGORITHM_CHUNKED) => None,
        None | Some("stream") => Some(refuse(
            doc,
            "transportUnavailable",
            "this community publishes no HTTPS endpoint for backup bytes, so it cannot serve \
             `stream`; ask again with algorithm chunkedTrustTask"
                .to_string(),
            None,
        )),
        Some(other) => Some(refuse(
            doc,
            "unsupportedAlgorithm",
            format!(
                "unsupported transfer algorithm `{other}`; this community serves chunkedTrustTask"
            ),
            None,
        )),
    }
}

/// The task slug of `doc` (`backup/<op>`), which namespaces its extended codes.
fn slug(doc: &TrustTask<Value>) -> String {
    doc.type_uri
        .to_string()
        .strip_prefix("https://trusttasks.org/spec/")
        .and_then(|rest| rest.rsplit_once('/'))
        .map(|(slug, _ver)| slug.to_string())
        .unwrap_or_else(|| "backup".to_string())
}

fn refuse(
    doc: &TrustTask<Value>,
    local: &str,
    message: String,
    details: Option<Value>,
) -> TrustTaskOutcome {
    let code = TrustTaskCode::new_extended(slug(doc), local)
        .expect("backup extended code is grammar-valid");
    reject_with_code(doc, code, message, details)
}

/// An `initiate-*` refusal. The open-bundle cap surfaces from the shared ops as
/// a `Conflict`; on these two tasks it has a declared code of its own.
fn initiate_reject(doc: &TrustTask<Value>, err: ChunkedError) -> TrustTaskOutcome {
    match err {
        ChunkedError::App(AppError::Conflict(message)) => {
            refuse(doc, "tooManyOpenBundles", message, None)
        }
        other => chunked_reject(doc, other),
    }
}

/// A [`ChunkedError`] as the code the task's specification declares.
fn chunked_reject(doc: &TrustTask<Value>, err: ChunkedError) -> TrustTaskOutcome {
    use ChunkedError as E;
    let message = err.to_string();
    let (local, details) = match err {
        E::App(e) => return app_error_to_reject(doc, &e),
        // `unavailable` with a `retryAfter` slows a client over its budget down
        // rather than failing it.
        E::RateLimited { retry_after_secs } => {
            return reject_with(
                doc,
                RejectReason::Unavailable {
                    retry_after: Some(
                        chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                    ),
                },
            );
        }
        E::NotFound => ("notFound", None),
        E::TerminalState(_) => ("terminalState", None),
        E::ChunkOutOfRange { .. } => ("chunkOutOfRange", None),
        E::DigestMismatch {
            expected_digest_multibase,
        } => (
            "digestMismatch",
            Some(json!({ "expectedDigestMultibase": expected_digest_multibase })),
        ),
        E::ChunkSizeMismatch { .. } => ("chunkSizeMismatch", None),
        E::IncompleteUpload {
            missing_count,
            missing_indices,
        } => (
            "incompleteUpload",
            Some(json!({ "missingCount": missing_count, "missingIndices": missing_indices })),
        ),
        E::BundleDigestMismatch => ("bundleDigestMismatch", None),
        E::BundleTooLarge { .. } => ("bundleTooLarge", None),
        E::InvalidManifest(_) => ("invalidManifest", None),
    };
    refuse(doc, local, message, details)
}

/// A [`TaskError`] from the shared export or import, on a `backup/*` document.
///
/// Those functions declare `vtc/backup/{export,import}` codes, which belong to
/// other tasks. The two this family names for the same condition are renamed;
/// anything else declared goes out as its underlying error, since a code
/// namespaced to another task is not one this document's reader can expect.
fn task_error_reject(doc: &TrustTask<Value>, err: TaskError) -> TrustTaskOutcome {
    match err {
        TaskError::Declared { code, error }
            if code == crate::backup::EXPORT_ERR_PASSWORD_TOO_SHORT =>
        {
            refuse(doc, "weakPassword", error.to_string(), None)
        }
        TaskError::Declared { code, error }
            if code == crate::backup::IMPORT_ERR_DECRYPTION_FAILED =>
        {
            refuse(doc, "decryptionFailed", error.to_string(), None)
        }
        TaskError::Declared { error, .. }
        | TaskError::App(error)
        | TaskError::StepUp { error, .. } => app_error_to_reject(doc, &error),
    }
}

fn manifest_json(bundle: &chunked::ChunkedBundle) -> Value {
    json!({
        "bundleId": bundle.bundle_id.to_string(),
        "algorithm": ALGORITHM_CHUNKED,
        "chunks": {
            "chunkSize": bundle.chunk_size,
            "chunkCount": bundle.chunk_count,
            "chunkDigests": bundle.digests,
        },
        "expectedSha256": bundle.expected_sha256,
        "expectedSizeBytes": bundle.expected_size_bytes,
        "expiresAt": bundle.expires_at,
    })
}

/// Build a generated response type from its JSON and answer with it, so a
/// response this node could not legally send is caught here rather than by the
/// client.
fn respond<R>(doc: &TrustTask<Value>, value: Value) -> TrustTaskOutcome
where
    R: serde::de::DeserializeOwned + serde::Serialize,
{
    match serde_json::from_value::<R>(value) {
        Ok(r) => success_response(doc, r),
        Err(e) => app_error_to_reject(
            doc,
            &AppError::Internal(format!("backup response does not fit its schema: {e}")),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::VtcRole;
    use crate::test_support::{TEST_VTC_DID, TestVtc};
    use base64::Engine as _;
    use sha2::Digest as _;
    use vti_rooms_dtg::test_support::Party;

    use super::super::members_admin_tests::{
        dispatch, dispatch_didcomm, error_code, payload_of, seed_acl, signed,
    };

    const PASSWORD: &str = "a-long-enough-backup-password";
    const MIN: u64 = vta_sdk::protocols::backup_management::chunked::MIN_CHUNK_SIZE;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    struct Fixture {
        vtc: TestVtc,
        super_admin: Party,
        other_super_admin: Party,
        scoped_admin: Party,
    }

    /// A community that can export — the plaintext secret backend seeded, as
    /// the `vtc/backup/export` tests do — and can apply an import, whose config
    /// restore writes `config_path`.
    async fn fixture() -> Fixture {
        let vtc = TestVtc::builder()
            .vtc_did(TEST_VTC_DID)
            .with_audit(true)
            .with_signers(true)
            .build()
            .await;
        let store = {
            let mut config = vtc.state.config.write().await;
            config.secrets.backend = Some(crate::config::SecretBackend::Plaintext);
            config.config_path = vtc.data_dir().join("config.toml");
            crate::keys::seed_store::create_secret_store(&config).expect("plaintext store")
        };
        store.set(b"signing-bundle").await.expect("seed the store");

        let super_admin = Party::new();
        let other_super_admin = Party::new();
        let scoped_admin = Party::new();
        seed_acl(&vtc, &super_admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(&vtc, &other_super_admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(
            &vtc,
            &scoped_admin.did,
            VtcRole::Admin,
            vec!["ctx-a".into()],
        )
        .await;
        Fixture {
            vtc,
            super_admin,
            other_super_admin,
            scoped_admin,
        }
    }

    async fn send(fix: &Fixture, from: &Party, uri: &str, payload: Value) -> TrustTaskOutcome {
        dispatch_didcomm(&fix.vtc, &signed(from, uri, payload).await).await
    }

    /// As [`send`], over the REST binding.
    async fn send_rest(fix: &Fixture, from: &Party, uri: &str, payload: Value) -> TrustTaskOutcome {
        dispatch(&fix.vtc, &signed(from, uri, payload).await).await
    }

    fn ok(out: &TrustTaskOutcome) -> Value {
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        payload_of(out)
    }

    /// Enough rows that a backup spans several minimum-size chunks.
    async fn seed_bulk(fix: &Fixture) {
        for i in 0..40 {
            fix.vtc
                .state
                .members_ks
                .insert_raw(format!("bulk:{i}").into_bytes(), vec![b'x'; 2048])
                .await
                .unwrap();
        }
    }

    /// Export the community chunk by chunk and return the assembled bytes.
    async fn export(fix: &Fixture, max_chunk: u64) -> Vec<u8> {
        let out = send(
            fix,
            &fix.super_admin,
            INITIATE_EXPORT_TYPE,
            json!({ "password": PASSWORD, "algorithm": ALGORITHM_CHUNKED, "maxChunkSize": max_chunk }),
        )
        .await;
        let descriptor = ok(&out)["descriptor"].clone();
        let bundle_id = descriptor["bundleId"].as_str().unwrap().to_string();
        let count = descriptor["chunks"]["chunkCount"].as_u64().unwrap();
        let digests = descriptor["chunks"]["chunkDigests"].clone();

        let mut bytes = Vec::new();
        for index in 0..count {
            let chunk = ok(&send(
                fix,
                &fix.super_admin,
                GET_CHUNK_TYPE,
                json!({ "bundleId": bundle_id, "index": index }),
            )
            .await);
            assert_eq!(chunk["digestMultibase"], digests[index as usize]);
            bytes.extend(B64.decode(chunk["data"].as_str().unwrap()).unwrap());
        }
        assert_eq!(
            vti_common::backup_transfer::sha256_hex(&bytes),
            descriptor["expectedSha256"].as_str().unwrap(),
            "the assembled chunks are the committed bundle"
        );

        let done = ok(&send(
            fix,
            &fix.super_admin,
            COMPLETE_EXPORT_TYPE,
            json!({ "bundleId": bundle_id }),
        )
        .await);
        assert_eq!(done["downloaded"], true);
        bytes
    }

    /// Open an import slot for `bytes` at `chunk_size` and upload every chunk.
    async fn upload(fix: &Fixture, bytes: &[u8], chunk_size: u64) -> String {
        let digests: Vec<String> = bytes
            .chunks(chunk_size as usize)
            .map(|c| {
                vta_sdk::protocols::backup_management::chunked::sha256_digest_multibase(
                    &sha2::Sha256::digest(c).into(),
                )
            })
            .collect();
        let slot = ok(&send(
            fix,
            &fix.super_admin,
            INITIATE_IMPORT_TYPE,
            json!({
                "algorithm": ALGORITHM_CHUNKED,
                "expectedSha256": vti_common::backup_transfer::sha256_hex(bytes),
                "expectedSizeBytes": bytes.len(),
                "chunks": {
                    "chunkSize": chunk_size,
                    "chunkCount": digests.len(),
                    "chunkDigests": digests,
                },
            }),
        )
        .await);
        let bundle_id = slot["descriptor"]["bundleId"].as_str().unwrap().to_string();
        for (index, chunk) in bytes.chunks(chunk_size as usize).enumerate() {
            let put = ok(&send(
                fix,
                &fix.super_admin,
                PUT_CHUNK_TYPE,
                json!({
                    "bundleId": bundle_id,
                    "index": index,
                    "digestMultibase": digests[index],
                    "data": B64.encode(chunk),
                }),
            )
            .await);
            assert_eq!(put["stored"], true);
        }
        bundle_id
    }

    /// The whole family end to end: export in chunks, upload the bytes back in
    /// chunks of a different size, preview, then commit.
    #[tokio::test]
    async fn a_community_backup_round_trips_chunk_by_chunk() {
        let fix = fixture().await;
        seed_bulk(&fix).await;
        let bytes = export(&fix, MIN).await;
        assert!(
            bytes.len() as u64 > 2 * MIN,
            "the backup should span several chunks, got {} bytes",
            bytes.len()
        );

        // Remove a row, so the commit visibly restores it.
        fix.vtc
            .state
            .members_ks
            .remove(b"bulk:0".to_vec())
            .await
            .unwrap();

        let bundle_id = upload(&fix, &bytes, MAX_CHUNK_SIZE).await;
        let preview = ok(&send(
            &fix,
            &fix.super_admin,
            FINALIZE_IMPORT_TYPE,
            json!({ "bundleId": bundle_id, "password": PASSWORD }),
        )
        .await);
        assert_eq!(preview["status"], "preview");
        assert_eq!(preview["sourceDid"], TEST_VTC_DID);
        assert!(preview["counts"]["members"].as_u64().unwrap() >= 40);
        assert!(
            fix.vtc
                .state
                .members_ks
                .get_raw(b"bulk:0".to_vec())
                .await
                .unwrap()
                .is_none(),
            "a preview writes nothing"
        );

        // The commit replaces the ACL, so it is authority-conferring
        // (`vtc-admin-roles.md` §7): it asks for the requester's gesture
        // before anyone's approval, and writes nothing without them. The
        // whole approved path is `tests/it/admin_roles_c2.rs`.
        let out = send(
            &fix,
            &fix.super_admin,
            FINALIZE_IMPORT_TYPE,
            json!({ "bundleId": bundle_id, "password": PASSWORD, "confirm": true }),
        )
        .await;
        assert!(!out.status.is_success(), "{}", payload_of(&out));
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
        assert!(
            fix.vtc
                .state
                .members_ks
                .get_raw(b"bulk:0".to_vec())
                .await
                .unwrap()
                .is_none(),
            "nothing is restored before the gesture and the approval"
        );
    }

    /// A restore replaces the ACL, so its commit is authority-conferring
    /// (`vtc-admin-roles.md` §4, §7; **VTI-APV-018**): after the requester's
    /// gesture it parks in the action list — shown to approvers without its
    /// password — keeps its staged bytes alive while it waits, and lands on
    /// another administrator's approval.
    #[tokio::test]
    async fn vti_apv_018_a_restore_parks_for_approval_and_lands_on_it() {
        use crate::admin_actions::{ActionRecord, Decided, DecisionInput};
        let fix = fixture().await;
        seed_bulk(&fix).await;
        let bytes = export(&fix, MIN).await;
        fix.vtc
            .state
            .members_ks
            .remove(b"bulk:0".to_vec())
            .await
            .unwrap();
        let bundle_id = upload(&fix, &bytes, MAX_CHUNK_SIZE).await;

        // The gesture is bound to what approvers are shown: no password.
        crate::acl::bound_step_up::record_mark_for_test(
            &fix.vtc.state,
            &fix.super_admin.did,
            FINALIZE_IMPORT_TYPE,
            &json!({ "bundleId": bundle_id, "confirm": true }),
        )
        .await
        .unwrap();
        let out = send(
            &fix,
            &fix.super_admin,
            FINALIZE_IMPORT_TYPE,
            json!({ "bundleId": bundle_id, "password": PASSWORD, "confirm": true }),
        )
        .await;
        let parked = payload_of(&out);
        assert!(
            parked["expects"][0]["hint"]["actionId"].is_string(),
            "parked for approval: {parked}"
        );
        assert!(
            fix.vtc
                .state
                .members_ks
                .get_raw(b"bulk:0".to_vec())
                .await
                .unwrap()
                .is_none(),
            "nothing is restored before the approval"
        );

        let rec: ActionRecord = fix
            .vtc
            .state
            .admin_actions_ks
            .prefix_iter_raw(b"action:".to_vec())
            .await
            .unwrap()
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice::<ActionRecord>(&v).ok())
            .find(|r| r.kind == "backup.restore")
            .expect("a restore action");
        assert!(
            rec.payload.get("password").is_none(),
            "approvers are never shown the backup's password"
        );
        let staged = vti_common::backup_transfer::bundle_store::get_bundle(
            &fix.vtc.state.backup_bundles_ks,
            &vti_common::backup_transfer::parse_bundle_id(&bundle_id).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            staged.expires_at.timestamp() as u64 >= rec.expires_at,
            "the staged bytes outlive the approval they wait for"
        );

        let slot = rec
            .approvers
            .iter()
            .find(|s| s.did == fix.other_super_admin.did)
            .expect("the other administrator is an approver")
            .clone();
        let decided = crate::admin_actions::decide(
            &fix.vtc.state,
            &fix.other_super_admin.did,
            DecisionInput {
                challenge: slot.challenge,
                payload_digest: slot.wire_digest,
                approve: true,
                reason: None,
                action_id: Some(rec.id.clone()),
                evidence: None,
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(
                decided,
                Decided::Granted {
                    completed: true,
                    ..
                }
            ),
            "{decided:?}"
        );
        assert!(
            fix.vtc
                .state
                .members_ks
                .get_raw(b"bulk:0".to_vec())
                .await
                .unwrap()
                .is_some(),
            "the approved restore landed"
        );
    }

    /// In single-administrator mode (VTI-APV-022), with nobody else able to
    /// approve, a restore's commit lands on the requester's bound gesture —
    /// the consent waived and audited `Critical`, like every other kind — and
    /// parks nothing.
    #[tokio::test]
    async fn vti_apv_022_a_sole_admin_restores_on_their_own_gesture() {
        let fix = fixture().await;
        fix.vtc.state.config.write().await.acl.single_admin_mode = true;
        for did in [&fix.other_super_admin.did, &fix.scoped_admin.did] {
            crate::acl::delete_acl_entry(&fix.vtc.state.acl_ks, did)
                .await
                .unwrap();
        }
        seed_bulk(&fix).await;
        let bytes = export(&fix, MIN).await;
        fix.vtc
            .state
            .members_ks
            .remove(b"bulk:0".to_vec())
            .await
            .unwrap();
        let bundle_id = upload(&fix, &bytes, MAX_CHUNK_SIZE).await;
        crate::acl::bound_step_up::record_mark_for_test(
            &fix.vtc.state,
            &fix.super_admin.did,
            FINALIZE_IMPORT_TYPE,
            &json!({ "bundleId": bundle_id, "confirm": true }),
        )
        .await
        .unwrap();
        let committed = ok(&send(
            &fix,
            &fix.super_admin,
            FINALIZE_IMPORT_TYPE,
            json!({ "bundleId": bundle_id, "password": PASSWORD, "confirm": true }),
        )
        .await);
        assert_eq!(committed["status"], "committed");
        assert!(
            fix.vtc
                .state
                .members_ks
                .get_raw(b"bulk:0".to_vec())
                .await
                .unwrap()
                .is_some(),
            "the restore landed on the requester's gesture alone"
        );
        let waived = fix
            .vtc
            .state
            .audit_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .into_iter()
            .filter_map(|(_, v)| {
                serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok()
            })
            .filter(|env| {
                matches!(&env.event, vti_common::audit::AuditEvent::SingleAdminMode(d)
                    if d.event == "consentWaived")
            })
            .count();
        assert_eq!(waived, 1, "the waiver is audited");
    }

    /// `stream` — named, or meant by absence — needs an HTTPS endpoint this
    /// node does not publish.
    #[tokio::test]
    async fn stream_is_transport_unavailable() {
        let fix = fixture().await;
        for payload in [
            json!({ "password": PASSWORD }),
            json!({ "password": PASSWORD, "algorithm": "stream" }),
        ] {
            let out = send(&fix, &fix.super_admin, INITIATE_EXPORT_TYPE, payload).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("backup/initiate-export:transportUnavailable")
            );
        }
        let out = send(
            &fix,
            &fix.super_admin,
            INITIATE_EXPORT_TYPE,
            json!({ "password": PASSWORD, "algorithm": "carrier-pigeon" }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("backup/initiate-export:unsupportedAlgorithm")
        );
    }

    /// A chunk too large for a `put-chunk` document this door accepts is
    /// refused up front, not after the first oversized upload fails.
    #[tokio::test]
    async fn a_chunk_size_the_door_cannot_carry_is_unacceptable() {
        let fix = fixture().await;
        let size = MAX_CHUNK_SIZE * 2;
        let out = send(
            &fix,
            &fix.super_admin,
            INITIATE_IMPORT_TYPE,
            json!({
                "algorithm": ALGORITHM_CHUNKED,
                "expectedSha256": "0".repeat(64),
                "expectedSizeBytes": size,
                "chunks": { "chunkSize": size, "chunkCount": 1, "chunkDigests": [
                    vta_sdk::protocols::backup_management::chunked::sha256_digest_multibase(&[0u8; 32])
                ] },
            }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("backup/initiate-import:chunkSizeUnacceptable"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// The bound is right: a signed `put-chunk` carrying a full-size chunk fits
    /// what the door accepts before it has checked a proof.
    #[tokio::test]
    async fn a_full_size_put_chunk_document_fits_the_door() {
        let from = Party::new();
        let doc = signed(
            &from,
            PUT_CHUNK_TYPE,
            json!({
                "bundleId": uuid::Uuid::new_v4().to_string(),
                "index": 4095,
                "digestMultibase": vta_sdk::protocols::backup_management::chunked::sha256_digest_multibase(&[0u8; 32]),
                "data": B64.encode(vec![0xAB; MAX_CHUNK_SIZE as usize]),
            }),
        )
        .await;
        let len = serde_json::to_vec(&doc).unwrap().len();
        assert!(
            len < crate::trust_tasks::size::max_document_bytes(PUT_CHUNK_TYPE),
            "a {MAX_CHUNK_SIZE}-byte chunk makes a {len}-byte document; the door takes {}",
            crate::trust_tasks::size::max_document_bytes(PUT_CHUNK_TYPE)
        );
    }

    /// Unrestricted administrators only — a scoped administrator is refused,
    /// as `vtc/backup/{export,import}` refuse them.
    #[tokio::test]
    async fn only_an_unrestricted_administrator_may_transfer() {
        let fix = fixture().await;
        let out = send(
            &fix,
            &fix.scoped_admin,
            INITIATE_EXPORT_TYPE,
            json!({ "password": PASSWORD, "algorithm": ALGORITHM_CHUNKED }),
        )
        .await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
    }

    /// A bundle is its opener's: another administrator's handle is `notFound`,
    /// not an oracle over whose transfers exist.
    #[tokio::test]
    async fn another_administrators_bundle_is_not_found() {
        let fix = fixture().await;
        let out = send(
            &fix,
            &fix.super_admin,
            INITIATE_EXPORT_TYPE,
            json!({ "password": PASSWORD, "algorithm": ALGORITHM_CHUNKED }),
        )
        .await;
        let bundle_id = ok(&out)["descriptor"]["bundleId"].clone();
        let out = send(
            &fix,
            &fix.other_super_admin,
            GET_CHUNK_TYPE,
            json!({ "bundleId": bundle_id, "index": 0 }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("backup/get-chunk:notFound")
        );
    }

    /// Finalizing with chunks missing names them and changes nothing, so the
    /// producer sends only those and asks again.
    #[tokio::test]
    async fn an_incomplete_upload_names_what_is_missing() {
        let fix = fixture().await;
        seed_bulk(&fix).await;
        let bytes = export(&fix, MIN).await;
        let digests: Vec<String> = bytes
            .chunks(MIN as usize)
            .map(|c| {
                vta_sdk::protocols::backup_management::chunked::sha256_digest_multibase(
                    &sha2::Sha256::digest(c).into(),
                )
            })
            .collect();
        let slot = ok(&send(
            &fix,
            &fix.super_admin,
            INITIATE_IMPORT_TYPE,
            json!({
                "algorithm": ALGORITHM_CHUNKED,
                "expectedSha256": vti_common::backup_transfer::sha256_hex(&bytes),
                "expectedSizeBytes": bytes.len(),
                "chunks": { "chunkSize": MIN, "chunkCount": digests.len(), "chunkDigests": digests },
            }),
        )
        .await);
        let bundle_id = slot["descriptor"]["bundleId"].as_str().unwrap().to_string();
        let first = &bytes[..MIN as usize];
        ok(&send(
            &fix,
            &fix.super_admin,
            PUT_CHUNK_TYPE,
            json!({ "bundleId": bundle_id, "index": 0, "digestMultibase": digests[0], "data": B64.encode(first) }),
        )
        .await);

        let out = send(
            &fix,
            &fix.super_admin,
            FINALIZE_IMPORT_TYPE,
            json!({ "bundleId": bundle_id, "password": PASSWORD }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("backup/finalize-import:incompleteUpload")
        );
        let details = &payload_of(&out)["details"];
        assert_eq!(details["missingCount"], digests.len() as u64 - 1);
        assert_eq!(details["missingIndices"][0], 1);
    }

    /// The wrong password is the family's `decryptionFailed`, not the
    /// `vtc/backup/import` code the shared import declares.
    #[tokio::test]
    async fn the_wrong_password_is_decryption_failed() {
        let fix = fixture().await;
        let bytes = export(&fix, MIN).await;
        let bundle_id = upload(&fix, &bytes, MAX_CHUNK_SIZE).await;
        let out = send(
            &fix,
            &fix.super_admin,
            FINALIZE_IMPORT_TYPE,
            json!({ "bundleId": bundle_id, "password": "not-the-backup-password" }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("backup/finalize-import:decryptionFailed")
        );
    }

    /// The verbs that carry the password, or open the bundle it unlocks, are
    /// refused over REST; nothing is minted.
    #[tokio::test]
    async fn the_password_bearing_verbs_are_refused_over_rest() {
        let fix = fixture().await;
        for (uri, payload) in [
            (
                INITIATE_EXPORT_TYPE,
                json!({ "password": "a-long-enough-backup-password", "algorithm": ALGORITHM_CHUNKED }),
            ),
            (
                FINALIZE_IMPORT_TYPE,
                json!({
                    "bundleId": uuid::Uuid::new_v4().to_string(),
                    "password": "a-long-enough-backup-password",
                    "confirm": false,
                }),
            ),
        ] {
            let out = send_rest(&fix, &fix.super_admin, uri, payload).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{uri}: {}",
                String::from_utf8_lossy(&out.body)
            );
            assert!(
                String::from_utf8_lossy(&out.body).contains("over REST"),
                "{uri}"
            );
        }
    }
}
