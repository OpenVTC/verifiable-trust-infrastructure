//! Backup-descriptor slice trust-task handlers.
//!
//! Five handlers for `spec/vta/backup/*`. Each is a thin wrapper:
//! parse payload → call `operations::backup::descriptors::*` →
//! serialize result. The op layer does the heavy lifting (auth
//! gates, caller-owns-bundle checks, state-machine transitions).
//!
//! See `docs/05-design-notes/backup-descriptor-pattern.md` for the
//! protocol design.

use super::helpers::TrustTaskOutcome;
use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::protocols::backup_management::chunked::{
    ALGORITHM_CHUNKED, finalize_import_1_1, get_chunk, initiate_export_1_1, initiate_import_1_1,
    put_chunk,
};
use vta_sdk::protocols::backup_management::descriptors::{
    AbortBundleBody, CompleteExportBody, FinalizeImportBody, InitiateExportBody, InitiateImportBody,
};
use vti_common::error::AppError;

use crate::auth::AuthClaims;
use crate::operations::backup::{chunked, descriptors};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, reject_with_code,
    success_response,
};

/// Slugs whose specifications declare `transportUnavailable`.
const INITIATE_EXPORT_SLUG: &str = "vta/backup/initiate-export";
const INITIATE_IMPORT_SLUG: &str = "vta/backup/initiate-import";

/// Refuse an `initiate-*` with the specification's own
/// `<slug>:transportUnavailable` code.
///
/// Both `initiate-export/1.0` and `initiate-import/1.0` require it of a
/// recipient with no address at which the bytes can move — the
/// DIDComm/TSP-only VTA, whose `public_url` is unset. This used to surface as
/// `internalError`, which tells the producer "not your fault, retry", when the
/// only fix is the agent's configuration: the opposite response to the one the
/// operator needs.
fn transport_unavailable(doc: &TrustTask<Value>, slug: &str) -> TrustTaskOutcome {
    tracing::warn!(
        slug,
        "backup descriptor refused: `public_url` is not configured, so the `stream` \
         algorithm has no blob URL to publish"
    );
    let code = trust_tasks_rs::TrustTaskCode::new_extended(slug, "transportUnavailable")
        .expect("backup extended code is grammar-valid");
    reject_with_code(doc, code, descriptors::TRANSPORT_UNAVAILABLE_MESSAGE, None)
}

/// The `initiate-*` preconditions the handler must answer itself, in the order
/// a caller should learn them: entitlement first (an unauthorized caller learns
/// nothing about this agent's deployment), then whether the transport exists.
async fn initiate_precheck(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    slug: &str,
) -> Result<(), TrustTaskOutcome> {
    auth.require_super_admin()
        .map_err(|e| app_error_to_reject(doc, e))?;
    if descriptors::blob_transport_base_url(&state.config)
        .await
        .is_none()
    {
        return Err(transport_unavailable(doc, slug));
    }
    Ok(())
}

/// Record a backup-lifecycle event against its bundle.
///
/// Both `initiate-*` verbs succeeded silently until the audit-coverage census
/// could see them — which it could not until #347 specced the family and gave
/// it conformance witnesses. They are the two most consequential successes in
/// this service to lose: an export mints a **fetchable copy of the entire
/// agent** at a known address, and an import opens a **writable endpoint into
/// it**. Neither alters stored state, which is why neither was caught by any
/// state-shaped check, and why the trail is the only place the event exists at
/// all.
///
/// Recorded here rather than in the op layer because the op layer is shared
/// with the REST blob routes, which have their own logging; and recorded
/// against the bundle id so the row joins to the later complete/finalize/abort.
///
/// The other three verbs are audited here too, and they were found by
/// *reasoning* rather than by the census — which is worth saying plainly,
/// because it marks the sweep's blind spot. `complete-export`, `finalize-import`
/// and `abort` all need a real bundle to succeed, and the census drives an
/// empty store, so it only ever sees their not-found refusals. It would have
/// reported this family green while every success path stayed silent. A test
/// that cannot reach a path cannot vouch for it.
///
/// Best-effort, as everywhere: a failed audit write must never fail the
/// operation.
async fn record_bundle_event(
    state: &AppState,
    auth: &AuthClaims,
    action: &str,
    bundle_id: &str,
    detail: String,
) {
    if let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        action,
        &auth.did,
        Some(bundle_id),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
        Some(&detail),
    )
    .await
    {
        tracing::warn!(error = %e, action, "audit record failed for {action}");
    }
}

/// Record an export's `backup.initiate-export` row **durably**, before the
/// descriptor that makes the bundle fetchable is returned. A failed write
/// aborts the bundle and refuses: the bundle carries the seed, and an
/// unrecorded copy of it is not permitted (VTI-VTA-003). The other bundle
/// events stay best-effort — by then the decision to release was recorded.
async fn record_export_or_abort(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    bundles_ks: &crate::store::KeyspaceHandle,
    bundle_id: &str,
    detail: String,
) -> Result<(), TrustTaskOutcome> {
    let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        "backup.initiate-export",
        &auth.did,
        Some(bundle_id),
        "success",
        Some(super::transport::audit_channel()),
        None,
        Some(&detail),
    )
    .await
    else {
        return Ok(());
    };
    tracing::error!(target: vta_audit::AUDIT_WRITE_FAILURE_TARGET, error = %e, actor = %auth.did, bundle_id, "backup export refused: its audit row could not be written");
    if let Ok(id) = uuid::Uuid::parse_str(bundle_id) {
        let _ = vti_common::backup_transfer::abort(bundles_ks, &auth.did, &id).await;
    }
    Err(app_error_to_reject(
        doc,
        AppError::Internal(
            "the backup was not released: the export could not be recorded in the audit \
             trail, and an unrecorded export is not permitted (VTI-VTA-003)"
                .into(),
        ),
    ))
}

/// Refuse an export whose request arrived hop-by-hop (Trust Tasks over HTTPS).
///
/// The bundle is sealed with the password the request carries. Over a channel
/// that is confidential only per hop, that password exists in plaintext
/// wherever TLS terminates, next to the bundle it opens — which carries the
/// seed. So, like `keys/export-secret`, a backup export needs a channel
/// confidential to the two parties: DIDComm or TSP (VTI-VTA-003). Fetching the
/// bundle's ciphertext afterwards is not affected.
fn refuse_hop_by_hop_export(doc: &TrustTask<Value>) -> Result<(), TrustTaskOutcome> {
    match super::transport::current() {
        super::transport::TransportConfidentiality::EndToEnd => Ok(()),
        super::transport::TransportConfidentiality::HopByHop => Err(app_error_to_reject(
            doc,
            AppError::Forbidden(
                "a backup export is refused over a hop-by-hop transport: the password that \
                 seals the bundle would exist in plaintext wherever TLS terminates. Send \
                 initiate-export over DIDComm or TSP"
                    .into(),
            ),
        )),
    }
}

/// `spec/vta/backup/initiate-export/1.0` — mint an export bundle.
/// Auth: super-admin.
pub(super) async fn handle_initiate_export(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: InitiateExportBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = initiate_precheck(state, auth, &doc, INITIATE_EXPORT_SLUG).await {
        return resp;
    }
    if let Err(resp) = refuse_hop_by_hop_export(&doc) {
        return resp;
    }
    let committer = state.backup_access().committer().await;
    let deps = crate::operations::descriptor_deps_from_app_state(state, &committer);
    // `include_audit` is read BEFORE the request moves into the op: it is the
    // one member that changes what leaves the agent — the trail records the
    // agent's dealings with counterparties who were never party to this export
    // — so an operator reviewing this row later needs it.
    let include_audit = req.include_audit;
    match descriptors::initiate_export(&deps, auth, req).await {
        Ok(body) => {
            if let Err(reject) = record_export_or_abort(
                state,
                auth,
                &doc,
                deps.bundles_ks,
                &body.descriptor.bundle_id,
                format!(
                    "includeAudit={include_audit} bytes={} expires={}",
                    body.descriptor.expected_size_bytes, body.descriptor.expires_at
                ),
            )
            .await
            {
                return reject;
            }
            success_response(&doc, body)
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/complete-export/1.0` — optional client ack.
/// Auth: super-admin (must match the initiator's DID).
pub(super) async fn handle_complete_export(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: CompleteExportBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let committer = state.backup_access().committer().await;
    let deps = crate::operations::descriptor_deps_from_app_state(state, &committer);
    match descriptors::complete_export(&deps, auth, req).await {
        Ok(body) => {
            // `downloaded` is the whole evidentiary content of this row. It is
            // the difference between "a copy of this agent left here" and "a
            // bundle expired unfetched", and after the bytes are released it is
            // the only place that difference survives — which is exactly where
            // an investigation into a leaked copy has to start.
            record_bundle_event(
                state,
                auth,
                "backup.complete-export",
                &body.bundle_id,
                format!("downloaded={}", body.downloaded),
            )
            .await;
            success_response(&doc, body)
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/initiate-import/1.0` — mint an upload slot.
/// Auth: super-admin.
pub(super) async fn handle_initiate_import(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: InitiateImportBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = initiate_precheck(state, auth, &doc, INITIATE_IMPORT_SLUG).await {
        return resp;
    }
    let committer = state.backup_access().committer().await;
    let deps = crate::operations::descriptor_deps_from_app_state(state, &committer);
    match descriptors::initiate_import(&deps, auth, req).await {
        Ok(body) => {
            // The digest identifies the exact bytes the operator committed to
            // upload, which is what lets a later review say *which* bundle was
            // brought in rather than only that one was.
            record_bundle_event(
                state,
                auth,
                "backup.initiate-import",
                &body.descriptor.bundle_id,
                format!(
                    "sha256={} bytes={} expires={}",
                    body.descriptor.expected_sha256,
                    body.descriptor.expected_size_bytes,
                    body.descriptor.expires_at
                ),
            )
            .await;
            success_response(&doc, body)
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/finalize-import/1.0` — apply uploaded bytes
/// (preview or commit). Auth: super-admin (must match the
/// initiator's DID).
pub(super) async fn handle_finalize_import(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: FinalizeImportBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // A chunked upload is assembled and verified here, before the password is
    // used; a no-op for a stream bundle. 1.0 declares none of the chunked codes,
    // so its refusals ride out as general failures — 1.1 renders them properly.
    if let Err(e) = chunked::finalize_precheck(&state.backup_bundles_ks, auth, &req.bundle_id).await
    {
        return match e {
            chunked::ChunkedError::App(app) => app_error_to_reject(&doc, app),
            chunked::ChunkedError::NotFound => app_error_to_reject(
                &doc,
                AppError::NotFound(format!("bundle not found: {}", req.bundle_id)),
            ),
            other => app_error_to_reject(&doc, AppError::Conflict(other.to_string())),
        };
    }
    let committer = state.backup_access().committer().await;
    let deps = crate::operations::descriptor_deps_from_app_state(state, &committer);
    match descriptors::finalize_import(&deps, auth, req).await {
        Ok(body) => {
            // The most consequential row this service writes. On commit the
            // agent's keys, ACLs, contexts and trail are REPLACED with the
            // bundle's — including, note, the audit trail itself. Anything this
            // agent recorded before the commit is gone with it, so a row
            // written into imported state would document its own erasure.
            //
            // This one is written after the op returns, to the sink, which is
            // outside the state the import replaced. That is the point, and it
            // is what the specification means by the response being the record
            // the *operator* holds.
            //
            // `status` distinguishes a rehearsal from the real thing, so a
            // preview does not read as a replacement that happened.
            record_bundle_event(
                state,
                auth,
                "backup.finalize-import",
                &body.bundle_id,
                format!(
                    "status={} source={} keys={} acls={} contexts={}",
                    body.status,
                    body.source_did.as_deref().unwrap_or("unknown"),
                    body.key_count,
                    body.acl_count,
                    body.context_count
                ),
            )
            .await;
            // A commit staged the restore and committed its seed; it takes
            // effect only when the VTA boots again. The reply goes out first.
            if body.status == "committed" {
                crate::restore::request_reboot(&state.restart_tx);
            }
            success_response(&doc, body)
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/abort/1.0` — cancel an in-flight bundle. Auth:
/// super-admin (must match the initiator's DID).
pub(super) async fn handle_abort(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: AbortBundleBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let committer = state.backup_access().committer().await;
    let deps = crate::operations::descriptor_deps_from_app_state(state, &committer);
    match descriptors::abort_bundle(&deps, auth, req).await {
        Ok(body) => {
            // A bundle that simply stops existing is indistinguishable from one
            // that was quietly fetched. `aborted` is what separates "no copy
            // was ever made" from "a copy left and nobody logged it", and it is
            // recorded on the idempotent no-op too so a repeat is visible as a
            // repeat rather than as a second cancellation.
            record_bundle_event(
                state,
                auth,
                "backup.abort",
                &body.bundle_id,
                format!("aborted={}", body.aborted),
            )
            .await;
            success_response(&doc, body)
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

// ─── The `chunkedTrustTask` algorithm (1.1 initiators, get/put-chunk) ────────
//
// Specified in `vta/backup/initiate-export/1.1` § Chunked transfer. A `stream`
// request to a 1.1 initiator is served by the 1.0 path unchanged — the two
// shapes are wire-identical — and only `chunkedTrustTask` takes the new ops.
//
// These handlers await the 1.0 handler (or a full state export) inline. They
// used to `Box::pin` those awaits, because `dispatch_typed` matched every
// handler inline and this handler — awaiting the whole 1.0 handler plus a full
// export — became its largest arm, overflowing the debug worker stack on the
// first chunked export. That boxing moved to the dispatch seam itself
// (`dispatch_typed` now `Box::pin`s every arm), so each handler's future is
// heap-allocated there and no longer sums into the match frame; the
// per-handler boxes here were redundant once the seam was fixed.

/// Task slug (`vta/backup/<op>`) of the incoming document, so an extended code
/// is namespaced to whichever task raised it (SPEC §8.5).
fn backup_slug(doc: &TrustTask<Value>) -> String {
    doc.type_uri
        .to_string()
        .strip_prefix("https://trusttasks.org/spec/")
        .and_then(|rest| rest.rsplit_once('/'))
        .map(|(slug, _ver)| slug.to_string())
        .unwrap_or_else(|| "vta/backup".to_string())
}

/// Render a [`chunked::ChunkedError`] as the code its specification declares.
fn chunked_reject(doc: &TrustTask<Value>, err: chunked::ChunkedError) -> TrustTaskOutcome {
    use chunked::ChunkedError as E;
    let slug = backup_slug(doc);
    let message = err.to_string();
    let (local, details) = match err {
        E::App(e) => return app_error_to_reject(doc, e),
        // `unavailable` with a `retryAfter` is what `VtaClient::idempotent`
        // waits on, so a client over the budget slows down rather than failing.
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
            // Declared by put-chunk only; get-chunk never raises it.
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
    let code = trust_tasks_rs::TrustTaskCode::new_extended(&slug, local)
        .expect("backup extended code is grammar-valid");
    reject_with_code(doc, code, message, details)
}

/// Build a generated response type from its JSON form. The generated types are
/// `#[non_exhaustive]`, so a struct literal is unavailable; deserializing also
/// runs the members' own pattern and range checks, so a response this agent
/// could not legally send is caught here rather than by the client.
fn typed<R: serde::de::DeserializeOwned>(value: Value) -> Result<R, AppError> {
    serde_json::from_value(value)
        .map_err(|e| AppError::Internal(format!("backup response does not fit its schema: {e}")))
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

fn is_chunked(algorithm: Option<&str>) -> bool {
    algorithm == Some(ALGORITHM_CHUNKED)
}

/// `spec/vta/backup/initiate-export/1.1` — `stream` exactly as 1.0, or a
/// `chunkedTrustTask` bundle whose chunks are pulled with `get-chunk`. The
/// chunked path needs no `public_url`, which is the point of it.
pub(super) async fn handle_initiate_export_1_1(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: initiate_export_1_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let algorithm = req.algorithm.as_ref().map(|a| a.as_str());
    if !is_chunked(algorithm) {
        // The recipient returns what was asked for or refuses; a `stream`
        // request never receives a chunked descriptor.
        return handle_initiate_export(state, auth, doc).await;
    }
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    if let Err(resp) = refuse_hop_by_hop_export(&doc) {
        return resp;
    }
    let include_audit = req.include_audit.unwrap_or(false);
    let committer = state.backup_access().committer().await;
    let deps = crate::operations::descriptor_deps_from_app_state(state, &committer);
    let bundle = match chunked::initiate_export(
        &deps,
        auth,
        req.password.as_str(),
        include_audit,
        req.max_chunk_size.map(|s| s.0.max(0) as u64),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return chunked_reject(&doc, e),
    };
    if let Err(reject) = record_export_or_abort(
        state,
        auth,
        &doc,
        deps.bundles_ks,
        &bundle.bundle_id.to_string(),
        format!(
            "algorithm={ALGORITHM_CHUNKED} includeAudit={include_audit} bytes={} chunks={} expires={}",
            bundle.expected_size_bytes, bundle.chunk_count, bundle.expires_at
        ),
    )
    .await
    {
        return reject;
    }
    match typed::<initiate_export_1_1::Response>(json!({
        "descriptor": manifest_json(&bundle),
        "completionHint": format!(
            "Send get-chunk for indices 0 to {}, verify each, then send complete-export.",
            bundle.chunk_count - 1
        ),
    })) {
        Ok(r) => success_response(&doc, r),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/initiate-import/1.1` — `stream` exactly as 1.0, or a
/// `chunkedTrustTask` slot for the manifest the request pre-commits.
pub(super) async fn handle_initiate_import_1_1(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: initiate_import_1_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let algorithm = req.algorithm.as_ref().map(|a| a.as_str());
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    if !is_chunked(algorithm) {
        // `chunks` belongs to `chunkedTrustTask` alone (the spec's
        // `invalidManifest`), so a stream request carrying one is refused rather
        // than having the manifest silently ignored.
        if req.chunks.is_some() {
            return chunked_reject(
                &doc,
                chunked::ChunkedError::InvalidManifest(
                    "`chunks` is only meaningful with algorithm chunkedTrustTask".into(),
                ),
            );
        }
        return handle_initiate_import(state, auth, doc).await;
    }
    let Some(manifest) = req.chunks else {
        return chunked_reject(
            &doc,
            chunked::ChunkedError::InvalidManifest(
                "algorithm chunkedTrustTask requires a `chunks` manifest".into(),
            ),
        );
    };
    let slot = match chunked::initiate_import(
        &state.backup_bundles_ks,
        auth,
        req.expected_sha256.as_str(),
        req.expected_size_bytes.0.get(),
        manifest.chunk_size.0.max(0) as u64,
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
        Err(e) => return chunked_reject(&doc, e),
    };
    record_bundle_event(
        state,
        auth,
        "backup.initiate-import",
        &slot.bundle_id.to_string(),
        format!(
            "algorithm={ALGORITHM_CHUNKED} sha256={} bytes={} chunks={} expires={}",
            slot.expected_sha256, slot.expected_size_bytes, slot.chunk_count, slot.expires_at
        ),
    )
    .await;
    match typed::<initiate_import_1_1::Response>(json!({
        "descriptor": manifest_json(&slot),
        "completionHint": format!(
            "Send put-chunk for indices 0 to {}, then send finalize-import.",
            slot.chunk_count - 1
        ),
    })) {
        Ok(r) => success_response(&doc, r),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/finalize-import/1.1` — as 1.0, with a chunked upload's
/// completeness and assembled digest checked first, answered with the codes 1.1
/// declares, before the password is used.
pub(super) async fn handle_finalize_import_1_1(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: finalize_import_1_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) =
        chunked::finalize_precheck(&state.backup_bundles_ks, auth, req.bundle_id.as_str()).await
    {
        return chunked_reject(&doc, e);
    }
    handle_finalize_import(state, auth, doc).await
}

/// `spec/vta/backup/get-chunk/1.0` — one chunk of a chunked export, by index.
///
/// Not audited per chunk: the specification's retention section keeps the
/// durable facts (an export was made; whether it was retrieved) on
/// `initiate-export` and `complete-export`, and a row per chunk would add
/// nothing to them but a timeline of the operator's connection. Refusals are
/// still recorded by the dispatch spine.
pub(super) async fn handle_get_chunk(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: get_chunk::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let served = match chunked::get_chunk(
        &state.backup_bundles_ks,
        chunked::ChunkRateLimiter::global(),
        auth,
        req.bundle_id.as_str(),
        req.index.0.max(0) as u64,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return chunked_reject(&doc, e),
    };
    use base64::Engine;
    match typed::<get_chunk::Response>(json!({
        "bundleId": served.bundle_id.to_string(),
        "index": served.index,
        "digestMultibase": served.digest_multibase,
        "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&served.data),
        "expiresAt": served.expires_at,
    })) {
        Ok(r) => success_response(&doc, r),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/put-chunk/1.0` — write one chunk of a chunked import.
/// Not audited per chunk, for the reason [`handle_get_chunk`] gives.
pub(super) async fn handle_put_chunk(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: put_chunk::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    use base64::Engine;
    let data = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(req.data.as_str()) {
        Ok(d) => d,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("`data` is not unpadded base64url: {e}"),
                },
            );
        }
    };
    let index = req.index.0.max(0) as u64;
    let outcome = match chunked::put_chunk(
        &state.backup_bundles_ks,
        &state.backup_blob_dir,
        chunked::ChunkRateLimiter::global(),
        auth,
        chunked::ChunkWrite {
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
    match typed::<put_chunk::Response>(json!({
        "bundleId": req.bundle_id.as_str(),
        "index": index,
        "stored": outcome.stored,
        "remainingCount": outcome.remaining_count,
        "expiresAt": outcome.expires_at,
    })) {
        Ok(r) => success_response(&doc, r),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::TypeUri;

    fn doc(uri: &str) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().expect("backup uri");
        TrustTask::new("urn:uuid:test", uri, serde_json::json!({}))
    }

    /// A VTA with no public HTTPS address answers `initiate-*` with the code
    /// its specification declares, not `internalError`.
    #[test]
    fn transport_unavailable_uses_the_specified_extended_code() {
        for (uri, slug) in [
            (
                vta_sdk::trust_tasks::TASK_BACKUP_INITIATE_EXPORT_1_0,
                INITIATE_EXPORT_SLUG,
            ),
            (
                vta_sdk::trust_tasks::TASK_BACKUP_INITIATE_IMPORT_1_0,
                INITIATE_IMPORT_SLUG,
            ),
        ] {
            assert!(
                uri.contains(slug),
                "{uri}: the slug constant must match the dispatched URI"
            );
            let outcome = transport_unavailable(&doc(uri), slug);
            let parsed: Value = serde_json::from_slice(&outcome.body).expect("error doc");
            assert_eq!(
                parsed["payload"]["code"],
                format!("{slug}:transportUnavailable"),
                "{parsed}"
            );
            assert_ne!(
                outcome.status,
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "transportUnavailable is not an internal error"
            );
            assert!(
                !parsed["payload"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("public_url"),
                "the wire message must not name configuration: {parsed}"
            );
        }
    }

    /// Run a chunked `initiate-export/1.1` as a super-admin over the given
    /// transport, returning the response document.
    async fn initiate_chunked_over(
        confidentiality: super::super::transport::TransportConfidentiality,
    ) -> Value {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let uri: TypeUri = vta_sdk::trust_tasks::TASK_BACKUP_INITIATE_EXPORT_1_1
            .parse()
            .unwrap();
        let doc = TrustTask::new(
            "urn:uuid:test",
            uri,
            serde_json::json!({
                "algorithm": "chunkedTrustTask",
                "includeAudit": false,
                "password": "chunked-export-test-pw",
            }),
        );
        let auth = crate::test_support::super_admin_claims();
        // Boxed: this is one of the largest handler futures the VTA has, and
        // the dispatch seam boxes it the same way.
        let outcome = super::super::transport::with_confidentiality(
            confidentiality,
            Box::pin(handle_initiate_export_1_1(&state, &auth, doc)),
        )
        .await;
        serde_json::from_slice(&outcome.body).expect("a response document")
    }

    /// The sealing password travels in the request, so an export requested
    /// hop-by-hop is refused before any bundle is built.
    #[tokio::test]
    async fn a_backup_export_over_https_is_refused() {
        let doc =
            initiate_chunked_over(super::super::transport::TransportConfidentiality::HopByHop)
                .await;
        assert!(
            doc["payload"]["descriptor"].is_null(),
            "no bundle is minted: {doc}"
        );
        assert!(doc.to_string().contains("hop-by-hop"), "{doc}");
    }

    /// Over an end-to-end channel the export runs.
    #[tokio::test]
    async fn a_backup_export_over_an_end_to_end_channel_mints_a_bundle() {
        let doc =
            initiate_chunked_over(super::super::transport::TransportConfidentiality::EndToEnd)
                .await;
        assert!(
            doc["payload"]["descriptor"].is_object(),
            "expected a chunked bundle descriptor, got: {doc}"
        );
    }
}
