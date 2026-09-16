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
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::backup_management::descriptors::{
    AbortBundleBody, CompleteExportBody, FinalizeImportBody, InitiateExportBody, InitiateImportBody,
};

use crate::auth::AuthClaims;
use crate::operations::backup::descriptors;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with_code, success_response,
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
    let deps = crate::operations::descriptor_deps_from_app_state(state);
    // `include_audit` is read BEFORE the request moves into the op: it is the
    // one member that changes what leaves the agent — the trail records the
    // agent's dealings with counterparties who were never party to this export
    // — so an operator reviewing this row later needs it.
    let include_audit = req.include_audit;
    match descriptors::initiate_export(&deps, auth, req).await {
        Ok(body) => {
            record_bundle_event(
                state,
                auth,
                "backup.initiate-export",
                &body.descriptor.bundle_id,
                format!(
                    "includeAudit={include_audit} bytes={} expires={}",
                    body.descriptor.expected_size_bytes, body.descriptor.expires_at
                ),
            )
            .await;
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
    let deps = crate::operations::descriptor_deps_from_app_state(state);
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
    let deps = crate::operations::descriptor_deps_from_app_state(state);
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
    let deps = crate::operations::descriptor_deps_from_app_state(state);
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
    let deps = crate::operations::descriptor_deps_from_app_state(state);
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
}
