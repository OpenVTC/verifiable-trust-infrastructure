//! `POST /v1/admin/did/register` — a self-hosted community installs a delivered
//! log for its own DID (`did-management/did/register/0.1`, Keyring VTI-35).
//!
//! `register` is the task a DID owner sends a DID host to publish a log, and a
//! second register from the owner with a longer log is an update. A community
//! that self-hosts its DID is that host for exactly one DID, so this answers
//! `register` for that one, at the root slot `.well-known` — the only path a
//! serverless `did:webvh:<scid>:<host>` resolves at, and the only one
//! `routes::did_log` serves. Everything else is refused rather than stored
//! somewhere no resolver reads.
//!
//! What is verified, and why an administrator cannot use this to publish a
//! document the key holder did not sign, is in [`crate::did_log_install`].

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use tracing::info;
use trust_tasks_rs::specs::did_management::did::register::v0_1::{
    DidRecord, PayloadDidData, Response,
};
use vta_sdk::openapi::{DidRegister01Payload, DidRegister01Response};
use vti_common::audit::{AuditEvent, CommunityDidLogInstalledData};
use vti_common::error::AppError;

use crate::auth::SuperAdminAuth;
use crate::did_log_install::{self, InstallError, InstallRefusal};
use crate::routes::did_log::did_log_label;
use crate::server::AppState;

/// The only slot a self-hosted community serves: the root.
const ROOT_SLOT: &str = ".well-known";

/// The host a root `did:webvh:<scid>:<host>` resolves at, with `%3A` decoded
/// to the port separator. `None` for anything with a path — such a DID is
/// published by a DID host, not by this community.
fn root_host(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:webvh:")?;
    let mut parts = rest.split(':');
    let _scid = parts.next().filter(|s| !s.is_empty())?;
    let host = parts.next().filter(|s| !s.is_empty())?;
    if parts.next().is_some() {
        return None;
    }
    Some(host.replace("%3A", ":").replace("%3a", ":"))
}

fn refused(r: InstallRefusal) -> AppError {
    // REST carries a status and a message; the message leads with the code a
    // Trust-Task client keys on. `notAnExtension` is this consumer's own
    // stricter rule — `register` alone would accept a shorter or forked log
    // from the owner — so it carries a consumer-minted code (SPEC §8.5).
    match r {
        InstallRefusal::InvalidLog(_) => {
            AppError::Validation(format!("did-management/did/register:invalidLog: {r}"))
        }
        InstallRefusal::WrongDid { .. } => {
            AppError::Validation(format!("did-management/did/register:hostMismatch: {r}"))
        }
        InstallRefusal::NotAnExtension(_) => {
            AppError::Conflict(format!("org.openvtc.vtc:didLogNotAnExtension: {r}"))
        }
        InstallRefusal::NotServedHere(_) => {
            AppError::NotFound(format!("org.openvtc.vtc:didLogNotSelfHosted: {r}"))
        }
    }
}

/// Install a delivered log for this community's own self-hosted DID.
///
/// `utoipa::ToSchema` cannot be derived on a foreign type, so the body and the
/// response are the `vta_sdk::openapi` wrappers around the generated types.
#[utoipa::path(
    post, path = "/admin/did/register",
    operation_id = "didRegister", tag = "admin",
    security(("bearer_jwt" = [])),
    request_body = DidRegister01Payload,
    responses(
        (status = 200, description = "Log verified and now served", body = DidRegister01Response),
        (status = 400, description = "Log does not verify, is for another DID, or targets another slot"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 404, description = "This community does not self-host its DID"),
        (status = 409, description = "Log does not keep every served entry unchanged"),
    ),
)]
pub async fn register(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(body): Json<DidRegister01Payload>,
) -> Result<Json<DidRegister01Response>, AppError> {
    let payload = body.into_inner();
    if payload.method.as_str() != "webvh" {
        return Err(AppError::Validation(format!(
            "did-management/did/register:invalidLog: a community self-hosts a did:webvh log; \
             method `{}` is not one",
            payload.method.as_str()
        )));
    }
    let PayloadDidData::String(log) = &payload.did_data else {
        return Err(AppError::Validation(
            "did-management/did/register:invalidLog: a webvh `didData` is the log as JSON Lines \
             text"
                .into(),
        ));
    };

    let (did, path) = {
        let config = state.config.read().await;
        let did = config.vtc_did.clone().ok_or_else(|| {
            refused(InstallRefusal::NotServedHere(
                "this community has no DID yet".into(),
            ))
        })?;
        let label = did_log_label(&did);
        let path = label.map(|l| config.store.data_dir.join("did").join(format!("{l}.jsonl")));
        (did, path)
    };

    let host = root_host(&did).ok_or_else(|| {
        refused(InstallRefusal::NotServedHere(format!(
            "{did} has a path, so a DID host publishes it; send the new entry there"
        )))
    })?;
    if payload.path.as_str() != ROOT_SLOT {
        return Err(AppError::Validation(format!(
            "did-management/did/register:hostMismatch: this community serves one slot, `{ROOT_SLOT}`, \
             not `{}`",
            payload.path.as_str()
        )));
    }
    if let Some(domain) = payload.domain.as_deref()
        && domain != host
    {
        return Err(AppError::Validation(format!(
            "did-management/did/register:hostMismatch: this community serves {host}, not {domain}"
        )));
    }
    let path = path.ok_or_else(|| {
        refused(InstallRefusal::NotServedHere(format!(
            "{did} has no servable log label"
        )))
    })?;

    let accepted = match did_log_install::install(&did, &path, log.as_str()).await {
        Ok(a) => a,
        Err(InstallError::Refused(r)) => return Err(refused(r)),
        Err(InstallError::Io(e)) => return Err(AppError::Io(e)),
    };

    if accepted.entries_added > 0 {
        if let Some(writer) = state.audit_writer.as_ref() {
            writer
                .write(
                    &auth.0.did,
                    None,
                    AuditEvent::CommunityDidLogInstalled(CommunityDidLogInstalledData {
                        did: did.clone(),
                        version_id: accepted.version_id.clone(),
                        previous_version_id: accepted.previous_version_id.clone(),
                        entries_added: accepted.entries_added as u64,
                    }),
                )
                .await?;
        }
        info!(
            %did,
            version_id = %accepted.version_id,
            entries_added = accepted.entries_added,
            "installed a delivered DID log"
        );
    }

    let now = Utc::now();
    let created = accepted
        .created
        .as_deref()
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or(now);
    // The slot's owner is the key holder — this community's VTA — whoever
    // delivered the log; the log's own proofs are what make it the owner's.
    let owner = state
        .config
        .read()
        .await
        .vta_did
        .clone()
        .unwrap_or_else(|| did.clone());
    let record: DidRecord = DidRecord::builder()
        .mnemonic(ROOT_SLOT.to_string())
        .owner(owner)
        .created_at(created)
        .updated_at(now)
        .version_count(accepted.entry_count as u64)
        .did_id(Some(did.clone()))
        .did_url(Some(format!("https://{host}/{ROOT_SLOT}/did.jsonl")))
        .method(Some("webvh".to_string()))
        .domain(Some(host))
        .disabled(Some(false))
        .try_into()
        .map_err(|e| AppError::Internal(format!("build DidRecord: {e}")))?;
    let response: Response = Response::builder()
        .record(record)
        .try_into()
        .map_err(|e| AppError::Internal(format!("build register response: {e}")))?;
    Ok(Json(response.into()))
}

#[cfg(test)]
mod tests {
    use super::root_host;

    #[test]
    fn only_a_root_did_is_self_hosted() {
        assert_eq!(
            root_host("did:webvh:Qm:vtc.example.com").as_deref(),
            Some("vtc.example.com")
        );
        assert_eq!(
            root_host("did:webvh:Qm:localhost%3A8100").as_deref(),
            Some("localhost:8100")
        );
        // A path means a DID host publishes it.
        assert_eq!(root_host("did:webvh:Qm:dids.example.com:vtc"), None);
        assert_eq!(root_host("did:key:z6Mk"), None);
    }
}
