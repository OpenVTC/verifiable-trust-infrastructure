//! A group's identity and its authority, held by the community's VTA
//! (`vtc/groups/create` steps 1 – 2).
//!
//! The VTA mints the group's `did:webvh` from the `vtc-group` template and signs,
//! as the community, the authority credential the community issues the group
//! (`keys/sign-document`), so this community never holds a group key and never
//! falls back to one (`noKeyHolder`). It reaches the VTA over the link it
//! already keeps for the rooms it owns.
//!
//! The authority credential carries a slot in the community's own revocation
//! list, flipped when the group is deleted (`vtc/groups/delete` item 3), and an
//! expiry, renewed well before it lapses (create item 5).

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;

use super::{Authority, GROUP_DID_PATH, did_log_key};
use crate::credentials::vmc::CredentialStatusRef;
use crate::rooms::community::{HolderError, KeyHolder, SIGN_TIMEOUT};
use crate::server::AppState;
use crate::status_list;

/// The action the community's authority credential grants a group: issuing its
/// own members' membership credentials, within the community.
pub const GROUP_AUTHORITY_ACTION: &str = "issue-membership";

/// Where a group identity's log is published.
#[derive(Debug, Clone)]
pub enum Publish {
    /// By a hosting server registered at the VTA, by its id there.
    Server(String),
    /// By this service, under its public URL.
    Served { public_url: String },
}

/// Everything a group's identity needs from configuration.
#[derive(Clone)]
pub struct Setup {
    pub holder: KeyHolder,
    pub community_did: String,
    /// The VTA key the community signs with, by its id there.
    pub community_key_id: String,
    pub context: String,
    pub publish: Publish,
    pub authority_days: u32,
}

/// What to configure when the community cannot hold a group's keys: the
/// message of a `noKeyHolder`.
pub async fn setup(state: &AppState) -> Result<Setup, String> {
    let config = state.config.read().await;
    let Some(groups) = config.groups.clone() else {
        return Err(
            "this community has no groups until its operator turns them on: add a `[groups]` \
             section naming the context at the community's VTA the groups' keys are minted in \
             (`context = \"<context id>\"`), and restart"
                .into(),
        );
    };
    let Some(holder) = state.community_rooms.key_holder() else {
        return Err(
            "this community has no link to a VTA that can hold the group's keys: set `vta_did`, \
             the community's signing key and `[messaging]`, and restart"
                .into(),
        );
    };
    let Some(community_did) = config.vtc_did.clone().filter(|d| !d.is_empty()) else {
        return Err("this community has no DID yet".into());
    };
    let Some(signer) = state.credential_signer.as_ref() else {
        return Err("this community has no signing key to name at its VTA".into());
    };
    let context = groups
        .context
        .clone()
        .or_else(|| config.rooms.community.as_ref().map(|c| c.context.clone()))
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            "a group's keys are minted in a context at the community's VTA: set `[groups] \
             context`, or `[rooms.community] context`"
                .to_string()
        })?;
    let publish = match (&groups.webvh_server, &config.public_url) {
        (Some(server), _) => Publish::Server(server.clone()),
        (None, Some(url)) => Publish::Served {
            public_url: url.trim_end_matches('/').to_string(),
        },
        (None, None) => {
            return Err(
                "a group's identity is served from this community's public URL unless `[groups] \
                 webvh_server` names a hosting server at the VTA: set `public_url`, or \
                 `webvh_server`"
                    .into(),
            );
        }
    };
    Ok(Setup {
        holder,
        community_did,
        community_key_id: signer.assertion_method_id().to_string(),
        context,
        publish,
        authority_days: groups.authority_valid_days(),
    })
}

/// Why minting a group's identity or authority did not complete.
#[derive(Debug)]
pub enum Failure {
    /// Nothing reached the VTA, or this service failed after.
    Local(AppError),
    /// The VTA did not answer, or refused; the DID it minted, when it did.
    Holder(HolderError, Option<String>),
}

/// A group identity the VTA minted, with its authority.
#[derive(Debug, Clone)]
pub struct Minted {
    pub group_did: String,
    pub signing_key_id: String,
    pub did_log_path: Option<String>,
    pub authority: Option<(Authority, Value)>,
}

fn read<T: serde::de::DeserializeOwned>(what: &str, v: Value) -> Result<T, HolderError> {
    serde_json::from_value(v)
        .map_err(|e| HolderError::Unavailable(format!("{what} answered a shape not its own: {e}")))
}

/// Steps 1 and 2 of `vtc/groups/create`: mint the group's DID, and where it
/// issues credentials, the community's authority credential to it. A DID log
/// this service serves is published before anything verifies against the DID,
/// and withdrawn when a later step fails.
pub async fn mint(
    state: &AppState,
    setup: &Setup,
    issues_credentials: bool,
) -> Result<Minted, Failure> {
    let did_path = match &setup.publish {
        Publish::Served { .. } => Some(uuid::Uuid::new_v4().simple().to_string()),
        Publish::Server(_) => None,
    };
    let webvh_server = match &setup.publish {
        Publish::Served { public_url } => public_url.clone(),
        Publish::Server(id) => id.clone(),
    };
    // A label at the VTA only: the group's name is never in its DID document,
    // nor anywhere the VTA publishes. No transport either, said explicitly: the
    // `vtc-group` template carries no service (nothing delivers messages to a
    // group yet), and a VTA left to its own default would try to add `#tsp`
    // at a mediator the document does not name.
    let mut request = json!({
        "contextId": setup.context,
        "template": "vtc-group",
        "templateVars": { "WEBVH_SERVER": webvh_server },
        "setPrimary": false,
        "label": "Community group",
        "addMediatorService": false,
        "addTspService": false,
    });
    match (&setup.publish, &did_path) {
        (Publish::Server(id), _) => request["serverId"] = json!(id),
        (Publish::Served { public_url }, Some(path)) => {
            request["url"] = json!(format!("{public_url}/{GROUP_DID_PATH}/{path}/did.jsonl"))
        }
        (Publish::Served { .. }, None) => unreachable!("a served identity always has a path"),
    }
    let request: vta_sdk::protocols::did_management::create::CreateDidWebvhBody =
        serde_json::from_value(request)
            .map_err(|e| Failure::Local(AppError::Internal(format!("webvh/dids/create: {e}"))))?;
    let request = serde_json::to_value(request)
        .map_err(|e| Failure::Local(AppError::Internal(format!("webvh/dids/create: {e}"))))?;
    let answer = setup
        .holder
        .ask(
            vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_1,
            request,
            SIGN_TIMEOUT,
        )
        .await
        .map_err(|e| Failure::Holder(e, None))?;
    let minted: vta_sdk::protocols::did_management::create::CreateDidWebvhResultBody =
        read("webvh/dids/create", answer).map_err(|e| Failure::Holder(e, None))?;
    let group_did = minted.did.clone();

    if let Some(path) = &did_path {
        let Some(log) = minted.log_entry.as_deref() else {
            return Err(Failure::Holder(
                HolderError::Unavailable(
                    "the community's VTA minted the group's identity serverless and returned no \
                     log"
                    .into(),
                ),
                Some(group_did),
            ));
        };
        put_did_log(state, path, &group_did, log)
            .await
            .map_err(Failure::Local)?;
    }

    let authority = if issues_credentials {
        match issue_authority(state, setup, &group_did, Utc::now(), None).await {
            Ok(a) => Some(a),
            Err(e) => {
                if let Some(path) = &did_path {
                    let _ = remove_did_log(state, path).await;
                }
                return Err(match e {
                    Failure::Holder(h, _) => Failure::Holder(h, Some(group_did)),
                    other => other,
                });
            }
        }
    } else {
        None
    };
    Ok(Minted {
        group_did,
        signing_key_id: minted.signing_key_id,
        did_log_path: did_path,
        authority,
    })
}

/// The community's authority credential to `group_did`, signed by its VTA as
/// the community: a DTG `AuthorityCredential` granting
/// [`GROUP_AUTHORITY_ACTION`] within the community, with a slot in the
/// community's revocation list. Answers what this community keeps of it, and
/// the signed credential.
///
/// `slot` is the slot a renewal reuses: every authority a group is ever issued
/// shares one, so deleting the group revokes them all with one bit. `None`
/// allocates a fresh one.
pub async fn issue_authority(
    state: &AppState,
    setup: &Setup,
    group_did: &str,
    valid_from: DateTime<Utc>,
    slot: Option<u32>,
) -> Result<(Authority, Value), Failure> {
    let valid_until = valid_from + Duration::days(i64::from(setup.authority_days));
    let slot = status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        move |row| {
            let slot = match slot {
                Some(slot) => Some(slot),
                None => status_list::allocate(row),
            };
            Ok(slot.map(|slot| (slot, row.list_credential_id.clone())))
        },
    )
    .await
    .map_err(Failure::Local)?;
    let Some((slot, list_credential_id)) = slot else {
        return Err(Failure::Local(AppError::Internal(
            "revocation status list is full — cannot allocate a slot for a group's authority"
                .into(),
        )));
    };
    let dtg = dtg_credentials::DTGCredential::new_vac(
        setup.community_did.clone(),
        dtg_credentials::IssuerScope::Public,
        group_did.to_string(),
        setup.community_did.clone(),
        vec![GROUP_AUTHORITY_ACTION.to_string()],
        valid_from,
        valid_until,
    )
    .map_err(|e| Failure::Local(AppError::Validation(format!("group authority: {e}"))))?;
    dtg.validate().map_err(|e| {
        Failure::Local(AppError::Validation(format!(
            "group authority is not conformant: {e}"
        )))
    })?;
    let mut document = serde_json::to_value(dtg.credential())
        .map_err(|e| Failure::Local(AppError::Internal(format!("group authority: {e}"))))?;
    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    document["id"] = json!(credential_id);
    document["credentialStatus"] =
        serde_json::to_value(CredentialStatusRef::revocation(list_credential_id, slot))
            .map_err(|e| Failure::Local(AppError::Internal(format!("credentialStatus: {e}"))))?;

    let answer = setup
        .holder
        .ask(
            vta_sdk::trust_tasks::TASK_KEYS_SIGN_DOCUMENT_0_1,
            json!({ "keyId": setup.community_key_id, "document": document }),
            SIGN_TIMEOUT,
        )
        .await
        .map_err(|e| Failure::Holder(e, None))?;
    let signed: vta_sdk::protocols::key_management::sign_document::SignDocumentResponse =
        read("keys/sign-document", answer).map_err(|e| Failure::Holder(e, None))?;
    Ok((
        Authority {
            credential_id,
            valid_until,
            status_list_index: slot,
        },
        Value::Object(signed.document),
    ))
}

/// Revoke a group's authority credential in the community's revocation list.
pub async fn revoke_authority(state: &AppState, authority: &Authority) -> Result<(), AppError> {
    let slot = authority.status_list_index;
    status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        move |row| {
            status_list::flip(row, slot, true)
                .map_err(|e| AppError::Internal(format!("flip status-list bit {slot}: {e}")))
        },
    )
    .await
}

#[derive(Serialize, Deserialize)]
struct DidLog {
    did: String,
    log: String,
}

pub async fn put_did_log(
    state: &AppState,
    path: &str,
    did: &str,
    log: &str,
) -> Result<(), AppError> {
    state
        .directory
        .ks()
        .insert(
            did_log_key(path),
            &DidLog {
                did: did.to_string(),
                log: log.to_string(),
            },
        )
        .await
}

pub async fn remove_did_log(state: &AppState, path: &str) -> Result<(), AppError> {
    state.directory.ks().remove(did_log_key(path)).await
}

/// Whether `id` is a path segment this service could have issued: hex.
fn plain_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `GET /group-dids/{id}/did.jsonl` — the log of a group identity this
/// community minted serverless. Public: a resolver carries no credential, and a
/// `did:webvh` log is published by design. It names no group.
pub async fn serve_group_did_log(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !plain_id(&id) {
        return (StatusCode::NOT_FOUND, "did log not found").into_response();
    }
    match state.directory.ks().get::<DidLog>(did_log_key(&id)).await {
        Ok(Some(l)) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/jsonl; charset=utf-8"),
            )],
            l.log,
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "did log not found").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "could not read a group identity's log");
            (StatusCode::INTERNAL_SERVER_ERROR, "did log unavailable").into_response()
        }
    }
}

/// Whether `path` is a group identity's log this service may serve: the
/// surface gate lets it through on every host, as it does a room identity's.
pub fn is_group_did_log_path(path: &str) -> bool {
    path.strip_prefix(&format!("/{GROUP_DID_PATH}/"))
        .and_then(|rest| rest.strip_suffix("/did.jsonl"))
        .is_some_and(plain_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_served_group_log_path_passes_the_surface_gate() {
        assert!(is_group_did_log_path("/group-dids/0a1b2c/did.jsonl"));
        assert!(!is_group_did_log_path("/group-dids/../did.jsonl"));
        assert!(!is_group_did_log_path("/group-dids/0a1b2c/other"));
        assert!(!is_group_did_log_path("/room-dids/0a1b2c/did.jsonl"));
    }
}
