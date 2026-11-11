//! `did:webs` client methods (`vta/webs/dids/*/0.1`): persona, relationship and
//! integration DIDs on KERI, which the VTA creates, hosts on a did-hosting
//! server, updates, rotates and deactivates (docs/02-vta/did-webs.md). Alpha.
//!
//! Every method takes the task's generated payload type and returns its
//! generated response type (`vti_specs::vta::webs::dids`). Declared refusals
//! (`methodDisabled`, `hostDoesNotHostWebs`, `versionConflict`, …) arrive as
//! [`VtaError::Rejected`] with their code; [`webs_refusal_fix`] says what to do
//! about the ones an operator can fix.
//!
//! `create`, `update` and `rotate-keys` each append to a public key event log,
//! so a lost reply must not become a second execution: a caller retrying them
//! wraps the call in [`VtaClient::idempotent`].

use vti_specs::vta::webs::dids;

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds): a write publishes to the hosting server.
const WEBS_TT_TIMEOUT: u64 = 60;

impl VtaClient {
    async fn webs_call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        uri: &str,
        payload: &P,
    ) -> Result<R, VtaError> {
        let payload = serde_json::to_value(payload)
            .map_err(|e| VtaError::Validation(format!("{uri} request: {e}")))?;
        let answer = self
            .dispatch_trust_task(uri, payload, WEBS_TT_TIMEOUT)
            .await?;
        serde_json::from_value(answer).map_err(|e| {
            VtaError::Protocol(format!("{uri} response does not match its schema: {e}"))
        })
    }

    /// `vta/webs/dids/create/0.1` — create a did:webs in a context and publish
    /// it to a hosting server.
    pub async fn create_did_webs(
        &self,
        req: &dids::create::v0_1::Payload,
    ) -> Result<dids::create::v0_1::Response, VtaError> {
        self.webs_call(trust_tasks::TASK_VTA_WEBS_DIDS_CREATE_0_1, req)
            .await
    }

    /// `vta/webs/dids/get/0.1` — the VTA's record of a did:webs it holds.
    pub async fn get_did_webs(
        &self,
        req: &dids::get::v0_1::Payload,
    ) -> Result<dids::get::v0_1::Response, VtaError> {
        self.webs_call(trust_tasks::TASK_VTA_WEBS_DIDS_GET_0_1, req)
            .await
    }

    /// `vta/webs/dids/list/0.1` — the did:webs records the caller may see. A
    /// page carrying `nextCursor` is not the whole listing.
    pub async fn list_dids_webs(
        &self,
        req: &dids::list::v0_1::Payload,
    ) -> Result<dids::list::v0_1::Response, VtaError> {
        self.webs_call(trust_tasks::TASK_VTA_WEBS_DIDS_LIST_0_1, req)
            .await
    }

    /// `vta/webs/dids/update/0.1` — replace designated services, the key
    /// agreement key or the aliases, without changing keys.
    pub async fn update_did_webs(
        &self,
        req: &dids::update::v0_1::Payload,
    ) -> Result<dids::update::v0_1::Response, VtaError> {
        self.webs_call(trust_tasks::TASK_VTA_WEBS_DIDS_UPDATE_0_1, req)
            .await
    }

    /// `vta/webs/dids/rotate-keys/0.1` — rotate to the committed successor key.
    pub async fn rotate_did_webs_keys(
        &self,
        req: &dids::rotate_keys::v0_1::Payload,
    ) -> Result<dids::rotate_keys::v0_1::Response, VtaError> {
        self.webs_call(trust_tasks::TASK_VTA_WEBS_DIDS_ROTATE_KEYS_0_1, req)
            .await
    }

    /// `vta/webs/dids/delete/0.1` — deactivate the DID for good and remove its
    /// slot from the host.
    pub async fn delete_did_webs(
        &self,
        req: &dids::delete::v0_1::Payload,
    ) -> Result<dids::delete::v0_1::Response, VtaError> {
        self.webs_call(trust_tasks::TASK_VTA_WEBS_DIDS_DELETE_0_1, req)
            .await
    }
}

/// What an operator does about a `vta/webs/dids/*` refusal, when it is one they
/// can fix. `None` for any other error.
pub fn webs_refusal_fix(e: &VtaError) -> Option<&'static str> {
    let code = e.rejection_code()?;
    Some(match code.rsplit(':').next()? {
        "methodDisabled" => {
            "did:webs creation is off on this VTA (alpha). Turn it on with \
             `webs_enabled = true` under `[dids]` in the VTA's config (or \
             VTA_DIDS_WEBS_ENABLED=true) and restart it."
        }
        "hostDoesNotHostWebs" => {
            "the hosting server was built without did:webs support: rebuild or run it with \
             its `method-webs` feature, or publish to a server that has it."
        }
        "serverNotFound" => {
            "no hosting server by that id is registered: list them with \
             `pnm webvh servers list`, or add one with `pnm webvh servers add`."
        }
        "domainNotServed" => {
            "the hosting server does not serve that domain for this VTA: see \
             `pnm webvh servers domains <server-id>`, or leave `--domain` out to use its \
             default."
        }
        "versionConflict" => {
            "the DID has changed since the version you named: read it again with \
             `pnm webs get <did>` and retry with its `versionId`."
        }
        "serviceDidNotPermitted" => {
            "a did:webs cannot be a node's service identity (VTI-KEY-001): leave \
             `--set-primary` off for that context, or use did:webvh."
        }
        "deactivated" => "the DID is deactivated; nothing more can change it.",
        _ => return None,
    })
}
