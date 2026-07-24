//! WebVH server + DID methods on [`VtaClient`].

use super::{
    AddWebvhServerRequest, CreateDidWebvhRequest, GetDidLogResponse, UpdateWebvhServerRequest,
    VtaClient, encode_path_segment,
};
use crate::error::VtaError;

#[cfg(feature = "client")]
use crate::protocols::did_management;
#[cfg(feature = "client")]
use crate::protocols::did_management::agent_name;

#[cfg(feature = "client")]
impl VtaClient {
    // ── WebVH server methods ──────────────────────────────────────────

    pub async fn add_webvh_server(
        &self,
        req: AddWebvhServerRequest,
    ) -> Result<crate::webvh::WebvhServerRecord, VtaError> {
        self.rpc(
            did_management::ADD_WEBVH_SERVER,
            serde_json::to_value(&req)?,
            did_management::ADD_WEBVH_SERVER_RESULT,
            30,
            |c, url| c.post(format!("{url}/webvh/servers")).json(&req),
        )
        .await
    }

    pub async fn list_webvh_servers(
        &self,
    ) -> Result<crate::protocols::did_management::servers::ListWebvhServersResultBody, VtaError>
    {
        self.rpc(
            did_management::LIST_WEBVH_SERVERS,
            serde_json::json!({}),
            did_management::LIST_WEBVH_SERVERS_RESULT,
            30,
            |c, url| c.get(format!("{url}/webvh/servers")),
        )
        .await
    }

    /// Fetch the registered hosting server's `/api/me/domains` view
    /// (caller-scoped subset of hosting domains, with the system
    /// default flagged). Used by `pnm did-mgmt list-domains` and the
    /// interactive `--domain` prompt in `create-did` /
    /// `register-did`. The VTA relays the call after authenticating
    /// to the server with its own credentials.
    pub async fn list_webvh_server_domains(
        &self,
        server_id: &str,
    ) -> Result<crate::protocols::did_management::servers::ListWebvhServerDomainsResultBody, VtaError>
    {
        self.rpc(
            did_management::LIST_WEBVH_SERVER_DOMAINS,
            serde_json::json!({ "server_id": server_id }),
            did_management::LIST_WEBVH_SERVER_DOMAINS_RESULT,
            30,
            |c, url| {
                c.get(format!(
                    "{url}/webvh/servers/{}/domains",
                    encode_path_segment(server_id)
                ))
            },
        )
        .await
    }

    pub async fn update_webvh_server(
        &self,
        id: &str,
        req: UpdateWebvhServerRequest,
    ) -> Result<crate::webvh::WebvhServerRecord, VtaError> {
        self.rpc(
            did_management::UPDATE_WEBVH_SERVER,
            serde_json::json!({ "id": id, "label": &req.label }),
            did_management::UPDATE_WEBVH_SERVER_RESULT,
            30,
            |c, url| {
                c.patch(format!("{url}/webvh/servers/{}", encode_path_segment(id)))
                    .json(&req)
            },
        )
        .await
    }

    pub async fn remove_webvh_server(&self, id: &str) -> Result<(), VtaError> {
        self.rpc_void(
            did_management::REMOVE_WEBVH_SERVER,
            serde_json::json!({ "id": id }),
            did_management::REMOVE_WEBVH_SERVER_RESULT,
            30,
            |c, url| c.delete(format!("{url}/webvh/servers/{}", encode_path_segment(id))),
        )
        .await
    }

    /// Promote a serverless WebVH DID to a server-managed one.
    ///
    /// The target server must already be registered via
    /// [`Self::add_webvh_server`]. The DID's local `did.jsonl` is
    /// pushed to the host and the local record's `server_id` flips
    /// to `server_id` so subsequent `update_did_webvh` calls
    /// (including the runtime `services` mutations) auto-publish
    /// there.
    ///
    /// Refused if the DID is already server-managed — re-pointing a
    /// hosted DID at a different server is a separate operation.
    pub async fn register_did_with_server(
        &self,
        did: &str,
        server_id: &str,
        force: bool,
        domain: Option<&str>,
    ) -> Result<crate::protocols::did_management::servers::RegisterDidWithServerResultBody, VtaError>
    {
        let body = crate::protocols::did_management::servers::RegisterDidWithServerBody {
            did: did.to_string(),
            server_id: server_id.to_string(),
            force,
            domain: domain.map(|d| d.to_string()),
        };
        self.rpc(
            did_management::REGISTER_DID_WITH_SERVER,
            serde_json::to_value(&body)?,
            did_management::REGISTER_DID_WITH_SERVER_RESULT,
            60,
            |c, url| {
                c.post(format!(
                    "{url}/webvh/dids/{}/register-server",
                    encode_path_segment(did)
                ))
                .json(&body)
            },
        )
        .await
    }

    // ── WebVH DID methods ──────────────────────────────────────────

    pub async fn create_did_webvh(
        &self,
        req: CreateDidWebvhRequest,
    ) -> Result<crate::protocols::did_management::create::CreateDidWebvhResultBody, VtaError> {
        self.rpc(
            did_management::CREATE_DID_WEBVH,
            serde_json::to_value(&req)?,
            did_management::CREATE_DID_WEBVH_RESULT,
            60,
            |c, url| c.post(format!("{url}/webvh/dids")).json(&req),
        )
        .await
    }

    pub async fn list_dids_webvh(
        &self,
        context_id: Option<&str>,
        server_id: Option<&str>,
    ) -> Result<crate::protocols::did_management::list::ListDidsWebvhResultBody, VtaError> {
        self.rpc(
            did_management::LIST_DIDS_WEBVH,
            serde_json::json!({
                "context_id": context_id,
                "server_id": server_id,
            }),
            did_management::LIST_DIDS_WEBVH_RESULT,
            30,
            |c, url| {
                let mut u = format!("{url}/webvh/dids");
                let mut sep = '?';
                if let Some(ctx) = context_id {
                    u.push_str(&format!("{sep}context_id={ctx}"));
                    sep = '&';
                }
                if let Some(srv) = server_id {
                    u.push_str(&format!("{sep}server_id={srv}"));
                }
                c.get(u)
            },
        )
        .await
    }

    pub async fn get_did_webvh(&self, did: &str) -> Result<crate::webvh::WebvhDidRecord, VtaError> {
        self.rpc(
            did_management::GET_DID_WEBVH,
            serde_json::json!({ "did": did }),
            did_management::GET_DID_WEBVH_RESULT,
            30,
            |c, url| c.get(format!("{url}/webvh/dids/{}", encode_path_segment(did))),
        )
        .await
    }

    pub async fn get_did_webvh_log(&self, did: &str) -> Result<GetDidLogResponse, VtaError> {
        self.rpc(
            did_management::GET_DID_WEBVH_LOG,
            serde_json::json!({ "did": did }),
            did_management::GET_DID_WEBVH_LOG_RESULT,
            30,
            |c, url| c.get(format!("{url}/webvh/dids/{}/log", encode_path_segment(did))),
        )
        .await
    }

    pub async fn delete_did_webvh(&self, did: &str) -> Result<(), VtaError> {
        self.rpc_void(
            did_management::DELETE_DID_WEBVH,
            serde_json::json!({ "did": did }),
            did_management::DELETE_DID_WEBVH_RESULT,
            60,
            |c, url| c.delete(format!("{url}/webvh/dids/{}", encode_path_segment(did))),
        )
        .await
    }

    /// Apply a generic update to an existing webvh DID.
    ///
    /// `ctx_id` is the context the DID lives in; `scid` is the
    /// stable component of the DID (e.g. the `Q...` segment of
    /// `did:webvh:Q...:host:slug`). REST path:
    /// `POST /contexts/{ctx_id}/dids/{scid}/update`.
    pub async fn update_did_webvh(
        &self,
        ctx_id: &str,
        scid: &str,
        body: crate::protocols::did_management::update::UpdateDidWebvhBody,
    ) -> Result<crate::protocols::did_management::update::UpdateDidWebvhResultBody, VtaError> {
        self.rpc(
            did_management::UPDATE_DID_WEBVH,
            serde_json::json!({
                "context_id": ctx_id,
                "scid": scid,
                "body": &body,
            }),
            did_management::UPDATE_DID_WEBVH_RESULT,
            60,
            |c, url| {
                c.post(format!(
                    "{url}/contexts/{}/dids/{}/update",
                    encode_path_segment(ctx_id),
                    encode_path_segment(scid)
                ))
                .json(&body)
            },
        )
        .await
    }

    /// Rotate every verificationMethod's keys on a webvh DID. Auth
    /// keys + pre-rotation rotate as a consequence of the resulting
    /// document update.
    pub async fn rotate_did_webvh_keys(
        &self,
        ctx_id: &str,
        scid: &str,
        body: crate::protocols::did_management::update::RotateDidWebvhKeysBody,
    ) -> Result<crate::protocols::did_management::update::UpdateDidWebvhResultBody, VtaError> {
        self.rpc(
            did_management::ROTATE_DID_WEBVH_KEYS,
            serde_json::json!({
                "context_id": ctx_id,
                "scid": scid,
                "body": &body,
            }),
            did_management::ROTATE_DID_WEBVH_KEYS_RESULT,
            60,
            |c, url| {
                c.post(format!(
                    "{url}/contexts/{}/dids/{}/rotate-keys",
                    encode_path_segment(ctx_id),
                    encode_path_segment(scid)
                ))
                .json(&body)
            },
        )
        .await
    }

    // ── Agent names ───────────────────────────────────────────────────
    //
    // An agent name is a human-memorable `domain/@name` that resolves to a
    // DID. Binding one edits the DID document's `alsoKnownAs` and republishes
    // the signed log — that claim is the *sole* authorisation for the hosting
    // server's `/@name` redirect, which is why every verb here goes through
    // the VTA rather than talking to the host directly: only the VTA can sign.
    //
    // These are trust-task-only by design — there is no bespoke REST route,
    // and none is needed: `dispatch_trust_task` posts to `/api/trust-tasks`
    // on a REST transport and rides the DIDComm envelope otherwise, so both
    // transports reach the same handler.

    /// Bind `name` to `did`, adding `https://{domain}/@{name}` to the
    /// document's `alsoKnownAs` and republishing.
    ///
    /// The hosting server refuses a binding whose document does not claim it,
    /// so a success here means the claim is live.
    pub async fn set_agent_name(
        &self,
        did: &str,
        name: &str,
    ) -> Result<agent_name::AgentNameResultBody, VtaError> {
        self.agent_name_verb(crate::trust_tasks::TASK_WEBVH_AGENT_NAME_SET_1_0, did, name)
            .await
    }

    /// Release `name` entirely, dropping the claim from the document.
    ///
    /// Distinct from [`disable_agent_name`](Self::disable_agent_name): remove
    /// frees the name for anyone else to claim, disable parks it so it stops
    /// resolving while staying reserved to this DID.
    pub async fn remove_agent_name(
        &self,
        did: &str,
        name: &str,
    ) -> Result<agent_name::AgentNameResultBody, VtaError> {
        self.agent_name_verb(
            crate::trust_tasks::TASK_WEBVH_AGENT_NAME_REMOVE_1_0,
            did,
            name,
        )
        .await
    }

    /// Stop `name` resolving while keeping it reserved to this DID.
    ///
    /// Drops the claim from the document — the reservation lives in the
    /// hosting server's registry, not in the DID.
    pub async fn disable_agent_name(
        &self,
        did: &str,
        name: &str,
    ) -> Result<agent_name::AgentNameResultBody, VtaError> {
        self.agent_name_verb(
            crate::trust_tasks::TASK_WEBVH_AGENT_NAME_DISABLE_1_0,
            did,
            name,
        )
        .await
    }

    /// Bring a parked name back into service, re-adding its claim.
    pub async fn enable_agent_name(
        &self,
        did: &str,
        name: &str,
    ) -> Result<agent_name::AgentNameResultBody, VtaError> {
        self.agent_name_verb(
            crate::trust_tasks::TASK_WEBVH_AGENT_NAME_ENABLE_1_0,
            did,
            name,
        )
        .await
    }

    /// Every name bound to `did`, including parked ones.
    ///
    /// Read live from the hosting control plane's registry, which is
    /// authoritative — a parked name is absent from the DID document by
    /// design, so the document alone cannot answer this.
    pub async fn list_agent_names(
        &self,
        did: &str,
    ) -> Result<agent_name::AgentNameListResultBody, VtaError> {
        self.dispatch_trust_task(
            crate::trust_tasks::TASK_WEBVH_AGENT_NAME_LIST_1_0,
            serde_json::json!({ "did": did }),
            30,
        )
        .await
        .and_then(|v| {
            serde_json::from_value(v)
                .map_err(|e| VtaError::Protocol(format!("agent-name list decode: {e}")))
        })
    }

    /// Whether `name` is free on the domain `did` is hosted under.
    ///
    /// Advisory only — the name can be taken between this call and a
    /// [`set_agent_name`](Self::set_agent_name), which is why `set` reports
    /// its own conflict rather than relying on a prior check.
    pub async fn check_agent_name(
        &self,
        did: &str,
        name: &str,
    ) -> Result<agent_name::AgentNameCheckResultBody, VtaError> {
        self.dispatch_trust_task(
            crate::trust_tasks::TASK_WEBVH_AGENT_NAME_CHECK_1_0,
            serde_json::json!({ "did": did, "name": name }),
            30,
        )
        .await
        .and_then(|v| {
            serde_json::from_value(v)
                .map_err(|e| VtaError::Protocol(format!("agent-name check decode: {e}")))
        })
    }

    /// The four mutating verbs share a body and differ only by task URI.
    async fn agent_name_verb(
        &self,
        task_uri: &str,
        did: &str,
        name: &str,
    ) -> Result<agent_name::AgentNameResultBody, VtaError> {
        // Republishing a signed log is slower than a plain read; the DID
        // document is rebuilt, re-signed and pushed to the host.
        let payload = self
            .dispatch_trust_task(
                task_uri,
                serde_json::json!({ "did": did, "name": name }),
                60,
            )
            .await?;
        serde_json::from_value(payload)
            .map_err(|e| VtaError::Protocol(format!("agent-name response decode: {e}")))
    }
}
