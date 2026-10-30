//! Context methods on [`VtaClient`].

use super::{
    ContextListResponse, ContextResponse, CreateContextRequest, UpdateContextRequest, VtaClient,
};
use crate::error::VtaError;

#[cfg(feature = "client")]
use crate::protocols::context_management;

#[cfg(feature = "client")]
impl VtaClient {
    pub async fn list_contexts(&self) -> Result<ContextListResponse, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_CONTEXTS_LIST_1_0,
            serde_json::json!({}),
            30,
        )
        .await
    }

    pub async fn get_context(&self, id: &str) -> Result<ContextResponse, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_CONTEXTS_GET_1_0,
            serde_json::json!({ "id": id }),
            30,
        )
        .await
    }

    pub async fn create_context(
        &self,
        req: CreateContextRequest,
    ) -> Result<ContextResponse, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            serde_json::to_value(&req)?,
            30,
        )
        .await
    }

    pub async fn update_context(
        &self,
        id: &str,
        req: UpdateContextRequest,
    ) -> Result<ContextResponse, VtaError> {
        // Built from the request struct rather than a `json!` literal, for two
        // reasons the literal got wrong.
        //
        // It named the members by hand and omitted `contextPolicy`, so a caller
        // setting a policy had it silently dropped — the field was accepted and
        // never sent. And it read `req.name`/`req.did`/`req.description`
        // directly, which bypasses their `skip_serializing_if` and emits
        // `null` for every unset one; the agent rejects that as
        // `malformedRequest`, since an absent optional must be ABSENT.
        let mut payload = serde_json::to_value(&req)?;
        match payload.as_object_mut() {
            Some(obj) => {
                obj.insert("id".into(), serde_json::Value::String(id.to_string()));
            }
            None => {
                return Err(VtaError::Protocol(
                    "update-context request did not serialize to an object".into(),
                ));
            }
        }
        self.rpc_tt(crate::trust_tasks::TASK_CONTEXTS_UPDATE_1_0, payload, 30)
            .await
    }

    /// Update the DID for a context. Requires Admin role with access to the context.
    ///
    /// Sent as `vta/contexts/update-did/1.1`, which requires `did` to be a DID
    /// (DID Core §3.1) — a malformed one is refused by the agent's schema check
    /// rather than stored as the context's identity.
    pub async fn update_context_did(
        &self,
        id: &str,
        did: impl Into<String>,
    ) -> Result<ContextResponse, VtaError> {
        let did = did.into();
        self.rpc_tt(
            crate::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_1,
            serde_json::json!({ "id": id, "did": &did }),
            30,
        )
        .await
    }

    /// Clear a context's DID, leaving it with no identity of its own — the
    /// state of a context created without one. Requires Admin role with access
    /// to the context.
    ///
    /// `vta/contexts/update-did/1.1` with `did: null`. The DID itself is not
    /// deleted; this is what lets `webvh/dids/delete` then proceed on a DID the
    /// context was acting as. Clearing a context with no DID succeeds.
    pub async fn clear_context_did(&self, id: &str) -> Result<ContextResponse, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_1,
            serde_json::json!({ "id": id, "did": null }),
            30,
        )
        .await
    }

    pub async fn preview_delete_context(
        &self,
        id: &str,
    ) -> Result<context_management::delete::DeleteContextPreviewResultBody, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0,
            serde_json::json!({ "id": id }),
            30,
        )
        .await
    }

    /// Delete a context over `vta/contexts/delete/1.1`, discarding the
    /// response.
    ///
    /// Host copies are required gone: a `did:webvh` log in the subtree whose
    /// hosting server cannot confirm removing it refuses the deletion
    /// (`vta/contexts/delete:hostCleanupFailed`) and nothing local is
    /// deleted, so there is never an orphan this method would have to hide.
    /// To complete such a deletion anyway, use
    /// [`delete_context_settling_hosts`](Self::delete_context_settling_hosts)
    /// with `abandon_host_copies` and surface its `daemon_cleanup_errors`.
    pub async fn delete_context(&self, id: &str, force: bool) -> Result<(), VtaError> {
        self.delete_context_settling_hosts(id, force, false)
            .await
            .map(|_| ())
    }

    /// Delete a context over `vta/contexts/delete/1.1`.
    ///
    /// The VTA removes every `did:webvh` host copy in the subtree **before**
    /// anything local. If one cannot be confirmed removed — the host is down,
    /// refuses, or is no longer registered — and `abandon_host_copies` is
    /// false, the call fails with a `vta/contexts/delete:hostCleanupFailed`
    /// rejection and nothing local is deleted; read the DIDs with
    /// [`host_cleanup_failures`](crate::protocols::context_management::delete::host_cleanup_failures),
    /// show them to the operator, then wait and retry or retry abandoning
    /// them. With `abandon_host_copies` the deletion completes and the
    /// abandoned copies come back in `daemon_cleanup_errors`.
    ///
    /// A VTA that predates 1.1 answers `unsupportedType`.
    pub async fn delete_context_settling_hosts(
        &self,
        id: &str,
        force: bool,
        abandon_host_copies: bool,
    ) -> Result<vti_specs::vta::contexts::delete::v1_1::Response, VtaError> {
        // 60s: the VTA spends up to 20s on hosts before it touches anything
        // local, then deletes the subtree.
        self.rpc_tt(
            crate::trust_tasks::TASK_CONTEXTS_DELETE_1_1,
            serde_json::json!({
                "id": id,
                "force": force,
                "abandonHostCopies": abandon_host_copies,
            }),
            60,
        )
        .await
    }
}
