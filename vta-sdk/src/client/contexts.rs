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
        // Built from the canonical body rather than a hand-rolled map. The map
        // emitted every member unconditionally, so an unset `name`/`did`/
        // `description` went out as `null` — and the published schema types
        // them as optional *strings*, which `null` is not. It validated only
        // while the registry had no schema for this task to check against.
        // Same defect, same fix, as `keys/create` (#919).
        let body = crate::protocols::context_management::update::UpdateContextBody {
            id: id.to_string(),
            name: req.name.clone(),
            did: req.did.clone(),
            description: req.description.clone(),
            ..Default::default()
        };
        self.rpc_tt(
            crate::trust_tasks::TASK_CONTEXTS_UPDATE_1_0,
            serde_json::to_value(&body)?,
            30,
        )
        .await
    }

    /// Update the DID for a context. Requires Admin role with access to the context.
    pub async fn update_context_did(
        &self,
        id: &str,
        did: impl Into<String>,
    ) -> Result<ContextResponse, VtaError> {
        let did = did.into();
        self.rpc_tt(
            crate::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
            serde_json::json!({ "id": id, "did": &did }),
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

    pub async fn delete_context(&self, id: &str, force: bool) -> Result<(), VtaError> {
        self.rpc_tt_void(
            crate::trust_tasks::TASK_CONTEXTS_DELETE_1_0,
            serde_json::json!({ "id": id, "force": force }),
            30,
        )
        .await
    }
}
