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
