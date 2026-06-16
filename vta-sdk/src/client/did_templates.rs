//! DID-template management methods on [`VtaClient`] (global + context scope).
//!
//! **Transport model.** On the REST transport these hit the dedicated
//! `/did-templates` (and `/contexts/{id}/did-templates`) routes. On the
//! DIDComm transport there is no raw protocol surface — the VTA exposes
//! template management only through its Trust-Task dispatcher, so the DIDComm
//! leg dispatches the `trusttasks.org/spec/vta/did-templates/*` (and
//! `.../contexts/did-templates/*`) Trust Tasks via the binding envelope. Both
//! legs are wired through [`VtaClient::rpc_tt`] / [`VtaClient::rpc_tt_void`].

use std::collections::HashMap;

use serde_json::Value;

use super::{VtaClient, encode_path_segment};
use crate::did_templates::{DidTemplate, DidTemplateRecord};
use crate::error::VtaError;
use crate::protocols::did_template_management as proto;
use crate::trust_tasks;

impl VtaClient {
    // ── DID templates — global scope ─────────────────────────────────────

    /// List all global templates.
    ///
    /// REST: `GET /did-templates`. DIDComm: `vta/did-templates/list/1.0`.
    pub async fn list_did_templates(&self) -> Result<Vec<DidTemplateRecord>, VtaError> {
        let resp: proto::list::ListDidTemplatesResultBody = self
            .rpc_tt(
                trust_tasks::TASK_DID_TEMPLATES_LIST_1_0,
                serde_json::to_value(proto::list::ListDidTemplatesBody::default())?,
                30,
                |c, url| c.get(format!("{url}/did-templates")),
            )
            .await?;
        Ok(resp.templates)
    }

    /// Fetch one global template by name.
    ///
    /// REST: `GET /did-templates/{name}`. DIDComm: `vta/did-templates/get/1.0`.
    pub async fn get_did_template(&self, name: &str) -> Result<DidTemplateRecord, VtaError> {
        self.rpc_tt(
            trust_tasks::TASK_DID_TEMPLATES_GET_1_0,
            serde_json::to_value(proto::get::GetDidTemplateBody {
                name: name.to_string(),
            })?,
            30,
            |c, url| c.get(format!("{url}/did-templates/{}", encode_path_segment(name))),
        )
        .await
    }

    /// Create a global template. Super admin only.
    ///
    /// REST: `POST /did-templates`. DIDComm: `vta/did-templates/create/1.0`.
    pub async fn create_did_template(
        &self,
        template: DidTemplate,
    ) -> Result<DidTemplateRecord, VtaError> {
        let payload = serde_json::to_value(proto::create::CreateDidTemplateBody {
            template: template.clone(),
        })?;
        self.rpc_tt(
            trust_tasks::TASK_DID_TEMPLATES_CREATE_1_0,
            payload,
            30,
            |c, url| c.post(format!("{url}/did-templates")).json(&template),
        )
        .await
    }

    /// Replace a global template. Super admin only.
    ///
    /// REST: `PUT /did-templates/{name}`. DIDComm: `vta/did-templates/update/1.0`.
    pub async fn update_did_template(
        &self,
        name: &str,
        template: DidTemplate,
    ) -> Result<DidTemplateRecord, VtaError> {
        let payload = serde_json::to_value(proto::update::UpdateDidTemplateBody {
            name: name.to_string(),
            template: template.clone(),
        })?;
        self.rpc_tt(
            trust_tasks::TASK_DID_TEMPLATES_UPDATE_1_0,
            payload,
            30,
            |c, url| {
                c.put(format!("{url}/did-templates/{}", encode_path_segment(name)))
                    .json(&template)
            },
        )
        .await
    }

    /// Delete a global template. Super admin only.
    ///
    /// REST: `DELETE /did-templates/{name}`. DIDComm: `vta/did-templates/delete/1.0`.
    pub async fn delete_did_template(&self, name: &str) -> Result<(), VtaError> {
        self.rpc_tt_void(
            trust_tasks::TASK_DID_TEMPLATES_DELETE_1_0,
            serde_json::to_value(proto::delete::DeleteDidTemplateBody {
                name: name.to_string(),
            })?,
            30,
            |c, url| c.delete(format!("{url}/did-templates/{}", encode_path_segment(name))),
        )
        .await
    }

    /// Render a stored global template with caller variables.
    ///
    /// Server injects ambient variables (`VTA_DID`, `VTA_URL`, `NOW`);
    /// `vars` provides everything else.
    ///
    /// REST: `POST /did-templates/{name}/render`. DIDComm:
    /// `vta/did-templates/render/1.0`.
    pub async fn render_did_template(
        &self,
        name: &str,
        vars: HashMap<String, Value>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(proto::render::RenderDidTemplateBody {
            name: name.to_string(),
            vars: vars.clone(),
        })?;
        let resp: proto::render::RenderDidTemplateResultBody = self
            .rpc_tt(
                trust_tasks::TASK_DID_TEMPLATES_RENDER_1_0,
                payload,
                30,
                |c, url| {
                    c.post(format!(
                        "{url}/did-templates/{}/render",
                        encode_path_segment(name)
                    ))
                    .json(&serde_json::json!({ "vars": vars }))
                },
            )
            .await?;
        Ok(resp.document)
    }

    // ── DID templates — context scope ────────────────────────────────────

    /// List context-scoped templates.
    ///
    /// REST: `GET /contexts/{id}/did-templates`. DIDComm:
    /// `vta/contexts/did-templates/list/1.0`.
    pub async fn list_context_did_templates(
        &self,
        context_id: &str,
    ) -> Result<Vec<DidTemplateRecord>, VtaError> {
        let resp: proto::list::ListDidTemplatesResultBody = self
            .rpc_tt(
                trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_LIST_1_0,
                serde_json::to_value(proto::list::ListContextDidTemplatesBody {
                    context_id: context_id.to_string(),
                })?,
                30,
                |c, url| {
                    c.get(format!(
                        "{url}/contexts/{}/did-templates",
                        encode_path_segment(context_id)
                    ))
                },
            )
            .await?;
        Ok(resp.templates)
    }

    /// Fetch one context-scoped template.
    ///
    /// REST: `GET /contexts/{id}/did-templates/{name}`. DIDComm:
    /// `vta/contexts/did-templates/get/1.0`.
    pub async fn get_context_did_template(
        &self,
        context_id: &str,
        name: &str,
    ) -> Result<DidTemplateRecord, VtaError> {
        self.rpc_tt(
            trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_GET_1_0,
            serde_json::to_value(proto::get::GetContextDidTemplateBody {
                context_id: context_id.to_string(),
                name: name.to_string(),
            })?,
            30,
            |c, url| {
                c.get(format!(
                    "{url}/contexts/{}/did-templates/{}",
                    encode_path_segment(context_id),
                    encode_path_segment(name)
                ))
            },
        )
        .await
    }

    /// Create a context-scoped template. Context admin or super admin.
    ///
    /// REST: `POST /contexts/{id}/did-templates`. DIDComm:
    /// `vta/contexts/did-templates/create/1.0`.
    pub async fn create_context_did_template(
        &self,
        context_id: &str,
        template: DidTemplate,
    ) -> Result<DidTemplateRecord, VtaError> {
        let payload = serde_json::to_value(proto::create::CreateContextDidTemplateBody {
            context_id: context_id.to_string(),
            template: template.clone(),
        })?;
        self.rpc_tt(
            trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_CREATE_1_0,
            payload,
            30,
            |c, url| {
                c.post(format!(
                    "{url}/contexts/{}/did-templates",
                    encode_path_segment(context_id)
                ))
                .json(&template)
            },
        )
        .await
    }

    /// Replace a context-scoped template.
    ///
    /// REST: `PUT /contexts/{id}/did-templates/{name}`. DIDComm:
    /// `vta/contexts/did-templates/update/1.0`.
    pub async fn update_context_did_template(
        &self,
        context_id: &str,
        name: &str,
        template: DidTemplate,
    ) -> Result<DidTemplateRecord, VtaError> {
        let payload = serde_json::to_value(proto::update::UpdateContextDidTemplateBody {
            context_id: context_id.to_string(),
            name: name.to_string(),
            template: template.clone(),
        })?;
        self.rpc_tt(
            trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_UPDATE_1_0,
            payload,
            30,
            |c, url| {
                c.put(format!(
                    "{url}/contexts/{}/did-templates/{}",
                    encode_path_segment(context_id),
                    encode_path_segment(name)
                ))
                .json(&template)
            },
        )
        .await
    }

    /// Delete a context-scoped template.
    ///
    /// REST: `DELETE /contexts/{id}/did-templates/{name}`. DIDComm:
    /// `vta/contexts/did-templates/delete/1.0`.
    pub async fn delete_context_did_template(
        &self,
        context_id: &str,
        name: &str,
    ) -> Result<(), VtaError> {
        self.rpc_tt_void(
            trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_DELETE_1_0,
            serde_json::to_value(proto::delete::DeleteContextDidTemplateBody {
                context_id: context_id.to_string(),
                name: name.to_string(),
            })?,
            30,
            |c, url| {
                c.delete(format!(
                    "{url}/contexts/{}/did-templates/{}",
                    encode_path_segment(context_id),
                    encode_path_segment(name)
                ))
            },
        )
        .await
    }

    /// Render a context-scoped template.
    ///
    /// Server injects ambient variables: `VTA_DID`, `VTA_URL`, `NOW`,
    /// `CONTEXT_ID`, and (if set on the context) `CONTEXT_DID`.
    ///
    /// REST: `POST /contexts/{id}/did-templates/{name}/render`. DIDComm:
    /// `vta/contexts/did-templates/render/1.0`.
    pub async fn render_context_did_template(
        &self,
        context_id: &str,
        name: &str,
        vars: HashMap<String, Value>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(proto::render::RenderContextDidTemplateBody {
            context_id: context_id.to_string(),
            name: name.to_string(),
            vars: vars.clone(),
        })?;
        let resp: proto::render::RenderDidTemplateResultBody = self
            .rpc_tt(
                trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_RENDER_1_0,
                payload,
                30,
                |c, url| {
                    c.post(format!(
                        "{url}/contexts/{}/did-templates/{}/render",
                        encode_path_segment(context_id),
                        encode_path_segment(name)
                    ))
                    .json(&serde_json::json!({ "vars": vars }))
                },
            )
            .await?;
        Ok(resp.document)
    }
}
