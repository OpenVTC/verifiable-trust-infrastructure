//! DID-template management methods on [`VtaClient`] (global + context scope).
//!
//! **Transport model.** On the REST transport these hit the dedicated
//! `/did-templates` (and `/contexts/{id}/did-templates`) routes. On the
//! DIDComm transport there is no raw protocol surface — the VTA exposes
//! template management only through its Trust-Task dispatcher, so the DIDComm
//! leg dispatches the `trusttasks.org/spec/vta/did-templates/*/2.0` Trust
//! Tasks via the binding envelope. One URI per operation; the payload's
//! optional `contextId` selects global vs context scope. Both legs are wired
//! through [`VtaClient::rpc_tt`] / [`VtaClient::rpc_tt_void`].

use std::collections::HashMap;

use serde_json::Value;

use super::VtaClient;
use crate::did_templates::{DidTemplate, DidTemplateRecord};
use crate::error::VtaError;
use crate::protocols::did_template_management as proto;
use crate::trust_tasks;

/// The task URI to carry `template` on: 3.0 when the template needs it, 2.0
/// otherwise.
///
/// # Why not simply always send 3.0
///
/// Because that would break this client against every VTA deployed before
/// 3.0 existed, for templates those VTAs can serve perfectly well. The rule
/// that avoids it is that **the task version follows the template version**: a
/// `schemaVersion` 1 template has nothing 2.0 cannot express, so demanding 3.0
/// buys nothing and costs compatibility; a `schemaVersion` 2 template genuinely
/// cannot travel on 2.0, so demanding 3.0 is the honest failure rather than a
/// silent one.
///
/// A caller sending a v2 template to an older VTA gets `UnsupportedType` naming
/// the 3.0 URI, which is the correct answer — that VTA cannot mint the keys the
/// template asks for either.
fn create_uri(template: &DidTemplate) -> &'static str {
    if template.schema_version >= 2 {
        trust_tasks::TASK_DID_TEMPLATES_CREATE_3_0
    } else {
        trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0
    }
}

/// As [`create_uri`], for replacement.
fn update_uri(template: &DidTemplate) -> &'static str {
    if template.schema_version >= 2 {
        trust_tasks::TASK_DID_TEMPLATES_UPDATE_3_0
    } else {
        trust_tasks::TASK_DID_TEMPLATES_UPDATE_2_0
    }
}

impl VtaClient {
    // ── DID templates — global scope ─────────────────────────────────────

    /// List all global templates.
    ///
    /// REST: `GET /did-templates`. DIDComm: `vta/did-templates/list/2.0`
    /// without `contextId`.
    pub async fn list_did_templates(&self) -> Result<Vec<DidTemplateRecord>, VtaError> {
        let resp: proto::list::ListDidTemplatesResultBody = self
            .rpc_tt(
                // 3.0 unconditionally: a 2.0 read refuses to return a v2 template
                // (it cannot express one), so staying on 2.0 would make this client
                // unable to see post-quantum templates at all.
                trust_tasks::TASK_DID_TEMPLATES_LIST_3_0,
                serde_json::to_value(proto::list::ListDidTemplatesBody { context_id: None })?,
                30,
            )
            .await?;
        Ok(resp.templates)
    }

    /// Fetch one global template by name.
    ///
    /// REST: `GET /did-templates/{name}`. DIDComm:
    /// `vta/did-templates/get/2.0` without `contextId`.
    pub async fn get_did_template(&self, name: &str) -> Result<DidTemplateRecord, VtaError> {
        self.rpc_tt(
            // 3.0 for the same reason as `list` above.
            trust_tasks::TASK_DID_TEMPLATES_GET_3_0,
            serde_json::to_value(proto::get::GetDidTemplateBody {
                context_id: None,
                name: name.to_string(),
            })?,
            30,
        )
        .await
    }

    /// Create a global template. Super admin only.
    ///
    /// REST: `POST /did-templates`. DIDComm:
    /// `vta/did-templates/create/2.0` without `contextId`.
    pub async fn create_did_template(
        &self,
        template: DidTemplate,
    ) -> Result<DidTemplateRecord, VtaError> {
        let payload = serde_json::to_value(proto::create::CreateDidTemplateBody {
            context_id: None,
            template: template.clone(),
        })?;
        self.rpc_tt(create_uri(&template), payload, 30).await
    }

    /// Replace a global template. Super admin only.
    ///
    /// REST: `PUT /did-templates/{name}`. DIDComm:
    /// `vta/did-templates/update/2.0` without `contextId`.
    pub async fn update_did_template(
        &self,
        name: &str,
        template: DidTemplate,
    ) -> Result<DidTemplateRecord, VtaError> {
        let payload = serde_json::to_value(proto::update::UpdateDidTemplateBody {
            context_id: None,
            name: name.to_string(),
            template: template.clone(),
        })?;
        self.rpc_tt(update_uri(&template), payload, 30).await
    }

    /// Delete a global template. Super admin only.
    ///
    /// REST: `DELETE /did-templates/{name}`. DIDComm:
    /// `vta/did-templates/delete/2.0` without `contextId`.
    pub async fn delete_did_template(&self, name: &str) -> Result<(), VtaError> {
        self.rpc_tt_void(
            trust_tasks::TASK_DID_TEMPLATES_DELETE_2_0,
            serde_json::to_value(proto::delete::DeleteDidTemplateBody {
                context_id: None,
                name: name.to_string(),
            })?,
            30,
        )
        .await
    }

    /// Render a stored global template with caller variables.
    ///
    /// Server injects ambient variables (`VTA_DID`, `VTA_URL`, `NOW`);
    /// `vars` provides everything else.
    ///
    /// REST: `POST /did-templates/{name}/render`. DIDComm:
    /// `vta/did-templates/render/2.0` without `contextId`.
    pub async fn render_did_template(
        &self,
        name: &str,
        vars: HashMap<String, Value>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(proto::render::RenderDidTemplateBody {
            context_id: None,
            name: name.to_string(),
            vars: vars.clone(),
        })?;
        let resp: proto::render::RenderDidTemplateResultBody = self
            .rpc_tt(trust_tasks::TASK_DID_TEMPLATES_RENDER_2_0, payload, 30)
            .await?;
        Ok(resp.document)
    }

    // ── DID templates — context scope ────────────────────────────────────

    /// List context-scoped templates.
    ///
    /// REST: `GET /contexts/{id}/did-templates`. DIDComm:
    /// `vta/did-templates/list/2.0` with `contextId` set.
    pub async fn list_context_did_templates(
        &self,
        context_id: &str,
    ) -> Result<Vec<DidTemplateRecord>, VtaError> {
        let resp: proto::list::ListDidTemplatesResultBody = self
            .rpc_tt(
                // 3.0 unconditionally: a 2.0 read refuses to return a v2 template
                // (it cannot express one), so staying on 2.0 would make this client
                // unable to see post-quantum templates at all.
                trust_tasks::TASK_DID_TEMPLATES_LIST_3_0,
                serde_json::to_value(proto::list::ListDidTemplatesBody {
                    context_id: Some(context_id.to_string()),
                })?,
                30,
            )
            .await?;
        Ok(resp.templates)
    }

    /// Fetch one context-scoped template.
    ///
    /// REST: `GET /contexts/{id}/did-templates/{name}`. DIDComm:
    /// `vta/did-templates/get/2.0` with `contextId` set.
    pub async fn get_context_did_template(
        &self,
        context_id: &str,
        name: &str,
    ) -> Result<DidTemplateRecord, VtaError> {
        self.rpc_tt(
            // 3.0 for the same reason as `list` above.
            trust_tasks::TASK_DID_TEMPLATES_GET_3_0,
            serde_json::to_value(proto::get::GetDidTemplateBody {
                context_id: Some(context_id.to_string()),
                name: name.to_string(),
            })?,
            30,
        )
        .await
    }

    /// Create a context-scoped template. Context admin or super admin.
    ///
    /// REST: `POST /contexts/{id}/did-templates`. DIDComm:
    /// `vta/did-templates/create/2.0` with `contextId` set.
    pub async fn create_context_did_template(
        &self,
        context_id: &str,
        template: DidTemplate,
    ) -> Result<DidTemplateRecord, VtaError> {
        let payload = serde_json::to_value(proto::create::CreateDidTemplateBody {
            context_id: Some(context_id.to_string()),
            template: template.clone(),
        })?;
        self.rpc_tt(create_uri(&template), payload, 30).await
    }

    /// Replace a context-scoped template.
    ///
    /// REST: `PUT /contexts/{id}/did-templates/{name}`. DIDComm:
    /// `vta/did-templates/update/2.0` with `contextId` set.
    pub async fn update_context_did_template(
        &self,
        context_id: &str,
        name: &str,
        template: DidTemplate,
    ) -> Result<DidTemplateRecord, VtaError> {
        let payload = serde_json::to_value(proto::update::UpdateDidTemplateBody {
            context_id: Some(context_id.to_string()),
            name: name.to_string(),
            template: template.clone(),
        })?;
        self.rpc_tt(update_uri(&template), payload, 30).await
    }

    /// Delete a context-scoped template.
    ///
    /// REST: `DELETE /contexts/{id}/did-templates/{name}`. DIDComm:
    /// `vta/did-templates/delete/2.0` with `contextId` set.
    pub async fn delete_context_did_template(
        &self,
        context_id: &str,
        name: &str,
    ) -> Result<(), VtaError> {
        self.rpc_tt_void(
            trust_tasks::TASK_DID_TEMPLATES_DELETE_2_0,
            serde_json::to_value(proto::delete::DeleteDidTemplateBody {
                context_id: Some(context_id.to_string()),
                name: name.to_string(),
            })?,
            30,
        )
        .await
    }

    /// Render a context-scoped template.
    ///
    /// Server injects ambient variables: `VTA_DID`, `VTA_URL`, `NOW`,
    /// `CONTEXT_ID`, and (if set on the context) `CONTEXT_DID`.
    ///
    /// REST: `POST /contexts/{id}/did-templates/{name}/render`. DIDComm:
    /// `vta/did-templates/render/2.0` with `contextId` set.
    pub async fn render_context_did_template(
        &self,
        context_id: &str,
        name: &str,
        vars: HashMap<String, Value>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(proto::render::RenderDidTemplateBody {
            context_id: Some(context_id.to_string()),
            name: name.to_string(),
            vars: vars.clone(),
        })?;
        let resp: proto::render::RenderDidTemplateResultBody = self
            .rpc_tt(trust_tasks::TASK_DID_TEMPLATES_RENDER_2_0, payload, 30)
            .await?;
        Ok(resp.document)
    }
}
