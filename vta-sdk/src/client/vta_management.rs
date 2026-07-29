//! VTA management methods on [`VtaClient`]: restart, config get/update.

use super::{ConfigResponse, UpdateConfigRequest, VtaClient};
use crate::error::VtaError;

#[cfg(feature = "client")]
use crate::protocols::vta_management;

#[cfg(feature = "client")]
impl VtaClient {
    /// Trigger a soft restart of the VTA.
    pub async fn restart(&self) -> Result<vta_management::restart::RestartResult, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_MANAGEMENT_RELOAD_SERVICES_1_0,
            serde_json::json!({}),
            30,
            |c, url| {
                c.post(format!("{url}/vta/restart"))
                    .json(&serde_json::json!({}))
            },
        )
        .await
    }

    pub async fn get_config(&self) -> Result<ConfigResponse, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_CONFIG_SHOW_0_1,
            serde_json::json!({}),
            30,
            |c, url| c.get(format!("{url}/config")),
        )
        .await
    }

    pub async fn update_config(
        &self,
        req: UpdateConfigRequest,
    ) -> Result<crate::protocols::vta_management::update_config::UpdateConfigResultBody, VtaError>
    {
        // `UpdateConfigRequest` flattens `UpdateConfigBody`, so the serialized
        // form is the canonical `config/patch/0.1` `{ overrides }` payload.
        self.rpc_tt(
            crate::trust_tasks::TASK_CONFIG_PATCH_0_1,
            serde_json::to_value(&req)?,
            30,
            |c, url| c.patch(format!("{url}/config")).json(&req),
        )
        .await
    }
}
