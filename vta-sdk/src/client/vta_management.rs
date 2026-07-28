//! VTA management methods on [`VtaClient`]: restart, config get/update.

use super::{ConfigResponse, UpdateConfigRequest, VtaClient};
use crate::error::VtaError;

#[cfg(feature = "client")]
use crate::protocols::vta_management;

#[cfg(feature = "client")]
impl VtaClient {
    /// Trigger a soft restart of the VTA.
    pub async fn restart(&self) -> Result<vta_management::restart::RestartResult, VtaError> {
        self.rpc(
            vta_management::RESTART,
            serde_json::json!({}),
            vta_management::RESTART_RESULT,
            30,
            |c, url| {
                c.post(format!("{url}/vta/restart"))
                    .json(&serde_json::json!({}))
            },
        )
        .await
    }

    pub async fn get_config(&self) -> Result<ConfigResponse, VtaError> {
        self.rpc(
            vta_management::GET_CONFIG,
            serde_json::json!({}),
            vta_management::GET_CONFIG_RESULT,
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
        self.rpc(
            vta_management::UPDATE_CONFIG,
            serde_json::to_value(&req)?,
            vta_management::UPDATE_CONFIG_RESULT,
            30,
            |c, url| c.patch(format!("{url}/config")).json(&req),
        )
        .await
    }
}
