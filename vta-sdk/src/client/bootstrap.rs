//! Bootstrap / provision-integration methods on [`VtaClient`].

use super::VtaClient;
// `VtaError` is only used by `provision_integration`, which is gated on the
// `provision-integration` feature — gate the import to match so it isn't
// reported unused in builds without it (e.g. `client,session`).
#[cfg(feature = "provision-integration")]
use crate::error::VtaError;

impl VtaClient {
    /// Bridge a VP-framed bootstrap request to the VTA and receive
    /// the sealed bundle.
    ///
    /// The `provision/integration` Trust Task, signed by this client's
    /// identity, over whichever transport the client holds — TSP, DIDComm, or
    /// HTTPS on `/trust-tasks`. The caller must hold admin in the target
    /// context's ACL. Sender and VP holder may legitimately differ — the
    /// air-gap onboarding flow relies on this, since the bundle is HPKE-sealed
    /// to the VP holder's X25519 derivation and the relayer can't decrypt it.
    #[cfg(feature = "provision-integration")]
    pub async fn provision_integration(
        &self,
        req: crate::provision_integration::http::ProvisionIntegrationRequest,
    ) -> Result<crate::provision_integration::http::ProvisionIntegrationResponse, VtaError> {
        use crate::protocols::provision_integration_management::{
            ProvisionSpecVersion, request_body_for_version,
        };
        // Generous: the VTA mints keys, renders the template, builds the webvh
        // log and seals the bundle before it answers.
        const TIMEOUT_SECS: u64 = 60;
        let uri = ProvisionSpecVersion::CURRENT.request_uri();
        let body = request_body_for_version(&req, uri).map_err(VtaError::from)?;
        let payload = self.dispatch_trust_task(uri, body, TIMEOUT_SECS).await?;
        serde_json::from_value(payload)
            .map_err(|e| VtaError::Protocol(format!("`{uri}` response decode: {e}")))
    }
}
