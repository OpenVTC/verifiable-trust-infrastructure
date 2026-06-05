//! Bootstrap / provision-integration methods on [`VtaClient`].

use super::VtaClient;
// `Transport` + `VtaError` are only used by `provision_integration`, which is
// gated on the `provision-integration` feature — gate the imports to match so
// they aren't reported unused in builds without it (e.g. `client,session`).
#[cfg(feature = "provision-integration")]
use super::Transport;
#[cfg(feature = "provision-integration")]
use crate::error::VtaError;

impl VtaClient {
    /// Bridge a VP-framed bootstrap request to the VTA and receive
    /// the sealed bundle.
    ///
    /// Works over both transports:
    /// - **REST**: `POST /bootstrap/provision-integration`.
    /// - **DIDComm**: `provision-integration/1.0` protocol over the
    ///   open authcrypt session. The VTA-side handler is the same
    ///   shared library function as REST; only the I/O differs.
    ///
    /// In DIDComm mode, the session's `client_did` must already
    /// hold admin role in the target context's ACL. Sender and VP
    /// holder may legitimately differ — the air-gap onboarding flow
    /// relies on this, since the bundle is HPKE-sealed to the VP
    /// holder's X25519 derivation and the relayer can't decrypt it.
    #[cfg(feature = "provision-integration")]
    pub async fn provision_integration(
        &self,
        req: crate::provision_integration::http::ProvisionIntegrationRequest,
    ) -> Result<crate::provision_integration::http::ProvisionIntegrationResponse, VtaError> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                Self::ensure_token_valid(client, base_url, auth).await?;
                let token = auth.lock().await.token.clone();
                let http_req = client
                    .post(format!("{base_url}/bootstrap/provision-integration"))
                    .json(&req);
                let resp = Self::with_auth_token(http_req, &token).send().await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => {
                crate::provision_integration::didcomm::provision_integration_didcomm(
                    session,
                    req.request,
                    req.context,
                    req.assertion,
                    req.vc_validity_seconds,
                    req.create_context,
                )
                .await
            }
        }
    }
}
