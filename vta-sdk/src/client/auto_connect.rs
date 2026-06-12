//! Transport-agnostic authenticated connect.
//!
//! [`VtaClient::connect_auto`] selects DIDComm vs REST from the supplied
//! credentials and encapsulates the handshake plus the REST-fallback
//! computation. Consumers used to re-implement this branch by hand — the
//! transport choice, the `rest_fallback` derivation, and the empty-URL
//! rule are SDK-level knowledge, so they live here where they can't drift
//! between call sites.

use crate::client::VtaClient;
use crate::error::VtaError;
use crate::session::TokenResult;

/// Inputs for [`VtaClient::connect_auto`].
///
/// `mediator_did.is_some()` selects DIDComm; otherwise a REST
/// challenge-response handshake is used.
#[derive(Debug, Clone)]
pub struct AutoConnect<'a> {
    /// VTA REST base URL. May be empty on the DIDComm path (fully-DIDComm
    /// VTAs publishing no `#vta-rest` service); when non-empty it is passed
    /// through as the DIDComm client's REST fallback. **Required (non-empty)
    /// on the REST path** — an empty `vta_url` with no mediator is an error.
    pub vta_url: &'a str,
    /// The VTA's DID.
    pub vta_did: &'a str,
    /// The caller's credential DID (the proven signer).
    pub credential_did: &'a str,
    /// The caller's Ed25519 private key, multibase-encoded.
    pub private_key_multibase: &'a str,
    /// `Some(mediator)` => connect over DIDComm via this mediator;
    /// `None` => authenticate over REST challenge-response.
    pub mediator_did: Option<&'a str>,
}

/// Result of [`VtaClient::connect_auto`].
///
/// Carries the authenticated client plus, on the REST path, the issued
/// token so callers that cache it (e.g. in an OS keyring) still can.
/// `rest_token` is `None` on the DIDComm path — there the session itself is
/// the authenticator and there is no bearer token to cache.
///
/// On the DIDComm path the inner `client` owns a live, auto-reconnecting
/// mediator session: callers **must** call [`VtaClient::shutdown`] when
/// done (or drive the whole interaction through
/// [`VtaClient::with_didcomm`]). See [`VtaClient::connect_didcomm`].
pub struct ConnectedVta {
    /// The authenticated client.
    pub client: VtaClient,
    /// The issued REST token, or `None` on the DIDComm path.
    pub rest_token: Option<TokenResult>,
}

impl VtaClient {
    /// Connect to a VTA, selecting the transport from `input`.
    ///
    /// - **DIDComm** (`mediator_did = Some`): derives
    ///   `rest_fallback = (!vta_url.is_empty()).then(|| vta_url)` and calls
    ///   [`connect_didcomm`](Self::connect_didcomm). An empty `vta_url` is
    ///   valid (fully-DIDComm VTAs). `rest_token` is `None`.
    /// - **REST** (`mediator_did = None`): errors with
    ///   [`VtaError::Validation`] if `vta_url` is empty, otherwise runs the
    ///   challenge-response handshake, builds a [`VtaClient::new`] client,
    ///   sets its bearer token, and returns the token in `rest_token` so the
    ///   caller can cache it.
    ///
    /// Token caching and auth-retry policy stay caller-side — they are
    /// application-specific.
    #[cfg(feature = "session")]
    pub async fn connect_auto(input: AutoConnect<'_>) -> Result<ConnectedVta, VtaError> {
        match input.mediator_did {
            // DIDComm transport. Empty `vta_url` is valid — it just means no
            // REST fallback for unauthenticated ops like `health()`.
            Some(mediator) => {
                let rest_fallback = (!input.vta_url.is_empty()).then(|| input.vta_url.to_string());
                let client = VtaClient::connect_didcomm(
                    input.credential_did,
                    input.private_key_multibase,
                    input.vta_did,
                    mediator,
                    rest_fallback,
                )
                .await?;
                Ok(ConnectedVta {
                    client,
                    rest_token: None,
                })
            }
            // REST transport. A non-empty URL is mandatory — without a
            // mediator there is nothing else to reach the VTA on.
            None => {
                if input.vta_url.is_empty() {
                    return Err(VtaError::Validation(
                        "REST transport requires a non-empty vta_url (no mediator_did was supplied)"
                            .into(),
                    ));
                }
                let token = crate::session::challenge_response(
                    input.vta_url,
                    input.credential_did,
                    input.private_key_multibase,
                    input.vta_did,
                )
                .await
                .map_err(|e| VtaError::Auth(e.to_string()))?;

                let client = VtaClient::new(input.vta_url);
                client.set_token_async(token.access_token.clone()).await;
                Ok(ConnectedVta {
                    client,
                    rest_token: Some(token),
                })
            }
        }
    }
}
