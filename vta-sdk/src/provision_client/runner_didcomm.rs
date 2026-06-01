//! DIDComm transport for the online provisioning attempt fns, plus the
//! one-shot [`provision_via_didcomm`] entry point that doesn't go through
//! the runner orchestration at all.
//!
//! Sibling to [`super::runner_rest`]. Both modules return the shared
//! [`super::event::AttemptOutcome`] so the orchestrator's outcome →
//! event translation is uniform regardless of which wire delivered the
//! credential.

use std::sync::Arc;

use tokio::sync::mpsc::UnboundedSender;

use crate::did_key::decode_private_key_multibase;
use crate::didcomm_session::DIDCommSession;
use crate::protocols::did_management::servers::ListWebvhServersResultBody;
use crate::protocols::did_management::{LIST_WEBVH_SERVERS, LIST_WEBVH_SERVERS_RESULT};
use crate::provision_integration::didcomm::provision_integration_didcomm;

use super::ask::ProvisionAsk;
use super::diagnostics::{DiagCheck, DiagStatus, Protocol};
use super::error::ProvisionError;
use super::event::{AttemptOutcome, VtaEvent};
use super::intent::{AdminCredentialReply, VtaIntent, VtaReply};
use super::messages::OperatorMessages;
use super::result::{ProvisionResult, decode_nonce_b64url, response_to_result};

/// Drive a one-shot `provision-integration` round-trip over DIDComm.
///
/// - `setup_did` / `setup_private_key_mb`: the ephemeral key the operator
///   enrolled on the VTA via `pnm acl create`. The VP is signed with it;
///   the bundle is sealed to it. Its authority at the VTA is gone at the
///   end of the round-trip if `ask.admin_template` was set (default).
/// - `vta_did`: VTA identity.
/// - `mediator_did`: the DIDComm mediator advertised in the VTA's DID
///   doc — required, because this is a DIDComm-only driver.
///
/// Returns a [`ProvisionResult`] the caller can inspect / persist. Stand-
/// alone — does not emit [`VtaEvent`]s; consumers that want diagnostics
/// drive [`super::run_provision`] instead.
pub async fn provision_via_didcomm(
    setup_did: &str,
    setup_private_key_mb: &str,
    vta_did: &str,
    mediator_did: &str,
    ask: &ProvisionAsk,
) -> Result<ProvisionResult, ProvisionError> {
    let seed = decode_private_key_multibase(setup_private_key_mb)
        .map_err(|e| ProvisionError::SetupKeyMalformed(e.to_string()))?;

    let session = DIDCommSession::connect(setup_did, setup_private_key_mb, vta_did, mediator_did)
        .await
        .map_err(|e| ProvisionError::SessionOpen(e.to_string()))?;

    let vp = ask.to_builder().sign_with(&seed, setup_did).await?;
    let nonce = decode_nonce_b64url(&vp.nonce).map_err(ProvisionError::Armor)?;

    let response =
        provision_integration_didcomm(&session, vp, Some(ask.context.clone()), None, None, false)
            .await?;

    response_to_result(&seed, nonce, response)
}

/// Run the DIDComm leg of the auth check.
///
/// Emits diagnostic rows ([`DiagCheck::AuthenticateDIDComm`],
/// [`DiagCheck::ListWebvhServers`], [`DiagCheck::ProvisionIntegration`])
/// through `tx`. Returns an [`AttemptOutcome`] capturing whether the
/// attempt reached its natural endpoint, failed pre-auth, or failed
/// post-auth — the orchestrator translates the outcome into the final
/// transport-agnostic [`VtaEvent`].
///
/// Pre-auth boundary: any failure before [`DIDCommSession::connect`]
/// resolves `Ok` is pre-auth. The DIDComm attempt has no post-auth
/// failure mode for FullSetup in this scope — `list_webvh_servers`
/// errors are non-fatal (we continue serverless) and downstream
/// `provision_integration` runs in [`run_provision_flight`]. The
/// `AdminRotated` arm runs `provision_integration` inline (no
/// preflight indirection) and reports post-auth failures here.
///
/// `ask` is consumed by the `AdminRotated` arm to drive the provision
/// round-trip; the `FullSetup` and `AdminOnly` arms ignore it (their
/// flight runs separately, or there is no flight).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_didcomm_attempt(
    intent: VtaIntent,
    vta_did: String,
    mediator_did: String,
    rest_url: Option<String>,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
    tx: &UnboundedSender<VtaEvent>,
) -> AttemptOutcome {
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::AuthenticateDIDComm));

    match intent {
        VtaIntent::FullSetup => {
            let session = match DIDCommSession::connect(
                &setup_did,
                &setup_privkey_mb,
                &vta_did,
                &mediator_did,
            )
            .await
            {
                Ok(s) => {
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Ok(format!("DIDComm session as {setup_did}")),
                    ));
                    s
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Failed(msg.clone()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    return AttemptOutcome::PreAuthFailure(format!(
                        "Could not open an authenticated DIDComm session to the VTA. \
                         Confirm the `pnm acl create` command ran successfully for \
                         this setup DID and that the VTA's mediator service is \
                         reachable. ({msg})"
                    ));
                }
            };

            // Webvh-server catalogue lookup. Failure here is non-fatal —
            // the serverless path still works — but we surface the
            // attempt in the checklist so the consumer can see whether
            // the picker is about to show up.
            let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ListWebvhServers));
            let servers = match session
                .send_and_wait::<ListWebvhServersResultBody>(
                    LIST_WEBVH_SERVERS,
                    serde_json::json!({}),
                    LIST_WEBVH_SERVERS_RESULT,
                    30,
                )
                .await
            {
                Ok(body) => {
                    let detail = match body.servers.len() {
                        0 => "no registered servers — serverless path".into(),
                        1 => format!("1 registered server ({})", body.servers[0].id),
                        n => format!("{n} registered servers"),
                    };
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Ok(detail),
                    ));
                    body.servers
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Failed(format!(
                            "could not list — continuing serverless ({msg})"
                        )),
                    ));
                    Vec::new()
                }
            };

            AttemptOutcome::PreflightOk {
                rest_url,
                mediator_did,
                servers,
            }
        }
        VtaIntent::AdminOnly => {
            // AdminOnly: open a DIDComm session as the setup DID and
            // stop there. The setup DID *is* the long-term admin DID
            // (no rotation) — the session open is the authenticated
            // proof that the operator's `pnm acl create` landed.
            match DIDCommSession::connect(&setup_did, &setup_privkey_mb, &vta_did, &mediator_did)
                .await
            {
                Ok(_session) => {
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Ok(format!("DIDComm session as {setup_did}")),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Skipped(
                            "AdminOnly — no VTA-minted DID so no webvh host needed".into(),
                        ),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped(
                            "AdminOnly — setup did:key is the long-term admin credential; \
                             no template render, no rollover"
                                .into(),
                        ),
                    ));
                    AttemptOutcome::Connected(VtaReply::AdminOnly(AdminCredentialReply {
                        admin_did: setup_did,
                        admin_private_key_mb: setup_privkey_mb,
                    }))
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Failed(msg.clone()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    AttemptOutcome::PreAuthFailure(format!(
                        "Could not open an authenticated DIDComm session to the VTA. \
                         Confirm the `pnm acl create` command ran successfully for \
                         this DID and that the VTA's mediator service is reachable. \
                         ({msg})"
                    ))
                }
            }
        }
        VtaIntent::AdminRotated => {
            // AdminRotated: open a DIDComm session, then run the
            // provision-integration round-trip with an AdminRotation
            // ask. No webvh-server picker — this flow doesn't mint an
            // integration DID.
            //
            // Authenticated session opens first; pre-auth failures here
            // map to PreAuthFailure (different transport may succeed).
            // Once auth completes, the round-trip itself becomes
            // post-auth.
            let _ = match DIDCommSession::connect(
                &setup_did,
                &setup_privkey_mb,
                &vta_did,
                &mediator_did,
            )
            .await
            {
                Ok(s) => {
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Ok(format!("DIDComm session as {setup_did}")),
                    ));
                    s
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Failed(msg.clone()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    return AttemptOutcome::PreAuthFailure(format!(
                        "Could not open an authenticated DIDComm session to the VTA. \
                         Confirm the `pnm acl create` command ran successfully for \
                         this setup DID and that the VTA's mediator service is reachable. \
                         ({msg})"
                    ));
                }
            };

            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ListWebvhServers,
                DiagStatus::Skipped(
                    "AdminRotated — no integration DID minted so no webvh host needed".into(),
                ),
            ));
            let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ProvisionIntegration));

            match provision_admin_rotation_via_didcomm(
                &setup_did,
                &setup_privkey_mb,
                &vta_did,
                &mediator_did,
                &ask,
            )
            .await
            {
                Ok(reply) => {
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Ok(format!(
                            "admin DID rotated: {} (via {})",
                            reply.admin_did,
                            ask.admin_template.as_deref().unwrap_or(
                                crate::provision_client::ask::BUILTIN_VTA_ADMIN_TEMPLATE
                            ),
                        )),
                    ));
                    AttemptOutcome::Connected(VtaReply::AdminOnly(reply))
                }
                Err(err) => {
                    let msg = err.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Failed(msg.clone()),
                    ));
                    AttemptOutcome::PostAuthFailure(format!(
                        "AdminRotation provisioning failed after auth. ({msg})"
                    ))
                }
            }
        }
    }
}

/// Drive a one-shot AdminRotation `provision-integration` round-trip
/// over DIDComm. Mirrors [`provision_via_didcomm`] but decodes the
/// returned bundle as the [`SealedPayloadV1::AdminRotation`] variant
/// and lifts the result into an [`AdminCredentialReply`] (admin DID +
/// private key) — discarding the VC + trust bundle.
///
/// [`SealedPayloadV1::AdminRotation`]:
/// crate::sealed_transfer::SealedPayloadV1::AdminRotation
pub async fn provision_admin_rotation_via_didcomm(
    setup_did: &str,
    setup_private_key_mb: &str,
    vta_did: &str,
    mediator_did: &str,
    ask: &ProvisionAsk,
) -> Result<AdminCredentialReply, ProvisionError> {
    let seed = decode_private_key_multibase(setup_private_key_mb)
        .map_err(|e| ProvisionError::SetupKeyMalformed(e.to_string()))?;

    let session = DIDCommSession::connect(setup_did, setup_private_key_mb, vta_did, mediator_did)
        .await
        .map_err(|e| ProvisionError::SessionOpen(e.to_string()))?;

    let vp = ask.to_builder().sign_with(&seed, setup_did).await?;
    let nonce = decode_nonce_b64url(&vp.nonce).map_err(ProvisionError::Armor)?;

    let response =
        provision_integration_didcomm(&session, vp, Some(ask.context.clone()), None, None, false)
            .await?;

    crate::provision_client::result::admin_rotation_response_to_reply(&seed, nonce, response)
}

/// FullSetup provision flight — runs after the preflight
/// [`VtaEvent::PreflightDone`] has been handled and the operator's
/// webvh-server choice is settled.
///
/// Public because interactive consumers (TUIs that drive their own
/// webvh-server picker) call it directly between `PreflightDone` and
/// the final provisioning step. Non-interactive callers should use
/// [`super::run_provision`] instead — it auto-picks for the 0/1-server
/// case and bails when there are 2+.
///
/// Opens a fresh DIDComm session rather than keeping preflight's session
/// alive across the picker dialog — the picker may stay on screen for
/// many seconds, and tying a live session to a UI wait is fragile.
/// Re-handshaking is cheap and well inside the VP's freshness window.
///
/// `webvh_server_id`: `Some(id)` → injects `WEBVH_SERVER` into the VP's
/// `integration_template_vars` so the VTA pins the minted DID's
/// `did.jsonl` log to that server; `None` → serverless path.
///
/// `webvh_path`: `Some(p)` → injects `WEBVH_PATH` into
/// `integration_template_vars` so the VTA forwards the operator's path
/// suggestion to the webvh server's `request_uri` call; `None` → server
/// auto-assigns. Only meaningful when `webvh_server_id` is `Some`.
/// Inject the webvh transport-metadata vars (`WEBVH_SERVER`,
/// `WEBVH_PATH`) into an ask's `integration_template_vars`.
///
/// `webvh_path` is only meaningful in server-managed mode
/// (`webvh_server_id` set): the VTA reads `WEBVH_PATH` and ignores the
/// path folded into `URL`, so the path must travel as its own var or the
/// hosting server gets an empty path (`e.p.did.path-invalid`). Serverless
/// mode reads the path straight from `URL`, so callers pass `None` there.
pub(crate) fn inject_webvh_vars(
    ask: &mut ProvisionAsk,
    webvh_server_id: Option<&str>,
    webvh_path: Option<&str>,
) {
    if let Some(id) = webvh_server_id {
        ask.integration_template_vars.insert(
            "WEBVH_SERVER".to_string(),
            serde_json::Value::String(id.to_string()),
        );
    }
    if let Some(p) = webvh_path {
        ask.integration_template_vars.insert(
            "WEBVH_PATH".to_string(),
            serde_json::Value::String(p.to_string()),
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_provision_flight(
    vta_did: String,
    setup_did: String,
    setup_privkey_mb: String,
    mediator_did: String,
    rest_url: Option<String>,
    ask: ProvisionAsk,
    webvh_server_id: Option<String>,
    webvh_path: Option<String>,
    messages: Arc<dyn OperatorMessages>,
    tx: UnboundedSender<VtaEvent>,
) {
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ProvisionIntegration));

    let mut ask = ask;
    inject_webvh_vars(&mut ask, webvh_server_id.as_deref(), webvh_path.as_deref());
    if ask.label.is_none() {
        ask.label = Some(format!(
            "{} setup — {}",
            messages.integration_label_lower(),
            ask.context
        ));
    }

    match provision_via_didcomm(&setup_did, &setup_privkey_mb, &vta_did, &mediator_did, &ask).await
    {
        Ok(result) => {
            let webvh_note = webvh_server_id
                .as_ref()
                .map(|id| format!(", webvh server: {id}"))
                .unwrap_or_else(|| ", webvh: serverless".into());
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Ok(format!(
                    "admin DID: {} (rolled: {}), integration DID: {}{webvh_note}",
                    result.admin_did(),
                    result.summary.admin_rolled_over,
                    result.integration_did().unwrap_or("(none)"),
                )),
            ));
            let _ = tx.send(VtaEvent::Connected {
                protocol: Protocol::DidComm,
                rest_url,
                mediator_did: Some(mediator_did),
                reply: VtaReply::Full(Box::new(result)),
            });
        }
        Err(err) => {
            let msg = err.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            let hint = if msg.to_lowercase().contains("forbidden")
                || msg.contains("401")
                || msg.contains("403")
            {
                format!(
                    "The VTA rejected the provisioning request. Confirm the \
                     `pnm acl create` command ran successfully for setup DID \
                     {setup_did} in context `{}`, then retry.",
                    ask.context
                )
            } else if msg.to_lowercase().contains("template") {
                format!(
                    "VTA rejected the template render — check the `{}` template \
                     is present and your `WEBVH_SERVER` (if any) matches a \
                     registered server. Details: {msg}",
                    ask.integration_template
                        .as_deref()
                        .unwrap_or("(admin rotation)")
                )
            } else {
                format!("Provisioning failed. Details: {msg}")
            };
            let _ = tx.send(VtaEvent::Failed(hint));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision_client::runner::webvh_path_from_url;
    use serde_json::json;

    /// Regression for `e.p.did.path-invalid` (server-managed, single
    /// auto-selected server): the path folded into `URL` must reach the
    /// VTA as `WEBVH_PATH`. Mirrors the derive→inject chain that
    /// `run_provision`'s `PreflightDone` handler runs before the flight.
    #[test]
    fn server_managed_url_path_is_injected_as_webvh_path() {
        let mut ask = ProvisionAsk::for_template(
            "did-hosting-control",
            [(
                "URL".to_string(),
                json!("https://host.example.com/dids/daemon"),
            )]
            .into_iter()
            .collect(),
            "ctx",
        );

        // What the PreflightDone handler does: derive path from URL when a
        // server was auto-selected, then inject it for the flight.
        let server_id = Some("srv-1".to_string());
        let derived = server_id
            .as_ref()
            .and_then(|_| ask.integration_template_vars.get("URL"))
            .and_then(|v| v.as_str())
            .and_then(webvh_path_from_url);
        assert_eq!(derived.as_deref(), Some("dids/daemon"));

        inject_webvh_vars(&mut ask, server_id.as_deref(), derived.as_deref());

        assert_eq!(
            ask.integration_template_vars.get("WEBVH_PATH"),
            Some(&json!("dids/daemon"))
        );
        assert_eq!(
            ask.integration_template_vars.get("WEBVH_SERVER"),
            Some(&json!("srv-1"))
        );
    }

    /// Serverless mode (no server selected) leaves `WEBVH_PATH` unset — the
    /// VTA reads the path straight from `URL`.
    #[test]
    fn serverless_leaves_webvh_path_unset() {
        let mut ask = ProvisionAsk::for_template(
            "did-hosting-control",
            [(
                "URL".to_string(),
                json!("https://host.example.com/dids/daemon"),
            )]
            .into_iter()
            .collect(),
            "ctx",
        );
        inject_webvh_vars(&mut ask, None, None);
        assert!(!ask.integration_template_vars.contains_key("WEBVH_PATH"));
        assert!(!ask.integration_template_vars.contains_key("WEBVH_SERVER"));
    }
}
