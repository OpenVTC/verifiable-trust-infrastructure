//! TSP transport for the online provisioning attempt fns, plus the
//! one-shot [`provision_via_tsp`] entry point that doesn't go through the
//! runner orchestration at all.
//!
//! Sibling to [`super::runner_didcomm`] and [`super::runner_rest`]. All
//! three return the shared [`super::event::AttemptOutcome`] so the
//! orchestrator's outcome → event translation is uniform regardless of
//! which wire delivered the credential.
//!
//! # Why provisioning rides TSP without new protocol surface
//!
//! The VTA's TSP inbound dispatcher (`vta-service`'s
//! `messaging::tsp_inbound::dispatch_one`) hands every unpacked frame
//! straight to `dispatch_trust_task_core` — the *same* spine REST and the
//! DIDComm trust-task envelope feed. Both operations this flow needs are
//! registered on that spine:
//!
//! - `spec/vta/webvh/servers/list/1.0`
//!   ([`TASK_WEBVH_SERVERS_LIST_1_0`]) — the webvh-host catalogue.
//! - `spec/provision/integration/0.2`
//!   ([`TASK_PROVISION_INTEGRATION_0_2`]) — the VP-framed bootstrap
//!   request and its sealed reply.
//!
//! So the request and reply documents are byte-identical to the ones the
//! other two transports carry, and this module is wiring rather than
//! protocol design. Note the **0.2** URI: the DIDComm leg addresses
//! `provision/integration/0.1` as a DIDComm *protocol message* (routed by
//! `messaging::handlers_protocol`, not by the trust-task spine), and only
//! 0.2 is on the spine. The signed VP inside is byte-identical either way
//! — `spec_version` selects the casing of the *options* around it.
//!
//! # What TSP does not share with DIDComm
//!
//! - **No handshake, no envelope.** TSP carries the Trust-Task bytes
//!   directly and `unpack` yields a cryptographically *proven* sender VID,
//!   which the VTA resolves straight to its ACL grant. There is no
//!   authcrypt envelope, no challenge, and no bearer token.
//! - **No mediator-side ACL step.** `DIDCommSession::connect` sets the
//!   client's mediator ACL and flushes its inbox; the TSP socket does
//!   neither.
//! - **Correlation is the application's job.** TSP frames carry no
//!   transport thread-id, so replies are matched on the response
//!   document's `threadId` (see `tsp_demux`). That is already implemented
//!   under [`VtaClient::dispatch_trust_task`], which this module drives
//!   rather than re-deriving.
//!
//! What it *does* share is the shape of the checklist: the socket open is
//! the [`DiagCheck::AuthenticateTSP`] proxy exactly as the mediator
//! connect is the [`DiagCheck::AuthenticateDIDComm`] proxy on the DIDComm
//! leg — neither transport performs a VTA round-trip at connect time. The
//! first *authorized* round-trip is the real ACL proof, and on the
//! FullSetup path that is the very next step.
//!
//! # Feature gate
//!
//! `provision-client` does not imply `tsp`, so every entry point here has
//! a `#[cfg(not(feature = "tsp"))]` twin that fails with the same message
//! shape `session::connect_tsp_bounded` uses: name the missing feature,
//! don't pretend the DID document was at fault.
//!
//! [`TASK_WEBVH_SERVERS_LIST_1_0`]: crate::trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0
//! [`TASK_PROVISION_INTEGRATION_0_2`]: crate::trust_tasks::TASK_PROVISION_INTEGRATION_0_2
//! [`VtaClient::dispatch_trust_task`]: crate::client::VtaClient::dispatch_trust_task
//! [`DiagCheck::AuthenticateTSP`]: super::diagnostics::DiagCheck::AuthenticateTSP
//! [`DiagCheck::AuthenticateDIDComm`]: super::diagnostics::DiagCheck::AuthenticateDIDComm

use tokio::sync::mpsc::UnboundedSender;

use super::ask::ProvisionAsk;
use super::event::{AttemptOutcome, VtaEvent};
use super::intent::VtaIntent;

/// Round-trip budget for the `provision-integration` call over TSP.
/// Matches the DIDComm leg's `DEFAULT_TIMEOUT_SECS` — the VTA mints keys,
/// renders templates, builds the webvh log and seals the bundle
/// synchronously before replying, and none of that is transport-dependent.
#[cfg(feature = "tsp")]
const PROVISION_TIMEOUT_SECS: u64 = 60;

/// Round-trip budget for the webvh-server catalogue lookup, matching the
/// DIDComm leg's `send_and_wait(..., 30)`.
#[cfg(feature = "tsp")]
const LIST_SERVERS_TIMEOUT_SECS: u64 = 30;

/// The message an operator sees when the VTA advertises `#tsp` but this
/// build cannot speak it. Mirrors `session::connect_tsp_bounded`'s wording
/// so the two paths read the same in a log.
#[cfg(not(feature = "tsp"))]
fn tsp_feature_missing(vta_did: &str, tsp_mediator_did: &str) -> String {
    format!(
        "VTA '{vta_did}' advertises a TSP service (`#tsp` → {tsp_mediator_did}), but this \
         build of the SDK was compiled without the `tsp` feature, so it cannot provision \
         over TSP.\n\n\
         Rebuild the setup tool with `--features tsp`, or point provisioning at a VTA \
         that also advertises a DIDComm mediator or a `#vta-rest` endpoint."
    )
}

/// Run the TSP leg of the auth check.
///
/// Emits diagnostic rows ([`super::diagnostics::DiagCheck::AuthenticateTSP`],
/// [`super::diagnostics::DiagCheck::ListWebvhServers`],
/// [`super::diagnostics::DiagCheck::ProvisionIntegration`]) through `tx`
/// and returns the shared [`AttemptOutcome`], exactly like
/// [`super::runner_didcomm::run_didcomm_attempt`].
///
/// Pre-auth boundary: anything up to and including the TSP socket opening
/// is pre-auth — a failure there is worth retrying on another transport,
/// and the orchestrator does so when the VTA advertises one. Once a
/// trust-task round-trip has been accepted by the VTA the failure is
/// post-auth and terminal.
///
/// # FullSetup and the webvh-server picker
///
/// Unlike the DIDComm leg this arm does **not** split into a preflight +
/// [`super::runner_didcomm::run_provision_flight`] pair. The split exists so an
/// interactive consumer can close its session while a picker dialog is on
/// screen; the picker itself is driven by the consumer off
/// [`VtaEvent::PreflightDone`], whose `mediator_did` field is a DIDComm
/// mediator by construction. Rather than overload that field with a TSP
/// mediator (the resolver deliberately keeps the two apart — see
/// [`super::resolve::ResolvedVta`]), the TSP leg runs the catalogue lookup
/// and the provision round-trip back-to-back on one socket and resolves
/// the server choice the way [`super::run_provision`] does:
///
/// - an explicit `WEBVH_SERVER` already in the ask's
///   `integration_template_vars` wins (this is what `vtc-service`'s wizard
///   does to bypass auto-pick);
/// - otherwise 0 or 1 catalogue entries auto-pick;
/// - 2+ entries with no explicit choice is refused rather than guessed,
///   naming `WEBVH_SERVER` as the fix.
///
/// A TSP-carried `PreflightDone` needs a public event-shape change; it is
/// deliberately out of scope here and is tracked as follow-up work.
#[cfg(feature = "tsp")]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_tsp_attempt(
    intent: VtaIntent,
    vta_did: String,
    tsp_mediator_did: String,
    rest_url: Option<String>,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
    tx: &UnboundedSender<VtaEvent>,
) -> AttemptOutcome {
    use super::diagnostics::{DiagCheck, DiagStatus};
    use crate::client::VtaClient;

    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::AuthenticateTSP));

    // The socket open is this leg's auth proxy — see the module docs for
    // why that is the same proxy the DIDComm leg uses.
    let client = match VtaClient::connect_tsp(
        &setup_did,
        &setup_privkey_mb,
        &vta_did,
        &tsp_mediator_did,
        rest_url.clone(),
    )
    .await
    {
        Ok(c) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateTSP,
                DiagStatus::Ok(format!("TSP session as {setup_did} via {tsp_mediator_did}")),
            ));
            c
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateTSP,
                DiagStatus::Failed(msg.clone()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ListWebvhServers,
                DiagStatus::Skipped("TSP session did not open".into()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Skipped("TSP session did not open".into()),
            ));
            return AttemptOutcome::PreAuthFailure(format!(
                "Could not open a TSP session to the VTA's `#tsp` mediator \
                 ({tsp_mediator_did}). Confirm the mediator is reachable and that the \
                 `pnm acl create` command ran successfully for setup DID {setup_did}. \
                 ({msg})"
            ));
        }
    };

    // Everything past the connect lives in its own fn so the session is
    // shut down on EVERY path out of it — the mediator permits one
    // websocket per DID, so a leaked session makes the next connect for
    // this DID fight the old one. Same contract as the DIDComm leg's
    // `session.shutdown()`, and the reason the body cannot just `?`.
    let outcome = tsp_attempt_body(&client, intent, &setup_did, &setup_privkey_mb, ask, tx).await;
    client.shutdown().await;
    outcome
}

/// The post-connect body of [`run_tsp_attempt`], split out so its caller
/// has exactly one place to shut the session down.
#[cfg(feature = "tsp")]
async fn tsp_attempt_body(
    client: &crate::client::VtaClient,
    intent: VtaIntent,
    setup_did: &str,
    setup_privkey_mb: &str,
    ask: ProvisionAsk,
    tx: &UnboundedSender<VtaEvent>,
) -> AttemptOutcome {
    use super::diagnostics::{DiagCheck, DiagStatus};
    use super::intent::VtaReply;

    match intent {
        VtaIntent::AdminOnly => {
            // AdminOnly: the setup DID *is* the long-term admin DID. The
            // session open is the proof the operator's `pnm acl create`
            // landed — same contract as the DIDComm leg's AdminOnly arm.
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ListWebvhServers,
                DiagStatus::Skipped("AdminOnly — no VTA-minted DID so no webvh host needed".into()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Skipped(
                    "AdminOnly — setup did:key is the long-term admin credential; \
                     no template render, no rollover"
                        .into(),
                ),
            ));
            AttemptOutcome::Connected(VtaReply::AdminOnly(super::intent::AdminCredentialReply {
                admin_did: setup_did.to_string(),
                admin_private_key_mb: setup_privkey_mb.to_string(),
            }))
        }
        VtaIntent::AdminRotated => {
            // No integration DID is minted, so no webvh host is needed —
            // straight to the provision round-trip.
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ListWebvhServers,
                DiagStatus::Skipped(
                    "AdminRotated — no integration DID minted so no webvh host needed".into(),
                ),
            ));
            let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ProvisionIntegration));

            match provision_admin_rotation_over(client, setup_did, setup_privkey_mb, &ask).await {
                Ok(reply) => {
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Ok(format!(
                            "admin DID rotated: {} (via {})",
                            reply.admin_did,
                            ask.admin_template
                                .as_deref()
                                .unwrap_or(super::ask::BUILTIN_VTA_ADMIN_TEMPLATE),
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
        VtaIntent::FullSetup => tsp_full_setup(client, setup_did, setup_privkey_mb, ask, tx).await,
    }
}

/// FullSetup over TSP: catalogue lookup, server choice, provision
/// round-trip — all on the one already-open session.
#[cfg(feature = "tsp")]
async fn tsp_full_setup(
    client: &crate::client::VtaClient,
    setup_did: &str,
    setup_privkey_mb: &str,
    ask: ProvisionAsk,
    tx: &UnboundedSender<VtaEvent>,
) -> AttemptOutcome {
    use super::diagnostics::{DiagCheck, DiagStatus};
    use super::intent::VtaReply;
    use super::runner_didcomm::inject_webvh_vars;
    use crate::protocols::did_management::servers::ListWebvhServersResultBody;

    // Webvh-server catalogue lookup. Failure here is non-fatal — the
    // serverless path still works — but we surface the attempt in the
    // checklist, exactly as the DIDComm leg does.
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ListWebvhServers));
    let servers = match client
        .dispatch_trust_task(
            crate::trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0,
            serde_json::json!({}),
            LIST_SERVERS_TIMEOUT_SECS,
        )
        .await
        .map_err(|e| e.to_string())
        .and_then(|payload| {
            serde_json::from_value::<ListWebvhServersResultBody>(payload)
                .map_err(|e| format!("webvh-server catalogue decode: {e}"))
        }) {
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
        Err(msg) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ListWebvhServers,
                DiagStatus::Failed(format!("could not list — continuing serverless ({msg})")),
            ));
            Vec::new()
        }
    };

    let mut ask = ask;
    // An explicit operator choice already in the ask wins outright; only
    // fill one in when there isn't one. Same precedence `run_provision`'s
    // `PreflightDone` handler applies via `inject_webvh_vars`.
    if !ask.integration_template_vars.contains_key("WEBVH_SERVER") {
        match servers.len() {
            0 => {}
            1 => inject_webvh_vars(&mut ask, Some(&servers[0].id), None),
            n => {
                let msg = format!(
                    "VTA has {n} registered webvh servers and the provisioning ask names \
                     none, so the choice is ambiguous. Set `WEBVH_SERVER` in the ask's \
                     integration_template_vars to the id you want. (The interactive \
                     picker is driven off VtaEvent::PreflightDone, which the TSP leg \
                     does not emit.)"
                );
                let _ = tx.send(VtaEvent::CheckDone(
                    DiagCheck::ProvisionIntegration,
                    DiagStatus::Failed(msg.clone()),
                ));
                return AttemptOutcome::PostAuthFailure(msg);
            }
        }
    }
    let webvh_note = match ask.integration_template_vars.get("WEBVH_SERVER") {
        Some(serde_json::Value::String(id)) => format!(", webvh server: {id}"),
        _ => ", webvh: serverless".to_string(),
    };

    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ProvisionIntegration));
    match provision_over(client, setup_did, setup_privkey_mb, &ask).await {
        Ok(result) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Ok(format!(
                    "admin DID: {} (rolled: {}), integration DID: {}{webvh_note}",
                    result.admin_did(),
                    result.summary.admin_rolled_over,
                    result.integration_did().unwrap_or("(none)"),
                )),
            ));
            AttemptOutcome::Connected(VtaReply::Full(Box::new(result)))
        }
        Err(err) => {
            let msg = err.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Failed(msg.clone()),
            ));
            AttemptOutcome::PostAuthFailure(format!("Provisioning failed after auth. ({msg})"))
        }
    }
}

/// Send the VP-framed bootstrap request as a `provision/integration/0.2`
/// trust task over `client`'s transport and open the sealed reply.
///
/// The VP is signed with the setup key and the bundle is sealed to it, so
/// the returned material is only openable here — identical to the DIDComm
/// and REST legs, which is the whole point of the wire being
/// transport-neutral.
#[cfg(feature = "tsp")]
async fn provision_over(
    client: &crate::client::VtaClient,
    setup_did: &str,
    setup_privkey_mb: &str,
    ask: &ProvisionAsk,
) -> Result<super::result::ProvisionResult, super::error::ProvisionError> {
    use super::error::ProvisionError;
    use super::result::{decode_nonce_b64url, response_to_result};

    let seed = crate::did_key::decode_private_key_multibase(setup_privkey_mb)
        .map_err(|e| ProvisionError::SetupKeyMalformed(e.to_string()))?;
    let vp = ask.to_builder().sign_with(&seed, setup_did).await?;
    let nonce = decode_nonce_b64url(&vp.nonce).map_err(ProvisionError::Armor)?;
    let request = vp.to_signed_wire_value()?;
    let response = dispatch_provision_integration(client, request, ask).await?;
    response_to_result(&seed, nonce, response)
}

/// [`provision_over`] for the `AdminRotation` ask — same round-trip,
/// different sealed-payload variant on the way out.
#[cfg(feature = "tsp")]
async fn provision_admin_rotation_over(
    client: &crate::client::VtaClient,
    setup_did: &str,
    setup_privkey_mb: &str,
    ask: &ProvisionAsk,
) -> Result<super::intent::AdminCredentialReply, super::error::ProvisionError> {
    use super::error::ProvisionError;
    use super::result::{admin_rotation_response_to_reply, decode_nonce_b64url};

    let seed = crate::did_key::decode_private_key_multibase(setup_privkey_mb)
        .map_err(|e| ProvisionError::SetupKeyMalformed(e.to_string()))?;
    let vp = ask.to_builder().sign_with(&seed, setup_did).await?;
    let nonce = decode_nonce_b64url(&vp.nonce).map_err(ProvisionError::Armor)?;
    let request = vp.to_signed_wire_value()?;
    let response = dispatch_provision_integration(client, request, ask).await?;
    admin_rotation_response_to_reply(&seed, nonce, response)
}

/// The one place the `provision/integration/0.2` trust task is built and
/// dispatched, so the two callers above cannot disagree about the wire
/// shape. `0.2` because that is the version registered on the VTA's shared
/// trust-task spine — the only surface the TSP inbound dispatcher feeds.
#[cfg(feature = "tsp")]
async fn dispatch_provision_integration(
    client: &crate::client::VtaClient,
    request: serde_json::Value,
    ask: &ProvisionAsk,
) -> Result<
    crate::provision_integration::http::ProvisionIntegrationResponse,
    super::error::ProvisionError,
> {
    use super::error::ProvisionError;
    use crate::protocols::provision_integration_management::{
        ProvisionSpecVersion, request_body_for_version,
    };

    let body_struct = crate::provision_integration::http::ProvisionIntegrationRequest {
        request,
        context: Some(ask.context.clone()),
        assertion: None,
        vc_validity_seconds: None,
        create_context: false,
    };
    let request_uri = ProvisionSpecVersion::V0_2.request_uri();
    let payload = request_body_for_version(&body_struct, request_uri)
        .map_err(ProvisionError::Serialization)?;

    let reply = client
        .dispatch_trust_task(request_uri, payload, PROVISION_TIMEOUT_SECS)
        .await
        .map_err(ProvisionError::Rpc)?;

    serde_json::from_value(reply).map_err(ProvisionError::Serialization)
}

/// Drive a one-shot `provision-integration` round-trip over TSP.
///
/// The TSP sibling of
/// [`provision_via_didcomm`](super::runner_didcomm::provision_via_didcomm)
/// and [`provision_via_rest`](super::runner::provision_via_rest).
/// Stand-alone — does not emit [`VtaEvent`]s; consumers that want
/// diagnostics drive [`super::run_provision`] instead.
///
/// - `setup_did` / `setup_private_key_mb`: the ephemeral key the operator
///   enrolled on the VTA via `pnm acl create`. TSP proves it as the sender
///   VID; the VP inside is signed with it and the returned bundle is
///   sealed to it.
/// - `tsp_mediator_did`: the mediator named by the VTA's `#tsp`
///   (`TSPTransport`) service — read it off
///   [`ResolvedVta::tsp_mediator_did`](super::resolve::ResolvedVta), not
///   off the DIDComm mediator entry, which the resolver deliberately keeps
///   separate.
#[cfg(feature = "tsp")]
pub async fn provision_via_tsp(
    setup_did: &str,
    setup_private_key_mb: &str,
    vta_did: &str,
    tsp_mediator_did: &str,
    ask: &ProvisionAsk,
) -> Result<super::result::ProvisionResult, super::error::ProvisionError> {
    use super::error::ProvisionError;

    let client = crate::client::VtaClient::connect_tsp(
        setup_did,
        setup_private_key_mb,
        vta_did,
        tsp_mediator_did,
        None,
    )
    .await
    .map_err(|e| ProvisionError::SessionOpen(e.to_string()))?;

    let result = provision_over(&client, setup_did, setup_private_key_mb, ask).await;
    client.shutdown().await;
    result
}

/// [`provision_via_tsp`] for the **admin-rotation** ask. Mirrors
/// [`provision_admin_rotation_via_didcomm`](super::runner_didcomm::provision_admin_rotation_via_didcomm).
#[cfg(feature = "tsp")]
pub async fn provision_admin_rotation_via_tsp(
    setup_did: &str,
    setup_private_key_mb: &str,
    vta_did: &str,
    tsp_mediator_did: &str,
    ask: &ProvisionAsk,
) -> Result<super::intent::AdminCredentialReply, super::error::ProvisionError> {
    use super::error::ProvisionError;

    let client = crate::client::VtaClient::connect_tsp(
        setup_did,
        setup_private_key_mb,
        vta_did,
        tsp_mediator_did,
        None,
    )
    .await
    .map_err(|e| ProvisionError::SessionOpen(e.to_string()))?;

    let result = provision_admin_rotation_over(&client, setup_did, setup_private_key_mb, ask).await;
    client.shutdown().await;
    result
}

/// `tsp`-less build: the VTA advertises `#tsp` and this binary cannot
/// speak it. Reported as a **pre-auth** failure so the orchestrator
/// degrades to DIDComm/REST when the VTA advertises one, and surfaces the
/// missing feature when it does not.
#[cfg(not(feature = "tsp"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_tsp_attempt(
    _intent: VtaIntent,
    vta_did: String,
    tsp_mediator_did: String,
    _rest_url: Option<String>,
    _setup_did: String,
    _setup_privkey_mb: String,
    _ask: ProvisionAsk,
    tx: &UnboundedSender<VtaEvent>,
) -> AttemptOutcome {
    use super::diagnostics::{DiagCheck, DiagStatus};

    let msg = tsp_feature_missing(&vta_did, &tsp_mediator_did);
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::AuthenticateTSP,
        DiagStatus::Skipped("built without the `tsp` feature".into()),
    ));
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::ListWebvhServers,
        DiagStatus::Skipped("no TSP session".into()),
    ));
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::ProvisionIntegration,
        DiagStatus::Skipped("no TSP session".into()),
    ));
    AttemptOutcome::PreAuthFailure(msg)
}

#[cfg(all(test, not(feature = "tsp")))]
mod tests {
    use super::*;

    /// The whole point of #869's honest-diagnostic half: a build that
    /// cannot speak TSP must say *that*, not "no endpoints". Anyone who
    /// reads this message must be sent to the cargo feature, not to the
    /// DID document.
    #[test]
    fn feature_missing_message_names_the_feature_not_the_document() {
        let msg = tsp_feature_missing("did:webvh:vta.test", "did:webvh:mediator.test");
        assert!(msg.contains("`tsp` feature"), "{msg}");
        assert!(msg.contains("--features tsp"), "{msg}");
        assert!(msg.contains("did:webvh:mediator.test"), "{msg}");
        assert!(
            !msg.contains("no endpoints"),
            "must not blame the DID document: {msg}"
        );
    }
}
