//! Background orchestration: pick a transport, run the diagnostic
//! checklist, dispatch to the appropriate runner.
//!
//! [`select_initial_transport`] is a pure function that picks DIDComm or
//! REST based on the VTA's advertised endpoints.
//!
//! [`run_connection_test`] is the event-driven entry point. Resolves the
//! VTA DID, enumerates services, then dispatches to either
//! [`super::runner_didcomm::run_didcomm_attempt`] or one of the
//! [`super::runner_rest`] entry points depending on the chosen transport
//! and the [`super::intent::VtaIntent`].
//!
//! [`run_provision`] wraps the whole flow into a `Result`-returning shape
//! suitable for non-interactive consumers — it forwards events to a
//! caller-owned channel AND returns the terminal reply (or error) so
//! headless code can drive the workflow without writing an event-loop.
//! For FullSetup over DIDComm with a 2+ webvh-server catalogue, it
//! errors out — interactive consumers should use `run_connection_test`
//! + their own picker UI.

use std::sync::Arc;

use tokio::sync::mpsc::{self, UnboundedSender};

use super::ask::ProvisionAsk;
use super::diagnostics::{DiagCheck, DiagStatus, Protocol};
use super::error::ProvisionError;
use super::event::{AttemptOutcome, AttemptResultKind, VtaEvent};
use super::intent::{AdminCredentialReply, VtaIntent, VtaReply};
use super::messages::OperatorMessages;
use super::resolve::{ResolvedVta, resolve_vta};
use super::result::ProvisionResult;
use super::runner_didcomm::{run_didcomm_attempt, run_provision_flight};
use super::runner_rest::{
    run_rest_attempt_admin_only, run_rest_attempt_admin_rotated, run_rest_attempt_full_setup,
};

/// Which transport(s) the VTA advertises and how the orchestrator should
/// treat them on this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialChoice {
    /// Both DIDComm and REST endpoints advertised. Start with DIDComm.
    BothAvailable,
    /// Only `#DIDCommMessaging` advertised.
    DIDCommOnly,
    /// Only `vta-rest` advertised.
    RestOnly,
    /// Neither transport is advertised — workflow cannot proceed online.
    Neither,
}

/// Decide the initial transport based on what the VTA's DID document
/// advertises. Pure function — no I/O.
pub fn select_initial_transport(resolved: &ResolvedVta) -> InitialChoice {
    match (resolved.mediator_did.is_some(), resolved.rest_url.is_some()) {
        (true, true) => InitialChoice::BothAvailable,
        (true, false) => InitialChoice::DIDCommOnly,
        (false, true) => InitialChoice::RestOnly,
        (false, false) => InitialChoice::Neither,
    }
}

/// Run the resolve → enumerate → dispatch sequence end-to-end.
///
/// Best-effort: every channel `send` is ignored on failure. Diagnostic
/// events carry enough detail for the consumer's UI to surface an
/// actionable error without having to dig into logs.
///
/// `force_transport`: `Some(Protocol::Rest)` forces REST; `Some(Protocol::DidComm)`
/// forces DIDComm; `None` lets [`select_initial_transport`] auto-pick.
/// The forced choice is honoured only when the requested transport is
/// actually advertised; otherwise the runner quietly falls back to
/// auto-pick.
pub async fn run_connection_test(
    intent: VtaIntent,
    vta_did: String,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
    force_transport: Option<Protocol>,
    tx: UnboundedSender<VtaEvent>,
) {
    // ── 1. Resolve ────────────────────────────────────────────────────
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ResolveDid));
    let resolved = match resolve_vta(&vta_did).await {
        Ok(r) => {
            let detail = match (&r.mediator_did, &r.rest_url) {
                (Some(m), _) => format!("mediator DID: {m}"),
                (None, Some(u)) => format!("REST: {u}"),
                (None, None) => "resolved (no endpoints)".into(),
            };
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ResolveDid,
                DiagStatus::Ok(detail),
            ));
            let _ = tx.send(VtaEvent::Resolved(r.clone()));
            r
        }
        Err(e) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ResolveDid,
                DiagStatus::Failed(e.to_string()),
            ));
            let _ = tx.send(VtaEvent::Failed(format!(
                "Could not resolve {vta_did}. Verify the DID is correct and its \
                 publication endpoint is reachable."
            )));
            return;
        }
    };

    // ── 2. Enumerate ──────────────────────────────────────────────────
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::EnumerateServices));
    let rest_url = resolved.rest_url.clone();
    let mediator_did_opt = resolved.mediator_did.clone();
    let enum_detail = format!(
        "REST: {}, DIDCommMessaging: {}",
        if rest_url.is_some() { "yes" } else { "no" },
        if mediator_did_opt.is_some() {
            "yes"
        } else {
            "no"
        },
    );
    let auto_choice = select_initial_transport(&resolved);

    let choice = match force_transport {
        Some(Protocol::Rest) if resolved.rest_url.is_some() => InitialChoice::RestOnly,
        Some(Protocol::DidComm) if resolved.mediator_did.is_some() => InitialChoice::DIDCommOnly,
        _ => auto_choice,
    };

    if matches!(choice, InitialChoice::Neither) {
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::EnumerateServices,
            DiagStatus::Failed(enum_detail),
        ));
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::AuthenticateDIDComm,
            DiagStatus::Skipped("no DIDComm endpoint".into()),
        ));
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::AuthenticateREST,
            DiagStatus::Skipped("no REST endpoint".into()),
        ));
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::ListWebvhServers,
            DiagStatus::Skipped("no transport".into()),
        ));
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::ProvisionIntegration,
            DiagStatus::Skipped("no transport".into()),
        ));
        let _ = tx.send(VtaEvent::Failed(
            "VTA DID document advertises neither a DIDComm mediator endpoint \
             nor a REST endpoint. Use the offline sealed-handoff flow."
                .into(),
        ));
        return;
    }
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::EnumerateServices,
        DiagStatus::Ok(enum_detail),
    ));

    // ── 3. Dispatch by transport choice ───────────────────────────────
    match choice {
        InitialChoice::BothAvailable | InitialChoice::DIDCommOnly => {
            let mediator_did = mediator_did_opt.expect("DIDComm path requires mediator_did");
            let rest_skip_msg = if matches!(choice, InitialChoice::BothAvailable) {
                "DIDComm-first VTA — REST fallback handled by consumer"
            } else {
                "DIDComm-only VTA"
            };
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateREST,
                DiagStatus::Skipped(rest_skip_msg.into()),
            ));

            let outcome = run_didcomm_attempt(
                intent,
                vta_did,
                mediator_did.clone(),
                rest_url.clone(),
                setup_did,
                setup_privkey_mb,
                ask.clone(),
                &tx,
            )
            .await;

            match outcome {
                AttemptOutcome::Connected(reply) => {
                    let _ = tx.send(VtaEvent::AttemptCompleted {
                        protocol: Protocol::DidComm,
                        outcome: AttemptResultKind::Connected,
                    });
                    let _ = tx.send(VtaEvent::Connected {
                        protocol: Protocol::DidComm,
                        rest_url,
                        mediator_did: Some(mediator_did),
                        reply,
                    });
                }
                AttemptOutcome::PreflightOk {
                    rest_url,
                    mediator_did,
                    servers,
                } => {
                    // Mid-attempt — the run_provision_flight follow-up
                    // emits its own terminal event.
                    let _ = tx.send(VtaEvent::PreflightDone {
                        rest_url,
                        mediator_did,
                        servers,
                    });
                }
                AttemptOutcome::PreAuthFailure(reason) => {
                    let _ = tx.send(VtaEvent::AttemptCompleted {
                        protocol: Protocol::DidComm,
                        outcome: AttemptResultKind::PreAuthFailure(reason.clone()),
                    });
                    let _ = tx.send(VtaEvent::Failed(reason));
                }
                AttemptOutcome::PostAuthFailure(reason) => {
                    let _ = tx.send(VtaEvent::AttemptCompleted {
                        protocol: Protocol::DidComm,
                        outcome: AttemptResultKind::PostAuthFailure(reason.clone()),
                    });
                    let _ = tx.send(VtaEvent::Failed(reason));
                }
            }
        }
        InitialChoice::RestOnly => {
            let rest_url_str = rest_url.clone().expect("REST path requires rest_url");
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateDIDComm,
                DiagStatus::Skipped("REST-only VTA".into()),
            ));

            let outcome = match intent {
                VtaIntent::AdminOnly => {
                    run_rest_attempt_admin_only(
                        &rest_url_str,
                        &vta_did,
                        setup_did,
                        setup_privkey_mb,
                        &tx,
                    )
                    .await
                }
                VtaIntent::FullSetup => {
                    run_rest_attempt_full_setup(
                        &rest_url_str,
                        &vta_did,
                        setup_did,
                        setup_privkey_mb,
                        ask,
                        &tx,
                    )
                    .await
                }
                VtaIntent::AdminRotated => {
                    run_rest_attempt_admin_rotated(
                        &rest_url_str,
                        &vta_did,
                        setup_did,
                        setup_privkey_mb,
                        ask,
                        &tx,
                    )
                    .await
                }
            };

            match outcome {
                AttemptOutcome::Connected(reply) => {
                    let _ = tx.send(VtaEvent::AttemptCompleted {
                        protocol: Protocol::Rest,
                        outcome: AttemptResultKind::Connected,
                    });
                    let _ = tx.send(VtaEvent::Connected {
                        protocol: Protocol::Rest,
                        rest_url,
                        mediator_did: None,
                        reply,
                    });
                }
                AttemptOutcome::PreflightOk { .. } => {
                    let _ = tx.send(VtaEvent::Failed(
                        "REST attempt produced an unexpected PreflightOk outcome — \
                         wiring bug; please report."
                            .into(),
                    ));
                }
                AttemptOutcome::PreAuthFailure(reason) => {
                    let _ = tx.send(VtaEvent::AttemptCompleted {
                        protocol: Protocol::Rest,
                        outcome: AttemptResultKind::PreAuthFailure(reason.clone()),
                    });
                    let _ = tx.send(VtaEvent::Failed(reason));
                }
                AttemptOutcome::PostAuthFailure(reason) => {
                    let _ = tx.send(VtaEvent::AttemptCompleted {
                        protocol: Protocol::Rest,
                        outcome: AttemptResultKind::PostAuthFailure(reason.clone()),
                    });
                    let _ = tx.send(VtaEvent::Failed(reason));
                }
            }
        }
        InitialChoice::Neither => unreachable!("handled above"),
    }
}

/// Drive the full provisioning workflow and return the terminal reply.
///
/// Forwards every [`VtaEvent`] to the caller-owned `events` channel for
/// progress rendering, and returns `Ok(VtaReply)` on a successful round-
/// trip or `Err(ProvisionError::WorkflowFailed)` on a terminal `Failed`
/// event. Handles the `PreflightDone` → `run_provision_flight`
/// transition automatically by auto-picking the webvh server when the
/// catalogue has 0 or 1 entries; bails with `WorkflowFailed` when there
/// are 2+ (interactive consumers should drive `run_connection_test` +
/// `run_provision_flight` directly to surface a picker).
///
/// The DID path is governed solely by `WEBVH_PATH`; the service `URL` (the
/// integration's DIDComm endpoint) never influences the DID name. When this
/// auto-selects a server it does **not** derive a path from `URL` — absent
/// `WEBVH_PATH` means the hosting server auto-assigns a random path. A
/// consumer that wants an explicit path sets `WEBVH_PATH` in the ask's
/// `integration_template_vars` directly (preserved by `inject_webvh_vars`),
/// or drives the lower-level `run_provision_flight`.
#[allow(clippy::too_many_arguments)]
pub async fn run_provision(
    intent: VtaIntent,
    vta_did: String,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
    force_transport: Option<Protocol>,
    messages: Arc<dyn OperatorMessages>,
    events: UnboundedSender<VtaEvent>,
) -> Result<VtaReply, ProvisionError> {
    let (internal_tx, mut internal_rx) = mpsc::unbounded_channel();

    let task_intent = intent;
    let task_vta_did = vta_did.clone();
    let task_setup_did = setup_did.clone();
    let task_setup_pk = setup_privkey_mb.clone();
    let task_ask = ask.clone();
    tokio::spawn(async move {
        run_connection_test(
            task_intent,
            task_vta_did,
            task_setup_did,
            task_setup_pk,
            task_ask,
            force_transport,
            internal_tx,
        )
        .await;
    });

    while let Some(ev) = internal_rx.recv().await {
        match ev {
            VtaEvent::Connected {
                protocol,
                rest_url,
                mediator_did,
                reply,
            } => {
                let reply_clone = reply.clone();
                let _ = events.send(VtaEvent::Connected {
                    protocol,
                    rest_url,
                    mediator_did,
                    reply,
                });
                return Ok(reply_clone);
            }
            VtaEvent::Failed(msg) => {
                let _ = events.send(VtaEvent::Failed(msg.clone()));
                return Err(ProvisionError::WorkflowFailed(msg));
            }
            VtaEvent::PreflightDone {
                rest_url,
                mediator_did,
                servers,
            } => {
                let webvh_server_id = match servers.len() {
                    0 => None,
                    1 => Some(servers[0].id.clone()),
                    n => {
                        let msg = format!(
                            "VTA has {n} registered webvh servers; auto-pick is \
                             ambiguous. Use run_connection_test + run_provision_flight \
                             directly to drive an interactive picker."
                        );
                        let _ = events.send(VtaEvent::Failed(msg.clone()));
                        return Err(ProvisionError::WorkflowFailed(msg));
                    }
                };
                // The DID path is governed solely by `WEBVH_PATH`; the
                // service `URL` must never leak into the DID name, so we no
                // longer derive a path from it. Absent `WEBVH_PATH` → the
                // hosting server auto-assigns. An explicit path already in
                // the ask's `integration_template_vars` is preserved by
                // `inject_webvh_vars` (it only inserts when `Some`), so
                // passing `None` here doesn't clobber it.
                let webvh_path: Option<String> = None;
                let mediator_did_clone = mediator_did.clone();
                let rest_url_clone = rest_url.clone();
                let _ = events.send(VtaEvent::PreflightDone {
                    rest_url,
                    mediator_did,
                    servers,
                });

                let (flight_tx, mut flight_rx) = mpsc::unbounded_channel();
                let flight_messages = messages.clone();
                let flight_vta_did = vta_did.clone();
                let flight_setup_did = setup_did.clone();
                let flight_setup_pk = setup_privkey_mb.clone();
                let flight_ask = ask.clone();
                tokio::spawn(async move {
                    run_provision_flight(
                        flight_vta_did,
                        flight_setup_did,
                        flight_setup_pk,
                        mediator_did_clone,
                        rest_url_clone,
                        flight_ask,
                        webvh_server_id,
                        webvh_path,
                        flight_messages,
                        flight_tx,
                    )
                    .await;
                });

                while let Some(fev) = flight_rx.recv().await {
                    match fev {
                        VtaEvent::Connected {
                            protocol,
                            rest_url,
                            mediator_did,
                            reply,
                        } => {
                            let reply_clone = reply.clone();
                            let _ = events.send(VtaEvent::Connected {
                                protocol,
                                rest_url,
                                mediator_did,
                                reply,
                            });
                            return Ok(reply_clone);
                        }
                        VtaEvent::Failed(msg) => {
                            let _ = events.send(VtaEvent::Failed(msg.clone()));
                            return Err(ProvisionError::WorkflowFailed(msg));
                        }
                        other => {
                            let _ = events.send(other);
                        }
                    }
                }
                return Err(ProvisionError::WorkflowAbandoned);
            }
            other => {
                let _ = events.send(other);
            }
        }
    }

    Err(ProvisionError::WorkflowAbandoned)
}

/// Drive a one-shot REST `provision-integration` round-trip. Mirror of
/// [`super::runner_didcomm::provision_via_didcomm`] for the REST path.
/// Stand-alone — does not emit [`VtaEvent`]s; consumers that want
/// diagnostics drive [`run_provision`] instead.
pub async fn provision_via_rest(
    rest_url: &str,
    vta_did: &str,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
) -> Result<ProvisionResult, ProvisionError> {
    let (tx, _rx) = mpsc::unbounded_channel();
    let outcome =
        run_rest_attempt_full_setup(rest_url, vta_did, setup_did, setup_privkey_mb, ask, &tx).await;

    match outcome {
        AttemptOutcome::Connected(VtaReply::Full(result)) => Ok(*result),
        AttemptOutcome::Connected(VtaReply::AdminOnly(_)) => Err(ProvisionError::WorkflowFailed(
            "AdminOnly reply on FullSetup REST flow — wiring bug".into(),
        )),
        AttemptOutcome::PreflightOk { .. } => Err(ProvisionError::WorkflowFailed(
            "REST flow produced PreflightOk — wiring bug".into(),
        )),
        AttemptOutcome::PreAuthFailure(reason) => Err(ProvisionError::WorkflowFailed(reason)),
        AttemptOutcome::PostAuthFailure(reason) => Err(ProvisionError::WorkflowFailed(reason)),
    }
}

/// Drive a one-shot REST `provision-integration` round-trip for the
/// **admin-rotation** intent ([`VtaIntent::AdminRotated`]). URL-direct
/// sibling of [`provision_via_rest`] (which is `FullSetup`-only): it takes an
/// explicit `rest_url` and never re-resolves `vta_did` — so a caller can drive
/// it against a loopback listener (e.g. a `MockVta`) whose DID isn't
/// resolvable back to its URL.
///
/// Returns the rotated admin credential ([`AdminCredentialReply`]). Stand-alone
/// — does not emit [`VtaEvent`]s; consumers that want diagnostics drive
/// [`run_provision`] with [`VtaIntent::AdminRotated`] instead.
pub async fn provision_admin_rotated_via_rest(
    rest_url: &str,
    vta_did: &str,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
) -> Result<AdminCredentialReply, ProvisionError> {
    let (tx, _rx) = mpsc::unbounded_channel();
    let outcome =
        run_rest_attempt_admin_rotated(rest_url, vta_did, setup_did, setup_privkey_mb, ask, &tx)
            .await;

    match outcome {
        AttemptOutcome::Connected(VtaReply::AdminOnly(reply)) => Ok(reply),
        AttemptOutcome::Connected(VtaReply::Full(_)) => Err(ProvisionError::WorkflowFailed(
            "Full reply on AdminRotated REST flow — wiring bug".into(),
        )),
        AttemptOutcome::PreflightOk { .. } => Err(ProvisionError::WorkflowFailed(
            "REST flow produced PreflightOk — wiring bug".into(),
        )),
        AttemptOutcome::PreAuthFailure(reason) => Err(ProvisionError::WorkflowFailed(reason)),
        AttemptOutcome::PostAuthFailure(reason) => Err(ProvisionError::WorkflowFailed(reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(mediator_did: Option<&str>, rest_url: Option<&str>) -> ResolvedVta {
        ResolvedVta {
            vta_did: "did:webvh:vta.test".into(),
            mediator_did: mediator_did.map(str::to_string),
            rest_url: rest_url.map(str::to_string),
        }
    }

    #[test]
    fn select_returns_both_when_both_advertised() {
        let r = resolved(Some("did:webvh:mediator.test"), Some("https://vta.test"));
        assert_eq!(select_initial_transport(&r), InitialChoice::BothAvailable);
    }

    #[test]
    fn select_returns_didcomm_only_when_only_didcomm_advertised() {
        let r = resolved(Some("did:webvh:mediator.test"), None);
        assert_eq!(select_initial_transport(&r), InitialChoice::DIDCommOnly);
    }

    #[test]
    fn select_returns_rest_only_when_only_rest_advertised() {
        let r = resolved(None, Some("https://vta.test"));
        assert_eq!(select_initial_transport(&r), InitialChoice::RestOnly);
    }

    #[test]
    fn select_returns_neither_when_no_transport_advertised() {
        let r = resolved(None, None);
        assert_eq!(select_initial_transport(&r), InitialChoice::Neither);
    }
}
