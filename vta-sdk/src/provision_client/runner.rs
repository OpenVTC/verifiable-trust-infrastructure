//! Background orchestration: pick a transport, run the diagnostic
//! checklist, dispatch to the appropriate runner.
//!
//! [`select_initial_transport`] is a pure function that picks TSP,
//! DIDComm or REST based on the VTA's advertised endpoints, in that
//! preference order.
//!
//! [`run_connection_test`] is the event-driven entry point. Resolves the
//! VTA DID, enumerates services, then dispatches to
//! [`super::runner_tsp::run_tsp_attempt`],
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
use super::runner_tsp::run_tsp_attempt;

/// Which transport(s) the VTA advertises and how the orchestrator should
/// treat them on this run.
///
/// One variant per cell of the 2×2×2 advertise matrix
/// (`#tsp` × `#DIDCommMessaging` × `#vta-rest`), so the choice never loses
/// information the runner needs for fallback. [`ResolvedVta`] carries all
/// three endpoints; before #869 this enum only looked at two of them, and a
/// VTA advertising nothing but `#tsp` therefore resolved to
/// [`Neither`](InitialChoice::Neither) — "no endpoints" — with an endpoint
/// sitting right there in the resolved document.
///
/// Preference order is TSP > DIDComm > REST, matching
/// [`ResolvedVta::advertised`] and the VTA's own inbound ranking
/// (`vta-service`'s `tsp_inbound`). The runner starts on the highest-ranked
/// transport advertised and degrades to a lower one only on a **pre-auth**
/// failure — see [`run_connection_test`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialChoice {
    /// Only `#tsp` advertised. Provisioning runs over TSP; there is nothing
    /// to fall back to, so a build without the `tsp` feature fails here
    /// (naming that as the reason).
    TspOnly,
    /// `#tsp` + `#DIDCommMessaging`. Start with TSP, fall back to DIDComm.
    /// This is the reference deployment's shape.
    TspAndDIDComm,
    /// `#tsp` + `vta-rest`. Start with TSP, fall back to REST.
    TspAndRest,
    /// All three advertised. Start with TSP, fall back to DIDComm.
    TspDIDCommAndRest,
    /// Both DIDComm and REST endpoints advertised, no `#tsp`. Start with
    /// DIDComm.
    BothAvailable,
    /// Only `#DIDCommMessaging` advertised.
    DIDCommOnly,
    /// Only `vta-rest` advertised.
    RestOnly,
    /// No transport is advertised — workflow cannot proceed online.
    Neither,
}

impl InitialChoice {
    /// Does the run start on the TSP leg?
    #[must_use]
    pub fn starts_with_tsp(self) -> bool {
        matches!(
            self,
            Self::TspOnly | Self::TspAndDIDComm | Self::TspAndRest | Self::TspDIDCommAndRest
        )
    }

    /// Is a DIDComm mediator available on this run — as the primary leg or as
    /// the TSP leg's fallback?
    #[must_use]
    pub fn has_didcomm(self) -> bool {
        matches!(
            self,
            Self::TspAndDIDComm | Self::TspDIDCommAndRest | Self::BothAvailable | Self::DIDCommOnly
        )
    }

    /// Is a REST endpoint available on this run — as the primary leg or as a
    /// fallback?
    #[must_use]
    pub fn has_rest(self) -> bool {
        matches!(
            self,
            Self::TspAndRest | Self::TspDIDCommAndRest | Self::BothAvailable | Self::RestOnly
        )
    }
}

/// Decide the initial transport based on what the VTA's DID document
/// advertises. Pure function — no I/O.
///
/// Consults **all three** of [`ResolvedVta`]'s endpoints. The result is
/// deliberately independent of which cargo features this build has: a
/// TSP-only VTA selects [`InitialChoice::TspOnly`] whether or not `tsp` is
/// compiled in, so the failure a `tsp`-less build produces names the missing
/// feature rather than pretending the DID document was empty.
pub fn select_initial_transport(resolved: &ResolvedVta) -> InitialChoice {
    match (
        resolved.tsp_mediator_did.is_some(),
        resolved.mediator_did.is_some(),
        resolved.rest_url.is_some(),
    ) {
        (true, true, true) => InitialChoice::TspDIDCommAndRest,
        (true, true, false) => InitialChoice::TspAndDIDComm,
        (true, false, true) => InitialChoice::TspAndRest,
        (true, false, false) => InitialChoice::TspOnly,
        (false, true, true) => InitialChoice::BothAvailable,
        (false, true, false) => InitialChoice::DIDCommOnly,
        (false, false, true) => InitialChoice::RestOnly,
        (false, false, false) => InitialChoice::Neither,
    }
}

/// Run the resolve → enumerate → dispatch sequence end-to-end.
///
/// Best-effort: every channel `send` is ignored on failure. Diagnostic
/// events carry enough detail for the consumer's UI to surface an
/// actionable error without having to dig into logs.
///
/// `force_transport`: `Some(Protocol::Tsp)` forces TSP;
/// `Some(Protocol::Rest)` forces REST; `Some(Protocol::DidComm)` forces
/// DIDComm; `None` lets [`select_initial_transport`] auto-pick.
/// The forced choice is honoured only when the requested transport is
/// actually advertised; otherwise the runner quietly falls back to
/// auto-pick. Forcing pins the run to that one leg — the auto-picked TSP
/// path degrades to DIDComm/REST on a pre-auth failure, a forced one does
/// not.
///
/// # Transport ranking and degradation
///
/// TSP > DIDComm > REST, per [`InitialChoice`]. When the auto-picked TSP
/// leg fails **before** auth (no `tsp` feature compiled in, mediator
/// unreachable, socket refused) and the VTA also advertises DIDComm or
/// REST, the runner reports the TSP attempt and continues on the next
/// transport rather than failing the run — the same reasoning the
/// pre-auth/post-auth split already encodes (`AttemptOutcome`). A
/// **post**-auth TSP failure is terminal: the VTA accepted us and another
/// wire reproduces the rejection.
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
            // Report the endpoint the runner will actually start on, in
            // preference order. `tsp_mediator_did` used to be missing from
            // this match, so a TSP-only VTA reported "resolved (no
            // endpoints)" about a document that had just yielded one (#869).
            let detail = match (&r.tsp_mediator_did, &r.mediator_did, &r.rest_url) {
                (Some(t), _, _) => format!("TSP mediator DID: {t}"),
                (None, Some(m), _) => format!("mediator DID: {m}"),
                (None, None, Some(u)) => format!("REST: {u}"),
                (None, None, None) => "resolved (no endpoints)".into(),
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
    let tsp_mediator_did_opt = resolved.tsp_mediator_did.clone();
    let yes_no = |present: bool| if present { "yes" } else { "no" };
    let enum_detail = format!(
        "TSP: {}, REST: {}, DIDCommMessaging: {}",
        yes_no(tsp_mediator_did_opt.is_some()),
        yes_no(rest_url.is_some()),
        yes_no(mediator_did_opt.is_some()),
    );
    let auto_choice = select_initial_transport(&resolved);

    // A forced transport pins the run to that single leg — hence the
    // `*Only` variants, which carry no fallback. Honoured only when the
    // requested transport is actually advertised.
    let choice = match force_transport {
        Some(Protocol::Tsp) if tsp_mediator_did_opt.is_some() => InitialChoice::TspOnly,
        Some(Protocol::Rest) if rest_url.is_some() => InitialChoice::RestOnly,
        Some(Protocol::DidComm) if mediator_did_opt.is_some() => InitialChoice::DIDCommOnly,
        _ => auto_choice,
    };

    if matches!(choice, InitialChoice::Neither) {
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::EnumerateServices,
            DiagStatus::Failed(enum_detail),
        ));
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::AuthenticateTSP,
            DiagStatus::Skipped("no TSP endpoint".into()),
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
            DiagCheck::VerifyAuthorization,
            DiagStatus::Skipped("no transport".into()),
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
            "VTA DID document advertises no usable transport — no `#tsp` \
             service, no DIDComm mediator endpoint, and no REST endpoint. \
             Use the offline sealed-handoff flow."
                .into(),
        ));
        return;
    }
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::EnumerateServices,
        DiagStatus::Ok(enum_detail),
    ));

    // ── 3. Dispatch by transport choice ───────────────────────────────
    if choice.starts_with_tsp() {
        let tsp_mediator_did = tsp_mediator_did_opt.expect("TSP path requires tsp_mediator_did");
        let outcome = run_tsp_attempt(
            intent,
            vta_did.clone(),
            tsp_mediator_did.clone(),
            rest_url.clone(),
            setup_did.clone(),
            setup_privkey_mb.clone(),
            ask.clone(),
            &tx,
        )
        .await;

        // Degrade only on a pre-auth failure, and only when the document
        // actually advertises somewhere else to go. Everything else is
        // terminal on this leg.
        if let AttemptOutcome::PreAuthFailure(reason) = &outcome
            && (choice.has_didcomm() || choice.has_rest())
        {
            let _ = tx.send(VtaEvent::AttemptCompleted {
                protocol: Protocol::Tsp,
                outcome: AttemptResultKind::PreAuthFailure(reason.clone()),
            });
            if choice.has_didcomm() {
                let mediator_did =
                    mediator_did_opt.expect("has_didcomm() implies an advertised mediator");
                dispatch_didcomm_leg(
                    intent,
                    vta_did,
                    mediator_did,
                    rest_url,
                    setup_did,
                    setup_privkey_mb,
                    ask,
                    "TSP leg unavailable — continuing on DIDComm",
                    &tx,
                )
                .await;
            } else {
                let rest_url_str = rest_url.clone().expect("has_rest() implies a REST URL");
                dispatch_rest_leg(
                    intent,
                    vta_did,
                    rest_url_str,
                    rest_url,
                    setup_did,
                    setup_privkey_mb,
                    ask,
                    "TSP leg unavailable — continuing on REST",
                    &tx,
                )
                .await;
            }
            return;
        }

        emit_mediator_outcome(Protocol::Tsp, outcome, rest_url, tsp_mediator_did, &tx);
        return;
    }

    match choice {
        InitialChoice::BothAvailable | InitialChoice::DIDCommOnly => {
            let mediator_did = mediator_did_opt.expect("DIDComm path requires mediator_did");
            let rest_skip_msg = if matches!(choice, InitialChoice::BothAvailable) {
                "DIDComm-first VTA — REST fallback handled by consumer"
            } else {
                "DIDComm-only VTA"
            };
            dispatch_didcomm_leg(
                intent,
                vta_did,
                mediator_did,
                rest_url,
                setup_did,
                setup_privkey_mb,
                ask,
                rest_skip_msg,
                &tx,
            )
            .await;
        }
        InitialChoice::RestOnly => {
            let rest_url_str = rest_url.clone().expect("REST path requires rest_url");
            dispatch_rest_leg(
                intent,
                vta_did,
                rest_url_str,
                rest_url,
                setup_did,
                setup_privkey_mb,
                ask,
                "REST-only VTA",
                &tx,
            )
            .await;
        }
        InitialChoice::Neither => unreachable!("handled above"),
        InitialChoice::TspOnly
        | InitialChoice::TspAndDIDComm
        | InitialChoice::TspAndRest
        | InitialChoice::TspDIDCommAndRest => {
            unreachable!("handled by the starts_with_tsp() branch above")
        }
    }
}

/// Translate a mediator-transport attempt (TSP or DIDComm) into the
/// terminal [`VtaEvent`]s. Shared so the two legs cannot drift in what
/// they report; `protocol` and `mediator_did` are what differ.
fn emit_mediator_outcome(
    protocol: Protocol,
    outcome: AttemptOutcome,
    rest_url: Option<String>,
    mediator_did: String,
    tx: &UnboundedSender<VtaEvent>,
) {
    match outcome {
        AttemptOutcome::Connected(reply) => {
            let _ = tx.send(VtaEvent::AttemptCompleted {
                protocol,
                outcome: AttemptResultKind::Connected,
            });
            let _ = tx.send(VtaEvent::Connected {
                protocol,
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
                protocol,
                outcome: AttemptResultKind::PreAuthFailure(reason.clone()),
            });
            let _ = tx.send(VtaEvent::Failed(reason));
        }
        AttemptOutcome::PostAuthFailure(reason) => {
            let _ = tx.send(VtaEvent::AttemptCompleted {
                protocol,
                outcome: AttemptResultKind::PostAuthFailure(reason.clone()),
            });
            let _ = tx.send(VtaEvent::Failed(reason));
        }
    }
}

/// Run the DIDComm leg and emit its terminal events.
///
/// Extracted from [`run_connection_test`]'s match so the TSP leg can reuse
/// it verbatim as its pre-auth fallback rather than growing a second copy.
#[allow(clippy::too_many_arguments)]
async fn dispatch_didcomm_leg(
    intent: VtaIntent,
    vta_did: String,
    mediator_did: String,
    rest_url: Option<String>,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
    rest_skip_msg: &str,
    tx: &UnboundedSender<VtaEvent>,
) {
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::AuthenticateREST,
        DiagStatus::Skipped(rest_skip_msg.to_string()),
    ));

    let outcome = run_didcomm_attempt(
        intent,
        vta_did,
        mediator_did.clone(),
        rest_url.clone(),
        setup_did,
        setup_privkey_mb,
        ask,
        tx,
    )
    .await;

    emit_mediator_outcome(Protocol::DidComm, outcome, rest_url, mediator_did, tx);
}

/// Run the REST leg and emit its terminal events. The counterpart to
/// [`dispatch_didcomm_leg`], reused as the TSP leg's fallback when the VTA
/// advertises REST but no DIDComm mediator.
#[allow(clippy::too_many_arguments)]
async fn dispatch_rest_leg(
    intent: VtaIntent,
    vta_did: String,
    rest_url_str: String,
    rest_url: Option<String>,
    setup_did: String,
    setup_privkey_mb: String,
    ask: ProvisionAsk,
    didcomm_skip_msg: &str,
    tx: &UnboundedSender<VtaEvent>,
) {
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::AuthenticateDIDComm,
        DiagStatus::Skipped(didcomm_skip_msg.to_string()),
    ));

    let outcome = match intent {
        VtaIntent::AdminOnly => {
            run_rest_attempt_admin_only(&rest_url_str, &vta_did, setup_did, setup_privkey_mb, tx)
                .await
        }
        VtaIntent::FullSetup => {
            run_rest_attempt_full_setup(
                &rest_url_str,
                &vta_did,
                setup_did,
                setup_privkey_mb,
                ask,
                tx,
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
                tx,
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

    const TSP_MEDIATOR: &str = "did:webvh:tsp-mediator.test";
    const MEDIATOR: &str = "did:webvh:mediator.test";
    const REST: &str = "https://vta.test";

    /// Full three-endpoint fixture. `tsp` is deliberately a *separate*
    /// argument from `mediator_did` — the resolver reads the `#tsp` entry on
    /// its own and never assumes it equals the DIDComm mediator, so the
    /// selection matrix must be exercised with them independent.
    fn resolved(
        tsp: Option<&str>,
        mediator_did: Option<&str>,
        rest_url: Option<&str>,
    ) -> ResolvedVta {
        ResolvedVta {
            vta_did: "did:webvh:vta.test".into(),
            tsp_mediator_did: tsp.map(str::to_string),
            mediator_did: mediator_did.map(str::to_string),
            rest_url: rest_url.map(str::to_string),
        }
    }

    // ── The 2×2×2 selection matrix ────────────────────────────────────
    //
    // Eight advertise combinations, eight variants, one test each. The
    // matrix is pinned exhaustively because #869 was precisely a cell that
    // nothing covered: `select_initial_transport` matched on two of the
    // three endpoints `ResolvedVta` carries, so every TSP-advertising row
    // below collapsed onto its non-TSP neighbour and the TSP-only row
    // reported `Neither`.

    #[test]
    fn select_returns_tsp_only_when_only_tsp_advertised() {
        let r = resolved(Some(TSP_MEDIATOR), None, None);
        assert_eq!(
            select_initial_transport(&r),
            InitialChoice::TspOnly,
            "a TSP-only VTA must not resolve to `Neither` — #869"
        );
    }

    #[test]
    fn select_returns_tsp_and_didcomm_when_both_mediator_transports_advertised() {
        let r = resolved(Some(TSP_MEDIATOR), Some(MEDIATOR), None);
        assert_eq!(select_initial_transport(&r), InitialChoice::TspAndDIDComm);
    }

    #[test]
    fn select_returns_tsp_and_rest_when_tsp_and_rest_advertised() {
        let r = resolved(Some(TSP_MEDIATOR), None, Some(REST));
        assert_eq!(select_initial_transport(&r), InitialChoice::TspAndRest);
    }

    #[test]
    fn select_returns_all_three_when_all_three_advertised() {
        let r = resolved(Some(TSP_MEDIATOR), Some(MEDIATOR), Some(REST));
        assert_eq!(
            select_initial_transport(&r),
            InitialChoice::TspDIDCommAndRest
        );
    }

    #[test]
    fn select_returns_both_when_both_advertised() {
        let r = resolved(None, Some(MEDIATOR), Some(REST));
        assert_eq!(select_initial_transport(&r), InitialChoice::BothAvailable);
    }

    #[test]
    fn select_returns_didcomm_only_when_only_didcomm_advertised() {
        let r = resolved(None, Some(MEDIATOR), None);
        assert_eq!(select_initial_transport(&r), InitialChoice::DIDCommOnly);
    }

    #[test]
    fn select_returns_rest_only_when_only_rest_advertised() {
        let r = resolved(None, None, Some(REST));
        assert_eq!(select_initial_transport(&r), InitialChoice::RestOnly);
    }

    #[test]
    fn select_returns_neither_when_no_transport_advertised() {
        let r = resolved(None, None, None);
        assert_eq!(select_initial_transport(&r), InitialChoice::Neither);
    }

    /// `Neither` means exactly one thing: the document advertises nothing.
    /// Any advertised endpoint — including a `#tsp` the SDK may or may not
    /// have been compiled to speak — must select something else, because
    /// `Neither` is what makes the runner print "advertises no usable
    /// transport" and send the operator hunting a DID-document error.
    #[test]
    fn neither_is_reserved_for_a_document_that_advertises_nothing() {
        for (tsp, didcomm, rest) in [
            (Some(TSP_MEDIATOR), None, None),
            (None, Some(MEDIATOR), None),
            (None, None, Some(REST)),
            (Some(TSP_MEDIATOR), Some(MEDIATOR), Some(REST)),
        ] {
            let r = resolved(tsp, didcomm, rest);
            assert_ne!(
                select_initial_transport(&r),
                InitialChoice::Neither,
                "{:?} advertises something",
                r.advertised()
            );
        }
    }

    /// Selection is feature-independent by construction: this assertion
    /// holds in a `tsp` build and a non-`tsp` build alike. A build that
    /// cannot speak TSP still *selects* TSP and then fails naming the
    /// missing cargo feature — see `runner_tsp`.
    #[test]
    fn tsp_selection_does_not_depend_on_the_tsp_feature() {
        let r = resolved(Some(TSP_MEDIATOR), None, None);
        assert_eq!(select_initial_transport(&r), InitialChoice::TspOnly);
    }

    // ── Ranking helpers: TSP > DIDComm > REST ─────────────────────────

    /// Every TSP-advertising cell starts on TSP; no other cell does.
    #[test]
    fn starts_with_tsp_covers_exactly_the_tsp_variants() {
        for choice in [
            InitialChoice::TspOnly,
            InitialChoice::TspAndDIDComm,
            InitialChoice::TspAndRest,
            InitialChoice::TspDIDCommAndRest,
        ] {
            assert!(choice.starts_with_tsp(), "{choice:?}");
        }
        for choice in [
            InitialChoice::BothAvailable,
            InitialChoice::DIDCommOnly,
            InitialChoice::RestOnly,
            InitialChoice::Neither,
        ] {
            assert!(!choice.starts_with_tsp(), "{choice:?}");
        }
    }

    /// The fallback predicates must agree with what the resolved document
    /// actually carried, or the runner's `expect`s in the degrade path are
    /// live panics.
    #[test]
    fn fallback_predicates_match_the_resolved_endpoints() {
        for (tsp, didcomm, rest) in [
            (None, None, None),
            (None, None, Some(REST)),
            (None, Some(MEDIATOR), None),
            (None, Some(MEDIATOR), Some(REST)),
            (Some(TSP_MEDIATOR), None, None),
            (Some(TSP_MEDIATOR), None, Some(REST)),
            (Some(TSP_MEDIATOR), Some(MEDIATOR), None),
            (Some(TSP_MEDIATOR), Some(MEDIATOR), Some(REST)),
        ] {
            let r = resolved(tsp, didcomm, rest);
            let choice = select_initial_transport(&r);
            assert_eq!(
                choice.starts_with_tsp(),
                r.tsp_mediator_did.is_some(),
                "{choice:?}"
            );
            assert_eq!(choice.has_didcomm(), r.mediator_did.is_some(), "{choice:?}");
            assert_eq!(choice.has_rest(), r.rest_url.is_some(), "{choice:?}");
        }
    }

    /// TSP-only is the one cell with nowhere to degrade to — the runner
    /// must surface the TSP failure rather than silently trying nothing.
    #[test]
    fn tsp_only_has_no_fallback() {
        assert!(!InitialChoice::TspOnly.has_didcomm());
        assert!(!InitialChoice::TspOnly.has_rest());
    }
}
