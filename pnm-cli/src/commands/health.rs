//! Dispatch for `pnm health` — the multi-section diagnostic run.
//!
//! Sections:
//!   - VTA: DID, resolution, advertised mode (REST / DIDComm / both)
//!   - Authentication: token freshness against the resolved REST URL
//!   - Mediator + DIDComm pings: trust-ping over the configured mediator
//!
//! Sections are intentionally individually fault-tolerant — a failure
//! in one row never aborts the rest, since the operator's most common
//! reason to run `pnm health` is precisely to find the broken row.

use vta_cli_common::render::{CYAN, DIM, GREEN, RED, RESET, print_section};
use vta_sdk::client::VtaClient;

use crate::auth;

/// `println!` that stays quiet when the caller asked for JSON — the
/// document is emitted once at the end instead.
macro_rules! hprintln {
    ($($arg:tt)*) => {
        if !vta_cli_common::render::is_json_output() {
            println!($($arg)*);
        }
    };
}

/// One probe's verdict.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Check {
    section: &'static str,
    name: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// What this run found. Built as the run goes, so the sequence that
/// prints the human rows is the one that yields the JSON document and
/// the two cannot disagree. Owned by `run` rather than held globally —
/// it is per-run data, and a second run must not inherit the first's
/// verdicts.
#[derive(Debug, Default)]
struct Report {
    section: &'static str,
    checks: Vec<Check>,
}

impl Report {
    /// Open a section. Prints its heading for a human; under `--json` it
    /// only sets what subsequent checks are filed under.
    fn section(&mut self, name: &'static str, label: &str) {
        self.section = name;
        if !vta_cli_common::render::is_json_output() {
            print_section(label);
        }
    }

    fn record(&mut self, name: &'static str, ok: bool, detail: Option<String>) {
        self.checks.push(Check {
            section: self.section,
            name,
            ok,
            detail,
        });
    }

    fn failures(&self) -> usize {
        self.checks.iter().filter(|c| !c.ok).count()
    }

    /// Whether this run established health.
    ///
    /// A run that probed nothing has not — an unconfigured profile
    /// records no checks, and reporting that as healthy would hand a
    /// pipeline a green light for a VTA that was never contacted.
    fn healthy(&self) -> bool {
        !self.checks.is_empty() && self.failures() == 0
    }
}

pub(crate) async fn run(
    url_override: Option<&str>,
    keyring_key: &str,
    fresh_tsp_probe: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut report = Report::default();
    let session = auth::loaded_session(keyring_key);

    // The process-shared DID resolver — the same one the SDK's own entry points
    // (authentication, endpoint discovery) use, so a DID resolved here is not
    // fetched again by them. Honours PNM_RESOLVER_URL (set from
    // `~/.config/pnm/config.toml`'s `resolver_url` at startup).
    let did_resolver = vta_sdk::resolver::shared_did_resolver_from_env().await.ok();

    // ── VTA ────────────────────────────────────────────────────────
    report.section("vta", "VTA");

    if let Some(ref info) = session {
        match info.vta_did.as_deref() {
            Some(vta_did) => {
                hprintln!("  {CYAN}{:<13}{RESET} {vta_did}", "DID");
                if let Some(ref resolver) = did_resolver {
                    match resolver.resolve(vta_did).await {
                        Ok(resolved) => {
                            let method = vta_did
                                .strip_prefix("did:")
                                .and_then(|s| s.split(':').next())
                                .unwrap_or("?");
                            report.record("resolution", true, Some(method.to_string()));
                            hprintln!("                {GREEN}✓{RESET} resolves ({method})");
                            // Names the document claims via `alsoKnownAs`.
                            // Free — the document is already in hand — and
                            // marked as claims because that half of the
                            // binding is self-asserted until resolved forward.
                            for claim in &resolved.doc.also_known_as {
                                hprintln!(
                                    "                {DIM}claims (unverified): {claim}{RESET}"
                                );
                            }
                        }
                        Err(e) => {
                            report.record("resolution", false, Some(e.to_string()));
                            hprintln!("                {RED}✗{RESET} resolution failed: {e}")
                        }
                    }
                }
            }
            None => {
                hprintln!(
                    "  {CYAN}{:<13}{RESET} {DIM}(pending — run `pnm setup continue <slug>`){RESET}",
                    "DID"
                );
            }
        }
    }

    // What the VTA's DID document actually advertises — the source of truth for
    // the "Mode" label below, and for whether to show URL / probe Service /
    // attempt REST authentication. Parse advertised transports by service
    // **type** (TSPTransport / DIDCommMessaging / VTARest) via the SDK's
    // canonical matcher — never by the `#id` fragment. This is what makes a
    // TSP-enabled VTA show as "TSP + DIDComm" rather than the old TSP-blind
    // "DIDComm-only" (the previous `resolve_vta_endpoint` had no TSP variant and
    // matched REST by `#vta-rest` id). An explicit `--url` override (or
    // `[vta] url = "..."` in pnm config) is still the only thing that can light
    // up the REST rows when the DID document doesn't advertise REST itself.
    // Uses the shared cached resolver rather than spinning up its own.
    let caps = match (
        session.as_ref().and_then(|s| s.vta_did.as_deref()),
        did_resolver.as_ref(),
    ) {
        (Some(vta_did), Some(resolver)) => resolver
            .resolve(vta_did)
            .await
            .ok()
            .and_then(|r| serde_json::to_value(&r.doc).ok())
            .map(|doc| vta_sdk::protocol::matching::ServiceCapabilities::from_did_document(&doc)),
        _ => None,
    };

    let has_vta_did = session
        .as_ref()
        .and_then(|s| s.vta_did.as_deref())
        .is_some();

    let (mode_label, advertised_rest_url, advertises_messaging) = match &caps {
        Some(caps) => {
            use vta_sdk::protocol::matching::Protocol;
            let label = if caps.advertised().is_empty() {
                "unknown (no advertised services)".to_string()
            } else {
                caps.advertised()
                    .iter()
                    .map(|p| match p {
                        Protocol::Tsp => "TSP",
                        Protocol::Didcomm => "DIDComm",
                        Protocol::Rest => "REST",
                    })
                    .collect::<Vec<_>>()
                    .join(" + ")
            };
            let rest_url = caps
                .rest
                .as_deref()
                .map(|u| u.trim_matches('"').trim_end_matches('/').to_string());
            (
                label,
                rest_url,
                caps.tsp.is_some() || caps.didcomm.is_some(),
            )
        }
        None if has_vta_did => (
            "unknown (could not enumerate services)".to_string(),
            None,
            false,
        ),
        None => ("(pending DID setup)".to_string(), None, false),
    };
    hprintln!("  {CYAN}{:<13}{RESET} {mode_label}", "Mode");

    // Effective URL = explicit override (CLI / config) OR what the DID
    // doc advertised. When neither is present (DIDComm-only VTA, no
    // override), `effective_rest_url` stays None and the URL / Service
    // / Authentication rows below are suppressed entirely.
    let override_url = url_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let url_overridden =
        override_url.is_some() && advertised_rest_url.as_deref() != override_url.as_deref();
    let effective_rest_url = override_url.clone().or_else(|| advertised_rest_url.clone());

    if let Some(ref url) = effective_rest_url {
        let suffix = if url_overridden {
            format!(" {DIM}(--url override){RESET}")
        } else {
            format!(" {DIM}(from DID){RESET}")
        };
        hprintln!("  {CYAN}{:<13}{RESET} {url}{suffix}", "URL");

        let probe_client = VtaClient::new(url);
        match probe_client.health().await {
            Ok(resp) => {
                let ver = resp
                    .version
                    .as_deref()
                    .map(|v| format!(" (v{v})"))
                    .unwrap_or_default();
                report.record("service", true, None);
                hprintln!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} ok{ver}", "Service");
            }
            Err(e) => {
                report.record("service", false, Some(e.to_string()));
                hprintln!(
                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} unreachable ({e})",
                    "Service"
                );
            }
        }
    }

    // ── Authentication ─────────────────────────────────────────────
    report.section("authentication", "Authentication");

    if let Some(ref url) = effective_rest_url {
        if let Some(ref info) = session {
            hprintln!("  {CYAN}{:<13}{RESET} {}", "Client DID", info.client_did);
            match auth::ensure_authenticated(url, keyring_key).await {
                Ok(_token) => {
                    if let Some(status) = auth::session_status(keyring_key) {
                        match status.token_status {
                            vta_sdk::session::TokenStatus::Valid { expires_in_secs } => {
                                report.record(
                                    "token",
                                    true,
                                    Some(format!("expires in {expires_in_secs}s")),
                                );
                                hprintln!(
                                    "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} valid (expires in {expires_in_secs}s)",
                                    "Token"
                                );
                            }
                            _ => {
                                report.record("token", true, None);
                                hprintln!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} valid", "Token");
                            }
                        }
                    }
                }
                Err(e) => {
                    report.record("token", false, Some(e.to_string()));
                    hprintln!("  {CYAN}{:<13}{RESET} {RED}✗{RESET} {e}", "Token");
                }
            }
        } else {
            hprintln!("  {DIM}Not authenticated{RESET}");
        }
    } else if advertises_messaging {
        hprintln!("  {DIM}Messaging-only VTA (TSP/DIDComm) — no REST auth{RESET}");
    } else {
        hprintln!("  {DIM}No transport advertised{RESET}");
    }

    // Re-read the session before anything below uses its key material.
    //
    // The `session` above is a snapshot taken at the top of `run`, but the
    // Authentication section just called `ensure_authenticated`, which rotates a
    // `needs_rotation` temp did:key: it mints a fresh DID, moves the ACL entry
    // onto it and *deletes the temp entry at the VTA*. The snapshot's
    // `client_did` / `private_key_multibase` are the dead temp identity from
    // that point on.
    //
    // Reading a stale identity used to cost only a failing ping. It now costs a
    // write: the DIDComm probe below provisions an allow-all mediator account
    // keyed on `sha256(client_did)`, so a stale DID here leaves a permanently
    // open account for a throwaway credential — exactly the litter
    // `vta_sdk::acl_setup`'s module docs say the SDK avoids.
    let session = auth::loaded_session(keyring_key).or(session);

    // ── Mediator + DIDComm pings ──────────────────────────────────
    report.section("mediator", "Mediator");

    if let Some(ref info) = session
        && let Some(vta_did) = info.vta_did.as_deref()
    {
        // Resolve mediator DID using the shared resolver (avoids creating a second one)
        let mediator_result = if let Some(ref resolver) = did_resolver {
            vta_sdk::session::resolve_mediator_did_with_resolver(vta_did, resolver).await
        } else {
            vta_sdk::session::resolve_mediator_did(vta_did).await
        };

        let mediator_result = match mediator_result {
            Ok(Some(mediator_did)) => Ok(Some((mediator_did, false))),
            Ok(None) => {
                // DID document has no DIDCommMessaging service (e.g. did:key).
                // Fallback: query VTA's REST status endpoint for mediator info.
                if let Some(url) = effective_rest_url.as_deref() {
                    match auth::ensure_authenticated(url, keyring_key).await {
                        Ok(_token) => {
                            let client = match auth::authenticated_client(url, keyring_key).await {
                                Ok(c) => c,
                                // The outer arm already handled an auth
                                // failure; this can only be a missing session,
                                // which the DIDComm probe below reports.
                                Err(_) => return Ok(()),
                            };
                            match client.didcomm_status().await {
                                Ok(status) if status.enabled => {
                                    Ok(status.mediator_did.map(|did| (did, true)))
                                }
                                Ok(_) => Ok(None),
                                Err(e) => {
                                    hprintln!("  {DIM}(status check failed: {e}){RESET}");
                                    Ok(None)
                                }
                            }
                        }
                        Err(e) => {
                            hprintln!("  {DIM}(auth for status check failed: {e}){RESET}");
                            Ok(None)
                        }
                    }
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(e),
        };

        match mediator_result {
            Ok(Some((mediator_did, via_status_endpoint))) => {
                hprintln!("  {CYAN}{:<13}{RESET} {mediator_did}", "DID");
                if via_status_endpoint {
                    hprintln!("                {DIM}discovered via /services/didcomm{RESET}");
                }

                // Resolve mediator DID document (uses cached resolver)
                if let Some(ref resolver) = did_resolver {
                    match resolver.resolve(&mediator_did).await {
                        Ok(_) => {
                            let method = mediator_did
                                .strip_prefix("did:")
                                .and_then(|s| s.split(':').next())
                                .unwrap_or("?");
                            report.record("resolution", true, Some(method.to_string()));
                            hprintln!("                {GREEN}✓{RESET} resolves ({method})");
                        }
                        Err(e) => {
                            report.record("resolution", false, Some(e.to_string()));
                            hprintln!("                {RED}✗{RESET} resolution failed: {e}");
                        }
                    }
                }

                // Set up a single DIDComm session and reuse for both pings
                match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    vta_sdk::session::TrustPingSession::new(
                        &info.client_did,
                        &info.private_key_multibase,
                        &mediator_did,
                    ),
                )
                .await
                {
                    Ok(Ok(session)) => {
                        // Open this client's own mediator account (allow-all)
                        // over the session's live socket before the forwarded
                        // VTA trust-ping. A freshly bootstrapped or rotated
                        // client is closed for forwarded delivery, so the VTA's
                        // pong would otherwise be dropped by the mediator.
                        session.provision_client_acl("pnm").await;

                        // Ping mediator (steady-state: warm-up + measured)
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(20),
                            steady_ping(&session, None),
                        )
                        .await
                        {
                            Ok(Ok(latency)) => {
                                report.record("trust-ping", true, Some(format!("{latency}ms")));
                                hprintln!("                {GREEN}✓{RESET} pong ({latency}ms)");
                            }
                            Ok(Err(e)) => {
                                report.record("trust-ping", false, Some(e.to_string()));
                                hprintln!("                {RED}✗{RESET} trust-ping failed: {e}");
                            }
                            Err(_) => {
                                report.record("trust-ping", false, None);
                                hprintln!("                {RED}✗{RESET} trust-ping timed out");
                            }
                        }

                        // Ping VTA through the same session (steady-state)
                        report.section("vta-didcomm", "VTA DIDComm");

                        match tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            steady_ping(&session, Some(vta_did)),
                        )
                        .await
                        {
                            Ok(Ok(latency)) => {
                                report.record("trust-ping", true, Some(format!("{latency}ms")));
                                hprintln!(
                                    "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                                    "Trust-ping"
                                );
                            }
                            Ok(Err(e)) => {
                                report.record("trust-ping", false, Some(e.to_string()));
                                hprintln!(
                                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping failed: {e}",
                                    "Trust-ping"
                                );
                            }
                            Err(_) => {
                                report.record("trust-ping", false, None);
                                hprintln!(
                                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping timed out",
                                    "Trust-ping"
                                );
                            }
                        }

                        session.shutdown().await;
                    }
                    Ok(Err(e)) => {
                        report.record("setup", false, Some(e.to_string()));
                        hprintln!("                {RED}✗{RESET} DIDComm setup failed: {e}");
                    }
                    Err(_) => {
                        report.record("setup", false, None);
                        hprintln!("                {RED}✗{RESET} DIDComm setup timed out");
                    }
                }
            }
            Ok(None) => {
                hprintln!("  {DIM}(not configured){RESET}");
            }
            Err(e) => {
                report.record("vta-did", false, Some(e.to_string()));
                hprintln!(
                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} could not resolve VTA DID: {e}",
                    "DID"
                );
            }
        }
    } else {
        hprintln!("  {DIM}(no session){RESET}");
    }

    // ── VTA TSP ────────────────────────────────────────────────────
    // TSP is the highest-preference transport; probe it when the VTA's DID
    // document advertises a `TSPTransport` service. That `#tsp` endpoint is the
    // mediator DID (the VTA is a local account on it — the same mediator the
    // DIDComm probe used). This runs *after* the DIDComm `TrustPingSession`
    // above has shut down, so the client DID never holds two mediator sockets at
    // once (the one-socket-per-DID rule — ADR 0005).
    let tsp_mediator = caps.as_ref().and_then(|c| c.tsp.as_deref());
    if let (Some(tsp_mediator), Some(info)) = (tsp_mediator, session.as_ref())
        && let Some(vta_did) = info.vta_did.as_deref()
    {
        report.section("vta-tsp", "VTA TSP");
        // `--fresh`: probe from a throwaway `did:key` minted right here. A DID
        // that did not exist until this instant can hold no pre-existing TSP
        // relationship, so a successful cold *send* is an unambiguous
        // relationship-free routed send — the §3 test with no reliance on the
        // in-memory-store assumption. Only the send is judged: the throwaway VID
        // has no ACL entry and isn't a registered mediator account, so it can't
        // complete a round-trip. Session identity (`cold = false`) does the full
        // pong round-trip.
        if fresh_tsp_probe {
            let (fresh_did, fresh_key) =
                vta_cli_common::local_keygen::generate_unbound_admin_did_key();
            hprintln!(
                "  {DIM}cold send probe — fresh throwaway DID (no prior relationship possible):{RESET}"
            );
            hprintln!("  {CYAN}{:<13}{RESET} {fresh_did}", "Probe DID");
            tsp_probe(
                &fresh_did,
                &fresh_key,
                tsp_mediator,
                vta_did,
                true,
                &mut report,
            )
            .await;
        } else {
            tsp_probe(
                &info.client_did,
                &info.private_key_multibase,
                tsp_mediator,
                vta_did,
                false,
                &mut report,
            )
            .await;
        }
    }

    let failed = report.failures();

    if report.checks.is_empty() {
        // Nothing was probed. Saying so beats an empty document that
        // reads as a pass.
        hprintln!();
        hprintln!("  {RED}✗{RESET} no checks ran — is a VTA configured? (`pnm vta list`)");
    }

    if vta_cli_common::render::is_json_output() {
        vta_cli_common::render::print_json(&serde_json::json!({
            "healthy": report.healthy(),
            "checks": report.checks,
        }))?;
    }

    // The rows above are printed whether they passed or not; without this
    // the command exits 0 over a broken VTA and a pipeline gating on it
    // stays green.
    if report.checks.is_empty() {
        return Err("no health checks ran — no VTA is configured for this profile".into());
    }

    if failed > 0 {
        return Err(format!(
            "{failed} health check{} failed (see the rows above)",
            if failed == 1 { "" } else { "s" }
        )
        .into());
    }

    Ok(())
}

/// Ping `target` twice through `session`, discarding the first and returning the
/// second — a **steady-state** latency. The first ping pays one-time costs the
/// steady state shouldn't be blamed for (resolving the target's DID + routing on
/// first send), which is why a cold VTA ping reads far higher than the
/// already-connected mediator ping. If the warm-up fails, its error is returned
/// (the endpoint is down; measuring twice adds nothing).
async fn steady_ping(
    session: &vta_sdk::session::TrustPingSession,
    target: Option<&str>,
) -> Result<u128, Box<dyn std::error::Error>> {
    session.ping(target).await?; // warm-up (propagates a genuine failure)
    session.ping(target).await // measured
}

/// Drive the TSP connectivity probe: open the client's TSP websocket to the
/// mediator and send a Trust Task to the VTA over TSP. With `cold = false`
/// (session identity) it awaits the reply and reports round-trip latency. With
/// `cold = true` (a throwaway `--fresh` DID) it reports on the **send** alone —
/// a throwaway VID has no ACL entry (the VTA 403s the ping) and isn't a
/// registered mediator account (the reply can't route back), so a round-trip is
/// impossible; the send succeeding is the §3 test (a cold relationship-free
/// routed send). Compiled only with the `tsp` feature.
#[cfg(feature = "tsp")]
async fn tsp_probe(
    client_did: &str,
    private_key_multibase: &str,
    mediator_did: &str,
    vta_did: &str,
    cold: bool,
    report: &mut Report,
) {
    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        vta_sdk::session::TspPingSession::new(client_did, private_key_multibase, mediator_did),
    )
    .await
    {
        Ok(Ok(mut session)) => {
            if cold {
                // The cold routed SEND is the whole §3 test here — no reply wait,
                // because a throwaway VID can never complete the round-trip.
                match session.probe_send(vta_did).await {
                    Ok(()) => {
                        report.record("cold-send", true, None);
                        hprintln!(
                            "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} cold send accepted — relationship-free routed send (§3 = 3c)",
                            "Cold-send"
                        );
                    }
                    Err(e) => {
                        report.record("cold-send", false, Some(e.to_string()));
                        hprintln!(
                            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} cold send failed: {e}",
                            "Cold-send"
                        );
                    }
                }
            } else {
                // §7.2.2: the VTA drops an application-level ping from a VID it
                // holds no relationship with — which, for a session-identity
                // probe, is every fresh run. Form the relationship first (the
                // VTA's answering arm accepts it, and an invite already admits
                // the messages that follow it, §3.6). `relate` is idempotent by
                // state read, so a persisted relationship is a no-op.
                //
                // Then a warm-up ping (pays the first-send VID/route resolution)
                // and a measured one — a steady-state latency comparable to the
                // DIDComm probe. A relate or warm-up failure is reported straight
                // away.
                let ping_timeout = std::time::Duration::from_secs(10);
                let measured = match session.relate(vta_did).await {
                    Ok(()) => match session.ping(vta_did, ping_timeout).await {
                        Ok(_) => session.ping(vta_did, ping_timeout).await,
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                };
                match measured {
                    Ok(latency) => {
                        report.record("ping", true, Some(format!("{latency}ms")));
                        hprintln!(
                            "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                            "Trust-ping"
                        );
                    }
                    Err(e) => {
                        report.record("ping", false, Some(e.to_string()));
                        hprintln!(
                            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} TSP ping failed: {e}",
                            "Trust-ping"
                        );
                    }
                }
            }
            session.shutdown().await;
        }
        Ok(Err(e)) => {
            report.record("setup", false, Some(e.to_string()));
            hprintln!(
                "  {CYAN}{:<13}{RESET} {RED}✗{RESET} TSP setup failed: {e}",
                "Trust-ping"
            );
        }
        Err(_) => {
            report.record("setup", false, None);
            hprintln!(
                "  {CYAN}{:<13}{RESET} {RED}✗{RESET} TSP setup timed out",
                "Trust-ping"
            );
        }
    }
}

/// Without the `tsp` feature the probe machinery isn't compiled in; note that
/// TSP is advertised but not exercised so the operator isn't misled into
/// thinking the transport was tested.
#[cfg(not(feature = "tsp"))]
async fn tsp_probe(
    _client_did: &str,
    _private_key_multibase: &str,
    _mediator_did: &str,
    _vta_did: &str,
    _cold: bool,
    _report: &mut Report,
) {
    hprintln!("  {DIM}advertised — rebuild pnm with `--features tsp` to probe over TSP{RESET}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_files_checks_under_the_open_section() {
        let mut r = Report::default();
        r.section("vta", "VTA");
        r.record("resolution", true, Some("webvh".into()));
        r.section("mediator", "Mediator");
        r.record("trust-ping", false, None);

        let sections: Vec<_> = r.checks.iter().map(|c| c.section).collect();
        assert_eq!(sections, vec!["vta", "mediator"]);
    }

    #[test]
    fn test_report_failures_counts_only_failed_checks() {
        let mut r = Report::default();
        r.section("vta", "VTA");
        r.record("a", true, None);
        r.record("b", false, None);
        r.record("c", false, None);
        assert_eq!(r.failures(), 2);
    }

    #[test]
    fn test_report_empty_is_not_healthy() {
        // A run that probed nothing has not established health, so it
        // must not hand a pipeline a green light.
        let r = Report::default();
        assert_eq!(r.failures(), 0, "nothing ran, so nothing failed");
        assert!(!r.healthy(), "but zero checks is not a pass");
    }

    #[test]
    fn test_report_all_passing_is_healthy() {
        let mut r = Report::default();
        r.section("vta", "VTA");
        r.record("resolution", true, None);
        assert!(r.healthy());
    }

    #[test]
    fn test_check_serializes_camel_case_and_omits_absent_detail() {
        let mut r = Report::default();
        r.section("vta", "VTA");
        r.record("resolution", true, None);
        let v = serde_json::to_value(&r.checks).expect("checks should serialize");
        let first = &v[0];
        assert_eq!(first["section"], "vta");
        assert_eq!(first["ok"], true);
        assert!(
            first.get("detail").is_none(),
            "an absent detail must not appear as null: {first}"
        );
    }
}
