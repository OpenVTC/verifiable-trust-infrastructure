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

pub(crate) async fn run(
    url_override: Option<&str>,
    keyring_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_did_resolver_cache_sdk::DIDCacheClient;

    let session = auth::loaded_session(keyring_key);

    // Single shared DID resolver — cached across all resolutions.
    // Honours PNM_RESOLVER_URL (set from `~/.config/pnm/config.toml`'s
    // `resolver_url` at startup) for shared-cache deployments.
    let did_resolver = DIDCacheClient::new(vta_sdk::resolver::build_did_cache_config_from_env())
        .await
        .ok();

    // ── VTA ────────────────────────────────────────────────────────
    print_section("VTA");

    if let Some(ref info) = session {
        match info.vta_did.as_deref() {
            Some(vta_did) => {
                println!("  {CYAN}{:<13}{RESET} {vta_did}", "DID");
                if let Some(ref resolver) = did_resolver {
                    match resolver.resolve(vta_did).await {
                        Ok(_) => {
                            let method = vta_did
                                .strip_prefix("did:")
                                .and_then(|s| s.split(':').next())
                                .unwrap_or("?");
                            println!("                {GREEN}✓{RESET} resolves ({method})");
                        }
                        Err(e) => {
                            println!("                {RED}✗{RESET} resolution failed: {e}")
                        }
                    }
                }
            }
            None => {
                println!(
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
    println!("  {CYAN}{:<13}{RESET} {mode_label}", "Mode");

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
        println!("  {CYAN}{:<13}{RESET} {url}{suffix}", "URL");

        let probe_client = VtaClient::new(url);
        match probe_client.health().await {
            Ok(resp) => {
                let ver = resp
                    .version
                    .as_deref()
                    .map(|v| format!(" (v{v})"))
                    .unwrap_or_default();
                println!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} ok{ver}", "Service");
            }
            Err(e) => {
                println!(
                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} unreachable ({e})",
                    "Service"
                );
            }
        }
    }

    // ── Authentication ─────────────────────────────────────────────
    print_section("Authentication");

    if let Some(ref url) = effective_rest_url {
        if let Some(ref info) = session {
            println!("  {CYAN}{:<13}{RESET} {}", "Client DID", info.client_did);
            match auth::ensure_authenticated(url, keyring_key).await {
                Ok(_token) => {
                    if let Some(status) = auth::session_status(keyring_key) {
                        match status.token_status {
                            vta_sdk::session::TokenStatus::Valid { expires_in_secs } => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} valid (expires in {expires_in_secs}s)",
                                    "Token"
                                );
                            }
                            _ => {
                                println!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} valid", "Token");
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("  {CYAN}{:<13}{RESET} {RED}✗{RESET} {e}", "Token");
                }
            }
        } else {
            println!("  {DIM}Not authenticated{RESET}");
        }
    } else if advertises_messaging {
        println!("  {DIM}Messaging-only VTA (TSP/DIDComm) — no REST auth{RESET}");
    } else {
        println!("  {DIM}No transport advertised{RESET}");
    }

    // ── Mediator + DIDComm pings ──────────────────────────────────
    print_section("Mediator");

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
                        Ok(token) => {
                            let client = VtaClient::new(url);
                            client.set_token_async(token).await;
                            match client.didcomm_status().await {
                                Ok(status) if status.enabled => {
                                    Ok(status.mediator_did.map(|did| (did, true)))
                                }
                                Ok(_) => Ok(None),
                                Err(e) => {
                                    println!("  {DIM}(status check failed: {e}){RESET}");
                                    Ok(None)
                                }
                            }
                        }
                        Err(e) => {
                            println!("  {DIM}(auth for status check failed: {e}){RESET}");
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
                println!("  {CYAN}{:<13}{RESET} {mediator_did}", "DID");
                if via_status_endpoint {
                    println!("                {DIM}discovered via /services/didcomm{RESET}");
                }

                // Resolve mediator DID document (uses cached resolver)
                if let Some(ref resolver) = did_resolver {
                    match resolver.resolve(&mediator_did).await {
                        Ok(_) => {
                            let method = mediator_did
                                .strip_prefix("did:")
                                .and_then(|s| s.split(':').next())
                                .unwrap_or("?");
                            println!("                {GREEN}✓{RESET} resolves ({method})");
                        }
                        Err(e) => {
                            println!("                {RED}✗{RESET} resolution failed: {e}");
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
                        // Ping mediator (steady-state: warm-up + measured)
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(20),
                            steady_ping(&session, None),
                        )
                        .await
                        {
                            Ok(Ok(latency)) => {
                                println!("                {GREEN}✓{RESET} pong ({latency}ms)");
                            }
                            Ok(Err(e)) => {
                                println!("                {RED}✗{RESET} trust-ping failed: {e}");
                            }
                            Err(_) => {
                                println!("                {RED}✗{RESET} trust-ping timed out");
                            }
                        }

                        // Ping VTA through the same session (steady-state)
                        print_section("VTA DIDComm");

                        match tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            steady_ping(&session, Some(vta_did)),
                        )
                        .await
                        {
                            Ok(Ok(latency)) => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                                    "Trust-ping"
                                );
                            }
                            Ok(Err(e)) => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping failed: {e}",
                                    "Trust-ping"
                                );
                            }
                            Err(_) => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping timed out",
                                    "Trust-ping"
                                );
                            }
                        }

                        session.shutdown().await;
                    }
                    Ok(Err(e)) => {
                        println!("                {RED}✗{RESET} DIDComm setup failed: {e}");
                    }
                    Err(_) => {
                        println!("                {RED}✗{RESET} DIDComm setup timed out");
                    }
                }
            }
            Ok(None) => {
                println!("  {DIM}(not configured){RESET}");
            }
            Err(e) => {
                println!(
                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} could not resolve VTA DID: {e}",
                    "DID"
                );
            }
        }
    } else {
        println!("  {DIM}(no session){RESET}");
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
        print_section("VTA TSP");
        tsp_probe(
            &info.client_did,
            &info.private_key_multibase,
            tsp_mediator,
            vta_did,
        )
        .await;
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
/// mediator, send a Trust Task to the VTA over TSP, and await the response —
/// proving the full TSP round-trip. Compiled only with the `tsp` feature.
#[cfg(feature = "tsp")]
async fn tsp_probe(
    client_did: &str,
    private_key_multibase: &str,
    mediator_did: &str,
    vta_did: &str,
) {
    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        vta_sdk::session::TspPingSession::new(client_did, private_key_multibase, mediator_did),
    )
    .await
    {
        Ok(Ok(mut session)) => {
            // Warm-up ping (pays the first-send VID/route resolution), then a
            // measured one — a steady-state latency comparable to the DIDComm
            // probe. A warm-up failure is reported straight away.
            let ping_timeout = std::time::Duration::from_secs(10);
            let measured = match session.ping(vta_did, ping_timeout).await {
                Ok(_) => session.ping(vta_did, ping_timeout).await,
                Err(e) => Err(e),
            };
            match measured {
                Ok(latency) => {
                    println!(
                        "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                        "Trust-ping"
                    );
                }
                Err(e) => {
                    println!(
                        "  {CYAN}{:<13}{RESET} {RED}✗{RESET} TSP ping failed: {e}",
                        "Trust-ping"
                    );
                }
            }
            session.shutdown().await;
        }
        Ok(Err(e)) => {
            println!(
                "  {CYAN}{:<13}{RESET} {RED}✗{RESET} TSP setup failed: {e}",
                "Trust-ping"
            );
        }
        Err(_) => {
            println!(
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
) {
    println!("  {DIM}advertised — rebuild pnm with `--features tsp` to probe over TSP{RESET}");
}
