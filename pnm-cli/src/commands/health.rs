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

    // What the VTA's DID document actually advertises. Source of truth
    // for the "Mode" label below — and for whether to show URL / probe
    // Service / attempt REST authentication. An explicit `--url`
    // override (or `[vta] url = "..."` in pnm config) is the only thing
    // that can light those up when the DID document doesn't advertise
    // REST itself; falling back to a URL synthesized from the DID
    // string would point at a non-existent endpoint for DIDComm-only
    // VTAs.
    let advertised = match session.as_ref().and_then(|s| s.vta_did.as_deref()) {
        Some(vta_did) => vta_sdk::session::resolve_vta_endpoint(vta_did).await.ok(),
        None => None,
    };

    let (mode_label, advertised_rest_url, advertises_didcomm) = match &advertised {
        Some(vta_sdk::session::VtaEndpoint::DIDComm {
            rest_url: Some(u), ..
        }) => ("DIDComm + REST", Some(u.clone()), true),
        Some(vta_sdk::session::VtaEndpoint::DIDComm { rest_url: None, .. }) => {
            ("DIDComm-only", None, true)
        }
        Some(vta_sdk::session::VtaEndpoint::Rest { url }) => {
            ("REST-only", Some(url.clone()), false)
        }
        None if session
            .as_ref()
            .and_then(|s| s.vta_did.as_deref())
            .is_some() =>
        {
            ("unknown (could not enumerate services)", None, false)
        }
        None => ("(pending DID setup)", None, false),
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
    } else if advertises_didcomm {
        println!("  {DIM}DIDComm-only VTA — no REST auth{RESET}");
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

        match mediator_result {
            Ok(Some(mediator_did)) => {
                println!("  {CYAN}{:<13}{RESET} {mediator_did}", "DID");

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
                        // Ping mediator
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            session.ping(None),
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

                        // Ping VTA through the same session
                        print_section("VTA DIDComm");

                        match tokio::time::timeout(
                            std::time::Duration::from_secs(15),
                            session.ping(Some(vta_did)),
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

    Ok(())
}
