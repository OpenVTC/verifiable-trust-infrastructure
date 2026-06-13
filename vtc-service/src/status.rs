use crate::store::keyspaces;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;

use crate::acl::{self, VtcRole};
use crate::auth::session::{self, SessionState};
use crate::config::AppConfig;
use crate::keys::seed_store::create_secret_store;
use crate::store::Store;

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

fn section(title: &str) {
    let pad = 46usize.saturating_sub(title.len());
    eprintln!(
        "\n{DIM}──{RESET} {BOLD}{title}{RESET} {DIM}{}{RESET}",
        "─".repeat(pad)
    );
}

pub async fn run_status(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Check setup completion
    let config = match AppConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            section("VTC Status");
            eprintln!("  {CYAN}{:<13}{RESET} {RED}✗{RESET} not complete", "Setup");
            eprintln!("  {CYAN}{:<13}{RESET} {e}", "Error");
            eprintln!();
            eprintln!("Run `vtc setup` to configure this instance.");
            return Ok(());
        }
    };

    section("VTC Status");
    let name = config.vtc_name.as_deref().unwrap_or("(not set)");
    let desc = config.vtc_description.as_deref().unwrap_or("(not set)");
    eprintln!(
        "  {CYAN}{:<13}{RESET} {}",
        "Name",
        if name == "(not set)" {
            format!("{DIM}{name}{RESET}")
        } else {
            name.to_string()
        }
    );
    eprintln!(
        "  {CYAN}{:<13}{RESET} {}",
        "Description",
        if desc == "(not set)" {
            format!("{DIM}{desc}{RESET}")
        } else {
            desc.to_string()
        }
    );
    eprintln!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} complete", "Setup");
    eprintln!(
        "  {CYAN}{:<13}{RESET} {}",
        "Config",
        config.config_path.display()
    );

    // 2. DID resolver for resolution checks
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .ok();

    // 3. VTC DID + resolution check → extract mediator DID from DIDCommMessaging
    let mut discovered_mediator: Option<String> = None;
    if let Some(ref did) = config.vtc_did {
        eprintln!("  {CYAN}{:<13}{RESET} {did}", "VTC DID");
        if let Some(ref resolver) = did_resolver {
            match resolver.resolve(did).await {
                Ok(resolved) => {
                    let method = did
                        .strip_prefix("did:")
                        .and_then(|s| s.split(':').next())
                        .unwrap_or("?");
                    eprintln!("                {GREEN}✓{RESET} resolves ({method})");

                    // Look for mediator DID in DIDCommMessaging service
                    for svc in &resolved.doc.service {
                        if svc.type_.iter().any(|t| t == "DIDCommMessaging")
                            && discovered_mediator.is_none()
                        {
                            discovered_mediator = svc
                                .service_endpoint
                                .get_uris()
                                .into_iter()
                                .map(|u| u.trim_matches('"').to_string())
                                .find(|u| u.starts_with("did:"));
                        }
                    }
                }
                Err(e) => eprintln!("                {RED}✗ resolution failed: {e}{RESET}"),
            }
        }
    } else {
        eprintln!("  {CYAN}{:<13}{RESET} {DIM}(not set){RESET}", "VTC DID");
    }

    // 4. URL + Store path
    let url = config.public_url.as_deref().unwrap_or("(not set)");
    eprintln!(
        "  {CYAN}{:<13}{RESET} {}",
        "URL",
        if url == "(not set)" {
            format!("{DIM}{url}{RESET}")
        } else {
            url.to_string()
        }
    );
    eprintln!(
        "  {CYAN}{:<13}{RESET} {}",
        "Store",
        config.store.data_dir.display()
    );

    // 5. Mediator section
    section("Mediator");
    let mediator_did = discovered_mediator
        .as_deref()
        .or(config.messaging.as_ref().map(|m| m.mediator_did.as_str()));

    if let Some(ref msg) = config.messaging {
        eprintln!("  {CYAN}{:<13}{RESET} {}", "URL", msg.mediator_url);
        eprintln!(
            "  {CYAN}{:<13}{RESET} {}",
            "DID",
            mediator_did.unwrap_or("(unknown)")
        );
        if let Some(ref resolver) = did_resolver
            && let Some(did) = mediator_did
        {
            match resolver.resolve(did).await {
                Ok(_) => {
                    let method = did
                        .strip_prefix("did:")
                        .and_then(|s| s.split(':').next())
                        .unwrap_or("?");
                    eprintln!("                {GREEN}✓{RESET} resolves ({method})");
                }
                Err(e) => eprintln!("                {RED}✗ resolution failed: {e}{RESET}"),
            }
        }
    } else {
        eprintln!("  {DIM}Not configured{RESET}");
    }

    // 6. Open store (may fail if VTC is already running)
    let store = match Store::open(&config.store) {
        Ok(s) => s,
        Err(_) => {
            eprintln!();
            eprintln!(
                "  {YELLOW}Note:{RESET} Could not open the data store (is VTC already running?)."
            );
            eprintln!("        Stop the VTC service and re-run `vtc status` for full diagnostics.");
            eprintln!();
            return Ok(());
        }
    };

    // 7. Trust-ping to mediator
    if let (Some(vtc_did), Some(mediator)) = (&config.vtc_did, mediator_did) {
        match tokio::time::timeout(
            Duration::from_secs(10),
            send_trust_ping(&config, vtc_did, mediator),
        )
        .await
        {
            Ok(Ok(latency)) => {
                eprintln!("                {GREEN}✓{RESET} pong ({latency}ms)");
            }
            Ok(Err(e)) => {
                eprintln!("                {RED}✗{RESET} trust-ping failed: {e}");
            }
            Err(_) => {
                eprintln!("                {RED}✗{RESET} trust-ping timed out");
            }
        }
    }

    // 8. Gather stats from store
    let acl_ks = store.keyspace(keyspaces::ACL)?;
    let sessions_ks = store.keyspace(keyspaces::SESSIONS)?;

    // --- ACL ---
    let acl_entries = acl::list_acl_entries(&acl_ks).await?;
    let admin_count = acl_entries
        .iter()
        .filter(|e| e.role == VtcRole::Admin)
        .count();
    let moderator_count = acl_entries
        .iter()
        .filter(|e| e.role == VtcRole::Moderator)
        .count();
    let issuer_count = acl_entries
        .iter()
        .filter(|e| e.role == VtcRole::Issuer)
        .count();
    let member_count = acl_entries
        .iter()
        .filter(|e| e.role == VtcRole::Member)
        .count();
    let custom_count = acl_entries
        .iter()
        .filter(|e| matches!(e.role, VtcRole::Custom(_)))
        .count();

    section(&format!("ACL ({})", acl_entries.len()));
    eprintln!("  {CYAN}{:<13}{RESET} {admin_count}", "Admin");
    eprintln!("  {CYAN}{:<13}{RESET} {moderator_count}", "Moderator");
    eprintln!("  {CYAN}{:<13}{RESET} {issuer_count}", "Issuer");
    eprintln!("  {CYAN}{:<13}{RESET} {member_count}", "Member");
    if custom_count > 0 {
        eprintln!("  {CYAN}{:<13}{RESET} {custom_count}", "Custom");
    }

    // --- Sessions ---
    let sessions = session::list_sessions(&sessions_ks).await?;
    let authenticated = sessions
        .iter()
        .filter(|s| s.state == SessionState::Authenticated)
        .count();
    let challenge_sent = sessions
        .iter()
        .filter(|s| s.state == SessionState::ChallengeSent)
        .count();

    section(&format!("Sessions ({})", sessions.len()));
    eprintln!("  {CYAN}{:<13}{RESET} {authenticated}", "Authenticated");
    eprintln!("  {CYAN}{:<13}{RESET} {challenge_sent}", "ChallengeSent");
    eprintln!();

    Ok(())
}

/// Send a DIDComm trust-ping to the mediator and return latency in milliseconds.
///
/// Loads key material from the secret store directly (no BIP-32 derivation).
async fn send_trust_ping(
    config: &AppConfig,
    vtc_did: &str,
    mediator_did: &str,
) -> Result<u128, Box<dyn std::error::Error>> {
    let secret_store = create_secret_store(config)?;
    let key_material = secret_store
        .get()
        .await?
        .ok_or("no key material available")?;

    // Accept both on-disk shapes: the JSON `VtcKeyBundle` every real
    // deployment writes since the VTA-driven-keys rework, and the legacy
    // 64-raw-byte fixture shape. The old `len() == 64` guard here rejected
    // the bundle shape, so the trust-ping failed on every production VTC
    // with a baffling byte-count error (P0.19).
    let (ed25519_bytes, x25519_bytes) =
        crate::setup::bundle::decode_secret_store_value(vtc_did, &key_material)?;

    let tdk = TDKSharedState::new(TDKConfig::builder().build()?).await?;

    let mut signing_secret = Secret::generate_ed25519(None, Some(&ed25519_bytes));
    signing_secret.id = format!("{vtc_did}#key-0");
    tdk.secrets_resolver().insert(signing_secret).await;

    let mut ka_secret = Secret::generate_x25519(None, Some(&x25519_bytes))?;
    ka_secret.id = format!("{vtc_did}#key-1");
    tdk.secrets_resolver().insert(ka_secret).await;

    let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;

    let profile = ATMProfile::new(
        &atm,
        None,
        vtc_did.to_string(),
        Some(mediator_did.to_string()),
    )
    .await?;
    let profile = Arc::new(profile);

    // The mediator may only expose a wss:// endpoint (no REST/https).
    atm.profile_enable_websocket(&profile).await?;

    let start = Instant::now();
    TrustPing::default()
        .send_ping(&atm, &profile, mediator_did, true, true, true)
        .await?;
    let elapsed = start.elapsed().as_millis();

    atm.graceful_shutdown().await;
    Ok(elapsed)
}
