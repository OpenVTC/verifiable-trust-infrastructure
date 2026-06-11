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
use ed25519_dalek_bip32::ExtendedSigningKey;

use crate::acl::{self, Role};
use crate::auth::session::{self, SessionState};
use crate::config::AppConfig;
use crate::contexts;
use crate::keys::derivation::Bip32Extension;
use crate::keys::seed_store::create_seed_store;
use crate::keys::{KeyRecord, KeyStatus, KeyType};
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
            section("VTA Status");
            eprintln!("  {CYAN}{:<13}{RESET} {RED}✗{RESET} not complete", "Setup");
            eprintln!("  {CYAN}{:<13}{RESET} {e}", "Error");
            eprintln!();
            eprintln!("Run `vta setup` to configure this instance.");
            return Ok(());
        }
    };

    section("VTA Status");
    let name = config.vta_name.as_deref().unwrap_or("(not set)");
    eprintln!(
        "  {CYAN}{:<13}{RESET} {}",
        "Name",
        if name == "(not set)" {
            format!("{DIM}{name}{RESET}")
        } else {
            name.to_string()
        }
    );
    eprintln!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} complete", "Setup");
    let mut svc_list = Vec::new();
    if config.services.rest {
        svc_list.push("REST");
    }
    if config.services.didcomm {
        svc_list.push("DIDComm");
    }
    let svc_display = if svc_list.is_empty() {
        format!("{DIM}(none){RESET}")
    } else {
        svc_list.join(", ")
    };
    eprintln!("  {CYAN}{:<13}{RESET} {svc_display}", "Services");
    eprintln!(
        "  {CYAN}{:<13}{RESET} {}",
        "Config",
        config.config_path.display()
    );

    // 2. DID resolver for resolution checks (created early, reused for contexts)
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .ok();

    // 3. VTA DID + resolution check → extract mediator DID from DIDCommMessaging
    let mut discovered_mediator: Option<String> = None;
    if let Some(ref did) = config.vta_did {
        eprintln!("  {CYAN}{:<13}{RESET} {did}", "VTA DID");
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
                            // get_uris() wraps Map-sourced values in JSON quotes
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
        eprintln!("  {CYAN}{:<13}{RESET} {DIM}(not set){RESET}", "VTA DID");
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

    // 5. Mediator section (grouped: display + resolution + trust-ping)
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

    // 6. Open store (may fail if VTA is already running)
    let store = match Store::open(&config.store) {
        Ok(s) => s,
        Err(_) => {
            eprintln!();
            eprintln!(
                "  {YELLOW}Note:{RESET} Could not open the data store (is VTA already running?)."
            );
            eprintln!("        Stop the VTA service and re-run `vta status` for full diagnostics.");
            eprintln!();
            return Ok(());
        }
    };

    // 7. Trust-ping to mediator (needs key records from store)
    if let (Some(vta_did), Some(mediator)) = (&config.vta_did, mediator_did) {
        match tokio::time::timeout(
            Duration::from_secs(10),
            send_trust_ping(&config, &store, vta_did, mediator),
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
    let contexts_ks = store.keyspace("contexts")?;
    let keys_ks = store.keyspace("keys")?;
    let acl_ks = store.keyspace("acl")?;
    let sessions_ks = store.keyspace("sessions")?;

    // --- Contexts ---
    let ctx_records = contexts::list_contexts(&contexts_ks).await?;
    section(&format!("Contexts ({})", ctx_records.len()));

    for ctx in &ctx_records {
        let did_display = ctx.did.as_deref().unwrap_or("(no DID)");
        let resolution = if let Some(ref did) = ctx.did {
            if let Some(ref resolver) = did_resolver {
                match resolver.resolve(did).await {
                    Ok(_) => {
                        let method = did
                            .strip_prefix("did:")
                            .and_then(|s| s.split(':').next())
                            .unwrap_or("unknown");
                        format!("{GREEN}✓{RESET} {method}")
                    }
                    Err(e) => format!("{RED}✗{RESET} {e}"),
                }
            } else {
                format!("{DIM}skipped{RESET}")
            }
        } else {
            String::new()
        };

        if resolution.is_empty() {
            eprintln!("  {CYAN}{:<16}{RESET} {DIM}{did_display}{RESET}", ctx.id);
        } else {
            eprintln!("  {CYAN}{:<16}{RESET} {did_display}   {resolution}", ctx.id);
        }
    }

    // --- Keys ---
    let raw_keys = keys_ks.prefix_iter_raw("key:").await?;
    let mut total_keys = 0usize;
    let mut active = 0usize;
    let mut revoked = 0usize;
    let mut ed25519_count = 0usize;
    let mut x25519_count = 0usize;
    let mut p256_count = 0usize;

    for (_key, value) in &raw_keys {
        if let Ok(record) = serde_json::from_slice::<KeyRecord>(value) {
            total_keys += 1;
            match record.status {
                KeyStatus::Active => active += 1,
                KeyStatus::Revoked => revoked += 1,
            }
            match record.key_type {
                KeyType::Ed25519 => ed25519_count += 1,
                KeyType::X25519 => x25519_count += 1,
                KeyType::P256 => p256_count += 1,
            }
        }
    }

    section(&format!("Keys ({total_keys})"));
    eprintln!(
        "  {CYAN}{:<13}{RESET} {active}  Ed25519: {ed25519_count}, X25519: {x25519_count}, P-256: {p256_count}",
        "Active"
    );
    eprintln!("  {CYAN}{:<13}{RESET} {revoked}", "Revoked");

    // --- ACL ---
    let acl_entries = acl::list_acl_entries(&acl_ks).await?;
    let admin_count = acl_entries.iter().filter(|e| e.role == Role::Admin).count();
    let initiator_count = acl_entries
        .iter()
        .filter(|e| e.role == Role::Initiator)
        .count();
    let application_count = acl_entries
        .iter()
        .filter(|e| e.role == Role::Application)
        .count();

    section(&format!("ACL ({})", acl_entries.len()));
    eprintln!("  {CYAN}{:<13}{RESET} {admin_count}", "Admin");
    eprintln!("  {CYAN}{:<13}{RESET} {initiator_count}", "Initiator");
    eprintln!("  {CYAN}{:<13}{RESET} {application_count}", "Application");

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
async fn send_trust_ping(
    config: &AppConfig,
    store: &Store,
    vta_did: &str,
    mediator_did: &str,
) -> Result<u128, Box<dyn std::error::Error>> {
    let seed_store = create_seed_store(config)?;
    // Master seed in plaintext — wipe on drop (P0.7).
    let seed = zeroize::Zeroizing::new(seed_store.get().await?.ok_or("no master seed available")?);

    let root = ExtendedSigningKey::from_seed(&seed)?;

    let keys_ks = store.keyspace("keys")?;

    // Internal storage always uses #key-0 for the signing record, regardless
    // of DID method. The X25519 record at #key-1 only exists for did:webvh
    // (did:key curve-converts the X25519 key from Ed25519 at runtime).
    let signing_key_id = format!("{vta_did}#key-0");

    let signing: KeyRecord = keys_ks
        .get(crate::keys::store_key(&signing_key_id))
        .await?
        .ok_or("VTA signing key record not found")?;

    let tdk = TDKSharedState::new(TDKConfig::builder().build()?).await?;

    if vta_did.starts_with("did:key:") {
        // did:key: X25519 is curve-converted from Ed25519, and verification method
        // IDs use multibase-encoded public key fragments, not #key-0/#key-1.
        let dp: ed25519_dalek_bip32::DerivationPath = signing.derivation_path.parse()?;
        let derived = root.derive(&dp)?;
        let seed_bytes: &[u8; 32] = derived.signing_key.as_bytes();
        let secrets = vta_sdk::did_key::secrets_from_did_key(vta_did, seed_bytes)?;
        tdk.secrets_resolver().insert(secrets.signing).await;
        tdk.secrets_resolver().insert(secrets.key_agreement).await;
    } else {
        // did:webvh / other methods: independently derived keys, #key-0/#key-1 IDs.
        let ka_key_id = format!("{vta_did}#key-1");
        let ka: KeyRecord = keys_ks
            .get(crate::keys::store_key(&ka_key_id))
            .await?
            .ok_or("VTA key-agreement key record not found")?;

        let mut signing_secret = root.derive_ed25519(&signing.derivation_path)?;
        signing_secret.id = signing_key_id;
        tdk.secrets_resolver().insert(signing_secret).await;

        let mut ka_secret = root.derive_x25519(&ka.derivation_path)?;
        ka_secret.id = ka_key_id;
        tdk.secrets_resolver().insert(ka_secret).await;
    }

    let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;

    let profile = ATMProfile::new(
        &atm,
        None,
        vta_did.to_string(),
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
