use std::io::{self, BufRead, Write};

use dialoguer::{Input, Select};
use ed25519_dalek::SigningKey;
use rand::Rng;
use serde::Serialize;
use vta_sdk::prelude::*;

use crate::auth;
use crate::config::{PnmConfig, VtaConfig, save_config, slugify, vta_keyring_key};

/// Options for interactive setup from the CLI.
///
/// Kept as a struct for forward-compatibility — today there are no setup
/// flags (the wizard is fully interactive). `pnm setup` never ingests a
/// credential file: PNM always self-mints, then coordinates an ACL grant
/// + key rotation via the admin.
pub struct SetupOptions {}

// ── JSON stdout contract (non-interactive paths) ────────────────────

#[derive(Serialize)]
struct SetupOutput<'a> {
    slug: &'a str,
    admin_did: &'a str,
    state: &'static str,
}

fn emit_json(slug: &str, admin_did: &str, state: &'static str) -> io::Result<()> {
    let line = serde_json::to_string(&SetupOutput {
        slug,
        admin_did,
        state,
    })
    .expect("SetupOutput serializes");
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{line}")?;
    stdout.flush()
}

// ── Interactive entry point ─────────────────────────────────────────

/// Interactive setup for PNM.
///
/// Two paths:
/// - **Connect to an existing non-TEE VTA** — phase-1 interactive. PNM
///   mints the ephemeral `did:key` first and shows it, then asks for a
///   name and (optionally) the VTA DID. If the operator leaves the VTA
///   DID blank, setup finishes in `PendingVtaBinding` state and they
///   come back later with `pnm setup continue <slug>`.
/// - **Set up a new VTA in a TEE** — operator is bootstrapping a brand
///   new enclave; generates an admin did:key to embed in the TEE config.
pub async fn run_setup(
    _opts: SetupOptions,
    config: &mut PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let choices = &[
        "Connect to an existing non-TEE VTA",
        "Set up a new VTA in a TEE  — generate admin identity for enclave deployment",
    ];

    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(choices)
        .default(0)
        .interact()?;

    match selection {
        0 => start_non_tee_setup_interactive(config).await,
        1 => setup_tee(config).await,
        _ => unreachable!(),
    }
}

// ── Non-TEE phase 1: interactive ───────────────────────────────────

async fn start_non_tee_setup_interactive(
    config: &mut PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("Generating ephemeral admin identity...");
    let (did, private_key_multibase) = mint_ephemeral_identity();

    eprintln!();
    eprintln!("  \x1b[1mAdmin DID:\x1b[0m {did}");
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Use this DID when setting up the VTA. Either:");
    eprintln!("         a. Run on the VTA host:");
    eprintln!("              \x1b[1mvta setup --from setup.toml\x1b[0m");
    eprintln!("            with: admin_did = \"{did}\"");
    eprintln!("         b. Or, on an already-running VTA:");
    eprintln!("              \x1b[1mvta import-did --did {did} --role admin\x1b[0m");
    eprintln!("    2. Once the VTA is running, finish here with:");
    eprintln!("         \x1b[1mpnm setup continue <name-you-pick>\x1b[0m");
    eprintln!();

    let name: String = Input::new()
        .with_prompt("Name for this VTA")
        .interact_text()?;
    let slug = slugify(&name);
    let keyring_key = vta_keyring_key(&slug);

    // Collision check BEFORE we write anything.
    match detect_existing_state(config, &slug, &keyring_key) {
        ExistingState::None => {}
        ExistingState::Complete { vta_did } => {
            return Err(format!(
                "'{slug}' is already set up (VTA DID: {vta_did}).\n\n\
                 To replace it, first run: \x1b[1mpnm vta remove {slug}\x1b[0m"
            )
            .into());
        }
        ExistingState::Pending { existing_did } => {
            let prompt_choices = &[
                "Show the existing DID and keep pending setup",
                "Override — mint a fresh DID, discard the old keypair",
                "Cancel",
            ];
            let choice = Select::new()
                .with_prompt(format!(
                    "A pending setup already exists for '{slug}':\n  Admin DID: {existing_did}\n\
                     Choose"
                ))
                .items(prompt_choices)
                .default(0)
                .interact()?;
            match choice {
                0 => {
                    eprintln!();
                    eprintln!("Keeping existing pending setup. Admin DID: {existing_did}");
                    eprintln!("Run `pnm setup continue {slug}` once the VTA is running.");
                    return Ok(());
                }
                1 => { /* fall through and overwrite below */ }
                _ => {
                    eprintln!("Cancelled.");
                    return Ok(());
                }
            }
        }
    }

    let vta_did_input: String = Input::new()
        .with_prompt("VTA DID (leave blank to finish setup later)")
        .allow_empty(true)
        .interact_text()?;
    let vta_did_input = vta_did_input.trim();

    if vta_did_input.is_empty() {
        persist_pending(
            config,
            &slug,
            &name,
            &keyring_key,
            &did,
            &private_key_multibase,
        )?;
        eprintln!();
        eprintln!("Saved pending VTA '{slug}'.");
        eprintln!(
            "Run \x1b[1mpnm setup continue {slug}\x1b[0m once the VTA is running and you \
             know its DID."
        );
        return Ok(());
    }

    if !vta_did_input.starts_with("did:") {
        return Err("VTA DID must start with `did:` (e.g. did:webvh:... or did:key:...)".into());
    }

    // Operator supplied the VTA DID up front → phase 1 + phase 2 in one
    // shot. Park in pending, then bind immediately.
    // did:key has no service endpoints — prompt for URL so PNM can reach the VTA.
    let vta_url = if vta_did_input.starts_with("did:key:") {
        let url: String = Input::new()
            .with_prompt("VTA URL (required for did:key — e.g. http://localhost:7001)")
            .interact_text()?;
        let url = url.trim().to_string();
        if url.is_empty() {
            return Err(
                "did:key VTAs require an explicit URL (the DID has no service endpoint)".into(),
            );
        }
        Some(url)
    } else {
        None
    };

    persist_pending(
        config,
        &slug,
        &name,
        &keyring_key,
        &did,
        &private_key_multibase,
    )?;
    finalize_session(
        config,
        &slug,
        &name,
        vta_did_input,
        &did,
        vta_url.as_deref(),
        false,
    )?;

    Ok(())
}

// ── Non-TEE phase 1: non-interactive ───────────────────────────────

pub async fn start_non_tee_setup_non_interactive(
    config: &mut PnmConfig,
    name: &str,
    overwrite: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let slug = slugify(name);
    if slug.is_empty() {
        return Err("--name must produce a non-empty slug after normalization".into());
    }
    let keyring_key = vta_keyring_key(&slug);

    match detect_existing_state(config, &slug, &keyring_key) {
        ExistingState::None => {}
        ExistingState::Complete { vta_did } => {
            return Err(format!(
                "'{slug}' is already set up (VTA DID: {vta_did}).\n\n\
                 To replace it, first run: pnm vta remove {slug}"
            )
            .into());
        }
        ExistingState::Pending { existing_did } => {
            if !overwrite {
                return Err(format!(
                    "pending setup already exists for slug '{slug}' (Admin DID: {existing_did}).\n\n\
                     Pass --overwrite to replace, or run `pnm setup continue {slug}` to finish it."
                )
                .into());
            }
        }
    }

    let (did, private_key_multibase) = mint_ephemeral_identity();
    persist_pending(
        config,
        &slug,
        name,
        &keyring_key,
        &did,
        &private_key_multibase,
    )?;

    eprintln!("Pending VTA '{slug}' created.");
    eprintln!("  Admin DID: {did}");
    eprintln!();
    eprintln!("Next: set `admin_did = \"{did}\"` in the VTA setup.toml, boot the VTA,");
    eprintln!("      then run: pnm setup continue {slug} --vta-did <did:...>");

    emit_json(&slug, &did, "pending")?;
    Ok(())
}

// ── Non-TEE phase 2: interactive ───────────────────────────────────

pub async fn continue_non_tee_setup_interactive(
    config: &mut PnmConfig,
    slug: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let keyring_key = vta_keyring_key(slug);
    let (name, existing_did) = require_pending(config, slug, &keyring_key)?;

    eprintln!();
    eprintln!("Continuing setup for '{slug}'.");
    eprintln!();
    eprintln!("  \x1b[1mAdmin DID:\x1b[0m {existing_did}   (unchanged from phase 1)");
    eprintln!();

    let vta_did: String = Input::new().with_prompt("VTA DID").interact_text()?;
    let vta_did = vta_did.trim();
    if !vta_did.starts_with("did:") {
        return Err("VTA DID must start with `did:` (e.g. did:webvh:... or did:key:...)".into());
    }

    // did:key has no service endpoints — prompt for URL so PNM can reach the VTA.
    let vta_url = if vta_did.starts_with("did:key:") {
        let url: String = Input::new()
            .with_prompt("VTA URL (required for did:key — e.g. http://localhost:7001)")
            .interact_text()?;
        let url = url.trim().to_string();
        if url.is_empty() {
            return Err(
                "did:key VTAs require an explicit URL (the DID has no service endpoint)".into(),
            );
        }
        Some(url)
    } else {
        None
    };

    finalize_session(
        config,
        slug,
        &name,
        vta_did,
        &existing_did,
        vta_url.as_deref(),
        false,
    )?;
    Ok(())
}

// ── Non-TEE phase 2: non-interactive ───────────────────────────────

pub async fn continue_non_tee_setup_non_interactive(
    config: &mut PnmConfig,
    slug: &str,
    vta_did: &str,
    vta_url: Option<&str>,
    mediator_did: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let keyring_key = vta_keyring_key(slug);
    let (name, existing_did) = require_pending(config, slug, &keyring_key)?;

    let vta_did = vta_did.trim();
    if !vta_did.starts_with("did:") {
        return Err("VTA DID must start with `did:` (e.g. did:webvh:... or did:key:...)".into());
    }

    // did:key has no service endpoints — require --vta-url.
    let vta_url = if vta_did.starts_with("did:key:") {
        match vta_url {
            Some(u) => Some(u),
            None => {
                return Err(
                    "did:key VTAs require --vta-url (the DID has no service endpoint)".into(),
                );
            }
        }
    } else {
        vta_url
    };

    finalize_session(config, slug, &name, vta_did, &existing_did, vta_url, true)?;

    // Persist mediator_did if provided
    if let Some(med_did) = mediator_did {
        if let Some(vta_cfg) = config.vtas.get_mut(slug) {
            vta_cfg.mediator_did = Some(med_did.to_string());
        }
        save_config(config)?;
    }

    Ok(())
}

// ── Shared helpers ─────────────────────────────────────────────────

fn mint_ephemeral_identity() -> (String, String) {
    vta_cli_common::local_keygen::generate_unbound_admin_did_key()
}

fn persist_pending(
    config: &mut PnmConfig,
    slug: &str,
    name: &str,
    keyring_key: &str,
    did: &str,
    private_key_multibase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    auth::store_pending_vta_binding(keyring_key, did, private_key_multibase)?;

    config.vtas.insert(
        slug.to_string(),
        VtaConfig {
            name: name.to_string(),
            vta_did: None,
            url: None,
            mediator_did: None,
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.to_string());
    }
    save_config(config)?;
    Ok(())
}

fn finalize_session(
    config: &mut PnmConfig,
    slug: &str,
    name: &str,
    vta_did: &str,
    did: &str,
    vta_url: Option<&str>,
    non_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let keyring_key = vta_keyring_key(slug);
    auth::bind_vta_did(&keyring_key, vta_did)?;

    config.vtas.insert(
        slug.to_string(),
        VtaConfig {
            name: name.to_string(),
            vta_did: Some(vta_did.to_string()),
            url: vta_url.map(|u| u.trim_end_matches('/').to_string()),
            mediator_did: None,
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.to_string());
    }
    save_config(config)?;

    if non_interactive {
        eprintln!("Bound VTA DID for '{slug}': {vta_did}");
        eprintln!("Ask the VTA admin to grant admin access:");
        eprintln!("  vta import-did --did {did} --role admin");
        emit_json(slug, did, "complete")?;
    } else {
        eprintln!();
        eprintln!("\x1b[1;32mSession stored for '{slug}'.\x1b[0m");
        eprintln!();
        eprintln!("  VTA slug: {slug}");
        eprintln!("  VTA DID:  {vta_did}");
        eprintln!("  Temp DID: {did}");
        eprintln!();
        eprintln!("Ask your VTA admin to grant this identity admin access:");
        eprintln!();
        eprintln!("  \x1b[1mvta import-did --did {did} --role admin\x1b[0m");
        eprintln!();
        eprintln!("Once the grant is in place, run any PNM command (e.g. `pnm health`). PNM will");
        eprintln!("rotate to a fresh long-lived did:key on first connect and drop the temp");
        eprintln!("from the ACL.");
        eprintln!();
    }

    Ok(())
}

enum ExistingState {
    None,
    Pending { existing_did: String },
    Complete { vta_did: String },
}

fn detect_existing_state(config: &PnmConfig, slug: &str, keyring_key: &str) -> ExistingState {
    let Some(vta) = config.vtas.get(slug) else {
        return ExistingState::None;
    };
    if let Some(ref vta_did) = vta.vta_did {
        return ExistingState::Complete {
            vta_did: vta_did.clone(),
        };
    }
    // vta_did is None → pending, *if* the keyring agrees. If the
    // keyring has no pending entry, the config is orphaned — treat as
    // None so the caller re-mints cleanly.
    match vta_sdk::session::SessionStore::new(
        "pnm-cli",
        crate::config::config_dir().expect("config dir"),
    )
    .loaded_session(keyring_key)
    {
        Some(info) if info.vta_did.is_none() => ExistingState::Pending {
            existing_did: info.client_did,
        },
        _ => ExistingState::None,
    }
}

fn require_pending(
    config: &PnmConfig,
    slug: &str,
    keyring_key: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let Some(vta) = config.vtas.get(slug) else {
        return Err(format!(
            "no pending VTA named '{slug}'.\n\n\
             Run `pnm vta list` to see configured VTAs."
        )
        .into());
    };
    if vta.vta_did.is_some() {
        return Err(format!(
            "'{slug}' is already set up.\n\n\
             Use `pnm vta show {slug}` to inspect, or `pnm vta remove {slug}` to start over."
        )
        .into());
    }
    let store = vta_sdk::session::SessionStore::new(
        "pnm-cli",
        crate::config::config_dir().expect("config dir"),
    );
    let info = store.loaded_session(keyring_key).ok_or_else(|| {
        format!(
            "'{slug}' is in pending state in config but the keyring entry is missing.\n\n\
             This usually means the keyring was cleared. Run `pnm setup --name \"{}\" --overwrite` \
             to mint a fresh ephemeral identity.",
            vta.name
        )
    })?;
    if info.vta_did.is_some() {
        return Err(format!(
            "'{slug}' keyring entry already has a VTA DID bound — config and keyring are \
             out of sync. Run `pnm vta remove {slug}` and start over."
        )
        .into());
    }
    Ok((vta.name.clone(), info.client_did))
}

/// Set up a new VTA for TEE deployment.
///
/// Single interactive session:
/// 1. Generate admin did:key (in memory)
/// 2. Print DID for config.toml
/// 3. Wait for operator to deploy + boot VTA
/// 4. Prompt for VTA DID
/// 5. Store credential in keyring, save config
///
/// The TEE admin identity is NOT rotated — it's the bootstrap key baked
/// into the TEE's config. Rotating it would break enclave boot.
async fn setup_tee(config: &mut PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("This will create an admin identity for a VTA running in a");
    eprintln!("Trusted Execution Environment. The private key stays on this");
    eprintln!("machine and never touches the TEE or the parent instance.");
    eprintln!();

    // 1. Prompt for name
    let name: String = Input::new()
        .with_prompt("Name for this VTA")
        .default("my-tee-vta".to_string())
        .interact_text()?;
    let slug = slugify(&name);

    // 2. Generate random Ed25519 keypair (in memory only)
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let multibase_pubkey = ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, seed);

    // 3. Print DID for config.toml
    eprintln!();
    eprintln!("Admin identity generated.");
    eprintln!();
    eprintln!("Add this to your VTA's deploy/nitro/config.toml under [tee.kms]:");
    eprintln!();
    println!("  admin_did = \"{did}\"");
    eprintln!();
    eprintln!("Then build the EIF and start the enclave.");

    // 4. Wait for VTA to be running
    eprintln!();
    eprint!("Press Enter once the VTA is running...");
    io::stderr().flush()?;
    let mut buf = String::new();
    io::stdin().lock().read_line(&mut buf)?;

    // 5. Prompt for VTA DID
    eprintln!();
    eprintln!("The VTA's DID is shown in its boot logs. You can also retrieve");
    eprintln!("it via: GET /attestation/did-log (if REST is enabled).");
    eprintln!();
    let vta_did: String = Input::new().with_prompt("VTA DID").interact_text()?;

    // 6. Prompt for mediator DID
    let mediator_did: String = Input::new().with_prompt("Mediator DID").interact_text()?;

    // 7. Store identity directly in the keyring. Bundle construction happens
    //    later, inside the TEE-first-boot flow, when the VTA is reachable.
    let keyring_key = vta_keyring_key(&slug);

    // Store session directly — the TEE admin identity does not rotate.
    // No REST URL in TEE mode; operator reaches the VTA via DIDComm through
    // the mediator, resolved from the VTA DID at connect time.
    auth::store_session(&keyring_key, &did, &private_key_multibase, &vta_did)?;

    // 8. Save to config
    config.vtas.insert(
        slug.clone(),
        VtaConfig {
            name: name.clone(),
            vta_did: Some(vta_did.clone()),
            url: None,
            mediator_did: None,
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.clone());
    }
    save_config(config)?;

    eprintln!();
    eprintln!("VTA '{slug}' configured.");
    eprintln!("  Admin DID:    {did}");
    eprintln!("  VTA DID:      {vta_did}");
    eprintln!("  Mediator DID: {mediator_did}");
    eprintln!("  Credential stored in keyring (key: {keyring_key})");
    if config.default_vta.as_deref() == Some(&slug) {
        eprintln!("  Default: yes");
    }
    eprintln!();
    eprintln!("You can now run commands against this VTA:");
    eprintln!("  pnm health");
    eprintln!("  pnm keys list");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cfg_with(slug: &str, vta_did: Option<&str>) -> PnmConfig {
        let mut config = PnmConfig::default();
        config.default_vta = Some(slug.to_string());
        let mut vtas = BTreeMap::new();
        vtas.insert(
            slug.to_string(),
            VtaConfig {
                name: slug.to_string(),
                vta_did: vta_did.map(str::to_string),
                url: None,
                mediator_did: None,
            },
        );
        config.vtas = vtas;
        config
    }

    #[test]
    fn emit_json_shape_matches_spec() {
        // Serialize without writing to stdout. The writer path is
        // exercised end-to-end in manual smoke tests.
        let line = serde_json::to_string(&SetupOutput {
            slug: "my-vta",
            admin_did: "did:key:z6MkTest",
            state: "pending",
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["slug"], "my-vta");
        assert_eq!(parsed["admin_did"], "did:key:z6MkTest");
        assert_eq!(parsed["state"], "pending");
        // Exactly three keys — no accidental leakage of an unserialized
        // field later.
        assert_eq!(parsed.as_object().unwrap().len(), 3);
    }

    #[test]
    fn emit_json_states_match_spec() {
        for state in ["pending", "complete"] {
            let line = serde_json::to_string(&SetupOutput {
                slug: "s",
                admin_did: "did:key:z",
                state,
            })
            .unwrap();
            assert!(line.contains(&format!(r#""state":"{state}""#)));
        }
    }

    #[test]
    fn detect_existing_state_complete() {
        let config = cfg_with("my-vta", Some("did:web:vta.example.com"));
        match detect_existing_state(&config, "my-vta", "vta:my-vta") {
            ExistingState::Complete { vta_did } => {
                assert_eq!(vta_did, "did:web:vta.example.com");
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn detect_existing_state_absent_for_missing_slug() {
        let config = cfg_with("my-vta", Some("did:web:vta.example.com"));
        matches!(
            detect_existing_state(&config, "other-vta", "vta:other-vta"),
            ExistingState::None
        );
    }

    #[test]
    fn require_pending_rejects_complete_slug() {
        let config = cfg_with("my-vta", Some("did:web:vta.example.com"));
        let err = require_pending(&config, "my-vta", "vta:my-vta").unwrap_err();
        assert!(err.to_string().contains("already set up"));
        assert!(err.to_string().contains("pnm vta remove"));
    }

    #[test]
    fn require_pending_rejects_unknown_slug() {
        let config = cfg_with("existing", Some("did:web:vta.example.com"));
        let err = require_pending(&config, "nope", "vta:nope").unwrap_err();
        assert!(err.to_string().contains("no pending VTA"));
        assert!(err.to_string().contains("pnm vta list"));
    }
}
