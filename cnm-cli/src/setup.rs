//! `cnm setup` and `cnm community add|continue`: the front-ends over
//! [`crate::onboard`].
//!
//! The personal VTA is onboarded the way `pnm` onboards one — a self-minted
//! `did:key`, a grant, then authenticate-and-rotate — with two alternatives:
//! borrowing an existing `pnm` session on this machine to make the grant, and
//! the sealed bundle an administrator hands over (air-gapped or remote).
//! Each community gets an identity of its own unless the operator explicitly
//! reuses another's.

use std::io::IsTerminal;
use std::path::Path;

use dialoguer::{Confirm, Input, Select};
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::session::{SessionStore, TransportChoice};

use crate::auth;
use crate::config::{
    CnmConfig, CommunityConfig, PERSONAL_KEYRING_KEY, PersonalVtaConfig, community_keyring_key,
    config_dir, load_config, save_config,
};
use crate::onboard::{self, CommunityIdentity, PersonalState};
use crate::pnm_profile;
use vta_sdk::prelude::*;

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Interactively prompt for an armored sealed bundle path + expected digest,
/// then open it via the shared consumer helper and extract the admin
/// credential. Used by every "gimme a credential" seam in the wizard.
///
/// `expected_vta_did` is the DID the operator typed for this VTA; the
/// credential must be for that VTA.
async fn prompt_for_sealed_credential(
    label: &str,
    expected_vta_did: &str,
) -> Result<CredentialBundle, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("Before continuing, generate a bootstrap request for the {label} admin:");
    eprintln!("  cnm bootstrap request --out request.json");
    eprintln!("Hand that file to the admin, then return here with the armored sealed");
    eprintln!("bundle they produce and its SHA-256 digest. Get the digest over a channel");
    eprintln!("you trust, separately from the bundle: it is what shows the bundle is theirs.");
    eprintln!();
    let path: String = Input::new()
        .with_prompt(format!("Path to the {label} armored sealed bundle"))
        .interact_text()?;
    let digest: String = Input::new()
        .with_prompt(format!(
            "Expected SHA-256 digest for the {label} bundle (64 hex characters)"
        ))
        .validate_with(|input: &String| digest_prompt_validator(input))
        .interact_text()?;
    let digest = vta_cli_common::sealed_consumer::normalize_expected_digest(&digest)?;
    open_sealed_credential(Path::new(path.trim()), &digest, expected_vta_did)
}

/// Validator for the digest prompt. Empty input is rejected: without the
/// digest, nothing shows that the bundle came from the VTA admin rather than
/// someone else who saw the bootstrap request.
fn digest_prompt_validator(input: &str) -> Result<(), String> {
    vta_cli_common::sealed_consumer::normalize_expected_digest(input).map(|_| ())
}

/// Open a sealed bundle file from `bundle_path`, verify it against the
/// digest and the expected VTA DID, and extract the [`CredentialBundle`].
fn open_sealed_credential(
    bundle_path: &Path,
    expect_digest: &str,
    expected_vta_did: &str,
) -> Result<CredentialBundle, Box<dyn std::error::Error>> {
    let config_dir = config_dir()?;
    let credential = vta_cli_common::sealed_consumer::open_admin_credential(
        bundle_path,
        &config_dir,
        Some(expect_digest),
        Some(expected_vta_did),
    )?;
    eprintln!("Sealed bundle opened and verified.");
    Ok(credential)
}

/// Derive a URL-safe slug from a community name.
///
/// Lowercases, replaces whitespace/non-alphanumeric with hyphens, trims hyphens.
pub(crate) fn slugify(name: &str) -> String {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    slug.trim_matches('-')
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Resolve a VTA DID's `#vta-rest` service endpoint to a URL. The DID is
/// the source of truth; CNM does not persist URLs locally, it derives
/// them at point-of-use.
async fn resolve_vta_url(did: &str) -> Result<String, Box<dyn std::error::Error>> {
    vta_sdk::session::resolve_vta_url(did)
        .await
        .map_err(|e| format!("could not resolve REST endpoint from {did}: {e}").into())
}

/// Prompt for a VTA DID and resolve its REST endpoint via the DID
/// document's `#vta-rest` service. The URL is **not** persisted — it is
/// re-resolved on each call. Returns `(did, url)`.
///
/// `label` is a human-readable prefix like "Personal" or "Community".
async fn prompt_vta_did(label: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let did: String = Input::new()
        .with_prompt(format!("{label} VTA DID"))
        .interact_text()?;
    let did = did.trim().to_string();
    if did.is_empty() {
        return Err(format!("{label} VTA DID is required").into());
    }

    eprintln!("Resolving DID...");
    let url = resolve_vta_url(&did).await?;
    eprintln!("  REST endpoint: {url}");
    Ok((did, url))
}

fn optional_did(prompt: &str) -> CliResult<Option<String>> {
    let v: String = Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact_text()?;
    let v = v.trim();
    Ok((!v.is_empty()).then(|| v.to_string()))
}

// ── cnm setup (interactive) ─────────────────────────────────────────

/// Run the interactive setup wizard: the personal VTA, then a community.
pub async fn run_setup_wizard() -> CliResult {
    eprintln!("Welcome to the CNM setup wizard.\n");

    let mut config = load_config()?;
    let store = auth::store();

    // ── Personal VTA ────────────────────────────────────────────────
    let ready = match onboard::personal_state(&config, &store) {
        PersonalState::Complete { vta_did } => {
            let choice = Select::new()
                .with_prompt(format!("Your personal VTA is already set up ({vta_did})"))
                .items(["Keep it and add a community", "Set it up again"])
                .default(0)
                .interact()?;
            if choice == 0 {
                true
            } else {
                config.personal_vta = None;
                personal_step_interactive(&mut config, &store).await?
            }
        }
        PersonalState::Pending { admin_did, .. } => {
            let choice = Select::new()
                .with_prompt(format!(
                    "A personal-VTA setup is pending (admin DID {admin_did})"
                ))
                .items([
                    "Continue it — the grant has been made",
                    "Start over with a fresh identity",
                    "Cancel",
                ])
                .default(0)
                .interact()?;
            match choice {
                0 => continue_personal_interactive(&mut config, &store, None).await?,
                1 => {
                    config.personal_vta = None;
                    personal_step_interactive(&mut config, &store).await?
                }
                _ => return Ok(()),
            }
        }
        PersonalState::None => personal_step_interactive(&mut config, &store).await?,
    };
    save_config(&config)?;
    if !ready {
        return Ok(());
    }

    // ── Community ───────────────────────────────────────────────────
    community_step_interactive(&mut config, &store).await?;
    save_config(&config)?;

    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    let path = crate::config::config_path()?;
    eprintln!("  Config saved to: {}", path.display());
    if let Some(d) = &config.default_community {
        eprintln!("  Default community: {d}");
    }
    eprintln!();
    Ok(())
}

/// The personal-VTA step. Returns `true` when the personal VTA is ready and
/// the wizard can go on to a community, `false` when it is parked pending a
/// grant (the operator finishes with `cnm setup continue`).
async fn personal_step_interactive(
    config: &mut CnmConfig,
    store: &SessionStore,
) -> CliResult<bool> {
    eprintln!("Personal VTA — the VTA that holds your own keys.");
    let vta_did = optional_did("Personal VTA DID (leave blank if it is not running yet)")?;

    let Some(vta_did) = vta_did else {
        // No VTA yet: only the cold start can proceed — mint now, grant later.
        let name = prompt_personal_name()?;
        let did = onboard::begin_personal(config, store, &name, true)?;
        save_config(config)?;
        print_personal_pending(&name, &did);
        return Ok(false);
    };
    if !vta_did.starts_with("did:") {
        return Err("the VTA DID must start with `did:`".into());
    }

    let pnm_matches = pnm_profile::find(&vta_did);
    let mut items = vec![
        "Self-mint a key and have an admin grant it (recommended — as `pnm setup` does)"
            .to_string(),
    ];
    for m in &pnm_matches {
        items.push(format!(
            "Bootstrap from your existing pnm session ('{}' — {})",
            m.slug, m.name
        ));
    }
    items.push("I have a sealed bundle from an admin (air-gapped/remote)".to_string());
    let choice = Select::new()
        .with_prompt("How should cnm get access to this VTA?")
        .items(&items)
        .default(0)
        .interact()?;

    if choice == 0 {
        let name = prompt_personal_name()?;
        let did = onboard::begin_personal(config, store, &name, true)?;
        onboard::bind_personal(config, store, Some(&vta_did))?;
        save_config(config)?;
        eprintln!();
        eprintln!("  \x1b[1mAdmin DID:\x1b[0m {did}");
        eprintln!();
        eprintln!("{}", onboard::personal_grant_commands(&did));
        eprintln!();
        let now = Confirm::new()
            .with_prompt("Has the grant been made? Authenticate now")
            .default(true)
            .interact()?;
        if !now {
            eprintln!("Saved. Once the grant is in place, finish with:");
            eprintln!("  cnm setup continue {name}");
            return Ok(false);
        }
        authenticate_and_report(config, store, None, TransportChoice::Auto).await?;
        return Ok(true);
    }

    if let Some(m) = pnm_matches.get(choice - 1) {
        bootstrap_from_pnm(config, store, &vta_did, m).await?;
        return Ok(true);
    }

    // Sealed bundle — unchanged: digest pinning and the VTA-DID check are the
    // shared consumer's.
    let url = resolve_vta_url(&vta_did).await?;
    let bundle = prompt_for_sealed_credential("personal VTA", &vta_did).await?;
    eprintln!();
    auth::login(&bundle, &url, PERSONAL_KEYRING_KEY).await?;
    config.personal_vta = Some(PersonalVtaConfig {
        vta_did: Some(vta_did),
        name: None,
    });
    Ok(true)
}

fn prompt_personal_name() -> CliResult<String> {
    let name: String = Input::new()
        .with_prompt("Name for your personal VTA")
        .default(onboard::DEFAULT_PERSONAL_NAME.to_string())
        .interact_text()?;
    Ok(name.trim().to_string())
}

fn print_personal_pending(name: &str, did: &str) {
    eprintln!();
    eprintln!("  \x1b[1mAdmin DID:\x1b[0m {did}");
    eprintln!();
    eprintln!("{}", onboard::personal_grant_commands(did));
    eprintln!();
    eprintln!("Once the VTA is running and the grant is in place, finish with:");
    eprintln!("  \x1b[1mcnm setup continue {name} --vta-did <did:...>\x1b[0m");
    eprintln!();
}

/// "Bootstrap from your existing pnm session": mint cnm's own key, park it
/// locally first (so a crash cannot leave a granted key nobody holds), let the
/// `pnm` session grant it, then authenticate and rotate as the cold start does.
async fn bootstrap_from_pnm(
    config: &mut CnmConfig,
    store: &SessionStore,
    vta_did: &str,
    m: &pnm_profile::PnmMatch,
) -> CliResult {
    let pnm_store = pnm_profile::store().ok_or("could not open pnm's session store")?;
    let pnm_session = pnm_profile::session_for(&pnm_store, &m.slug, vta_did).ok_or_else(|| {
        format!(
            "pnm's profile '{}' has no session for {vta_did} (is its setup still pending? \
             try `pnm --vta {} health`).\nChoose the self-minted option instead.",
            m.slug, m.slug
        )
    })?;
    let url = match &m.url {
        Some(u) => u.clone(),
        None => resolve_vta_url(vta_did).await?,
    };

    let did = onboard::begin_personal(config, store, onboard::DEFAULT_PERSONAL_NAME, true)?;
    onboard::bind_personal(config, store, Some(vta_did))?;
    save_config(config)?;
    eprintln!(
        "Minted cnm's own key {did}; granting it with pnm's session '{}'…",
        m.slug
    );
    onboard::grant_from_pnm(&pnm_session, vta_did, &url, &did).await?;
    eprintln!("  Granted. pnm's key was used only to sign that grant; cnm never stored it.");
    authenticate_and_report(config, store, Some(&url), TransportChoice::Auto).await
}

async fn authenticate_and_report(
    config: &mut CnmConfig,
    store: &SessionStore,
    url: Option<&str>,
    transport: TransportChoice,
) -> CliResult {
    eprintln!("Authenticating and rotating to a fresh key…");
    let result = onboard::authenticate_personal(config, store, url, transport).await;
    // Saved either way: success completes the personal VTA, and a refusal
    // leaves the pending state intact for `continue`.
    save_config(config)?;
    let rotated = result?;
    eprintln!("\x1b[1;32mPersonal VTA ready.\x1b[0m cnm now authenticates as {rotated}");
    eprintln!("  (the temporary DID's ACL entry was replaced and removed)");
    Ok(())
}

async fn continue_personal_interactive(
    config: &mut CnmConfig,
    store: &SessionStore,
    vta_url: Option<&str>,
) -> CliResult<bool> {
    let vta_did = match onboard::personal_state(config, store) {
        PersonalState::Pending {
            bound_vta: None, ..
        } => {
            let did: String = Input::new()
                .with_prompt("Personal VTA DID")
                .interact_text()?;
            Some(did.trim().to_string())
        }
        _ => None,
    };
    onboard::bind_personal(config, store, vta_did.as_deref())?;
    authenticate_and_report(config, store, vta_url, TransportChoice::Auto).await?;
    Ok(true)
}

// ── cnm setup --name / continue (scriptable) ────────────────────────

/// `cnm setup --name <name>` — phase 1 without prompts. One JSON line on
/// stdout, `pnm setup --name`'s shape.
pub async fn start_personal_non_interactive(name: &str, overwrite: bool) -> CliResult {
    let slug = slugify(name);
    if slug.is_empty() {
        return Err("--name must produce a non-empty slug after normalization".into());
    }
    let mut config = load_config()?;
    let store = auth::store();
    let did = onboard::begin_personal(&mut config, &store, name, overwrite)?;
    save_config(&config)?;
    eprintln!("Pending personal VTA '{slug}' created.");
    eprintln!("  Admin DID: {did}");
    eprintln!();
    eprintln!("{}", onboard::personal_grant_commands(&did));
    eprintln!();
    eprintln!("Next: cnm setup continue {slug} --vta-did <did:...>");
    onboard::emit_json(&slug, &did, "pending")?;
    Ok(())
}

/// `cnm setup continue [<name>] [--vta-did <did>] [--vta-url <url>]`.
///
/// Binds the pending identity to the VTA (prompting for the DID only on a
/// terminal), authenticates — which rotates to a fresh `did:key` and drops the
/// temp DID's ACL entry — and, interactively, goes on to the community step.
/// With `--vta-did`, or off a terminal, it prints one JSON line instead.
pub async fn continue_personal(
    name: Option<&str>,
    vta_did: Option<&str>,
    vta_url: Option<&str>,
    transport: TransportChoice,
) -> CliResult {
    let mut config = load_config()?;
    let store = auth::store();
    onboard::check_personal_name(&config, name)?;
    let interactive = vta_did.is_none() && std::io::stdin().is_terminal();

    if interactive {
        continue_personal_interactive(&mut config, &store, vta_url).await?;
        let more = Confirm::new()
            .with_prompt("Add a community now")
            .default(true)
            .interact()?;
        if more {
            community_step_interactive(&mut config, &store).await?;
            save_config(&config)?;
        }
        return Ok(());
    }

    onboard::bind_personal(&config, &store, vta_did)?;
    let result = onboard::authenticate_personal(&mut config, &store, vta_url, transport).await;
    save_config(&config)?;
    let rotated = result?;
    let slug = slugify(
        config
            .personal_vta
            .as_ref()
            .and_then(|p| p.name.as_deref())
            .unwrap_or(onboard::DEFAULT_PERSONAL_NAME),
    );
    eprintln!("Personal VTA ready; cnm authenticates as {rotated}.");
    eprintln!("Next: cnm community add <name>");
    onboard::emit_json(&slug, &rotated, "complete")?;
    Ok(())
}

// ── Communities ─────────────────────────────────────────────────────

/// Arguments of `cnm community add`.
pub struct AddCommunityArgs {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub reuse_identity: Option<String>,
    pub vtc_did: Option<String>,
    pub vta_did: Option<String>,
    pub overwrite: bool,
}

/// `cnm community add` — interactive without a name, scriptable with one.
pub async fn add_community(args: AddCommunityArgs) -> CliResult {
    let mut config = load_config()?;
    let store = auth::store();
    let Some(name) = args.name else {
        community_step_interactive(&mut config, &store).await?;
        save_config(&config)?;
        return Ok(());
    };
    let slug = args.slug.unwrap_or_else(|| slugify(&name));
    let identity = match args.reuse_identity {
        Some(from) => CommunityIdentity::Reuse { from },
        None => CommunityIdentity::Fresh,
    };
    let did = onboard::begin_community(
        &mut config,
        &store,
        &name,
        &slug,
        &identity,
        args.vtc_did.as_deref(),
        args.vta_did.as_deref(),
        args.overwrite,
    )?;
    save_config(&config)?;
    eprintln!("Pending community '{slug}' created.");
    eprintln!("  Admin DID: {did}");
    if let CommunityIdentity::Reuse { from } = &identity {
        eprintln!("  Reused from '{from}' — the two communities now share this key.");
    }
    eprintln!();
    eprintln!("{}", onboard::community_grant_commands(&slug, &did));
    onboard::emit_json(&slug, &did, "pending")?;
    Ok(())
}

/// `cnm community continue <slug>` — confirm the grant at the VTC and make
/// the community usable.
pub async fn continue_community(
    slug: &str,
    vtc_did: Option<&str>,
    vta_did: Option<&str>,
    url: Option<&str>,
) -> CliResult {
    let mut config = load_config()?;
    let store = auth::store();
    let did = onboard::continue_community(&mut config, &store, slug, vtc_did, vta_did, url).await?;
    save_config(&config)?;
    eprintln!("\x1b[1;32mCommunity '{slug}' ready.\x1b[0m cnm authenticates to it as {did}.");
    eprintln!(
        "  The VTC has no key-rotation task, so this minted key is kept; its private half \
         never left this machine."
    );
    onboard::emit_json(slug, &did, "complete")?;
    Ok(())
}

/// The community step of the wizard, and `cnm community add` without a name.
async fn community_step_interactive(config: &mut CnmConfig, store: &SessionStore) -> CliResult {
    let community_name: String = Input::new().with_prompt("Community name").interact_text()?;
    let default_slug = slugify(&community_name);
    let community_slug: String = Input::new()
        .with_prompt("Community slug (short identifier)")
        .default(default_slug)
        .interact_text()?;

    let personal_ready = matches!(
        onboard::personal_state(config, store),
        PersonalState::Complete { .. }
    );
    let mut items = vec![(
        "fresh",
        "Mint a fresh admin identity for this community (recommended)",
    )];
    if !config.communities.is_empty() {
        items.push((
            "reuse",
            "Reuse another community's identity (the two become linkable)",
        ));
    }
    items.push(("import", "Import a sealed credential from an admin"));
    if personal_ready {
        items.push(("personal", "Generate from personal VTA"));
    }
    let labels: Vec<&str> = items.iter().map(|(_, l)| *l).collect();
    let choice = Select::new()
        .with_prompt("Which identity should cnm use for this community?")
        .items(&labels)
        .default(0)
        .interact()?;

    match items[choice].0 {
        "fresh" | "reuse" => {
            let identity = if items[choice].0 == "reuse" {
                let others: Vec<&String> = config.communities.keys().collect();
                let pick = Select::new()
                    .with_prompt("Reuse the identity of")
                    .items(&others)
                    .default(0)
                    .interact()?;
                let from = others[pick].clone();
                eprintln!(
                    "\x1b[33m⚠\x1b[0m The same key in two communities lets anyone who sees \
                     both ACLs link them to one operator."
                );
                if !Confirm::new()
                    .with_prompt(format!("Use '{from}'s identity for '{community_slug}'"))
                    .default(false)
                    .interact()?
                {
                    return Err("cancelled — run `cnm community add` again for a fresh one".into());
                }
                CommunityIdentity::Reuse { from }
            } else {
                CommunityIdentity::Fresh
            };
            let vtc_did = optional_did("Community VTC DID (leave blank to supply it later)")?;
            let vta_did = optional_did("Community VTA DID (leave blank if it has none)")?;
            let did = onboard::begin_community(
                config,
                store,
                &community_name,
                &community_slug,
                &identity,
                vtc_did.as_deref(),
                vta_did.as_deref(),
                true,
            )?;
            save_config(config)?;
            eprintln!();
            eprintln!("  \x1b[1mCommunity admin DID:\x1b[0m {did}");
            eprintln!();
            eprintln!(
                "{}",
                onboard::community_grant_commands(&community_slug, &did)
            );
            eprintln!();
            if vtc_did.is_none()
                || !Confirm::new()
                    .with_prompt("Has the grant been made? Confirm it now")
                    .default(true)
                    .interact()?
            {
                return Ok(());
            }
            let did = onboard::continue_community(config, store, &community_slug, None, None, None)
                .await?;
            eprintln!("\x1b[1;32mCommunity '{community_slug}' ready\x1b[0m as {did}.");
            Ok(())
        }
        "import" => import_community(config, &community_name, &community_slug).await,
        _ => generate_from_personal(config, &community_name, &community_slug).await,
    }
}

/// Import a sealed credential for the community's VTA — the path that existed
/// before per-community identities, unchanged.
async fn import_community(config: &mut CnmConfig, name: &str, slug: &str) -> CliResult {
    let (community_did, community_url) = prompt_vta_did("Community").await?;
    let bundle = prompt_for_sealed_credential("community VTA", &community_did).await?;
    let keyring_key = community_keyring_key(slug);
    eprintln!();
    auth::login(&bundle, &community_url, &keyring_key).await?;
    insert_community(config, slug, name, None, Some(community_did));
    Ok(())
}

/// "Generate from personal VTA" — unchanged: a context on the personal VTA and
/// a locally minted admin key registered in it.
async fn generate_from_personal(config: &mut CnmConfig, name: &str, slug: &str) -> CliResult {
    let personal_did = config
        .personal_vta
        .as_ref()
        .and_then(|p| p.vta_did.clone())
        .ok_or("the personal VTA is not set up")?;
    let personal_url = resolve_vta_url(&personal_did).await?;
    let (community_did, community_url) = prompt_vta_did("Community").await?;

    let context_slug = format!("cnm-{slug}");
    let context_name = format!("CNM - {name}");
    let personal_client = auth::authenticated_client(&personal_url, PERSONAL_KEYRING_KEY).await?;

    eprintln!("\nCreating context '{context_name}' in personal VTA...");
    let ctx_req = CreateContextRequest::new(&context_slug, &context_name)
        .description(format!("Community admin identity for {name}"));
    match personal_client.create_context(ctx_req).await {
        Ok(ctx) => eprintln!("  Context created: {} ({})", ctx.id, ctx.base_path),
        Err(ref e) if matches!(e, vta_sdk::error::VtaError::Conflict(_)) => {
            eprintln!("  Context '{context_slug}' already exists, reusing it.");
        }
        Err(e) => return Err(e.into()),
    }

    // Mint admin did:key locally and register it on the personal VTA via
    // POST /acl. The private key stays on this machine.
    eprintln!("Minting community admin credential locally...");
    let (bundle, admin_did) = vta_cli_common::local_keygen::generate_admin_did_key(
        community_did.clone(),
        Some(community_url),
    );
    let acl_req = vta_sdk::client::CreateAclRequest::new(&admin_did, "admin")
        .label(format!("CNM community admin — {slug}"))
        .contexts(vec![context_slug.clone()]);
    personal_client.create_acl(acl_req).await?;

    auth::store_session_direct(
        &community_keyring_key(slug),
        &admin_did,
        &bundle.private_key_multibase,
        &community_did,
    )?;

    eprintln!();
    eprintln!("\x1b[1;32mGenerated community admin DID:\x1b[0m {admin_did}");
    eprintln!();
    eprintln!("Share this DID with the community administrator.");
    eprintln!("They will run:");
    eprintln!("  vta import-did --did {admin_did} --role admin");
    eprintln!();
    insert_community(config, slug, name, Some(context_slug), Some(community_did));
    Ok(())
}

fn insert_community(
    config: &mut CnmConfig,
    slug: &str,
    name: &str,
    context_id: Option<String>,
    vta_did: Option<String>,
) {
    // Re-running setup for a slug keeps the VTC it was pointed at.
    let vtc_did = config.communities.get(slug).and_then(|c| c.vtc_did.clone());
    config.pending_communities.remove(slug);
    config.communities.insert(
        slug.to_string(),
        CommunityConfig {
            name: name.to_string(),
            context_id,
            vta_did,
            vtc_did,
        },
    );
    if config.default_community.is_none() || config.communities.len() == 1 {
        config.default_community = Some(slug.to_string());
    }
}

/// Bootstrap a community session from the personal VTA.
///
/// When a community was set up via "Generate from personal VTA" but the session
/// was lost (e.g. setup ran before auto-store was implemented), this function
/// regenerates a credential from the personal VTA and stores it.
///
/// **Note:** This creates a NEW admin DID. The user must run `vta import-did`
/// on the community VTA with the new DID.
pub async fn bootstrap_community_session(
    slug: &str,
    community: &CommunityConfig,
    personal_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let context_id = community
        .context_id
        .as_deref()
        .ok_or("community has no context_id")?;
    let community_vta_did = community
        .vta_did
        .as_deref()
        .ok_or("community has no vta_did in config (setup ran before this feature was added)")?;

    // Resolve the community VTA's REST endpoint from its DID document
    // for the credential bundle hint (no longer persisted in CNM config).
    let community_url = resolve_vta_url(community_vta_did).await?;

    // Authenticate to personal VTA
    let personal_client = auth::authenticated_client(personal_url, PERSONAL_KEYRING_KEY).await?;

    // Mint a new admin credential locally and register it on the personal
    // VTA via POST /acl. No key material crosses the wire.
    eprintln!("Bootstrapping community session from personal VTA...");
    let (bundle, admin_did) = vta_cli_common::local_keygen::generate_admin_did_key(
        community_vta_did.to_string(),
        Some(community_url),
    );
    let acl_req = vta_sdk::client::CreateAclRequest::new(&admin_did, "admin")
        .label(format!("CNM community admin — {slug} (bootstrapped)"))
        .contexts(vec![context_id.to_string()]);
    personal_client.create_acl(acl_req).await?;

    // Store community session — URL not persisted, derived at runtime.
    let keyring_key = community_keyring_key(slug);
    auth::store_session_direct(
        &keyring_key,
        &admin_did,
        &bundle.private_key_multibase,
        community_vta_did,
    )?;

    eprintln!();
    eprintln!("\x1b[1;32mBootstrapped community session with new DID:\x1b[0m {admin_did}");
    eprintln!();
    eprintln!("This is a NEW DID. You must grant it access on the community VTA:");
    eprintln!("  vta import-did --did {admin_did} --role admin");
    eprintln!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slugify_basic() {
        assert_eq!(slugify("Storm Network"), "storm-network");
    }

    #[test]
    fn test_slugify_special_chars() {
        assert_eq!(slugify("Acme Corp."), "acme-corp");
    }

    #[test]
    fn test_slugify_multiple_spaces() {
        assert_eq!(slugify("  My   Test  Community  "), "my-test-community");
    }

    #[test]
    fn test_slugify_already_slug() {
        assert_eq!(slugify("already-good"), "already-good");
    }

    #[test]
    fn test_slugify_uppercase() {
        assert_eq!(slugify("UPPERCASE"), "uppercase");
    }

    #[test]
    fn test_slugify_numbers() {
        assert_eq!(slugify("Community 42"), "community-42");
    }

    #[test]
    fn digest_prompt_rejects_empty_input() {
        assert!(digest_prompt_validator("").is_err());
        assert!(digest_prompt_validator("  ").is_err());
    }

    #[test]
    fn digest_prompt_accepts_only_a_sha256_hex_digest() {
        assert!(digest_prompt_validator(&"0f".repeat(32)).is_ok());
        assert!(digest_prompt_validator(&"0f".repeat(31)).is_err());
        assert!(digest_prompt_validator(&"zz".repeat(32)).is_err());
    }

    /// The sealed-bundle option goes through the same digest-pinned consumer
    /// as before: a bundle it cannot verify is refused, and a missing file is
    /// an error rather than a silent skip.
    #[test]
    fn the_sealed_bundle_path_refuses_what_it_cannot_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.armored");
        std::fs::write(
            &path,
            "-----BEGIN VTA SEALED BUNDLE-----\nnot a bundle\n-----END VTA SEALED BUNDLE-----\n",
        )
        .unwrap();
        let err = vta_cli_common::sealed_consumer::open_admin_credential(
            &path,
            dir.path(),
            Some(&"0f".repeat(32)),
            Some("did:webvh:QmPersonal:vta.example.com"),
        );
        assert!(err.is_err());
        assert!(
            vta_cli_common::sealed_consumer::open_admin_credential(
                &dir.path().join("missing"),
                dir.path(),
                Some(&"0f".repeat(32)),
                None,
            )
            .is_err()
        );
    }
}
