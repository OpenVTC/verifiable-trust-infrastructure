use std::path::Path;

use dialoguer::{Input, Select};
use vta_sdk::credentials::CredentialBundle;

use crate::auth;
use crate::config::{
    CommunityConfig, PERSONAL_KEYRING_KEY, PersonalVtaConfig, community_keyring_key, config_dir,
    load_config, save_config,
};
use vta_sdk::prelude::*;

/// Interactively prompt for an armored sealed bundle path + expected digest,
/// then open it via the shared consumer helper and extract the admin
/// credential. Used by every "gimme a credential" seam in the wizard.
async fn prompt_for_sealed_credential(
    label: &str,
) -> Result<CredentialBundle, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("Before continuing, generate a bootstrap request for the {label} admin:");
    eprintln!("  cnm bootstrap request --out request.json");
    eprintln!("Hand that file to the admin, then return here with the armored sealed");
    eprintln!("bundle they produce (and its SHA-256 digest for verification).");
    eprintln!();
    let path: String = Input::new()
        .with_prompt(format!("Path to the {label} armored sealed bundle"))
        .interact_text()?;
    let digest: String = Input::new()
        .with_prompt(format!(
            "Expected SHA-256 digest for {label} bundle (empty = skip verification)"
        ))
        .allow_empty(true)
        .interact_text()?;
    let (expect_digest, no_verify) = if digest.trim().is_empty() {
        (None, true)
    } else {
        (Some(digest.trim().to_string()), false)
    };
    open_sealed_credential(Path::new(path.trim()), expect_digest.as_deref(), no_verify)
}

/// Open a sealed bundle file from `bundle_path` and extract a
/// [`CredentialBundle`]. Shared by the CLI-flag path and the interactive
/// path.
fn open_sealed_credential(
    bundle_path: &Path,
    expect_digest: Option<&str>,
    no_verify_digest: bool,
) -> Result<CredentialBundle, Box<dyn std::error::Error>> {
    let config_dir = config_dir()?;
    if no_verify_digest {
        vta_cli_common::sealed_consumer::warn_no_verify_digest();
    }
    let opened = vta_cli_common::sealed_consumer::open_armored_bundle(
        bundle_path,
        &config_dir,
        expect_digest,
        no_verify_digest,
    )?;
    eprintln!(
        "Sealed bundle opened ({} — digest {}).",
        opened.bundle_id_hex, opened.digest
    );
    vta_cli_common::sealed_consumer::extract_admin_credential(opened.payload)
}

/// Derive a URL-safe slug from a community name.
///
/// Lowercases, replaces whitespace/non-alphanumeric with hyphens, trims hyphens.
fn slugify(name: &str) -> String {
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

/// Run the interactive setup wizard.
pub async fn run_setup_wizard() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Welcome to the CNM setup wizard.\n");

    let mut config = load_config()?;

    // ── Personal VTA ────────────────────────────────────────────────
    let (personal_did, personal_url) = prompt_vta_did("Personal").await?;

    let personal_bundle = prompt_for_sealed_credential("personal VTA").await?;

    // Authenticate against personal VTA
    eprintln!();
    auth::login(&personal_bundle, &personal_url, PERSONAL_KEYRING_KEY).await?;

    config.personal_vta = Some(PersonalVtaConfig {
        vta_did: Some(personal_did.clone()),
    });

    // ── Community ───────────────────────────────────────────────────
    let community_name: String = Input::new().with_prompt("Community name").interact_text()?;

    let default_slug = slugify(&community_name);
    let community_slug: String = Input::new()
        .with_prompt("Community slug (short identifier)")
        .default(default_slug)
        .interact_text()?;

    let (community_did, community_url) = prompt_vta_did("Community").await?;

    let join_options = &["Import existing credential", "Generate from personal VTA"];
    let join_choice = Select::new()
        .with_prompt("How do you want to join this community?")
        .items(join_options)
        .default(0)
        .interact()?;

    let community_vta_did_for_config: Option<String> = Some(community_did.clone());

    let context_id = match join_choice {
        // Import existing credential
        0 => {
            let bundle = prompt_for_sealed_credential("community VTA").await?;

            let keyring_key = community_keyring_key(&community_slug);
            eprintln!();
            auth::login(&bundle, &community_url, &keyring_key).await?;

            None
        }
        // Generate from personal VTA
        _ => {
            let context_slug = format!("cnm-{community_slug}");
            let context_name = format!("CNM - {community_name}");

            // Authenticate personal VTA client
            let personal_client =
                auth::authenticated_client(&personal_url, PERSONAL_KEYRING_KEY).await?;

            // Create context in personal VTA
            eprintln!("\nCreating context '{context_name}' in personal VTA...");
            let ctx_req = CreateContextRequest::new(&context_slug, &context_name)
                .description(format!("Community admin identity for {}", community_name));
            match personal_client.create_context(ctx_req).await {
                Ok(ctx) => {
                    eprintln!("  Context created: {} ({})", ctx.id, ctx.base_path);
                }
                Err(ref e) if matches!(e, vta_sdk::error::VtaError::Conflict(_)) => {
                    eprintln!("  Context '{context_slug}' already exists, reusing it.");
                }
                Err(e) => {
                    return Err(e.into());
                }
            }

            // Mint admin did:key locally and register it on the personal VTA
            // via POST /acl. The private key stays on this machine and is
            // immediately stored in the community session — no round-trip
            // through `/auth/credentials` (removed in 5c6).
            eprintln!("Minting community admin credential locally...");

            let (bundle, admin_did) = vta_cli_common::local_keygen::generate_admin_did_key(
                community_did.clone(),
                Some(community_url.clone()),
            );
            let acl_req = vta_sdk::client::CreateAclRequest::new(&admin_did, "admin")
                .label(format!("CNM community admin — {community_slug}"))
                .contexts(vec![context_slug.clone()]);
            personal_client.create_acl(acl_req).await?;

            // Store community session so cnm can authenticate automatically.
            // No URL persisted — derived from `community_did` at runtime
            // on every subsequent command.
            let keyring_key = community_keyring_key(&community_slug);
            auth::store_session_direct(
                &keyring_key,
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
            eprintln!("Once access is granted, cnm will authenticate automatically.");
            eprintln!();

            Some(context_slug)
        }
    };

    // ── Save config ─────────────────────────────────────────────────
    // The REST URL isn't persisted — `community_url` is derived from
    // `community_did` at runtime on every call.
    let _ = community_url;
    config.communities.insert(
        community_slug.clone(),
        CommunityConfig {
            name: community_name,
            context_id,
            vta_did: community_vta_did_for_config,
        },
    );

    // Set as default if first community
    if config.default_community.is_none() || config.communities.len() == 1 {
        config.default_community = Some(community_slug.clone());
    }

    save_config(&config)?;

    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    let path = crate::config::config_path()?;
    eprintln!("  Config saved to: {}", path.display());
    eprintln!("  Default community: {community_slug}");
    eprintln!();

    Ok(())
}

/// Add a new community interactively.
pub async fn add_community() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    let community_name: String = Input::new().with_prompt("Community name").interact_text()?;

    let default_slug = slugify(&community_name);
    let community_slug: String = Input::new()
        .with_prompt("Community slug (short identifier)")
        .default(default_slug)
        .interact_text()?;

    if config.communities.contains_key(&community_slug) {
        return Err(
            format!("community '{community_slug}' already exists. Use a different slug.").into(),
        );
    }

    let (community_did, community_url) = prompt_vta_did("Community").await?;

    let bundle = prompt_for_sealed_credential("community VTA").await?;

    let keyring_key = community_keyring_key(&community_slug);
    eprintln!();
    auth::login(&bundle, &community_url, &keyring_key).await?;

    config.communities.insert(
        community_slug.clone(),
        CommunityConfig {
            name: community_name,
            context_id: None,
            vta_did: Some(community_did),
        },
    );

    if config.default_community.is_none() {
        config.default_community = Some(community_slug.clone());
    }

    save_config(&config)?;

    eprintln!();
    eprintln!("Community '{community_slug}' added.");
    Ok(())
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
}
