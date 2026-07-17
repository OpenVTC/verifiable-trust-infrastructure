//! `vtc setup` interactive wizard.
//!
//! Drives the VTA-provisioned bootstrap of a fresh VTC daemon per
//! `tasks/vtc-mvp/vta-driven-keys.md` §3:
//!
//! 1. Prompt the operator for the four configuration knobs (config
//!    path, VTC base URL, VTA DID, context).
//! 2. Mint an ephemeral `did:key` for the round-trip.
//! 3. Pause for the operator to create the target context at the VTA
//!    and grant the ephemeral DID admin access in one step
//!    (`pnm contexts create --id <ctx> --name "VTC" --admin-did <…>
//!    --admin-expires 1h`). Matches the canonical
//!    `MediatorMessages` / `WebvhServerMessages` shape so all
//!    template-driven integration setups read the same.
//! 4. Drive `vta_sdk::provision_client::run_provision` with
//!    `VtaIntent::FullSetup` + `ProvisionAsk::for_template
//!    ("vtc-host", { URL = base_url }, ctx)`. `URL` is the daemon's
//!    host base — the template's default `STATUS_LIST_PATH` is
//!    `/v1/status-lists`, so the rendered status-list endpoint is
//!    `{base_url}/v1/status-lists`. Passing the API base with `/v1`
//!    here renders a double-`/v1` endpoint in the DID doc.
//! 5. Open the sealed bundle; extract the `DidKeyMaterial` into a
//!    [`crate::setup::VtcKeyBundle`].
//! 6. Write the bundle into the chosen secret-store backend; the
//!    `did.jsonl` to `<data_dir>/did/<scid>.jsonl`; the config to
//!    `config.toml`. Mint an install token, print the URL.
//!
//! Refuses to re-run on an already-set-up daemon (config or seed
//! present).

use crate::store::keyspaces;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use dialoguer::{Confirm, Input};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc;
use tracing::warn;
use vta_sdk::client::VtaClient;
use vta_sdk::provision_client::{
    EphemeralSetupKey, OperatorMessages, ProvisionAsk, ProvisionResult, ResolvedVta, VtaEvent,
    VtaIntent, VtaReply, resolve_vta, run_connection_test, run_provision_flight,
};

use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::setup::secrets_prompt::{
    AvailableBackends, BackendResolvers, SecretsBackendChoice, SecretsPromptError,
    configure_secrets,
};
use vti_common::store::Store;

use crate::config::{AppConfig, AuthConfig, LogConfig, MessagingConfig, SecretsConfig};
use crate::install::{
    INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallTokenSigner, InstallTokenStore, mint_install_token,
};
use crate::keys::seed_store::create_secret_store;
use crate::setup::VtcKeyBundle;

/// Entry point bound to `Commands::Setup` in `main.rs`.
pub async fn run_setup_wizard(config_path: Option<PathBuf>) -> Result<(), AppError> {
    intro_banner();
    let plan = collect_interactive(config_path).await?;
    let outcome = apply(plan).await?;
    print_setup_summary_interactive(&outcome)?;
    Ok(())
}

/// Gather every operator decision interactively and assemble a
/// fully-resolved [`WizardPlan`]. This is the TTY half — prompts plus
/// the live VTA round-trips (DID resolution, the ACL-grant pause, the
/// did-hosting picker). The non-interactive `setup --from <toml>` path
/// builds the same plan from a file and feeds it to the same [`apply`],
/// so the two never drift.
async fn collect_interactive(config_path: Option<PathBuf>) -> Result<WizardPlan, AppError> {
    let config_path = prompt_config_path(config_path)?;
    refuse_if_already_set_up(&config_path)?;

    let inputs = prompt_inputs()?;

    // 1. Resolve the VTA DID once, up front. This doubles as an early
    //    "is the VTA DID valid?" check — bail-fast on a typo rather than
    //    after the operator has gone off to grant the ACL — and feeds
    //    both the mediator suggestion below and the REST URL the
    //    did-hosting picker needs later. A resolution failure isn't fatal:
    //    the operator can still supply a mediator by hand and the picker
    //    degrades to the VTA's own server auto-selection.
    let resolved: Option<ResolvedVta> = match resolve_vta(&inputs.vta_did).await {
        Ok(r) => Some(r),
        Err(e) => {
            warn!(
                error = %e,
                vta_did = %inputs.vta_did,
                "could not resolve VTA DID — mediator suggestion + did-hosting picker unavailable"
            );
            None
        }
    };

    // 2. Mediator choice.
    let messaging = prompt_messaging(resolved.as_ref().and_then(|r| r.mediator_did.clone()))?;

    // 3. Mint the ephemeral DID first so we can show it to the
    //    operator before they pick a secret-store backend (the
    //    pause for the ACL step is the slow part — get the
    //    decision-needed-from-the-operator instructions on screen
    //    before asking them anything else).
    let setup_key = EphemeralSetupKey::generate()
        .map_err(|e| AppError::Internal(format!("failed to generate ephemeral setup key: {e}")))?;
    print_acl_step(&inputs, &setup_key);
    if !Confirm::new()
        .with_prompt("Has the ACL grant been created at the VTA?")
        .default(false)
        .interact()
        .map_err(prompt_err)?
    {
        return Err(AppError::Validation("setup aborted".into()));
    }

    // 4. Choose where the VTC DID is published. The ACL grant just
    //    landed, so the ephemeral key can now authenticate to the VTA and
    //    enumerate its did-hosting servers + tenant domains for an
    //    interactive picker. Done before the secrets prompt so any auth /
    //    listing failure surfaces while the operator is still engaged.
    let webvh = select_webvh_target(resolved.as_ref(), &setup_key).await?;

    // 5. Pick a secrets-store backend. We delay this until after
    //    the ACL pause because the operator may want to interrupt
    //    setup at this point (e.g. realise they typed the VTA URL
    //    wrong); resolving the keyring path before the VTA
    //    round-trip avoids burning a useful slot at the storage
    //    layer.
    let secrets = prompt_secrets_config()?;

    Ok(WizardPlan {
        config_path,
        inputs,
        webvh,
        secrets,
        messaging,
        setup_key,
    })
}

/// Provision the VTC against the VTA and write every piece of on-disk
/// state (did.jsonl, config.toml, the sealed key bundle, the install
/// token). Deliberately free of prompts — both the interactive wizard
/// and `setup --from <toml>` drive this identical effect path, so the
/// non-interactive flow can't diverge from the interactive one. Returns
/// the facts the caller presents; it does not print.
pub(crate) async fn apply(plan: WizardPlan) -> Result<SetupOutcome, AppError> {
    let WizardPlan {
        config_path,
        inputs,
        webvh,
        secrets,
        messaging,
        setup_key,
    } = plan;

    // Drive the provision-integration round-trip. Capture and discard
    // event traffic so the setup UX stays terse — long-form progress UX
    // is for `pnm`, not the daemon setup flow.
    let provision = run_provision_quietly(&inputs, &webvh, &setup_key).await?;
    let integration_did = provision
        .integration_did()
        .ok_or_else(|| {
            AppError::Internal(
                "VTA returned a bundle with no integration DID — vtc-host template should mint \
                 one"
                .into(),
            )
        })?
        .to_string();
    let integration_key = provision.integration_key().ok_or_else(|| {
        AppError::Internal(
            "VTA returned a bundle with no integration key material — vtc-host bundle is \
             malformed"
                .into(),
        )
    })?;
    let bundle = VtcKeyBundle::from_did_key_material(integration_did.clone(), integration_key);

    // 5. Persist the did.jsonl log so the daemon's `GET
    //    /.well-known/did.jsonl` route can serve it after restart.
    let did_log = provision.webvh_log().ok_or_else(|| {
        AppError::Internal(
            "vtc-host template did not produce a did.jsonl output — the VTC must be a did:webvh"
                .into(),
        )
    })?;
    let data_dir = default_data_dir_for(&config_path);
    let label = did_log_label_or_err(&integration_did)?;
    write_did_log(&data_dir, &label, did_log)?;

    // 6. Materialise the config. We hold off writing it to disk until
    //    step 7 because the config-secret backend stores the key bundle
    //    *inside* the config file itself.
    let mut app_config = build_app_config(
        config_path.clone(),
        integration_did.clone(),
        inputs.vta_did.clone(),
        inputs.base_url.clone(),
        data_dir.clone(),
        secrets,
        messaging,
    )?;

    // 7. Persist the key bundle via the chosen backend.
    //
    //    Every backend except config-secret is a writable store the
    //    daemon reads back at runtime: write the config first (so
    //    `create_secret_store` resolves the right backend), then `.set()`
    //    the bundle.
    //
    //    The config-secret backend is read-only at runtime by design — its
    //    bytes live inline in `[secrets] secret` in config.toml, and
    //    `ConfigSecretStore::set` deliberately errors. For that backend we
    //    hex-encode the bundle into the config and let the config write
    //    carry it to disk instead of calling `.set()`.
    //    `secrets_choice_to_config` seeds `secret = Some("")` when the
    //    interactive operator picks the inline backend, so an `is_some()`
    //    secret is one signal we took that path; an explicit
    //    `backend = "config"` (the non-interactive selector, where the
    //    operator leaves `secret` empty because the bundle is minted here)
    //    is the other. Mirrors the VTA wizard's config-seed handling in
    //    `vta-service/src/setup/interactive.rs`.
    let bundle_bytes = bundle.to_secret_store_bytes()?;
    let inline_config_backend = app_config.secrets.secret.is_some()
        || matches!(
            app_config.secrets.backend,
            Some(crate::config::SecretBackend::Config)
        );
    if inline_config_backend {
        app_config.secrets.secret = Some(hex::encode(&bundle_bytes));
        write_config_toml(&config_path, &app_config)?;
    } else {
        write_config_toml(&config_path, &app_config)?;
        let secret_store = create_secret_store(&app_config)
            .map_err(|e| AppError::Config(format!("failed to construct secret store: {e}")))?;
        secret_store
            .set(&bundle_bytes)
            .await
            .map_err(|e| AppError::SecretStore(format!("failed to store VTC key bundle: {e}")))?;
    }

    // 8. Materialise the keyspaces so a `vtc` start doesn't have
    //    to pay the partition-create cost.
    open_keyspaces(&app_config)?;

    // 9. Mint a one-shot install token. The operator uses this to
    //    claim their admin passkey on the running daemon.
    // Admin DID for the install ceremony — the rotated long-term DID
    // the VTA returned from the bootstrap. Same identity at both VTA
    // and VTC: a single admin credential the operator can use for
    // either daemon's auth. The install URL attaches a passkey to this
    // DID for browser-based admin UI access.
    let admin_did = provision.admin_did().to_string();
    let (install_url, claim_code) =
        mint_initial_install_token(&app_config, &bundle, &admin_did, &inputs.base_url).await?;

    // Surface the long-term admin key material so the operator can
    // save it for CLI use (the wizard doesn't yet write it to a
    // keyring — manual handling is the MVP). The integration key
    // doesn't contain the admin private key; we pull it from the
    // provision result.
    let admin_key_summary = provision
        .admin_key()
        .and_then(|k| serde_json::to_string_pretty(k).ok());

    Ok(SetupOutcome {
        vtc_did: integration_did,
        admin_did,
        config_path,
        data_dir,
        install_url,
        claim_code,
        admin_key_json: admin_key_summary,
    })
}

/// Print the rich, interactive completion summary, gating the one-shot
/// admin-key reveal behind an explicit confirm so the private key never
/// spills into terminal scrollback unasked.
fn print_setup_summary_interactive(outcome: &SetupOutcome) -> Result<(), AppError> {
    println!();
    println!("\x1b[1;32m✅ VTC setup complete.\x1b[0m");
    println!();
    println!("VTC DID:       {}", outcome.vtc_did);
    println!("Admin DID:     {}", outcome.admin_did);
    println!("Config:        {}", outcome.config_path.display());
    println!("Data dir:      {}", outcome.data_dir.display());
    println!();
    if let Some(key_json) = outcome.admin_key_json.as_deref() {
        // The admin private key lands in the terminal scrollback / any
        // session recording the moment it's printed. Make the operator
        // consciously reveal it rather than spilling it by default.
        // TODO(keyring): write this to the OS keyring instead of stdout.
        let reveal = Confirm::new()
            .with_prompt(
                "Display the admin private key now? It's needed for CLI access and is shown only once",
            )
            .default(false)
            .interact()
            .map_err(prompt_err)?;
        if reveal {
            println!("\x1b[1;33mAdmin key (save this — needed for CLI access):\x1b[0m");
            println!("{key_json}");
        } else {
            println!(
                "\x1b[1;33mAdmin key not displayed.\x1b[0m Re-run setup if you need it; it is \
                 not persisted."
            );
        }
        println!();
    }
    println!("\x1b[1mInstall URL (one-shot, 15 min TTL):\x1b[0m");
    println!("  {}", outcome.install_url);
    println!();
    println!("\x1b[1mClaim code (required at claim time):\x1b[0m");
    println!("  {}", outcome.claim_code);
    println!();
    println!("Both URL and code are needed to claim the passkey. The code is shown");
    println!("only once and not persisted — copy it before continuing.");
    println!();
    println!("Next steps:");
    println!("  1. Run `vtc` to start the daemon.");
    println!("  2. Open the install URL in your browser.");
    println!("  3. Enter the claim code when prompted, then register your passkey.");
    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// Input collection
// ---------------------------------------------------------------------------

pub(crate) struct WizardInputs {
    /// Daemon's host base URL (e.g. `https://vtc.example.com`). The
    /// three surfaces — API, admin UX, public website — all mount
    /// under this in path mode (the default). Stored verbatim as
    /// `public_url` in the config and passed as the `vtc-host`
    /// template's `URL` var.
    pub(crate) base_url: String,
    pub(crate) vta_did: String,
    pub(crate) context: String,
}

/// A fully-resolved setup plan: every operator decision gathered, no
/// further prompts needed. Both front-ends produce one of these — the
/// interactive [`collect_interactive`] (TTY prompts + the live VTA
/// round-trips) and the non-interactive `from_toml::parse_from_toml`
/// (`setup --from <toml>`) — and both feed it to the same [`apply`]
/// effect driver. That shared seam is what keeps the two paths from
/// drifting.
pub(crate) struct WizardPlan {
    pub(crate) config_path: PathBuf,
    pub(crate) inputs: WizardInputs,
    pub(crate) webvh: WebvhTarget,
    pub(crate) secrets: SecretsConfig,
    pub(crate) messaging: Option<MessagingConfig>,
    /// The ephemeral `did:key` that authenticates the provision-
    /// integration round-trip. Its DID must already be ACL-authorised
    /// at the VTA: the interactive path generates it and pauses for the
    /// operator to grant the ACL; the `--from` path loads a key the
    /// operator persisted + granted out of band (the two-phase bridge
    /// `EphemeralSetupKey::persist_to`/`load_from` exists for).
    pub(crate) setup_key: EphemeralSetupKey,
}

/// The facts [`apply`] produces once the VTC is provisioned and all
/// on-disk state is written. The caller decides how to present them
/// (the interactive wizard prints a rich summary with a one-shot
/// admin-key reveal; `setup --from` prints a terse, scrape-friendly
/// block).
pub(crate) struct SetupOutcome {
    pub(crate) vtc_did: String,
    pub(crate) admin_did: String,
    pub(crate) config_path: PathBuf,
    pub(crate) data_dir: PathBuf,
    pub(crate) install_url: String,
    pub(crate) claim_code: String,
    /// Pretty-printed JSON of the long-term admin key, when the VTA
    /// returned one. Sensitive — the interactive path gates its display
    /// behind a confirm; the non-interactive path never prints it.
    pub(crate) admin_key_json: Option<String>,
}

/// Where the VTC's `did:webvh` is published, as chosen by the operator
/// after the ACL grant (when the ephemeral key can authenticate to the
/// VTA and enumerate its did-hosting catalogue). All three fields are
/// optional; a fully-`None` target reproduces the serverless default
/// (self-hosted at the VTC base URL, server-assigned path).
#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebvhTarget {
    /// Registered did-hosting server id (the `WEBVH_SERVER` var).
    /// `None` → serverless: the VTC publishes its own `did.jsonl` at
    /// the base URL.
    #[serde(default)]
    pub(crate) server_id: Option<String>,
    /// Tenant domain on a multi-domain hosting server (the
    /// `WEBVH_DOMAIN` var). `None` → the server resolves its default.
    #[serde(default)]
    pub(crate) domain: Option<String>,
    /// Path component of `did:webvh:<scid>:<host>:<path>` (the
    /// `WEBVH_PATH` var). `None` → the server auto-assigns.
    #[serde(default)]
    pub(crate) path: Option<String>,
}

fn prompt_config_path(initial: Option<PathBuf>) -> Result<PathBuf, AppError> {
    let default = initial
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| std::env::var("VTC_CONFIG_PATH").ok())
        .unwrap_or_else(|| "config.toml".into());
    let path: String = Input::new()
        .with_prompt("Config file path")
        .default(default)
        .interact_text()
        .map_err(prompt_err)?;
    Ok(PathBuf::from(path))
}

pub(crate) fn refuse_if_already_set_up(config_path: &std::path::Path) -> Result<(), AppError> {
    if !config_path.exists() {
        return Ok(());
    }
    // Try parsing — if vtc_did is set, the VTC is already configured.
    if let Ok(existing) = AppConfig::load(Some(config_path.to_path_buf()))
        && existing.vtc_did.is_some()
    {
        return Err(AppError::Config(format!(
            "VTC already configured at {} (vtc_did = {:?}). \
             Move the config aside or pass `--config <other-path>` to set up a fresh community.",
            config_path.display(),
            existing.vtc_did
        )));
    }
    Ok(())
}

fn prompt_inputs() -> Result<WizardInputs, AppError> {
    println!();
    println!("Provisioning a fresh VTC requires the daemon's base URL, the VTA's DID,");
    println!("and the context name. The VTA's transport endpoints are resolved from");
    println!("its DID document — no separate VTA URL is needed.");
    println!();
    println!("The VTC daemon serves three surfaces — API, admin UX, public website —");
    println!("all mounted under one base URL by default:");
    println!();
    println!("  Base URL      https://vtc.example.com");
    println!("    API         https://vtc.example.com/v1/...");
    println!("    Admin UX    https://vtc.example.com/admin");
    println!("    Website     https://vtc.example.com/");
    println!();
    println!("If you want separate subdomains per surface (e.g. api.vtc.example.com,");
    println!("admin.vtc.example.com), keep the base URL as the public-website host");
    println!("here and add [routing.api].host / [routing.admin_ui].host to config.toml");
    println!("after setup. See docs/03-vtc/website-and-admin.md.");
    println!();
    let base_url: String = Input::new()
        .with_prompt("VTC base URL (no trailing slash, no /v1, e.g. https://vtc.example.com)")
        .interact_text()
        .map_err(prompt_err)?;
    let base_url = base_url.trim_end_matches('/').to_string();
    let vta_did: String = Input::new()
        .with_prompt("VTA DID (e.g. did:webvh:vta.example.com:abc)")
        .interact_text()
        .map_err(prompt_err)?;
    let context: String = Input::new()
        .with_prompt("Context name at the VTA for this community")
        .default("default".into())
        .interact_text()
        .map_err(prompt_err)?;

    // The VTC DID's hosting target (did-hosting server, domain, path) is
    // collected later, in `select_webvh_target`, after the ACL grant — at
    // that point the ephemeral key can authenticate to the VTA and
    // enumerate the available servers/domains so the operator picks from a
    // live list rather than typing blind.

    Ok(WizardInputs {
        base_url,
        vta_did,
        context,
    })
}

/// Ask the operator which mediator the VTC should route DIDComm traffic
/// through. Three paths:
///
/// 1. Use the same mediator the VTA advertises in its DID document.
///    This is the dominant choice for single-operator deployments —
///    one mediator serves both the VTA and its VTCs.
/// 2. Specify a different mediator DID (e.g. the operator runs a
///    per-VTC mediator, or the VTA's mediator is overloaded).
/// 3. Skip messaging entirely. The daemon logs a one-line warning at
///    startup ("messaging not configured — inbound message handling
///    disabled") but otherwise stays healthy on the REST surface.
///
/// `vta_mediator` is the mediator DID resolved from the VTA's DID
/// document (the caller resolves the VTA once, up front; see
/// [`run_setup_wizard`]). `None` means the document advertised no
/// mediator (or didn't resolve) — the wizard then falls through to
/// options 2 + 3, letting the operator supply one or skip messaging.
fn prompt_messaging(vta_mediator: Option<String>) -> Result<Option<MessagingConfig>, AppError> {
    use dialoguer::Select;

    println!();
    let mut labels: Vec<String> = Vec::new();
    let mut tags: Vec<&str> = Vec::new();
    if let Some(med) = vta_mediator.as_deref() {
        labels.push(format!("Use the VTA's mediator ({med})"));
        tags.push("vta-mediator");
    } else {
        println!("  Note: the VTA's DID document does not advertise a DIDComm mediator;");
        println!("        you'll need to supply one yourself or skip messaging.");
        println!();
    }
    labels.push("Specify a different mediator DID".to_string());
    tags.push("custom");
    labels.push("Skip messaging (DIDComm disabled)".to_string());
    tags.push("skip");

    let idx = Select::new()
        .with_prompt("DIDComm messaging")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(prompt_err)?;

    let mediator_did = match tags[idx] {
        "vta-mediator" => vta_mediator.expect("present when tag was inserted"),
        "custom" => Input::new()
            .with_prompt("Mediator DID (must start with `did:`)")
            .validate_with(|input: &String| -> Result<(), String> {
                if input.starts_with("did:") {
                    Ok(())
                } else {
                    Err("DID must start with 'did:' (e.g. did:webvh:... or did:key:...)".into())
                }
            })
            .interact_text()
            .map_err(prompt_err)?,
        "skip" => return Ok(None),
        other => {
            return Err(AppError::Internal(format!(
                "internal: unknown messaging tag '{other}'"
            )));
        }
    };

    Ok(Some(MessagingConfig {
        mediator_url: String::new(),
        mediator_did,
        mediator_host: None,
        setup_acl: false,
        drain_inbox_on_start: false,
    }))
}

// ---------------------------------------------------------------------------
// did:webvh hosting-target selection
// ---------------------------------------------------------------------------

/// Collect the VTC DID's hosting target — did-hosting server, tenant
/// domain, and path — after the ACL grant.
///
/// The freshly-authorized ephemeral key connects to the VTA (REST when
/// advertised, otherwise DIDComm) and enumerates the registered
/// did-hosting servers + their tenant domains so the operator picks from a
/// live list. If the VTA didn't resolve or the connection fails, the
/// picker degrades gracefully: only the path is collected and the VTA's
/// own 0-or-1-server auto-selection applies.
async fn select_webvh_target(
    resolved: Option<&ResolvedVta>,
    setup_key: &EphemeralSetupKey,
) -> Result<WebvhTarget, AppError> {
    println!();
    println!("\x1b[1mDID hosting\x1b[0m");
    println!("  Your community is identified by a `did:webvh` DID of the form:");
    println!();
    println!("    did:webvh:<scid>:<host>:<path>");
    println!();
    println!("  <scid> is a self-certifying id the VTA generates for you. <host> is the");
    println!("  did-hosting server's domain and <path> is an optional label under it.");
    println!("  This is the DID every member, credential, and trust-registry entry will");
    println!("  reference — choose its host and path deliberately.");
    println!();
    println!("  Serverless instead drops the <path>: the VTC self-hosts its own");
    println!("  did.jsonl at <host>/.well-known/did.jsonl, served by this daemon — no");
    println!("  external did-hosting server required.");
    println!();

    // Connect over whichever transport the VTA advertises so we can offer
    // live server/domain pickers. Any failure here is non-fatal: we fall
    // back to the path-only prompt and the VTA's own server auto-pick.
    let client = match resolved {
        Some(r) => match connect_setup_client(r, setup_key).await {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(error = %e, "could not connect to the VTA to list did-hosting servers");
                println!(
                    "  Could not reach the VTA to list did-hosting servers ({e}); the VTA \
                     will auto-select one (or self-host)."
                );
                None
            }
        },
        None => {
            println!(
                "  The VTA DID didn't resolve, so an interactive server/domain picker isn't \
                 available; the VTA will auto-select a server (or self-host)."
            );
            None
        }
    };

    let Some(client) = client else {
        // No live catalogue — leave server selection to the VTA (it
        // auto-picks a registered did-hosting server, or self-hosts).
        // We don't prompt for a path: it's only meaningful once a
        // hosting server is in play, and a serverless DID ignores it
        // entirely (it always resolves at `<host>/.well-known/`), so a
        // prompt here would have unpredictable effect.
        return Ok(WebvhTarget::default());
    };

    let server_id = prompt_webvh_server(&client).await?;
    let (domain, path) = match server_id.as_deref() {
        // A hosting server is selected: the `<path>` is a real label
        // under that server, so offer it (and the tenant-domain picker).
        Some(sid) => {
            let domain = prompt_webvh_domain(&client, sid).await?;
            let path = prompt_webvh_path(sid)?;
            (domain, path)
        }
        // Serverless: the VTC self-hosts its `did.jsonl`, and the DID
        // `did:webvh:<scid>:<host>` always resolves at
        // `<host>/.well-known/did.jsonl`. There's no meaningful path to
        // pick, so we don't ask.
        None => (None, None),
    };

    Ok(WebvhTarget {
        server_id,
        domain,
        path,
    })
}

/// Connect the ephemeral setup key to the VTA and return a client capable
/// of reading the did-hosting catalogue.
///
/// Prefers REST — the lightweight challenge-response flow (`auth_light`)
/// reads the catalogue without spinning up a mediator session. Falls back
/// to a DIDComm session against a DIDComm-only VTA so the picker still
/// works there. The choice of listing transport is independent of the
/// transport the later provision round-trip uses.
async fn connect_setup_client(
    resolved: &ResolvedVta,
    setup_key: &EphemeralSetupKey,
) -> Result<VtaClient, AppError> {
    if let Some(rest_url) = resolved.rest_url.as_deref() {
        let http = reqwest::Client::new();
        let auth = vta_sdk::auth_light::challenge_response_light(
            &http,
            rest_url,
            &setup_key.did,
            setup_key.private_key_multibase(),
            &resolved.vta_did,
        )
        .await
        .map_err(|e| AppError::Internal(format!("VTA REST authentication failed: {e}")))?;
        let client = VtaClient::new(rest_url);
        client.set_token_async(auth.access_token).await;
        return Ok(client);
    }

    if let Some(mediator_did) = resolved.mediator_did.as_deref() {
        return VtaClient::connect_didcomm(
            &setup_key.did,
            setup_key.private_key_multibase(),
            &resolved.vta_did,
            mediator_did,
            resolved.rest_url.clone(),
        )
        .await
        .map_err(|e| AppError::Internal(format!("VTA DIDComm connection failed: {e}")));
    }

    Err(AppError::Internal(
        "VTA advertises neither a REST nor a DIDComm transport".into(),
    ))
}

/// List the VTA's registered did-hosting servers and let the operator
/// pick one — or choose serverless (self-hosted at the base URL). An
/// empty catalogue or a listing error falls back to serverless (`None`).
async fn prompt_webvh_server(client: &VtaClient) -> Result<Option<String>, AppError> {
    use dialoguer::Select;

    let servers = match client.list_webvh_servers().await {
        Ok(body) => body.servers,
        Err(e) => {
            println!("  Could not list did-hosting servers ({e}); defaulting to serverless.");
            return Ok(None);
        }
    };

    if servers.is_empty() {
        println!("  No did-hosting servers are registered with this VTA — the VTC will");
        println!("  self-host its `did.jsonl` at the base URL (serverless).");
        return Ok(None);
    }

    let mut labels: Vec<String> = servers
        .iter()
        .map(|s| match s.label.as_deref() {
            Some(label) if !label.is_empty() => format!("{} — {label}  ({})", s.id, s.did),
            _ => format!("{}  ({})", s.id, s.did),
        })
        .collect();
    labels.push("Serverless — self-host did.jsonl at the VTC base URL".to_string());

    let idx = Select::new()
        .with_prompt("Where should the VTC DID be published?")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(prompt_err)?;

    if idx == servers.len() {
        Ok(None)
    } else {
        Ok(Some(servers[idx].id.clone()))
    }
}

/// On a multi-domain hosting server, let the operator pick the tenant
/// domain the DID is allocated under. A 0-or-1-domain server (or a
/// listing error) returns `None` so the server resolves its own default.
/// Mirrors `pnm did-mgmt`'s `prompt_domain_if_interactive`.
async fn prompt_webvh_domain(
    client: &VtaClient,
    server_id: &str,
) -> Result<Option<String>, AppError> {
    use dialoguer::Select;

    let domains = match client.list_webvh_server_domains(server_id).await {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, server_id, "could not list hosting domains");
            println!(
                "  Could not list hosting domains on `{server_id}` ({e}); using the \
                 server's default domain."
            );
            return Ok(None);
        }
    };

    // 0 or 1 domain → nothing meaningful to choose; let the server resolve
    // its default.
    if domains.domains.len() < 2 {
        return Ok(None);
    }

    let mut labels: Vec<String> = domains
        .domains
        .iter()
        .map(|d| {
            let default = if d.default_domain { " (default)" } else { "" };
            let disabled = if d.status == "disabled" {
                " [disabled]"
            } else {
                ""
            };
            match d.label.as_deref() {
                Some(l) if !l.is_empty() => format!("{}{default}{disabled} — {l}", d.name),
                _ => format!("{}{default}{disabled}", d.name),
            }
        })
        .collect();
    labels.push("Use the server's default domain".to_string());

    // Default the cursor to the server's flagged default domain, falling
    // back to the "use default" sentinel when none is flagged.
    let default_idx = domains
        .domains
        .iter()
        .position(|d| d.default_domain)
        .unwrap_or(domains.domains.len());

    let idx = Select::new()
        .with_prompt(format!("Tenant domain on `{server_id}`"))
        .items(&labels)
        .default(default_idx)
        .interact()
        .map_err(prompt_err)?;

    if idx == domains.domains.len() {
        Ok(None)
    } else {
        Ok(Some(domains.domains[idx].name.clone()))
    }
}

/// Prompt for the optional `<path>` label of the VTC DID under the
/// selected hosting server. Blank input → `None` (the server assigns
/// one). Only called in hosted mode: serverless self-hosting always
/// resolves at `<host>/.well-known/did.jsonl`, so it has no path to pick.
fn prompt_webvh_path(server_id: &str) -> Result<Option<String>, AppError> {
    println!();
    println!("  Optional path label under the hosting server `{server_id}`. It becomes the");
    println!("  trailing `<path>` of the VTC DID — e.g. `acme` yields a DID ending");
    println!("  `:acme`. Operators with a naming convention (community slug, env)");
    println!("  can pin it; leave blank to let the server assign one.");
    let raw: String = Input::new()
        .with_prompt("WebVH path (blank → server-assigned)")
        .default(String::new())
        .allow_empty(true)
        .interact_text()
        .map_err(prompt_err)?;
    let trimmed = raw.trim();
    Ok(if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    })
}

fn prompt_secrets_config() -> Result<SecretsConfig, AppError> {
    #[cfg_attr(
        not(any(
            feature = "aws-secrets",
            feature = "gcp-secrets",
            feature = "azure-secrets"
        )),
        allow(unused_mut)
    )]
    let mut resolvers = BackendResolvers::empty();
    #[cfg(feature = "aws-secrets")]
    {
        resolvers.aws = Some(Box::new(aws_resolver));
    }
    #[cfg(feature = "gcp-secrets")]
    {
        resolvers.gcp = Some(Box::new(gcp_resolver));
    }
    #[cfg(feature = "azure-secrets")]
    {
        resolvers.azure = Some(Box::new(azure_resolver));
    }
    let choice = configure_secrets(
        &AvailableBackends {
            keyring: cfg!(feature = "keyring"),
            aws: cfg!(feature = "aws-secrets"),
            gcp: cfg!(feature = "gcp-secrets"),
            azure: cfg!(feature = "azure-secrets"),
            k8s: cfg!(feature = "k8s-secrets"),
            inline_config: cfg!(feature = "config-secret"),
            plaintext: true,
        },
        "vtc",
        resolvers,
    )
    .map_err(secrets_prompt_err)?;
    Ok(secrets_choice_to_config(choice))
}

/// AWS Secrets Manager: prompt for region, list existing secrets,
/// let the operator pick one or type a name for a new secret.
///
/// Bridges to async AWS SDK calls via `tokio::task::block_in_place`
/// because `configure_secrets` is sync. Safe under the wizard's
/// multi-thread `#[tokio::main]` runtime; would panic on a
/// current-thread runtime (no test takes this path).
#[cfg(feature = "aws-secrets")]
fn aws_resolver() -> Result<(String, Option<String>), SecretsPromptError> {
    let region: String = dialoguer::Input::new()
        .with_prompt("AWS region (leave empty for SDK default)")
        .allow_empty(true)
        .interact_text()?;
    let region_opt = if region.is_empty() {
        None
    } else {
        Some(region)
    };

    let listing = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(vti_secrets::discovery::list_aws_secrets(
            region_opt.as_deref(),
        ))
    });

    let default_name = "vtc-master-seed";
    let secret_name = match listing {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let pick = dialoguer::Select::new()
                .with_prompt("Select an existing secret or create a new one")
                .items(&items)
                .default(0)
                .interact()?;
            if pick == items.len() - 1 {
                dialoguer::Input::new()
                    .with_prompt("AWS Secrets Manager secret name")
                    .default(default_name.into())
                    .interact_text()?
            } else {
                items.swap_remove(pick)
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found in this region.");
            dialoguer::Input::new()
                .with_prompt("AWS Secrets Manager secret name")
                .default(default_name.into())
                .interact_text()?
        }
        Err(e) => {
            warn!(error = %e, "could not list AWS secrets");
            eprintln!("  Warning: could not list secrets ({e}).");
            dialoguer::Input::new()
                .with_prompt("AWS Secrets Manager secret name")
                .default(default_name.into())
                .interact_text()?
        }
    };

    Ok((secret_name, region_opt))
}

/// GCP Secret Manager: prompt for project, list existing secrets,
/// let the operator pick one or type a name. Same async-from-sync
/// bridging as [`aws_resolver`]; same pagination cap.
#[cfg(feature = "gcp-secrets")]
fn gcp_resolver() -> Result<(String, String), SecretsPromptError> {
    let project: String = dialoguer::Input::new()
        .with_prompt("GCP project ID")
        .interact_text()?;

    let listing = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(vti_secrets::discovery::list_gcp_secrets(&project))
    });

    let default_name = "vtc-master-seed";
    let secret_name = match listing {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let pick = dialoguer::Select::new()
                .with_prompt("Select an existing secret or create a new one")
                .items(&items)
                .default(0)
                .interact()?;
            if pick == items.len() - 1 {
                dialoguer::Input::new()
                    .with_prompt("GCP Secret Manager secret name")
                    .default(default_name.into())
                    .interact_text()?
            } else {
                items.swap_remove(pick)
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found in this project.");
            dialoguer::Input::new()
                .with_prompt("GCP Secret Manager secret name")
                .default(default_name.into())
                .interact_text()?
        }
        Err(e) => {
            warn!(error = %e, "could not list GCP secrets");
            eprintln!("  Warning: could not list secrets ({e}).");
            dialoguer::Input::new()
                .with_prompt("GCP Secret Manager secret name")
                .default(default_name.into())
                .interact_text()?
        }
    };

    Ok((project, secret_name))
}

/// Azure Key Vault: prompt for vault URL, list existing secrets,
/// let the operator pick one or type a name. Credentials come from
/// `DeveloperToolsCredential` (Azure CLI / Developer CLI / VS Code),
/// mirroring the runtime credential resolution used by
/// [`crate::keys::seed_store::AzureSecretStore`].
///
/// Note: vta-service's wizard does not currently have an Azure picker
/// (it falls back to a plain input). vtc-service is intentionally
/// ahead — both crates use the same `azure_security_keyvault_secrets`
/// client at runtime, so listing at setup is a strict UX improvement.
#[cfg(feature = "azure-secrets")]
fn azure_resolver() -> Result<(String, String), SecretsPromptError> {
    let vault_url: String = dialoguer::Input::new()
        .with_prompt("Azure Key Vault URL (e.g. https://my-vault.vault.azure.net)")
        .interact_text()?;

    let listing = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(vti_secrets::discovery::list_azure_secrets(&vault_url))
    });

    let default_name = "vtc-master-seed";
    let secret_name = match listing {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let pick = dialoguer::Select::new()
                .with_prompt("Select an existing secret or create a new one")
                .items(&items)
                .default(0)
                .interact()?;
            if pick == items.len() - 1 {
                dialoguer::Input::new()
                    .with_prompt("Azure Key Vault secret name")
                    .default(default_name.into())
                    .interact_text()?
            } else {
                items.swap_remove(pick)
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found in this vault.");
            dialoguer::Input::new()
                .with_prompt("Azure Key Vault secret name")
                .default(default_name.into())
                .interact_text()?
        }
        Err(e) => {
            warn!(error = %e, "could not list Azure secrets");
            eprintln!("  Warning: could not list secrets ({e}).");
            dialoguer::Input::new()
                .with_prompt("Azure Key Vault secret name")
                .default(default_name.into())
                .interact_text()?
        }
    };

    Ok((vault_url, secret_name))
}

fn secrets_choice_to_config(choice: SecretsBackendChoice) -> SecretsConfig {
    let mut config = SecretsConfig::default();
    match choice {
        SecretsBackendChoice::Keyring { service } => config.keyring_service = service,
        SecretsBackendChoice::Aws {
            secret_name,
            region,
        } => {
            config.aws_secret_name = Some(secret_name);
            config.aws_region = region;
        }
        SecretsBackendChoice::Gcp {
            project,
            secret_name,
        } => {
            config.gcp_project = Some(project);
            config.gcp_secret_name = Some(secret_name);
        }
        SecretsBackendChoice::Azure {
            vault_url,
            secret_name,
        } => {
            config.azure_vault_url = Some(vault_url);
            config.azure_secret_name = Some(secret_name);
        }
        SecretsBackendChoice::Kubernetes {
            secret_name,
            namespace,
            secret_key,
        } => {
            config.k8s_secret_name = Some(secret_name);
            config.k8s_namespace = namespace;
            // A blank key from the prompt means "use the default" — keep the
            // `SecretsConfig::default()` value rather than overwriting it with
            // an empty string.
            if !secret_key.is_empty() {
                config.k8s_secret_key = secret_key;
            }
        }
        SecretsBackendChoice::InlineConfig => {
            // The bundle bytes go into `secret` via the
            // `inline_secret:` wrapper on first `set`.
            config.secret = Some(String::new());
        }
        SecretsBackendChoice::Plaintext => {
            // No fields to populate — the plaintext store reads
            // from `store.data_dir`.
        }
    }
    config
}

// ---------------------------------------------------------------------------
// Provision-integration drive
// ---------------------------------------------------------------------------

async fn run_provision_quietly(
    inputs: &WizardInputs,
    webvh: &WebvhTarget,
    setup_key: &EphemeralSetupKey,
) -> Result<ProvisionResult, AppError> {
    let mut vars = BTreeMap::new();
    // The template appends `STATUS_LIST_PATH` (default `/v1/status-lists`)
    // to `URL`, so `URL` must be the host base — passing the API base
    // with `/v1` here renders a double-`/v1` endpoint in the DID doc.
    vars.insert(
        "URL".to_string(),
        JsonValue::String(inputs.base_url.clone()),
    );
    // `WEBVH_SERVER` / `WEBVH_DOMAIN` / `WEBVH_PATH` are sideband hints
    // consumed VTA-side (see `provision_integration::webvh`) before the
    // template renders — they pin where the VTC's `did.jsonl` is published
    // and the `did:webvh:<scid>:<host>:<path>` shape. All come from the
    // operator's choices in `select_webvh_target`. They ride in the ask's
    // template vars and `drive_provision` forwards them verbatim on both
    // transports.
    if let Some(server) = webvh.server_id.as_deref() {
        vars.insert(
            "WEBVH_SERVER".to_string(),
            JsonValue::String(server.to_string()),
        );
    }
    if let Some(domain) = webvh.domain.as_deref() {
        vars.insert(
            "WEBVH_DOMAIN".to_string(),
            JsonValue::String(domain.to_string()),
        );
    }
    if let Some(path) = webvh.path.as_deref() {
        vars.insert(
            "WEBVH_PATH".to_string(),
            JsonValue::String(path.to_string()),
        );
    }
    let ask = ProvisionAsk::for_template("vtc-host", vars, inputs.context.clone())
        .with_label("vtc-host integration");

    let reply = drive_provision(inputs.vta_did.clone(), setup_key, ask).await?;

    match reply {
        VtaReply::Full(result) => Ok(*result),
        VtaReply::AdminOnly(_) => Err(AppError::Internal(
            "VTA returned an admin-only reply but the vtc-host template requires a \
             FullSetup reply"
                .into(),
        )),
    }
}

/// Drive the provision-integration workflow to completion, honouring the
/// operator's explicit webvh choice already baked into `ask`.
///
/// This replicates `run_provision`'s orchestration but deliberately
/// bypasses its client-side webvh-server auto-pick. On the DIDComm
/// preflight we hand `run_provision_flight` `None`/`None` so the
/// `WEBVH_SERVER` / `WEBVH_PATH` / `WEBVH_DOMAIN` vars already present in
/// `ask` flow through verbatim. That makes an explicit server choice — or
/// an explicit *serverless* choice — work on both transports, including
/// against a VTA with 2+ registered hosting servers, where `run_provision`
/// refuses to guess and bails. The REST path needs no special handling:
/// its one-shot attempt already forwards the ask's vars unchanged.
///
/// Transport is auto-selected (DIDComm-first when both are advertised),
/// matching `run_provision`'s default. Events are consumed for control
/// flow only — the wizard keeps its own UX terse.
async fn drive_provision(
    vta_did: String,
    setup_key: &EphemeralSetupKey,
    ask: ProvisionAsk,
) -> Result<VtaReply, AppError> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(run_connection_test(
        VtaIntent::FullSetup,
        vta_did.clone(),
        setup_key.did.clone(),
        setup_key.private_key_multibase().to_string(),
        ask.clone(),
        None,
        tx,
    ));

    while let Some(ev) = rx.recv().await {
        match ev {
            // REST one-shot path completes here.
            VtaEvent::Connected { reply, .. } => return Ok(reply),
            VtaEvent::Failed(msg) => return Err(provision_failed(&msg)),
            // DIDComm FullSetup: preflight done — drive the flight with the
            // explicit choice baked into `ask` (None/None → no auto-pick).
            VtaEvent::PreflightDone {
                rest_url,
                mediator_did,
                ..
            } => {
                let (ftx, mut frx) = mpsc::unbounded_channel();
                tokio::spawn(run_provision_flight(
                    vta_did.clone(),
                    setup_key.did.clone(),
                    setup_key.private_key_multibase().to_string(),
                    mediator_did,
                    rest_url,
                    ask.clone(),
                    None,
                    None,
                    Arc::new(VtcHostMessages),
                    ftx,
                ));
                while let Some(fev) = frx.recv().await {
                    match fev {
                        VtaEvent::Connected { reply, .. } => return Ok(reply),
                        VtaEvent::Failed(msg) => return Err(provision_failed(&msg)),
                        _ => {}
                    }
                }
                return Err(provision_failed(
                    "provisioning ended without a terminal event",
                ));
            }
            _ => {}
        }
    }

    Err(provision_failed(
        "provisioning ended without a terminal event",
    ))
}

/// Wrap a terminal failure string with the actionable hint the wizard has
/// always printed — the most common cause is a missing or expired ACL
/// grant on the setup DID.
fn provision_failed(msg: &str) -> AppError {
    AppError::Internal(format!(
        "VTA provisioning failed: {msg}. Double-check the VTA URL/DID and that the ephemeral \
         DID was authorized via `pnm contexts create` (or `pnm acl create` if the context \
         already exists)."
    ))
}

/// `OperatorMessages` impl for the vtc-host integration kind.
///
/// Reused by the phase-1 `--setup-key-out` helper
/// ([`super::run_setup_phase1`]) so the printed grant command matches
/// the one the interactive/DIDComm provision paths reference.
pub(crate) struct VtcHostMessages;

impl OperatorMessages for VtcHostMessages {
    fn integration_label(&self) -> &str {
        "VTC"
    }
    fn integration_label_lower(&self) -> &str {
        "vtc"
    }
    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        // Matches the canonical `MediatorMessages` /
        // `WebvhServerMessages` shape: create the context AND grant
        // the admin ACL atomically. The previous `pnm acl create`
        // form failed against a fresh VTA where the target context
        // hadn't been created yet — the VTA returned "context not
        // found" and the wizard hung.
        format!(
            "pnm contexts create --id {context_id} --name \"VTC\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h"
        )
    }
}

// ---------------------------------------------------------------------------
// Side outputs
// ---------------------------------------------------------------------------

fn write_did_log(data_dir: &std::path::Path, scid: &str, content: &str) -> Result<(), AppError> {
    let did_dir = data_dir.join("did");
    std::fs::create_dir_all(&did_dir).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("create did dir {}: {e}", did_dir.display()),
        ))
    })?;
    let path = did_dir.join(format!("{scid}.jsonl"));
    std::fs::write(&path, content).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("write did log {}: {e}", path.display()),
        ))
    })?;
    Ok(())
}

fn build_app_config(
    config_path: PathBuf,
    vtc_did: String,
    vta_did: String,
    public_url: String,
    data_dir: PathBuf,
    secrets: SecretsConfig,
    messaging: Option<MessagingConfig>,
) -> Result<AppConfig, AppError> {
    // Build the minimal config bones via a TOML `Table` (not
    // `format!`). The earlier `format!(r#"vtc_did = "{vtc_did}""#)`
    // round-trip would have produced malformed TOML if any of
    // `vtc_did` / `vta_did` / `public_url` / `data_dir` happened to
    // contain a `"` or `\` — `toml::Value::String` handles escaping
    // for us. `data_dir` is the only required field on `AppConfig`
    // (every other top-level setting has a `#[serde(default)]`),
    // so we seed `store.data_dir` and let serde fill the rest.
    use toml::Value;
    let mut store_table = toml::map::Map::new();
    store_table.insert(
        "data_dir".into(),
        Value::String(data_dir.to_string_lossy().into_owned()),
    );
    let mut root = toml::map::Map::new();
    root.insert("store".into(), Value::Table(store_table));
    let mut config: AppConfig = Value::Table(root)
        .try_into()
        .map_err(|e| AppError::Config(format!("config: {e}")))?;
    // The fields that are operator-controlled strings — fill from
    // arguments rather than the TOML literal so the values can't
    // affect parsing.
    config.vtc_did = Some(vtc_did);
    config.vta_did = Some(vta_did);
    config.public_url = Some(public_url);
    config.secrets = secrets;
    config.messaging = messaging;
    config.auth = AuthConfig {
        jwt_signing_key: Some(generate_jwt_signing_key()),
        ..AuthConfig::default()
    };
    config.log = LogConfig::default();
    config.config_path = config_path;
    Ok(config)
}

fn generate_jwt_signing_key() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    B64.encode(bytes)
}

fn write_config_toml(path: &std::path::Path, config: &AppConfig) -> Result<(), AppError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            AppError::Io(std::io::Error::new(
                e.kind(),
                format!("create config dir {}: {e}", parent.display()),
            ))
        })?;
    }
    let serialised = toml::to_string_pretty(config)
        .map_err(|e| AppError::Config(format!("config serialise: {e}")))?;
    std::fs::write(path, serialised).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("write config {}: {e}", path.display()),
        ))
    })?;
    // config.toml carries `auth.jwt_signing_key` and, under the config-secret
    // backend, the hex `VtcKeyBundle` — owner-only, never world-readable.
    crate::secure_file::restrict_file_to_owner(path).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("harden config perms {}: {e}", path.display()),
        ))
    })?;
    Ok(())
}

fn open_keyspaces(config: &AppConfig) -> Result<(), AppError> {
    let store = Store::open(&StoreConfig {
        data_dir: config.store.data_dir.clone(),
    })?;
    // Pre-create *every* keyspace the daemon opens at boot, not a subset
    // (this used to open 8 of 21), so the first `vtc start` doesn't pay the
    // partition-creation cost. Iterating `keyspaces::ALL` keeps it in lockstep
    // with `server::run`.
    for ks in keyspaces::ALL {
        let _ = store.keyspace(ks)?;
    }
    Ok(())
}

async fn mint_initial_install_token(
    config: &AppConfig,
    bundle: &VtcKeyBundle,
    admin_did: &str,
    base_url: &str,
) -> Result<(String, String), AppError> {
    let ed25519 = bundle.ed25519_private_bytes()?;
    let signer = InstallTokenSigner::from_master_seed(&*ed25519)?;
    let minted = mint_install_token(
        &signer,
        &bundle.integration_did,
        admin_did,
        INSTALL_TOKEN_DEFAULT_TTL_SECS,
    )?;
    let claim_code = crate::install::claim_secret::generate();
    let claim_code_hash = crate::install::claim_secret::hash(&claim_code)?;

    // Open the install keyspace to record the token. Open + close
    // in this short scope; the daemon opens its own at boot.
    let store = Store::open(&StoreConfig {
        data_dir: config.store.data_dir.clone(),
    })?;
    let install_ks = store.keyspace(keyspaces::INSTALL)?;
    let install_store = InstallTokenStore::new(install_ks);
    let exp = Utc::now() + ChronoDuration::seconds(INSTALL_TOKEN_DEFAULT_TTL_SECS as i64);
    install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            exp,
            Some(claim_code_hash),
            Some(admin_did.to_string()),
        )
        .await?;

    // `/admin/install` so the embedded admin SPA picks the request
    // up and runs the install-claim ceremony in-browser. The bare
    // `/install` path would hit the website fallback, which has no
    // install page. See `docs/03-vtc/getting-started.md` §"Step 3".
    let install_url = format!(
        "{}/admin/install?token={}",
        base_url.trim_end_matches('/'),
        minted.jwt
    );
    Ok((install_url, claim_code))
}

// ---------------------------------------------------------------------------
// UX helpers
// ---------------------------------------------------------------------------

fn intro_banner() {
    println!();
    println!("\x1b[1;36m`vtc setup` — provision a fresh Verifiable Trust Community.\x1b[0m");
    println!();
    println!(
        "This wizard provisions the VTC's DID + keys against a running VTA, then writes the\n\
         daemon's config and the one-shot URL you'll use to claim your admin passkey."
    );
    println!();
}

fn print_acl_step(inputs: &WizardInputs, setup_key: &EphemeralSetupKey) {
    println!();
    println!("\x1b[1;33m── Operator action required ──\x1b[0m");
    println!();
    println!("Authorize this ephemeral DID at the VTA before continuing:");
    println!();
    println!("  DID:      {}", setup_key.did);
    println!("  Context:  {}", inputs.context);
    println!();
    println!(
        "Run on a machine with PNM admin access to the VTA ({}):",
        inputs.vta_did
    );
    println!();
    println!(
        "  {}",
        VtcHostMessages.pnm_admin_command_hint(&inputs.context, &setup_key.did)
    );
    println!();
    println!("  If the context already exists, grant admin access to the ephemeral DID instead:");
    println!();
    println!(
        "  pnm acl create --did {} \\\n    --role admin --contexts {} --expires 1h",
        setup_key.did, inputs.context,
    );
    println!();
}

fn default_data_dir_for(config_path: &std::path::Path) -> PathBuf {
    config_path
        .parent()
        .map(|p| p.join("data"))
        .unwrap_or_else(|| PathBuf::from("data"))
}

/// Derive the on-disk log label for the VTC's own `did:webvh` — the
/// final colon-separated component (for a serverless
/// `did:webvh:<scid>:<host>` that's the host). This is purely a
/// storage-key derivation: the daemon's `GET /.well-known/did.jsonl`
/// route (`routes::did_log`) reads the log back under the *same*
/// derivation, so the two must stay in lockstep. Not an SCID — the
/// SCID is the first label, and nothing here needs it.
fn did_log_label_or_err(did: &str) -> Result<String, AppError> {
    did.strip_prefix("did:webvh:")
        .and_then(|suffix| suffix.split(':').next_back())
        .map(str::to_string)
        .ok_or_else(|| AppError::Internal(format!("VTA returned non-webvh DID: {did}")))
}

fn prompt_err(e: dialoguer::Error) -> AppError {
    AppError::Internal(format!("interactive prompt failed: {e}"))
}

fn secrets_prompt_err(e: SecretsPromptError) -> AppError {
    match e {
        SecretsPromptError::Dialoguer(d) => prompt_err(d),
        other => {
            warn!(error = %other, "secrets prompt failed");
            AppError::Internal(format!("secrets prompt: {other}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_log_label_is_the_final_component() {
        // Real did:webvh is `did:webvh:<scid>:<host>` — the wizard's
        // log label is the final component, i.e. the host. (The serve
        // route reads the file back under this same label.)
        let label = did_log_label_or_err("did:webvh:abc123:vtc.example.com").unwrap();
        assert_eq!(label, "vtc.example.com");
    }

    #[test]
    fn did_log_label_refuses_non_webvh() {
        let err = did_log_label_or_err("did:key:z6Mk…").unwrap_err();
        assert!(format!("{err}").contains("non-webvh"));
    }

    #[test]
    fn default_data_dir_sits_alongside_config() {
        let cfg = PathBuf::from("/etc/vtc/config.toml");
        assert_eq!(default_data_dir_for(&cfg), PathBuf::from("/etc/vtc/data"));
    }

    #[test]
    fn default_data_dir_falls_back_when_config_has_no_parent() {
        let cfg = PathBuf::from("config.toml");
        // PathBuf::parent() returns Some("") here on most platforms.
        let dir = default_data_dir_for(&cfg);
        assert!(dir.ends_with("data"));
    }

    #[test]
    fn secrets_choice_to_config_routes_keyring_to_keyring_service() {
        let choice = SecretsBackendChoice::Keyring {
            service: "custom-name".into(),
        };
        let config = secrets_choice_to_config(choice);
        assert_eq!(config.keyring_service, "custom-name");
    }

    #[test]
    fn secrets_choice_to_config_routes_aws_to_aws_fields() {
        let choice = SecretsBackendChoice::Aws {
            secret_name: "my-secret".into(),
            region: Some("us-east-1".into()),
        };
        let config = secrets_choice_to_config(choice);
        assert_eq!(config.aws_secret_name.as_deref(), Some("my-secret"));
        assert_eq!(config.aws_region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn vtc_host_messages_use_pnm_contexts_create_command() {
        // Must match the canonical MediatorMessages / WebvhServerMessages
        // shape: one command that creates the context and grants the
        // admin ACL atomically. The previous `pnm acl create` form failed
        // against a fresh VTA where the target context didn't exist yet.
        let msg = VtcHostMessages.pnm_admin_command_hint("ctx-x", "did:key:zAbc");
        assert!(
            msg.contains("pnm contexts create"),
            "expected `pnm contexts create` form, got: {msg}"
        );
        assert!(msg.contains("--id ctx-x"));
        assert!(msg.contains("--name \"VTC\""));
        assert!(msg.contains("--admin-did did:key:zAbc"));
        assert!(msg.contains("--admin-expires 1h"));
    }

    #[cfg(unix)]
    #[test]
    fn write_config_toml_produces_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join(format!("vtc-cfg-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg_path = tmp.join("config.toml");

        let config = build_app_config(
            cfg_path.clone(),
            "did:webvh:scid:vtc.example.com".into(),
            "did:webvh:scid:vta.example.com".into(),
            "https://vtc.example.com".into(),
            tmp.join("data"),
            secrets_choice_to_config(SecretsBackendChoice::Keyring {
                service: "vtc".into(),
            }),
            None,
        )
        .unwrap();

        write_config_toml(&cfg_path, &config).unwrap();

        // The serialized config carries `auth.jwt_signing_key` — must not be
        // world-readable.
        let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "config.toml must be 0600, got {mode:o}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
