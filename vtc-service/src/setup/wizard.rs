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
//!    --admin-expires 1h --admin-handoff`). Matches the canonical
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
use vta_sdk::did_templates::{
    DIDCOMM_SERVICE_VAR, TRUST_REGISTRY_SERVICE_VAR, TSP_SERVICE_VAR, didcomm_service,
    referral_service, tsp_service,
};
use vta_sdk::provision_client::{
    EphemeralSetupKey, OperatorMessages, Protocol, ProvisionAsk, ProvisionResultV2, ResolvedVta,
    VtaEvent, VtaIntent, VtaReply, resolve_vta, run_connection_test, run_provision_flight,
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
    INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallTokenSigner, InstallTokenStore,
    mint_passkey_install_token,
};
use crate::keys::seed_store::create_secret_store;
use crate::setup::VtcKeyBundle;

/// Entry point bound to `Commands::Setup` in `main.rs`.
///
/// `single_admin` (`--single-admin`) answers the single-administrator-mode
/// question in advance.
pub async fn run_setup_wizard(
    config_path: Option<PathBuf>,
    single_admin: bool,
) -> Result<(), AppError> {
    intro_banner();
    let plan = collect_interactive(config_path, single_admin).await?;
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
async fn collect_interactive(
    config_path: Option<PathBuf>,
    single_admin: bool,
) -> Result<WizardPlan, AppError> {
    let config_path = prompt_config_path(config_path)?;
    refuse_if_already_set_up(&config_path)?;

    let inputs = prompt_inputs(single_admin)?;

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

    // 2. Mediator choice, then which transports to advertise over it. Both
    //    happen before the mint below, because the answers become service
    //    entries in the document being minted and cannot be added afterwards.
    let messaging = prompt_messaging(resolved.as_ref().and_then(|r| r.mediator_did.clone()))?;
    let transports = match messaging.as_ref() {
        Some(m) => prompt_transports(&m.mediator_did)?,
        // No mediator, nothing to advertise. The document carries REST only.
        None => Vec::new(),
    };
    let provision_transport = prompt_provision_transport(resolved.as_ref())?;

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
    let (identity_method, webvh) = select_webvh_target(resolved.as_ref(), &setup_key).await?;

    // 5. Pick a secrets-store backend. We delay this until after
    //    the ACL pause because the operator may want to interrupt
    //    setup at this point (e.g. realise they typed the VTA URL
    //    wrong); resolving the keyring path before the VTA
    //    round-trip avoids burning a useful slot at the storage
    //    layer.
    let secrets = prompt_secrets_config()?;

    Ok(WizardPlan {
        config_path,
        // The transport choice is gathered at step 2 (it needs the mediator),
        // long after `prompt_inputs` built the rest. Folded in here rather than
        // threaded through every intervening prompt.
        inputs: WizardInputs {
            transports,
            provision_transport,
            identity_method,
            ..inputs
        },
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
    let provision = run_provision_quietly(&inputs, &webvh, messaging.as_ref(), &setup_key).await?;
    persist_provisioned(config_path, inputs, secrets, messaging, provision).await
}

/// Everything [`apply`] does once the VTA has answered: the VTC's DID log (a
/// did:webvh's) or nothing (a did:webs's), `config.toml`, the key bundle, the
/// keyspaces and the install token. Split from the round-trip so a test can
/// hand it what a VTA returns.
pub(crate) async fn persist_provisioned(
    config_path: PathBuf,
    inputs: WizardInputs,
    secrets: SecretsConfig,
    messaging: Option<MessagingConfig>,
    provision: ProvisionResultV2,
) -> Result<SetupOutcome, AppError> {
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
    let bundle = VtcKeyBundle::from_did_key_material_v2(integration_did.clone(), integration_key);

    // 5. Persist the did.jsonl log so the daemon's `GET
    //    /.well-known/did.jsonl` route can serve it after restart.
    //
    //    A did:webs has no log for the VTC to keep: its VTA published the key
    //    event stream (`keri.cesr`) at the did-hosting server, which derives
    //    `did.json` from it, and every later change to it is the VTA's
    //    (`vta/webs/dids/update`). So nothing is written, and the bundle must
    //    carry the stream instead — proof the VTA minted what was asked.
    let data_dir = default_data_dir_for(&config_path);
    check_identity_matches(inputs.identity_method, &integration_did)?;
    match inputs.identity_method {
        IdentityMethod::Webvh => {
            let did_log = provision.webvh_log().ok_or_else(|| {
                AppError::Internal(format!(
                    "the VTA did not return a did.jsonl for the VTC's DID {integration_did}"
                ))
            })?;
            let label = did_log_label_or_err(&integration_did)?;
            write_did_log(&data_dir, &label, did_log)?;
        }
        IdentityMethod::Webs => {
            provision.webs_keri_cesr().ok_or_else(|| {
                AppError::Internal(format!(
                    "the VTA returned no key event stream (keri.cesr) for the VTC's DID \
                     {integration_did}: a VTA older than did:webs provisioning (#2695) \
                     cannot mint a did:webs VTC"
                ))
            })?;
        }
    }

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
    // VTI-APV-022: written only when chosen (`skip_serializing_if`), so a
    // config.toml that does not mention it is a community without it.
    app_config.acl.single_admin_mode = inputs.single_admin_mode;
    app_config.dids.default_did_method = inputs.did_method;
    app_config.dids.scid_also_known_as = inputs.scid_also_known_as;
    // Where the VTC's DID lives at its VTA: what its entry there must cover for the VTA
    // to act as the community (`rooms::vta_access`).
    app_config.vta_context = Some(inputs.context.clone());

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

    // 8b. Hand the long-term admin key over as an owner-only file in the data
    // directory — never on a terminal (#2703). The integration key doesn't
    // contain the admin private key; it comes from the provision result.
    let admin_key_file = provision
        .admin_key()
        .map(|key| write_admin_key_file(&data_dir, key))
        .transpose()?;

    // 9. Mint a one-shot install token. The operator claims the community
    //    with a passkey on the running daemon; the founder is that passkey's
    //    own `did:key`. The admin DID below — the rotated long-term DID the
    //    VTA returned from the bootstrap — is not named by the token: an
    //    operator who wants it to administer the VTC too (CLI access) grants
    //    it with `offline_acl_add_command`, printed in the summary.
    let admin_did = provision.admin_did().to_string();
    if let Some(warning) = single_admin_warning(&inputs) {
        eprintln!("{warning}");
    }
    if inputs.co_admin_did.as_deref() == Some(admin_did.as_str()) {
        return Err(AppError::Config(format!(
            "the second administrator ({admin_did}) is the first one; name a different DID, \
             or leave it out"
        )));
    }
    let (install_url, claim_code) = mint_initial_install_token(
        &app_config,
        &bundle,
        inputs.co_admin_did.as_deref(),
        &inputs.base_url,
    )
    .await?;

    Ok(SetupOutcome {
        vtc_did: integration_did,
        admin_did,
        config_path,
        data_dir,
        install_url,
        claim_code,
        admin_key_file,
        single_admin_mode: inputs.single_admin_mode,
    })
}

/// The warning for single-administrator mode chosen beside a second
/// administrator: allowed, but the mode should be on only where every
/// administrator is the same person (VTI-APV-022 item 2).
pub(crate) fn single_admin_warning(inputs: &WizardInputs) -> Option<String> {
    (inputs.single_admin_mode && inputs.co_admin_did.is_some()).then(|| {
        "warning: single-administrator mode is set, and a second administrator \
         (co_admin_did) is installed too. The mode waives another administrator's consent \
         whether or not other administrators exist, so neither administrator's operations will \
         wait for the other. Keep it only if co_admin_did is another of your own identifiers \
         (VTI-APV-022)."
            .to_string()
    })
}

/// Print the rich, interactive completion summary. The admin private key is
/// never printed, only the owner-only file holding it (#2703).
fn print_setup_summary_interactive(outcome: &SetupOutcome) -> Result<(), AppError> {
    println!();
    println!("\x1b[1;32m✅ VTC setup complete.\x1b[0m");
    println!();
    println!("VTC DID:       {}", outcome.vtc_did);
    println!("Admin DID:     {}", outcome.admin_did);
    println!("Config:        {}", outcome.config_path.display());
    println!("Data dir:      {}", outcome.data_dir.display());
    if outcome.single_admin_mode {
        println!(
            "Single-administrator mode: on ([acl] single_admin_mode in config.toml; \
             VTI-APV-022)"
        );
    }
    println!();
    if let Some(key_file) = outcome.admin_key_file.as_deref() {
        // Only the path: a key printed to a terminal lands in scrollback
        // and any session recording (#2703).
        println!(
            "\x1b[1;33mAdmin key:\x1b[0m     {} (owner-only; needed for CLI access as the admin \
             DID — move it to where that client keeps its keys, then delete this copy)",
            key_file.display()
        );
        println!();
    }
    println!("\x1b[1mInstall URL (one-shot, 15 min TTL):\x1b[0m");
    println!("  {}", outcome.install_url);
    println!();
    println!("\x1b[1mClaim code (required at claim time):\x1b[0m");
    println!("  {}", outcome.claim_code);
    println!();
    println!("Both URL and code are needed to claim the community. The code is shown");
    println!("only once and not persisted — copy it before continuing.");
    println!();
    println!("Next steps:");
    println!("  1. Run `vtc` to start the daemon.");
    println!("  2. Open the install URL in your browser.");
    println!("  3. Enter the claim code when prompted, then register your passkey.");
    println!("     The first administrator is the passkey's own did:key.");
    println!();
    // VTI-11: nothing is in the ACL until the install is claimed. The admin
    // DID above is not the passkey's, so say how to grant it — for CLI access,
    // or instead of the browser claim (docs/03-vtc/bootstrap-runbook.md,
    // Path B).
    println!("The admin DID above is not made an administrator by the install URL.");
    println!("To grant it (CLI access, or instead of a browser), with the daemon stopped:");
    println!("  {}", offline_acl_add_command(outcome));
    println!();
    Ok(())
}

/// Write the long-term admin key the VTA returned to
/// `<data_dir>/keys/admin-key.json` (directory `0700`, file `0600`, created
/// new) and return the path. The file is the [`DidKeyMaterialV2`] JSON the VTA
/// sealed to the setup key.
///
/// This is the hand-over the rest of setup already uses for key material
/// that must outlive the run (`--setup-key-out`, `vtc keys request`): an
/// owner-only file, never a terminal (#2703). An existing `admin-key.json`
/// (a re-run against the same data directory) is never overwritten — it may
/// be the only copy of an earlier admin key — so the new one gets a
/// timestamped name beside it.
///
/// [`DidKeyMaterialV2`]: vta_sdk::sealed_transfer::DidKeyMaterialV2
pub(crate) fn write_admin_key_file(
    data_dir: &std::path::Path,
    key: &vta_sdk::sealed_transfer::DidKeyMaterialV2,
) -> Result<PathBuf, AppError> {
    let io_err = |what: &str, path: &std::path::Path, e: std::io::Error| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("{what} {}: {e}", path.display()),
        ))
    };
    let dir = data_dir.join("keys");
    std::fs::create_dir_all(&dir).map_err(|e| io_err("create key dir", &dir, e))?;
    crate::secure_file::restrict_dir_to_owner(&dir)
        .map_err(|e| io_err("harden key dir perms", &dir, e))?;

    let json = zeroize::Zeroizing::new(
        serde_json::to_vec_pretty(key)
            .map_err(|e| AppError::Internal(format!("serialise admin key: {e}")))?,
    );
    let path = dir.join("admin-key.json");
    match vti_common::secure_file::write_secret_file(&path, &json) {
        Ok(()) => Ok(path),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let path = dir.join(format!(
                "admin-key.{}.json",
                Utc::now().format("%Y%m%dT%H%M%SZ")
            ));
            vti_common::secure_file::write_secret_file(&path, &json)
                .map_err(|e| io_err("write admin key", &path, e))?;
            Ok(path)
        }
        Err(e) => Err(io_err("write admin key", &path, e)),
    }
}

/// The offline command that grants the setup's admin DID without the
/// install claim — the runbook's "Path B".
pub(crate) fn offline_acl_add_command(outcome: &SetupOutcome) -> String {
    format!(
        "vtc --config {} acl add --did {} --role admin --label \"first admin\"",
        outcome.config_path.display(),
        outcome.admin_did
    )
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
    /// DID of the trust registry authoritative for this community, when it
    /// has one. Renders a `TrustRegistry` referral into the VTC's DID
    /// document so a client holding only the community's DID can resolve one
    /// hop to its registry instead of being configured with both.
    ///
    /// Optional: a community with no registry omits it and the service entry
    /// is pruned. The VTC cannot re-sign its own log, so changing it after
    /// mint is a VTA-side `pnm did-mgmt dids edit` — then, for a VTC serving
    /// its own `did.jsonl`, `cnm did-log install` with the extended log.
    pub(crate) registry_did: Option<String>,
    /// Messaging transports to advertise in the community's DID document.
    ///
    /// Empty when the operator skipped messaging — the document then carries
    /// REST only, and nothing can be delivered to this community over a
    /// mediator by any route a DID-driven client would find.
    ///
    /// Changeable after mint the same way as [`Self::registry_did`] — a
    /// VTA-side `dids edit`, then `cnm did-log install` for a self-hosted VTC
    /// — but that is a second, manual step, so setup is the moment to say how
    /// this community can be reached.
    pub(crate) transports: Vec<Transport>,
    /// A second unrestricted admin to install beside the first (VTI-APV-014).
    ///
    /// Making anyone an unrestricted admin needs another unrestricted admin's
    /// consent, and a community installed with one has nobody to give it — it
    /// could only add a second through the offline break-glass. Naming one here
    /// lets the community grant remotely from its first day. The install
    /// bootstrap writes it alongside the first admin; it needs no passkey to
    /// consent, since a decision is a document its DID signs.
    pub(crate) co_admin_did: Option<String>,
    /// Run the community in **single-administrator mode** (VTI-APV-022):
    /// every administrator is one person, so an operation that ordinarily
    /// needs another administrator's consent is authorized by the requester's
    /// passkey gesture bound to it, audited at `Critical`. Host
    /// configuration — written to `config.toml` as `[acl] single_admin_mode =
    /// true`, only when chosen, and never settable online.
    pub(crate) single_admin_mode: bool,
    /// The transport to provision over, or `None` for the runner's automatic
    /// TSP > DIDComm > REST. Automatic moves on only when a transport fails to
    /// connect; a reply lost after the VTA acted on the request is final,
    /// because the setup DID's one-time hand-off is spent by then. Forcing one
    /// up front is the way round a mediator that drops replies (OpenVTC #501).
    /// Not persisted: it only decides how setup reaches the VTA.
    pub(crate) provision_transport: Option<ProvisionTransport>,
    /// How the community's own DID, and those it mints later, are presented:
    /// `webvh` or `scid` (VTI-VTC-004). `None` → the VTA's `[dids]`. Sent with
    /// the `vtc-host` provisioning and written to `[dids]`.
    pub(crate) did_method: Option<vta_sdk::did_scid::DidMethod>,
    /// Whether the community's logs list their did:scid alias. `None` → the
    /// VTA's `[dids]`.
    pub(crate) scid_also_known_as: Option<bool>,
    /// The method of the community's **own** DID: a `did:webvh` (the
    /// default, presented per `did_method`) or a level-1 `did:webs`
    /// (VTI-KEY-001, VTI-KEY-146). Distinct from `did_method`, which also
    /// decides how the DIDs the community mints later are presented, and which
    /// only a did:webvh log has.
    pub(crate) identity_method: IdentityMethod,
}

/// The method of the VTC's own durable DID (VTI-KEY-001).
///
/// A `did:webs` VTC is provisioned from `vtc-host-classical` — `vtc-host`
/// without its post-quantum second signing key, which a level-1 did:webs cannot
/// hold (CONVENTIONS.md 0.2 §9.2) — with `DID_METHOD=webs`, and published by the
/// VTA at a did-hosting server: it has no serverless mode and no `did.jsonl`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum IdentityMethod {
    /// `did:webvh` (or its `did:scid` presentation), from `vtc-host`.
    #[default]
    Webvh,
    /// A level-1 `did:webs`, from `vtc-host-classical`.
    Webs,
}

impl IdentityMethod {
    /// The DID template the VTC's identity is provisioned from.
    pub(crate) fn template(self) -> &'static str {
        match self {
            Self::Webvh => "vtc-host",
            Self::Webs => "vtc-host-classical",
        }
    }
}

/// The transport `vtc setup` provisions over, when the operator forces one.
///
/// Distinct from [`Transport`], which selects what the community *advertises*:
/// this is how setup reaches the *VTA*, and REST is a choice here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProvisionTransport {
    Tsp,
    Didcomm,
    Rest,
}

impl ProvisionTransport {
    /// The runner's `force_transport` vocabulary.
    pub(crate) fn protocol(self) -> Protocol {
        match self {
            ProvisionTransport::Tsp => Protocol::Tsp,
            ProvisionTransport::Didcomm => Protocol::DidComm,
            ProvisionTransport::Rest => Protocol::Rest,
        }
    }

    /// The transports `resolved` advertises, in the runner's preference order.
    fn advertised(resolved: &ResolvedVta) -> Vec<Self> {
        [
            (resolved.tsp_mediator_did.is_some(), ProvisionTransport::Tsp),
            (resolved.mediator_did.is_some(), ProvisionTransport::Didcomm),
            (resolved.rest_url.is_some(), ProvisionTransport::Rest),
        ]
        .into_iter()
        .filter_map(|(on, t)| on.then_some(t))
        .collect()
    }

    fn label(self) -> &'static str {
        match self {
            ProvisionTransport::Tsp => "TSP",
            ProvisionTransport::Didcomm => "DIDComm",
            ProvisionTransport::Rest => "REST",
        }
    }
}

/// Ask which transport to provision over, when the VTA advertises more than
/// one. `None` (automatic) without asking otherwise — including when the DID
/// did not resolve, where the runner reports that itself.
fn prompt_provision_transport(
    resolved: Option<&ResolvedVta>,
) -> Result<Option<ProvisionTransport>, AppError> {
    use dialoguer::Select;

    let advertised = resolved
        .map(ProvisionTransport::advertised)
        .unwrap_or_default();
    if advertised.len() < 2 {
        return Ok(None);
    }
    let order: Vec<&str> = advertised.iter().map(|t| t.label()).collect();
    let mut labels = vec![format!("Automatic ({})", order.join(" → "))];
    labels.extend(advertised.iter().map(|t| format!("{} only", t.label())));

    println!();
    println!("  How should setup reach the VTA?");
    println!("  Automatic tries the next transport only if one fails to connect. A reply");
    println!("  lost after the VTA acted is final — its one-time grant is spent — so pick");
    println!("  a transport here if your mediator is known to drop replies.");
    println!();
    let picked = Select::new()
        .with_prompt("Provisioning transport")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(prompt_err)?;
    Ok(picked.checked_sub(1).map(|i| advertised[i]))
}

/// A messaging transport a community can advertise.
///
/// Both bind the *same* mediator DID — one dual-protocol mediator serves both
/// (`docs/05-design-notes/tsp-enablement.md` §14 Q2) — so this enum selects
/// which service entries are rendered, never which mediator.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Transport {
    /// `TSPTransport`. Listed first: the workspace prefers TSP over DIDComm
    /// over REST, and array order is what encodes that to a resolver.
    Tsp,
    /// `DIDCommMessaging`.
    Didcomm,
}

impl Transport {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Transport::Tsp => "tsp",
            Transport::Didcomm => "didcomm",
        }
    }
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
/// (the interactive wizard prints a rich summary; `setup --from` prints a
/// terse, scrape-friendly block).
pub(crate) struct SetupOutcome {
    pub(crate) vtc_did: String,
    pub(crate) admin_did: String,
    pub(crate) config_path: PathBuf,
    pub(crate) data_dir: PathBuf,
    pub(crate) install_url: String,
    pub(crate) claim_code: String,
    /// The owner-only file holding the long-term admin key, when the VTA
    /// returned one ([`write_admin_key_file`]). Both front-ends print only
    /// this path, never the key (#2703).
    pub(crate) admin_key_file: Option<PathBuf>,
    /// Whether the community was set up in single-administrator mode
    /// (VTI-APV-022).
    pub(crate) single_admin_mode: bool,
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

fn prompt_inputs(single_admin: bool) -> Result<WizardInputs, AppError> {
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

    println!();
    println!("If this community has a trust registry, naming it here publishes a");
    println!("TrustRegistry referral in the VTC's DID document, so a client that");
    println!("holds only this community's DID can resolve one hop to the registry");
    println!("rather than being configured with both DIDs.");
    println!();
    println!("You can change it later: `pnm did-mgmt dids edit` at the VTA, then, if");
    println!("this VTC serves its own DID log, `cnm did-log install`. Leave blank if");
    println!("the community has no registry, or if you don't know it yet.");
    println!();
    let registry_did: String = Input::new()
        .with_prompt("Trust registry DID (blank for none)")
        .allow_empty(true)
        .interact_text()
        .map_err(prompt_err)?;
    let registry_did = normalize_registry_did(&registry_did)?;

    println!();
    println!("Making anyone an unrestricted administrator of this community needs");
    println!("the consent of another unrestricted administrator. With only one, there");
    println!("is nobody to give it: a second could then only be added offline, with");
    println!("the daemon stopped. Name a second administrator's DID here to install");
    println!("both. They need no passkey to approve — an approval is a document their");
    println!("DID signs. Leave blank to install one.");
    println!();
    let co_admin_did: String = Input::new()
        .with_prompt("Second administrator DID (blank for none)")
        .allow_empty(true)
        .interact_text()
        .map_err(prompt_err)?;
    let co_admin_did = normalize_co_admin_did(&co_admin_did)?;

    let single_admin_mode = if single_admin {
        true
    } else {
        println!();
        println!("A community run by one person has nobody to give that consent. In");
        println!("single-administrator mode, your own passkey gesture bound to the");
        println!("operation authorizes it instead — even if you administer from several");
        println!("identifiers, one per device — audited at the highest severity, and");
        println!("shown to every administrator in every session. Turn it on only if every");
        println!("administrator is you. It can be changed only on this host, in");
        println!("config.toml (VTI-APV-022).");
        println!();
        Confirm::new()
            .with_prompt("Run as a single-administrator community?")
            .default(false)
            .interact()
            .map_err(prompt_err)?
    };

    // The VTC DID's hosting target (did-hosting server, domain, path) is
    // collected later, in `select_webvh_target`, after the ACL grant — at
    // that point the ephemeral key can authenticate to the VTA and
    // enumerate the available servers/domains so the operator picks from a
    // live list rather than typing blind.

    Ok(WizardInputs {
        co_admin_did,
        single_admin_mode,
        base_url,
        vta_did,
        context,
        registry_did,
        // Gathered later, once the mediator is known (see `collect_interactive`
        // step 2) — there is nothing to advertise before then.
        transports: Vec::new(),
        provision_transport: None,
        // The VTA's `[dids]` decides; `vtc setup --from` can state them.
        did_method: None,
        scid_also_known_as: None,
        identity_method: IdentityMethod::Webvh,
    })
}

/// Trim an operator-supplied registry DID, mapping blank to "no registry".
///
/// Rejects a non-DID early, at the prompt or at TOML-parse time, rather than
/// letting it surface as a template-render failure several VTA round-trips
/// later. A referral's `uri` is tested for a `did:` prefix by consumers, so an
/// https URL here would render an entry that reads as this community serving
/// TRQP itself.
/// A co-admin DID as entered: blank is none, anything else must be a DID.
pub(crate) fn normalize_co_admin_did(raw: &str) -> Result<Option<String>, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !trimmed.starts_with("did:") {
        return Err(AppError::Config(format!(
            "the second administrator must be named by DID, got '{trimmed}'"
        )));
    }
    Ok(Some(trimmed.to_string()))
}

pub(crate) fn normalize_registry_did(raw: &str) -> Result<Option<String>, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !trimmed.starts_with("did:") {
        return Err(AppError::Config(format!(
            "trust registry must be named by DID, got '{trimmed}'. The referral published in \
             the VTC's DID document names the registry by DID, not by URL."
        )));
    }
    Ok(Some(trimmed.to_string()))
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

/// Ask which transports the community's DID document should advertise.
///
/// Only reached when the operator configured a mediator: with no mediator there
/// is no endpoint to advertise, and the document carries REST alone.
///
/// **Both are pre-selected**, matching §12 Phase A ("advertise TSP + DIDComm").
/// Advertising TSP alone strands every peer that does not speak it; advertising
/// DIDComm alone forgoes the preferred transport. Neither is wrong, so both are
/// offered — but the default is the one that strands nobody.
///
/// The warning is not decoration. Both entries name the operator's mediator,
/// and nothing here can check that the mediator actually routes the protocol
/// being advertised — its services belong to its own controller
/// (`docs/05-design-notes/tsp-enablement.md` §14 Q3). Advertising a transport
/// the mediator cannot carry produces an entry every conforming client will
/// choose and none can use, which is the same failure shape as advertising one
/// the binary cannot serve.
fn prompt_transports(mediator_did: &str) -> Result<Vec<Transport>, AppError> {
    use dialoguer::MultiSelect;

    println!();
    println!("  Which transports should this community advertise in its DID document?");
    println!();
    println!("  Both entries point at your mediator:");
    println!("    {mediator_did}");
    println!();
    println!("  ⚠ Advertising a transport your mediator does not route makes this");
    println!("    community unreachable on it — clients will prefer it and fail.");
    println!("    Check your mediator advertises the matching service before enabling.");
    println!();
    println!("  To change this later: `pnm did-mgmt dids edit` at the VTA, then, if this");
    println!("  VTC serves its own DID log, `cnm did-log install`.");
    println!();

    // Order matches the workspace preference (TSP > DIDComm), so the list reads
    // the way a resolver walks it.
    let options = [
        (
            "TSP     (TSPTransport)   — preferred transport",
            Transport::Tsp,
        ),
        (
            "DIDComm (DIDCommMessaging) — supported fallback",
            Transport::Didcomm,
        ),
    ];
    let labels: Vec<&str> = options.iter().map(|(label, _)| *label).collect();

    loop {
        let picked = MultiSelect::new()
            .with_prompt("Transports (space to toggle, enter to confirm)")
            .items(&labels)
            .defaults(&[true, true])
            .interact()
            .map_err(prompt_err)?;

        if picked.is_empty() {
            // A mediator with no advertised transport is almost certainly a
            // mis-toggle: the operator just chose a mediator, and this leaves
            // the VTC connected to it while telling nobody. Re-ask rather than
            // silently minting an unreachable community.
            println!();
            println!("  No transport selected — this community would connect to the mediator");
            println!("  but advertise no way to reach it. Select at least one, or restart");
            println!("  setup and choose \"Skip messaging\" if that is what you want.");
            println!();
            continue;
        }

        let chosen: Vec<Transport> = picked.into_iter().map(|i| options[i].1).collect();

        // Echo the decision in the terms the document will carry, so the
        // operator sees what is about to be minted rather than which
        // checkboxes they ticked. This is their last chance to notice it.
        println!();
        println!(
            "  Advertising: {}",
            chosen
                .iter()
                .map(|t| t.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if chosen.len() == 1 && chosen[0] == Transport::Tsp {
            println!(
                "  Note: TSP only — peers that do not speak TSP will have no way to reach this"
            );
            println!("        community over a mediator.");
        }
        println!();

        return Ok(chosen);
    }
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
) -> Result<(IdentityMethod, WebvhTarget), AppError> {
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
    println!("  Or a did:webs (alpha): did:webs:<host>:<path>:<AID>, a KERI identifier the");
    println!("  VTA publishes at a did-hosting server built with did:webs hosting. It has");
    println!("  one signing key (no post-quantum key), no serverless mode, and its services");
    println!("  change only through the VTA. See docs/02-vta/did-webs.md.");
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
        // prompt here would have unpredictable effect. A did:webs needs a
        // named server, so without the catalogue it is not offered: `vtc
        // setup --from` with `identity_method = "webs"` names one directly.
        println!(
            "  did:webs needs a did-hosting server picked from the VTA's catalogue; to set \
             one up without it, use `vtc setup --from` with identity_method = \"webs\"."
        );
        return Ok((IdentityMethod::Webvh, WebvhTarget::default()));
    };

    // A DIDComm-connected client holds a live, auto-reconnecting session for
    // the setup key. Shut it down on every path — success or a `?` out of a
    // prompt — before returning: left to drop, it keeps the mediator's one
    // socket for that DID and fights the provision round-trip's own session
    // (and trips `vta-sdk`'s leak guard, a panic in debug builds).
    let target = prompt_webvh_target(&client).await;
    client.shutdown().await;
    target
}

/// The server, tenant-domain and path prompts, against a connected client.
/// Split out of [`select_webvh_target`] so the client is shut down however
/// these end.
async fn prompt_webvh_target(
    client: &VtaClient,
) -> Result<(IdentityMethod, WebvhTarget), AppError> {
    let method = prompt_identity_method()?;
    let server_id = prompt_webvh_server(client, method).await?;
    let (domain, path) = match server_id.as_deref() {
        // A hosting server is selected: the `<path>` is a real label
        // under that server, so offer it (and the tenant-domain picker).
        Some(sid) => {
            let domain = prompt_webvh_domain(client, sid).await?;
            let path = prompt_webvh_path(sid)?;
            (domain, path)
        }
        // Serverless: the VTC self-hosts its `did.jsonl`, and the DID
        // `did:webvh:<scid>:<host>` always resolves at
        // `<host>/.well-known/did.jsonl`. There's no meaningful path to
        // pick, so we don't ask.
        None => (None, None),
    };

    Ok((
        method,
        WebvhTarget {
            server_id,
            domain,
            path,
        },
    ))
}

/// did:webvh (the default) or a level-1 did:webs for the VTC's own DID.
fn prompt_identity_method() -> Result<IdentityMethod, AppError> {
    let idx = dialoguer::Select::new()
        .with_prompt("DID method of the community's own DID")
        .items([
            "did:webvh (recommended; can carry a post-quantum key)",
            "did:webs (alpha, KERI; one signing key; hosted only)",
        ])
        .default(0)
        .interact()
        .map_err(prompt_err)?;
    Ok(if idx == 1 {
        IdentityMethod::Webs
    } else {
        IdentityMethod::Webvh
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
        // The setup key is this client's identity — it is what just
        // authenticated, and the tasks the wizard dispatches are proof-REQUIRED
        // like any other.
        let client = VtaClient::authenticated(
            rest_url,
            vta_sdk::client::ClientIdentity {
                client_did: setup_key.did.clone(),
                private_key_multibase: setup_key.private_key_multibase().to_string(),
                vta_did: resolved.vta_did.clone(),
                verification_method: None,
            },
            auth.access_token,
        )
        .await;
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
async fn prompt_webvh_server(
    client: &VtaClient,
    method: IdentityMethod,
) -> Result<Option<String>, AppError> {
    use dialoguer::Select;

    // A did:webs has no serverless mode: no server is a refusal, with the fix.
    let no_webs_server = |why: String| {
        AppError::Validation(format!(
            "{why}; a did:webs VTC is published by one of the VTA's did-hosting servers, which \
             must be built with did:webs hosting (`method-webs`). Register one (`pnm \
             did-mgmt servers add`) and set up again, or choose did:webvh."
        ))
    };
    let servers = match client.list_webvh_servers().await {
        Ok(body) => body.servers,
        Err(e) if method == IdentityMethod::Webs => {
            return Err(no_webs_server(format!(
                "could not list the VTA's did-hosting servers ({e})"
            )));
        }
        Err(e) => {
            println!("  Could not list did-hosting servers ({e}); defaulting to serverless.");
            return Ok(None);
        }
    };

    if servers.is_empty() && method == IdentityMethod::Webs {
        return Err(no_webs_server(
            "no did-hosting servers are registered with this VTA".into(),
        ));
    }
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
    if method == IdentityMethod::Webvh {
        labels.push("Serverless — self-host did.jsonl at the VTC base URL".to_string());
    }

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
            // The store reads from `store.data_dir`, so no fields to
            // populate — but the selector must be explicit. Left `None`,
            // `create_secret_store` walks its implicit chain and picks the
            // keyring whenever it is compiled in, ignoring this choice.
            config.backend = Some(crate::config::SecretBackend::Plaintext);
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
    // Supplies the mediator DID that `inputs.transports` advertise. Passed
    // separately rather than folded into `WizardInputs` because it is also the
    // daemon's *runtime* messaging config — the DID document and `config.toml`
    // read the same operator decision, and duplicating the DID into both
    // structs would let them drift.
    messaging: Option<&MessagingConfig>,
    setup_key: &EphemeralSetupKey,
) -> Result<ProvisionResultV2, AppError> {
    let ask = provision_ask(inputs, webvh, messaging)?;
    let reply = drive_provision(
        inputs.vta_did.clone(),
        setup_key,
        ask,
        inputs.provision_transport.map(ProvisionTransport::protocol),
    )
    .await?;

    match reply {
        VtaReply::Full(result) => Ok(*result),
        VtaReply::AdminOnly(_) => Err(AppError::Internal(
            "VTA returned an admin-only reply but the vtc-host template requires a \
             FullSetup reply"
                .into(),
        )),
    }
}

/// What setup asks the VTA to provision: the template for the identity method
/// and its variables.
pub(crate) fn provision_ask(
    inputs: &WizardInputs,
    webvh: &WebvhTarget,
    messaging: Option<&MessagingConfig>,
) -> Result<ProvisionAsk, AppError> {
    let mut vars = BTreeMap::new();
    // The template appends both `REST_PATH` (default `/v1`) and
    // `STATUS_LIST_PATH` (default `/v1/status-lists`) to `URL`, so `URL` must
    // be the host base — passing the API base with `/v1` here renders a
    // double-`/v1` in both endpoints of the DID doc.
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
    // The whole `TrustRegistry` service entry rides as one var. The template
    // declares it in `optionalVars` with a `null` default and places it as a
    // bare array member, so leaving it out prunes the element — that
    // null-pruning slot is the only conditional the template format has, and
    // it is why `referral_service` builds the entry here rather than the
    // template spelling it out. Building it in the SDK keeps one owner for
    // the `TrustRegistry` type and the TRQP profile URI.
    if let Some(registry_did) = inputs.registry_did.as_deref() {
        vars.insert(
            TRUST_REGISTRY_SERVICE_VAR.to_string(),
            referral_service(registry_did)
                .map_err(|e| AppError::Config(format!("trust-registry referral: {e}")))?,
        );
    }
    // The messaging transports, same null-pruning slots. Both name the one
    // mediator the operator chose — TSP and DIDComm share it (§14 Q2), so this
    // renders one DID under two service types rather than two endpoints.
    //
    // A transport selected without a mediator is unrepresentable: the selection
    // prompt only runs when `messaging` is `Some`, and `from_toml` rejects the
    // combination. Guarding again here would be dead code that reads as if the
    // case were possible.
    if !inputs.transports.is_empty() {
        let mediator_did = messaging.map(|m| m.mediator_did.as_str()).ok_or_else(|| {
            AppError::Internal(
                "transports selected with no mediator configured — the setup front-ends must \
                     not produce this"
                    .into(),
            )
        })?;
        for transport in &inputs.transports {
            let (var, entry) = match transport {
                Transport::Tsp => (
                    TSP_SERVICE_VAR,
                    tsp_service(mediator_did)
                        .map_err(|e| AppError::Config(format!("TSP service entry: {e}")))?,
                ),
                Transport::Didcomm => (
                    DIDCOMM_SERVICE_VAR,
                    didcomm_service(mediator_did)
                        .map_err(|e| AppError::Config(format!("DIDComm service entry: {e}")))?,
                ),
            };
            vars.insert(var.to_string(), entry);
        }
    }
    // How the community's DID is presented (VTI-VTC-004, VTI-VTA-036): the
    // VTA's provisioning takes it as template vars, and its `[dids]` decides
    // what is not stated.
    //
    // A did:webs identity is chosen by the same var (`DID_METHOD=webs`, as
    // provision-integration reads it); `did_method` then only shapes the DIDs
    // the community mints later, and a key event log lists no did:scid alias.
    match inputs.identity_method {
        IdentityMethod::Webs => {
            vars.insert("DID_METHOD".to_string(), JsonValue::String("webs".into()));
        }
        IdentityMethod::Webvh => {
            if let Some(method) = inputs.did_method {
                vars.insert(
                    "DID_METHOD".to_string(),
                    JsonValue::String(method.as_str().to_string()),
                );
            }
            if let Some(alias) = inputs.scid_also_known_as {
                vars.insert("SCID_ALSO_KNOWN_AS".to_string(), JsonValue::Bool(alias));
            }
        }
    }
    let template = inputs.identity_method.template();
    Ok(
        ProvisionAsk::for_template(template, vars, inputs.context.clone())
            .with_label(format!("{template} integration")),
    )
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
    force_transport: Option<Protocol>,
) -> Result<VtaReply, AppError> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(run_connection_test(
        VtaIntent::FullSetup,
        vta_did.clone(),
        setup_key.did.clone(),
        setup_key.private_key_multibase().to_string(),
        ask.clone(),
        force_transport,
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

/// Wrap a terminal failure string with an actionable hint.
///
/// The ACL hint is the right guess for most failures — a missing or expired
/// grant on the setup DID is the common cause — but it is **wrong for a
/// transport failure**, and confidently wrong at that: a VTA that timed out
/// talking to its DID-hosting host reported "authorize the ephemeral DID",
/// sending operators to re-check an ACL that was never the problem while the
/// real fault was two hops away. A hint that names the wrong layer costs more
/// than no hint.
///
/// The classification is a heuristic over the rendered message because
/// [`VtaEvent::Failed`] carries a string, not a typed error. Threading a typed
/// variant through the event would let this switch on the cause instead of its
/// spelling; until then, match only unambiguous transport markers and fall
/// through to the ACL hint, so a message we don't recognise keeps the advice
/// that is usually right.
fn provision_failed(msg: &str) -> AppError {
    const TRANSPORT_MARKERS: &[&str] = &[
        "timed out",
        "request timed out",
        "bad gateway",
        "transport error",
        "failed to send message",
    ];
    let lower = msg.to_ascii_lowercase();
    let hint = if TRANSPORT_MARKERS.iter().any(|m| lower.contains(m)) {
        "The VTA accepted the request but could not complete it — this is a transport failure \
         between the VTA and one of its peers (its DID-hosting server or mediator), not an \
         authorization problem. Check the VTA's own logs for the operation that stalled, and \
         that its DID-hosting server and mediator are reachable and version-compatible."
    } else {
        "Double-check the VTA URL/DID and that the ephemeral DID was authorized via \
         `pnm contexts create` (or `pnm acl create` if the context already exists)."
    };
    AppError::Internal(format!("VTA provisioning failed: {msg}. {hint}"))
}

#[cfg(test)]
mod provision_failed_tests {
    use super::provision_failed;

    /// The exact message that shipped the misleading hint: a 30s DIDComm
    /// timeout between the VTA and its DID-hosting host. It must NOT tell the
    /// operator to go fix an ACL.
    #[test]
    fn transport_timeout_does_not_blame_the_acl() {
        let err = provision_failed(
            "Provisioning failed. Details: provision-integration call failed: server error \
             (500): bad gateway: failed to send message: transport error: request timed out \
             after 30s",
        );
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("pnm contexts create"),
            "a transport failure must not suggest an ACL grant: {rendered}"
        );
        assert!(
            rendered.contains("transport failure"),
            "a transport failure must be named as one: {rendered}"
        );
    }

    /// An unrecognised failure keeps the ACL hint — it is the common cause, and
    /// dropping it would make the usual case harder to diagnose.
    #[test]
    fn unclassified_failure_keeps_the_acl_hint() {
        let err = provision_failed("provisioning ended without a terminal event");
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("pnm contexts create"),
            "the default hint must survive: {rendered}"
        );
    }

    /// A genuine permission failure keeps the ACL hint too — "forbidden" is
    /// not a transport marker, so it must not be swallowed by the new branch.
    #[test]
    fn forbidden_keeps_the_acl_hint() {
        let err = provision_failed("provision-integration call failed: forbidden");
        let rendered = format!("{err:?}");
        assert!(rendered.contains("pnm acl create"), "{rendered}");
    }
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
             --admin-did {setup_did} --admin-expires 1h --admin-handoff"
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
    config.auth = {
        let mut c = AuthConfig::default();
        c.jwt_signing_key = Some(generate_jwt_signing_key());
        c
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

/// Mint the first install token: a **passkey** invitation. Its token names no
/// DID; the founder is the `did:key` of the passkey that claims it
/// (`vtc/install/claim/passkey/finish/0.1` item 5), written by
/// `vtc/admin/bootstrap`. The passkey install no longer attaches a passkey to
/// a DID the token names (`vtc/install/claim/{start,finish}/0.2`, retired) —
/// the setup's admin DID is granted separately (`offline_acl_add_command`).
async fn mint_initial_install_token(
    config: &AppConfig,
    bundle: &VtcKeyBundle,
    co_admin_did: Option<&str>,
    base_url: &str,
) -> Result<(String, String), AppError> {
    // The daemon derives the install-token key from the derivation root
    // (`server::init_auth`); a token minted under anything else never verifies.
    let root = bundle.derivation_root()?;
    let signer = InstallTokenSigner::from_master_seed(&*root)?;
    let minted = mint_passkey_install_token(
        &signer,
        &bundle.integration_did,
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
        .record_issued_passkey(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            exp,
            Some(claim_code_hash),
            crate::install::InvitedAuthority::community_admin("vtc setup", "first admin (install)"),
        )
        .await?;
    // The install bootstrap writes the co-admin beside the first admin, in
    // the same step, so the community never has one without the other.
    if let Some(co_admin) = co_admin_did {
        install_store.record_co_admin(co_admin).await?;
    }

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
        "  pnm acl create --did {} \\\n    --role admin --contexts {} --expires 1h --handoff",
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

/// The DID the VTA minted is of the method asked for. A VTA that does not read
/// `DID_METHOD=webs` would otherwise hand back a did:webvh the operator did not
/// choose, and a did:webs answer to a did:webvh ask is as wrong.
fn check_identity_matches(method: IdentityMethod, did: &str) -> Result<(), AppError> {
    let is_webs = did.starts_with("did:webs:");
    match (method, is_webs) {
        (IdentityMethod::Webs, false) => Err(AppError::Internal(format!(
            "asked the VTA for a did:webs VTC and it minted {did}: the VTA does not provision \
             did:webs integrations (it needs the `webs` feature, `[dids] webs_enabled` and \
             `webs_service_dids`). Fix the VTA and set up again, or set up as did:webvh."
        ))),
        (IdentityMethod::Webvh, true) => Err(AppError::Internal(format!(
            "asked the VTA for a did:webvh VTC and it minted the did:webs {did}"
        ))),
        _ => Ok(()),
    }
}

/// Derive the on-disk log label for the VTC's own `did:webvh` — the
/// final colon-separated component (for a serverless
/// `did:webvh:<scid>:<host>` that's the host). This is purely a
/// storage-key derivation: the daemon's `GET /.well-known/did.jsonl`
/// route (`routes::did_log`) reads the log back under the *same*
/// derivation, so the two must stay in lockstep. Not an SCID — the
/// SCID is the first label, and nothing here needs it.
fn did_log_label_or_err(did: &str) -> Result<String, AppError> {
    // A did:scid VTC DID: the label of the log its `src` names (VTI-KEY-160).
    let log_did = vta_sdk::did_scid::webvh_did(did);
    let did = log_did.as_deref().unwrap_or(did);
    did.strip_prefix("did:webvh:")
        .and_then(|suffix| suffix.split(':').next_back())
        .map(str::to_string)
        .ok_or_else(|| {
            AppError::Internal(format!(
                "the VTA returned {did}, which is not a did:webvh, for a did:webvh VTC"
            ))
        })
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

    fn webs_inputs(method: IdentityMethod) -> WizardInputs {
        WizardInputs {
            base_url: "https://vtc.example".into(),
            vta_did: "did:webvh:QmVta:vta.example".into(),
            context: "community".into(),
            registry_did: None,
            transports: vec![Transport::Tsp, Transport::Didcomm],
            co_admin_did: None,
            single_admin_mode: false,
            provision_transport: None,
            did_method: Some(vta_sdk::did_scid::DidMethod::Webvh),
            scid_also_known_as: Some(true),
            identity_method: method,
        }
    }

    fn mediator() -> MessagingConfig {
        MessagingConfig {
            mediator_url: String::new(),
            mediator_did: "did:webvh:QmMediator:mediator.example".into(),
            mediator_host: None,
            setup_acl: false,
            drain_inbox_on_start: false,
        }
    }

    /// VTI-KEY-001: a did:webs VTC is asked for as `vtc-host-classical` with
    /// `DID_METHOD=webs` at the chosen server and slot, with its transports and
    /// no did:scid alias; a did:webvh VTC is asked for exactly as before.
    #[test]
    fn vti_key_001_setup_asks_the_vta_for_a_did_webs_vtc() {
        let target = WebvhTarget {
            server_id: Some("host-1".into()),
            domain: None,
            path: Some("communities".into()),
        };
        let m = mediator();
        let ask = provision_ask(&webs_inputs(IdentityMethod::Webs), &target, Some(&m)).unwrap();
        assert_eq!(
            ask.integration_template.as_deref(),
            Some("vtc-host-classical")
        );
        let vars = &ask.integration_template_vars;
        assert_eq!(vars["DID_METHOD"], "webs");
        assert_eq!(vars["WEBVH_SERVER"], "host-1");
        assert_eq!(vars["WEBVH_PATH"], "communities");
        assert_eq!(vars["URL"], "https://vtc.example");
        assert!(vars.contains_key(TSP_SERVICE_VAR) && vars.contains_key(DIDCOMM_SERVICE_VAR));
        assert!(!vars.contains_key("SCID_ALSO_KNOWN_AS"));

        let ask = provision_ask(&webs_inputs(IdentityMethod::Webvh), &target, Some(&m)).unwrap();
        assert_eq!(ask.integration_template.as_deref(), Some("vtc-host"));
        assert_eq!(ask.integration_template_vars["DID_METHOD"], "webvh");
        assert_eq!(ask.integration_template_vars["SCID_ALSO_KNOWN_AS"], true);
    }

    /// What a VTA returns for a did:webs `vtc-host-classical`: the key-state
    /// key and the designated key agreement key under the document's ids, the
    /// derived document, and the stream in place of a did.jsonl.
    fn webs_provision_result() -> (ProvisionResultV2, serde_json::Value) {
        use crate::setup::bundle::level_one_tests::{KA, SIGNING, level_one_vtc_with_stream};
        use affinidi_secrets_resolver::secrets::Secret;
        use vta_sdk::sealed_transfer::template_bootstrap::{
            DidKeyMaterialV2, SlotKeyPair, TemplateBootstrapConfig, TemplateBootstrapPayloadV2,
            TemplateOutput, VtaTrustBundle,
        };
        let (did, document, stream) = level_one_vtc_with_stream();
        let ids = vta_sdk::node_keys::NodeKeyIds::from_document(&did, &document).unwrap();
        let signing = Secret::generate_ed25519(None, Some(&SIGNING));
        let ka = Secret::generate_x25519(None, Some(&KA)).unwrap();
        let pair = |slot: &str, key_type, key_id: &str, s: &Secret| SlotKeyPair {
            slot: slot.into(),
            key_type,
            key_id: key_id.into(),
            public_key_multibase: s.get_public_keymultibase().unwrap(),
            private_key_multibase: s.get_private_keymultibase().unwrap(),
        };
        let material = DidKeyMaterialV2 {
            did: did.clone(),
            signing_key: pair(
                "signing",
                vta_sdk::keys::KeyType::Ed25519,
                &ids.signing,
                &signing,
            ),
            ka_key: pair(
                "ka",
                vta_sdk::keys::KeyType::X25519,
                ids.key_agreement.as_deref().unwrap(),
                &ka,
            ),
            additional_signing_keys: Vec::new(),
        };
        let summary = serde_json::from_value(serde_json::json!({
            "clientDid": "did:key:z6MkSetup",
            "adminDid": "did:key:z6MkAdmin",
            "adminRolledOver": true,
            "integrationDid": did,
            "templateName": "vtc-host-classical",
            "templateKind": "vtc-host",
            "bundleIdHex": "00".repeat(16),
            "secretCount": 1,
            "outputCount": 1,
            "webvhServerId": "host-1",
        }))
        .unwrap();
        let result = ProvisionResultV2 {
            bundle_id_hex: "00".repeat(16),
            digest: "sha256:test".into(),
            summary,
            payload: TemplateBootstrapPayloadV2 {
                authorization: serde_json::json!({}),
                secrets: [(did.clone(), material)].into_iter().collect(),
                config: TemplateBootstrapConfig {
                    template_name: "vtc-host-classical".into(),
                    template_kind: "vtc-host".into(),
                    did_document: document.clone(),
                    outputs: vec![TemplateOutput::WebsKeriCesr {
                        did: did.clone(),
                        keri_cesr: stream,
                    }],
                    vta_url: None,
                    vta_trust: VtaTrustBundle {
                        vta_did: "did:webvh:QmVta:vta.example".into(),
                        vta_did_document: serde_json::json!({}),
                        vta_did_log: None,
                    },
                },
            },
        };
        (result, document)
    }

    fn inline_secrets() -> SecretsConfig {
        let mut secrets: SecretsConfig = toml::from_str("").unwrap();
        secrets.backend = Some(crate::config::SecretBackend::Config);
        secrets
    }

    /// VTI-KEY-001: first-boot setup of a did:webs VTC, against what a VTA
    /// returns. No did.jsonl is written (the VTA published the stream at its
    /// host); the stored bundle names each key by the document's own id, so
    /// the daemon signs and decrypts as its document says, with no `#key-0`.
    #[tokio::test]
    async fn vti_key_001_first_boot_setup_of_a_did_webs_vtc() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let (provision, document) = webs_provision_result();
        let did = document["id"].as_str().unwrap().to_string();
        let outcome = persist_provisioned(
            config_path.clone(),
            webs_inputs(IdentityMethod::Webs),
            inline_secrets(),
            Some(mediator()),
            provision,
        )
        .await
        .expect("setup completes");
        assert_eq!(outcome.vtc_did, did);
        assert!(
            !outcome.data_dir.join("did").exists(),
            "a did:webs VTC keeps no did.jsonl"
        );

        let config = AppConfig::load(Some(config_path)).unwrap();
        assert_eq!(config.vtc_did.as_deref(), Some(did.as_str()));
        let stored = hex::decode(config.secrets.secret.as_deref().unwrap()).unwrap();
        let own = crate::setup::bundle::own_key_material(&did, &stored).unwrap();
        let ids = vta_sdk::node_keys::NodeKeyIds::from_document(&did, &document).unwrap();
        assert_eq!(own.key_role_ids, Some(ids.clone()));
        let signer = crate::credentials::LocalSigner::for_own_keys(did.clone(), &own);
        assert_eq!(signer.assertion_method_id(), ids.signing);
        assert_eq!(signer.authentication_method_id(), ids.signing);
        assert_eq!(signer.key_count(), 1);
    }

    /// A VTA that ignores `DID_METHOD=webs` and mints a did:webvh is refused,
    /// with what to fix, before anything is written.
    #[tokio::test]
    async fn a_did_webvh_minted_for_a_did_webs_ask_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let (mut provision, _) = webs_provision_result();
        provision.summary.integration_did = Some("did:webvh:QmScid:vtc.example".into());
        let material = provision.payload.secrets.values().next().unwrap().clone();
        provision.payload.secrets = [("did:webvh:QmScid:vtc.example".to_string(), material)]
            .into_iter()
            .collect();
        let err = persist_provisioned(
            config_path.clone(),
            webs_inputs(IdentityMethod::Webs),
            inline_secrets(),
            None,
            provision,
        )
        .await
        .err()
        .expect("refused");
        assert!(err.to_string().contains("webs_service_dids"), "{err}");
        assert!(!config_path.exists());
    }

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
        let msg = format!("{err}");
        assert!(msg.contains("not a did:webvh"), "{msg}");
        assert!(msg.contains("for a did:webvh VTC"), "{msg}");
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
    fn secrets_choice_to_config_pins_plaintext_backend() {
        let config = secrets_choice_to_config(SecretsBackendChoice::Plaintext);
        assert_eq!(
            config.backend,
            Some(crate::config::SecretBackend::Plaintext)
        );
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
        assert!(msg.contains("--admin-expires 1h --admin-handoff"));
    }

    fn sample_config(cfg_path: &std::path::Path) -> AppConfig {
        build_app_config(
            cfg_path.to_path_buf(),
            "did:webvh:scid:vtc.example.com".into(),
            "did:webvh:scid:vta.example.com".into(),
            "https://vtc.example.com".into(),
            cfg_path.parent().unwrap().join("data"),
            secrets_choice_to_config(SecretsBackendChoice::Keyring {
                service: "vtc".into(),
            }),
            None,
        )
        .unwrap()
    }

    /// VTI-APV-022: setup writes `[acl] single_admin_mode = true` only when it
    /// was chosen, and the daemon reads it back as on.
    #[test]
    fn vti_apv_022_setup_writes_single_admin_mode_only_when_chosen() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = tmp.path().join("config.toml");

        let config = sample_config(&cfg_path);
        assert!(!config.acl.single_admin_mode, "off by default");
        write_config_toml(&cfg_path, &config).unwrap();
        let written = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(
            !written.contains("single_admin_mode"),
            "not written unless chosen:\n{written}"
        );

        let mut config = sample_config(&cfg_path);
        config.acl.single_admin_mode = true;
        write_config_toml(&cfg_path, &config).unwrap();
        let written = std::fs::read_to_string(&cfg_path).unwrap();
        let parsed: toml::Value = toml::from_str(&written).unwrap();
        assert_eq!(
            parsed["acl"]["single_admin_mode"].as_bool(),
            Some(true),
            "{written}"
        );
        let reloaded = AppConfig::load(Some(cfg_path.clone())).unwrap();
        assert!(reloaded.acl.single_admin_mode);
    }

    /// Chosen beside a second administrator: allowed, with a warning that it
    /// keep it only where that administrator is another of the same person's
    /// identifiers, since the mode waives consent regardless.
    #[test]
    fn vti_apv_022_single_admin_beside_a_co_admin_warns() {
        let inputs = |single, co: Option<&str>| WizardInputs {
            base_url: "https://vtc.example.com".into(),
            vta_did: "did:webvh:vta".into(),
            context: "default".into(),
            registry_did: None,
            transports: Vec::new(),
            co_admin_did: co.map(String::from),
            single_admin_mode: single,
            provision_transport: None,
            did_method: None,
            scid_also_known_as: None,
            identity_method: IdentityMethod::Webvh,
        };
        assert!(single_admin_warning(&inputs(true, None)).is_none());
        assert!(single_admin_warning(&inputs(false, Some("did:key:z6MkCo"))).is_none());
        let w = single_admin_warning(&inputs(true, Some("did:key:z6MkCo"))).unwrap();
        assert!(w.contains("another of your own identifiers"), "{w}");
        assert!(w.contains("VTI-APV-022"), "{w}");
    }

    /// #501: the provisioning transports on offer are the advertised ones, in
    /// the runner's order, and each maps to the runner's own vocabulary.
    #[test]
    fn the_provisioning_transports_on_offer_are_the_advertised_ones() {
        let resolved = ResolvedVta {
            vta_did: "did:webvh:vta".into(),
            tsp_mediator_did: Some("did:web:m".into()),
            mediator_did: None,
            rest_url: Some("https://vta.example".into()),
        };
        assert_eq!(
            ProvisionTransport::advertised(&resolved),
            vec![ProvisionTransport::Tsp, ProvisionTransport::Rest]
        );
        assert_eq!(ProvisionTransport::Rest.protocol(), Protocol::Rest);
        assert_eq!(ProvisionTransport::Didcomm.protocol(), Protocol::DidComm);
        // One transport is no choice, and an unresolved DID asks nothing.
        assert_eq!(prompt_provision_transport(None).unwrap(), None);
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

    fn admin_key_material() -> vta_sdk::sealed_transfer::DidKeyMaterialV2 {
        use vta_sdk::keys::KeyType;
        use vta_sdk::sealed_transfer::{DidKeyMaterialV2, SlotKeyPair};
        let pair = |slot: &str, key_type: KeyType| SlotKeyPair {
            slot: slot.into(),
            key_type,
            key_id: format!("did:key:z6MkAdmin#{slot}"),
            public_key_multibase: "z6MkPublic".into(),
            private_key_multibase: "zPrivateSecretMaterial".into(),
        };
        DidKeyMaterialV2 {
            did: "did:key:z6MkAdmin".into(),
            signing_key: pair("signing", KeyType::Ed25519),
            ka_key: pair("ka", KeyType::X25519),
            additional_signing_keys: Vec::new(),
        }
    }

    /// #2703: setup hands the admin key over as an owner-only file in the
    /// data directory (never on a terminal), loadable as the material the VTA
    /// returned, and never overwrites an earlier one.
    #[test]
    fn admin_key_is_written_owner_only_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let key = admin_key_material();

        let first = write_admin_key_file(dir.path(), &key).expect("first write");
        assert_eq!(first, dir.path().join("keys").join("admin-key.json"));
        let read: vta_sdk::sealed_transfer::DidKeyMaterialV2 =
            serde_json::from_slice(&std::fs::read(&first).unwrap()).unwrap();
        assert_eq!(read.did, key.did);
        assert_eq!(
            read.signing_key.private_key_multibase,
            key.signing_key.private_key_multibase
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&first), 0o600, "admin key file must be 0600");
            assert_eq!(mode(first.parent().unwrap()), 0o700, "key dir must be 0700");
        }

        let before = std::fs::read(&first).unwrap();
        let second = write_admin_key_file(dir.path(), &key).expect("second write");
        assert_ne!(second, first, "an existing admin key is never overwritten");
        assert_eq!(std::fs::read(&first).unwrap(), before);
        assert!(second.exists());
    }
}
