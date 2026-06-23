//! Interactive setup wizard (`vta setup`).
//!
//! This module is **pure prompting**: it gathers operator answers into a
//! [`WizardInputs`] and hands them to the shared engine
//! ([`super::apply_inputs`]) — the same engine that drives
//! `vta setup --from <file>`. All the *work* (store init, seed persistence,
//! mediator + VTA DID minting, config write, summary) lives in `apply_inputs`,
//! so the two setup paths cannot drift (P1.2).
//!
//! Prompts go through the [`Prompter`] seam rather than calling `dialoguer`
//! directly. Production uses [`DialoguerPrompter`]; tests drive a scripted
//! prompter, which is what lets the golden test assert that prompt-gathered
//! inputs match the equivalent TOML byte-for-byte.
//!
//! Module-private by design: only [`run_setup_wizard`] is pub. Everything else
//! is an implementation detail.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use bip39::Mnemonic;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde_json::json;

use crate::config::{AuditConfig, LogConfig, LogFormat, ServerConfig, ServicesConfig};

use super::{
    SetupUi, apply_inputs, derive_ws_url,
    from_toml::{
        ExistingDataDirPolicy, MessagingInput, SecretsBackendInput, VtaDidInput, WizardInputs,
    },
};

type DynErr = Box<dyn std::error::Error>;

// ---------------------------------------------------------------------------
// Prompter seam
// ---------------------------------------------------------------------------

/// Abstraction over the handful of `dialoguer` prompt kinds the wizard uses.
///
/// The real implementation ([`DialoguerPrompter`]) drives a terminal; the test
/// suite supplies a scripted implementation so the prompt-gathering code can
/// run head-less. Keeping the seam this narrow (text / confirm / select /
/// multiselect) is what makes the golden equivalence test possible.
pub(crate) trait Prompter {
    /// Free-text input. `default` is offered when the operator just presses
    /// enter; `allow_empty` permits an empty answer; `validate`, when set,
    /// rejects (and in the real impl re-prompts on) bad input.
    fn text(
        &self,
        prompt: &str,
        default: Option<&str>,
        allow_empty: bool,
        validate: Option<&dyn Fn(&str) -> Result<(), String>>,
    ) -> Result<String, DynErr>;

    /// Yes/no confirmation.
    fn confirm(&self, prompt: &str, default: bool) -> Result<bool, DynErr>;

    /// Single choice among `items`; returns the chosen index.
    fn select(&self, prompt: &str, items: &[&str], default: usize) -> Result<usize, DynErr>;

    /// Multiple choice; returns the chosen indices.
    fn multiselect(
        &self,
        prompt: &str,
        items: &[&str],
        defaults: &[bool],
    ) -> Result<Vec<usize>, DynErr>;
}

/// Terminal-backed [`Prompter`] using `dialoguer`.
pub(crate) struct DialoguerPrompter;

impl Prompter for DialoguerPrompter {
    fn text(
        &self,
        prompt: &str,
        default: Option<&str>,
        allow_empty: bool,
        validate: Option<&dyn Fn(&str) -> Result<(), String>>,
    ) -> Result<String, DynErr> {
        let mut input = Input::<String>::new().with_prompt(prompt);
        if let Some(d) = default {
            input = input.default(d.to_owned());
        }
        if allow_empty {
            input = input.allow_empty(true);
        }
        let out = match validate {
            Some(v) => input
                .validate_with(move |s: &String| v(s.as_str()))
                .interact_text()?,
            None => input.interact_text()?,
        };
        Ok(out)
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool, DynErr> {
        Ok(Confirm::new()
            .with_prompt(prompt)
            .default(default)
            .interact()?)
    }

    fn select(&self, prompt: &str, items: &[&str], default: usize) -> Result<usize, DynErr> {
        Ok(Select::new()
            .with_prompt(prompt)
            .items(items)
            .default(default)
            .interact()?)
    }

    fn multiselect(
        &self,
        prompt: &str,
        items: &[&str],
        defaults: &[bool],
    ) -> Result<Vec<usize>, DynErr> {
        Ok(MultiSelect::new()
            .with_prompt(prompt)
            .items(items)
            .defaults(defaults)
            .interact()?)
    }
}

// ---------------------------------------------------------------------------
// SetupUi — the engine's callbacks, driven by the prompter
// ---------------------------------------------------------------------------

/// Interactive [`SetupUi`]: displays the mnemonic for confirmation and prompts
/// for the `did.jsonl` save path. Both go through the same [`Prompter`] as the
/// rest of the wizard so the whole flow is scriptable.
struct InteractiveUi<'p> {
    prompter: &'p dyn Prompter,
}

impl SetupUi for InteractiveUi<'_> {
    fn confirm_mnemonic(&self, mnemonic: &Mnemonic) -> Result<(), DynErr> {
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: Write down your mnemonic phrase and store it   ║");
        eprintln!("║  securely. It is the ONLY way to recover your keys.      ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        eprintln!("\x1b[1m{mnemonic}\x1b[0m");
        eprintln!();

        if self
            .prompter
            .confirm("I have saved my mnemonic phrase", false)?
        {
            Ok(())
        } else {
            Err("Setup cancelled — please save your mnemonic before proceeding.".into())
        }
    }

    fn did_log_path(&self, label: &str, _default: &Path) -> Option<PathBuf> {
        let default_file = format!("{label}-did.jsonl");
        // A prompt failure here shouldn't abort an otherwise-finished setup;
        // fall back to the canonical default the engine passed.
        match self
            .prompter
            .text("Save DID log to file", Some(&default_file), false, None)
        {
            Ok(entered) => {
                eprintln!();
                eprintln!(
                    "  \x1b[2mTo self-host this DID, upload {entered} to the DID URL.\x1b[0m"
                );
                Some(PathBuf::from(entered))
            }
            Err(_) => Some(_default.to_path_buf()),
        }
    }
}

// ---------------------------------------------------------------------------
// Prompt helpers — each returns a piece of WizardInputs
// ---------------------------------------------------------------------------

/// Prompt which services to enable. Returns `(rest, didcomm)`; at least one.
fn prompt_services(p: &dyn Prompter) -> Result<(bool, bool), DynErr> {
    let items = ["REST API", "DIDComm Messaging"];
    loop {
        let selected = p.multiselect(
            "Services to enable (select at least one)",
            &items,
            &[true, true],
        )?;
        if selected.is_empty() {
            eprintln!("\x1b[31mPlease select at least one service.\x1b[0m");
            continue;
        }
        return Ok((selected.contains(&0), selected.contains(&1)));
    }
}

/// Prompt for the seed-store backend, returning the typed [`SecretsBackendInput`]
/// the engine consumes. Only backends compiled into this build are offered.
async fn configure_secrets(p: &dyn Prompter) -> Result<SecretsBackendInput, DynErr> {
    let mut labels: Vec<&str> = Vec::new();
    let mut tags: Vec<&str> = Vec::new();

    #[cfg(feature = "aws-secrets")]
    {
        labels.push("AWS Secrets Manager");
        tags.push("aws");
    }
    #[cfg(feature = "gcp-secrets")]
    {
        labels.push("GCP Secret Manager");
        tags.push("gcp");
    }
    #[cfg(feature = "azure-secrets")]
    {
        labels.push("Azure Key Vault");
        tags.push("azure");
    }
    #[cfg(feature = "vault-secrets")]
    {
        labels.push("HashiCorp Vault");
        tags.push("vault");
    }
    #[cfg(feature = "k8s-secrets")]
    {
        labels.push("Kubernetes Secret");
        tags.push("k8s");
    }
    #[cfg(feature = "config-seed")]
    {
        labels.push("Config file (hex-encoded seed in config.toml)");
        tags.push("config");
    }
    #[cfg(feature = "keyring")]
    {
        labels.push("OS keyring");
        tags.push("keyring");
    }
    labels.push("Plaintext file (NOT recommended)");
    tags.push("plaintext");

    // If only one backend is compiled, use it without prompting.
    let choice = if labels.len() == 1 {
        0
    } else {
        p.select("Seed storage backend", &labels, 0)?
    };
    let tag = tags[choice];

    #[cfg(feature = "aws-secrets")]
    if tag == "aws" {
        return prompt_aws_secrets(p).await;
    }
    #[cfg(feature = "gcp-secrets")]
    if tag == "gcp" {
        return prompt_gcp_secrets(p).await;
    }
    #[cfg(feature = "azure-secrets")]
    if tag == "azure" {
        return prompt_azure_secrets(p);
    }
    #[cfg(feature = "vault-secrets")]
    if tag == "vault" {
        return prompt_vault_secrets(p);
    }
    #[cfg(feature = "k8s-secrets")]
    if tag == "k8s" {
        return prompt_k8s_secrets(p);
    }
    #[cfg(feature = "config-seed")]
    if tag == "config" {
        return Ok(SecretsBackendInput::ConfigSeed);
    }
    #[cfg(feature = "keyring")]
    if tag == "keyring" {
        let service = p.text(
            "Keyring service name (use a unique name per VTA instance)",
            Some("vta"),
            false,
            None,
        )?;
        return Ok(SecretsBackendInput::Keyring { service });
    }
    if tag == "plaintext" {
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: Plaintext storage is NOT secure.               ║");
        eprintln!("║  Seeds will be stored in a plaintext file on disk.       ║");
        eprintln!("║  Use only for development or testing.                    ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        return Ok(SecretsBackendInput::Plaintext);
    }

    unreachable!("selected backend tag does not match any compiled feature")
}

#[cfg(feature = "aws-secrets")]
async fn prompt_aws_secrets(p: &dyn Prompter) -> Result<SecretsBackendInput, DynErr> {
    let region = p.text("AWS region (leave empty for SDK default)", None, true, None)?;
    let region = if region.is_empty() {
        None
    } else {
        Some(region)
    };

    let secret_name = pick_or_enter_secret(
        p,
        vti_secrets::discovery::list_aws_secrets(region.as_deref())
            .await
            .map_err(Into::into),
    )
    .await?;
    Ok(SecretsBackendInput::Aws {
        region,
        secret_name,
    })
}

#[cfg(feature = "gcp-secrets")]
async fn prompt_gcp_secrets(p: &dyn Prompter) -> Result<SecretsBackendInput, DynErr> {
    let project = p.text("GCP project ID", None, false, None)?;
    let secret_name = pick_or_enter_secret(
        p,
        vti_secrets::discovery::list_gcp_secrets(&project)
            .await
            .map_err(Into::into),
    )
    .await?;
    Ok(SecretsBackendInput::Gcp {
        project,
        secret_name,
    })
}

/// Shared "pick from a listed set or type a new name" flow for the cloud
/// secret-manager backends. A listing error degrades to a free-text prompt.
#[cfg(any(feature = "aws-secrets", feature = "gcp-secrets"))]
async fn pick_or_enter_secret(
    p: &dyn Prompter,
    listed: Result<Vec<String>, DynErr>,
) -> Result<String, DynErr> {
    match listed {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let item_refs: Vec<&str> = items.iter().map(String::as_str).collect();
            let choice = p.select(
                "Select an existing secret or create a new one",
                &item_refs,
                0,
            )?;
            if choice == items.len() - 1 {
                p.text("Secret name", Some("vta-master-seed"), false, None)
            } else {
                Ok(items.swap_remove(choice))
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found.");
            p.text("Secret name", Some("vta-master-seed"), false, None)
        }
        Err(e) => {
            eprintln!("  Warning: could not list secrets: {e}");
            p.text("Secret name", Some("vta-master-seed"), false, None)
        }
    }
}

#[cfg(feature = "azure-secrets")]
fn prompt_azure_secrets(p: &dyn Prompter) -> Result<SecretsBackendInput, DynErr> {
    let vault_url = p.text(
        "Azure Key Vault URL (e.g. https://my-vault.vault.azure.net)",
        None,
        false,
        None,
    )?;
    let secret_name = p.text(
        "Azure Key Vault secret name",
        Some("vta-master-seed"),
        false,
        None,
    )?;
    Ok(SecretsBackendInput::Azure {
        vault_url,
        secret_name,
    })
}

/// Prompt for HashiCorp Vault settings. Synchronous — actual Vault auth
/// happens at first seed-store call.
#[cfg(feature = "vault-secrets")]
fn prompt_vault_secrets(p: &dyn Prompter) -> Result<SecretsBackendInput, DynErr> {
    use super::from_toml::{
        default_vault_approle_mount, default_vault_k8s_jwt_path, default_vault_k8s_mount,
    };

    let addr = p.text(
        "Vault server URL (e.g. https://vault.example.com:8200)",
        None,
        false,
        None,
    )?;
    let secret_path = p.text(
        "KV v2 secret path (e.g. vta/master-seed)",
        None,
        false,
        None,
    )?;
    let kv_mount = p.text("KV v2 mount path", Some("secret"), false, None)?;
    let secret_key = p.text(
        "Field name within the KV entry holding the hex seed",
        Some("seed"),
        false,
        None,
    )?;
    let namespace = p.text(
        "Vault Enterprise namespace (leave empty if not using)",
        None,
        true,
        None,
    )?;
    let namespace = if namespace.is_empty() {
        None
    } else {
        Some(namespace)
    };

    let auth_methods = ["kubernetes", "token", "approle"];
    let auth_idx = p.select("Auth method", &auth_methods, 0)?;
    let auth_method = auth_methods[auth_idx].to_string();

    let mut k8s_role = None;
    let mut token = None;
    let mut approle_role_id = None;
    let mut approle_secret_id = None;
    match auth_method.as_str() {
        "kubernetes" => {
            k8s_role = Some(p.text("Kubernetes auth role name", None, false, None)?);
        }
        "token" => {
            eprintln!(
                "  \x1b[2mLeave empty to read from the VAULT_TOKEN env var at runtime.\x1b[0m"
            );
            let t = p.text("Vault token", None, true, None)?;
            if !t.is_empty() {
                token = Some(t);
            }
        }
        "approle" => {
            approle_role_id = Some(p.text("AppRole role_id", None, false, None)?);
            approle_secret_id = Some(p.text("AppRole secret_id", None, false, None)?);
        }
        _ => unreachable!("auth_method came from a fixed list"),
    }

    Ok(SecretsBackendInput::Vault {
        addr,
        secret_path,
        kv_mount,
        secret_key,
        namespace,
        auth_method,
        k8s_role,
        k8s_mount: default_vault_k8s_mount(),
        k8s_jwt_path: default_vault_k8s_jwt_path(),
        token,
        approle_role_id,
        approle_secret_id,
        approle_mount: default_vault_approle_mount(),
        skip_verify: false,
    })
}

/// Prompt for Kubernetes Secret backend settings. Synchronous — the actual
/// cluster connection happens at first seed-store call.
#[cfg(feature = "k8s-secrets")]
fn prompt_k8s_secrets(p: &dyn Prompter) -> Result<SecretsBackendInput, DynErr> {
    use super::from_toml::default_k8s_secret_key;

    let secret_name = p.text(
        "Kubernetes Secret name",
        Some("vta-master-seed"),
        false,
        None,
    )?;
    let namespace = p.text(
        "Namespace (leave empty to use the pod's ServiceAccount namespace)",
        None,
        true,
        None,
    )?;
    let namespace = if namespace.is_empty() {
        None
    } else {
        Some(namespace)
    };
    let secret_key = p.text(
        "Key within the Secret's data map holding the hex seed",
        Some("seed"),
        false,
        None,
    )?;
    let secret_key = if secret_key.is_empty() {
        default_k8s_secret_key()
    } else {
        secret_key
    };

    Ok(SecretsBackendInput::Kubernetes {
        secret_name,
        namespace,
        secret_key,
    })
}

/// Prompt for the optional `mediator_host` override (TEE vsock-bridge SNI).
fn prompt_optional_mediator_host(p: &dyn Prompter) -> Result<Option<String>, DynErr> {
    let host = p.text(
        "Mediator hostname for vsock-bridged TEE deployments (leave empty to skip)",
        None,
        true,
        None,
    )?;
    Ok(if host.is_empty() { None } else { Some(host) })
}

/// Prompt for DIDComm messaging configuration, returning a [`MessagingInput`].
async fn configure_messaging(p: &dyn Prompter) -> Result<MessagingInput, DynErr> {
    let options = [
        "Use an existing mediator DID",
        "Create a new mediator DID (did:webvh)",
        "Do not use DIDComm messaging",
    ];
    let choice = p.select("DIDComm messaging", &options, 0)?;

    match choice {
        0 => {
            let did = p.text(
                "Mediator DID",
                None,
                false,
                Some(&|s: &str| {
                    if s.starts_with("did:") {
                        Ok(())
                    } else {
                        Err("DID must start with 'did:' (e.g. did:webvh:... or did:key:...)".into())
                    }
                }),
            )?;
            let mediator_host = prompt_optional_mediator_host(p)?;
            Ok(MessagingInput::Existing { did, mediator_host })
        }
        1 => {
            let context = p
                .text(
                    "Trust context for the mediator DID",
                    Some("mediator"),
                    false,
                    None,
                )?
                .trim()
                .to_string();
            if context.is_empty() {
                return Err("mediator context id cannot be empty".into());
            }

            let url = p.text("Mediator URL", None, false, None)?;
            let ws_default = derive_ws_url(&url);
            let ws_url = p.text("Mediator WebSocket URL", ws_default.as_deref(), false, None)?;

            // Hosting URL for the mediator's `did.jsonl` — separate knob from
            // the DIDComm endpoint above. Defaults to the DIDComm URL for the
            // common case where both live on the same host; operators with
            // split hosts (DIDComm at e.g. `mediator.example.com/mediator/v1`,
            // DID document at `dids.example.com/mediator`) override here.
            // The engine reads this as `webvh_url` and falls back to `url`
            // when None — we always send Some so the operator's choice is
            // captured explicitly.
            let webvh_url = prompt_webvh_url(p, &context, Some(&url))?;

            let mediator_host = prompt_optional_mediator_host(p)?;

            // Optional ROUTING_KEYS escape hatch (mediator chains). The
            // engine fills URL / WS_URL from the fields above; the other
            // optional template vars (ACCEPT, WEBVH_SERVER) have correct
            // defaults and are only reachable via `--from <toml>`.
            let routing_raw = p.text(
                "Upstream routing-key DIDs for this mediator (comma-separated, leave empty to skip)",
                None,
                true,
                None,
            )?;
            let routing_keys: Vec<String> = routing_raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            let mut template_vars: HashMap<String, serde_json::Value> = HashMap::new();
            if !routing_keys.is_empty() {
                template_vars.insert("ROUTING_KEYS".into(), json!(routing_keys));
            }

            Ok(MessagingInput::CreateMediator {
                context,
                url,
                ws_url: Some(ws_url),
                webvh_url: Some(webvh_url),
                mediator_host,
                template_vars,
            })
        }
        _ => Ok(MessagingInput::Skip),
    }
}

/// Prompt for the VTA's own DID, returning a [`VtaDidInput`]. The advanced
/// webvh modes collect file paths / key ids only — the engine reads the files
/// and mints the DID.
fn create_vta_did(p: &dyn Prompter) -> Result<VtaDidInput, DynErr> {
    let did_options = [
        "Create a new did:webvh DID (recommended for production)",
        "Create a new did:key (no external hosting; great for local dev)",
        "Enter an existing DID",
        "Skip (no VTA DID for now)",
    ];
    let choice = p.select("VTA DID", &did_options, 0)?;

    match choice {
        0 => {
            let url = prompt_webvh_url(p, "VTA", None)?;

            let mode_options = [
                "Simple — VTA creates keys and document (recommended)",
                "Advanced — provide your own document, keys, or pre-signed log",
            ];
            let advanced = p.select("DID creation mode", &mode_options, 0)? == 1;

            let (did_document_file, did_log_file, signing_key_id, ka_key_id) = if advanced {
                let adv_options = [
                    "Provide a DID Document template (VTA signs it)",
                    "Import a pre-signed did.jsonl",
                    "Use existing imported keys",
                ];
                match p.select("Advanced option", &adv_options, 0)? {
                    0 => {
                        let path = p.text("Path to DID Document JSON file", None, false, None)?;
                        (Some(PathBuf::from(path)), None, None, None)
                    }
                    1 => {
                        let path = p.text("Path to did.jsonl file", None, false, None)?;
                        (None, Some(PathBuf::from(path)), None, None)
                    }
                    _ => {
                        let signing = p.text("Signing key ID (Ed25519)", None, false, None)?;
                        let ka = p.text(
                            "Key-agreement key ID (X25519, leave empty to skip)",
                            None,
                            true,
                            None,
                        )?;
                        let ka_id = if ka.is_empty() { None } else { Some(ka) };
                        (None, None, Some(signing), ka_id)
                    }
                }
            } else {
                (None, None, None, None)
            };

            // Portability / pre-rotation are meaningless for a pre-signed log.
            let (portable, pre_rotation_count) = if did_log_file.is_none() {
                let portable = p.confirm(
                    "Make this DID portable (can move to a different domain later)?",
                    true,
                )?;
                eprintln!();
                eprintln!(
                    "  \x1b[2mPre-rotation protects against key compromise by publishing hashes"
                );
                eprintln!("  of future keys now. Recommended: 1-3 keys.\x1b[0m");
                let pre_rotation_count = p
                    .text(
                        "Number of pre-rotation keys",
                        Some("1"),
                        false,
                        Some(&|s: &str| {
                            s.parse::<u32>()
                                .map(|_| ())
                                .map_err(|e| format!("must be a non-negative integer: {e}"))
                        }),
                    )?
                    .parse()
                    .expect("validated above");
                (portable, pre_rotation_count)
            } else {
                (true, 0)
            };

            Ok(VtaDidInput::CreateWebvh {
                url,
                portable,
                pre_rotation_count,
                did_document_file,
                did_log_file,
                signing_key_id,
                ka_key_id,
            })
        }
        1 => Ok(VtaDidInput::CreateDidKey),
        2 => {
            let did = p.text("VTA DID", None, false, None)?;
            Ok(VtaDidInput::Existing { did })
        }
        _ => Ok(VtaDidInput::Skip),
    }
}

/// Prompt for a webvh hosting URL, returning the raw string the engine parses.
/// Re-prompts (via the validator) until the URL parses as an `http(s)://` URL.
///
/// `default` lets the caller offer a sensible default the operator can accept
/// with Enter — used by the create-mediator path to pre-fill the DIDComm
/// endpoint URL, so the common-case "DIDComm and DID hosting on the same host"
/// stays one keystroke while operators with split hosts can override.
fn prompt_webvh_url(
    p: &dyn Prompter,
    label: &str,
    default: Option<&str>,
) -> Result<String, DynErr> {
    eprintln!();
    eprintln!("  Enter the URL where the {label} DID document will be hosted.");
    eprintln!("  Examples:");
    eprintln!("    https://example.com                -> did:webvh:{{SCID}}:example.com");
    eprintln!("    https://example.com/dids/vta       -> did:webvh:{{SCID}}:example.com:dids:vta");
    eprintln!("    http://localhost:8000               -> did:webvh:{{SCID}}:localhost%3A8000");
    eprintln!();

    let url = p.text(
        &format!("{label} DID URL"),
        default.or(Some("http://localhost:8000/")),
        false,
        Some(&|s: &str| {
            let parsed = url::Url::parse(s).map_err(|e| format!("invalid URL: {e}"))?;
            didwebvh_rs::url::WebVHURL::parse_url(&parsed)
                .map(|_| ())
                .map_err(|e| format!("could not convert to a webvh DID: {e}"))
        }),
    )?;
    Ok(url)
}

// ---------------------------------------------------------------------------
// Gather → WizardInputs
// ---------------------------------------------------------------------------

/// Walk the operator through every setup knob and assemble a [`WizardInputs`].
///
/// Returns `Ok(None)` when the operator cancels (declines to overwrite an
/// existing config or to wipe an existing data directory). Performs no work
/// beyond resolving the operator's intent — the engine ([`apply_inputs`]) does
/// the rest.
async fn gather_inputs(
    p: &dyn Prompter,
    default_config_path: Option<PathBuf>,
) -> Result<Option<WizardInputs>, DynErr> {
    // 1. Config file path.
    let default_path = default_config_path
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            std::env::var("VTA_CONFIG_PATH").unwrap_or_else(|_| "config.toml".into())
        });
    let config_path =
        PathBuf::from(p.text("Config file path", Some(&default_path), false, None)?);
    if config_path.exists() {
        let overwrite = p.confirm(
            &format!("{} already exists. Overwrite?", config_path.display()),
            false,
        )?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(None);
        }
        // The engine refuses to overwrite; the operator just confirmed they
        // want to, so clear the way.
        std::fs::remove_file(&config_path)
            .map_err(|e| format!("could not remove {}: {e}", config_path.display()))?;
    }

    // 2. VTA name.
    let vta_name = p.text("VTA name (leave empty to skip)", None, true, None)?;
    let vta_name = if vta_name.is_empty() {
        None
    } else {
        Some(vta_name)
    };

    // 3. Services.
    let (enable_rest, enable_didcomm) = prompt_services(p)?;

    // 4. Server host + port + REST URL (URL asked after the port so the
    //    localhost default can use it).
    let (public_url, host, port) = if enable_rest {
        let host = p.text("Server host", Some("0.0.0.0"), false, None)?;
        let port: u16 = p
            .text(
                "Server port",
                Some("8100"),
                false,
                Some(&|s: &str| {
                    s.parse::<u16>()
                        .map(|_| ())
                        .map_err(|e| format!("invalid port: {e}"))
                }),
            )?
            .parse()
            .expect("validated above");

        eprintln!();
        eprintln!(
            "  REST is enabled — the VTA needs a public URL to publish as a service endpoint in its DID document. Other parties (CLI clients, other VTAs) resolve the DID and use this URL to reach the REST API."
        );
        eprintln!("  Examples:");
        eprintln!("    • Local development: http://localhost:{port}");
        eprintln!("    • Production:        https://vta.example.com");
        eprintln!();
        let default_url = format!("http://localhost:{port}");
        let public_url = p.text(
            "VTA REST URL",
            Some(&default_url),
            false,
            Some(&|s: &str| {
                let s = s.trim();
                if s.is_empty() {
                    Err("VTA REST URL is required when REST is enabled".into())
                } else if !(s.starts_with("http://") || s.starts_with("https://")) {
                    Err(
                        "URL must start with http:// or https:// (e.g. http://localhost:8100)"
                            .into(),
                    )
                } else {
                    Ok(())
                }
            }),
        )?;
        let public_url = public_url.trim().trim_end_matches('/').to_string();
        (Some(public_url), host, port)
    } else {
        (
            None,
            ServerConfig::default().host,
            ServerConfig::default().port,
        )
    };

    // 5. Log level + format.
    let log_level = p.text("Log level", Some("info"), false, None)?;
    let log_format = match p.select("Log format", &["text", "json"], 0)? {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    // 6. Optional remote DID resolver — TEE/Nitro builds only (the enclave
    //    can't reach the network, so resolution is bridged over vsock).
    #[cfg(feature = "tee")]
    let resolver_url = {
        eprintln!();
        eprintln!("DID resolution");
        eprintln!("  In a TEE the enclave cannot reach the network directly, so DID");
        eprintln!("  resolution is dispatched to an external resolver-cache-server on the");
        eprintln!("  parent, bridged over vsock. Example: ws://127.0.0.1:4445/did/v1/ws");
        eprintln!();
        let entered = p.text("Remote DID resolver WebSocket URL", None, true, None)?;
        if entered.is_empty() {
            None
        } else {
            Some(entered)
        }
    };
    #[cfg(not(feature = "tee"))]
    let resolver_url: Option<String> = None;

    // 7. Audit-log retention.
    let retention_days: u32 = p
        .text(
            "Audit-log retention (days)",
            Some(&AuditConfig::default().retention_days.to_string()),
            false,
            Some(&|s: &str| match s.parse::<u32>() {
                Ok(0) => {
                    Err("retention must be > 0; the audit sweeper assumes a positive window".into())
                }
                Ok(_) => Ok(()),
                Err(e) => Err(format!("invalid number: {e}")),
            }),
        )?
        .parse()
        .expect("validated above");
    let audit = AuditConfig { retention_days };

    // 8. Data directory + existing-dir policy.
    let data_dir = PathBuf::from(p.text("Data directory", Some("data/vta"), false, None)?);
    let mut data_dir_exists = ExistingDataDirPolicy::default();
    if data_dir.exists() {
        let delete = p.confirm(
            &format!(
                "Data directory \"{}\" already exists. Delete and start fresh?",
                data_dir.display()
            ),
            false,
        )?;
        if delete {
            data_dir_exists = ExistingDataDirPolicy::Delete;
        } else {
            eprintln!("Setup cancelled.");
            return Ok(None);
        }
    }

    // 9. Advanced server options (REST only). Opt-in so the common path stays
    //    short; defaults match the pre-P1.2 hardcoded values.
    let (cors_origins, trust_xff, webauthn) = if enable_rest
        && p.confirm(
            "Configure advanced server options (CORS, trusted proxy header, WebAuthn)?",
            false,
        )? {
        let cors_raw = p.text(
            "Allowed CORS origins (comma-separated, leave empty for none)",
            None,
            true,
            None,
        )?;
        let cors_origins: Vec<String> = cors_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let trust_xff = p.confirm(
            "Trust the X-Forwarded-For header (only behind a trusted reverse proxy)?",
            false,
        )?;
        let webauthn = p.confirm("Advertise a WebAuthn-RP service in the VTA DID?", false)?;
        (cors_origins, trust_xff, webauthn)
    } else {
        (Vec::new(), false, false)
    };

    // 10. Secrets backend.
    let secrets = configure_secrets(p).await?;

    // 11. Messaging (DIDComm only).
    let messaging = if enable_didcomm {
        configure_messaging(p).await?
    } else {
        MessagingInput::Skip
    };

    // 12. VTA DID.
    let vta_did = create_vta_did(p)?;

    Ok(Some(WizardInputs {
        config_path,
        vta_name,
        public_url,
        data_dir,
        data_dir_exists,
        services: ServicesConfig {
            rest: enable_rest,
            didcomm: enable_didcomm,
            webauthn,
        },
        server: ServerConfig {
            host,
            port,
            cors_origins,
            trust_xff,
        },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        secrets,
        messaging,
        vta_did,
        // The interactive wizard never seeds an admin inline — operators use
        // `pnm setup` + `vta import-did` after setup. `--from` exposes these.
        admin_did: None,
        admin_label: None,
        resolver_url,
        audit,
        // Staff provisioning is a non-interactive (enterprise) feature, exposed
        // only via `--from <toml>`.
        staff: Vec::new(),
    }))
}

/// Entry point for `vta setup`. Gathers inputs interactively, then runs the
/// shared engine.
pub async fn run_setup_wizard(config_path: Option<PathBuf>) -> Result<(), DynErr> {
    eprintln!("Welcome to the VTA setup wizard.\n");
    let prompter = DialoguerPrompter;
    let Some(inputs) = gather_inputs(&prompter, config_path).await? else {
        return Ok(());
    };
    apply_inputs(
        inputs,
        &InteractiveUi {
            prompter: &prompter,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// A single scripted answer, consumed in prompt-call order.
    #[derive(Clone)]
    enum Answer {
        Text(String),
        Bool(bool),
        Index(usize),
        Indices(Vec<usize>),
    }

    /// Head-less [`Prompter`] that replays a fixed script of answers. Panics on
    /// a script/prompt-kind mismatch or exhaustion so a wrong test script fails
    /// loudly rather than silently.
    struct ScriptedPrompter {
        answers: RefCell<VecDeque<Answer>>,
    }

    impl ScriptedPrompter {
        fn new(answers: Vec<Answer>) -> Self {
            Self {
                answers: RefCell::new(answers.into()),
            }
        }
        fn next(&self, prompt: &str) -> Answer {
            self.answers
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| panic!("script exhausted at prompt: {prompt}"))
        }
    }

    impl Prompter for ScriptedPrompter {
        fn text(
            &self,
            prompt: &str,
            _default: Option<&str>,
            _allow_empty: bool,
            validate: Option<&dyn Fn(&str) -> Result<(), String>>,
        ) -> Result<String, DynErr> {
            match self.next(prompt) {
                Answer::Text(s) => {
                    if let Some(v) = validate {
                        v(&s)
                            .map_err(|e| format!("scripted answer {s:?} failed validation: {e}"))?;
                    }
                    Ok(s)
                }
                _ => panic!("expected Text answer for prompt: {prompt}"),
            }
        }
        fn confirm(&self, prompt: &str, _default: bool) -> Result<bool, DynErr> {
            match self.next(prompt) {
                Answer::Bool(b) => Ok(b),
                _ => panic!("expected Bool answer for prompt: {prompt}"),
            }
        }
        fn select(&self, prompt: &str, _items: &[&str], _default: usize) -> Result<usize, DynErr> {
            match self.next(prompt) {
                Answer::Index(i) => Ok(i),
                _ => panic!("expected Index answer for prompt: {prompt}"),
            }
        }
        fn multiselect(
            &self,
            prompt: &str,
            _items: &[&str],
            _defaults: &[bool],
        ) -> Result<Vec<usize>, DynErr> {
            match self.next(prompt) {
                Answer::Indices(v) => Ok(v),
                _ => panic!("expected Indices answer for prompt: {prompt}"),
            }
        }
    }

    fn text(s: &str) -> Answer {
        Answer::Text(s.to_string())
    }

    /// Golden test: a scripted run of the interactive wizard produces a
    /// `WizardInputs` structurally identical to the equivalent `--from` TOML.
    /// REST + DIDComm, keyring backend, create-mediator, simple webvh VTA DID,
    /// advanced server options — exercises the divergence-prone mappings.
    #[tokio::test]
    async fn interactive_matches_equivalent_toml() {
        // Scripted answers, in the exact order the prompts fire. Backend Select
        // is index 0 = "OS keyring" (the only cloud-free backend in the default
        // feature set besides plaintext).
        let answers = vec![
            text("/tmp/vta-golden/config.toml"), // config path (doesn't exist)
            text("golden-vta"),                  // vta name
            Answer::Indices(vec![0, 1]),         // services: REST + DIDComm
            text("0.0.0.0"),                     // host
            text("8100"),                        // port
            text("https://trust.example.com"),   // REST URL
            text("info"),                        // log level
            Answer::Index(0),                    // log format = text
            // TEE builds add an extra "Remote DID resolver WebSocket URL"
            // prompt here (vsock-bridged resolution); empty = skip. Only
            // scripted when `tee` is active so the answer sequence stays
            // aligned under both feature sets (CI's `--workspace` build
            // unifies `tee` onto this binary via vta-enclave).
            #[cfg(feature = "tee")]
            text(""), // TEE-only: remote DID resolver URL (skip)
            text("90"),                                // audit retention
            text("/tmp/vta-golden/data"),              // data dir (doesn't exist)
            Answer::Bool(true),                        // configure advanced server opts?
            text("https://app.example.com"),           // cors origins
            Answer::Bool(true),                        // trust_xff
            Answer::Bool(true),                        // webauthn
            Answer::Index(0),                          // secrets backend = keyring
            text("golden-keyring"),                    // keyring service
            Answer::Index(1),                          // messaging = create mediator
            text("mediator"),                          // mediator context
            text("https://mediator.example.com"),      // mediator DIDComm url
            text("wss://mediator.example.com/ws"),     // mediator ws url
            text("https://dids.example.com/mediator"), // mediator DID URL (split host)
            text(""),                                  // mediator host (skip)
            text(""),                                  // routing keys (skip)
            Answer::Index(1),                          // VTA DID = did:key
        ];
        let p = ScriptedPrompter::new(answers);
        let gathered = gather_inputs(&p, None)
            .await
            .expect("gather should succeed")
            .expect("gather should not cancel");

        let toml_str = r#"
            config_path = "/tmp/vta-golden/config.toml"
            vta_name    = "golden-vta"
            public_url  = "https://trust.example.com"
            data_dir    = "/tmp/vta-golden/data"

            [services]
            rest     = true
            didcomm  = true
            webauthn = true

            [server]
            host         = "0.0.0.0"
            port         = 8100
            cors_origins = ["https://app.example.com"]
            trust_xff    = true

            [log]
            level  = "info"
            format = "text"

            [audit]
            retention_days = 90

            [secrets]
            backend = "keyring"
            service = "golden-keyring"

            [messaging]
            kind      = "create_mediator"
            context   = "mediator"
            url       = "https://mediator.example.com"
            ws_url    = "wss://mediator.example.com/ws"
            webvh_url = "https://dids.example.com/mediator"

            [vta_did]
            kind = "create_did_key"
        "#;
        let from_toml: WizardInputs = toml::from_str(toml_str).expect("equivalent TOML parses");

        let a = serde_json::to_value(&gathered).unwrap();
        let b = serde_json::to_value(&from_toml).unwrap();
        assert_eq!(
            a, b,
            "interactive-gathered inputs must equal the equivalent --from TOML\n\
             interactive = {a:#}\n--from = {b:#}"
        );
    }

    /// The advanced webvh "use existing keys" mode maps to the right
    /// `VtaDidInput::CreateWebvh` fields.
    #[tokio::test]
    async fn advanced_existing_keys_mode_maps_through() {
        let answers = vec![
            text("/tmp/vta-golden2/config.toml"),
            text(""),                      // vta name (skip)
            Answer::Indices(vec![0]),      // services: REST only
            text("0.0.0.0"),               // host
            text("8100"),                  // port
            text("https://t.example.com"), // REST URL
            text("info"),                  // log level
            Answer::Index(0),              // log format
            // TEE-only "Remote DID resolver WebSocket URL" prompt; empty =
            // skip. See the note in `interactive_matches_equivalent_toml`.
            #[cfg(feature = "tee")]
            text(""), // TEE-only: remote DID resolver URL (skip)
            text("28"),                    // audit retention
            text("/tmp/vta-golden2/data"), // data dir
            Answer::Bool(false),           // advanced server opts? no
            Answer::Index(0),              // secrets backend = keyring
            text("vta"),                   // keyring service
            // messaging skipped (REST only)
            Answer::Index(0),                       // VTA DID = create_webvh
            text("https://t.example.com/dids/vta"), // webvh url
            Answer::Index(1),                       // advanced mode
            Answer::Index(2),                       // "use existing keys"
            text("did:key:z6MkSigner#key-0"),       // signing key id
            text("did:key:z6MkKa#key-1"),           // ka key id
            Answer::Bool(true), // portable (existing-keys still prompts — no pre-signed log)
            text("2"),          // pre-rotation count
        ];
        let p = ScriptedPrompter::new(answers);
        let gathered = gather_inputs(&p, None)
            .await
            .expect("gather should succeed")
            .expect("gather should not cancel");

        match gathered.vta_did {
            VtaDidInput::CreateWebvh {
                ref url,
                portable,
                pre_rotation_count,
                ref did_document_file,
                ref did_log_file,
                ref signing_key_id,
                ref ka_key_id,
            } => {
                assert_eq!(url, "https://t.example.com/dids/vta");
                assert!(portable);
                assert_eq!(pre_rotation_count, 2);
                assert!(did_document_file.is_none());
                assert!(did_log_file.is_none());
                assert_eq!(signing_key_id.as_deref(), Some("did:key:z6MkSigner#key-0"));
                assert_eq!(ka_key_id.as_deref(), Some("did:key:z6MkKa#key-1"));
            }
            other => panic!("expected CreateWebvh, got {other:?}"),
        }
    }
}
