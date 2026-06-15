//! Shared "pick a secret-store backend" UX.
//!
//! Each service (vta-service, vtc-service) maintains its own
//! `SecretsConfig` struct with subtly different field names and
//! backend coverage — vta-service includes HashiCorp Vault, vtc-service
//! doesn't, etc. To avoid baking either schema into vti-common, this
//! module returns a neutral [`SecretsBackendChoice`] enum and lets the
//! caller materialise their own config from it.
//!
//! Cloud-SDK-backed niceties (e.g. "list existing AWS secrets so the
//! operator can pick one") live in the caller — they need the cloud
//! SDK as a direct dep, which is too much for a hygiene crate to take
//! on. This module covers the universal pieces: backend selection,
//! the keyring service-name prompt, the plaintext-storage warning.
//!
//! The whole module is behind the `setup` feature so headless
//! consumers don't pull in `dialoguer`.

use dialoguer::{Input, Select};

/// What the operator picked.
///
/// Variants are gated behind feature-style strings the caller passes
/// in via [`AvailableBackends`] — vti-common doesn't know which
/// backends the service compiles with, so the caller advertises that
/// up front. This keeps the prompt's "what backends are available"
/// menu in sync with what the resulting `SecretsConfig` can actually
/// satisfy at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsBackendChoice {
    /// OS keyring (Apple Keychain / Windows Credential Manager /
    /// Secret Service on Linux). `service` is the keyring service
    /// name — a unique-per-instance identifier the platform uses to
    /// partition entries between concurrent VTC / VTA daemons.
    Keyring { service: String },
    /// AWS Secrets Manager. The caller-supplied closure already
    /// resolved the secret name + region — typically by prompting
    /// the operator and offering a "list existing secrets" pick.
    Aws {
        secret_name: String,
        region: Option<String>,
    },
    /// GCP Secret Manager.
    Gcp {
        project: String,
        secret_name: String,
    },
    /// Azure Key Vault.
    Azure {
        vault_url: String,
        secret_name: String,
    },
    /// Kubernetes `Secret`. `namespace` is `None` when the operator
    /// wants the in-cluster ServiceAccount namespace; `secret_key` is
    /// the key within the Secret's `data` map (the caller substitutes
    /// its own default when the operator leaves it blank).
    Kubernetes {
        secret_name: String,
        namespace: Option<String>,
        secret_key: String,
    },
    /// Hex-encoded seed embedded directly in `config.toml`. The
    /// wizard fills the value in after key derivation; this variant
    /// just signals the choice.
    InlineConfig,
    /// Plaintext file on disk. Strongly discouraged; the prompt
    /// shows a warning before returning this.
    Plaintext,
}

/// Which backends the caller's service supports. Reflects the
/// compile-time feature gates on the consuming crate — vti-common
/// itself is feature-agnostic.
#[derive(Debug, Clone, Default)]
pub struct AvailableBackends {
    pub keyring: bool,
    pub aws: bool,
    pub gcp: bool,
    pub azure: bool,
    pub k8s: bool,
    pub inline_config: bool,
    /// Plaintext is always available as a fallback; the field is
    /// here so a service that strictly disallows it (e.g. a TEE
    /// build) can refuse to surface the option.
    pub plaintext: bool,
}

impl AvailableBackends {
    fn any(&self) -> bool {
        self.keyring
            || self.aws
            || self.gcp
            || self.azure
            || self.k8s
            || self.inline_config
            || self.plaintext
    }
}

/// Caller-supplied resolvers for the cloud backends. Each closure
/// runs only if the operator picks that backend; cloud SDK calls
/// (list-existing-secrets etc.) belong in the service since they
/// need the SDK as a direct dep.
#[allow(clippy::type_complexity)]
pub struct BackendResolvers<'a> {
    pub aws: Option<Box<dyn FnOnce() -> Result<(String, Option<String>), SecretsPromptError> + 'a>>,
    pub gcp: Option<Box<dyn FnOnce() -> Result<(String, String), SecretsPromptError> + 'a>>,
    pub azure: Option<Box<dyn FnOnce() -> Result<(String, String), SecretsPromptError> + 'a>>,
}

impl<'a> BackendResolvers<'a> {
    pub fn empty() -> Self {
        Self {
            aws: None,
            gcp: None,
            azure: None,
        }
    }
}

/// Errors the prompt can surface. `Inner` wraps anything the caller-
/// supplied resolvers produce so the caller can preserve their own
/// error context.
#[derive(Debug, thiserror::Error)]
pub enum SecretsPromptError {
    #[error("no backends configured — service must enable at least one")]
    NoBackendsAvailable,
    #[error("user aborted prompt: {0}")]
    Dialoguer(#[from] dialoguer::Error),
    #[error("{0}")]
    Inner(String),
}

/// Run the interactive "pick a backend" prompt.
///
/// Arguments:
/// - `available` advertises the backends the caller's `SecretsConfig`
///   can actually persist.
/// - `keyring_default_service` is the default name shown in the keyring
///   service-name prompt (e.g. `"vtc"` or `"vta"`).
/// - `resolvers` supplies per-backend lookups (e.g. AWS list-secrets).
///   `None` means "prompt the user for the name directly, no listing".
pub fn configure_secrets(
    available: &AvailableBackends,
    keyring_default_service: &str,
    resolvers: BackendResolvers<'_>,
) -> Result<SecretsBackendChoice, SecretsPromptError> {
    if !available.any() {
        return Err(SecretsPromptError::NoBackendsAvailable);
    }

    let mut labels: Vec<&str> = Vec::new();
    let mut tags: Vec<&str> = Vec::new();
    if available.aws {
        labels.push("AWS Secrets Manager");
        tags.push("aws");
    }
    if available.gcp {
        labels.push("GCP Secret Manager");
        tags.push("gcp");
    }
    if available.azure {
        labels.push("Azure Key Vault");
        tags.push("azure");
    }
    if available.k8s {
        labels.push("Kubernetes Secret");
        tags.push("k8s");
    }
    if available.inline_config {
        labels.push("Config file (hex-encoded seed in config.toml)");
        tags.push("inline-config");
    }
    if available.keyring {
        labels.push("OS keyring");
        tags.push("keyring");
    }
    if available.plaintext {
        labels.push("Plaintext file (NOT recommended)");
        tags.push("plaintext");
    }

    let choice = if labels.len() == 1 {
        0
    } else {
        Select::new()
            .with_prompt("Seed storage backend")
            .items(&labels)
            .default(0)
            .interact()?
    };

    match tags[choice] {
        "keyring" => prompt_keyring(keyring_default_service),
        "aws" => match resolvers.aws {
            Some(r) => r().map(|(secret_name, region)| SecretsBackendChoice::Aws {
                secret_name,
                region,
            }),
            None => prompt_aws_fallback(),
        },
        "gcp" => match resolvers.gcp {
            Some(r) => r().map(|(project, secret_name)| SecretsBackendChoice::Gcp {
                project,
                secret_name,
            }),
            None => prompt_gcp_fallback(),
        },
        "azure" => match resolvers.azure {
            Some(r) => r().map(|(vault_url, secret_name)| SecretsBackendChoice::Azure {
                vault_url,
                secret_name,
            }),
            None => prompt_azure_fallback(),
        },
        "k8s" => prompt_k8s(),
        "inline-config" => Ok(SecretsBackendChoice::InlineConfig),
        "plaintext" => {
            print_plaintext_warning();
            Ok(SecretsBackendChoice::Plaintext)
        }
        // The tag list is constructed above from the same booleans —
        // this branch is unreachable in practice but stays total for
        // safety.
        other => Err(SecretsPromptError::Inner(format!(
            "internal: unknown backend tag '{other}'"
        ))),
    }
}

fn prompt_keyring(default_service: &str) -> Result<SecretsBackendChoice, SecretsPromptError> {
    let service: String = Input::new()
        .with_prompt("Keyring service name (use a unique name per instance)")
        .default(default_service.to_string())
        .interact_text()?;
    Ok(SecretsBackendChoice::Keyring { service })
}

fn prompt_aws_fallback() -> Result<SecretsBackendChoice, SecretsPromptError> {
    let region: String = Input::new()
        .with_prompt("AWS region (leave empty for SDK default)")
        .allow_empty(true)
        .interact_text()?;
    let region = if region.is_empty() {
        None
    } else {
        Some(region)
    };
    let secret_name: String = Input::new()
        .with_prompt("AWS Secrets Manager secret name")
        .interact_text()?;
    Ok(SecretsBackendChoice::Aws {
        secret_name,
        region,
    })
}

fn prompt_gcp_fallback() -> Result<SecretsBackendChoice, SecretsPromptError> {
    let project: String = Input::new().with_prompt("GCP project ID").interact_text()?;
    let secret_name: String = Input::new()
        .with_prompt("GCP Secret Manager secret name")
        .interact_text()?;
    Ok(SecretsBackendChoice::Gcp {
        project,
        secret_name,
    })
}

fn prompt_azure_fallback() -> Result<SecretsBackendChoice, SecretsPromptError> {
    let vault_url: String = Input::new()
        .with_prompt("Azure Key Vault URL (e.g. https://my-vault.vault.azure.net)")
        .interact_text()?;
    let secret_name: String = Input::new()
        .with_prompt("Azure Key Vault secret name")
        .interact_text()?;
    Ok(SecretsBackendChoice::Azure {
        vault_url,
        secret_name,
    })
}

/// Prompt for the Kubernetes Secret backend. No cluster calls happen here —
/// the connection is made at first secret-store access. A blank namespace
/// means "use the in-cluster ServiceAccount namespace"; a blank data key
/// means "use the caller's default" (`secret_key` comes back empty and the
/// caller substitutes its own default when materialising its config).
fn prompt_k8s() -> Result<SecretsBackendChoice, SecretsPromptError> {
    let secret_name: String = Input::new()
        .with_prompt("Kubernetes Secret name")
        .interact_text()?;
    let namespace: String = Input::new()
        .with_prompt("Namespace (leave empty for the pod's ServiceAccount namespace)")
        .allow_empty(true)
        .interact_text()?;
    let namespace = if namespace.is_empty() {
        None
    } else {
        Some(namespace)
    };
    let secret_key: String = Input::new()
        .with_prompt("Key within the Secret's data map (leave empty for the default)")
        .allow_empty(true)
        .interact_text()?;
    Ok(SecretsBackendChoice::Kubernetes {
        secret_name,
        namespace,
        secret_key,
    })
}

fn print_plaintext_warning() {
    eprintln!();
    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  WARNING: Plaintext storage is NOT secure.               ║");
    eprintln!("║  Seeds will be stored in a plaintext file on disk.       ║");
    eprintln!("║  Use only for development or testing.                    ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_backends_available_errors() {
        let available = AvailableBackends::default();
        let err = configure_secrets(&available, "vtc", BackendResolvers::empty())
            .expect_err("must error when no backends advertised");
        assert!(matches!(err, SecretsPromptError::NoBackendsAvailable));
    }

    #[test]
    fn available_backends_any_is_true_when_keyring_is_set() {
        let available = AvailableBackends {
            keyring: true,
            ..Default::default()
        };
        assert!(available.any());
    }

    #[test]
    fn available_backends_any_is_false_by_default() {
        assert!(!AvailableBackends::default().any());
    }
}
