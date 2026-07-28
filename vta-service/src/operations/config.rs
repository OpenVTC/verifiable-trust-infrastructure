//! Runtime configuration, on the canonical `config/{show,patch}/0.1` tasks.
//!
//! The VTA's configuration is exposed as a **registry** of keys rather than
//! named typed fields, which is what let it fold onto the canonical family
//! (#840 phase A) instead of carrying a `vta/config/*` pair of its own.
//!
//! # Identity is immutable at runtime
//!
//! [`REGISTRY`] marks `vta_did` `mutable: false`. It is readable through
//! `config/show`, and a `config/patch` naming it is **rejected** — reported
//! back under `rejected` with a reason, never written.
//!
//! Before the fold, `update_config` wrote `vta_did` straight into
//! `config.toml` with no guard at all. A single mistaken super-admin call
//! could re-point the agent's own identity, persist it, and survive a restart:
//! every credential the VTA had issued, every ACL grant naming it, and its
//! DID-document linkage would then refer to an identity it no longer claimed.
//! Super-admin gating made that a bricking footgun rather than a privilege
//! escalation — the same class of defect VTC fixed in its P1.1 hardening.
//!
//! Enforcing it through the registry rather than an `if` in the handler is
//! deliberate: there is one table saying what may change, and every write path
//! consults it. A new mutation surface cannot forget the check.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::RwLock;
use tracing::info;

use vta_sdk::protocols::vta_management::get_config::{ConfigField, GetConfigResultBody};
use vta_sdk::protocols::vta_management::update_config::{RejectedKey, UpdateConfigResultBody};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;

/// One registered configuration key.
struct KeyDef {
    key: &'static str,
    /// False → readable but refused by `config/patch`.
    mutable: bool,
    /// True → a change is stored but only takes effect on restart.
    requires_restart: bool,
    /// Why an immutable key is immutable. Surfaced verbatim as the rejection
    /// reason, so an operator learns the rule rather than just the refusal.
    immutable_reason: &'static str,
}

/// Every configuration key this VTA exposes. **The single source of truth for
/// what may change at runtime** — `patch` consults it, so a new write path
/// cannot bypass it.
const REGISTRY: &[KeyDef] = &[
    KeyDef {
        key: "vta_did",
        mutable: false,
        requires_restart: false,
        immutable_reason: "the VTA's own identity is set at setup and cannot be changed at \
                           runtime; re-pointing it would orphan every credential this agent \
                           issued and every ACL grant naming it",
    },
    KeyDef {
        key: "vta_name",
        mutable: true,
        requires_restart: false,
        immutable_reason: "",
    },
    KeyDef {
        key: "public_url",
        mutable: true,
        // The advertised origin is read at boot; changing it while running
        // would diverge the live services from the stored value.
        requires_restart: true,
        immutable_reason: "",
    },
];

fn lookup(key: &str) -> Option<&'static KeyDef> {
    REGISTRY.iter().find(|d| d.key == key)
}

fn value_of(config: &AppConfig, key: &str) -> Value {
    let v = match key {
        "vta_did" => config.vta_did.clone(),
        "vta_name" => config.vta_name.clone(),
        "public_url" => config.public_url.clone(),
        _ => None,
    };
    v.map(Value::String).unwrap_or(Value::Null)
}

fn source_of(config: &AppConfig, key: &str) -> &'static str {
    if value_of(config, key).is_null() {
        "default"
    } else if key == "vta_did" {
        "setup"
    } else {
        "toml"
    }
}

/// `config/show/0.1`. Auth: any authenticated caller.
pub async fn get_config(
    config: &Arc<RwLock<AppConfig>>,
    auth: &AuthClaims,
    keys: Option<Vec<String>>,
    channel: &str,
) -> Result<GetConfigResultBody, AppError> {
    let config = config.read().await;
    let fields = REGISTRY
        .iter()
        .filter(|d| keys.as_ref().is_none_or(|ks| ks.iter().any(|k| k == d.key)))
        .map(|d| ConfigField {
            key: d.key.to_string(),
            value: value_of(&config, d.key),
            source: source_of(&config, d.key).to_string(),
            requires_restart: d.requires_restart,
        })
        .collect();
    info!(channel, caller = %auth.did, "config retrieved");
    Ok(GetConfigResultBody { fields })
}

/// `config/patch/0.1`. Auth: super-admin.
///
/// Unknown and immutable keys are reported under `rejected`; everything else
/// is applied. A patch that rejects every key writes nothing.
pub async fn update_config(
    config: &Arc<RwLock<AppConfig>>,
    auth: &AuthClaims,
    overrides: HashMap<String, Value>,
    channel: &str,
) -> Result<UpdateConfigResultBody, AppError> {
    auth.require_super_admin()?;

    let mut applied = Vec::new();
    let mut pending_restart = Vec::new();
    let mut rejected = Vec::new();

    // Partition before taking the write lock: validation needs no lock, and a
    // patch that changes nothing must not rewrite config.toml.
    let mut writes: Vec<(&'static KeyDef, String)> = Vec::new();
    for (key, value) in &overrides {
        let Some(def) = lookup(key) else {
            rejected.push(RejectedKey {
                key: key.clone(),
                reason: "unknown config key (not in the registry)".into(),
            });
            continue;
        };
        if !def.mutable {
            rejected.push(RejectedKey {
                key: key.clone(),
                reason: def.immutable_reason.to_string(),
            });
            continue;
        }
        let Some(s) = value.as_str() else {
            rejected.push(RejectedKey {
                key: key.clone(),
                reason: "expected a string value".into(),
            });
            continue;
        };
        writes.push((def, s.to_string()));
    }

    if writes.is_empty() {
        info!(channel, caller = %auth.did, rejected = rejected.len(), "config patch applied nothing");
        return Ok(UpdateConfigResultBody {
            applied,
            pending_restart,
            rejected,
        });
    }

    let (contents, path) = {
        let mut config = config.write().await;
        for (def, value) in &writes {
            match def.key {
                "vta_name" => config.vta_name = Some(value.clone()),
                "public_url" => config.public_url = Some(value.clone()),
                // Unreachable: `writes` only ever holds mutable registry keys.
                other => unreachable!("non-mutable key {other} reached the write path"),
            }
            if def.requires_restart {
                pending_restart.push(def.key.to_string());
            } else {
                applied.push(def.key.to_string());
            }
        }
        let contents = toml::to_string_pretty(&*config)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        (contents, config.config_path.clone())
    };

    std::fs::write(&path, contents).map_err(AppError::Io)?;

    info!(
        channel,
        caller = %auth.did,
        applied = applied.len(),
        pending_restart = pending_restart.len(),
        rejected = rejected.len(),
        "config updated"
    );
    Ok(UpdateConfigResultBody {
        applied,
        pending_restart,
        rejected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is the authorization boundary, so the properties that
    /// matter are properties *of the table* — asserting them here means a new
    /// key cannot quietly become mutable, and no write path can disagree.
    #[test]
    fn identity_is_registered_but_immutable() {
        let did = lookup("vta_did").expect("vta_did is readable through config/show");
        assert!(
            !did.mutable,
            "the VTA's own identity must never be patchable at runtime — \
             re-pointing it orphans every credential this agent issued"
        );
        assert!(
            !did.immutable_reason.is_empty(),
            "an immutable key must carry a reason; it is surfaced to the operator verbatim"
        );
    }

    /// Readable *and* immutable, not absent. VTC solved the same problem by
    /// leaving its DID out of the registry entirely, which loses the read path
    /// and answers "unknown key" to a question that deserves a better answer.
    #[test]
    fn identity_is_readable() {
        assert!(
            REGISTRY.iter().any(|d| d.key == "vta_did"),
            "config/show must still return the VTA DID"
        );
    }

    /// Every immutable key states why, and every mutable one does not pretend
    /// to. Guards against a key being marked immutable with an empty reason,
    /// which would surface as a blank rejection.
    #[test]
    fn reasons_track_mutability() {
        for d in REGISTRY {
            assert_eq!(
                d.mutable,
                d.immutable_reason.is_empty(),
                "{}: an immutable key needs a reason and a mutable one must not carry one",
                d.key
            );
        }
    }

    /// `public_url` is boot-stable: it is read once at startup to build the
    /// advertised origin, so a patch stores it but must report it as pending.
    /// Silently applying it would diverge the running services from the value
    /// an operator just read back.
    #[test]
    fn boot_stable_keys_are_marked_restart_required() {
        assert!(
            lookup("public_url").expect("registered").requires_restart,
            "public_url is read at boot; a change cannot take effect in place"
        );
        assert!(!lookup("vta_name").expect("registered").requires_restart);
    }
}
