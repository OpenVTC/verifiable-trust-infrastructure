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
//!
//! # Rate limits are tunable at runtime
//!
//! The four `[server]` rate-limit keys (`rate_limit_interval_secs`,
//! `rate_limit_burst`, `did_log_rate_limit_interval_secs`,
//! `did_log_rate_limit_burst`) are integer registry keys, bounded, and applied
//! without a restart: the limiters read `[server]` from the shared config on
//! every request (see `routes::rate_limit`), so writing the value here *is*
//! applying it. They are persisted to `config.toml` like every other key.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::RwLock;
use tracing::info;

use vta_sdk::protocols::vta_management::get_config::{ConfigField, GetConfigResultBody};
// The rate-limit key names are the SDK's, so the CLI hints that name them
// (`vta_sdk::rate_limit::suggested_fix`) cannot drift from the registry.
use vta_sdk::protocols::vta_management::update_config::{RejectedKey, UpdateConfigResultBody};
use vta_sdk::rate_limit as rl;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;

/// The value shape a registry key accepts.
#[derive(Clone, Copy)]
enum Kind {
    /// A string.
    Text,
    /// An integer in `min..=max`. A JSON number, or a string of decimal digits
    /// (so a client that only sends strings is not locked out).
    Int { min: u64, max: u64 },
}

/// One registered configuration key.
struct KeyDef {
    key: &'static str,
    kind: Kind,
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
        kind: Kind::Text,
        mutable: false,
        requires_restart: false,
        immutable_reason: "the VTA's own identity is set at setup and cannot be changed at \
                           runtime; re-pointing it would orphan every credential this agent \
                           issued and every ACL grant naming it",
    },
    KeyDef {
        key: "vta_name",
        kind: Kind::Text,
        mutable: true,
        requires_restart: false,
        immutable_reason: "",
    },
    KeyDef {
        key: "public_url",
        kind: Kind::Text,
        mutable: true,
        // The advertised origin is read at boot; changing it while running
        // would diverge the live services from the stored value.
        requires_restart: true,
        immutable_reason: "",
    },
    // Per-IP rate limits (`routes::rate_limit`). Intervals are seconds PER
    // TOKEN — lower is looser. Applied live: the limiters re-read `[server]`
    // on every request.
    KeyDef {
        key: rl::VTA_INTERVAL_KEY,
        kind: INTERVAL,
        mutable: true,
        requires_restart: false,
        immutable_reason: "",
    },
    KeyDef {
        key: rl::VTA_BURST_KEY,
        kind: BURST,
        mutable: true,
        requires_restart: false,
        immutable_reason: "",
    },
    KeyDef {
        key: rl::VTA_DID_LOG_INTERVAL_KEY,
        kind: INTERVAL,
        mutable: true,
        requires_restart: false,
        immutable_reason: "",
    },
    KeyDef {
        key: rl::VTA_DID_LOG_BURST_KEY,
        kind: BURST,
        mutable: true,
        requires_restart: false,
        immutable_reason: "",
    },
];

const INTERVAL: Kind = Kind::Int {
    min: 1,
    max: crate::routes::rate_limit::MAX_INTERVAL_SECS,
};
const BURST: Kind = Kind::Int {
    min: 1,
    max: crate::routes::rate_limit::MAX_BURST as u64,
};

/// A validated value, ready to write.
enum Parsed {
    Text(String),
    Int(u64),
}

impl Kind {
    fn parse(self, value: &Value) -> Result<Parsed, String> {
        match self {
            Kind::Text => value
                .as_str()
                .map(|s| Parsed::Text(s.to_string()))
                .ok_or_else(|| "expected a string value".to_string()),
            Kind::Int { min, max } => {
                let n = match value {
                    Value::Number(n) => n.as_u64(),
                    Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
                        s.parse::<u64>().ok()
                    }
                    _ => None,
                };
                match n {
                    Some(n) if (min..=max).contains(&n) => Ok(Parsed::Int(n)),
                    _ => Err(format!("expected an integer from {min} to {max}")),
                }
            }
        }
    }
}

fn lookup(key: &str) -> Option<&'static KeyDef> {
    REGISTRY.iter().find(|d| d.key == key)
}

/// The current and the default value of an integer key, or `None` for a
/// string key.
fn int_value_of(config: &AppConfig, key: &str) -> Option<(u64, u64)> {
    let s = &config.server;
    let d = crate::config::ServerConfig::default();
    match key {
        rl::VTA_INTERVAL_KEY => Some((s.rate_limit_interval_secs, d.rate_limit_interval_secs)),
        rl::VTA_BURST_KEY => Some((s.rate_limit_burst.into(), d.rate_limit_burst.into())),
        rl::VTA_DID_LOG_INTERVAL_KEY => Some((
            s.did_log_rate_limit_interval_secs,
            d.did_log_rate_limit_interval_secs,
        )),
        rl::VTA_DID_LOG_BURST_KEY => Some((
            s.did_log_rate_limit_burst.into(),
            d.did_log_rate_limit_burst.into(),
        )),
        _ => None,
    }
}

fn value_of(config: &AppConfig, key: &str) -> Value {
    if let Some((current, _)) = int_value_of(config, key) {
        return Value::from(current);
    }
    let v = match key {
        "vta_did" => config.vta_did.clone(),
        "vta_name" => config.vta_name.clone(),
        "public_url" => config.public_url.clone(),
        _ => None,
    };
    v.map(Value::String).unwrap_or(Value::Null)
}

fn source_of(config: &AppConfig, key: &str) -> &'static str {
    // An integer key always has a value; it reads as "default" while it still
    // holds the built-in one.
    if let Some((current, default)) = int_value_of(config, key) {
        return if current == default {
            "default"
        } else {
            "toml"
        };
    }
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
    let mut writes: Vec<(&'static KeyDef, Parsed)> = Vec::new();
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
        match def.kind.parse(value) {
            Ok(parsed) => writes.push((def, parsed)),
            Err(reason) => rejected.push(RejectedKey {
                key: key.clone(),
                reason,
            }),
        }
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
            match (def.key, value) {
                ("vta_name", Parsed::Text(v)) => config.vta_name = Some(v.clone()),
                ("public_url", Parsed::Text(v)) => config.public_url = Some(v.clone()),
                (rl::VTA_INTERVAL_KEY, Parsed::Int(n)) => {
                    config.server.rate_limit_interval_secs = *n
                }
                (rl::VTA_DID_LOG_INTERVAL_KEY, Parsed::Int(n)) => {
                    config.server.did_log_rate_limit_interval_secs = *n
                }
                // Bursts are bounded by `MAX_BURST`, which fits in a u32.
                (rl::VTA_BURST_KEY, Parsed::Int(n)) => {
                    config.server.rate_limit_burst = u32::try_from(*n).unwrap_or(u32::MAX)
                }
                (rl::VTA_DID_LOG_BURST_KEY, Parsed::Int(n)) => {
                    config.server.did_log_rate_limit_burst = u32::try_from(*n).unwrap_or(u32::MAX)
                }
                // Unreachable: `writes` only ever holds mutable registry keys,
                // each parsed by its own registered kind.
                (other, _) => {
                    unreachable!("key {other} reached the write path with the wrong kind")
                }
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

    /// The rate-limit keys are the point of runtime tuning: patchable, and
    /// applied live rather than parked behind a restart.
    #[test]
    fn rate_limit_keys_are_mutable_and_live() {
        for key in [
            "rate_limit_interval_secs",
            "rate_limit_burst",
            "did_log_rate_limit_interval_secs",
            "did_log_rate_limit_burst",
        ] {
            let def = lookup(key).unwrap_or_else(|| panic!("{key} must be registered"));
            assert!(def.mutable, "{key} must be patchable");
            assert!(!def.requires_restart, "{key} applies live");
            assert!(
                matches!(def.kind, Kind::Int { min: 1, .. }),
                "{key} is an integer >= 1"
            );
        }
    }

    /// The registry's key names are exactly the ones the SDK's 429 guidance
    /// tells an operator to set.
    #[test]
    fn rate_limit_keys_match_the_sdk_guidance() {
        for key in [
            rl::VTA_INTERVAL_KEY,
            rl::VTA_BURST_KEY,
            rl::VTA_DID_LOG_INTERVAL_KEY,
            rl::VTA_DID_LOG_BURST_KEY,
        ] {
            assert!(lookup(key).is_some(), "{key} must be a registry key");
        }
    }

    #[test]
    fn integer_kind_accepts_numbers_and_digit_strings_within_bounds() {
        let k = Kind::Int { min: 1, max: 3600 };
        for ok in [
            serde_json::json!(1),
            serde_json::json!(3600),
            serde_json::json!("60"),
        ] {
            assert!(
                matches!(k.parse(&ok), Ok(Parsed::Int(_))),
                "{ok} must parse"
            );
        }
        for bad in [
            serde_json::json!(0),
            serde_json::json!(3601),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("0"),
            serde_json::json!("+5"),
            serde_json::json!(" 5"),
            serde_json::json!(""),
            serde_json::json!(true),
            serde_json::Value::Null,
        ] {
            let err = match k.parse(&bad) {
                Err(e) => e,
                Ok(_) => panic!("{bad} must be rejected"),
            };
            assert!(err.contains("1 to 3600"), "{err}");
        }
    }

    fn config_in(dir: &std::path::Path) -> Arc<RwLock<AppConfig>> {
        let mut config = crate::test_support::test_app_config(dir.join("data"));
        config.config_path = dir.join("config.toml");
        Arc::new(RwLock::new(config))
    }

    #[tokio::test]
    async fn patching_rate_limits_writes_memory_and_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let auth = crate::test_support::super_admin_claims();
        let overrides = HashMap::from([
            ("rate_limit_interval_secs".to_string(), serde_json::json!(2)),
            ("rate_limit_burst".to_string(), serde_json::json!(30)),
            (
                "did_log_rate_limit_interval_secs".to_string(),
                serde_json::json!("3"),
            ),
            (
                "did_log_rate_limit_burst".to_string(),
                serde_json::json!(600),
            ),
        ]);
        let result = update_config(&config, &auth, overrides, "test")
            .await
            .unwrap();
        let mut applied = result.applied.clone();
        applied.sort();
        assert_eq!(
            applied,
            [
                "did_log_rate_limit_burst",
                "did_log_rate_limit_interval_secs",
                "rate_limit_burst",
                "rate_limit_interval_secs"
            ]
        );
        assert!(result.pending_restart.is_empty());
        assert!(result.rejected.is_empty());

        let server = config.read().await.server.clone();
        assert_eq!(server.rate_limit_interval_secs, 2);
        assert_eq!(server.rate_limit_burst, 30);
        assert_eq!(server.did_log_rate_limit_interval_secs, 3);
        assert_eq!(server.did_log_rate_limit_burst, 600);

        let written = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
        let reloaded: AppConfig = toml::from_str(&written).unwrap();
        assert_eq!(reloaded.server.did_log_rate_limit_burst, 600);
        assert_eq!(reloaded.server.rate_limit_interval_secs, 2);

        // config/show reports them as integers from toml.
        let shown = get_config(&config, &auth, None, "test").await.unwrap();
        let field = shown
            .fields
            .iter()
            .find(|f| f.key == "did_log_rate_limit_burst")
            .unwrap();
        assert_eq!(field.value, serde_json::json!(600));
        assert_eq!(field.source, "toml");
        assert!(!field.requires_restart);
    }

    #[tokio::test]
    async fn out_of_range_rate_limit_is_rejected_and_nothing_written() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let auth = crate::test_support::super_admin_claims();
        let overrides = HashMap::from([
            ("rate_limit_burst".to_string(), serde_json::json!(0)),
            (
                "did_log_rate_limit_interval_secs".to_string(),
                serde_json::json!(1_000_000),
            ),
        ]);
        let result = update_config(&config, &auth, overrides, "test")
            .await
            .unwrap();
        assert!(result.applied.is_empty());
        assert_eq!(result.rejected.len(), 2);
        assert!(
            !dir.path().join("config.toml").exists(),
            "a fully rejected patch writes nothing"
        );
        let server = config.read().await.server.clone();
        assert_eq!(server.rate_limit_burst, 10);
        assert_eq!(server.did_log_rate_limit_interval_secs, 1);
    }

    #[tokio::test]
    async fn rate_limit_patch_requires_super_admin() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let mut auth = crate::test_support::super_admin_claims();
        auth.role = vti_common::acl::Role::Reader;
        let overrides = HashMap::from([("rate_limit_burst".to_string(), serde_json::json!(100))]);
        assert!(
            update_config(&config, &auth, overrides, "test")
                .await
                .is_err()
        );
        assert_eq!(config.read().await.server.rate_limit_burst, 10);
    }

    #[tokio::test]
    async fn show_reports_default_rate_limits_as_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let auth = crate::test_support::super_admin_claims();
        let shown = get_config(&config, &auth, None, "test").await.unwrap();
        let field = shown
            .fields
            .iter()
            .find(|f| f.key == "rate_limit_interval_secs")
            .unwrap();
        assert_eq!(field.value, serde_json::json!(5));
        assert_eq!(field.source, "default");
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
