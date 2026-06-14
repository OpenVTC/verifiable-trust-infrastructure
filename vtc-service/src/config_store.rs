//! Three-layer runtime configuration overlay.
//!
//! Implements **M0.8.1** of the VTC MVP Phase 0 plan. Spec §14.6
//! defines the effective-config precedence:
//!
//! ```text
//! effective = env > db_overrides > toml > defaults
//! ```
//!
//! This module owns the **db_overrides** layer (the `config`
//! keyspace) and the merge logic that combines all four layers into
//! the [`EffectiveConfig`] shape the admin endpoints surface.
//!
//! ## What's overlayable
//!
//! Every key the admin UX can `PATCH /v1/admin/config` against is
//! registered in [`REGISTRY`]. Phase 0 ships a small catalog —
//! `server.host`, `server.port`, `log.level`. More keys are added
//! mechanically as later phases introduce the underlying config
//! fields (status-list capacity, audit retention, membership
//! validity, etc.).
//!
//! Keys **not** in the registry are not addressable via PATCH and
//! don't appear in `GET /v1/admin/config`. Operators who need them
//! settable should add a registry entry alongside the field
//! definition.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::config::AppConfig;

const STORAGE_PREFIX: &[u8] = b"config:override:";

fn storage_key(key: &str) -> Vec<u8> {
    let mut out = STORAGE_PREFIX.to_vec();
    out.extend_from_slice(key.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Where the **prior** value came from in the four-layer overlay.
/// Mirrors the variant on `vti_common::audit::ConfigSource` (M0.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    Env,
    Db,
    Toml,
    Default,
}

/// Permitted value shape for a registry entry. The PATCH validator
/// rejects values that don't match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKeyKind {
    /// Free-form string.
    String,
    /// Unsigned integer in `0..=u64::MAX` (PATCH accepts any JSON
    /// number; we coerce + range-check).
    U64,
    /// Restricted set of strings — the value must be one of the
    /// listed variants. Useful for `log.level` ∈ {"trace", "debug",
    /// "info", "warn", "error"}.
    StringEnum(&'static [&'static str]),
    /// String constrained to start with one of the listed prefixes.
    /// The directory-allowlist gate for `server.tls.*` /
    /// `storage.path` (plan §14.6 — sensitive paths can't be
    /// pointed at arbitrary filesystem locations via the UX).
    PathAllowlist(&'static [&'static str]),
}

/// Static metadata for one overlayable config key.
#[derive(Debug, Clone, Copy)]
pub struct ConfigKeyDef {
    /// Dotted path as the admin UX addresses it (e.g. `log.level`).
    pub key: &'static str,
    /// Permitted value shape.
    pub kind: ConfigKeyKind,
    /// `true` when changing this key requires a daemon restart to
    /// take effect (server bind, TLS cert, storage path …). PATCH
    /// still accepts the new value and stores it; the response's
    /// `pending_restart` list flags it for the caller.
    pub requires_restart: bool,
    /// `true` when the key's value should be redacted in audit
    /// events (plan **M0.1.5** ConfigChange::redact_if hook).
    /// Phase 0 has no sensitive keys yet — TLS paths land later
    /// alongside the actual `server.tls.*` config fields.
    pub sensitive: bool,
}

/// The full catalog of UX-settable keys for Phase 0.
///
/// Adding a new key requires:
/// 1. The underlying field on [`crate::config::AppConfig`] (or a
///    sub-struct).
/// 2. An entry here.
/// 3. A new arm in [`compute_effective_value`] that pulls the toml-layer
///    value for the key.
/// 4. A new arm in [`apply_overrides`] that writes a db-layer value
///    back into [`AppConfig`].
///
/// Steps 3 + 4 are mechanical because the registry is small. A
/// future refactor can replace them with serde-driven reflection
/// when the catalog grows past ~20 keys.
pub const REGISTRY: &[ConfigKeyDef] = &[
    ConfigKeyDef {
        key: "server.host",
        kind: ConfigKeyKind::String,
        requires_restart: true,
        sensitive: false,
    },
    ConfigKeyDef {
        key: "server.port",
        kind: ConfigKeyKind::U64,
        requires_restart: true,
        sensitive: false,
    },
    ConfigKeyDef {
        key: "log.level",
        kind: ConfigKeyKind::StringEnum(&["trace", "debug", "info", "warn", "error"]),
        requires_restart: false,
        sensitive: false,
    },
    // The operational RP origin: the WebAuthn relying-party handle +
    // every VMC's `credentialStatus` status-list URL derive from it at
    // boot, so a change needs a restart. Canonical in the db-overlay
    // (P1.1 part 2b) — no longer round-tripped through `config.toml`.
    ConfigKeyDef {
        key: "public_url",
        kind: ConfigKeyKind::String,
        requires_restart: true,
        sensitive: false,
    },
];

/// Look up a key's metadata. `None` means the key is not
/// overlayable.
pub fn lookup(key: &str) -> Option<&'static ConfigKeyDef> {
    REGISTRY.iter().find(|d| d.key == key)
}

// ---------------------------------------------------------------------------
// ConfigStore
// ---------------------------------------------------------------------------

/// Wraps the `config` keyspace with the db-overlay-layer ops.
/// Cheap to clone (handle is `Arc`-shared internally).
#[derive(Clone)]
pub struct ConfigStore {
    ks: KeyspaceHandle,
}

impl ConfigStore {
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self { ks }
    }

    /// Read a single db-layer override, if any.
    pub async fn get(&self, key: &str) -> Result<Option<Value>, AppError> {
        self.ks.get(storage_key(key)).await
    }

    /// Write (insert or replace) a db-layer override.
    pub async fn put(&self, key: &str, value: &Value) -> Result<(), AppError> {
        self.ks.insert(storage_key(key), value).await
    }

    /// Remove a db-layer override. After this call, the effective
    /// value comes from the lower-priority layer (env, toml, or
    /// default).
    pub async fn delete(&self, key: &str) -> Result<(), AppError> {
        self.ks.remove(storage_key(key)).await
    }

    /// Snapshot every db-layer override. Used by
    /// [`compute_effective_config`] to avoid one round-trip per
    /// key during GET.
    pub async fn snapshot(&self) -> Result<HashMap<String, Value>, AppError> {
        let pairs = self.ks.prefix_iter_raw(STORAGE_PREFIX.to_vec()).await?;
        let prefix_len = STORAGE_PREFIX.len();
        let mut out = HashMap::with_capacity(pairs.len());
        for (key_bytes, value_bytes) in pairs {
            let Some(rest) = key_bytes.get(prefix_len..) else {
                continue;
            };
            let Ok(name) = String::from_utf8(rest.to_vec()) else {
                tracing::warn!("skipping non-UTF-8 config-override key");
                continue;
            };
            let Ok(value) = serde_json::from_slice::<Value>(&value_bytes) else {
                tracing::warn!(key = %name, "skipping unparseable config-override value");
                continue;
            };
            out.insert(name, value);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Effective config view
// ---------------------------------------------------------------------------

/// One field in the merged [`EffectiveConfig`] view. Per spec §14.6
/// the admin UX needs both the value and the *source* layer so an
/// operator can tell whether the running value was set in TOML, by
/// an env override, by a PATCH against the DB layer, or fell back
/// to the compiled-in default.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveField {
    pub key: String,
    pub value: Value,
    pub source: ConfigSource,
    pub requires_restart: bool,
}

/// Response shape for `GET /v1/admin/config` — every registry key
/// resolved through the four-layer overlay.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct EffectiveConfig {
    pub fields: Vec<EffectiveField>,
}

/// Pull the TOML-layer value for `key` from `cfg`. Returns `None`
/// when the field is at its compiled-in default (so the merge
/// algorithm can attribute the value to `Default` instead of
/// `Toml`).
///
/// Mechanically maintained: one arm per registry key. See
/// [`REGISTRY`] for the catalog.
fn toml_layer_value(key: &str, cfg: &AppConfig) -> Option<Value> {
    use crate::config::default_host_value;
    use crate::config::default_port_value;
    match key {
        "server.host" => {
            if cfg.server.host == default_host_value() {
                None
            } else {
                Some(Value::String(cfg.server.host.clone()))
            }
        }
        "server.port" => {
            if cfg.server.port == default_port_value() {
                None
            } else {
                Some(Value::Number(serde_json::Number::from(cfg.server.port)))
            }
        }
        "log.level" => {
            // `LogConfig::level` defaults to `"info"`; treat that
            // as the compiled-in default.
            if cfg.log.level == "info" {
                None
            } else {
                Some(Value::String(cfg.log.level.clone()))
            }
        }
        // `public_url` has no compiled-in default — `None` (unset) is the
        // default, so any configured value is the toml-layer value.
        "public_url" => cfg.public_url.clone().map(Value::String),
        _ => None,
    }
}

/// Compiled-in default for `key`. Always returns a value (every
/// registered key has a default).
fn default_layer_value(key: &str) -> Value {
    use crate::config::default_host_value;
    use crate::config::default_port_value;
    match key {
        "server.host" => Value::String(default_host_value()),
        "server.port" => Value::Number(serde_json::Number::from(default_port_value())),
        "log.level" => Value::String("info".into()),
        // No compiled-in default: `null` means "unset" (pre-setup
        // deployment — WebAuthn / status lists deferred).
        "public_url" => Value::Null,
        _ => Value::Null, // unreachable for registry keys
    }
}

/// Env-layer override for `key`, if the operator has set the
/// matching `VTC_*` variable. The names match what
/// [`AppConfig::load`] already consults so the merge view is
/// consistent with what the daemon actually loaded.
fn env_layer_value(key: &str) -> Option<Value> {
    match key {
        "server.host" => std::env::var("VTC_SERVER_HOST").ok().map(Value::String),
        "server.port" => std::env::var("VTC_SERVER_PORT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|n| Value::Number(serde_json::Number::from(n))),
        "log.level" => std::env::var("VTC_LOG_LEVEL").ok().map(Value::String),
        "public_url" => std::env::var("VTC_PUBLIC_URL").ok().map(Value::String),
        _ => None,
    }
}

/// Compute the four-layer-merged view for every registry key.
pub async fn compute_effective_config(
    cfg: &AppConfig,
    db: &ConfigStore,
) -> Result<EffectiveConfig, AppError> {
    let db_snapshot = db.snapshot().await?;
    let mut fields = Vec::with_capacity(REGISTRY.len());

    for def in REGISTRY {
        let (value, source) = if let Some(v) = env_layer_value(def.key) {
            (v, ConfigSource::Env)
        } else if let Some(v) = db_snapshot.get(def.key) {
            (v.clone(), ConfigSource::Db)
        } else if let Some(v) = toml_layer_value(def.key, cfg) {
            (v, ConfigSource::Toml)
        } else {
            (default_layer_value(def.key), ConfigSource::Default)
        };

        fields.push(EffectiveField {
            key: def.key.into(),
            value,
            source,
            requires_restart: def.requires_restart,
        });
    }

    Ok(EffectiveConfig { fields })
}

// ---------------------------------------------------------------------------
// Boot-time override application
// ---------------------------------------------------------------------------

/// Write the resolved (effective) `value` for `key` back into the
/// in-memory [`AppConfig`]. The inverse of [`toml_layer_value`] — one
/// arm per registry key (the step-4 the [`REGISTRY`] doc references).
///
/// A type mismatch is skipped rather than panicked: the value was
/// validated by the PATCH that stored it, so a mismatch here means a
/// corrupt row, and a corrupt row must not take down boot.
fn set_app_config_field(cfg: &mut AppConfig, key: &str, value: &Value) {
    match key {
        "server.host" => {
            if let Some(s) = value.as_str() {
                cfg.server.host = s.to_string();
            }
        }
        "server.port" => match value.as_u64().and_then(|n| u16::try_from(n).ok()) {
            Some(p) => cfg.server.port = p,
            None => tracing::warn!(
                %value,
                "config override `server.port` is not a valid u16 — ignored"
            ),
        },
        "log.level" => {
            if let Some(s) = value.as_str() {
                cfg.log.level = s.to_string();
            }
        }
        // A string sets it; `null` (the default layer, i.e. unset) leaves
        // it `None`. A configured value resolves via `toml_layer_value`,
        // so an absent db override never clears a TOML-set `public_url`.
        "public_url" => {
            cfg.public_url = value.as_str().map(str::to_string);
        }
        _ => {}
    }
}

/// Fold the db-overlay (the `config` keyspace) onto the in-memory
/// [`AppConfig`] at boot, so an operator's runtime PATCHes actually
/// take effect.
///
/// This is the step that makes `config_store` **canonical** (P1.1):
/// without it a `PATCH /v1/admin/config` against a `requires_restart`
/// key (the server bind host/port) is stored but never applied — even
/// after the restart it asks for, because boot read only TOML + env.
/// Resolves every registry key through the same
/// `env > db > toml > default` precedence [`compute_effective_config`]
/// uses, then writes the resolved value back into `cfg`.
///
/// **`log.level` caveat:** the tracing subscriber is initialised from
/// `cfg.log.level` in `main` *before* this runs, so a db-override of
/// `log.level` updates the in-memory config but not the already-live
/// filter — wiring the subscriber reload is the same separate follow-up
/// `reload_config` documents.
pub async fn apply_overrides(cfg: &mut AppConfig, db: &ConfigStore) -> Result<(), AppError> {
    let eff = compute_effective_config(cfg, db).await?;
    for field in eff.fields {
        set_app_config_field(cfg, &field.key, &field.value);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate that `value` matches `def.kind`. Returns a structured
/// `AppError::Validation` on mismatch.
pub fn validate_value(def: &ConfigKeyDef, value: &Value) -> Result<(), AppError> {
    match def.kind {
        ConfigKeyKind::String => {
            if !value.is_string() {
                return Err(AppError::Validation(format!(
                    "{} must be a string",
                    def.key
                )));
            }
            Ok(())
        }
        ConfigKeyKind::U64 => match value.as_u64() {
            Some(_) => Ok(()),
            None => Err(AppError::Validation(format!(
                "{} must be an unsigned integer",
                def.key
            ))),
        },
        ConfigKeyKind::StringEnum(allowed) => {
            let s = value
                .as_str()
                .ok_or_else(|| AppError::Validation(format!("{} must be a string", def.key)))?;
            if allowed.contains(&s) {
                Ok(())
            } else {
                Err(AppError::Validation(format!(
                    "{} must be one of {:?}, got {:?}",
                    def.key, allowed, s
                )))
            }
        }
        ConfigKeyKind::PathAllowlist(prefixes) => {
            let s = value
                .as_str()
                .ok_or_else(|| AppError::Validation(format!("{} must be a string", def.key)))?;
            if prefixes.iter().any(|p| s.starts_with(p)) {
                Ok(())
            } else {
                Err(AppError::Validation(format!(
                    "{} must start with one of {:?}",
                    def.key, prefixes
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn temp_store() -> (ConfigStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let ks = store.keyspace("config-test").expect("ks");
        (ConfigStore::new(ks), dir)
    }

    fn default_app_config() -> AppConfig {
        toml::from_str("").expect("empty TOML parses")
    }

    // ── ConfigStore CRUD ──

    #[tokio::test]
    async fn put_then_get_returns_value() {
        let (store, _dir) = temp_store();
        store.put("log.level", &json!("debug")).await.unwrap();
        let got = store.get("log.level").await.unwrap();
        assert_eq!(got, Some(json!("debug")));
    }

    #[tokio::test]
    async fn delete_removes_value() {
        let (store, _dir) = temp_store();
        store.put("log.level", &json!("debug")).await.unwrap();
        store.delete("log.level").await.unwrap();
        let got = store.get("log.level").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn snapshot_returns_all_overrides() {
        let (store, _dir) = temp_store();
        store.put("log.level", &json!("debug")).await.unwrap();
        store.put("server.host", &json!("10.0.0.1")).await.unwrap();
        let snap = store.snapshot().await.unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get("log.level"), Some(&json!("debug")));
        assert_eq!(snap.get("server.host"), Some(&json!("10.0.0.1")));
    }

    // ── Validation ──

    #[test]
    fn validate_string_kind() {
        let def = lookup("server.host").unwrap();
        assert!(validate_value(def, &json!("0.0.0.0")).is_ok());
        assert!(validate_value(def, &json!(42)).is_err());
    }

    #[test]
    fn validate_u64_kind() {
        let def = lookup("server.port").unwrap();
        assert!(validate_value(def, &json!(8200)).is_ok());
        assert!(validate_value(def, &json!(-1)).is_err());
        assert!(validate_value(def, &json!("8200")).is_err());
    }

    #[test]
    fn validate_string_enum_kind() {
        let def = lookup("log.level").unwrap();
        for lvl in ["trace", "debug", "info", "warn", "error"] {
            assert!(
                validate_value(def, &json!(lvl)).is_ok(),
                "{lvl} should pass"
            );
        }
        assert!(validate_value(def, &json!("verbose")).is_err());
        assert!(validate_value(def, &json!(42)).is_err());
    }

    // ── Effective-config layering ──

    #[tokio::test]
    async fn effective_returns_defaults_when_no_overrides() {
        let (store, _dir) = temp_store();
        let cfg = default_app_config();
        let eff = compute_effective_config(&cfg, &store).await.unwrap();

        let by_key: HashMap<_, _> = eff.fields.iter().map(|f| (&*f.key, f)).collect();
        assert_eq!(by_key["server.host"].source, ConfigSource::Default);
        assert_eq!(by_key["server.host"].value, json!("0.0.0.0"));
        assert_eq!(by_key["server.port"].source, ConfigSource::Default);
        assert_eq!(by_key["server.port"].value, json!(8200));
        assert_eq!(by_key["log.level"].source, ConfigSource::Default);
        assert_eq!(by_key["log.level"].value, json!("info"));
    }

    #[tokio::test]
    async fn db_layer_beats_toml() {
        let (store, _dir) = temp_store();
        let mut cfg = default_app_config();
        cfg.log.level = "debug".into(); // toml-layer override

        // db-layer override wins.
        store.put("log.level", &json!("warn")).await.unwrap();

        let eff = compute_effective_config(&cfg, &store).await.unwrap();
        let f = eff.fields.iter().find(|f| f.key == "log.level").unwrap();
        assert_eq!(f.source, ConfigSource::Db);
        assert_eq!(f.value, json!("warn"));
    }

    #[tokio::test]
    async fn toml_layer_used_when_no_db_override() {
        let (store, _dir) = temp_store();
        let mut cfg = default_app_config();
        cfg.log.level = "debug".into();

        let eff = compute_effective_config(&cfg, &store).await.unwrap();
        let f = eff.fields.iter().find(|f| f.key == "log.level").unwrap();
        assert_eq!(f.source, ConfigSource::Toml);
        assert_eq!(f.value, json!("debug"));
    }

    #[tokio::test]
    async fn requires_restart_flag_propagates_from_registry() {
        let (store, _dir) = temp_store();
        let cfg = default_app_config();
        let eff = compute_effective_config(&cfg, &store).await.unwrap();

        let host = eff.fields.iter().find(|f| f.key == "server.host").unwrap();
        assert!(host.requires_restart);
        let level = eff.fields.iter().find(|f| f.key == "log.level").unwrap();
        assert!(!level.requires_restart);
    }

    // ── apply_overrides (P1.1: boot folds the db overlay onto AppConfig) ──

    #[tokio::test]
    async fn apply_overrides_writes_db_layer_into_config() {
        let (store, _dir) = temp_store();
        let mut cfg = default_app_config();
        assert_eq!(cfg.server.host, "0.0.0.0");
        assert_eq!(cfg.server.port, 8200);

        store.put("server.host", &json!("10.0.0.5")).await.unwrap();
        store.put("server.port", &json!(9100)).await.unwrap();
        store.put("log.level", &json!("debug")).await.unwrap();

        apply_overrides(&mut cfg, &store).await.unwrap();

        assert_eq!(cfg.server.host, "10.0.0.5");
        assert_eq!(cfg.server.port, 9100);
        assert_eq!(cfg.log.level, "debug");
    }

    #[tokio::test]
    async fn apply_overrides_preserves_toml_when_no_db_override() {
        let (store, _dir) = temp_store();
        let mut cfg = default_app_config();
        cfg.server.host = "192.168.1.1".into(); // toml-layer value
        cfg.server.port = 8443;

        apply_overrides(&mut cfg, &store).await.unwrap();

        assert_eq!(cfg.server.host, "192.168.1.1");
        assert_eq!(cfg.server.port, 8443);
    }

    #[tokio::test]
    async fn apply_overrides_db_beats_toml() {
        let (store, _dir) = temp_store();
        let mut cfg = default_app_config();
        cfg.server.port = 8443; // toml-layer
        store.put("server.port", &json!(9100)).await.unwrap();

        apply_overrides(&mut cfg, &store).await.unwrap();

        assert_eq!(cfg.server.port, 9100, "db override must win over toml");
    }

    #[tokio::test]
    async fn apply_overrides_ignores_out_of_range_port() {
        // The U64 registry kind accepts any u64, but the field is u16 —
        // a stored 70000 is a corrupt row and must not be applied.
        let (store, _dir) = temp_store();
        let mut cfg = default_app_config();
        cfg.server.port = 8443;
        store.put("server.port", &json!(70_000)).await.unwrap();

        apply_overrides(&mut cfg, &store).await.unwrap();

        assert_eq!(cfg.server.port, 8443, "out-of-range port override ignored");
    }

    #[tokio::test]
    async fn apply_overrides_public_url_db_beats_toml_and_preserves_toml() {
        let (store, _dir) = temp_store();
        let mut cfg = default_app_config();
        cfg.public_url = Some("https://toml.example".into()); // toml-layer

        // No db override → toml value preserved.
        apply_overrides(&mut cfg, &store).await.unwrap();
        assert_eq!(cfg.public_url.as_deref(), Some("https://toml.example"));

        // db override wins.
        store
            .put("public_url", &json!("https://db.example"))
            .await
            .unwrap();
        apply_overrides(&mut cfg, &store).await.unwrap();
        assert_eq!(cfg.public_url.as_deref(), Some("https://db.example"));
    }

    #[tokio::test]
    async fn apply_overrides_public_url_unset_stays_none() {
        let (store, _dir) = temp_store();
        let mut cfg = default_app_config();
        assert!(cfg.public_url.is_none());
        // No db override + no toml value → default layer (null) → stays None,
        // never spuriously set to an empty string.
        apply_overrides(&mut cfg, &store).await.unwrap();
        assert!(
            cfg.public_url.is_none(),
            "no override → public_url stays unset"
        );
    }
}
