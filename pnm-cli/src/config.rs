use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PnmConfig {
    /// Slug of the default VTA (used when no --vta flag or PNM_VTA env is set).
    pub default_vta: Option<String>,
    /// Configured VTA targets, keyed by slug.
    #[serde(default)]
    pub vtas: BTreeMap<String, VtaConfig>,

    /// WebSocket URL of an external `affinidi-did-resolver-cache-server`
    /// (e.g. `ws://127.0.0.1:4445/did/v1/ws`). When set, PNM exports it
    /// as `PNM_RESOLVER_URL` at startup and the SDK dispatches every DID
    /// resolution to that server instead of resolving in-process. Useful
    /// when running PNM alongside a VTA pointed at the same server —
    /// both share the cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_url: Option<String>,

    // Legacy field — migrated to vtas on first load.
    #[serde(default, skip_serializing)]
    url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtaConfig {
    pub name: String,
    #[serde(default)]
    pub vta_did: Option<String>,
    /// Explicit REST URL for DIDs that cannot advertise a service endpoint
    /// (e.g. `did:key`). Ignored for `did:webvh` where the URL is derived
    /// from the DID document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Returns `~/.config/pnm/`, creating it if it doesn't exist.
pub fn config_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = dirs::config_dir()
        .ok_or("could not determine config directory")?
        .join("pnm");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

/// Returns `~/.config/pnm/config.toml`.
pub fn config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(config_dir()?.join("config.toml"))
}

/// Load config from `~/.config/pnm/config.toml`. Returns default if missing.
/// Automatically migrates legacy single-VTA config to multi-VTA format.
pub fn load_config() -> Result<PnmConfig, Box<dyn std::error::Error>> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(PnmConfig::default());
    }
    let contents = std::fs::read_to_string(&path)?;
    let mut config: PnmConfig = toml::from_str(&contents)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;

    // Migrate legacy single-URL config. The URL itself is no longer
    // persisted (PNM resolves the REST endpoint at runtime from the VTA's
    // DID document); we just create the slug placeholder so the operator
    // can `pnm setup continue` to bind a VTA DID.
    if config.vtas.is_empty() && config.url.take().is_some() {
        eprintln!("\x1b[33mMigrating legacy config to multi-VTA format...\x1b[0m");
        config.vtas.insert(
            "default".to_string(),
            VtaConfig {
                name: "Default VTA".to_string(),
                vta_did: None,
                url: None,
            },
        );
        config.default_vta = Some("default".to_string());
        save_config(&config)?;
        eprintln!("  Migrated to VTA slug: \x1b[36mdefault\x1b[0m");
        eprintln!("  Run `pnm setup continue default` to bind a VTA DID.");
    }

    Ok(config)
}

/// Save config to `~/.config/pnm/config.toml`.
pub fn save_config(config: &PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path()?;
    let contents =
        toml::to_string_pretty(config).map_err(|e| format!("failed to serialize config: {e}"))?;
    std::fs::write(&path, contents)?;
    Ok(())
}

/// Resolve the active VTA from CLI override, env var, or config default.
///
/// Returns `(slug, &VtaConfig)`.
///
/// Rejects pending-setup slugs with a targeted `pnm setup continue`
/// hint. Invariant: pending ⇔ `VtaConfig.vta_did.is_none()` AND the
/// keyring holds a `PendingVtaBinding` session for the slug. If
/// `vta_did.is_none()` but the keyring entry is missing, the config is
/// orphaned and we fall through to the generic not-configured error.
pub fn resolve_vta<'a>(
    cli_override: Option<&str>,
    config: &'a PnmConfig,
) -> Result<(String, &'a VtaConfig), Box<dyn std::error::Error>> {
    let slug = cli_override
        .map(|s| s.to_string())
        .or_else(|| config.default_vta.clone())
        .ok_or(
            "no VTA specified.\n\n\
             Run `pnm setup` to configure a VTA, or use --vta <name>.",
        )?;

    let vta = config.vtas.get(&slug).ok_or_else(|| {
        format!(
            "VTA '{slug}' not found in config.\n\n\
             Run `pnm vta list` to see configured VTAs."
        )
    })?;

    if vta.vta_did.is_none() && crate::auth::has_pending_vta_binding(&vta_keyring_key(&slug)) {
        return Err(format!(
            "VTA '{slug}' is pending setup — the admin DID has been minted but the VTA DID \
             has not been supplied yet.\n\n\
             Run `pnm setup continue {slug}` once the VTA is running, or\n\
             `pnm setup continue {slug} --vta-did <did:...>` non-interactively."
        )
        .into());
    }

    Ok((slug, vta))
}

/// Build the keyring key for a VTA session.
pub fn vta_keyring_key(slug: &str) -> String {
    format!("vta:{slug}")
}

/// Legacy keyring key (pre-multi-VTA). Used for migration detection.
///
/// `dead_code` allowed: referenced only by the migration path that runs at
/// startup to transfer a single-VTA credential into the multi-VTA keyring
/// layout. Deleting it would break operators upgrading from pre-0.4 pnm.
#[allow(dead_code)]
pub const LEGACY_SESSION_KEY: &str = "vta";

/// Convert a name to a slug (lowercase, spaces → hyphens, non-alphanumeric removed).
pub fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_round_trip() {
        let mut config = PnmConfig {
            default_vta: Some("personal".into()),
            ..Default::default()
        };
        config.vtas.insert(
            "personal".into(),
            VtaConfig {
                name: "Personal VTA".into(),
                vta_did: Some("did:web:vta.example.com".into()),
                url: None,
            },
        );
        config.vtas.insert(
            "work".into(),
            VtaConfig {
                name: "Work VTA".into(),
                vta_did: Some("did:webvh:abc:work.example.com:vta".into()),
                url: None,
            },
        );

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let restored: PnmConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.default_vta.as_deref(), Some("personal"));
        assert_eq!(restored.vtas.len(), 2);
        assert_eq!(restored.vtas["personal"].name, "Personal VTA");
        assert_eq!(
            restored.vtas["personal"].vta_did.as_deref(),
            Some("did:web:vta.example.com")
        );
    }

    /// Existing config files written by older PNM versions carry a per-VTA
    /// `url` field. After the `did:key` URL support, the field is restored
    /// for DIDs that cannot advertise a service endpoint. Legacy configs
    /// with a URL now round-trip correctly.
    #[test]
    fn test_legacy_per_vta_url_is_preserved() {
        let toml_str = r#"
default_vta = "personal"
[vtas.personal]
name = "Personal"
url = "https://vta.example.com"
vta_did = "did:web:vta.example.com"
"#;
        let restored: PnmConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(restored.vtas["personal"].name, "Personal");
        assert_eq!(
            restored.vtas["personal"].url.as_deref(),
            Some("https://vta.example.com")
        );
        assert_eq!(
            restored.vtas["personal"].vta_did.as_deref(),
            Some("did:web:vta.example.com")
        );
    }

    #[test]
    fn test_config_default_is_empty() {
        let config = PnmConfig::default();
        assert!(config.default_vta.is_none());
        assert!(config.vtas.is_empty());
    }

    #[test]
    fn test_config_deserialize_empty_toml() {
        let config: PnmConfig = toml::from_str("").unwrap();
        assert!(config.default_vta.is_none());
        assert!(config.vtas.is_empty());
    }

    #[test]
    fn test_legacy_config_deserialize() {
        let config: PnmConfig = toml::from_str("url = \"https://old.example.com\"").unwrap();
        assert_eq!(config.url.as_deref(), Some("https://old.example.com"));
        assert!(config.vtas.is_empty());
    }

    #[test]
    fn test_resolve_vta_with_override() {
        let mut config = PnmConfig::default();
        config.vtas.insert(
            "personal".into(),
            VtaConfig {
                name: "Personal".into(),
                vta_did: None,
                url: None,
            },
        );
        let (slug, vta) = resolve_vta(Some("personal"), &config).unwrap();
        assert_eq!(slug, "personal");
        assert_eq!(vta.name, "Personal");
    }

    #[test]
    fn test_resolve_vta_with_default() {
        let mut config = PnmConfig {
            default_vta: Some("work".into()),
            ..Default::default()
        };
        config.vtas.insert(
            "work".into(),
            VtaConfig {
                name: "Work".into(),
                vta_did: None,
                url: None,
            },
        );
        let (slug, _) = resolve_vta(None, &config).unwrap();
        assert_eq!(slug, "work");
    }

    #[test]
    fn test_resolve_vta_no_default_fails() {
        let config = PnmConfig::default();
        assert!(resolve_vta(None, &config).is_err());
    }

    #[test]
    fn test_resolve_vta_slug_not_found_fails() {
        let config = PnmConfig {
            default_vta: Some("missing".into()),
            ..Default::default()
        };
        let err = resolve_vta(None, &config).unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn test_vta_keyring_key() {
        assert_eq!(vta_keyring_key("personal"), "vta:personal");
        assert_eq!(vta_keyring_key("work"), "vta:work");
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("My Personal VTA"), "my-personal-vta");
        assert_eq!(slugify("Work VTA #2"), "work-vta-2");
        assert_eq!(slugify("  spaces  "), "spaces");
        assert_eq!(slugify("simple"), "simple");
    }
}
