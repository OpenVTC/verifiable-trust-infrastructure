use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CnmConfig {
    pub default_community: Option<String>,
    pub personal_vta: Option<PersonalVtaConfig>,
    #[serde(default)]
    pub communities: BTreeMap<String, CommunityConfig>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersonalVtaConfig {
    /// VTA DID is the source of truth — the REST endpoint and the
    /// DIDComm mediator are both resolved from the DID document at
    /// runtime.
    #[serde(default)]
    pub vta_did: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommunityConfig {
    pub name: String,
    pub context_id: Option<String>,
    /// VTA DID is the source of truth — see [`PersonalVtaConfig::vta_did`].
    #[serde(default)]
    pub vta_did: Option<String>,
    /// The community's own DID — the VTC's, not its VTA's. Community
    /// administration (`cnm vetting`, `cnm audit`, `cnm backup`) authenticates
    /// to the VTC with this as the audience, and resolves the VTC's API base
    /// from its document. Set with `cnm community set-vtc`; absent in profiles
    /// made before it existed, which then need `--vtc-did`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vtc_did: Option<String>,
}

/// Returns `~/.config/cnm/`, creating it if it doesn't exist.
pub fn config_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = dirs::config_dir()
        .ok_or("could not determine config directory")?
        .join("cnm");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

/// Returns `~/.config/cnm/config.toml`.
pub fn config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(config_dir()?.join("config.toml"))
}

/// Returns `~/.config/cnm/sessions.json`.
#[cfg(all(feature = "config-session", not(feature = "keyring")))]
pub fn sessions_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(config_dir()?.join("sessions.json"))
}

/// Load config from `~/.config/cnm/config.toml`. Returns default if missing.
pub fn load_config() -> Result<CnmConfig, Box<dyn std::error::Error>> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(CnmConfig::default());
    }
    let contents = std::fs::read_to_string(&path)?;
    let config: CnmConfig = toml::from_str(&contents)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
    Ok(config)
}

/// Save config to `~/.config/cnm/config.toml`.
pub fn save_config(config: &CnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path()?;
    let contents =
        toml::to_string_pretty(config).map_err(|e| format!("failed to serialize config: {e}"))?;
    std::fs::write(&path, contents)?;
    Ok(())
}

/// Resolve the active community from CLI override or config default.
///
/// Returns `(slug, &CommunityConfig)`.
pub fn resolve_community<'a>(
    cli_override: Option<&str>,
    config: &'a CnmConfig,
) -> Result<(String, &'a CommunityConfig), Box<dyn std::error::Error>> {
    let slug = cli_override
        .map(|s| s.to_string())
        .or_else(|| config.default_community.clone())
        .ok_or("no community specified.\n\nRun `cnm setup` to configure a community, or use --community <name>.")?;

    let community = config
        .communities
        .get(&slug)
        .ok_or_else(|| format!("community '{slug}' not found in config.\n\nRun `cnm community list` to see configured communities."))?;

    Ok((slug, community))
}

/// Build the keyring key for a community session.
pub fn community_keyring_key(slug: &str) -> String {
    format!("community:{slug}")
}

/// Keyring key for the personal VTA session.
pub const PERSONAL_KEYRING_KEY: &str = "personal";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_round_trip() {
        let mut config = CnmConfig {
            default_community: Some("storm".into()),
            personal_vta: Some(PersonalVtaConfig {
                vta_did: Some("did:webvh:personal.example.com".into()),
            }),
            communities: BTreeMap::new(),
        };
        config.communities.insert(
            "storm".into(),
            CommunityConfig {
                name: "Storm Network".into(),
                context_id: Some("cnm-storm-network".into()),
                vta_did: Some("did:key:z6MkStorm".into()),
                vtc_did: Some("did:webvh:QmStorm:storm.example.com".into()),
            },
        );
        config.communities.insert(
            "acme".into(),
            CommunityConfig {
                name: "Acme Corp".into(),
                context_id: None,
                vta_did: None,
                vtc_did: None,
            },
        );

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let restored: CnmConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.default_community.as_deref(), Some("storm"));
        assert_eq!(
            restored.personal_vta.as_ref().unwrap().vta_did.as_deref(),
            Some("did:webvh:personal.example.com")
        );
        assert_eq!(restored.communities.len(), 2);
        assert_eq!(restored.communities["storm"].name, "Storm Network");
        assert_eq!(restored.communities["acme"].name, "Acme Corp");
        assert!(restored.communities["acme"].context_id.is_none());
        assert_eq!(
            restored.communities["storm"].vtc_did.as_deref(),
            Some("did:webvh:QmStorm:storm.example.com")
        );
        assert!(restored.communities["acme"].vtc_did.is_none());
    }

    /// Older CNM configs persisted `url = "..."` on PersonalVtaConfig and
    /// CommunityConfig. After this change the field is no longer in the
    /// struct; serde silently drops it on deserialize so legacy configs
    /// keep loading. The URL is now derived from the VTA DID at runtime.
    #[test]
    fn test_legacy_url_is_silently_dropped() {
        let toml_str = r#"
default_community = "storm"

[personal_vta]
url = "https://personal.example.com"

[communities.storm]
name = "Storm"
url = "https://vta.storm.ws"
vta_did = "did:key:z6MkStorm"
"#;
        let restored: CnmConfig = toml::from_str(toml_str).unwrap();
        assert!(restored.personal_vta.is_some());
        assert!(restored.personal_vta.unwrap().vta_did.is_none());
        assert_eq!(restored.communities["storm"].name, "Storm");
        assert_eq!(
            restored.communities["storm"].vta_did.as_deref(),
            Some("did:key:z6MkStorm")
        );
    }

    #[test]
    fn test_config_default_is_empty() {
        let config = CnmConfig::default();
        assert!(config.default_community.is_none());
        assert!(config.personal_vta.is_none());
        assert!(config.communities.is_empty());
    }

    #[test]
    fn test_config_deserialize_empty_toml() {
        let config: CnmConfig = toml::from_str("").unwrap();
        assert!(config.default_community.is_none());
        assert!(config.communities.is_empty());
    }

    #[test]
    fn test_resolve_community_with_override() {
        let mut config = CnmConfig::default();
        config.communities.insert(
            "storm".into(),
            CommunityConfig {
                name: "Storm".into(),
                context_id: None,
                vta_did: None,
                vtc_did: None,
            },
        );
        let (slug, community) = resolve_community(Some("storm"), &config).unwrap();
        assert_eq!(slug, "storm");
        assert_eq!(community.name, "Storm");
    }

    #[test]
    fn test_resolve_community_with_default() {
        let mut config = CnmConfig {
            default_community: Some("acme".into()),
            ..Default::default()
        };
        config.communities.insert(
            "acme".into(),
            CommunityConfig {
                name: "Acme".into(),
                context_id: None,
                vta_did: None,
                vtc_did: None,
            },
        );
        let (slug, community) = resolve_community(None, &config).unwrap();
        assert_eq!(slug, "acme");
        assert_eq!(community.name, "Acme");
    }

    #[test]
    fn test_resolve_community_no_default_no_override_fails() {
        let config = CnmConfig::default();
        assert!(resolve_community(None, &config).is_err());
    }

    #[test]
    fn test_resolve_community_slug_not_found_fails() {
        let config = CnmConfig {
            default_community: Some("missing".into()),
            ..Default::default()
        };
        let err = resolve_community(None, &config).unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn test_community_keyring_key() {
        assert_eq!(community_keyring_key("storm"), "community:storm");
        assert_eq!(community_keyring_key("acme"), "community:acme");
    }
}
