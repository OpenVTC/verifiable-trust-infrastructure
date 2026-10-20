//! `config.toml`: where the service keeps its data, where it listens, and who it is.
//!
//! ```toml
//! data_dir = "/var/lib/vti-voting"
//! listen = "127.0.0.1:8740"          # the HTTPS cast door (terminate TLS in front of it)
//! operator_vta_did = "did:webvh:…"   # the VTA that minted the identity
//!
//! [secrets]                           # where the identity's keys are kept
//! backend = "keyring"
//!
//! [identity]                          # written by `vti-voting-service setup`
//! did = "did:webvh:…"
//! mediator_did = "did:webvh:…"
//! ```
//!
//! With no `[identity]` the service runs as a `did:key` minted into `data_dir`, over HTTPS only:
//! enough for a test, and nothing a community could reach over TSP or DIDComm.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vti_secrets::{SecretBackend, SecretsConfig};

/// The service's configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VotingConfig {
    /// The journal, and (with no `[identity]`) the test identity's seed.
    pub data_dir: PathBuf,
    /// The address the HTTPS binding is served on.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// The VTA that minted `[identity]`. The service answers as an identity of its own, never as
    /// this one (VTI-KEY-007).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_vta_did: Option<String>,
    /// A DID resolver sidecar to resolve through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_url: Option<String>,
    /// Where `[identity]`'s keys are kept.
    #[serde(default)]
    pub secrets: SecretsConfig,
    /// The provisioned identity, reached over TSP and DIDComm at its mediator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ServiceIdentity>,
}

/// The identity a VTA provisioned from the `ballot-box` template.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentity {
    /// The service's DID: what communities name as `ballotBox`.
    pub did: String,
    /// The mediator its DID document names, and its socket connects to.
    pub mediator_did: String,
}

/// The address the HTTPS binding listens on unless configured.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8740";

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

impl VotingConfig {
    /// Read, parse and validate `path`.
    ///
    /// # Errors
    /// If it cannot be read, carries a key this binary does not know, or breaks a rule.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
        Self::from_toml_str(&raw).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }

    /// Parse and validate, refusing an unknown key at any depth: a misspelt setting would
    /// otherwise take its default in silence.
    ///
    /// # Errors
    /// As [`Self::load`].
    pub fn from_toml_str(raw: &str) -> anyhow::Result<Self> {
        let mut ignored = Vec::new();
        let de = toml::Deserializer::parse(raw)?;
        let config: Self = serde_ignored::deserialize(de, |path| ignored.push(path.to_string()))?;
        if !ignored.is_empty() {
            anyhow::bail!("unknown key(s): {}", ignored.join(", "));
        }
        config.validate()?;
        Ok(config)
    }

    /// Every rule, reported together.
    ///
    /// # Errors
    /// Listing each rule broken.
    pub fn validate(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        if matches!(self.secrets.backend, Some(SecretBackend::ConfigSeed)) {
            errors.push(
                "secrets.backend = \"config_seed\" would keep the identity's keys in config.toml"
                    .to_string(),
            );
        }
        if let Some(vta) = &self.operator_vta_did
            && !vta.starts_with("did:")
        {
            errors.push(format!("operator_vta_did must be a DID (got {vta:?})"));
        }
        if let Some(id) = &self.identity {
            for (what, did) in [
                ("identity.did", &id.did),
                ("identity.mediator_did", &id.mediator_did),
            ] {
                if !did.starts_with("did:") {
                    errors.push(format!("{what} must be a DID (got {did:?})"));
                }
            }
            // VTI-KEY-007: a receipt or a head is signed as the service, which is public by
            // design, so it must never be the operator's own durable DID.
            if self.operator_vta_did.as_deref() == Some(id.did.as_str()) {
                errors.push(
                    "identity.did is the operator VTA's own DID; provision one with \
                     `vti-voting-service setup`"
                        .to_string(),
                );
            }
            if id.mediator_did == id.did {
                errors.push("identity.mediator_did is the identity itself, not a mediator".into());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "{} configuration error(s):\n  - {}",
                errors.len(),
                errors.join("\n  - ")
            )
        }
    }

    /// Serialise for writing.
    ///
    /// # Errors
    /// If TOML cannot express it.
    pub fn to_toml_string(&self) -> anyhow::Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_provisioned_configuration_round_trips() {
        let raw = r#"
            data_dir = "/var/lib/vti-voting"
            operator_vta_did = "did:webvh:QmVTA:vta.example.com"

            [secrets]
            backend = "plaintext"

            [identity]
            did = "did:webvh:QmBBX:votes.example.net:b1"
            mediator_did = "did:webvh:QmMED:mediator.example.org:mediator"
        "#;
        let config = VotingConfig::from_toml_str(raw).unwrap();
        assert_eq!(config.listen, DEFAULT_LISTEN);
        let again = VotingConfig::from_toml_str(&config.to_toml_string().unwrap()).unwrap();
        assert_eq!(
            again.identity.unwrap().did,
            "did:webvh:QmBBX:votes.example.net:b1"
        );
    }

    #[test]
    fn an_unknown_key_is_refused_not_ignored() {
        let err = VotingConfig::from_toml_str("data_dir = \"d\"\nlisten_on = \"x\"\n").unwrap_err();
        assert!(err.to_string().contains("listen_on"), "{err}");
    }

    #[test]
    fn the_operators_own_did_is_never_the_service_identity() {
        let raw = r#"
            data_dir = "d"
            operator_vta_did = "did:webvh:QmVTA:vta.example.com"
            [identity]
            did = "did:webvh:QmVTA:vta.example.com"
            mediator_did = "did:webvh:QmMED:m.example.org"
        "#;
        let err = VotingConfig::from_toml_str(raw).unwrap_err();
        assert!(
            err.to_string().contains("VTI-KEY-007")
                || err.to_string().contains("operator VTA's own DID"),
            "{err}"
        );
    }
}
