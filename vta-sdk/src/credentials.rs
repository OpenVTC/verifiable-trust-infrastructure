use serde::{Deserialize, Serialize};

/// A portable credential bundle issued by a VTA for client authentication.
///
/// Post-Phase-5 the canonical transport for this type is
/// [`crate::sealed_transfer`] (HPKE-sealed armored bundle); in-process it is
/// passed as a struct. `serde_json::to_string` / `serde_json::from_str` are
/// the canonical serialization points when a plaintext on-disk form is
/// genuinely needed (e.g. at-rest keyring storage, where the OS already
/// provides confidentiality).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBundle {
    pub did: String,
    #[serde(rename = "privateKeyMultibase")]
    pub private_key_multibase: String,
    #[serde(rename = "vtaDid")]
    pub vta_did: String,
    #[serde(rename = "vtaUrl", default, skip_serializing_if = "Option::is_none")]
    pub vta_url: Option<String>,
}

/// Written by hand so the private key never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for CredentialBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialBundle")
            .field("did", &self.did)
            .field("private_key_multibase", &"<redacted>")
            .field("vta_did", &self.vta_did)
            .field("vta_url", &self.vta_url)
            .finish()
    }
}

impl CredentialBundle {
    /// Create a new credential bundle.
    pub fn new(
        did: impl Into<String>,
        private_key_multibase: impl Into<String>,
        vta_did: impl Into<String>,
    ) -> Self {
        Self {
            did: did.into(),
            private_key_multibase: private_key_multibase.into(),
            vta_did: vta_did.into(),
            vta_url: None,
        }
    }

    /// Set the VTA URL on this bundle.
    pub fn vta_url(mut self, url: impl Into<String>) -> Self {
        self.vta_url = Some(url.into());
        self
    }

    /// Build a [`CredentialBundle`] from a private-key multibase by
    /// deriving its `did:key`.
    ///
    /// Shared between the online path (`vta-cli-common::commands::contexts::credential_from_key`
    /// → `client.get_key_secret` → this helper) and the offline path
    /// (`vta-service::operations::export::credential_from_key_offline`
    /// → local keystore read → this helper). Previously each side had
    /// its own byte-for-byte copy; keeping the derivation in one place
    /// prevents drift if the `did:key` encoding ever changes (e.g.
    /// different multicodec, different multibase alphabet).
    ///
    /// `private_key_multibase` must be an Ed25519 seed (32 raw bytes,
    /// multicodec-prefixed `0x1300` or naked) — the shape every
    /// `get_key_secret` path returns for admin-role keys.
    ///
    /// Returns `(bundle, admin_did)` so the caller can reuse the
    /// derived DID for ACL / audit without re-deriving.
    #[cfg(feature = "sealed-transfer")]
    pub fn from_ed25519_seed_multibase(
        private_key_multibase: &str,
        vta_did: &str,
        vta_url: Option<&str>,
    ) -> Result<(Self, String), crate::did_key::DidKeyError> {
        let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
        let public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let admin_did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&public_key)
        );
        let bundle = Self {
            did: admin_did.clone(),
            private_key_multibase: private_key_multibase.to_string(),
            vta_did: vta_did.to_string(),
            vta_url: vta_url.map(String::from),
        };
        Ok((bundle, admin_did))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_bundle_full() {
        let json = r#"{
            "did": "did:key:z6Mk123",
            "privateKeyMultibase": "z1234567890",
            "vtaDid": "did:key:z6MkVTA",
            "vtaUrl": "https://vta.example.com"
        }"#;
        let bundle: CredentialBundle = serde_json::from_str(json).unwrap();
        assert_eq!(bundle.did, "did:key:z6Mk123");
        assert_eq!(bundle.private_key_multibase, "z1234567890");
        assert_eq!(bundle.vta_did, "did:key:z6MkVTA");
        assert_eq!(bundle.vta_url.as_deref(), Some("https://vta.example.com"));
    }

    #[test]
    fn test_credential_bundle_without_url() {
        let json = r#"{
            "did": "did:key:z6Mk123",
            "privateKeyMultibase": "z1234567890",
            "vtaDid": "did:key:z6MkVTA"
        }"#;
        let bundle: CredentialBundle = serde_json::from_str(json).unwrap();
        assert!(bundle.vta_url.is_none());
    }

    #[test]
    fn test_credential_bundle_missing_did_fails() {
        let json = r#"{
            "privateKeyMultibase": "z1234567890",
            "vtaDid": "did:key:z6MkVTA"
        }"#;
        assert!(serde_json::from_str::<CredentialBundle>(json).is_err());
    }

    #[test]
    fn test_serde_json_roundtrip() {
        let bundle = CredentialBundle {
            did: "did:key:z6Mk123".to_string(),
            private_key_multibase: "z1234567890".to_string(),
            vta_did: "did:key:z6MkVTA".to_string(),
            vta_url: Some("https://vta.example.com".to_string()),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let decoded: CredentialBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.did, bundle.did);
        assert_eq!(decoded.private_key_multibase, bundle.private_key_multibase);
        assert_eq!(decoded.vta_did, bundle.vta_did);
        assert_eq!(decoded.vta_url, bundle.vta_url);
    }

    #[test]
    fn test_serde_json_roundtrip_without_url() {
        let bundle = CredentialBundle {
            did: "did:key:z6Mk123".to_string(),
            private_key_multibase: "z1234567890".to_string(),
            vta_did: "did:key:z6MkVTA".to_string(),
            vta_url: None,
        };
        let json = serde_json::to_string(&bundle).unwrap();
        // vta_url is skipped when None — field must be absent from output.
        assert!(!json.contains("vtaUrl"));
        let decoded: CredentialBundle = serde_json::from_str(&json).unwrap();
        assert!(decoded.vta_url.is_none());
    }
}
