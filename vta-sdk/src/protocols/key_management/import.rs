//! `keys/import/0.1` — hand an externally-created private key to the VTA.

use serde::{Deserialize, Serialize};

use crate::keys::KeyType;

/// Request payload for canonical `keys/import/0.1`.
///
/// Exactly one carrier member conveys the key. The choice between them is a
/// **confidentiality decision, not a formatting one**: `private_key_sealed`
/// and `private_key_jwe` encrypt the material to the VTA, so it is opaque to
/// every intermediary and to the transport itself, while
/// `private_key_multibase` is cleartext and safe only where the transport is
/// end-to-end confidential.
///
/// The trust-task dispatcher **refuses the cleartext carrier outright**, because
/// one dispatcher serves REST, DIDComm and TSP and cannot tell which one carried
/// a given request. The legacy `key-management/1.0/import-key` DIDComm message
/// still accepts it, where authcrypt has already established that guarantee.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImportKeyBody {
    #[serde(alias = "key_type")]
    pub key_type: KeyType,
    /// Armored sealed-transfer bundle carrying the private key, encrypted to
    /// the VTA. The carrier to prefer.
    #[serde(
        default,
        alias = "private_key_sealed",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key_sealed: Option<String>,
    /// JWE compact serialization of the private key, encrypted to the VTA.
    #[serde(
        default,
        alias = "private_key_jwe",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key_jwe: Option<String>,
    /// Raw multibase-encoded private key — **cleartext**. Refused by the
    /// trust-task dispatcher; see the type's documentation.
    #[serde(
        default,
        alias = "private_key_multibase",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key_multibase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, alias = "context_id", skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

// Manual Debug — every carrier field is (or decrypts to) the private key being
// imported. Redact via `{:?}` so no tracing call site or panic-with-debug can
// leak it. Serialize is unchanged.
impl std::fmt::Debug for ImportKeyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportKeyBody")
            .field("key_type", &self.key_type)
            .field(
                "private_key_sealed",
                &self.private_key_sealed.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "private_key_jwe",
                &self.private_key_jwe.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "private_key_multibase",
                &self.private_key_multibase.as_ref().map(|_| "<redacted>"),
            )
            .field("label", &self.label)
            .field("context_id", &self.context_id)
            .finish()
    }
}

/// `keys/import/0.1` response — the realized record under `key`, exactly as
/// `keys/create` answers.
pub use super::create::CreateKeyResponseBody as ImportKeyResponseBody;

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical wire form is camelCase; the pre-fold snake_case spellings
    /// keep deserializing so a producer written against them is not broken by
    /// the fold.
    #[test]
    fn accepts_both_spellings_on_intake() {
        let canonical = serde_json::json!({
            "keyType": "ed25519",
            "privateKeySealed": "-----BEGIN SEALED TRANSFER-----",
            "contextId": "app"
        });
        let body: ImportKeyBody = serde_json::from_value(canonical).unwrap();
        assert_eq!(body.context_id.as_deref(), Some("app"));
        assert!(body.private_key_sealed.is_some());

        let legacy = serde_json::json!({
            "key_type": "ed25519",
            "private_key_sealed": "-----BEGIN SEALED TRANSFER-----",
            "context_id": "app"
        });
        let body: ImportKeyBody = serde_json::from_value(legacy).unwrap();
        assert_eq!(body.context_id.as_deref(), Some("app"));
    }

    /// Emission is canonical regardless of which spelling came in.
    #[test]
    fn emits_camel_case() {
        let body = ImportKeyBody {
            key_type: KeyType::Ed25519,
            private_key_sealed: Some("sealed".into()),
            private_key_jwe: None,
            private_key_multibase: None,
            label: None,
            context_id: Some("app".into()),
        };
        let v = serde_json::to_value(&body).unwrap();
        assert!(v.get("keyType").is_some(), "{v}");
        assert!(v.get("privateKeySealed").is_some(), "{v}");
        assert!(v.get("key_type").is_none(), "{v}");
    }

    /// The redacting Debug is the only thing standing between a private key and
    /// a log line, so it is pinned rather than assumed.
    #[test]
    fn debug_redacts_every_carrier() {
        let body = ImportKeyBody {
            key_type: KeyType::Ed25519,
            private_key_sealed: Some("SEALED-SECRET".into()),
            private_key_jwe: Some("JWE-SECRET".into()),
            private_key_multibase: Some("z-MULTIBASE-SECRET".into()),
            label: None,
            context_id: None,
        };
        let rendered = format!("{body:?}");
        assert!(!rendered.contains("SEALED-SECRET"), "{rendered}");
        assert!(!rendered.contains("JWE-SECRET"), "{rendered}");
        assert!(!rendered.contains("MULTIBASE-SECRET"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
