use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How the `<path>` segment of a server-managed `did:webvh` is chosen.
///
/// Only meaningful when a hosting server is selected (`server_id` is
/// set). A serverless DID always resolves at
/// `<host>/.well-known/did.jsonl` and ignores this — serverless mode is
/// selected by the *absence* of `server_id`, not by this enum. The three
/// variants map onto the hosting server's `check-name` / `create_did`
/// path contract:
///
/// - [`WebvhPathMode::WellKnown`] → the reserved `.well-known` root slot
///   (`<host>/.well-known/did.jsonl`). Admin-gated on the host.
/// - [`WebvhPathMode::Explicit`] → an operator-chosen label
///   (`<host>/<path>/did.jsonl`).
/// - [`WebvhPathMode::AutoAssign`] → the host allocates a path (it mints
///   a fresh mnemonic). This is the default.
///
/// `AutoAssign` is the default because that is the long-standing
/// "no path given → the server assigns one" contract: the setup wizard's
/// "leave blank → server-assigned" prompt maps a blank path here. An
/// absent path has never meant the `.well-known` root on a hosting
/// server — that is the serverless case (selected by the absence of a
/// `server_id`, where the DID location comes from the `URL` itself).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", content = "path", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum WebvhPathMode {
    /// Root DID at the host: resolves at `<host>/.well-known/did.jsonl`.
    WellKnown,
    /// Operator-chosen path label: `<host>/<path>/did.jsonl`.
    Explicit(String),
    /// Let the hosting server allocate the path.
    #[default]
    AutoAssign,
}

impl WebvhPathMode {
    /// The path string to hand the hosting server's `check-name` /
    /// `create_did` call. `Some(".well-known")` / `Some(label)` reserve a
    /// specific slot; `None` tells the host to allocate one (the
    /// auto-assign contract — the host mints a mnemonic).
    ///
    /// Returning `None` for [`AutoAssign`](WebvhPathMode::AutoAssign) is
    /// load-bearing: the DIDComm/REST clients must *omit* the `path` wire
    /// field for auto-assign. Sending an empty string instead makes the
    /// host reject it with `e.p.did.path-invalid` ("path must not be
    /// empty"), since the host validates a present-but-empty path.
    pub fn to_request_path(&self) -> Option<&str> {
        match self {
            WebvhPathMode::WellKnown => Some(".well-known"),
            WebvhPathMode::Explicit(p) => Some(p),
            WebvhPathMode::AutoAssign => None,
        }
    }

    /// Resolve the effective mode from the new explicit `path_mode` field
    /// and the legacy `path: Option<String>` field. `path_mode` wins when
    /// present; otherwise the legacy `path` is interpreted (via
    /// `From<Option<String>>`) so pre-enum callers keep working.
    pub fn resolve(path_mode: Option<WebvhPathMode>, legacy_path: Option<String>) -> Self {
        path_mode.unwrap_or_else(|| WebvhPathMode::from(legacy_path))
    }
}

impl From<Option<String>> for WebvhPathMode {
    fn from(path: Option<String>) -> Self {
        match path {
            None => WebvhPathMode::AutoAssign,
            Some(p) => WebvhPathMode::from(p),
        }
    }
}

impl From<String> for WebvhPathMode {
    fn from(path: String) -> Self {
        match path.trim() {
            // Empty / whitespace-only is auto-assign, not an explicit
            // empty path — an explicit "" would be rejected by the host.
            "" => WebvhPathMode::AutoAssign,
            ".well-known" => WebvhPathMode::WellKnown,
            trimmed => WebvhPathMode::Explicit(trimmed.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateDidWebvhBody {
    pub context_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Legacy path selector. Prefer [`path_mode`](Self::path_mode) for
    /// new callers — it distinguishes the `.well-known` root, an explicit
    /// label, and server-side auto-assignment. Kept for wire back-compat:
    /// when `path_mode` is absent, this is interpreted as `None`/empty →
    /// auto-assign, `".well-known"` → root, else explicit (see
    /// [`WebvhPathMode::resolve`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Explicit path-selection mode for server-managed DIDs. When set it
    /// overrides [`path`](Self::path). Absent → fall back to `path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_mode: Option<WebvhPathMode>,
    /// Optional explicit hosting domain on the target server. When
    /// the server hosts multiple tenant domains, the caller may
    /// supply this to direct the new DID at a specific one;
    /// otherwise the server resolves via caller's ACL default →
    /// system default. An unknown domain on the server is rejected
    /// with `did-management:unknown_domain`. Ignored in serverless
    /// mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_mediator_service: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_services: Option<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_rotation_count: Option<u32>,
    /// Client-provided DID Document template. When set, the VTA uses this
    /// instead of building the document internally. `{DID}` placeholders are
    /// resolved by `didwebvh-rs`. Mutually exclusive with `did_log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    /// Complete, pre-signed did.jsonl log entry. When set, the VTA publishes
    /// it as-is without deriving keys or creating a log entry. Mutually
    /// exclusive with `did_document`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_log: Option<String>,
    /// Whether to set this DID as the primary DID for the context.
    /// Defaults to `true` for backwards compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_primary: Option<bool>,
    /// Use an existing key as the signing (Ed25519) verification method.
    /// When set, the VTA skips key derivation and uses this key instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    /// Use an existing key as the key-agreement (X25519) verification method.
    /// Required when the DID document includes DIDCommMessaging services.
    /// Requires `signing_key_id` to also be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ka_key_id: Option<String>,
    /// Stored DID template name to render as the DID document. Mutually
    /// exclusive with `did_document` and `did_log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Scope to look the template up in. `None` means "global only"; `Some(ctx)`
    /// means "this context first, then global, then builtin".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_context: Option<String>,
    /// Caller-supplied template variables. Server injects `DID`,
    /// `SIGNING_KEY_MB`, `KA_KEY_MB`, `VTA_DID`, `VTA_URL`, `CONTEXT_ID`,
    /// `CONTEXT_DID`, `NOW` automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_vars: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateDidWebvhResultBody {
    pub did: String,
    pub context_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    pub scid: String,
    pub portable: bool,
    pub signing_key_id: String,
    pub ka_key_id: String,
    pub pre_rotation_key_count: u32,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_entry: Option<String>,
}

// Manual Debug — `mnemonic` is a 24-word BIP-39 phrase that recovers
// the entire key hierarchy under the DID. Logging it via `{:?}` is a
// total compromise. Serialize is unchanged so the wire shape and
// sealed-transfer payload still round-trip.
impl std::fmt::Debug for CreateDidWebvhResultBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateDidWebvhResultBody")
            .field("did", &self.did)
            .field("context_id", &self.context_id)
            .field("server_id", &self.server_id)
            .field("mnemonic", &self.mnemonic.as_ref().map(|_| "<redacted>"))
            .field("scid", &self.scid)
            .field("portable", &self.portable)
            .field("signing_key_id", &self.signing_key_id)
            .field("ka_key_id", &self.ka_key_id)
            .field("pre_rotation_key_count", &self.pre_rotation_key_count)
            .field("created_at", &self.created_at)
            .field("did_document", &self.did_document)
            .field("log_entry", &self.log_entry)
            .finish()
    }
}

#[cfg(test)]
mod webvh_path_mode_tests {
    use super::WebvhPathMode;

    /// The wire path the host's `check-name`/`create_did` receives.
    /// `AutoAssign → None` is load-bearing: the clients omit the field,
    /// which is the only form the host treats as "allocate one for me".
    #[test]
    fn to_request_path_maps_each_mode() {
        assert_eq!(
            WebvhPathMode::WellKnown.to_request_path(),
            Some(".well-known")
        );
        assert_eq!(
            WebvhPathMode::Explicit("alice".into()).to_request_path(),
            Some("alice")
        );
        assert_eq!(WebvhPathMode::AutoAssign.to_request_path(), None);
    }

    /// Default is auto-assign — the long-standing "no path → server
    /// assigns one" contract. An absent path has never meant `.well-known`.
    #[test]
    fn default_is_auto_assign() {
        assert_eq!(WebvhPathMode::default(), WebvhPathMode::AutoAssign);
    }

    /// Legacy `path: Option<String>` interpretation: None/empty →
    /// auto-assign, `.well-known` → root, else explicit (trimmed).
    #[test]
    fn from_legacy_path() {
        assert_eq!(WebvhPathMode::from(None), WebvhPathMode::AutoAssign);
        assert_eq!(
            WebvhPathMode::from(Some("   ".to_string())),
            WebvhPathMode::AutoAssign
        );
        assert_eq!(
            WebvhPathMode::from(Some(".well-known".to_string())),
            WebvhPathMode::WellKnown
        );
        assert_eq!(
            WebvhPathMode::from(Some("  alice ".to_string())),
            WebvhPathMode::Explicit("alice".into())
        );
    }

    /// `resolve`: explicit `path_mode` wins; otherwise fall back to the
    /// legacy `path`.
    #[test]
    fn resolve_prefers_explicit_mode() {
        // Explicit mode set → legacy path ignored.
        assert_eq!(
            WebvhPathMode::resolve(Some(WebvhPathMode::AutoAssign), Some("alice".into())),
            WebvhPathMode::AutoAssign
        );
        // No mode → interpret legacy path.
        assert_eq!(
            WebvhPathMode::resolve(None, Some("alice".into())),
            WebvhPathMode::Explicit("alice".into())
        );
        assert_eq!(
            WebvhPathMode::resolve(None, None),
            WebvhPathMode::AutoAssign
        );
    }

    /// Adjacently-tagged serde shape, and that it round-trips.
    #[test]
    fn serde_round_trips() {
        for mode in [
            WebvhPathMode::WellKnown,
            WebvhPathMode::Explicit("alice".into()),
            WebvhPathMode::AutoAssign,
        ] {
            let json = serde_json::to_value(&mode).unwrap();
            let back: WebvhPathMode = serde_json::from_value(json).unwrap();
            assert_eq!(mode, back);
        }
        // Pin the explicit wire shape.
        assert_eq!(
            serde_json::to_value(WebvhPathMode::Explicit("alice".into())).unwrap(),
            serde_json::json!({ "mode": "explicit", "path": "alice" })
        );
        assert_eq!(
            serde_json::to_value(WebvhPathMode::AutoAssign).unwrap(),
            serde_json::json!({ "mode": "auto_assign" })
        );
    }
}
