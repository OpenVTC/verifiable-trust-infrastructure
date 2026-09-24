//! Wire bodies for the backup-descriptor trust-task slice.
//!
//! See `docs/05-design-notes/backup-descriptor-pattern.md` for the
//! full protocol design. Summary: the trust-task envelope carries
//! the control plane (`initiate-{export,import}`, `complete-export`,
//! `finalize-import`, `abort`); the bulk encrypted bytes flow
//! out-of-band over `GET / POST /backup/blob/{bundle_id}`. The
//! `BundleDescriptor` here is the shared shape both `initiate-*`
//! responses return.
//!
//! v1 of this module ships the wire shapes only — the dispatcher
//! match arms, op-layer functions, and blob REST routes land in
//! follow-on commits per the rollout plan in the design doc.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Descriptor returned by `initiate-export` / `initiate-import`.
/// Tells the client where to read or write the bulk bytes, what
/// integrity envelope to expect, and when the slot expires.
///
/// The token is plaintext on the wire — it's freshly minted
/// (random 32 bytes, base64url-encoded), one-shot for GET,
/// short-TTL, and bound to `bundle_id` server-side. Server stores
/// only `SHA-256(token)` so a leaked DB doesn't leak the token.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct BundleDescriptor {
    /// Server-generated UUID v4. Unique to this bundle for its
    /// entire lifecycle.
    #[serde(alias = "bundle_id")]
    pub bundle_id: String,

    /// Transport algorithm. v1 supports only `"stream"`. Future:
    /// `"s3-presigned"`, `"chunked-trust-task"`. The dispatcher
    /// rejects unknown values with `MalformedRequest`.
    pub algorithm: String,

    /// HTTPS URL for the byte transfer. For `stream`, this is the
    /// VTA's `{GET, POST} /backup/blob/{bundle_id}` URL.
    #[serde(alias = "transport_url")]
    pub transport_url: String,

    /// Bearer token for the byte endpoint. Passed in the
    /// `X-Backup-Token` header. Never reused across bundles.
    #[serde(alias = "transport_token")]
    pub transport_token: String,

    /// Hex-encoded SHA-256 of the byte stream. Wire-level integrity
    /// check independent of the encrypted envelope's internal MAC.
    #[serde(alias = "expected_sha256")]
    pub expected_sha256: String,

    /// Total byte count. Lets the recipient pre-allocate buffers
    /// and detect truncated transfers.
    #[serde(alias = "expected_size_bytes")]
    pub expected_size_bytes: u64,

    /// RFC 3339 timestamp after which the bundle is
    /// garbage-collected and the token rejected. Default 5 minutes
    /// from descriptor mint; max 1 hour.
    #[serde(alias = "expires_at")]
    pub expires_at: DateTime<Utc>,
}

/// Written by hand so the bearer token never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for BundleDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleDescriptor")
            .field("bundle_id", &self.bundle_id)
            .field("algorithm", &self.algorithm)
            .field("transport_url", &self.transport_url)
            .field("transport_token", &"<redacted>")
            .field("expected_sha256", &self.expected_sha256)
            .field("expected_size_bytes", &self.expected_size_bytes)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

fn default_stream() -> String {
    "stream".into()
}

fn default_true() -> bool {
    true
}

// ─── Export ──────────────────────────────────────────────────────────────

/// `spec/vta/backup/initiate-export/1.0` payload.
/// Auth: super-admin.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct InitiateExportBody {
    /// Password to derive the AES-256-GCM key (Argon2id KDF).
    /// Minimum length is [`super::MIN_BACKUP_PASSWORD_LEN`], enforced at the
    /// op layer via [`super::validate_backup_password`].
    pub password: String,

    /// Include audit logs in the backup. Default: false.
    #[serde(default, alias = "include_audit")]
    pub include_audit: bool,

    /// Preferred transport algorithm. Defaults to `"stream"`.
    /// Forward-compat hook — the slice rejects unknown values
    /// with `MalformedRequest`.
    #[serde(default = "default_stream")]
    pub algorithm: String,
}

/// Written by hand so the backup password never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for InitiateExportBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiateExportBody")
            .field("password", &"<redacted>")
            .field("include_audit", &self.include_audit)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// `spec/vta/backup/initiate-export/1.0` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct InitiateExportResultBody {
    pub descriptor: BundleDescriptor,

    /// Operator-facing hint the CLI prints so they know how to
    /// complete the download.
    #[serde(alias = "completion_hint")]
    pub completion_hint: String,
}

/// `spec/vta/backup/complete-export/1.0` payload. Optional ack
/// from the client after a successful download.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CompleteExportBody {
    #[serde(alias = "bundle_id")]
    pub bundle_id: String,
}

/// `spec/vta/backup/complete-export/1.0` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CompleteExportResultBody {
    #[serde(alias = "bundle_id")]
    pub bundle_id: String,
    /// True if the byte stream was downloaded before this ack.
    /// False when the operator skipped the download or the bundle
    /// already expired.
    pub downloaded: bool,
}

// ─── Import ──────────────────────────────────────────────────────────────

/// `spec/vta/backup/initiate-import/1.0` payload.
/// Auth: super-admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct InitiateImportBody {
    /// Hex-encoded SHA-256 of the `.vtabak` bytes the client is
    /// about to upload. Pre-committed so the VTA detects tampered
    /// uploads.
    #[serde(alias = "expected_sha256")]
    pub expected_sha256: String,

    /// Byte count of the upcoming upload.
    #[serde(alias = "expected_size_bytes")]
    pub expected_size_bytes: u64,

    /// Preferred transport algorithm. Defaults to `"stream"`.
    #[serde(default = "default_stream")]
    pub algorithm: String,
}

/// `spec/vta/backup/initiate-import/1.0` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct InitiateImportResultBody {
    pub descriptor: BundleDescriptor,
    #[serde(alias = "completion_hint")]
    pub completion_hint: String,
}

/// `spec/vta/backup/finalize-import/1.0` payload. Applies the
/// uploaded bytes after the client has POSTed them to the blob
/// endpoint. Two-phase: `confirm: false` runs validation in preview
/// mode (no state mutation), `confirm: true` commits.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FinalizeImportBody {
    #[serde(alias = "bundle_id")]
    pub bundle_id: String,

    /// Password to derive the AES-256-GCM key. Kept in the
    /// trust-task envelope (authcrypted / bearer-protected); never
    /// sent to the blob endpoint so it doesn't appear in transport
    /// logs.
    pub password: String,

    /// `true` = commit. `false` = preview (validate + report counts
    /// without mutating state). Defaults to `true`.
    #[serde(default = "default_true")]
    pub confirm: bool,

    /// Extension members (SPEC §4.5.1). This agent reads
    /// `ext["org.openvtc"].replaceIdentity` — see
    /// [`FinalizeImportBody::replace_identity`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Written by hand so the backup password never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for FinalizeImportBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalizeImportBody")
            .field("bundle_id", &self.bundle_id)
            .field("password", &"<redacted>")
            .field("confirm", &self.confirm)
            .field("ext", &self.ext)
            .finish()
    }
}

/// The extension namespace this agent's own members live under.
pub const OPENVTC_EXT_NAMESPACE: &str = "org.openvtc";

impl FinalizeImportBody {
    /// Whether the caller allows the restore to replace a *different* identity
    /// the VTA already runs as (`ext["org.openvtc"].replaceIdentity: true`).
    ///
    /// Carried as an extension because the specification's payload has no such
    /// member: it describes the replacement of an agent, and whether this agent
    /// guards against replacing itself with someone else's is its own policy.
    #[must_use]
    pub fn replace_identity(&self) -> bool {
        self.ext
            .as_ref()
            .and_then(|ext| ext.get(OPENVTC_EXT_NAMESPACE))
            .and_then(|ns| ns.get("replaceIdentity"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    /// The `ext` object that asks for [`Self::replace_identity`], or `None`
    /// when it is not asked for (so a default request carries no extension).
    #[must_use]
    pub fn replace_identity_ext(
        replace_identity: bool,
    ) -> Option<serde_json::Map<String, serde_json::Value>> {
        replace_identity.then(|| {
            let mut ext = serde_json::Map::new();
            ext.insert(
                OPENVTC_EXT_NAMESPACE.into(),
                serde_json::json!({ "replaceIdentity": true }),
            );
            ext
        })
    }
}

/// `spec/vta/backup/finalize-import/1.0` response body. The
/// shape mirrors the legacy `ImportResult` minus `status` which
/// becomes a structured `"preview" | "committed"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FinalizeImportResultBody {
    #[serde(alias = "bundle_id")]
    pub bundle_id: String,
    /// `"preview"` or `"committed"`.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none", alias = "source_did")]
    pub source_did: Option<String>,
    #[serde(alias = "key_count")]
    pub key_count: usize,
    #[serde(alias = "acl_count")]
    pub acl_count: usize,
    #[serde(alias = "context_count")]
    pub context_count: usize,
    #[serde(alias = "audit_count")]
    pub audit_count: usize,
    #[serde(default, alias = "imported_secret_count")]
    pub imported_secret_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ─── Abort (shared by export + import) ───────────────────────────────────

/// `spec/vta/backup/abort/1.0` payload. Cancels an in-flight
/// bundle in any non-terminal state. Caller-DID must match
/// `BundleRecord.created_by`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AbortBundleBody {
    #[serde(alias = "bundle_id")]
    pub bundle_id: String,
}

/// `spec/vta/backup/abort/1.0` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AbortBundleResultBody {
    #[serde(alias = "bundle_id")]
    pub bundle_id: String,
    /// True when the abort transitioned a live bundle to
    /// `Aborted`. False if the bundle was already in a terminal
    /// state (treated as idempotent — not an error).
    pub aborted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiate_export_body_round_trips() {
        let body = InitiateExportBody {
            password: "correct-horse-battery-staple".into(),
            include_audit: true,
            algorithm: "stream".into(),
        };
        let json = serde_json::to_string(&body).unwrap();
        let restored: InitiateExportBody = serde_json::from_str(&json).unwrap();
        assert!(restored.include_audit);
        assert_eq!(restored.algorithm, "stream");
    }

    #[test]
    fn algorithm_defaults_to_stream() {
        let body: InitiateExportBody =
            serde_json::from_str(r#"{"password": "twelve-chars"}"#).unwrap();
        assert_eq!(body.algorithm, "stream");
        assert!(!body.include_audit);
    }

    #[test]
    fn finalize_import_confirm_defaults_to_true() {
        let body: FinalizeImportBody =
            serde_json::from_str(r#"{"bundle_id": "abc", "password": "twelve-chars"}"#).unwrap();
        assert!(body.confirm);
        assert!(!body.replace_identity());
    }

    #[test]
    fn replace_identity_rides_the_openvtc_extension() {
        let body = FinalizeImportBody {
            bundle_id: "abc".into(),
            password: "twelve-chars".into(),
            confirm: true,
            ext: FinalizeImportBody::replace_identity_ext(true),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["ext"]["org.openvtc"]["replaceIdentity"], true);
        let back: FinalizeImportBody = serde_json::from_value(json).unwrap();
        assert!(back.replace_identity());
        // Not asked for → no extension on the wire at all.
        assert!(FinalizeImportBody::replace_identity_ext(false).is_none());
    }

    #[test]
    fn descriptor_round_trips() {
        let descriptor = BundleDescriptor {
            bundle_id: "00000000-0000-4000-8000-000000000000".into(),
            algorithm: "stream".into(),
            transport_url: "https://vta.example/backup/blob/00000000-0000-4000-8000-000000000000"
                .into(),
            transport_token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            expected_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .into(),
            expected_size_bytes: 1024,
            expires_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&descriptor).unwrap();
        let restored: BundleDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.bundle_id, descriptor.bundle_id);
        assert_eq!(restored.expected_size_bytes, 1024);
    }
}
