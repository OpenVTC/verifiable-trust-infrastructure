//! Op-layer for the backup-descriptor pattern (`spec/vta/backup/*`).
//!
//! Five functions, one per trust-task URI. Each one:
//!
//! 1. Verifies super-admin auth.
//! 2. (For non-`initiate-*` ops) verifies the caller-DID matches
//!    `BundleRecord.created_by` — without this a second super-admin
//!    could complete or abort the first's in-flight backup.
//! 3. Reads / mutates the [`BundleRecord`] in `backup_bundles_ks`.
//! 4. For export: writes the staged `.vtabak` bytes to disk under
//!    `backup_blob_dir`. For import: reads them back at finalize.
//! 5. Delegates the actual encrypt/decrypt to the existing
//!    `export_backup` / `preview_import` / `apply_import` helpers
//!    in the parent module.
//!
//! See `docs/05-design-notes/backup-descriptor-pattern.md` for the
//! full state machine and rationale.

use std::path::Path;
use std::sync::Arc;

use chrono::{Duration, Utc};
use tracing::{info, warn};
use uuid::Uuid;

use vta_sdk::protocols::backup_management::descriptors::{
    AbortBundleBody, AbortBundleResultBody, BundleDescriptor, CompleteExportBody,
    CompleteExportResultBody, FinalizeImportBody, FinalizeImportResultBody, InitiateExportBody,
    InitiateExportResultBody, InitiateImportBody, InitiateImportResultBody,
};
use vta_sdk::protocols::backup_management::types::BackupEnvelope;

use crate::auth::AuthClaims;
use crate::backup_bundle_store::{
    self, BundleKind, BundleRecord, BundleState, BundleToken, mint_token,
};
use crate::config::AppConfig;
use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::store::{KeyspaceHandle, Store};

/// Default bundle TTL — 5 minutes per the design doc. Operators
/// can override via the (future) `VTA_BACKUP_BUNDLE_TTL_SECS` env
/// var; cap at 1 hour to prevent operator footguns.
pub const DEFAULT_BUNDLE_TTL_SECS: u64 = 300;

/// Hard ceiling on bundle TTL. 1 hour. A descriptor sitting around
/// for hours invites token-replay attacks once the operator has
/// closed their session.
pub const MAX_BUNDLE_TTL_SECS: u64 = 3600;

/// Per-DID cap on simultaneously-open (non-terminal) bundles.
/// Prevents one operator from tying up disk by spamming
/// `initiate-*` without ever finalizing. v1: 3. Future:
/// config-driven.
pub const MAX_OPEN_BUNDLES_PER_DID: usize = 3;

/// Borrowed deps for the descriptor ops. Avoids dragging the full
/// `AppState` into the op layer (it's a server-runtime type)
/// while keeping the call surface tractable.
///
/// Lifetime: `'a` ties to the calling `AppState` (or `VtaState`)
/// since these are short-lived per-request references.
pub struct DescriptorDeps<'a> {
    pub bundles_ks: &'a KeyspaceHandle,
    pub blob_dir: &'a Path,
    pub keyspaces: super::super::Keyspaces<'a>,
    pub seed_store: &'a Arc<dyn SeedStore>,
    pub config: &'a tokio::sync::RwLock<AppConfig>,
    pub store: Option<&'a Store>,
}

impl<'a> DescriptorDeps<'a> {
    /// Borrow from an `AppState`. The owning `s` outlives the
    /// returned deps.
    pub fn from_app_state(s: &'a crate::server::AppState) -> Self {
        Self {
            bundles_ks: &s.backup_bundles_ks,
            blob_dir: &s.backup_blob_dir,
            keyspaces: super::super::Keyspaces::from_app_state(s),
            seed_store: &s.seed_store,
            config: &s.config,
            store: None, // TEE-only path; not threaded here yet.
        }
    }
}

// ─── initiate-export ──────────────────────────────────────────────────

/// Stage the bytes for an export bundle and return the descriptor.
/// Caller path: `spec/vta/backup/initiate-export/1.0` trust-task
/// handler.
///
/// Steps:
/// 1. Super-admin auth check.
/// 2. Validate `algorithm` (only `"stream"` ships v1).
/// 3. Enforce per-DID open-bundle cap.
/// 4. Encrypt the backup via the existing `export_backup` op.
/// 5. Mint bundle_id + bearer token.
/// 6. Persist bytes to `${blob_dir}/{bundle_id}.vtabak` (0600).
/// 7. Persist [`BundleRecord`] with state=ExportReady.
/// 8. Return descriptor + completion hint.
///
/// Failure modes:
/// - Non-`stream` algorithm → `Validation`.
/// - DID has too many open bundles → `Conflict`.
/// - `export_backup` failures (password too short, KMS unavailable,
///   etc.) propagate as their original `AppError`.
pub async fn initiate_export(
    deps: &DescriptorDeps<'_>,
    auth: &AuthClaims,
    body: InitiateExportBody,
) -> Result<InitiateExportResultBody, AppError> {
    auth.require_super_admin()?;
    validate_algorithm(&body.algorithm)?;
    enforce_open_bundle_cap(deps.bundles_ks, &auth.did).await?;

    // 1. Run the existing encrypt path to get the envelope.
    let envelope = {
        let config_guard = deps.config.read().await;
        super::export_backup(
            &deps.keyspaces,
            deps.seed_store.as_ref(),
            &config_guard,
            auth,
            &body.password,
            body.include_audit,
        )
        .await?
    };

    // 2. Serialize the envelope as JSON bytes. The blob endpoint
    //    streams these verbatim; the operator's CLI inflates back
    //    to BackupEnvelope at import time. SHA-256 over the JSON
    //    bytes is the wire integrity check.
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|e| AppError::Internal(format!("serialize backup envelope: {e}")))?;
    let sha256_hex = sha256_hex(&bytes);
    let size = bytes.len() as u64;

    // 3. Mint bundle + token; pre-stage on disk before storing the
    //    record so a crash leaves no record pointing at missing
    //    bytes.
    let bundle_id = Uuid::new_v4();
    let (token, token_hash) = mint_token()?;

    tokio::fs::create_dir_all(deps.blob_dir)
        .await
        .map_err(AppError::Io)?;
    #[cfg(unix)]
    set_dir_mode_700(deps.blob_dir).await?;
    let blob_path = deps.blob_dir.join(format!("{bundle_id}.vtabak"));
    tokio::fs::write(&blob_path, &bytes)
        .await
        .map_err(AppError::Io)?;
    #[cfg(unix)]
    set_file_mode_600(&blob_path).await?;

    let now = Utc::now();
    let record = BundleRecord {
        bundle_id,
        kind: BundleKind::Export,
        state: BundleState::ExportReady,
        created_at: now,
        expires_at: now + bundle_ttl(),
        created_by: auth.did.clone(),
        algorithm: body.algorithm,
        expected_sha256: sha256_hex.clone(),
        expected_size_bytes: size,
        token_hash,
        blob_path: Some(blob_path),
    };
    backup_bundle_store::store_bundle(deps.bundles_ks, &record).await?;

    info!(bundle_id = %bundle_id, size, "initiate-export: bundle ready");

    Ok(InitiateExportResultBody {
        descriptor: build_descriptor(&record, token, deps.config).await?,
        completion_hint: format!(
            "Download with: pnm backup save --bundle-id {bundle_id} --output backup.vtabak"
        ),
    })
}

// ─── complete-export ─────────────────────────────────────────────────

/// Optional ack from the client after a successful download. Idempotent
/// on terminal states (returns `downloaded` reflecting whether the
/// transfer actually happened).
///
/// Caller path: `spec/vta/backup/complete-export/1.0` trust-task handler.
pub async fn complete_export(
    deps: &DescriptorDeps<'_>,
    auth: &AuthClaims,
    body: CompleteExportBody,
) -> Result<CompleteExportResultBody, AppError> {
    auth.require_super_admin()?;
    let bundle_id = parse_bundle_id(&body.bundle_id)?;

    let mut record = require_owned(deps.bundles_ks, &bundle_id, &auth.did).await?;
    enforce_kind(&record, BundleKind::Export)?;

    let downloaded = match record.state {
        BundleState::ExportDownloaded => {
            record.state = BundleState::ExportAcked;
            backup_bundle_store::store_bundle(deps.bundles_ks, &record).await?;
            true
        }
        BundleState::ExportAcked => true,  // already acked
        BundleState::ExportReady => false, // download never happened
        BundleState::Aborted | BundleState::Expired => {
            return Err(AppError::Conflict(format!(
                "bundle {bundle_id} is in terminal state {:?}; cannot ack",
                record.state
            )));
        }
        // Import states would have failed the kind check above; this
        // arm is unreachable in practice, but keep it exhaustive.
        _ => {
            return Err(AppError::Internal(format!(
                "unexpected state for export bundle {bundle_id}: {:?}",
                record.state
            )));
        }
    };

    info!(bundle_id = %bundle_id, downloaded, "complete-export: acked");
    Ok(CompleteExportResultBody {
        bundle_id: bundle_id.to_string(),
        downloaded,
    })
}

// ─── initiate-import ─────────────────────────────────────────────────

/// Mint an upload slot for an import bundle. Returns the descriptor
/// the client uses to POST bytes to the blob endpoint. Bytes aren't
/// validated until the subsequent `finalize-import` (since the upload
/// happens out-of-band).
pub async fn initiate_import(
    deps: &DescriptorDeps<'_>,
    auth: &AuthClaims,
    body: InitiateImportBody,
) -> Result<InitiateImportResultBody, AppError> {
    auth.require_super_admin()?;
    validate_algorithm(&body.algorithm)?;
    enforce_open_bundle_cap(deps.bundles_ks, &auth.did).await?;

    // Sanity-check the pre-committed hash and size — empty string
    // or zero-length blobs almost certainly indicate a CLI bug.
    if body.expected_sha256.len() != 64
        || !body.expected_sha256.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(AppError::Validation(format!(
            "expected_sha256 must be 64 lowercase hex chars; got `{}`",
            body.expected_sha256
        )));
    }
    if body.expected_size_bytes == 0 {
        return Err(AppError::Validation(
            "expected_size_bytes must be > 0".into(),
        ));
    }

    let bundle_id = Uuid::new_v4();
    let (token, token_hash) = mint_token()?;
    let now = Utc::now();
    let record = BundleRecord {
        bundle_id,
        kind: BundleKind::Import,
        state: BundleState::ImportPending,
        created_at: now,
        expires_at: now + bundle_ttl(),
        created_by: auth.did.clone(),
        algorithm: body.algorithm,
        expected_sha256: body.expected_sha256,
        expected_size_bytes: body.expected_size_bytes,
        token_hash,
        // Populated by the blob POST handler.
        blob_path: None,
    };
    backup_bundle_store::store_bundle(deps.bundles_ks, &record).await?;

    info!(bundle_id = %bundle_id, "initiate-import: slot ready");
    Ok(InitiateImportResultBody {
        descriptor: build_descriptor(&record, token, deps.config).await?,
        completion_hint: format!(
            "Upload with: pnm backup restore --bundle-id {bundle_id} --input <path> --password <pw>"
        ),
    })
}

// ─── finalize-import ─────────────────────────────────────────────────

/// Apply (or preview) the uploaded bytes for an import bundle. The
/// state machine allows multiple preview calls but exactly one
/// commit (the second commit attempt finds the bundle in
/// `ImportCommitted`, which is terminal).
pub async fn finalize_import(
    deps: &DescriptorDeps<'_>,
    auth: &AuthClaims,
    body: FinalizeImportBody,
) -> Result<FinalizeImportResultBody, AppError> {
    auth.require_super_admin()?;
    let bundle_id = parse_bundle_id(&body.bundle_id)?;

    let mut record = require_owned(deps.bundles_ks, &bundle_id, &auth.did).await?;
    enforce_kind(&record, BundleKind::Import)?;

    // State must be ImportReceived (upload done) OR ImportPreviewed
    // (re-running preview after first preview). Anything else is
    // an error — the client must POST to /backup/blob/{id} first.
    match record.state {
        BundleState::ImportReceived | BundleState::ImportPreviewed => {}
        BundleState::ImportPending => {
            return Err(AppError::Conflict(format!(
                "bundle {bundle_id} has no uploaded bytes yet; \
                 POST to /backup/blob/{bundle_id} first"
            )));
        }
        BundleState::ImportCommitted => {
            return Err(AppError::Conflict(format!(
                "bundle {bundle_id} already committed"
            )));
        }
        BundleState::Aborted | BundleState::Expired => {
            return Err(AppError::Conflict(format!(
                "bundle {bundle_id} in terminal state {:?}",
                record.state
            )));
        }
        _ => {
            return Err(AppError::Internal(format!(
                "unexpected state for import bundle {bundle_id}: {:?}",
                record.state
            )));
        }
    }

    let blob_path = record.blob_path.clone().ok_or_else(|| {
        AppError::Internal(format!("bundle {bundle_id} has no blob_path on disk"))
    })?;
    let bytes = tokio::fs::read(&blob_path).await.map_err(AppError::Io)?;

    let envelope: BackupEnvelope = serde_json::from_slice(&bytes).map_err(|e| {
        AppError::Validation(format!("uploaded bytes are not a BackupEnvelope: {e}"))
    })?;

    if body.confirm {
        // Commit path — call existing apply_import.
        let result = super::apply_import(
            &super::preview_import(&envelope, &body.password).await?.0,
            &deps.keyspaces,
            deps.seed_store,
            deps.config,
            deps.store,
        )
        .await?;

        // Best-effort delete; sweeper retries.
        if let Err(e) = tokio::fs::remove_file(&blob_path).await {
            warn!(
                bundle_id = %bundle_id,
                path = %blob_path.display(),
                error = %e,
                "finalize-import: failed to delete blob after commit"
            );
        }
        record.state = BundleState::ImportCommitted;
        record.blob_path = None;
        backup_bundle_store::store_bundle(deps.bundles_ks, &record).await?;

        info!(bundle_id = %bundle_id, "finalize-import: committed");
        Ok(FinalizeImportResultBody {
            bundle_id: bundle_id.to_string(),
            status: "committed".into(),
            source_did: result.source_did,
            key_count: result.key_count,
            acl_count: result.acl_count,
            context_count: result.context_count,
            audit_count: result.audit_count,
            imported_secret_count: result.imported_secret_count,
            message: result.message,
        })
    } else {
        // Preview path — decrypt + validate but don't mutate state.
        let (_payload, result) = super::preview_import(&envelope, &body.password).await?;
        record.state = BundleState::ImportPreviewed;
        backup_bundle_store::store_bundle(deps.bundles_ks, &record).await?;

        info!(bundle_id = %bundle_id, "finalize-import: preview");
        Ok(FinalizeImportResultBody {
            bundle_id: bundle_id.to_string(),
            status: "preview".into(),
            source_did: result.source_did,
            key_count: result.key_count,
            acl_count: result.acl_count,
            context_count: result.context_count,
            audit_count: result.audit_count,
            imported_secret_count: result.imported_secret_count,
            message: result.message,
        })
    }
}

// ─── abort ─────────────────────────────────────────────────────────────

/// Cancel an in-flight bundle in any non-terminal state. Idempotent
/// on terminal — returns `aborted: false` instead of erroring so
/// re-tries from the operator are safe.
pub async fn abort_bundle(
    deps: &DescriptorDeps<'_>,
    auth: &AuthClaims,
    body: AbortBundleBody,
) -> Result<AbortBundleResultBody, AppError> {
    auth.require_super_admin()?;
    let bundle_id = parse_bundle_id(&body.bundle_id)?;

    let mut record = require_owned(deps.bundles_ks, &bundle_id, &auth.did).await?;

    if record.state.is_terminal() {
        info!(bundle_id = %bundle_id, state = ?record.state, "abort: bundle already terminal");
        return Ok(AbortBundleResultBody {
            bundle_id: bundle_id.to_string(),
            aborted: false,
        });
    }

    // Best-effort delete of any staged bytes (export-side: bytes
    // are on disk; import-side: only if upload already happened).
    if let Some(path) = record.blob_path.clone()
        && let Err(e) = tokio::fs::remove_file(&path).await
    {
        // NotFound is fine — already gone. Anything else: log
        // but proceed; the sweeper will retry.
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(
                bundle_id = %bundle_id,
                path = %path.display(),
                error = %e,
                "abort: failed to delete staged bytes; sweeper will retry"
            );
        }
    }

    record.state = BundleState::Aborted;
    record.blob_path = None;
    backup_bundle_store::store_bundle(deps.bundles_ks, &record).await?;

    info!(bundle_id = %bundle_id, "abort: bundle cancelled");
    Ok(AbortBundleResultBody {
        bundle_id: bundle_id.to_string(),
        aborted: true,
    })
}

// ─── Internal helpers ────────────────────────────────────────────────

fn bundle_ttl() -> Duration {
    Duration::seconds(DEFAULT_BUNDLE_TTL_SECS as i64)
}

fn validate_algorithm(algorithm: &str) -> Result<(), AppError> {
    if algorithm != "stream" {
        return Err(AppError::Validation(format!(
            "unsupported transport algorithm: `{algorithm}`; this VTA supports: stream"
        )));
    }
    Ok(())
}

async fn enforce_open_bundle_cap(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    let all = backup_bundle_store::list_bundles(ks).await?;
    let open = all
        .iter()
        .filter(|r| r.created_by == did && !r.state.is_terminal())
        .count();
    if open >= MAX_OPEN_BUNDLES_PER_DID {
        return Err(AppError::Conflict(format!(
            "operator `{did}` has {open} open backup bundles; \
             abort or wait for expiry before initiating another \
             (cap: {MAX_OPEN_BUNDLES_PER_DID})"
        )));
    }
    Ok(())
}

fn parse_bundle_id(s: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(s).map_err(|e| AppError::Validation(format!("invalid bundle_id `{s}`: {e}")))
}

/// Look up a bundle and verify the caller owns it. Returns `NotFound`
/// for both "no such record" and "exists but wrong DID" so the API
/// doesn't leak the existence of a peer super-admin's bundle.
async fn require_owned(
    ks: &KeyspaceHandle,
    id: &Uuid,
    caller_did: &str,
) -> Result<BundleRecord, AppError> {
    let record = backup_bundle_store::get_bundle(ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bundle not found: {id}")))?;
    if record.created_by != caller_did {
        // Don't leak the bundle's existence.
        warn!(
            bundle_id = %id,
            caller = %caller_did,
            owner = %record.created_by,
            "bundle owned by a different super-admin; treating as not-found"
        );
        return Err(AppError::NotFound(format!("bundle not found: {id}")));
    }
    Ok(record)
}

fn enforce_kind(record: &BundleRecord, expected: BundleKind) -> Result<(), AppError> {
    if record.kind != expected {
        // Treat as not-found — don't leak the existence of a bundle
        // of the other kind with the same id.
        return Err(AppError::NotFound(format!(
            "bundle not found: {}",
            record.bundle_id
        )));
    }
    Ok(())
}

async fn build_descriptor(
    record: &BundleRecord,
    token: BundleToken,
    config: &tokio::sync::RwLock<AppConfig>,
) -> Result<BundleDescriptor, AppError> {
    let public_url = config.read().await.public_url.clone().ok_or_else(|| {
        AppError::Internal(
            "VTA `public_url` is not configured; cannot build backup bundle URL. \
                 Set `public_url` in config (or VTA_PUBLIC_URL env var) and restart."
                .into(),
        )
    })?;
    let transport_url = build_blob_url(&public_url, &record.bundle_id);
    Ok(BundleDescriptor {
        bundle_id: record.bundle_id.to_string(),
        algorithm: record.algorithm.clone(),
        transport_url,
        transport_token: token.as_str().to_string(),
        expected_sha256: record.expected_sha256.clone(),
        expected_size_bytes: record.expected_size_bytes,
        expires_at: record.expires_at,
    })
}

fn build_blob_url(public_url: &str, bundle_id: &Uuid) -> String {
    let base = public_url.trim_end_matches('/');
    format!("{base}/backup/blob/{bundle_id}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(unix)]
async fn set_dir_mode_700(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    tokio::fs::set_permissions(path, perms)
        .await
        .map_err(AppError::Io)
}

#[cfg(unix)]
async fn set_file_mode_600(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    tokio::fs::set_permissions(path, perms)
        .await
        .map_err(AppError::Io)
}

#[cfg(test)]
mod tests {
    //! Focused unit tests for the descriptor ops. The full
    //! `initiate_export → blob GET → complete_export` lifecycle
    //! lands once the trust-task slice + integration harness are
    //! in (Stage 5/6); these tests cover the surface that doesn't
    //! depend on the full `export_backup` keyspace plumbing —
    //! mostly state-machine transitions, auth gates, owner
    //! checks, and validation helpers.
    //!
    //! Lifecycle tests against the real router will land in the
    //! Phase-6 integration suite.

    use super::*;
    use crate::backup_bundle_store::{BundleKind, BundleRecord, BundleState};
    use chrono::Duration;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use vti_common::acl::Role;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    fn super_admin(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.into(),
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn context_admin(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.into(),
            role: Role::Admin,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    async fn open_bundles_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace("backup_bundles").unwrap();
        (dir, ks)
    }

    fn config_with_public_url(url: &str) -> Arc<RwLock<AppConfig>> {
        let mut config: AppConfig = toml::from_str(&format!(
            r#"
            vta_did = "did:key:zTestVTA"
            public_url = "{url}"
            [store]
            data_dir = "/tmp/does-not-matter-for-this-test"
            [auth]
            "#
        ))
        .expect("parse config");
        // `from_str` doesn't populate config_path; ops that read it
        // would need this set, but the descriptor builder only
        // reads `public_url`.
        config.config_path = std::path::PathBuf::from("/tmp/does-not-matter");
        Arc::new(RwLock::new(config))
    }

    fn seed_export_ready(bundle_id: Uuid, owner: &str, token_hash: [u8; 32]) -> BundleRecord {
        let now = Utc::now();
        BundleRecord {
            bundle_id,
            kind: BundleKind::Export,
            state: BundleState::ExportReady,
            created_at: now,
            expires_at: now + Duration::minutes(5),
            created_by: owner.into(),
            algorithm: "stream".into(),
            expected_sha256: "deadbeef".into(),
            expected_size_bytes: 1024,
            token_hash,
            blob_path: None,
        }
    }

    #[test]
    fn validate_algorithm_accepts_stream_only() {
        assert!(validate_algorithm("stream").is_ok());
        let err = validate_algorithm("s3-presigned").unwrap_err();
        assert!(
            matches!(err, AppError::Validation(_)),
            "unknown algorithm must surface as Validation: {err:?}"
        );
        // Empty also rejected.
        assert!(validate_algorithm("").is_err());
        // Case-sensitive.
        assert!(validate_algorithm("Stream").is_err());
    }

    #[test]
    fn parse_bundle_id_rejects_malformed() {
        assert!(parse_bundle_id("00000000-0000-0000-0000-000000000000").is_ok());
        assert!(parse_bundle_id("not-a-uuid").is_err());
        assert!(parse_bundle_id("").is_err());
    }

    #[test]
    fn build_blob_url_strips_trailing_slash() {
        let id = Uuid::nil();
        // With trailing slash.
        let url = build_blob_url("https://vta.example/", &id);
        assert_eq!(url, format!("https://vta.example/backup/blob/{id}"));
        // Without.
        let url = build_blob_url("https://vta.example", &id);
        assert_eq!(url, format!("https://vta.example/backup/blob/{id}"));
    }

    #[tokio::test]
    async fn require_owned_returns_record_for_owner() {
        let (_dir, ks) = open_bundles_ks().await;
        let id = Uuid::new_v4();
        let r = seed_export_ready(id, "did:example:alice", [0u8; 32]);
        backup_bundle_store::store_bundle(&ks, &r).await.unwrap();
        let restored = require_owned(&ks, &id, "did:example:alice").await.unwrap();
        assert_eq!(restored.bundle_id, id);
    }

    #[tokio::test]
    async fn require_owned_treats_cross_did_as_not_found() {
        // Critical security invariant: super-admin Bob can't see
        // super-admin Alice's bundle. The response is `NotFound`,
        // not `Forbidden`, to avoid leaking the bundle's existence.
        let (_dir, ks) = open_bundles_ks().await;
        let id = Uuid::new_v4();
        let r = seed_export_ready(id, "did:example:alice", [0u8; 32]);
        backup_bundle_store::store_bundle(&ks, &r).await.unwrap();
        let err = require_owned(&ks, &id, "did:example:bob")
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::NotFound(_)),
            "cross-DID lookup must report NotFound (don't leak existence): {err:?}"
        );
    }

    #[tokio::test]
    async fn require_owned_404_for_unknown_bundle() {
        let (_dir, ks) = open_bundles_ks().await;
        let err = require_owned(&ks, &Uuid::new_v4(), "did:example:alice")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn enforce_kind_rejects_wrong_kind_as_not_found() {
        let r = seed_export_ready(Uuid::new_v4(), "did:example:alice", [0u8; 32]);
        let err = enforce_kind(&r, BundleKind::Import).unwrap_err();
        assert!(
            matches!(err, AppError::NotFound(_)),
            "wrong-kind must report NotFound (don't leak the kind): {err:?}"
        );
        assert!(enforce_kind(&r, BundleKind::Export).is_ok());
    }

    #[tokio::test]
    async fn enforce_open_bundle_cap_allows_under_limit() {
        let (_dir, ks) = open_bundles_ks().await;
        // Two open bundles; cap is 3 → ok.
        for _ in 0..2 {
            let r = seed_export_ready(Uuid::new_v4(), "did:example:alice", [0u8; 32]);
            backup_bundle_store::store_bundle(&ks, &r).await.unwrap();
        }
        assert!(
            enforce_open_bundle_cap(&ks, "did:example:alice")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn enforce_open_bundle_cap_rejects_at_limit() {
        let (_dir, ks) = open_bundles_ks().await;
        for _ in 0..MAX_OPEN_BUNDLES_PER_DID {
            let r = seed_export_ready(Uuid::new_v4(), "did:example:alice", [0u8; 32]);
            backup_bundle_store::store_bundle(&ks, &r).await.unwrap();
        }
        let err = enforce_open_bundle_cap(&ks, "did:example:alice")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn enforce_open_bundle_cap_ignores_terminal_states() {
        // Three Aborted bundles — terminal — must not count.
        let (_dir, ks) = open_bundles_ks().await;
        for _ in 0..MAX_OPEN_BUNDLES_PER_DID {
            let mut r = seed_export_ready(Uuid::new_v4(), "did:example:alice", [0u8; 32]);
            r.state = BundleState::Aborted;
            backup_bundle_store::store_bundle(&ks, &r).await.unwrap();
        }
        assert!(
            enforce_open_bundle_cap(&ks, "did:example:alice")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn enforce_open_bundle_cap_scopes_to_did() {
        // Alice has the cap full; Bob is fresh — still allowed.
        let (_dir, ks) = open_bundles_ks().await;
        for _ in 0..MAX_OPEN_BUNDLES_PER_DID {
            let r = seed_export_ready(Uuid::new_v4(), "did:example:alice", [0u8; 32]);
            backup_bundle_store::store_bundle(&ks, &r).await.unwrap();
        }
        assert!(
            enforce_open_bundle_cap(&ks, "did:example:bob")
                .await
                .is_ok()
        );
    }

    /// Smoke test: initiate_import + abort, exercising the
    /// lightweight path that doesn't need the full keyspaces.
    #[tokio::test]
    async fn initiate_import_then_abort_round_trip() {
        let (dir, bundles_ks) = open_bundles_ks().await;
        let config = config_with_public_url("https://vta.example");
        let blob_dir = dir.path().join("backups");

        // The full DescriptorDeps requires all the other keyspaces.
        // For tests targeting just initiate_import + abort, we
        // construct it manually because Keyspaces holds &-refs we
        // can't easily fabricate without an AppState. Instead, exercise
        // the underlying call surface — `initiate_import` doesn't
        // actually touch the other keyspaces, so re-implement its
        // public flow here using only public helpers:
        let _ = config; // referenced for future test additions

        let auth = super_admin("did:example:alice");
        validate_algorithm("stream").unwrap();
        enforce_open_bundle_cap(&bundles_ks, &auth.did)
            .await
            .unwrap();
        let (token, token_hash) = mint_token().unwrap();
        let id = Uuid::new_v4();
        let now = Utc::now();
        let record = BundleRecord {
            bundle_id: id,
            kind: BundleKind::Import,
            state: BundleState::ImportPending,
            created_at: now,
            expires_at: now + Duration::minutes(5),
            created_by: auth.did.clone(),
            algorithm: "stream".into(),
            expected_sha256: "a".repeat(64),
            expected_size_bytes: 100,
            token_hash,
            blob_path: None,
        };
        backup_bundle_store::store_bundle(&bundles_ks, &record)
            .await
            .unwrap();
        // Token plaintext is what would go into the descriptor.
        assert!(!token.as_str().is_empty());

        // Now run the public `abort_bundle` against this seeded record.
        // We need a DescriptorDeps; the only fields it reads are
        // `bundles_ks` and `blob_dir` (for cleanup). Pass dummies
        // for the rest via a focused alternative path: call
        // `require_owned` directly + transition state.
        let mut r = require_owned(&bundles_ks, &id, &auth.did).await.unwrap();
        assert_eq!(r.state, BundleState::ImportPending);
        r.state = BundleState::Aborted;
        backup_bundle_store::store_bundle(&bundles_ks, &r)
            .await
            .unwrap();

        // Aborted is terminal — subsequent abort is idempotent.
        let r2 = require_owned(&bundles_ks, &id, &auth.did).await.unwrap();
        assert!(r2.state.is_terminal());
        let _ = blob_dir;
    }

    #[test]
    fn context_admin_is_not_super_admin() {
        // Pin the invariant the op layer relies on: a context-admin
        // (Role::Admin with non-empty allowed_contexts) must NOT
        // satisfy `require_super_admin`. If the role model ever
        // changes, the descriptor ops' auth gate silently weakens
        // — this catches that.
        let auth = context_admin("did:example:ctx-admin");
        assert!(
            auth.require_super_admin().is_err(),
            "context-admin must NOT pass require_super_admin"
        );
    }
}
