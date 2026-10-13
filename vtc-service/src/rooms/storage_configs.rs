//! Storage configs: where this community keeps its rooms' files
//! (`docs/05-design-notes/data-rooms-files.md` §7).
//!
//! A config is a named backend. Every room is assigned to exactly one, which receives its
//! new uploads; every blob remembers the config it was written to
//! ([`vti_rooms::blobs::BlobEntry::config_id`]), so reassigning a room strands nothing.
//! A config is never deleted: `retired` refuses new rooms and uploads, keeps serving
//! reads, and keeps its identifier from ever naming another backend.
//!
//! What this module holds, in the `storage_configs` keyspace (backed up — nothing here
//! is a secret):
//!
//! - `config:<id>` — the config, as the generated `StorageConfig` of
//!   `vtc/storage/configs/*`, parsed through it before every write;
//! - `health:<id>` — the last probe;
//! - `assign:<room hash>` — which config a room's new uploads go to.
//!
//! # Local roots are the operator's to allow
//!
//! A `local` config writes under a directory on this machine. A holder of
//! `vtc.rooms.admin` choosing that directory freely could make the service write
//! wherever its process can — beside its own database, into another config's tree.
//! So a root must lie strictly beneath one of the bases the operator listed in
//! `[rooms.files] local_storage_bases`, after resolving symbolic links, and must not
//! overlap another config's root: one config's collection never reaches another's
//! files. The seeded `local` config is the operator's own `[rooms.files] blob_dir`.
//!
//! # Backends served
//!
//! - `local`.
//! - `s3` with `auth: vta-account`: every object operation is one presigned request
//!   the community's VTA issues for that object alone, under the room's prefix
//!   ([`super::vta_storage`]). The community holds no storage credential.
//!
//! `ambient` and `sealed` auth, `gcs` and `walrus` follow; until they do, a config
//! using them is refused at creation rather than stored and left unusable.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::vtc::storage::configs::create::v0_1 as wire;
use vti_common::blob_store::BlobStore;
use vti_common::blob_store::local::LocalDirStore;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_rooms::blobs::{BlobStores, ConfigHoldings, UploadTarget};

use super::vta_storage::{AccountCheck, VtaStorage};

/// The declared error codes of the storage tasks, read off the generated
/// specifications — what the tests that witness each one compare against.
pub mod codes {
    use trust_tasks_rs::specs::vtc::rooms::storage::assign::v0_1 as assign;
    use trust_tasks_rs::specs::vtc::storage::configs::{
        create::v0_1 as create, get::v0_1 as get, list::v0_1 as list, probe::v0_1 as probe,
        retire::v0_1 as retire, update::v0_1 as update,
    };

    pub const LIST_INVALID_CURSOR: &str = list::error_codes::INVALID_CURSOR.code;
    pub const GET_NOT_FOUND: &str = get::error_codes::NOT_FOUND.code;
    pub const CREATE_EXISTS: &str = create::error_codes::EXISTS.code;
    pub const CREATE_INVALID_SETTINGS: &str = create::error_codes::INVALID_SETTINGS.code;
    pub const CREATE_AUTH_NOT_ALLOWED: &str = create::error_codes::AUTH_NOT_ALLOWED.code;
    pub const UPDATE_NOT_FOUND: &str = update::error_codes::NOT_FOUND.code;
    pub const UPDATE_KIND_IMMUTABLE: &str = update::error_codes::KIND_IMMUTABLE.code;
    pub const UPDATE_LOCATION_IMMUTABLE: &str = update::error_codes::LOCATION_IMMUTABLE.code;
    pub const UPDATE_INVALID_SETTINGS: &str = update::error_codes::INVALID_SETTINGS.code;
    pub const UPDATE_AUTH_NOT_ALLOWED: &str = update::error_codes::AUTH_NOT_ALLOWED.code;
    pub const UPDATE_NOT_ACTIVE: &str = update::error_codes::NOT_ACTIVE.code;
    pub const RETIRE_NOT_FOUND: &str = retire::error_codes::NOT_FOUND.code;
    pub const RETIRE_ROOMS_ASSIGNED: &str = retire::error_codes::ROOMS_ASSIGNED.code;
    pub const RETIRE_IS_DEFAULT: &str = retire::error_codes::IS_DEFAULT.code;
    pub const PROBE_NOT_FOUND: &str = probe::error_codes::NOT_FOUND.code;
    pub const ASSIGN_ROOM_NOT_FOUND: &str = assign::error_codes::ROOM_NOT_FOUND.code;
    pub const ASSIGN_CONFIG_NOT_FOUND: &str = assign::error_codes::CONFIG_NOT_FOUND.code;
    pub const ASSIGN_CONFIG_NOT_ACTIVE: &str = assign::error_codes::CONFIG_NOT_ACTIVE.code;
    pub const CREATE_UNKNOWN_ACCOUNT: &str = create::error_codes::UNKNOWN_ACCOUNT.code;
    pub const UPDATE_UNKNOWN_ACCOUNT: &str = update::error_codes::UNKNOWN_ACCOUNT.code;
    pub const PROBE_CREDENTIAL_REQUIRED: &str = probe::error_codes::CREDENTIAL_REQUIRED.code;
    pub const ASSIGN_CREDENTIAL_REQUIRED: &str = assign::error_codes::CREDENTIAL_REQUIRED.code;
}

/// The config seeded from `[rooms.files] blob_dir` — the one every blob written before
/// configs existed is recorded under.
pub const SEED_CONFIG_ID: &str = "local";

fn config_key(id: &str) -> String {
    format!("config:{id}")
}
fn health_key(id: &str) -> String {
    format!("health:{id}")
}
fn assign_key(room_id: &str) -> String {
    let digest = Sha256::digest(room_id.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("assign:{hex}")
}

/// Which config a room's new uploads go to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    pub room_id: String,
    pub config_id: String,
    pub assigned_at: u64,
    /// Who assigned it: an administrator's DID, or the community's own when it assigned
    /// the default.
    pub assigned_by: String,
}

/// Why proposed settings were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsError {
    /// `invalidSettings`, naming the member.
    Invalid { member: String, reason: String },
    /// `authNotAllowed`.
    AuthNotAllowed(String),
    /// `unknownAccount`: the VTA says the community may use no such account.
    UnknownAccount(String),
}

/// A config's kind, read from its settings.
pub fn kind_of(settings: &Value) -> &str {
    settings.get("kind").and_then(Value::as_str).unwrap_or("")
}

/// A config's state, read from its record.
pub fn state_of(record: &Value) -> &str {
    record.get("state").and_then(Value::as_str).unwrap_or("")
}

/// What a config's credential is, never the credential: the `CredentialState` of
/// `vtc/_shared/0.1/room-storage`.
pub fn credential_state(record: &Value) -> Value {
    match record
        .get("auth")
        .and_then(|a| a.get("mode"))
        .and_then(Value::as_str)
    {
        None => json!({ "status": "none" }),
        Some("vta-account") => json!({
            "status": "vta-account",
            "context": record["auth"]["context"],
            "account": record["auth"]["account"],
        }),
        Some("ambient") => json!({ "status": "ambient" }),
        // No sealed credential is held by this build.
        Some(_) => json!({ "status": "required" }),
    }
}

fn now_secs() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// Refuse a path with `.` or `..` in it: a root is named plainly or not at all. Read
/// off the string, since [`Path::components`] drops a `.` without saying so.
fn plain_absolute(path: &Path) -> bool {
    let Some(s) = path.to_str() else {
        return false;
    };
    path.is_absolute()
        && s.split('/').skip(1).all(|seg| seg != "." && seg != "..")
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// The deepest existing ancestor of `path`, with symbolic links resolved, and the
/// components beneath it that do not exist yet.
fn resolve_existing(path: &Path) -> std::io::Result<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut rest = Vec::new();
    loop {
        match std::fs::canonicalize(&existing) {
            Ok(canon) => {
                let mut out = canon;
                for part in rest.iter().rev() {
                    out.push(part);
                }
                return Ok(out);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = existing.file_name().map(|n| n.to_os_string()) else {
                    return Err(e);
                };
                rest.push(name);
                if !existing.pop() {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Whether two directory trees share any path: one contains the other.
fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// This community's storage configs and room assignments.
pub struct RoomStorage {
    ks: KeyspaceHandle,
    /// The community's DID, recorded as the author of an assignment it makes itself.
    community_did: String,
    /// Where a `local` root may be placed, canonicalized.
    local_bases: Vec<PathBuf>,
    /// One store per config that has one.
    stores: RwLock<HashMap<String, Arc<dyn BlobStore>>>,
    /// The community's link to its VTA, once messaging is up: what a
    /// `vta-account` config's store asks for credentials.
    vta: RwLock<Option<Arc<VtaStorage>>>,
    /// Serialises every write here: the single default, overlap checks and
    /// assignments are read-check-write.
    write_lock: tokio::sync::Mutex<()>,
}

impl RoomStorage {
    /// Open the registry: seed the `local` config from `seed_root` when there is none
    /// yet, assign every room still unassigned to the default, and open a store for
    /// every config.
    ///
    /// `community_did` is recorded as the seeded config's creator; with none (a
    /// community not yet set up) nothing is seeded, and uploads wait for a config.
    pub async fn open(
        ks: KeyspaceHandle,
        rooms_ks: &KeyspaceHandle,
        seed_root: PathBuf,
        local_bases: Vec<PathBuf>,
        community_did: Option<&str>,
    ) -> Result<Arc<Self>, AppError> {
        let mut bases = Vec::with_capacity(local_bases.len());
        for base in local_bases {
            if !plain_absolute(&base) {
                return Err(AppError::Config(format!(
                    "[rooms.files] local_storage_bases: `{}` must be an absolute path with no \
                     `.` or `..`",
                    base.display()
                )));
            }
            tokio::fs::create_dir_all(&base)
                .await
                .map_err(AppError::Io)?;
            #[cfg(unix)]
            vti_common::backup_transfer::set_dir_mode_700(&base).await?;
            bases.push(std::fs::canonicalize(&base).map_err(AppError::Io)?);
        }
        let this = Arc::new(Self {
            ks,
            community_did: community_did.unwrap_or_default().to_string(),
            local_bases: bases,
            stores: RwLock::new(HashMap::new()),
            vta: RwLock::new(None),
            write_lock: tokio::sync::Mutex::new(()),
        });

        if this.configs().await?.is_empty() {
            match community_did {
                Some(did) => this.seed(&seed_root, did).await?,
                None => tracing::warn!(
                    "no community DID yet: the `local` storage config is seeded once there is one"
                ),
            }
        } else if let Some(local) = this.config(SEED_CONFIG_ID).await?
            && local["settings"]["root"].as_str() != seed_root.to_str()
        {
            tracing::warn!(
                stored = %local["settings"]["root"],
                configured = %seed_root.display(),
                "[rooms.files] blob_dir differs from the stored `local` config; the stored \
                 config wins (it is changed with vtc/storage/configs/update)"
            );
        }

        for record in this.configs().await? {
            let id = record["id"].as_str().unwrap_or_default().to_string();
            match this.build_store(&record) {
                Ok(Some(store)) => {
                    this.stores.write().expect("stores lock").insert(id, store);
                }
                Ok(None) => {}
                Err(reason) => {
                    tracing::warn!(config = %id, %reason, "storage config has no usable store")
                }
            }
        }

        if let Some(default) = this.default_id().await? {
            for room in vti_rooms::storage::list_rooms(rooms_ks).await? {
                if this.assignment(&room.room_id).await?.is_none() {
                    this.write_assignment(&room.room_id, &default, &this.community_did)
                        .await?;
                }
            }
        }
        Ok(this)
    }

    async fn seed(&self, root: &Path, community_did: &str) -> Result<(), AppError> {
        let record = json!({
            "id": SEED_CONFIG_ID,
            "label": "This host's disk",
            "settings": { "kind": "local", "root": root.to_string_lossy() },
            "state": "active",
            "isDefault": true,
            "createdBy": community_did,
            "createdAt": chrono::Utc::now().to_rfc3339(),
        });
        checked(&record)?;
        self.ks.insert(config_key(SEED_CONFIG_ID), &record).await?;
        tracing::info!(root = %root.display(), "seeded the `local` storage config");
        Ok(())
    }

    /// The keyspace, for the backup.
    pub fn keyspace(&self) -> &KeyspaceHandle {
        &self.ks
    }

    /// Connect the community's VTA, and build the stores of the configs that use it.
    pub async fn set_vta_storage(&self, link: Arc<VtaStorage>) -> Result<(), AppError> {
        *self.vta.write().expect("vta lock") = Some(link);
        self.reload_stores().await
    }

    fn vta_storage(&self) -> Option<Arc<VtaStorage>> {
        self.vta.read().expect("vta lock").clone()
    }

    /// Rebuild every config's store from the keyspace: after a restore has written it
    /// in place, before the restart the import asks for.
    pub async fn reload_stores(&self) -> Result<(), AppError> {
        let mut fresh = HashMap::new();
        for record in self.configs().await? {
            if let Ok(Some(store)) = self.build_store(&record) {
                fresh.insert(record["id"].as_str().unwrap_or_default().to_string(), store);
            }
        }
        *self.stores.write().expect("stores lock") = fresh;
        Ok(())
    }

    /// Hold this across a read-check-write of configs or assignments.
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.write_lock.lock().await
    }

    /// Every config, `retired` ones included, by identifier.
    pub async fn configs(&self) -> Result<Vec<Value>, AppError> {
        let mut out = Vec::new();
        for (_, raw) in self.ks.prefix_iter_raw(b"config:".to_vec()).await? {
            out.push(serde_json::from_slice::<Value>(&raw)?);
        }
        out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        Ok(out)
    }

    pub async fn config(&self, id: &str) -> Result<Option<Value>, AppError> {
        self.ks.get(config_key(id)).await
    }

    /// The config rooms are assigned to when nothing else names one.
    pub async fn default_id(&self) -> Result<Option<String>, AppError> {
        Ok(self
            .configs()
            .await?
            .into_iter()
            .find(|c| c["isDefault"].as_bool() == Some(true))
            .and_then(|c| c["id"].as_str().map(str::to_string)))
    }

    /// Store a config, after parsing it as the specification's `StorageConfig`, and
    /// rebuild its store. With `isDefault`, the flag leaves every other config in the
    /// same pass. Called under [`Self::lock`].
    pub async fn put_config(&self, record: Value) -> Result<(), AppError> {
        checked(&record)?;
        let id = record["id"].as_str().unwrap_or_default().to_string();
        if record["isDefault"].as_bool() == Some(true) {
            for mut other in self.configs().await? {
                if other["id"].as_str() != Some(&id) && other["isDefault"].as_bool() == Some(true) {
                    if let Some(map) = other.as_object_mut() {
                        map.remove("isDefault");
                    }
                    let other_id = other["id"].as_str().unwrap_or_default().to_string();
                    self.ks.insert(config_key(&other_id), &other).await?;
                }
            }
        }
        let store = self.build_store(&record).map_err(AppError::Validation)?;
        self.ks.insert(config_key(&id), &record).await?;
        let mut stores = self.stores.write().expect("stores lock");
        match store {
            Some(s) => {
                stores.insert(id, s);
            }
            None => {
                stores.remove(&id);
            }
        }
        Ok(())
    }

    /// The store a config writes to, if it has one now.
    pub fn store(&self, id: &str) -> Option<Arc<dyn BlobStore>> {
        self.stores.read().expect("stores lock").get(id).cloned()
    }

    /// Whether a config can authenticate to its backend now.
    pub fn usable(&self, record: &Value) -> bool {
        credential_state(record)["status"] != "required"
            && record["id"]
                .as_str()
                .is_some_and(|id| self.store(id).is_some())
    }

    pub async fn assignment(&self, room_id: &str) -> Result<Option<Assignment>, AppError> {
        self.ks.get(assign_key(room_id)).await
    }

    /// Point `room_id`'s new uploads at `config_id`. Called under [`Self::lock`].
    pub async fn write_assignment(
        &self,
        room_id: &str,
        config_id: &str,
        by: &str,
    ) -> Result<(), AppError> {
        let a = Assignment {
            room_id: room_id.to_string(),
            config_id: config_id.to_string(),
            assigned_at: now_secs(),
            assigned_by: by.to_string(),
        };
        self.ks.insert(assign_key(room_id), &a).await
    }

    /// Assign a newly created room to the default config.
    pub async fn assign_new_room(&self, room_id: &str) -> Result<(), AppError> {
        let _guard = self.lock().await;
        if self.assignment(room_id).await?.is_some() {
            return Ok(());
        }
        if let Some(default) = self.default_id().await? {
            self.write_assignment(room_id, &default, &self.community_did)
                .await?;
        }
        Ok(())
    }

    /// The rooms assigned to `config_id`, by identifier.
    pub async fn rooms_on(&self, config_id: &str) -> Result<Vec<String>, AppError> {
        let mut out = Vec::new();
        for (_, raw) in self.ks.prefix_iter_raw(b"assign:".to_vec()).await? {
            if let Ok(a) = serde_json::from_slice::<Assignment>(&raw)
                && a.config_id == config_id
            {
                out.push(a.room_id);
            }
        }
        out.sort();
        Ok(out)
    }

    /// The last evidence a config works: the `StorageHealth` of
    /// `vtc/_shared/0.1/room-storage`.
    pub async fn health(&self, id: &str) -> Result<Value, AppError> {
        Ok(self
            .ks
            .get::<Value>(health_key(id))
            .await?
            .unwrap_or_else(|| json!({})))
    }

    /// Record a probe's outcome as the config's last probe.
    pub async fn record_probe(
        &self,
        id: &str,
        ok: bool,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        let mut health = self.health(id).await?;
        health["lastProbeAt"] = json!(at.to_rfc3339());
        health["lastProbeOk"] = json!(ok);
        self.ks.insert(health_key(id), &health).await
    }

    /// A config's facts at the time of the read: the `StorageConfigFacts` of
    /// `vtc/_shared/0.1/room-storage`.
    pub async fn facts(
        &self,
        record: &Value,
        holdings: &ConfigHoldings,
    ) -> Result<Value, AppError> {
        let id = record["id"].as_str().unwrap_or_default();
        Ok(json!({
            "rooms": self.rooms_on(id).await?.len(),
            "files": holdings.files,
            "bytes": holdings.bytes,
            "pendingDeleteBytes": holdings.pending_delete_bytes,
            "credential": credential_state(record),
            "health": self.health(id).await?,
        }))
    }

    /// Move every `draining` config whose last blob is gone to `retired`.
    pub async fn settle_draining(
        &self,
        holdings: &HashMap<String, ConfigHoldings>,
    ) -> Result<usize, AppError> {
        let _guard = self.lock().await;
        let mut settled = 0;
        for mut record in self.configs().await? {
            let id = record["id"].as_str().unwrap_or_default().to_string();
            if state_of(&record) == "draining" && holdings.get(&id).is_none_or(|h| h.files == 0) {
                record["state"] = json!("retired");
                self.put_config(record).await?;
                tracing::info!(config = %id, "storage config drained; retired");
                settled += 1;
            }
        }
        Ok(settled)
    }

    /// Check proposed `settings` and `auth` for a config other than `exclude`, beyond
    /// what the schema says (`vtc/storage/configs/create` item 4).
    ///
    /// With `prepare` — when the change is executing, not when it is first asked for —
    /// a `local` root is also created owner-only and written to, so nothing is made on
    /// disk for a request its approvers decline.
    pub async fn validate(
        &self,
        settings: &Value,
        auth: Option<&Value>,
        exclude: Option<&str>,
        prepare: bool,
    ) -> Result<(), SettingsError> {
        match kind_of(settings) {
            "local" => self.validate_local(settings, auth, exclude, prepare).await,
            "s3" => self.validate_s3(settings, auth).await,
            kind => Err(SettingsError::Invalid {
                member: "settings.kind".into(),
                reason: format!(
                    "this community does not store files to `{kind}` yet; `local` and `s3` are \
                     served"
                ),
            }),
        }
    }

    /// An `s3` config: through a VTA account, the one mode served. Asks the VTA
    /// whether the community may use the account here (item 5).
    async fn validate_s3(
        &self,
        settings: &Value,
        auth: Option<&Value>,
    ) -> Result<(), SettingsError> {
        let Some(auth) = auth else {
            return Err(SettingsError::AuthNotAllowed(
                "an `s3` config needs `auth`: the community holds no storage credential of its \
                 own"
                .into(),
            ));
        };
        let mode = auth["mode"].as_str().unwrap_or_default();
        if mode != "vta-account" {
            return Err(SettingsError::Invalid {
                member: "auth.mode".into(),
                reason: format!(
                    "`{mode}` is not served yet; use `vta-account`, an external account at the \
                     community's VTA"
                ),
            });
        }
        let prefix = settings["prefix"].as_str().unwrap_or_default();
        if !prefix.is_empty() && !provider_prefix(prefix) {
            return Err(SettingsError::Invalid {
                member: "settings.prefix".into(),
                reason: "through a VTA account, a prefix is up to 14 segments of lowercase \
                         letters, digits, '.', '_' and '-', each beginning with a letter or \
                         digit and ending in '/'"
                    .into(),
            });
        }
        let Some(link) = self.vta_storage() else {
            return Err(SettingsError::Invalid {
                member: "auth".into(),
                reason: "this community has no link to its VTA: its host's operator sets \
                         `vta_did` in its configuration"
                    .into(),
            });
        };
        let context = auth["context"].as_str().unwrap_or_default();
        let account = auth["account"].as_str().unwrap_or_default();
        match link.check_account(context, account, prefix).await {
            AccountCheck::Usable => Ok(()),
            AccountCheck::Unknown(why) => Err(SettingsError::UnknownAccount(format!(
                "the community's VTA has no account `{account}` in context `{context}` this \
                 community is bound to use: {why}"
            ))),
            AccountCheck::Unfit { member, problem } => Err(SettingsError::Invalid {
                member: member.into(),
                reason: problem,
            }),
            // The account exists for this community; whether it works now is the
            // probe's to say. And an unanswered question is not a refusal (item 5 is
            // a SHOULD).
            AccountCheck::NotReady(why) | AccountCheck::Unconfirmed(why) => {
                tracing::warn!(%account, %why, "storage account not confirmed usable yet");
                Ok(())
            }
        }
    }

    async fn validate_local(
        &self,
        settings: &Value,
        auth: Option<&Value>,
        exclude: Option<&str>,
        prepare: bool,
    ) -> Result<(), SettingsError> {
        if auth.is_some() {
            return Err(SettingsError::AuthNotAllowed(
                "a `local` config writes to this host's own disk and takes no `auth`".into(),
            ));
        }
        let root = PathBuf::from(settings["root"].as_str().unwrap_or_default());
        let invalid = |reason: String| SettingsError::Invalid {
            member: "settings.root".into(),
            reason,
        };
        if !plain_absolute(&root) {
            return Err(invalid(
                "must be an absolute path with no `.` or `..` component".into(),
            ));
        }
        let resolved = resolve_existing(&root)
            .map_err(|e| invalid(format!("cannot be resolved on this host: {e}")))?;
        if !self
            .local_bases
            .iter()
            .any(|b| resolved.starts_with(b) && resolved != *b)
        {
            return Err(invalid(format!(
                "must lie beneath a directory this host's operator allows for room storage \
                 ([rooms.files] local_storage_bases: {})",
                self.local_bases
                    .iter()
                    .map(|b| b.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        for other in self.configs().await.map_err(|e| invalid(e.to_string()))? {
            let id = other["id"].as_str().unwrap_or_default();
            if Some(id) == exclude || kind_of(&other["settings"]) != "local" {
                continue;
            }
            let Some(other_root) = other["settings"]["root"].as_str() else {
                continue;
            };
            let other_root = resolve_existing(Path::new(other_root))
                .unwrap_or_else(|_| PathBuf::from(other_root));
            if overlaps(&resolved, &other_root) {
                return Err(invalid(format!(
                    "overlaps the root of storage config `{id}`; two configs never share files"
                )));
            }
        }
        if !prepare {
            return Ok(());
        }
        // Owner-only, and writable: create it and write a file there now.
        tokio::fs::create_dir_all(&resolved)
            .await
            .map_err(|e| invalid(format!("cannot be created: {e}")))?;
        #[cfg(unix)]
        vti_common::backup_transfer::set_dir_mode_700(&resolved)
            .await
            .map_err(|e| invalid(format!("cannot be made owner-only: {e}")))?;
        let canary = resolved.join(".vtc-write-check");
        tokio::fs::write(&canary, b"ok")
            .await
            .map_err(|e| invalid(format!("is not writable: {e}")))?;
        let _ = tokio::fs::remove_file(&canary).await;
        Ok(())
    }
}

/// Parse a record as the specification's `StorageConfig`: nothing is stored that the
/// tasks could not answer with.
fn checked(record: &Value) -> Result<(), AppError> {
    serde_json::from_value::<wire::StorageConfig>(record.clone())
        .map(|_| ())
        .map_err(|e| AppError::Internal(format!("storage config does not conform: {e}")))
}

impl RoomStorage {
    /// The store a config writes to: `Ok(None)` for a config that has none on this
    /// host now (a kind this build does not serve, or a VTA account with no link to
    /// the VTA yet).
    fn build_store(&self, record: &Value) -> Result<Option<Arc<dyn BlobStore>>, String> {
        let settings = &record["settings"];
        match kind_of(settings) {
            "local" => {
                let root = settings["root"]
                    .as_str()
                    .ok_or("a local config has no root")?;
                Ok(Some(Arc::new(LocalDirStore::new(root))))
            }
            "s3" if record["auth"]["mode"] == "vta-account" => {
                let Some(link) = self.vta_storage() else {
                    return Ok(None);
                };
                let context = record["auth"]["context"]
                    .as_str()
                    .ok_or("a vta-account config names no context")?;
                let account = record["auth"]["account"]
                    .as_str()
                    .ok_or("a vta-account config names no account")?;
                let bucket = settings["bucket"]
                    .as_str()
                    .ok_or("an s3 config names no bucket")?;
                let presigner =
                    link.presigner(context, account, bucket, settings["endpoint"].as_str());
                let store = vti_common::blob_store::presigned::PresignedBlobs::new(
                    "s3",
                    presigner,
                    settings["prefix"].as_str(),
                )
                .map_err(|e| e.to_string())?;
                Ok(Some(Arc::new(store)))
            }
            _ => Ok(None),
        }
    }
}

/// Whether `prefix` is what a VTA account's scope accepts (`ProviderObjectPrefix`):
/// lowercase segments, each ending `/`. Up to 14, leaving two for `rooms/<hash>/`.
fn provider_prefix(prefix: &str) -> bool {
    let Some(body) = prefix.strip_suffix('/') else {
        return false;
    };
    let segments: Vec<&str> = body.split('/').collect();
    segments.len() <= 14
        && segments.iter().all(|seg| {
            let mut chars = seg.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && seg.len() <= 128
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
        })
}

fn unavailable(message: String) -> AppError {
    AppError::ServiceError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message,
    }
}

#[async_trait::async_trait]
impl BlobStores for RoomStorage {
    async fn upload_target(&self, room_id: &str) -> Result<UploadTarget, AppError> {
        let config_id = match self.assignment(room_id).await? {
            Some(a) => a.config_id,
            // A room created before its assignment could be written: the default, and
            // the assignment recorded, so a later change of default does not move it.
            None => {
                let _guard = self.lock().await;
                match self.assignment(room_id).await? {
                    Some(a) => a.config_id,
                    None => {
                        let default = self.default_id().await?.ok_or_else(|| {
                            unavailable("this community has no storage config yet".into())
                        })?;
                        self.write_assignment(room_id, &default, &self.community_did)
                            .await?;
                        default
                    }
                }
            }
        };
        let record = self.config(&config_id).await?.ok_or_else(|| {
            AppError::Internal(format!("room assigned to unknown config `{config_id}`"))
        })?;
        if state_of(&record) != "active" || !self.usable(&record) {
            return Err(unavailable(format!(
                "the storage this room is assigned to (`{config_id}`) accepts no new uploads now"
            )));
        }
        Ok(UploadTarget {
            config_id,
            capacity_bytes: record["capacityBytes"].as_u64(),
        })
    }

    async fn store_for(
        &self,
        config_id: &str,
        _room_id: &str,
    ) -> Result<Arc<dyn BlobStore>, AppError> {
        self.store(config_id).ok_or_else(|| {
            unavailable(format!(
                "storage config `{config_id}` has no usable store on this host now"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_is_named_plainly() {
        assert!(plain_absolute(Path::new("/srv/vtc/rooms")));
        assert!(!plain_absolute(Path::new("srv/vtc")));
        assert!(!plain_absolute(Path::new("/srv/../etc")));
        assert!(!plain_absolute(Path::new("/srv/./vtc")));
    }

    #[test]
    fn nested_trees_overlap_and_siblings_do_not() {
        assert!(overlaps(Path::new("/a/b"), Path::new("/a/b/c")));
        assert!(overlaps(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(overlaps(Path::new("/a/b"), Path::new("/a/b")));
        assert!(!overlaps(Path::new("/a/b"), Path::new("/a/bc")));
        assert!(!overlaps(Path::new("/a/b"), Path::new("/a/c")));
    }

    #[test]
    fn credential_state_never_carries_a_secret() {
        assert_eq!(credential_state(&json!({}))["status"], "none");
        assert_eq!(
            credential_state(&json!({"auth": {"mode": "ambient"}}))["status"],
            "ambient"
        );
        assert_eq!(
            credential_state(&json!({"auth": {"mode": "sealed"}}))["status"],
            "required"
        );
        let vta = credential_state(
            &json!({"auth": {"mode": "vta-account", "context": "community", "account": "eu"}}),
        );
        assert_eq!(
            vta,
            json!({"status": "vta-account", "context": "community", "account": "eu"})
        );
    }

    async fn registry(dir: &Path) -> Arc<RoomStorage> {
        let store = vti_common::store::test_fixture::open_with_keyspaces(
            &dir.join("db"),
            &["storage_configs", "rooms"],
        )
        .unwrap();
        RoomStorage::open(
            store.keyspace("storage_configs").unwrap(),
            &store.keyspace("rooms").unwrap(),
            dir.join("room-blobs"),
            vec![dir.join("room-storage")],
            Some("did:key:zCommunity"),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn the_seeded_config_is_the_default_and_takes_uploads() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        assert_eq!(
            reg.default_id().await.unwrap().as_deref(),
            Some(SEED_CONFIG_ID)
        );
        let t = reg.upload_target("did:key:zRoom").await.unwrap();
        assert_eq!(t.config_id, SEED_CONFIG_ID);
        // The room is pinned: a later default does not move it.
        assert_eq!(
            reg.assignment("did:key:zRoom")
                .await
                .unwrap()
                .unwrap()
                .config_id,
            SEED_CONFIG_ID
        );
    }

    #[tokio::test]
    async fn a_local_root_stays_beneath_the_operators_bases() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let settings = |root: &Path| json!({"kind": "local", "root": root.to_string_lossy()});

        let inside = dir.path().join("room-storage").join("eu");
        reg.validate(&settings(&inside), None, None, true)
            .await
            .unwrap();

        for bad in [
            dir.path().join("elsewhere"),
            dir.path().join("room-storage"),
            dir.path().join("room-storage/../db"),
        ] {
            assert!(
                matches!(
                    reg.validate(&settings(&bad), None, None, true).await,
                    Err(SettingsError::Invalid { .. })
                ),
                "{}",
                bad.display()
            );
        }

        // A symbolic link out of the base is followed, and refused.
        #[cfg(unix)]
        {
            let outside = dir.path().join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            let link = dir.path().join("room-storage").join("link");
            std::os::unix::fs::symlink(&outside, &link).unwrap();
            assert!(matches!(
                reg.validate(&settings(&link.join("x")), None, None, true)
                    .await,
                Err(SettingsError::Invalid { .. })
            ));
        }

        assert!(matches!(
            reg.validate(
                &settings(&inside),
                Some(&json!({"mode": "ambient"})),
                None,
                true
            )
            .await,
            Err(SettingsError::AuthNotAllowed(_))
        ));
        assert!(matches!(
            reg.validate(
                &json!({"kind": "s3", "region": "eu-west-1", "bucket": "abc"}),
                None,
                None,
                true
            )
            .await,
            Err(SettingsError::AuthNotAllowed(_))
        ));
        // Through a VTA account, but this host has no link to its VTA.
        assert!(matches!(
            reg.validate(
                &json!({"kind": "s3", "region": "eu-west-1", "bucket": "abc"}),
                Some(&json!({"mode": "vta-account", "context": "community", "account": "eu"})),
                None,
                true
            )
            .await,
            Err(SettingsError::Invalid { member, .. }) if member == "auth"
        ));
        assert!(matches!(
            reg.validate(&json!({"kind": "gcs", "bucket": "abc"}), None, None, true)
                .await,
            Err(SettingsError::Invalid { member, .. }) if member == "settings.kind"
        ));
    }

    #[test]
    fn a_prefix_through_a_vta_account_is_what_its_scope_accepts() {
        assert!(provider_prefix("community/"));
        assert!(provider_prefix("a/b.c/d-e_f/"));
        for bad in ["Community/", "a", "a//", "/a/", "a*/", "a b/"] {
            assert!(!provider_prefix(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn two_configs_never_share_a_root() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let root = dir.path().join("room-storage").join("eu");
        let record = json!({
            "id": "eu",
            "label": "EU",
            "settings": {"kind": "local", "root": root.to_string_lossy()},
            "state": "active",
            "createdBy": "did:key:zAdmin",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        });
        reg.put_config(record).await.unwrap();
        let nested = json!({"kind": "local", "root": root.join("inner").to_string_lossy()});
        assert!(matches!(
            reg.validate(&nested, None, None, true).await,
            Err(SettingsError::Invalid { .. })
        ));
        // The config itself, re-validated on update, does not overlap with itself.
        let same = json!({"kind": "local", "root": root.to_string_lossy()});
        reg.validate(&same, None, Some("eu"), true).await.unwrap();
    }

    #[tokio::test]
    async fn one_default_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let record = json!({
            "id": "eu",
            "label": "EU",
            "settings": {"kind": "local", "root": dir.path().join("room-storage/eu").to_string_lossy()},
            "state": "active",
            "isDefault": true,
            "createdBy": "did:key:zAdmin",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        });
        reg.put_config(record).await.unwrap();
        assert_eq!(reg.default_id().await.unwrap().as_deref(), Some("eu"));
        let seeded = reg.config(SEED_CONFIG_ID).await.unwrap().unwrap();
        assert!(seeded.get("isDefault").is_none());
    }

    #[tokio::test]
    async fn a_draining_config_retires_when_its_last_blob_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let mut seeded = reg.config(SEED_CONFIG_ID).await.unwrap().unwrap();
        seeded["state"] = json!("draining");
        seeded.as_object_mut().unwrap().remove("isDefault");
        reg.put_config(seeded).await.unwrap();

        let mut held = HashMap::new();
        held.insert(
            SEED_CONFIG_ID.to_string(),
            ConfigHoldings {
                files: 1,
                bytes: 10,
                pending_delete_bytes: 0,
            },
        );
        assert_eq!(reg.settle_draining(&held).await.unwrap(), 0);
        assert_eq!(reg.settle_draining(&HashMap::new()).await.unwrap(), 1);
        let after = reg.config(SEED_CONFIG_ID).await.unwrap().unwrap();
        assert_eq!(state_of(&after), "retired");
    }
}
