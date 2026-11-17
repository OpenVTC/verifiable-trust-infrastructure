//! Community logo — an image the community stores and serves from its own
//! origin (`vtc/community/logo/update/0.1`, read with
//! `vtc/community/logo/show/0.1` and served at [`LOGO_PATH`]).
//!
//! Why the community holds the bytes: its console, member portal and default
//! landing page are served with `img-src 'self' data:`, so a logo named by the
//! profile's `logoUrl` at another host is never drawn. A deployment with no
//! other place on its own origin to put a file had no logo at all. This is
//! separate state from `logoUrl`, which stays an address for readers that fetch
//! from anywhere; the pages prefer this one (`PublicCommunityProfile::logo`).
//!
//! **Re-encoded, never stored as sent** (update item 4):
//! [`crate::directory::images::reencode_logo`] decodes strictly as the declared
//! type within bounds and writes a fresh PNG, so no metadata, no trailing
//! polyglot payload and no byte the administrator sent survives.
//!
//! Two rows in the `community` keyspace, backed up with the profile:
//! [`LOGO_RECORD_KEY`] ([`LogoRecord`]) and [`LOGO_BYTES_KEY`] (the bytes),
//! always written in one batch. Removal keeps the record (with no logo) so
//! `updatedAt` still answers when it was removed.
//!
//! **One address, served from memory.** The logo is served at one URL that
//! does not change across updates (update item 9's SHOULD), revalidated by an
//! `ETag` of its digest. Every reader — the route, the public profile, the
//! member portal and `logo/show` — goes through [`LogoState::snapshot`], which
//! loads the record and bytes once, checks the bytes against the record, and
//! keeps the result until an update or a backup import
//! ([`LogoState::invalidate`]) changes what is stored. Bytes whose digest does
//! not match their record, or a record naming a media type outside
//! [`MEDIA_TYPES`], are never served — and never advertised, so a page that
//! cannot draw the stored logo falls back to `logoUrl` rather than a broken
//! image.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

/// The logo's record in the `community` keyspace.
pub const LOGO_RECORD_KEY: &[u8] = b"community/logo";

/// The stored bytes, beside [`LOGO_RECORD_KEY`].
pub const LOGO_BYTES_KEY: &[u8] = b"community/logo/bytes";

/// Where the community serves its logo, from the site root. The same across
/// updates (update item 9).
pub const LOGO_PATH: &str = "/v1/community/logo";

/// The media types a stored logo may have (`LogoMediaType`). The route answers
/// its `Content-Type` from this list, never from the record's own string.
pub const MEDIA_TYPES: [&str; 3] = ["image/png", "image/jpeg", "image/webp"];

/// Updates one administrator may send per hour (update item 5).
pub const UPDATES_PER_HOUR: usize = 20;

/// How often a load retries when the record changes between its two reads.
const LOAD_ATTEMPTS: usize = 3;

/// The stored logo as its record names it. A storage record, not a wire
/// type: the tasks answer it as their generated `LogoRef` ([`logo_ref!`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogoMeta {
    /// Lowercase hex SHA-256 of the stored bytes.
    pub sha256: String,
    pub media_type: String,
    pub size: u32,
    pub width: u32,
    pub height: u32,
}

impl LogoMeta {
    /// Whether the record is one the route may serve: a digest of the shape
    /// it writes, a media type from [`MEDIA_TYPES`], and sizes a `LogoRef`
    /// can carry.
    fn well_formed(&self) -> bool {
        self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && MEDIA_TYPES.contains(&self.media_type.as_str())
            && self.size > 0
            && self.width > 0
            && self.height > 0
    }
}

/// The absolute `https` URL the logo is served at, for a `LogoRef`'s `url`
/// (update item 9): [`LOGO_PATH`] under the community's `public_url`. `None`
/// when the community has no `https` public URL — a `LogoRef` then omits
/// `url`, as the schema allows, rather than name an address a reader elsewhere
/// cannot resolve.
#[must_use]
pub fn logo_url(public_url: Option<&str>) -> Option<String> {
    let base = public_url?.trim().trim_end_matches('/');
    base.strip_prefix("https://")
        .filter(|host| !host.is_empty())
        .map(|_| format!("{base}{LOGO_PATH}"))
}

/// A task's generated `LogoRef` (`$ty`) for `meta`, served at `url`. A macro
/// because `logo/update` and `logo/show` each generate their own (identical)
/// type.
macro_rules! logo_ref {
    ($ty:ty, $meta:expr, $url:expr) => {{
        let meta: &$crate::community::logo::LogoMeta = $meta;
        let built: Result<$ty, _> = <$ty>::builder()
            .sha256(meta.sha256.as_str())
            .media_type(meta.media_type.as_str())
            .size(u64::from(meta.size))
            .width(u64::from(meta.width))
            .height(u64::from(meta.height))
            .url($url)
            .try_into();
        built.map_err(|e| {
            ::vti_common::error::AppError::Internal(format!("community logo reference: {e}"))
        })
    }};
}
pub(crate) use logo_ref;

/// The stored logo as a page is told about it: the `logo` member of the
/// public profile and of the member portal's `community`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PublicLogo {
    /// Where a page loads it: [`LOGO_PATH`] on the same origin as the profile
    /// it appears in (a reader elsewhere resolves it against the URL it read
    /// the profile from), with the digest as `?v=` so a browser's in-page
    /// image cache never shows a replaced logo. The route ignores the query
    /// and revalidates every use, so any `v` answers the current logo.
    /// `vtc/community/logo/show/0.1` names the absolute, unversioned URL.
    pub url: String,
    pub sha256: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
}

impl From<&LogoMeta> for PublicLogo {
    fn from(m: &LogoMeta) -> Self {
        Self {
            url: format!("{LOGO_PATH}?v={}", &m.sha256[..16]),
            sha256: m.sha256.clone(),
            media_type: m.media_type.clone(),
            width: m.width,
            height: m.height,
        }
    }
}

/// `community/logo`: the logo held, if any, and when it last changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogoRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<LogoMeta>,
    pub updated_at: DateTime<Utc>,
}

/// The record, if the community has ever held a logo.
pub async fn load_record(ks: &KeyspaceHandle) -> Result<Option<LogoRecord>, AppError> {
    match ks.get_raw(LOGO_RECORD_KEY).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppError::Internal(format!("community logo decode: {e}"))),
        None => Ok(None),
    }
}

/// Store `logo` (its record and bytes in one batch), or remove the stored one
/// when `None`, keeping the record so `updatedAt` answers.
pub async fn store_logo(
    ks: &KeyspaceHandle,
    logo: Option<(LogoMeta, Vec<u8>)>,
    now: DateTime<Utc>,
) -> Result<LogoRecord, AppError> {
    let mut batch = Batch::new();
    let record = match logo {
        Some((meta, bytes)) => {
            batch.insert_raw(LOGO_BYTES_KEY.to_vec(), bytes);
            LogoRecord {
                logo: Some(meta),
                updated_at: now,
            }
        }
        None => {
            batch.remove(LOGO_BYTES_KEY.to_vec());
            LogoRecord {
                logo: None,
                updated_at: now,
            }
        }
    };
    batch.insert(LOGO_RECORD_KEY.to_vec(), &record)?;
    ks.apply_batch(batch).await?;
    Ok(record)
}

/// Lowercase hex SHA-256.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A logo the community may serve: its record, and bytes that match it.
#[derive(Debug, Clone)]
pub struct HeldLogo {
    pub meta: LogoMeta,
    /// Reference-counted: a response shares them, never copies.
    pub bytes: Bytes,
}

/// What the community holds, as every reader sees it.
#[derive(Debug, Clone, Default)]
pub struct LogoSnapshot {
    /// The logo it serves, or `None` when it holds none it may serve.
    pub held: Option<HeldLogo>,
    /// When the stored logo was last replaced or removed; `None` when the
    /// community has never held one.
    pub updated_at: Option<DateTime<Utc>>,
}

/// The cached snapshot, and the generation an invalidation bumps so a load
/// that began before it never caches what it read.
#[derive(Default)]
struct Cache {
    generation: u64,
    snapshot: Option<LogoSnapshot>,
}

/// What the service holds in memory for the logo: the snapshot every reader
/// is answered from, the per-administrator update counts, and the
/// one-at-a-time update permit.
pub struct LogoState {
    cache: Mutex<Cache>,
    /// Updates per administrator in the last hour. In memory: a restart
    /// forgives, which a rate limit may.
    updates: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// One update at a time, from its first read to its write: re-encoding is
    /// CPU-bound, and two updates must not interleave their check and write.
    pub update: tokio::sync::Semaphore,
}

impl Default for LogoState {
    fn default() -> Self {
        Self {
            cache: Mutex::new(Cache::default()),
            updates: Mutex::new(HashMap::new()),
            update: tokio::sync::Semaphore::new(1),
        }
    }
}

impl LogoState {
    /// Count one update by the administrator `did`; `false` once they have
    /// sent [`UPDATES_PER_HOUR`] in the last hour.
    pub fn admit_update(&self, did: &str) -> bool {
        crate::directory::admit(
            &self.updates,
            did,
            Duration::from_secs(3600),
            UPDATES_PER_HOUR,
        )
    }

    /// Forget the snapshot, so the next reader loads what is stored now. Call
    /// after anything writes the logo's rows: an update, a backup import.
    pub fn invalidate(&self) {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.generation = cache.generation.wrapping_add(1);
        cache.snapshot = None;
    }

    /// What the community holds: from memory, or loaded once and kept.
    pub async fn snapshot(&self, ks: &KeyspaceHandle) -> LogoSnapshot {
        let generation = {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(snapshot) = &cache.snapshot {
                return snapshot.clone();
            }
            cache.generation
        };
        let (snapshot, settled) = load_snapshot(ks).await;
        if settled {
            let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if cache.generation == generation {
                cache.snapshot = Some(snapshot.clone());
            }
        }
        snapshot
    }

    /// The logo to serve, or `None`.
    pub async fn served(&self, ks: &KeyspaceHandle) -> Option<HeldLogo> {
        self.snapshot(ks).await.held
    }

    /// The `logo` a page is told about: only a logo the route will serve.
    pub async fn public_logo(&self, ks: &KeyspaceHandle) -> Option<PublicLogo> {
        self.served(ks).await.map(|h| PublicLogo::from(&h.meta))
    }
}

/// Read the record and its bytes. The second member is whether the result may
/// be kept: not after a store error, which the next reader should retry.
///
/// The two reads are not one snapshot of the store, so an update landing
/// between them pairs a record with the next logo's bytes. A mismatch is
/// therefore checked against the record read again: only one that persists
/// is a store whose bytes do not match their record.
async fn load_snapshot(ks: &KeyspaceHandle) -> (LogoSnapshot, bool) {
    for _ in 0..LOAD_ATTEMPTS {
        let raw = match ks.get_raw(LOGO_RECORD_KEY).await {
            Ok(Some(raw)) => raw,
            Ok(None) => return (LogoSnapshot::default(), true),
            Err(e) => {
                tracing::warn!(error = %e, "community logo record unreadable; serving none");
                return (LogoSnapshot::default(), false);
            }
        };
        let record: LogoRecord = match serde_json::from_slice(&raw) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "stored community logo record is malformed; serving none");
                return (LogoSnapshot::default(), true);
            }
        };
        let none = LogoSnapshot {
            held: None,
            updated_at: Some(record.updated_at),
        };
        let meta = match record.logo {
            None => return (none, true),
            Some(meta) if meta.well_formed() => meta,
            Some(_) => {
                tracing::warn!("stored community logo record is malformed; serving none");
                return (none, true);
            }
        };
        let bytes = match ks.get_raw(LOGO_BYTES_KEY).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(error = %e, "community logo bytes unreadable; serving none");
                return (none, false);
            }
        };
        if let Some(bytes) = bytes
            && bytes.len() == meta.size as usize
            && digest(&bytes) == meta.sha256
        {
            return (
                LogoSnapshot {
                    held: Some(HeldLogo {
                        meta,
                        bytes: Bytes::from(bytes),
                    }),
                    updated_at: none.updated_at,
                },
                true,
            );
        }
        match ks.get_raw(LOGO_RECORD_KEY).await {
            // The record changed under us: an update landed. Read it again.
            Ok(again) if again.as_deref() != Some(raw.as_slice()) => continue,
            Ok(_) => {
                tracing::warn!("stored community logo does not match its record; serving none");
                return (none, true);
            }
            Err(e) => {
                tracing::warn!(error = %e, "community logo record unreadable; serving none");
                return (none, false);
            }
        }
    }
    tracing::warn!("community logo changed on every read; serving none for now");
    (LogoSnapshot::default(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn scratch() -> KeyspaceHandle {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::test_fixture::open_with_keyspaces(
            &dir.path().join("db"),
            &["community"],
        )
        .unwrap();
        let ks = store.keyspace("community").unwrap();
        std::mem::forget(dir);
        std::mem::forget(store);
        ks
    }

    fn meta_for(bytes: &[u8]) -> LogoMeta {
        LogoMeta {
            sha256: digest(bytes),
            media_type: "image/png".into(),
            size: u32::try_from(bytes.len()).unwrap(),
            width: 4,
            height: 2,
        }
    }

    #[tokio::test]
    async fn a_stored_logo_is_served_and_a_removed_one_is_not() {
        let ks = scratch().await;
        let state = LogoState::default();
        assert!(state.served(&ks).await.is_none());

        let bytes = b"\x89PNG-fixture".to_vec();
        let at = Utc::now();
        store_logo(&ks, Some((meta_for(&bytes), bytes.clone())), at)
            .await
            .unwrap();
        state.invalidate();
        let held = state.served(&ks).await.unwrap();
        assert_eq!(&*held.bytes, bytes.as_slice());
        let public = state.public_logo(&ks).await.unwrap();
        assert_eq!(
            public.url,
            format!("{LOGO_PATH}?v={}", &held.meta.sha256[..16])
        );
        assert_eq!(public.sha256, held.meta.sha256);

        let removed = store_logo(&ks, None, at).await.unwrap();
        assert!(removed.logo.is_none());
        state.invalidate();
        let snapshot = state.snapshot(&ks).await;
        assert!(snapshot.held.is_none());
        assert_eq!(
            snapshot.updated_at,
            Some(at),
            "removal keeps when it happened"
        );
        assert!(ks.get_raw(LOGO_BYTES_KEY).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_snapshot_is_kept_until_invalidated() {
        let ks = scratch().await;
        let state = LogoState::default();
        let first = b"\x89PNG-first".to_vec();
        store_logo(&ks, Some((meta_for(&first), first.clone())), Utc::now())
            .await
            .unwrap();
        assert_eq!(&*state.served(&ks).await.unwrap().bytes, first.as_slice());

        let second = b"\x89PNG-second".to_vec();
        store_logo(&ks, Some((meta_for(&second), second.clone())), Utc::now())
            .await
            .unwrap();
        assert_eq!(
            &*state.served(&ks).await.unwrap().bytes,
            first.as_slice(),
            "answered from memory, not the store"
        );
        state.invalidate();
        assert_eq!(&*state.served(&ks).await.unwrap().bytes, second.as_slice());
    }

    #[tokio::test]
    async fn bytes_that_do_not_match_their_record_are_never_served_or_advertised() {
        let ks = scratch().await;
        let state = LogoState::default();
        let bytes = b"\x89PNG-fixture".to_vec();
        store_logo(&ks, Some((meta_for(&bytes), bytes)), Utc::now())
            .await
            .unwrap();
        ks.insert_raw(LOGO_BYTES_KEY.to_vec(), b"<script>".to_vec())
            .await
            .unwrap();
        assert!(state.served(&ks).await.is_none());
        assert!(
            state.public_logo(&ks).await.is_none(),
            "a page is never pointed at a logo the route will not serve"
        );
    }

    #[tokio::test]
    async fn a_record_naming_another_media_type_is_never_served() {
        let ks = scratch().await;
        let state = LogoState::default();
        let bytes = b"<svg/>".to_vec();
        let mut meta = meta_for(&bytes);
        meta.media_type = "image/svg+xml".into();
        store_logo(&ks, Some((meta, bytes)), Utc::now())
            .await
            .unwrap();
        assert!(state.served(&ks).await.is_none());
    }

    #[test]
    fn the_logo_url_is_absolute_https_or_absent() {
        assert_eq!(
            logo_url(Some("https://vtc.example/")).as_deref(),
            Some("https://vtc.example/v1/community/logo")
        );
        assert_eq!(logo_url(Some("http://localhost:8100")), None);
        assert_eq!(logo_url(Some("https://")), None);
        assert_eq!(logo_url(None), None);
    }

    #[test]
    fn updates_are_bounded_per_administrator() {
        let state = LogoState::default();
        for _ in 0..UPDATES_PER_HOUR {
            assert!(state.admit_update("did:example:a"));
        }
        assert!(!state.admit_update("did:example:a"));
        assert!(state.admit_update("did:example:b"), "per administrator");
    }
}
