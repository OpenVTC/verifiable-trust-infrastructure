//! Community logo — an image the community stores and serves from its own
//! origin (`vtc/community/logo/update/0.1`, served at [`LOGO_PATH`]).
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
//! **Served from memory, checked against the store.** The public route reads
//! only the small record on each request and keeps the bytes of the digest it
//! names in [`LogoState`]; a record that changes under it (an update, or a
//! backup import before its restart) is noticed on the next request. Bytes
//! whose digest does not match their record, or a record naming a media type
//! outside [`MEDIA_TYPES`], are never served.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

/// The logo's record in the `community` keyspace.
pub const LOGO_RECORD_KEY: &[u8] = b"community/logo";

/// The stored bytes, beside [`LOGO_RECORD_KEY`].
pub const LOGO_BYTES_KEY: &[u8] = b"community/logo/bytes";

/// Where the community serves its logo (under the API mount).
pub const LOGO_PATH: &str = "/v1/community/logo";

/// The media types a stored logo may have (`LogoMediaType`). The route answers
/// its `Content-Type` from this list, never from the record's own string.
pub const MEDIA_TYPES: [&str; 3] = ["image/png", "image/jpeg", "image/webp"];

/// Updates one signer may send per hour (update item 5).
pub const UPDATES_PER_HOUR: usize = 20;

/// The stored logo, as `LogoRef` names it.
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
    /// The `logo` the profile's readers are given: the path to load it from,
    /// versioned by digest so a replaced logo is never read from a cache.
    pub fn public_url(&self) -> String {
        format!(
            "{LOGO_PATH}?v={}",
            &self.sha256[..16.min(self.sha256.len())]
        )
    }

    /// Whether the record is one the route may serve: a digest of the shape
    /// it writes, and a media type from [`MEDIA_TYPES`].
    fn well_formed(&self) -> bool {
        self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && MEDIA_TYPES.contains(&self.media_type.as_str())
            && self.size > 0
    }
}

/// The stored logo as a page is told about it: the `logo` member of the
/// public profile and of the member portal's `community`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PublicLogo {
    /// Same-origin path to load it from, versioned by digest.
    pub url: String,
    pub sha256: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
}

impl From<LogoMeta> for PublicLogo {
    fn from(m: LogoMeta) -> Self {
        Self {
            url: m.public_url(),
            sha256: m.sha256,
            media_type: m.media_type,
            width: m.width,
            height: m.height,
        }
    }
}

/// The [`PublicLogo`] for the logo the community holds and may serve.
pub async fn public_logo(ks: &KeyspaceHandle) -> Option<PublicLogo> {
    current(ks).await.map(PublicLogo::from)
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

/// The logo the community holds and may serve, or `None`. A record that is
/// unreadable or not [`LogoMeta::well_formed`] answers `None` and is logged:
/// what nothing here wrote is never served.
pub async fn current(ks: &KeyspaceHandle) -> Option<LogoMeta> {
    match load_record(ks).await {
        Ok(Some(LogoRecord {
            logo: Some(meta), ..
        })) if meta.well_formed() => Some(meta),
        Ok(Some(LogoRecord { logo: Some(_), .. })) => {
            tracing::warn!("stored community logo record is malformed; serving none");
            None
        }
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, "stored community logo record unreadable; serving none");
            None
        }
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

/// What the service holds in memory for the logo: the bytes last served, the
/// per-signer update counts, and the one-at-a-time re-encoding permit.
pub struct LogoState {
    /// The bytes of the digest last served, so a request reads only the record.
    served: Mutex<Option<(String, Arc<[u8]>)>>,
    /// Updates per signer in the last hour. In memory: a restart forgives,
    /// which a rate limit may.
    updates: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// Re-encoding is CPU-bound; one at a time keeps a burst of updates from
    /// tying up the blocking pool.
    pub encode: tokio::sync::Semaphore,
}

impl Default for LogoState {
    fn default() -> Self {
        Self {
            served: Mutex::new(None),
            updates: Mutex::new(HashMap::new()),
            encode: tokio::sync::Semaphore::new(1),
        }
    }
}

impl LogoState {
    /// Count one update by `did`; `false` once they have sent
    /// [`UPDATES_PER_HOUR`] in the last hour.
    pub fn admit_update(&self, did: &str) -> bool {
        crate::directory::admit(
            &self.updates,
            did,
            Duration::from_secs(3600),
            UPDATES_PER_HOUR,
        )
    }

    /// Forget the cached bytes (after an update, so the next read reloads).
    pub fn invalidate(&self) {
        *self.served.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// The logo to serve: its record and bytes, or `None` when there is none
    /// or what is stored does not match its record.
    pub async fn served(&self, ks: &KeyspaceHandle) -> Option<(LogoMeta, Arc<[u8]>)> {
        let meta = current(ks).await?;
        if let Some((sha, bytes)) = self
            .served
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            && *sha == meta.sha256
        {
            return Some((meta, Arc::clone(bytes)));
        }
        let bytes = match ks.get_raw(LOGO_BYTES_KEY).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                tracing::warn!("community logo record names bytes that are not stored");
                return None;
            }
            Err(e) => {
                tracing::warn!(error = %e, "community logo bytes unreadable");
                return None;
            }
        };
        if digest(&bytes) != meta.sha256 || bytes.len() != meta.size as usize {
            tracing::warn!("stored community logo does not match its record; serving none");
            return None;
        }
        let bytes: Arc<[u8]> = bytes.into();
        *self.served.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((meta.sha256.clone(), Arc::clone(&bytes)));
        Some((meta, bytes))
    }
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
        let (meta, served) = state.served(&ks).await.unwrap();
        assert_eq!(&*served, bytes.as_slice());
        assert_eq!(
            meta.public_url(),
            format!("{LOGO_PATH}?v={}", &meta.sha256[..16])
        );

        let removed = store_logo(&ks, None, at).await.unwrap();
        assert!(removed.logo.is_none());
        assert!(
            state.served(&ks).await.is_none(),
            "the cache follows the record"
        );
        assert_eq!(load_record(&ks).await.unwrap().unwrap().updated_at, at);
        assert!(ks.get_raw(LOGO_BYTES_KEY).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn bytes_that_do_not_match_their_record_are_never_served() {
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
        assert!(current(&ks).await.is_none());
        assert!(state.served(&ks).await.is_none());
    }

    #[test]
    fn updates_are_bounded_per_signer() {
        let state = LogoState::default();
        for _ in 0..UPDATES_PER_HOUR {
            assert!(state.admit_update("did:example:a"));
        }
        assert!(!state.admit_update("did:example:a"));
        assert!(state.admit_update("did:example:b"), "per signer");
    }
}
