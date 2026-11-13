//! An expiry-ordered index beside a keyspace's records, so a TTL sweep reads
//! what has expired rather than everything retained (#2626).
//!
//! A sweep that walks every record (`prefix_iter_raw`) costs memory and CPU in
//! proportion to the whole keyspace on every tick, and over vsock fails for
//! good once the scan's one response frame passes 16 MiB — after which nothing
//! is pruned and the keyspace only grows. Records whose rows carry whole
//! responses (accepted document ids, idempotency entries) get there first.
//!
//! The index is one empty row per record write, keyed
//! `{index prefix}{deadline as 20 decimal digits}:{record key}`, so the rows
//! sort by deadline and a sweep reads them in bounded pages up to `now` and
//! stops. A row is written **before** (or in the same batch as) the record it
//! names: an index row without its record is harmless — the sweep drops it —
//! while a record without an index row would never be swept.
//!
//! Records written before the index existed have no row. The first sweep that
//! finds no [`ExpiryIndex::marker`] row walks the records once, in bounded
//! pages, indexing the live ones and dropping the expired ones, then writes the
//! marker. That backfill is ordinary store state — nothing a TEE restart can
//! lose half of: an interrupted pass simply runs again.
//!
//! A record whose deadline moves (re-claimed, extended) gets a new index row;
//! the old one, read at its earlier deadline, finds the record still live and
//! is dropped without touching it.

use chrono::{DateTime, Utc};

use super::{Batch, KeyspaceHandle, ScanOpts};
use crate::error::AppError;

/// Rows read per page by a sweep: small enough that a page of the largest
/// records stays far below the vsock frame cap.
const PAGE: usize = 256;

/// What a sweep learns from a record's bytes.
pub enum RecordState {
    /// Past its deadline: remove it.
    Expired,
    /// Retained until this instant.
    Live(DateTime<Utc>),
    /// This build cannot read it.
    Unreadable,
}

/// What a sweep does with a record it cannot read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// Leave it in place (a record that cannot be read may be one that cannot
    /// be shown absent — the accepted-id record fails closed on it).
    Keep,
    /// Remove it.
    Remove,
}

/// What one sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepCount {
    /// Expired records removed.
    pub purged: usize,
    /// Records that could not be read (removed or kept per [`Unreadable`]).
    pub unreadable: usize,
}

/// An expiry index over records under `record_prefix` in one keyspace.
#[derive(Clone, Copy)]
pub struct ExpiryIndex {
    /// Prefix of the records the index covers.
    pub record_prefix: &'static [u8],
    /// Prefix of the index rows. Must not start with `record_prefix`.
    pub index_prefix: &'static [u8],
    /// The row whose presence says every record has an index row.
    pub marker: &'static [u8],
}

impl ExpiryIndex {
    /// The index row for `record_key` expiring at `deadline`.
    pub fn index_key(&self, deadline: DateTime<Utc>, record_key: &[u8]) -> Vec<u8> {
        // Rounded up, so a row that is due names a record that is past its
        // deadline unless the deadline moved.
        let secs = deadline.timestamp() + i64::from(deadline.timestamp_subsec_nanos() > 0);
        let secs = u64::try_from(secs).unwrap_or(0);
        let mut k = self.index_prefix.to_vec();
        k.extend_from_slice(format!("{secs:020}:").as_bytes());
        k.extend_from_slice(record_key);
        k
    }

    /// Add the index row for `record_key` to `batch`.
    pub fn stage(&self, batch: &mut Batch, deadline: DateTime<Utc>, record_key: &[u8]) {
        batch.insert_raw(self.index_key(deadline, record_key), Vec::new());
    }

    /// Write the index row for `record_key`. Call **before** writing the record.
    pub async fn insert(
        &self,
        ks: &KeyspaceHandle,
        deadline: DateTime<Utc>,
        record_key: &[u8],
    ) -> Result<(), AppError> {
        ks.insert_raw(self.index_key(deadline, record_key), Vec::new())
            .await
    }

    /// Split an index row's key into its deadline (seconds) and record key.
    fn parse<'k>(&self, key: &'k [u8]) -> Option<(u64, &'k [u8])> {
        let rest = key.strip_prefix(self.index_prefix)?;
        if rest.len() < 21 || rest[20] != b':' {
            return None;
        }
        let secs = std::str::from_utf8(&rest[..20]).ok()?.parse().ok()?;
        Some((secs, &rest[21..]))
    }

    /// Remove every expired record, reading only what the index says is due
    /// (after a one-time backfill of records that predate the index).
    ///
    /// `classify` reads a record's bytes as of `now`.
    pub async fn sweep(
        &self,
        ks: &KeyspaceHandle,
        now: DateTime<Utc>,
        unreadable: Unreadable,
        classify: impl Fn(&[u8]) -> RecordState,
    ) -> Result<SweepCount, AppError> {
        let mut count = SweepCount::default();
        if ks.get_raw(self.marker.to_vec()).await?.is_none() {
            self.backfill(ks, unreadable, &classify, &mut count).await?;
            ks.insert_raw(self.marker.to_vec(), Vec::new()).await?;
        }

        let now_secs = u64::try_from(now.timestamp()).unwrap_or(0);
        let mut pages = ks.scan_pager(ScanOpts::new(self.index_prefix, PAGE));
        'walk: loop {
            let page = pages.next_page().await?;
            if page.is_empty() {
                break;
            }
            for (index_key, _) in page {
                let Some((deadline, record_key)) = self.parse(&index_key) else {
                    // Not a row this module wrote; drop it so it cannot wedge
                    // the walk at the front of the range.
                    ks.remove(index_key).await?;
                    continue;
                };
                if deadline > now_secs {
                    break 'walk;
                }
                if let Some(raw) = ks.get_raw(record_key.to_vec()).await? {
                    match classify(&raw) {
                        RecordState::Expired => {
                            ks.remove(record_key.to_vec()).await?;
                            count.purged += 1;
                        }
                        // Re-written with a later deadline. Its write indexed
                        // it; re-indexing is idempotent and keeps a record
                        // from ever being left without a row.
                        RecordState::Live(at) => self.insert(ks, at, record_key).await?,
                        RecordState::Unreadable => {
                            count.unreadable += 1;
                            if unreadable == Unreadable::Remove {
                                ks.remove(record_key.to_vec()).await?;
                            }
                        }
                    }
                }
                ks.remove(index_key).await?;
            }
        }
        Ok(count)
    }

    async fn backfill(
        &self,
        ks: &KeyspaceHandle,
        unreadable: Unreadable,
        classify: &impl Fn(&[u8]) -> RecordState,
        count: &mut SweepCount,
    ) -> Result<(), AppError> {
        let mut pages = ks.scan_pager(ScanOpts::new(self.record_prefix, PAGE));
        loop {
            let page = pages.next_page().await?;
            if page.is_empty() {
                return Ok(());
            }
            for (key, value) in page {
                match classify(&value) {
                    RecordState::Expired => {
                        ks.remove(key).await?;
                        count.purged += 1;
                    }
                    RecordState::Live(deadline) => self.insert(ks, deadline, &key).await?,
                    RecordState::Unreadable => {
                        count.unreadable += 1;
                        if unreadable == Unreadable::Remove {
                            ks.remove(key).await?;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;
    use chrono::Duration;

    const IDX: ExpiryIndex = ExpiryIndex {
        record_prefix: b"rec:",
        index_prefix: b"rec-exp:",
        marker: b"meta:rec-exp-index",
    };

    fn ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (store.keyspace("expiry-index-test").unwrap(), dir)
    }

    /// A record is its deadline as decimal seconds.
    fn classify(now: DateTime<Utc>) -> impl Fn(&[u8]) -> RecordState {
        move |v| match std::str::from_utf8(v)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
        {
            Some(secs) => {
                let at = DateTime::from_timestamp(secs, 0).unwrap();
                if at <= now {
                    RecordState::Expired
                } else {
                    RecordState::Live(at)
                }
            }
            None => RecordState::Unreadable,
        }
    }

    async fn put(ks: &KeyspaceHandle, id: &str, at: DateTime<Utc>) {
        // Whole seconds, as the record stores it.
        let at = DateTime::from_timestamp(at.timestamp(), 0).unwrap();
        let key = format!("rec:{id}").into_bytes();
        IDX.insert(ks, at, &key).await.unwrap();
        ks.insert_raw(key, at.timestamp().to_string().into_bytes())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_sweep_removes_what_expired_and_keeps_what_did_not() {
        let (ks, _d) = ks();
        let now = Utc::now();
        put(&ks, "old", now - Duration::hours(1)).await;
        put(&ks, "new", now + Duration::hours(1)).await;
        let n = IDX
            .sweep(&ks, now, Unreadable::Keep, classify(now))
            .await
            .unwrap();
        assert_eq!(n.purged, 1);
        assert!(ks.get_raw(b"rec:old".to_vec()).await.unwrap().is_none());
        assert!(ks.get_raw(b"rec:new".to_vec()).await.unwrap().is_some());
        // The live record's index row stays for the sweep that finds it due.
        assert_eq!(ks.prefix_keys(IDX.index_prefix).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn records_from_before_the_index_are_backfilled_once() {
        let (ks, _d) = ks();
        let now = Utc::now();
        // Written as an older build did: no index row.
        let later = (now + Duration::hours(1)).timestamp().to_string();
        let past = (now - Duration::hours(1)).timestamp().to_string();
        ks.insert_raw(b"rec:legacy-live".to_vec(), later.into_bytes())
            .await
            .unwrap();
        ks.insert_raw(b"rec:legacy-dead".to_vec(), past.into_bytes())
            .await
            .unwrap();
        ks.insert_raw(b"rec:junk".to_vec(), b"?".to_vec())
            .await
            .unwrap();

        let n = IDX
            .sweep(&ks, now, Unreadable::Keep, classify(now))
            .await
            .unwrap();
        assert_eq!(
            n,
            SweepCount {
                purged: 1,
                unreadable: 1
            }
        );
        assert!(ks.get_raw(IDX.marker.to_vec()).await.unwrap().is_some());
        assert!(
            ks.get_raw(b"rec:junk".to_vec()).await.unwrap().is_some(),
            "kept"
        );

        // The legacy live record now has a row, and is swept once it is due.
        let due = now + Duration::hours(2);
        let n = IDX
            .sweep(&ks, due, Unreadable::Keep, classify(due))
            .await
            .unwrap();
        assert_eq!(n.purged, 1);
        assert!(
            ks.get_raw(b"rec:legacy-live".to_vec())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_moved_deadline_is_honoured_and_its_stale_row_dropped() {
        let (ks, _d) = ks();
        let now = Utc::now();
        put(&ks, "moved", now - Duration::minutes(5)).await;
        put(&ks, "moved", now + Duration::hours(1)).await;
        let n = IDX
            .sweep(&ks, now, Unreadable::Keep, classify(now))
            .await
            .unwrap();
        assert_eq!(n.purged, 0, "the record's current deadline is later");
        assert!(ks.get_raw(b"rec:moved".to_vec()).await.unwrap().is_some());
        assert_eq!(ks.prefix_keys(IDX.index_prefix).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_sweep_walks_more_than_one_page() {
        let (ks, _d) = ks();
        let now = Utc::now();
        for i in 0..(PAGE + 10) {
            put(&ks, &format!("{i:05}"), now - Duration::seconds(1)).await;
        }
        let n = IDX
            .sweep(&ks, now, Unreadable::Keep, classify(now))
            .await
            .unwrap();
        assert_eq!(n.purged, PAGE + 10);
        assert!(ks.prefix_keys(IDX.index_prefix).await.unwrap().is_empty());
    }
}
