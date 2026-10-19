//! The member directory: the community's field schema, each member's card,
//! and what of it each viewer is shown (VTI spec, *Community Directory and
//! Groups*; `vtc/directory/*`; design `docs/05-design-notes/vtc-member-directory.md`).
//!
//! Three owners, three stores. The community owns the schema ([`fields`]),
//! the member owns their card ([`cards`]), and a viewer's own annotations —
//! stars, lists, notes, private names — are never here at all (VTI-DIR-001):
//! they live in the viewer's VTA.
//!
//! Every read is a projection ([`project`]): the subject's choice, the field's
//! ceiling and the community's `directory` policy, intersected. Nothing in
//! this module reads a card for another member any other way.
//!
//! One keyspace, `directory`, backed up: `field:<key>`, `card:<entryId>`, the
//! index `entry:<did>`, pictures ([`images`]: `img:`, `imgmeta:`, `upload:`)
//! and published external cards ([`external`]: `published:<entryId>`).

pub mod cards;
pub mod disclosure;
pub mod external;
pub mod fields;
pub mod images;
pub mod model;
pub mod notes;
pub mod project;
pub mod read;
pub mod sweep;
pub mod values;
pub mod write_policy;

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use vti_common::store::KeyspaceHandle;

use model::Settings;

/// Serialises every write to the directory keyspace. Writes are rare and
/// small; one lock makes every read-check-write sequence here atomic without a
/// per-key scheme to get wrong.
pub(crate) static WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The directory as the service holds it.
pub struct Directory {
    ks: KeyspaceHandle,
    settings: Settings,
    /// `entries/list` requests per caller in the last minute (VTI-DIR-114).
    /// In memory: a restart forgives, which a rate limit may.
    recent: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// `images/upload` requests per writer in the last hour.
    uploads: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// `images/get` requests per identified caller in the last minute.
    image_reads: Mutex<HashMap<String, VecDeque<Instant>>>,
}

/// Count one request by `key` in `window`; `false` once `limit` are in it.
fn admit(
    map: &Mutex<HashMap<String, VecDeque<Instant>>>,
    key: &str,
    window: Duration,
    limit: usize,
) -> bool {
    let now = Instant::now();
    let mut recent = map.lock().unwrap_or_else(|p| p.into_inner());
    // Keep the map bounded by forgetting callers idle for a window.
    if recent.len() > 10_000 {
        recent.retain(|_, q| q.back().is_some_and(|t| now.duration_since(*t) < window));
    }
    let q = recent.entry(key.to_string()).or_default();
    while q.front().is_some_and(|t| now.duration_since(*t) >= window) {
        q.pop_front();
    }
    if q.len() >= limit {
        return false;
    }
    q.push_back(now);
    true
}

impl Directory {
    pub fn new(ks: KeyspaceHandle, settings: Settings) -> Self {
        Self {
            ks,
            settings,
            recent: Mutex::new(HashMap::new()),
            uploads: Mutex::new(HashMap::new()),
            image_reads: Mutex::new(HashMap::new()),
        }
    }

    pub fn ks(&self) -> &KeyspaceHandle {
        &self.ks
    }

    pub fn settings(&self) -> Settings {
        self.settings
    }

    /// Count one `entries/list` request by `did`; `false` once they have made
    /// the community's limit in the last minute. Counted whatever the
    /// request finds, so the limit says nothing about the directory.
    pub fn admit_list_request(&self, did: &str) -> bool {
        admit(
            &self.recent,
            did,
            Duration::from_secs(60),
            self.settings.list_rate_per_minute as usize,
        )
    }

    /// Count one `images/upload` by `did`; `false` once they have uploaded the
    /// community's limit in the last hour (`images/upload` item 7).
    pub fn admit_upload(&self, did: &str) -> bool {
        admit(
            &self.uploads,
            did,
            Duration::from_secs(3600),
            self.settings.image_uploads_per_hour as usize,
        )
    }

    /// Count one `images/get` by an identified caller: ten pictures for every
    /// listing a caller may browse, per minute (`images/get` item 6).
    pub fn admit_image_read(&self, did: &str) -> bool {
        admit(
            &self.image_reads,
            did,
            Duration::from_secs(60),
            (self.settings.list_rate_per_minute as usize).saturating_mul(10),
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use vti_common::store::KeyspaceHandle;

    /// A fresh `directory` keyspace in a temporary store that lives for the
    /// rest of the test process.
    pub(crate) async fn scratch() -> KeyspaceHandle {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::test_fixture::open_with_keyspaces(
            &dir.path().join("db"),
            &["directory"],
        )
        .unwrap();
        let ks = store.keyspace("directory").unwrap();
        std::mem::forget(dir);
        std::mem::forget(store);
        ks
    }

    #[test]
    fn vti_dir_114_reads_are_rate_limited_per_caller() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let ks = rt.block_on(scratch());
        let d = super::Directory::new(
            ks,
            super::Settings {
                list_rate_per_minute: 2,
                ..super::Settings::default()
            },
        );
        assert!(d.admit_list_request("did:example:a"));
        assert!(d.admit_list_request("did:example:a"));
        assert!(!d.admit_list_request("did:example:a"));
        assert!(d.admit_list_request("did:example:b"), "counted per caller");
    }
}
