//! What a witness keeps: open sessions, the attestations it issued, and the
//! duplicate-execution record.
//!
//! One embedded fjall store (`vti_common::store`, the store the VTA and VTC
//! use) under `<data_dir>/store`, shared by every identity of the service. Rows
//! are keyed `<identity DID> \0 <id>`, so one identity never reads another's.
//!
//! # What is kept, and for how long
//!
//! | keyspace | holds | lifetime |
//! |---|---|---|
//! | [`SESSIONS`] | each open session: opener, `parties`, challenge, domain, the session document as received, expiry | until submitted (consumed) or expired (swept) |
//! | [`ACCEPTED_IDS`] | §7.2 item 11: each accepted document `id` and its digest | the document's acceptance window (swept) |
//! | [`ATTESTATIONS`] | one row per issued VWC: its `id`, `vwcDigestMultibase`, submitter, session id, identity, time | kept, for revocation |
//!
//! Sessions and the replay record are **ephemeral**: nothing in them outlives
//! the exchange they serve, so they are never carried into a copy of this
//! service's state ([`EPHEMERAL`]). Attestations are the only durable state
//! ([`KEPT`]). The service has no backup facility of its own today; the
//! partition is pinned by a test so the day one is added it starts from the
//! right list (design note §4 P2: "sessions excluded from backup; attestations
//! kept").
//!
//! **No presentation is ever stored** (`witness/session/submit` Retention):
//! the VP a party submits is verified in memory and dropped.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vti_common::config::StoreConfig;
use vti_common::store::{KeyspaceHandle, Store};

/// Open sessions. Ephemeral.
pub const SESSIONS: &str = "witness_sessions";
/// The issued-VWC record. Kept.
pub const ATTESTATIONS: &str = "witness_attestations";
/// The §7.2 item 11 accepted-document record. Ephemeral.
pub const ACCEPTED_IDS: &str = "witness_accepted_ids";

/// Every keyspace this service opens.
pub const ALL: &[&str] = &[SESSIONS, ATTESTATIONS, ACCEPTED_IDS];
/// Keyspaces whose rows outlive the exchange that wrote them.
pub const KEPT: &[&str] = &[ATTESTATIONS];
/// Keyspaces never carried into a copy of this service's state.
pub const EPHEMERAL: &[&str] = &[SESSIONS, ACCEPTED_IDS];

/// One open witness session.
///
/// Holds the session document **as received** (`document`): its `id` is what
/// the VWC cites as `taskContext`, and the task digest the VWC carries is
/// computed over this exact content, so it must not be re-serialised from a
/// parsed form.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionRecord {
    /// The witness identity the session is with.
    pub identity_did: String,
    /// The session document's `id` — the session's name and its thread.
    pub session_id: String,
    /// The transport-proven issuer that opened it; the only party who may submit.
    pub opener_did: String,
    /// The two relationship DIDs the session names, as sent.
    pub parties: Vec<String>,
    /// The single-use challenge the presentation binds to.
    pub challenge: String,
    /// The domain the presentation binds to.
    pub domain: String,
    /// The session document, verbatim.
    pub document: String,
    /// When it was opened.
    pub opened_at: DateTime<Utc>,
    /// When it stops being submittable.
    pub expires_at: DateTime<Utc>,
}

/// Hand-written: the challenge is live binding material while the session is
/// open, and the document carries the parties' pairwise DIDs. Neither belongs
/// in a log line.
impl std::fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRecord")
            .field("identity_did", &self.identity_did)
            .field("session_id", &self.session_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl SessionRecord {
    /// Whether the session can no longer be submitted at `now`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// What the witness keeps about one VWC it issued: enough to revoke it, and
/// nothing it was shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationRecord {
    /// The VWC's `id`.
    pub vwc_id: String,
    /// The `vwcDigestMultibase` delivered with it.
    pub vwc_digest_multibase: String,
    /// The party it attests (`credentialSubject.id`).
    pub submitter_did: String,
    /// The session it cites (`taskContext`).
    pub session_id: String,
    /// The witness identity that issued it.
    pub identity_did: String,
    /// When it was issued.
    pub issued_at: DateTime<Utc>,
}

/// The witness's store: one fjall database, three keyspaces.
#[derive(Clone)]
pub struct WitnessStore {
    sessions: KeyspaceHandle,
    attestations: KeyspaceHandle,
    accepted: KeyspaceHandle,
}

/// Row key `<identity> \0 <id>`. A DID cannot contain NUL, so the split is
/// unambiguous and one identity's prefix never matches another's.
pub(crate) fn row_key(identity_did: &str, id: &str) -> Vec<u8> {
    let mut key = identity_prefix(identity_did);
    key.extend_from_slice(id.as_bytes());
    key
}

fn identity_prefix(identity_did: &str) -> Vec<u8> {
    let mut key = identity_did.as_bytes().to_vec();
    key.push(0);
    key
}

impl WitnessStore {
    /// Open (or create) the store under `<data_dir>/store`.
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        let store = Store::open(&StoreConfig {
            data_dir: data_dir.join("store"),
        })
        .map_err(|e| anyhow::anyhow!("open the witness store: {e}"))?;
        Self::from_store(&store)
    }

    /// The keyspaces of an already-open store.
    pub fn from_store(store: &Store) -> anyhow::Result<Self> {
        let ks = |name: &str| {
            store
                .keyspace(name)
                .map_err(|e| anyhow::anyhow!("open keyspace {name}: {e}"))
        };
        Ok(Self {
            sessions: ks(SESSIONS)?,
            attestations: ks(ATTESTATIONS)?,
            accepted: ks(ACCEPTED_IDS)?,
        })
    }

    /// The duplicate-execution record's keyspace.
    pub(crate) fn accepted_ids(&self) -> &KeyspaceHandle {
        &self.accepted
    }

    /// Every session of `identity_did` still open at `now`.
    pub async fn open_sessions(
        &self,
        identity_did: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Vec<SessionRecord>> {
        let rows = self
            .sessions
            .prefix_iter_raw(identity_prefix(identity_did))
            .await
            .map_err(|e| anyhow::anyhow!("list sessions: {e}"))?;
        Ok(rows
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice::<SessionRecord>(&v).ok())
            .filter(|s| !s.is_expired_at(now))
            .collect())
    }

    /// Store a new session. `false` if one with the same id already exists.
    pub async fn insert_session(&self, session: &SessionRecord) -> anyhow::Result<bool> {
        self.sessions
            .insert_if_absent(row_key(&session.identity_did, &session.session_id), session)
            .await
            .map_err(|e| anyhow::anyhow!("store a session: {e}"))
    }

    /// The session `session_id` of `identity_did`, open or not.
    pub async fn session(
        &self,
        identity_did: &str,
        session_id: &str,
    ) -> anyhow::Result<Option<SessionRecord>> {
        self.sessions
            .get(row_key(identity_did, session_id))
            .await
            .map_err(|e| anyhow::anyhow!("read a session: {e}"))
    }

    /// Atomically remove and return the session: of two racing callers,
    /// exactly one receives it. This is what makes a session single-use.
    pub async fn take_session(
        &self,
        identity_did: &str,
        session_id: &str,
    ) -> anyhow::Result<Option<SessionRecord>> {
        let raw = self
            .sessions
            .take_raw(row_key(identity_did, session_id))
            .await
            .map_err(|e| anyhow::anyhow!("claim a session: {e}"))?;
        raw.map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("a stored session does not parse: {e}"))
        })
        .transpose()
    }

    /// Put back a session taken by [`Self::take_session`] whose VWC could not
    /// be issued, so the party can submit again.
    pub async fn restore_session(&self, session: &SessionRecord) -> anyhow::Result<()> {
        self.insert_session(session).await.map(|_| ())
    }

    /// Record an issued VWC.
    pub async fn record_attestation(&self, record: &AttestationRecord) -> anyhow::Result<()> {
        self.attestations
            .insert(row_key(&record.identity_did, &record.vwc_id), record)
            .await
            .map_err(|e| anyhow::anyhow!("record an attestation: {e}"))
    }

    /// Every VWC `identity_did` has issued.
    pub async fn attestations(&self, identity_did: &str) -> anyhow::Result<Vec<AttestationRecord>> {
        let rows = self
            .attestations
            .prefix_iter_raw(identity_prefix(identity_did))
            .await
            .map_err(|e| anyhow::anyhow!("list attestations: {e}"))?;
        rows.into_iter()
            .map(|(_, v)| {
                serde_json::from_slice(&v)
                    .map_err(|e| anyhow::anyhow!("a stored attestation does not parse: {e}"))
            })
            .collect()
    }

    /// Remove every expired session, and every duplicate-execution record past
    /// its retention. Returns how many rows went.
    ///
    /// A session is removed with `take_raw` and re-checked, so a sweep racing a
    /// submit can only ever remove a session that was already expired.
    pub async fn sweep(&self, now: DateTime<Utc>) -> anyhow::Result<usize> {
        let mut removed = 0;
        let rows = self
            .sessions
            .prefix_iter_raw(Vec::new())
            .await
            .map_err(|e| anyhow::anyhow!("scan sessions: {e}"))?;
        for (key, value) in rows {
            let expired = serde_json::from_slice::<SessionRecord>(&value)
                .map(|s| s.is_expired_at(now))
                // A row that does not parse is never submittable either.
                .unwrap_or(true);
            if expired {
                self.sessions
                    .remove(key)
                    .await
                    .map_err(|e| anyhow::anyhow!("remove a session: {e}"))?;
                removed += 1;
            }
        }
        removed += crate::replay::sweep(&self.accepted, now).await?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The partition the design note fixes: sessions and the replay record
    /// are ephemeral, attestations are kept, and every keyspace is one or the
    /// other.
    #[test]
    fn every_keyspace_is_kept_or_ephemeral_never_both() {
        for ks in ALL {
            let kept = KEPT.contains(ks);
            let ephemeral = EPHEMERAL.contains(ks);
            assert!(
                kept ^ ephemeral,
                "{ks} must be exactly one of kept / ephemeral"
            );
        }
        assert_eq!(KEPT.len() + EPHEMERAL.len(), ALL.len());
        assert!(
            EPHEMERAL.contains(&SESSIONS),
            "sessions are never backed up"
        );
        assert!(
            KEPT.contains(&ATTESTATIONS),
            "attestations are kept for revocation"
        );
    }

    #[test]
    fn a_sessions_debug_shows_neither_its_challenge_nor_its_document() {
        let s = SessionRecord {
            identity_did: "did:example:w".into(),
            session_id: "urn:uuid:1".into(),
            opener_did: "did:example:a".into(),
            parties: vec!["did:example:a".into(), "did:example:b".into()],
            challenge: "CHALLENGE-VALUE".into(),
            domain: "did:example:w".into(),
            document: "{\"secret-ish\":true}".into(),
            opened_at: Utc::now(),
            expires_at: Utc::now(),
        };
        let shown = format!("{s:?}");
        assert!(!shown.contains("CHALLENGE-VALUE"), "{shown}");
        assert!(!shown.contains("secret-ish"), "{shown}");
    }
}
