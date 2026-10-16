//! A room's revocation list — the room's own, signed statement of which credentials it has
//! withdrawn before they expire (`RevocationList` of `rooms/_shared/0.1/room.schema.json`,
//! `rooms/revocations/put/0.1`, trust-tasks-tf #804).
//!
//! # Why this is the one piece of state a host consults beyond the presentation
//!
//! Everything else a host decides, it decides from the presentation — invariant I5: no
//! roster, no ACL. A withdrawal cannot work that way, because a credential that verifies
//! today verifies tomorrow. So a host holds **one** thing more per room: the latest list the
//! room signed and an administrator delivered. It is room state, not host state — signed by
//! the room, cumulative, numbered — so it means the same thing at every host it reaches, a
//! host cannot add to or subtract from it, and it moves with the room.
//!
//! # Three halves
//!
//! - **The list** ([`RevocationList::parse`], [`RevocationList::accept`]): shape, the
//!   acceptance rules of `RevocationList` (*Accepting*) and `rooms/revocations/put` items
//!   2–4, and the head digest. Pure; nothing here touches storage or keys.
//! - **Matching** ([`RevocationList::revokes`], [`Presented`]): which presented credential
//!   an entry withdraws — `RevocationEntry`, and `rooms/revocations/put` *Matching*.
//! - **Holding** (behind `host`): the durable list per room ([`held`], [`store`]) and the
//!   per-room gate ([`gate`]) that serializes acceptance against authorization
//!   (*Enforcement* item 3).
//!
//! The list's **signature** is not checked here: that needs a resolver, and lives with the
//! credential verifier ([`crate::authz::ChainVerifier::verify_room_signature`]).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;

/// The most entries a list may carry (`RevocationList.entries`, `maxItems`).
pub const MAX_ENTRIES: usize = 4096;

/// How far past an entry's `until` a key holder keeps it when building the next list —
/// `rooms/owner/revoke` item 3: a host whose clock is behind the key holder's must not see
/// an entry it still counts as live dropped, and refuse the list `notAppendOnly`.
pub const DROP_MARGIN: chrono::Duration = chrono::Duration::hours(24);

/// What a host knows about one presented credential: enough to match it against a list,
/// and nothing about what it grants.
///
/// Stored with a transfer opened under a presentation (an upload or a download), so the
/// steps that present nothing can be held to a list accepted after they began
/// (*Enforcement* item 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialFacts {
    /// The credential's own `id`, where it carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Its `credentialSubject` id.
    pub subject: String,
    /// Its `issuer`.
    pub issuer: String,
    /// Its `validFrom`. Absent is treated as issued before every entry (fail closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
}

/// Every credential a presentation carried, as the verifier read them.
///
/// `membership` is `None` on a `private` room, where the membership credential is presented
/// in zero knowledge and the host learns nothing it could match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Presented {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<CredentialFacts>,
    /// The authority chain, leaf first, every link.
    #[serde(default)]
    pub authority: Vec<CredentialFacts>,
}

impl Presented {
    /// Every credential, membership first.
    pub fn all(&self) -> impl Iterator<Item = &CredentialFacts> {
        self.membership.iter().chain(self.authority.iter())
    }
}

/// One withdrawal (`RevocationEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// One credential, by `id`.
    Credential {
        credential_id: String,
        revoked_at: DateTime<Utc>,
        until: Option<DateTime<Utc>>,
    },
    /// A party: every credential naming them as subject **or issuer**, issued before
    /// `revoked_at`.
    Subject {
        subject: String,
        revoked_at: DateTime<Utc>,
        until: Option<DateTime<Utc>>,
    },
    /// Every credential issued before `revoked_at`.
    Room {
        revoked_at: DateTime<Utc>,
        until: Option<DateTime<Utc>>,
    },
}

impl Entry {
    /// `until`, after which every credential this entry matches has expired anyway.
    pub fn until(&self) -> Option<DateTime<Utc>> {
        match self {
            Entry::Credential { until, .. }
            | Entry::Subject { until, .. }
            | Entry::Room { until, .. } => *until,
        }
    }

    /// When the room made the withdrawal.
    pub fn revoked_at(&self) -> DateTime<Utc> {
        match self {
            Entry::Credential { revoked_at, .. }
            | Entry::Subject { revoked_at, .. }
            | Entry::Room { revoked_at, .. } => *revoked_at,
        }
    }

    /// Whether the entry still counts as live at `now`: no `until`, or one not yet passed.
    pub fn live_at(&self, now: DateTime<Utc>) -> bool {
        self.until().is_none_or(|until| until >= now)
    }

    /// Whether this entry withdraws `c` (`RevocationEntry`, and `rooms/revocations/put`
    /// *Matching*). A credential without `validFrom` is issued before every entry.
    pub fn matches(&self, c: &CredentialFacts) -> bool {
        let issued_before = |at: &DateTime<Utc>| c.valid_from.is_none_or(|from| from < *at);
        match self {
            Entry::Credential { credential_id, .. } => c.id.as_deref() == Some(credential_id),
            Entry::Subject {
                subject,
                revoked_at,
                ..
            } => (c.subject == *subject || c.issuer == *subject) && issued_before(revoked_at),
            Entry::Room { revoked_at, .. } => issued_before(revoked_at),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Entry::Credential { .. } => "credential",
            Entry::Subject { .. } => "subject",
            Entry::Room { .. } => "room",
        }
    }

    /// The wire form, as `RevocationEntry` writes it.
    ///
    /// `revokedAt` keeps its sub-second part. Truncated to the second, a credential issued
    /// earlier in the same second as the withdrawal would read as issued *after* it, and
    /// escape it.
    pub fn to_wire(&self) -> Value {
        let mut v = serde_json::json!({
            "kind": self.kind(),
            "revokedAt": self
                .revoked_at()
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        });
        match self {
            Entry::Credential { credential_id, .. } => {
                v["credentialId"] = Value::String(credential_id.clone());
            }
            Entry::Subject { subject, .. } => v["subject"] = Value::String(subject.clone()),
            Entry::Room { .. } => {}
        }
        if let Some(until) = self.until() {
            v["until"] = Value::String(rfc3339(until));
        }
        v
    }

    fn parse(raw: &Value, index: usize) -> Result<Self, ListRefusal> {
        let invalid = |why: &str| ListRefusal::ListInvalid(format!("entry {index}: {why}"));
        let obj = raw.as_object().ok_or_else(|| invalid("is not an object"))?;
        let time = |name: &str| -> Result<Option<DateTime<Utc>>, ListRefusal> {
            match obj.get(name) {
                None => Ok(None),
                Some(Value::String(s)) => DateTime::parse_from_rfc3339(s)
                    .map(|t| Some(t.with_timezone(&Utc)))
                    .map_err(|_| invalid(&format!("`{name}` is not an RFC 3339 date-time"))),
                Some(_) => Err(invalid(&format!("`{name}` is not a string"))),
            }
        };
        let revoked_at = time("revokedAt")?.ok_or_else(|| invalid("carries no `revokedAt`"))?;
        let until = time("until")?;
        let string = |name: &str| -> Result<String, ListRefusal> {
            match obj.get(name) {
                Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
                _ => Err(invalid(&format!("carries no `{name}`"))),
            }
        };
        let allowed: &[&str] = match obj.get("kind").and_then(Value::as_str) {
            Some("credential") => &["kind", "credentialId", "revokedAt", "until"],
            Some("subject") => &["kind", "subject", "revokedAt", "until"],
            Some("room") => &["kind", "revokedAt", "until"],
            _ => return Err(invalid("has no `kind` of credential, subject or room")),
        };
        if let Some(extra) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
            return Err(invalid(&format!(
                "carries `{extra}`, which its kind does not"
            )));
        }
        Ok(match obj.get("kind").and_then(Value::as_str) {
            Some("credential") => Entry::Credential {
                credential_id: string("credentialId")?,
                revoked_at,
                until,
            },
            Some("subject") => {
                let subject = string("subject")?;
                if !subject.starts_with("did:") {
                    return Err(invalid("`subject` is not a DID"));
                }
                Entry::Subject {
                    subject,
                    revoked_at,
                    until,
                }
            }
            _ => Entry::Room { revoked_at, until },
        })
    }
}

/// Why a host refused a list — the codes `rooms/revocations/put` declares. Every one leaves
/// the held list as it was.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListRefusal {
    /// Not one the room signed for this room (item 2).
    #[error("the list is not one this room signed for itself: {0}")]
    ListInvalid(String),
    /// A `credential` or `subject` entry on a `private` room (item 3).
    #[error(
        "the room is private, and a list naming a credential or a party is one its host \
         cannot apply and a disclosure of who was in the room; only `room` entries are \
         permitted"
    )]
    EntryNotPermitted,
    /// Below the held sequence (item 4).
    #[error("this host holds a later revocation list for the room, at sequence {held_sequence}")]
    Stale { held_sequence: u64 },
    /// A different list at the held sequence (item 4): the room's key equivocated.
    #[error(
        "this host holds a different list at the same sequence: the room has signed two lists \
         at one position, so its key holder has forked or its key is in more than one party's \
         hands"
    )]
    SequenceConflict,
    /// Drops a live entry of the held list (item 4).
    #[error(
        "the list omits a withdrawal of the held list that is still live; a withdrawal is \
         never undone by omission — re-admit a party by issuing fresh credentials"
    )]
    NotAppendOnly,
}

/// Whether an accepted list was new, or a repeat of the one held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// A higher sequence: from now on it is the list in force.
    New,
    /// The same sequence and an identical list: answered as accepted, changing nothing
    /// (item 4), with the `inForceAt` of its first acceptance.
    Repeat,
}

/// A revocation list, read and checked for shape.
#[derive(Debug, Clone)]
pub struct RevocationList {
    raw: Value,
    room_id: String,
    sequence: u64,
    entries: Vec<Entry>,
}

impl RevocationList {
    /// Read `raw` as a `RevocationList` delivered for `room_id`.
    ///
    /// Refuses `listInvalid` for anything the schema does not admit, a `roomId` other than
    /// the request's, an entry over [`MAX_ENTRIES`], a `subject` entry naming the room
    /// (`rooms/revocations/put` item 2), or a list carrying no `proof` (the signature
    /// itself is checked elsewhere, against the room's key).
    pub fn parse(raw: &Value, room_id: &str) -> Result<Self, ListRefusal> {
        let invalid = |why: String| ListRefusal::ListInvalid(why);
        let obj = raw
            .as_object()
            .ok_or_else(|| invalid("the list is not an object".into()))?;
        const MEMBERS: &[&str] = &["roomId", "sequence", "issuedAt", "entries", "proof"];
        if let Some(extra) = obj.keys().find(|k| !MEMBERS.contains(&k.as_str())) {
            return Err(invalid(format!("the list carries `{extra}`")));
        }
        let list_room = obj
            .get("roomId")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("the list names no `roomId`".into()))?;
        if list_room != room_id {
            return Err(invalid(
                "the list's `roomId` is not the room it was delivered for".into(),
            ));
        }
        let sequence = obj
            .get("sequence")
            .and_then(Value::as_u64)
            .filter(|s| *s >= 1)
            .ok_or_else(|| invalid("`sequence` is not an integer of at least 1".into()))?;
        match obj.get("issuedAt").and_then(Value::as_str) {
            Some(s) if DateTime::parse_from_rfc3339(s).is_ok() => {}
            _ => return Err(invalid("`issuedAt` is not an RFC 3339 date-time".into())),
        }
        if !obj.get("proof").is_some_and(Value::is_object) {
            return Err(invalid("the list carries no proof".into()));
        }
        let raw_entries = obj
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("`entries` is not an array".into()))?;
        if raw_entries.len() > MAX_ENTRIES {
            return Err(invalid(format!(
                "the list carries {} entries; it is bounded at {MAX_ENTRIES}",
                raw_entries.len()
            )));
        }
        let entries = raw_entries
            .iter()
            .enumerate()
            .map(|(i, e)| Entry::parse(e, i))
            .collect::<Result<Vec<_>, _>>()?;
        // Never the room itself: an entry naming the room as subject would withdraw every
        // credential it issued as issuer — a reset by another name, which a `room` entry
        // already says plainly.
        if entries
            .iter()
            .any(|e| matches!(e, Entry::Subject { subject, .. } if subject == room_id))
        {
            return Err(invalid("a `subject` entry names the room itself".into()));
        }
        Ok(Self {
            raw: raw.clone(),
            room_id: room_id.to_string(),
            sequence,
            entries,
        })
    }

    /// The list exactly as the room signed it, `proof` included.
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The list's head (`RevocationHead`): its sequence and the SHA-256 multihash of its
    /// JCS canonicalization, `proof` included, multibase base58btc.
    pub fn head(&self) -> Head {
        Head {
            sequence: self.sequence,
            digest: digest_multibase(&self.raw),
        }
    }

    /// Whether the list carries an entry a `private` room's host cannot apply
    /// (`rooms/revocations/put` item 3).
    pub fn names_anyone(&self) -> bool {
        self.entries
            .iter()
            .any(|e| !matches!(e, Entry::Room { .. }))
    }

    /// Decide whether a host holding `held` accepts this list for a room of `visibility`
    /// (`rooms/revocations/put` items 3 and 4; `RevocationList` *Accepting* (3) and (4)).
    ///
    /// Run after [`Self::parse`] and after the room's signature verified.
    pub fn accept(
        &self,
        visibility: crate::Visibility,
        held: Option<&RevocationList>,
        now: DateTime<Utc>,
    ) -> Result<Acceptance, ListRefusal> {
        if matches!(visibility, crate::Visibility::Private) && self.names_anyone() {
            return Err(ListRefusal::EntryNotPermitted);
        }
        let Some(held) = held else {
            // A host that holds none accepts any valid list, whatever its sequence.
            return Ok(Acceptance::New);
        };
        if self.sequence < held.sequence {
            return Err(ListRefusal::Stale {
                held_sequence: held.sequence,
            });
        }
        if self.sequence == held.sequence {
            return if self.head().digest == held.head().digest {
                Ok(Acceptance::Repeat)
            } else {
                Err(ListRefusal::SequenceConflict)
            };
        }
        // Append-only: every held entry whose `until` has not passed appears unchanged.
        if held
            .entries
            .iter()
            .filter(|e| e.live_at(now))
            .any(|e| !self.entries.contains(e))
        {
            return Err(ListRefusal::NotAppendOnly);
        }
        Ok(Acceptance::New)
    }

    /// Whether this list withdraws `c`.
    pub fn revokes(&self, c: &CredentialFacts) -> bool {
        self.entries.iter().any(|e| e.matches(c))
    }

    /// Whether a `private` room's host must refuse every presentation while this list is
    /// held: one whose membership it cannot see, so it cannot establish that no credential
    /// predates a live `room` entry (`RevocationEntry`, *Tiers*). A `room` entry past its
    /// `until` reaches only credentials that have expired anyway.
    pub fn bars_private(&self, now: DateTime<Utc>) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e, Entry::Room { .. }) && e.live_at(now))
    }

    /// Whether this list withdraws anything in `presented`, on a room of `visibility`.
    ///
    /// Fails closed: a disclosing tier's presentation whose membership the verifier did not
    /// report, or a `private` room while [`Self::bars_private`], is withdrawn.
    pub fn withdraws(
        &self,
        visibility: crate::Visibility,
        presented: &Presented,
        now: DateTime<Utc>,
    ) -> bool {
        if matches!(visibility, crate::Visibility::Private) {
            if self.bars_private(now) {
                return true;
            }
        } else if presented.membership.is_none() {
            return !self.entries.is_empty();
        }
        presented.all().any(|c| self.revokes(c))
    }
}

/// A list's head (`RevocationHead`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Head {
    pub sequence: u64,
    pub digest: String,
}

impl Head {
    /// The wire form.
    pub fn to_wire(&self) -> Value {
        serde_json::json!({ "sequence": self.sequence, "digest": self.digest })
    }
}

/// SHA-256 multihash (`0x12 0x20`) of `value`'s RFC 8785 canonicalization, multibase
/// base58btc — `DigestMultibase` as the framework defines it.
pub fn digest_multibase(value: &Value) -> String {
    let canonical = serde_json_canonicalizer::to_vec(value).unwrap_or_default();
    let digest = sha2::Sha256::digest(&canonical);
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base58Btc, multihash)
}

/// RFC 3339 at second precision, `Z`.
pub fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The next list a key holder signs (`rooms/owner/revoke` item 3), without its `proof`:
/// every entry of `held` except those whose `until` passed more than [`DROP_MARGIN`] ago,
/// then `added`, at `held`'s sequence plus one (or 1).
///
/// The caller stamps each added entry's `revokedAt` with `now`, the time it signs.
pub fn next_unsigned(
    room_id: &str,
    held: Option<&RevocationList>,
    added: &[Entry],
    now: DateTime<Utc>,
) -> Value {
    let kept = held
        .into_iter()
        .flat_map(|h| h.entries.iter())
        .filter(|e| e.until().is_none_or(|until| until + DROP_MARGIN >= now));
    let entries: Vec<Value> = kept.chain(added.iter()).map(Entry::to_wire).collect();
    serde_json::json!({
        "roomId": room_id,
        "sequence": held.map_or(1, |h| h.sequence + 1),
        "issuedAt": rfc3339(now),
        "entries": entries,
    })
}

/// The list a host holds for a room, durably, with when it began enforcing it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeldList {
    /// Exactly as the room signed it, `proof` included — `rooms/revocations/get` returns
    /// it unaltered.
    pub list: Value,
    /// When this host began refusing what it withdraws.
    pub in_force_at: DateTime<Utc>,
}

impl HeldList {
    /// The held list, read again. A list this host stored and can no longer read is a
    /// corrupt store, and authorization fails closed on it.
    pub fn parsed(&self, room_id: &str) -> Result<RevocationList, ListRefusal> {
        RevocationList::parse(&self.list, room_id)
    }
}

#[cfg(feature = "host")]
pub use host::*;

#[cfg(feature = "host")]
mod host {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, Weak};

    use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};
    use vti_common::error::AppError;
    use vti_common::store::KeyspaceHandle;

    use super::HeldList;

    /// Key prefix of a room's held list in [`crate::ROOM_REVOCATIONS_KEYSPACE`].
    pub const REVOCATIONS_PREFIX: &str = "room_revocations:";

    fn key(room_id: &str) -> String {
        format!("{REVOCATIONS_PREFIX}{room_id}")
    }

    /// The list this host holds for `room_id`, if any.
    pub async fn held(ks: &KeyspaceHandle, room_id: &str) -> Result<Option<HeldList>, AppError> {
        ks.get(key(room_id)).await
    }

    /// Hold `list` for `room_id`, durably, **before** anything answers
    /// (`rooms/revocations/put` item 5). Called under [`gate::write`].
    pub async fn store(
        ks: &KeyspaceHandle,
        room_id: &str,
        list: &HeldList,
    ) -> Result<(), AppError> {
        ks.insert(key(room_id), list).await?;
        ks.persist().await
    }

    /// Discard the list with the room (*Retention*: a host that stops serving a room
    /// discards the list with it).
    pub async fn discard(ks: &KeyspaceHandle, room_id: &str) -> Result<(), AppError> {
        ks.remove(key(room_id)).await
    }

    /// An empty revocation keyspace for tests, one per process: nothing withdrawn unless a
    /// test stores a list for a room of its own.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_keyspace() -> &'static KeyspaceHandle {
        static REVS: std::sync::LazyLock<(tempfile::TempDir, KeyspaceHandle)> =
            std::sync::LazyLock::new(|| {
                let dir = tempfile::tempdir().expect("tempdir");
                let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
                    data_dir: dir.path().to_path_buf(),
                })
                .expect("open store");
                let ks = store
                    .keyspace(crate::ROOM_REVOCATIONS_KEYSPACE)
                    .expect("keyspace");
                (dir, ks)
            });
        &REVS.1
    }

    /// The per-room gate serializing list acceptance against authorization
    /// (`rooms/revocations/put`, *Enforcement* item 3).
    ///
    /// Authorization holds the room's gate **shared** from before it reads the held list
    /// until the operation it authorized has committed — [`crate::authz::AuthorizedAction`]
    /// carries the guard, and a handler keeps that value until it answers. Accepting a list
    /// holds the gate **exclusively**. So no mutation verified before a list was accepted
    /// commits after it: acceptance waits for every operation already authorized to finish,
    /// and every operation authorized after acceptance reads the new list.
    ///
    /// Process-wide, keyed by room, because the property must hold whichever handle a
    /// request came in on; a second gate per state value would be no gate. Two hosts in one
    /// process (tests) that share a room id only serialize more than they need to.
    ///
    /// **One authorization per room per request.** The gate is fair: a writer waiting
    /// blocks later readers, so a request that authorized twice on one room while holding
    /// the first could deadlock against a list delivery. No handler does.
    pub mod gate {
        use super::*;

        static GATES: std::sync::LazyLock<Mutex<HashMap<String, Weak<RwLock<()>>>>> =
            std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

        fn lock_for(room_id: &str) -> Arc<RwLock<()>> {
            let mut gates = GATES.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(gate) = gates.get(room_id).and_then(Weak::upgrade) {
                return gate;
            }
            // Drop the entries nobody holds any more, so the map stays the size of the
            // rooms in use rather than every room ever touched.
            if gates.len() >= 1024 {
                gates.retain(|_, w| w.strong_count() > 0);
            }
            let gate = Arc::new(RwLock::new(()));
            gates.insert(room_id.to_string(), Arc::downgrade(&gate));
            gate
        }

        /// Held by an authorization until what it authorized has committed.
        pub struct Shared(#[allow(dead_code)] OwnedRwLockReadGuard<()>);

        /// Held while a list is accepted.
        pub struct Exclusive(#[allow(dead_code)] OwnedRwLockWriteGuard<()>);

        impl std::fmt::Debug for Shared {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("gate::Shared")
            }
        }
        impl std::fmt::Debug for Exclusive {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("gate::Exclusive")
            }
        }

        /// The room's gate, shared.
        pub async fn read(room_id: &str) -> Shared {
            Shared(lock_for(room_id).read_owned().await)
        }

        /// The room's gate, exclusive.
        pub async fn write(room_id: &str) -> Exclusive {
            Exclusive(lock_for(room_id).write_owned().await)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Visibility;

    const ROOM: &str = "did:webvh:QmRoom:rooms.example:deal";

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn list(sequence: u64, entries: Vec<Value>) -> Value {
        serde_json::json!({
            "roomId": ROOM,
            "sequence": sequence,
            "issuedAt": "2026-10-16T09:29:58Z",
            "entries": entries,
            "proof": { "type": "DataIntegrityProof", "proofValue": format!("z{sequence}") },
        })
    }

    fn subject(did: &str, at: &str) -> Value {
        serde_json::json!({ "kind": "subject", "subject": did, "revokedAt": at })
    }

    fn parsed(v: &Value) -> RevocationList {
        RevocationList::parse(v, ROOM).expect("a well-formed list")
    }

    fn facts(subject: &str, issuer: &str, from: Option<&str>) -> CredentialFacts {
        CredentialFacts {
            id: Some("urn:uuid:c".into()),
            subject: subject.into(),
            issuer: issuer.into(),
            valid_from: from.map(t),
        }
    }

    // ─── rooms/revocations/put item 2: listInvalid ───────────────────────────

    #[test]
    fn a_list_for_another_room_is_invalid() {
        let mut v = list(1, vec![]);
        v["roomId"] = "did:key:zOther".into();
        assert!(matches!(
            RevocationList::parse(&v, ROOM),
            Err(ListRefusal::ListInvalid(_))
        ));
    }

    #[test]
    fn a_subject_entry_naming_the_room_is_invalid() {
        let v = list(1, vec![subject(ROOM, "2026-10-16T09:00:00Z")]);
        assert!(matches!(
            RevocationList::parse(&v, ROOM),
            Err(ListRefusal::ListInvalid(_))
        ));
    }

    #[test]
    fn a_list_without_a_proof_or_with_a_stray_member_is_invalid() {
        let mut v = list(1, vec![]);
        v.as_object_mut().unwrap().remove("proof");
        assert!(RevocationList::parse(&v, ROOM).is_err());
        let mut v = list(1, vec![]);
        v["note"] = "x".into();
        assert!(RevocationList::parse(&v, ROOM).is_err());
        let v = list(
            1,
            vec![
                serde_json::json!({"kind": "room", "subject": "did:key:z", "revokedAt": "2026-10-16T09:00:00Z"}),
            ],
        );
        assert!(RevocationList::parse(&v, ROOM).is_err());
    }

    // ─── item 3: entryNotPermitted on a private room ─────────────────────────

    #[test]
    fn a_private_room_accepts_only_room_entries() {
        let naming = parsed(&list(
            1,
            vec![subject("did:key:zA", "2026-10-16T09:00:00Z")],
        ));
        assert_eq!(
            naming.accept(Visibility::Private, None, Utc::now()),
            Err(ListRefusal::EntryNotPermitted)
        );
        let reset = parsed(&list(
            1,
            vec![serde_json::json!({"kind": "room", "revokedAt": "2026-10-16T09:00:00Z"})],
        ));
        assert_eq!(
            reset.accept(Visibility::Private, None, Utc::now()),
            Ok(Acceptance::New)
        );
    }

    // ─── item 4: sequence and append-only ────────────────────────────────────

    #[test]
    fn a_lower_sequence_is_stale_and_names_the_held_one() {
        let held = parsed(&list(4, vec![]));
        let old = parsed(&list(3, vec![]));
        assert_eq!(
            old.accept(Visibility::Open, Some(&held), Utc::now()),
            Err(ListRefusal::Stale { held_sequence: 4 })
        );
    }

    #[test]
    fn the_same_list_again_is_a_repeat_and_a_different_one_a_conflict() {
        let held = parsed(&list(2, vec![]));
        assert_eq!(
            parsed(&list(2, vec![])).accept(Visibility::Open, Some(&held), Utc::now()),
            Ok(Acceptance::Repeat)
        );
        let fork = parsed(&list(
            2,
            vec![subject("did:key:zA", "2026-10-16T09:00:00Z")],
        ));
        assert_eq!(
            fork.accept(Visibility::Open, Some(&held), Utc::now()),
            Err(ListRefusal::SequenceConflict)
        );
    }

    #[test]
    fn a_later_list_must_keep_every_live_entry() {
        let a = subject("did:key:zA", "2026-10-16T09:00:00Z");
        let held = parsed(&list(1, vec![a.clone()]));
        let dropped = parsed(&list(2, vec![]));
        assert_eq!(
            dropped.accept(Visibility::Open, Some(&held), Utc::now()),
            Err(ListRefusal::NotAppendOnly)
        );
        let kept = parsed(&list(
            2,
            vec![a, subject("did:key:zB", "2026-10-16T10:00:00Z")],
        ));
        assert_eq!(
            kept.accept(Visibility::Open, Some(&held), Utc::now()),
            Ok(Acceptance::New)
        );
    }

    #[test]
    fn an_entry_past_its_until_may_be_dropped() {
        let lapsed = serde_json::json!({
            "kind": "credential", "credentialId": "urn:uuid:x",
            "revokedAt": "2026-01-01T00:00:00Z", "until": "2026-02-01T00:00:00Z",
        });
        let held = parsed(&list(1, vec![lapsed]));
        assert_eq!(
            parsed(&list(2, vec![])).accept(
                Visibility::Open,
                Some(&held),
                t("2026-10-16T00:00:00Z")
            ),
            Ok(Acceptance::New)
        );
    }

    #[test]
    fn a_host_holding_nothing_accepts_any_sequence() {
        assert_eq!(
            parsed(&list(7, vec![])).accept(Visibility::Open, None, Utc::now()),
            Ok(Acceptance::New)
        );
    }

    // ─── Matching ────────────────────────────────────────────────────────────

    #[test]
    fn a_subject_entry_reaches_what_they_held_and_what_they_delegated_before_it() {
        let l = parsed(&list(
            1,
            vec![subject("did:key:zA", "2026-10-16T09:00:00Z")],
        ));
        // Their own credential, issued before.
        assert!(l.revokes(&facts("did:key:zA", ROOM, Some("2026-10-01T00:00:00Z"))));
        // What they delegated to an agent before: matched as issuer.
        assert!(l.revokes(&facts(
            "did:key:zAgent",
            "did:key:zA",
            Some("2026-10-02T00:00:00Z")
        )));
        // Re-admitted: a fresh credential issued after the withdrawal verifies.
        assert!(!l.revokes(&facts("did:key:zA", ROOM, Some("2026-10-16T09:00:01Z"))));
        // Nobody else.
        assert!(!l.revokes(&facts("did:key:zB", ROOM, Some("2026-10-01T00:00:00Z"))));
    }

    #[test]
    fn a_credential_without_valid_from_was_issued_before_every_entry() {
        let l = parsed(&list(
            1,
            vec![subject("did:key:zA", "2000-01-01T00:00:00Z")],
        ));
        assert!(l.revokes(&facts("did:key:zA", ROOM, None)));
    }

    /// A withdrawal made in the same second as a credential's issue, but after it, still
    /// reaches it: `revokedAt` is not truncated on the wire.
    #[test]
    fn a_withdrawal_reaches_a_credential_issued_earlier_in_the_same_second() {
        let issued = t("2026-10-16T09:00:00.200Z");
        let revoked = t("2026-10-16T09:00:00.700Z");
        let mut list = next_unsigned(
            ROOM,
            None,
            &[Entry::Subject {
                subject: "did:key:zA".into(),
                revoked_at: revoked,
                until: None,
            }],
            revoked,
        );
        list["proof"] = serde_json::json!({});
        let l = parsed(&list);
        let mut c = facts("did:key:zA", ROOM, None);
        c.valid_from = Some(issued);
        assert!(l.revokes(&c));
        c.valid_from = Some(t("2026-10-16T09:00:00.900Z"));
        assert!(!l.revokes(&c), "issued after it, in the same second");
    }

    #[test]
    fn a_credential_entry_matches_by_id_alone() {
        let l = parsed(&list(
            1,
            vec![
                serde_json::json!({"kind": "credential", "credentialId": "urn:uuid:c", "revokedAt": "2000-01-01T00:00:00Z"}),
            ],
        ));
        assert!(l.revokes(&facts("did:key:zX", ROOM, Some("2030-01-01T00:00:00Z"))));
        let mut other = facts("did:key:zX", ROOM, None);
        other.id = Some("urn:uuid:other".into());
        assert!(!l.revokes(&other));
    }

    #[test]
    fn a_room_entry_resets_everything_issued_before_it() {
        let l = parsed(&list(
            1,
            vec![serde_json::json!({"kind": "room", "revokedAt": "2026-10-16T09:00:00Z"})],
        ));
        assert!(l.revokes(&facts("did:key:zA", ROOM, Some("2026-10-16T08:59:59Z"))));
        assert!(!l.revokes(&facts("did:key:zA", ROOM, Some("2026-10-16T09:00:00Z"))));
    }

    /// A chain with any revoked link is refused whole, and a disclosing tier's presentation
    /// without its membership facts fails closed.
    #[test]
    fn any_withdrawn_link_withdraws_the_presentation() {
        let l = parsed(&list(
            1,
            vec![subject("did:key:zA", "2026-10-16T09:00:00Z")],
        ));
        let p = Presented {
            membership: Some(facts("did:key:zA", ROOM, Some("2026-10-17T00:00:00Z"))),
            authority: vec![
                facts("did:key:zAgent", "did:key:zA", Some("2026-10-17T00:00:00Z")),
                facts("did:key:zA", ROOM, Some("2026-10-01T00:00:00Z")),
            ],
        };
        assert!(l.withdraws(Visibility::Attributed, &p, Utc::now()));
        let blind = Presented::default();
        assert!(l.withdraws(Visibility::Open, &blind, Utc::now()));
        assert!(!parsed(&list(1, vec![])).withdraws(Visibility::Open, &blind, Utc::now()));
    }

    #[test]
    fn a_private_room_refuses_while_a_live_reset_is_held() {
        let l = parsed(&list(
            1,
            vec![serde_json::json!({"kind": "room", "revokedAt": "2026-10-16T09:00:00Z"})],
        ));
        assert!(l.withdraws(Visibility::Private, &Presented::default(), Utc::now()));
        let lapsed = parsed(&list(
            1,
            vec![
                serde_json::json!({"kind": "room", "revokedAt": "2026-01-01T00:00:00Z", "until": "2026-02-01T00:00:00Z"}),
            ],
        ));
        assert!(!lapsed.withdraws(
            Visibility::Private,
            &Presented::default(),
            t("2026-10-16T00:00:00Z")
        ));
    }

    // ─── Head and next list ──────────────────────────────────────────────────

    #[test]
    fn the_head_digest_covers_the_proof() {
        let a = parsed(&list(1, vec![]));
        let mut v = list(1, vec![]);
        v["proof"]["proofValue"] = "zOther".into();
        let b = parsed(&v);
        assert_eq!(a.head().sequence, 1);
        assert!(a.head().digest.starts_with("zQm"), "{}", a.head().digest);
        assert_ne!(a.head().digest, b.head().digest);
    }

    #[test]
    fn the_next_list_keeps_live_entries_drops_long_lapsed_ones_and_appends() {
        let now = t("2026-10-16T12:00:00Z");
        let held = parsed(&list(
            3,
            vec![
                serde_json::json!({"kind": "credential", "credentialId": "urn:uuid:old", "revokedAt": "2026-01-01T00:00:00Z", "until": "2026-10-10T00:00:00Z"}),
                // Lapsed less than a day ago: kept for a host whose clock is behind.
                serde_json::json!({"kind": "credential", "credentialId": "urn:uuid:recent", "revokedAt": "2026-01-01T00:00:00Z", "until": "2026-10-16T00:00:00Z"}),
                subject("did:key:zA", "2026-10-01T00:00:00Z"),
            ],
        ));
        let added = Entry::Subject {
            subject: "did:key:zB".into(),
            revoked_at: now,
            until: None,
        };
        let mut next = next_unsigned(ROOM, Some(&held), &[added], now);
        assert_eq!(next["sequence"], 4);
        let entries = next["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0]["credentialId"], "urn:uuid:recent");
        assert_eq!(entries[2]["subject"], "did:key:zB");
        next["proof"] = serde_json::json!({});
        let next = parsed(&next);
        assert_eq!(
            next.accept(Visibility::Open, Some(&held), now),
            Ok(Acceptance::New),
            "what a key holder builds, a host accepts"
        );
    }
}
