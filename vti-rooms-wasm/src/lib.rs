//! A data room's **member half**, for a browser.
//!
//! Everything a member does with a room's keys — holding the MLS group, sealing a record,
//! opening one, and walking the epoch key chain — with none of what a host does. The
//! implementation is [`vti_rooms`]; this crate is the boundary, and its whole job is to
//! decide what crosses it.
//!
//! # Why this exists at all
//!
//! Until now a member's keys lived in a VTA, and every browser surface was a *client* of
//! one: the wallet plugin drives an agent, `pnm-cli` drives an agent. That is right for an
//! agent's principal and wrong for a stranger with a link, who has no agent and should not
//! need one to look inside a room. With this, a tab is a member — it holds the group,
//! opens what it is entitled to, and asks a host for nothing it could compute itself.
//!
//! # The rule at the boundary
//!
//! **Secrets do not cross.** Everything that leaves this module is either public (a
//! KeyPackage, ciphertext, an epoch number) or a snapshot that is opaque to JavaScript and
//! meant only to be handed back. Nothing returns a group key, a signature key, or a leaf
//! secret, and no method takes one — because a key that crosses into JS is a key in a
//! string, in a heap the page shares with everything else on it.
//!
//! A snapshot is the exception that proves it: it *is* key material, base64 inside JSON,
//! and it exists because OpenMLS persists a group through its provider rather than as a
//! value. The caller's job is to put it in IndexedDB and nowhere else. It is not a
//! backup format and must never be sent anywhere.
//!
//! # Two layers, and why the inner one exists
//!
//! Every method appears twice: a plain Rust one carrying the logic, and a thin
//! `#[wasm_bindgen]` wrapper that only converts the error. That is not ceremony —
//! `JsError` and `JsValue` are *imported JS functions*, so constructing one on a native
//! target panics outright. A crate whose only entry points were wrapped would therefore
//! have no reachable native tests at all, and the tests worth having here are exactly the
//! ones that assert a failure: a record that must not open at the wrong version, a stale
//! snapshot that must refuse rather than return garbage. Those are unreachable through the
//! wrapper, so the logic lives below it.
//!
//! # Shape of the API
//!
//! JSON strings in and out, `Uint8Array` for record bodies. Deliberately not
//! `serde-wasm-bindgen`: the structures crossing here are small, they are the published
//! `rooms/*` wire types, and a JSON string is the form they already travel in over the
//! network — so the boundary speaks the same language as the transport and there is one
//! fewer representation to get wrong.
//!
//! # Joining is two calls, and they are days apart
//!
//! [`mint_key_package`] produces an identity and the KeyPackage to send; [`RoomMember::join`]
//! consumes both when the Welcome comes back. Between them the identity snapshot **is
//! retained private key material** — that is why minting is not free and why a member who
//! never joins should discard it. Joining with a *fresh* identity instead produces a group
//! whose leaf nobody added, which fails at the first read looking like a bad Welcome rather
//! than a wrong identity.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use vti_rooms::mls::{GroupSnapshot, IdentitySnapshot, RoomGroup};
use vti_rooms::sealed::SealedRoom;
use vti_rooms::wire::{EpochLink, SealedContent};
use wasm_bindgen::prelude::*;

/// What [`mint_key_package`] returns: the half to keep, and the half to send.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MintedIdentity {
    /// Retain this — privately. The Welcome will be sealed to it.
    identity: IdentitySnapshot,
    /// Send this to the room's owner. Public.
    key_package: String,
}

/// What [`RoomMember::apply_commit`] returns.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitApplied {
    /// The room epoch after the commit.
    epoch: u32,
    /// The rung this commit produced, or `null` for the first one.
    link: Option<EpochLink>,
}

/// Everything needed to reconstruct a [`RoomMember`].
///
/// Three parts because they have three different lifetimes: the room id never changes, the
/// group advances with every commit, and the links only ever accumulate.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberSnapshot {
    room_id: String,
    group: GroupSnapshot,
    /// Ascending. Ciphertext — a party holding no epoch key learns nothing from them.
    #[serde(default)]
    links: Vec<EpochLink>,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// The only place a JS error is constructed. See the module docs on why it is only here.
fn js(e: String) -> JsError {
    JsError::new(&e)
}

/// Mint an identity and a KeyPackage for **one** room.
///
/// Returns `{ identity, keyPackage }` as JSON. Send `keyPackage` to the room's owner and
/// keep `identity` until the Welcome arrives.
///
/// **One per room, never reused.** A KeyPackage is a stable public identifier, so offering
/// the same one to two rooms tells anybody who sees both that one party is in both — the
/// correlation a `private` room exists to deny, arriving through the door rather than
/// through the wall.
pub fn mint_key_package(member_did: &str) -> Result<String, String> {
    let (identity, key_package) = IdentitySnapshot::mint(member_did).map_err(err)?;
    serde_json::to_string(&MintedIdentity {
        identity,
        key_package: B64.encode(key_package),
    })
    .map_err(err)
}

/// See [`mint_key_package`].
#[wasm_bindgen(js_name = mintKeyPackage)]
pub fn mint_key_package_js(member_did: &str) -> Result<String, JsError> {
    mint_key_package(member_did).map_err(js)
}

/// One room this browser can open.
///
/// Holds the MLS group and the epoch key chain. Every method that resolves a key takes
/// `&mut self`, because walking the chain memoises what it derives — opening a room's
/// history is one walk, not one per record.
#[wasm_bindgen]
pub struct RoomMember {
    inner: SealedRoom,
}

impl RoomMember {
    /// Accept a Welcome, using the identity whose KeyPackage the owner added.
    ///
    /// `minted` is the JSON from [`mint_key_package`]; `welcome` is the Welcome bytes the
    /// owner sent. The identity is consumed here and should be discarded afterwards.
    ///
    /// Fails rather than half-joining if the Welcome was not sealed to this identity.
    pub fn join(room_id: &str, minted: &str, welcome: &[u8]) -> Result<RoomMember, String> {
        let minted: MintedIdentity = serde_json::from_str(minted).map_err(err)?;
        let group = RoomGroup::join_from_identity(&minted.identity, welcome).map_err(err)?;
        Ok(RoomMember {
            inner: SealedRoom::new(room_id, group),
        })
    }

    /// Reconstruct from a snapshot previously returned by [`RoomMember::snapshot`].
    pub fn restore(snapshot: &str) -> Result<RoomMember, String> {
        let snap: MemberSnapshot = serde_json::from_str(snapshot).map_err(err)?;
        let group = RoomGroup::restore(&snap.group).map_err(err)?;
        let mut inner = SealedRoom::new(snap.room_id, group);
        inner.add_links(snap.links);
        Ok(RoomMember { inner })
    }

    /// Everything needed to reconstruct this member, as JSON.
    ///
    /// **This is key material.** It belongs in IndexedDB on this device and nowhere else:
    /// not in `localStorage` a script can read as a string, not in a URL, not in a
    /// "backup" sent anywhere. Anyone holding it can read every record this member can.
    ///
    /// Take a fresh one after every call that advances the group — [`RoomMember::join`],
    /// [`RoomMember::apply_commit`] — or the next restore comes back at the old epoch and
    /// every record written since fails to open, which reads as corruption rather than as
    /// a snapshot that was not saved.
    pub fn snapshot(&self) -> Result<String, String> {
        serde_json::to_string(&MemberSnapshot {
            room_id: self.inner.room_id().to_string(),
            group: self.inner.group().snapshot().map_err(err)?,
            links: self.inner.links(),
        })
        .map_err(err)
    }

    /// The room this member belongs to.
    pub fn room_id(&self) -> String {
        self.inner.room_id().to_string()
    }

    /// The epoch this member is at.
    ///
    /// Behind the room's own epoch means a commit has not been delivered — not that
    /// anything is lost. Show it beside [`RoomMember::earliest_readable_epoch`]: they are
    /// different repairs, and collapsing them into one number makes "less history than I
    /// expected" read as loss rather than as a delivery that has not happened yet.
    pub fn epoch(&self) -> u32 {
        self.inner.room_epoch()
    }

    /// The earliest epoch this member can currently open.
    ///
    /// On a chained room this should be 1. Anything else means either links that have not
    /// been delivered, or history that was deliberately severed at the join — and only the
    /// party that *walks* the chain can answer it, which is why no host serves this number.
    pub fn earliest_readable_epoch(&mut self) -> Result<u32, String> {
        self.inner.earliest_readable_epoch().map_err(err)
    }

    /// Apply a commit — a membership change somebody else made.
    ///
    /// **Not optional.** A member who misses one is stuck at their last epoch and can open
    /// nothing sealed after it; the symptom is "this record does not open", which reads
    /// like corruption rather than a missed message.
    ///
    /// Returns `{ epoch, link }`. The link is a rung of the epoch key chain, minted in the
    /// one moment any party knows both the outgoing key and the incoming one, and it has
    /// already been added to this member's chain — it is returned because it is also what a
    /// host stores on the member's behalf, and because a member who never uploads one keeps
    /// their history only as long as this browser does. `null` on the first commit, which
    /// has no predecessor epoch to wrap.
    pub fn apply_commit(&mut self, commit: &[u8]) -> Result<String, String> {
        let (epoch, link) = self.inner.apply_commit(commit).map_err(err)?;
        serde_json::to_string(&CommitApplied { epoch, link }).map_err(err)
    }

    /// Add epoch links, extending how far back this member can read.
    ///
    /// Takes the JSON array a host's `rooms/epoch/chain` returns. Idempotent and
    /// order-independent — a rung already held is never replaced, because a second rung for
    /// an epoch is either a replay (which must be a no-op, or a retried delivery becomes a
    /// failure) or an attempt to re-point this member's history at somebody else's key
    /// material.
    pub fn add_links(&mut self, links: &str) -> Result<(), String> {
        let links: Vec<EpochLink> = serde_json::from_str(links).map_err(err)?;
        self.inner.add_links(links);
        Ok(())
    }

    /// Seal a record for writing. Returns `{ ciphertext, nonce, epoch }` as JSON.
    ///
    /// `version` **must** be the version the write will be stored at: it is bound into the
    /// ciphertext along with the room, the key and the epoch. Get it wrong and the record
    /// stores fine and never opens.
    pub fn seal_record(&self, key: &str, version: u64, plaintext: &[u8]) -> Result<String, String> {
        let sealed = self
            .inner
            .seal_record(key, version, plaintext)
            .map_err(err)?;
        serde_json::to_string(&sealed).map_err(err)
    }

    /// Open a record a host returned.
    ///
    /// Fails rather than returning wrong bytes if the record was relocated, if its epoch
    /// was relabelled, or if the key for that epoch is not one this member can reach. The
    /// key used is the one for the *record's* epoch, walked out of the chain — never the
    /// group's current key.
    pub fn open_record(
        &mut self,
        key: &str,
        version: u64,
        sealed: &str,
    ) -> Result<Vec<u8>, String> {
        let sealed: SealedContent = serde_json::from_str(sealed).map_err(err)?;
        self.inner.open_record(key, version, &sealed).map_err(err)
    }
}

/// The JS boundary: error conversion and nothing else.
///
/// Every method here is one line over its namesake above. Keeping it that way is the point
/// — a wrapper that grew logic would be logic no native test could reach.
#[wasm_bindgen]
impl RoomMember {
    /// See [`RoomMember::join`].
    #[wasm_bindgen(js_name = join)]
    pub fn join_js(room_id: &str, minted: &str, welcome: &[u8]) -> Result<RoomMember, JsError> {
        Self::join(room_id, minted, welcome).map_err(js)
    }

    /// See [`RoomMember::restore`].
    #[wasm_bindgen(js_name = restore)]
    pub fn restore_js(snapshot: &str) -> Result<RoomMember, JsError> {
        Self::restore(snapshot).map_err(js)
    }

    /// See [`RoomMember::snapshot`].
    #[wasm_bindgen(js_name = snapshot)]
    pub fn snapshot_js(&self) -> Result<String, JsError> {
        self.snapshot().map_err(js)
    }

    /// See [`RoomMember::room_id`].
    #[wasm_bindgen(getter, js_name = roomId)]
    pub fn room_id_js(&self) -> String {
        self.room_id()
    }

    /// See [`RoomMember::epoch`].
    #[wasm_bindgen(getter, js_name = epoch)]
    pub fn epoch_js(&self) -> u32 {
        self.epoch()
    }

    /// See [`RoomMember::earliest_readable_epoch`].
    #[wasm_bindgen(js_name = earliestReadableEpoch)]
    pub fn earliest_readable_epoch_js(&mut self) -> Result<u32, JsError> {
        self.earliest_readable_epoch().map_err(js)
    }

    /// See [`RoomMember::apply_commit`].
    #[wasm_bindgen(js_name = applyCommit)]
    pub fn apply_commit_js(&mut self, commit: &[u8]) -> Result<String, JsError> {
        self.apply_commit(commit).map_err(js)
    }

    /// See [`RoomMember::add_links`].
    #[wasm_bindgen(js_name = addLinks)]
    pub fn add_links_js(&mut self, links: &str) -> Result<(), JsError> {
        self.add_links(links).map_err(js)
    }

    /// See [`RoomMember::seal_record`].
    #[wasm_bindgen(js_name = sealRecord)]
    pub fn seal_record_js(
        &self,
        key: &str,
        version: u64,
        plaintext: &[u8],
    ) -> Result<String, JsError> {
        self.seal_record(key, version, plaintext).map_err(js)
    }

    /// See [`RoomMember::open_record`].
    #[wasm_bindgen(js_name = openRecord)]
    pub fn open_record_js(
        &mut self,
        key: &str,
        version: u64,
        sealed: &str,
    ) -> Result<Vec<u8>, JsError> {
        self.open_record(key, version, sealed).map_err(js)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_rooms::mls::RoomGroup;

    /// The whole member story in one test, because the failures worth catching are all
    /// *between* the steps: a snapshot taken before a commit, a version bound into
    /// ciphertext that the write then disagrees with, a chain that was never fed.
    #[test]
    fn a_member_joins_reads_and_survives_a_restart() {
        // The owner's side. Not part of this crate's API — a browser member is never an
        // owner — but a Welcome has to come from somewhere.
        let mut owner = RoomGroup::create("did:key:zOwner").unwrap();
        let owner_room_id = "did:webvh:example.com:room";

        let minted = mint_key_package("did:key:zJoiner").unwrap();
        let parsed: MintedIdentity = serde_json::from_str(&minted).unwrap();
        let key_package = B64.decode(&parsed.key_package).unwrap();

        let change = owner.add_member_from_bytes(&key_package).unwrap();
        let welcome = change
            .welcome
            .clone()
            .expect("adding a member makes a Welcome");

        let mut member = RoomMember::join(owner_room_id, &minted, &welcome).unwrap();
        assert_eq!(member.room_id(), owner_room_id);

        // A record the member writes and reads back.
        let sealed = member.seal_record("rec-1", 7, b"hello").unwrap();
        let opened = member.open_record("rec-1", 7, &sealed).unwrap();
        assert_eq!(opened, b"hello");

        // The version is bound into the ciphertext, not merely alongside it.
        assert!(
            member.open_record("rec-1", 8, &sealed).is_err(),
            "a record must not open at a version it was not sealed for"
        );

        // …and so is the record key.
        assert!(
            member.open_record("rec-2", 7, &sealed).is_err(),
            "a record must not open under a key it was not sealed for"
        );

        // A restart: everything the browser keeps is this string.
        let snapshot = member.snapshot().unwrap();
        let mut restored = RoomMember::restore(&snapshot).unwrap();
        assert_eq!(restored.epoch(), member.epoch());
        assert_eq!(
            restored.open_record("rec-1", 7, &sealed).unwrap(),
            b"hello",
            "a restored member reads what it wrote before the restart"
        );

        // Nothing was fed to the chain, so this member reads from its join epoch only.
        assert_eq!(
            restored.earliest_readable_epoch().unwrap(),
            restored.epoch(),
            "with no links, the earliest readable epoch is the current one"
        );
    }

    /// The failure this crate exists to make impossible to hit silently: a snapshot taken
    /// before a commit restores to a member who cannot read what came after it.
    #[test]
    fn a_snapshot_taken_before_a_commit_is_stale() {
        let mut owner = RoomGroup::create("did:key:zOwner").unwrap();
        let minted = mint_key_package("did:key:zJoiner").unwrap();
        let parsed: MintedIdentity = serde_json::from_str(&minted).unwrap();
        let change = owner
            .add_member_from_bytes(&B64.decode(&parsed.key_package).unwrap())
            .unwrap();
        let mut member = RoomMember::join(
            "did:webvh:example.com:room",
            &minted,
            &change.welcome.unwrap(),
        )
        .unwrap();

        let stale = member.snapshot().unwrap();

        // Somebody else joins; the commit advances everyone's epoch.
        let other = mint_key_package("did:key:zOther").unwrap();
        let other_parsed: MintedIdentity = serde_json::from_str(&other).unwrap();
        let change = owner
            .add_member_from_bytes(&B64.decode(&other_parsed.key_package).unwrap())
            .unwrap();
        let applied: CommitApplied =
            serde_json::from_str(&member.apply_commit(&change.commit).unwrap()).unwrap();
        assert!(applied.epoch > RoomMember::restore(&stale).unwrap().epoch());
        assert!(
            applied.link.is_some(),
            "a commit past the first mints a rung, which is what keeps history readable"
        );

        // A record written at the new epoch does not open for the stale snapshot — and
        // fails as a refusal, not as garbage.
        let sealed = member.seal_record("rec-1", 1, b"after").unwrap();
        let mut stale = RoomMember::restore(&stale).unwrap();
        assert!(stale.open_record("rec-1", 1, &sealed).is_err());
    }
}
