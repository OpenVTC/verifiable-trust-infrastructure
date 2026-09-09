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

pub mod identity;
pub mod invitation;

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
pub fn mint_key_package(
    member_did: &str,
    room_id: &str,
    invitation: &str,
    spent: &str,
) -> Result<String, String> {
    // Gated, and gated *here* rather than only at the Welcome, because minting is
    // not free: it retains a private key against a Welcome that may never come. A
    // key holder that minted for anyone is one anyone can fill.
    let spent: Vec<String> = serde_json::from_str(spent).map_err(err)?;
    invitation::verify(invitation, room_id, member_did, &spent)?;

    let (identity, key_package) = IdentitySnapshot::mint(member_did).map_err(err)?;
    serde_json::to_string(&MintedIdentity {
        identity,
        key_package: B64.encode(key_package),
    })
    .map_err(err)
}

/// See [`mint_key_package`].
#[wasm_bindgen(js_name = mintKeyPackage)]
pub fn mint_key_package_js(
    member_did: &str,
    room_id: &str,
    invitation: &str,
    spent: &str,
) -> Result<String, JsError> {
    mint_key_package(member_did, room_id, invitation, spent).map_err(js)
}

/// A member's signing identity — the JS boundary over [`identity::MemberIdentity`].
///
/// Every secret this member has now lives on this side: the Ed25519 key that names their
/// `did:key` and signs, and the MLS keys inside [`RoomMember`]. JavaScript holds two opaque
/// snapshots and no key.
#[wasm_bindgen]
pub struct Identity {
    inner: identity::MemberIdentity,
}

#[wasm_bindgen]
impl Identity {
    /// Mint a fresh `did:key`.
    #[wasm_bindgen(js_name = mint)]
    pub fn mint_js() -> Result<Identity, JsError> {
        identity::MemberIdentity::mint()
            .map(|inner| Identity { inner })
            .map_err(js)
    }

    /// Restore one from [`Identity::snapshot`].
    #[wasm_bindgen(js_name = restore)]
    pub fn restore_js(snapshot: &str) -> Result<Identity, JsError> {
        identity::MemberIdentity::restore(snapshot)
            .map(|inner| Identity { inner })
            .map_err(js)
    }

    /// **Key material.** Per-origin, per-device storage and nowhere else — anyone holding
    /// this is this member.
    #[wasm_bindgen(js_name = snapshot)]
    pub fn snapshot_js(&self) -> Result<String, JsError> {
        self.inner.snapshot().map_err(js)
    }

    #[wasm_bindgen(getter, js_name = did)]
    pub fn did_js(&self) -> String {
        self.inner.did().to_string()
    }

    /// See [`identity::MemberIdentity::sign_document`].
    #[wasm_bindgen(js_name = signDocument)]
    pub fn sign_document_js(&self, document: &str) -> Result<String, JsError> {
        self.inner.sign_document(document).map_err(js)
    }

    /// See [`identity::MemberIdentity::present`].
    #[wasm_bindgen(js_name = present)]
    pub fn present_js(
        &self,
        vac: &str,
        vmc: &str,
        action: &str,
        nonce: Option<String>,
    ) -> Result<String, JsError> {
        self.inner
            .present(vac, vmc, action, nonce.as_deref())
            .map_err(js)
    }
}

/// Run the five invitation checks and return the credential id to record as spent.
///
/// Exposed separately from [`mint_key_package`] so a surface can *show* the checks — which
/// is most of what a person needs to understand about a room they are being let into.
#[wasm_bindgen(js_name = verifyInvitation)]
pub fn verify_invitation_js(
    invitation: &str,
    room_id: &str,
    member_did: &str,
    spent: &str,
) -> Result<String, JsError> {
    let spent: Vec<String> = serde_json::from_str(spent).map_err(|e| js(e.to_string()))?;
    invitation::verify(invitation, room_id, member_did, &spent)
        .map(|v| v.credential_id)
        .map_err(js)
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
    pub fn join(
        room_id: &str,
        minted: &str,
        welcome: &[u8],
        invitation: &str,
        spent: &str,
    ) -> Result<RoomMember, String> {
        let minted: MintedIdentity = serde_json::from_str(minted).map_err(err)?;

        // The same invitation, checked again and consumed by the caller after this
        // returns. A Welcome carries a group's secrets, so a key holder that
        // accepted an uninvited one would hold keys for a room nobody agreed to
        // join — and would have made the invitation decorative.
        let spent: Vec<String> = serde_json::from_str(spent).map_err(err)?;
        invitation::verify(invitation, room_id, minted.identity.member_did(), &spent)?;

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
    pub fn join_js(
        room_id: &str,
        minted: &str,
        welcome: &[u8],
        invitation: &str,
        spent: &str,
    ) -> Result<RoomMember, JsError> {
        Self::join(room_id, minted, welcome, invitation, spent).map_err(js)
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
    use crate::invitation::verify;
    /// A room with a real `did:key` identity, and the secret it signs invitations with.
    ///
    /// `did:key` because the whole invitation check has to be lexical here: a browser
    /// verifying a proof cannot go and resolve something, and a room that carries its key
    /// in its own name means it does not have to.
    fn a_room(seed: u8) -> (String, affinidi_secrets_resolver::secrets::Secret) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(&pk);
        let did = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &mc)
        );
        let secret = affinidi_secrets_resolver::secrets::Secret::from_str(
            // The `did:key` convention: the multibase tag IS the fragment.
            &format!("{did}#{}", did.trim_start_matches("did:key:")),
            &serde_json::json!({
                "crv": "Ed25519",
                "d": B64U.encode(sk.to_bytes()),
                "kty": "OKP",
                "x": B64U.encode(pk),
            }),
        )
        .expect("build the room's signing secret");
        (did, secret)
    }

    /// An invitation from `room` to `subject`, signed, open from a minute ago for an hour.
    fn an_invitation(
        room: &str,
        secret: &affinidi_secrets_resolver::secrets::Secret,
        subject: &str,
        id: &str,
    ) -> String {
        let now = chrono::Utc::now();
        an_invitation_valid(
            room,
            secret,
            subject,
            id,
            now - chrono::Duration::minutes(1),
            Some(now + chrono::Duration::hours(1)),
        )
    }

    /// The same, with the window said explicitly.
    ///
    /// Split out because a window cannot be tested by a helper that hardcodes a good one —
    /// which is why it was not tested.
    fn an_invitation_valid(
        room: &str,
        secret: &affinidi_secrets_resolver::secrets::Secret,
        subject: &str,
        id: &str,
        from: chrono::DateTime<chrono::Utc>,
        until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> String {
        let mut vic = dtg_credentials::DTGCredential::new_vic(
            room.to_string(),
            subject.to_string(),
            from,
            until,
        )
        .with_id(id);
        futures_lite::future::block_on(vic.sign(secret, None)).expect("sign the invitation");
        serde_json::to_string(vic.credential()).expect("serialise the invitation")
    }

    const NONE_SPENT: &str = "[]";

    use vti_rooms::mls::RoomGroup;

    /// The whole member story in one test, because the failures worth catching are all
    /// *between* the steps: a snapshot taken before a commit, a version bound into
    /// ciphertext that the write then disagrees with, a chain that was never fed.
    #[test]
    fn a_member_joins_reads_and_survives_a_restart() {
        // The owner's side. Not part of this crate's API — a browser member is never an
        // owner — but a Welcome has to come from somewhere.
        let mut owner = RoomGroup::create("did:key:zOwner").unwrap();

        let (room_did, room_secret) = a_room(0x11);
        let joiner = "did:key:zJoiner";
        let vic = an_invitation(&room_did, &room_secret, joiner, "urn:uuid:invite-1");
        let minted = mint_key_package(joiner, &room_did, &vic, NONE_SPENT).unwrap();
        let parsed: MintedIdentity = serde_json::from_str(&minted).unwrap();
        let key_package = B64.decode(&parsed.key_package).unwrap();

        let change = owner.add_member_from_bytes(&key_package).unwrap();
        let welcome = change
            .welcome
            .clone()
            .expect("adding a member makes a Welcome");

        let mut member = RoomMember::join(&room_did, &minted, &welcome, &vic, NONE_SPENT).unwrap();
        assert_eq!(member.room_id(), room_did);

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

    /// A room grants a member `read`; the browser narrows it to one action and signs; the
    /// **real chain verifier** accepts it.
    ///
    /// This is the assertion the whole authority slice rests on, and it is deliberately
    /// made against `dtg_credentials::authority::verify_chain` — the same function a host
    /// runs — rather than against a restatement of what it ought to do.
    ///
    /// It also pins the shape that is unusual here. Server-side, a presentation attenuates
    /// to a *separate agent*, so the leaf's subject differs from the chain root's. A browser
    /// member is its own agent, so they are the same DID: a case the VTA's path never
    /// produces. The pooling defence compares the chain's **root** subject rather than its
    /// leaf, so it should hold — asserted here rather than assumed.
    #[test]
    fn a_browser_minted_presentation_verifies_against_the_real_chain_verifier() {
        use dtg_credentials::authority::verify_chain;

        let (room, room_secret) = a_room(0x31);
        let me = crate::identity::MemberIdentity::mint().unwrap();
        let now = chrono::Utc::now();

        // The room grants this member `read` and `curate` at its own scope.
        let mut vac = dtg_credentials::DTGCredential::new_vac(
            room.clone(),
            me.did().to_string(),
            room.clone(),
            vec!["read".into(), "curate".into()],
            now - chrono::Duration::minutes(1),
            now + chrono::Duration::days(30),
        )
        .expect("mint the room's authority credential")
        .with_id("urn:uuid:vac-1");
        futures_lite::future::block_on(vac.sign(&room_secret, None)).unwrap();
        let vac_json = serde_json::to_string(vac.credential()).unwrap();
        let vmc_json = serde_json::json!({ "id": "urn:uuid:vmc-1" }).to_string();

        let presentation: serde_json::Value = serde_json::from_str(
            &me.present(&vac_json, &vmc_json, "read", Some("n-1"))
                .expect("mint a presentation"),
        )
        .unwrap();

        // Echoed unchanged: its value to the verifier is that it came back as sent.
        assert_eq!(presentation["nonce"], "n-1");

        // The wire form is strings, so a verifier parses each link before checking it.
        // Asserted rather than assumed: a host handed objects instead refuses the whole
        // request as "invalid type: map, expected a string", which reads as a malformed
        // payload rather than as the shape mismatch it is.
        let chain: Vec<dtg_credentials::DTGCredential> = presentation["authority"]
            .as_array()
            .expect("authority is an array")
            .iter()
            .map(|link| {
                serde_json::from_str(link.as_str().expect("each link is a string")).unwrap()
            })
            .collect();
        assert_eq!(
            chain.len(),
            2,
            "leaf first, then the credential the room issued"
        );
        assert!(
            presentation["membership"].is_string(),
            "membership travels as a string too"
        );

        verify_chain(&chain, &room, &room, "read", me.did(), chrono::Utc::now())
            .expect("the host's own verifier must accept what the browser minted");

        // The narrowing is real: `curate` is held at the root but was not asked for, so the
        // leaf does not carry it. A presentation is for one action.
        assert!(
            verify_chain(&chain, &room, &room, "curate", me.did(), chrono::Utc::now()).is_err(),
            "a presentation minted for `read` must not authorise `curate`"
        );
    }

    /// A captured presentation is worthless to anyone else.
    ///
    /// This is what the `audience` binding buys, and the reason [`identity::MemberIdentity::present`]
    /// takes no audience parameter: bound to the member, a presentation somebody observes on
    /// the wire authorises nothing when they present it themselves.
    ///
    /// Worth pinning because the same field, filled with the *host's* DID instead, refuses
    /// the legitimate presenter and protects nobody — which is what `vta-cli-common` does
    /// today.
    #[test]
    fn a_captured_presentation_does_not_work_for_whoever_captured_it() {
        use dtg_credentials::authority::verify_chain;

        let (room, room_secret) = a_room(0x33);
        let me = crate::identity::MemberIdentity::mint().unwrap();
        let thief = crate::identity::MemberIdentity::mint().unwrap();
        let now = chrono::Utc::now();

        let mut vac = dtg_credentials::DTGCredential::new_vac(
            room.clone(),
            me.did().to_string(),
            room.clone(),
            vec!["read".into()],
            now - chrono::Duration::minutes(1),
            now + chrono::Duration::days(30),
        )
        .unwrap()
        .with_id("urn:uuid:vac-3");
        futures_lite::future::block_on(vac.sign(&room_secret, None)).unwrap();

        let presentation: serde_json::Value = serde_json::from_str(
            &me.present(
                &serde_json::to_string(vac.credential()).unwrap(),
                "{}",
                "read",
                None,
            )
            .unwrap(),
        )
        .unwrap();
        let chain: Vec<dtg_credentials::DTGCredential> = presentation["authority"]
            .as_array()
            .unwrap()
            .iter()
            .map(|link| serde_json::from_str(link.as_str().unwrap()).unwrap())
            .collect();

        // The rightful member: accepted.
        verify_chain(&chain, &room, &room, "read", me.did(), chrono::Utc::now()).unwrap();

        // Whoever lifted it off the wire: refused, and refused for the right reason — the
        // chain is perfectly valid, it is just not theirs.
        //
        // The refusal used to be `WrongAudience`, from a leaf this method bound to its own
        // subject. dtg-credentials 0.8 removed `audience` and made the subject rule the
        // library's own, so the same property is now enforced without a field to fill in:
        // `NotThePresenter`.
        let err = verify_chain(
            &chain,
            &room,
            &room,
            "read",
            thief.did(),
            chrono::Utc::now(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                dtg_credentials::authority::AuthorityError::NotThePresenter { .. }
            ),
            "expected a NotThePresenter refusal, got {err:?}"
        );
    }

    /// `attenuate` refuses to widen, and it refuses on *this* side.
    ///
    /// Asking for an action the member does not hold fails in the credential library, where
    /// the member can be told why — rather than as a refusal from a host, which arrives
    /// worded as though the member were at fault.
    #[test]
    fn a_member_cannot_ask_for_more_than_the_room_gave_them() {
        let (room, room_secret) = a_room(0x32);
        let me = crate::identity::MemberIdentity::mint().unwrap();
        let now = chrono::Utc::now();

        let mut vac = dtg_credentials::DTGCredential::new_vac(
            room.clone(),
            me.did().to_string(),
            room.clone(),
            vec!["read".into()],
            now - chrono::Duration::minutes(1),
            now + chrono::Duration::days(30),
        )
        .unwrap()
        .with_id("urn:uuid:vac-2");
        futures_lite::future::block_on(vac.sign(&room_secret, None)).unwrap();
        let vac_json = serde_json::to_string(vac.credential()).unwrap();
        let vmc_json = "{}".to_string();

        let refused = me.present(&vac_json, &vmc_json, "write", None).unwrap_err();
        assert!(
            refused.contains("cannot narrow your authority"),
            "{refused}"
        );
    }

    /// An identity survives a restart, and a tampered snapshot does not load.
    #[test]
    fn an_identity_round_trips_and_refuses_a_mismatched_snapshot() {
        let me = crate::identity::MemberIdentity::mint().unwrap();
        let snapshot = me.snapshot().unwrap();
        let back = crate::identity::MemberIdentity::restore(&snapshot).unwrap();
        assert_eq!(back.did(), me.did());

        // A `did:key` is derived from its key, so a snapshot naming a different DID is one
        // that was edited. It fails here rather than as an unexplained refusal from a host.
        let other = crate::identity::MemberIdentity::mint().unwrap();
        let swapped: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
        let mut swapped = swapped.as_object().unwrap().clone();
        swapped.insert("did".into(), other.did().into());
        let err =
            crate::identity::MemberIdentity::restore(&serde_json::to_string(&swapped).unwrap())
                .unwrap_err();
        assert!(err.contains("does not match its key"), "{err}");
    }

    /// An invitation issued with `valid_from = now` — exactly what the demo's owner mints.
    ///
    /// Separate from the fixture above, which back-dates by a minute. A credential minted
    /// and checked in the same instant is the normal case for an interactive join, and a
    /// window check that is off by a rounding is a check that fails only in production.
    #[test]
    fn an_invitation_valid_from_this_instant_verifies() {
        let (room, secret) = a_room(0x51);
        let me = "did:key:zMe";
        let now = chrono::Utc::now();
        let mut vic = dtg_credentials::DTGCredential::new_vic(
            room.clone(),
            me.to_string(),
            now,
            Some(now + chrono::Duration::hours(1)),
        )
        .with_id("urn:uuid:now-1");
        futures_lite::future::block_on(vic.sign(&secret, None)).unwrap();
        let json = serde_json::to_string(vic.credential()).unwrap();

        verify(&json, &room, me, &[]).expect("an invitation valid from now must verify now");
    }

    /// A room identified by `did:peer:2` can issue an invitation this member verifies.
    ///
    /// The case that matters for admission: only a `did:peer:2` carries a service block, so
    /// only it can advertise the mediator a member reaches the room's owner through. If the
    /// invitation from such a room did not verify here, a room could be reachable and
    /// un-joinable at the same time.
    ///
    /// Still no network — `PeerResolver` is pure computation, which is why the same check
    /// works in a browser that is offline.
    #[test]
    fn an_invitation_from_a_did_peer_room_verifies() {
        use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};

        let (room, secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )
        .expect("mint the room's did:peer");

        // The room signs with its verification key, named the way a proof names one.
        let signing = secrets
            .iter()
            .find(|s| s.id.ends_with("#key-1"))
            .expect("the verification secret")
            .clone();

        let me = "did:key:zMember";
        let now = chrono::Utc::now();
        let mut vic = dtg_credentials::DTGCredential::new_vic(
            room.clone(),
            me.to_string(),
            now - chrono::Duration::minutes(1),
            Some(now + chrono::Duration::hours(1)),
        )
        .with_id("urn:uuid:peer-invite");
        futures_lite::future::block_on(vic.sign(&signing, None)).expect("sign as the room");

        let encoded = serde_json::to_string(vic.credential()).unwrap();
        verify(&encoded, &room, me, &[])
            .expect("a did:peer room's invitation must verify, with no network");

        // And the issuer binding still bites: the same invitation, for somebody else.
        assert!(verify(&encoded, &room, "did:key:zOther", &[]).is_err());
    }

    /// Each of the five checks, made to bite.
    ///
    /// A gate is only worth having if every clause of it refuses something, and a five-check
    /// gate is exactly the shape that quietly becomes a four-check one. So each is asserted
    /// separately rather than through one "a bad invitation is refused" case, which would
    /// still pass with any four of them.
    #[test]
    fn every_invitation_check_refuses_something() {
        let (room, secret) = a_room(0x21);
        let (other_room, other_secret) = a_room(0x22);
        let me = "did:key:zMe";

        let good = an_invitation(&room, &secret, me, "urn:uuid:i-1");
        assert!(
            verify(&good, &room, me, &[]).is_ok(),
            "the control must pass"
        );

        // 1. Not an invitation at all.
        let now = chrono::Utc::now();
        let mut vrc = dtg_credentials::DTGCredential::new_vac(
            room.clone(),
            me.to_string(),
            "room".into(),
            vec!["read".into()],
            now,
            now + chrono::Duration::hours(1),
        )
        .expect("build an authority credential")
        .with_id("urn:uuid:i-2");
        futures_lite::future::block_on(vrc.sign(&secret, None)).unwrap();
        let as_json = serde_json::to_string(vrc.credential()).unwrap();
        assert!(
            verify(&as_json, &room, me, &[])
                .unwrap_err()
                .contains("not an invitation")
        );

        // 2. Issued by a different room. Valid, and not an invitation to *this* one.
        let elsewhere = an_invitation(&other_room, &other_secret, me, "urn:uuid:i-3");
        assert!(
            verify(&elsewhere, &room, me, &[])
                .unwrap_err()
                .contains("issued by")
        );

        // 3. Issued to somebody else. An invitation is not transferable — without this a
        //    third party could place a member into a room they were invited to.
        let theirs = an_invitation(&room, &secret, "did:key:zSomeoneElse", "urn:uuid:i-4");
        assert!(
            verify(&theirs, &room, me, &[])
                .unwrap_err()
                .contains("not transferable")
        );

        // 4. Signed by the wrong key. Everything above is a claim until the proof holds: a
        //    well-formed invitation naming anyone is trivial to write, and this is the one
        //    check that makes the other four mean anything.
        let forged = an_invitation(&room, &other_secret, me, "urn:uuid:i-5");
        assert!(
            verify(&forged, &room, me, &[])
                .unwrap_err()
                .contains("is signed by")
        );

        // 5. Already spent. Single-use is what stops an invitation being a standing
        //    entitlement to rejoin a room you were removed from.
        let spent = vec!["urn:uuid:i-1".to_string()];
        assert!(
            verify(&good, &room, me, &spent)
                .unwrap_err()
                .contains("already been used")
        );
    }

    /// **An invitation's window is the other half of single-use, and nothing was testing it.**
    ///
    /// Both clauses were here and both were unexercised — on this side and in
    /// `vta-service`'s copy of the same gate. Which is the failure mode worth naming: a
    /// regression would not break anything visibly. Expired invitations would simply keep
    /// working, and a room's owner would have no way to tell, because the artefact that
    /// stopped meaning anything is the one they issued and forgot.
    ///
    /// An hour is chosen for a real invitation because it is an act somebody is about to
    /// perform, not a standing entitlement. That reasoning is only true if the window is
    /// enforced.
    #[test]
    fn an_invitation_outside_its_window_is_refused() {
        let (room, secret) = a_room(0x24);
        let me = "did:key:zMe";
        let now = chrono::Utc::now();

        let expired = an_invitation_valid(
            &room,
            &secret,
            me,
            "urn:uuid:w-1",
            now - chrono::Duration::hours(2),
            Some(now - chrono::Duration::hours(1)),
        );
        assert!(
            verify(&expired, &room, me, &[])
                .unwrap_err()
                .contains("expired"),
            "an invitation that has run out must not still admit"
        );

        let premature = an_invitation_valid(
            &room,
            &secret,
            me,
            "urn:uuid:w-2",
            now + chrono::Duration::hours(1),
            Some(now + chrono::Duration::hours(2)),
        );
        assert!(
            verify(&premature, &room, me, &[])
                .unwrap_err()
                .contains("not valid yet"),
            "nor one that has not started"
        );

        // No `validUntil` at all. The credential type permits it, so a room *can* issue one
        // that never expires — and this asserts the gate treats that as the room's decision
        // rather than quietly refusing it. An invitation with no end is a policy question for
        // whoever issues it, not something a member's key holder overrules.
        let forever = an_invitation_valid(
            &room,
            &secret,
            me,
            "urn:uuid:w-3",
            now - chrono::Duration::minutes(1),
            None,
        );
        assert!(
            verify(&forever, &room, me, &[]).is_ok(),
            "an open-ended invitation is the issuer's call, not this gate's"
        );
    }

    /// The failure this crate exists to make impossible to hit silently: a snapshot taken
    /// before a commit restores to a member who cannot read what came after it.
    #[test]
    fn a_snapshot_taken_before_a_commit_is_stale() {
        let mut owner = RoomGroup::create("did:key:zOwner").unwrap();
        let (room_did, room_secret) = a_room(0x11);
        let joiner = "did:key:zJoiner";
        let vic = an_invitation(&room_did, &room_secret, joiner, "urn:uuid:invite-1");
        let minted = mint_key_package(joiner, &room_did, &vic, NONE_SPENT).unwrap();
        let parsed: MintedIdentity = serde_json::from_str(&minted).unwrap();
        let change = owner
            .add_member_from_bytes(&B64.decode(&parsed.key_package).unwrap())
            .unwrap();
        let mut member = RoomMember::join(
            &room_did,
            &minted,
            &change.welcome.unwrap(),
            &vic,
            NONE_SPENT,
        )
        .unwrap();

        let stale = member.snapshot().unwrap();

        // Somebody else joins; the commit advances everyone's epoch.
        let other_vic = an_invitation(
            &room_did,
            &room_secret,
            "did:key:zOther",
            "urn:uuid:invite-2",
        );
        let other = mint_key_package("did:key:zOther", &room_did, &other_vic, NONE_SPENT).unwrap();
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
