//! The watches this VTA holds for its principal's clients (`rooms/keys/watch/0.1`,
//! trust-tasks-tf #1040): the record each keeps, the bounds, and the addresses it receives
//! the hosts' signals at.
//!
//! # What is kept
//!
//! Recipient item 6 is the whole list: the caller, the member, the room, the host, the
//! address and the key material the VTA receives at, and when the watch lapses
//! ([`WatchRecord`]). Never the watermark the caller gave, the version a host signalled,
//! or when a signal arrived. A record is deleted — and its address retired — when the
//! watch fires, is cancelled or lapses, when the caller may no longer act as the member,
//! and when the VTA no longer holds the member's credentials for the room (item 7). The
//! keyspace is not backed up ([`crate::keyspaces::ROOM_KEY_WATCHES`]).
//!
//! # The address
//!
//! A `did:peer:2` this VTA mints for one watch ([`super::did_peer`]), from keys drawn
//! from the CSPRNG rather than the seed — nothing derives it again and nothing needs to —
//! whose one service is `DIDCommMessaging` at the VTA's own mediator, named by the
//! mediator's DID. Never the VTA's DID, the member's or the caller's, and never another
//! watch's (item 5): each is fresh. A host learns the mediator from it, which the
//! specification accepts (*Correlation*). A re-arm of a watch that has not fired keeps
//! its address, so that it replaces the host's watch rather than adding one; every other
//! arming mints a new one.
//!
//! The VTA receives at an address over a mediator connection of its own, one per
//! address, opened and closed by `messaging::watch_addresses` from these records — the
//! mediator allows one connection per DID, and each address is a DID nobody else holds.
//!
//! # Bounds
//!
//! [`MAX_PER_MEMBER`], [`MAX_PER_CALLER`] and [`MAX_WATCHES`]: one connection each is what
//! a watch costs this node, so the bounds are this VTA's own (`limitReached`, distinct from
//! a host's `rooms/watch:limitReached`). A VTA with no mediator holds none.

use std::collections::HashMap;
use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// The most watches one member holds here, across its callers.
pub const MAX_PER_MEMBER: usize = 64;
/// The most watches one caller holds here, across its members.
pub const MAX_PER_CALLER: usize = 64;
/// The most watches this VTA holds at all.
pub const MAX_WATCHES: usize = 256;
/// The longest a watch lasts if it does not fire: `rooms/keys/watch/0.1`'s 30 days.
pub const MAX_LEASE_SECS: i64 = 30 * 24 * 60 * 60;

const WATCH_PREFIX: &str = "w:";

/// One armed watch: exactly what Recipient item 6 keeps.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WatchRecord {
    /// The client that armed it, and the only party a signal is passed on to.
    pub caller: String,
    /// The member it was armed as.
    pub member: String,
    /// The room.
    pub room_id: String,
    /// The host it was armed at, and the only party whose signal is passed on.
    pub host: String,
    /// The address it was armed with: a `did:peer:2` this VTA minted for it.
    pub address: String,
    /// The address's key material — its Ed25519 authentication key and X25519
    /// key-agreement key — which this VTA receives at.
    keys: Vec<Secret>,
    /// When the watch lapses, as Unix seconds.
    pub expires_at: i64,
}

/// Written by hand: a derived `Debug` would print the address's private keys.
impl std::fmt::Debug for WatchRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchRecord")
            .field("caller", &self.caller)
            .field("member", &self.member)
            .field("room_id", &self.room_id)
            .field("host", &self.host)
            .field("address", &self.address)
            .field("keys", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl WatchRecord {
    /// The store key: one watch per (caller, member, host, room), so a re-arm finds the
    /// watch it replaces.
    pub fn key(&self) -> String {
        watch_key(&self.caller, &self.member, &self.host, &self.room_id)
    }

    /// The address's secrets, for the connection that receives at it.
    pub fn secrets(&self) -> &[Secret] {
        &self.keys
    }

    /// Whether the watch has lapsed at `now` (Unix seconds).
    pub fn lapsed(&self, now: i64) -> bool {
        self.expires_at <= now
    }
}

/// The store key of the watch `caller` armed as `member` on `room_id` at `host`. A digest,
/// so the key names nobody.
pub fn watch_key(caller: &str, member: &str, host: &str, room_id: &str) -> String {
    let mut h = Sha256::new();
    for part in [caller, member, host, room_id] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    format!("{WATCH_PREFIX}{}", hex::encode(h.finalize()))
}

/// A fresh address for one watch, receiving at `mediator_did`: a `did:peer:2` whose only
/// service is `DIDCommMessaging` at that mediator, and its two secrets.
pub fn mint_address(mediator_did: &str) -> Result<(String, Vec<Secret>), AppError> {
    let services = super::did_peer::mediator_did_didcomm_service(
        mediator_did,
        vec!["didcomm/v2".into()],
        vec![],
    );
    super::did_peer::mint_did_peer_with_services(services)
        .map_err(|e| AppError::Internal(format!("mint a watch address: {e}")))
}

/// A connection receiving at one watch's address. Closed when the watch is forgotten.
pub trait AddressSession: Send + Sync {
    /// Stop receiving at the address.
    fn close(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// Why a watch could not be taken on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Full {
    /// The member holds [`MAX_PER_MEMBER`].
    Member,
    /// The caller holds [`MAX_PER_CALLER`].
    Caller,
    /// The VTA holds [`MAX_WATCHES`], or holds none because it has no mediator.
    Node,
}

/// The watch store, and the connections receiving at its addresses.
pub struct RoomKeyWatches {
    ks: KeyspaceHandle,
    /// Serialises every change to the store: an arming's bound check and its write, a
    /// fired watch's removal, a sweep. A signal racing a re-arm finds one or the other.
    lock: tokio::sync::Mutex<()>,
    /// Wakes the address supervisor when the records changed.
    kick: tokio::sync::Notify,
    sessions: std::sync::Mutex<HashMap<String, Arc<dyn AddressSession>>>,
}

impl RoomKeyWatches {
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self {
            ks,
            lock: tokio::sync::Mutex::new(()),
            kick: tokio::sync::Notify::new(),
            sessions: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Hold the store's lock for a change made of several steps.
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.lock.lock().await
    }

    /// Every watch held.
    pub async fn all(&self) -> Result<Vec<WatchRecord>, AppError> {
        Ok(self
            .ks
            .prefix_iter_raw(WATCH_PREFIX.to_string())
            .await?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect())
    }

    /// The watch `caller` armed as `member` on `room_id` at `host`.
    pub async fn get(
        &self,
        caller: &str,
        member: &str,
        host: &str,
        room_id: &str,
    ) -> Result<Option<WatchRecord>, AppError> {
        self.ks.get(watch_key(caller, member, host, room_id)).await
    }

    /// The watch armed with `address`, if one is held.
    pub async fn by_address(&self, address: &str) -> Result<Option<WatchRecord>, AppError> {
        Ok(self.all().await?.into_iter().find(|w| w.address == address))
    }

    /// Store `record`. The caller holds [`Self::lock`].
    pub async fn put(&self, record: &WatchRecord) -> Result<(), AppError> {
        self.ks.insert(record.key(), record).await?;
        self.kick.notify_one();
        Ok(())
    }

    /// Forget the watch stored under `key`. The caller holds [`Self::lock`]. Its address's
    /// connection closes on the supervisor's next pass, which this wakes.
    pub async fn forget(&self, key: &str) -> Result<(), AppError> {
        self.ks.remove(key.to_string()).await?;
        self.kick.notify_one();
        Ok(())
    }

    /// Whether one more watch fits for `member` and `caller`, given what is held. The
    /// caller holds [`Self::lock`].
    pub async fn room_for(&self, caller: &str, member: &str) -> Result<Result<(), Full>, AppError> {
        let held = self.all().await?;
        if held.len() >= MAX_WATCHES {
            return Ok(Err(Full::Node));
        }
        if held.iter().filter(|w| w.member == member).count() >= MAX_PER_MEMBER {
            return Ok(Err(Full::Member));
        }
        if held.iter().filter(|w| w.caller == caller).count() >= MAX_PER_CALLER {
            return Ok(Err(Full::Caller));
        }
        Ok(Ok(()))
    }

    /// A new record for an arming, its address minted for it.
    pub fn new_record(
        caller: &str,
        member: &str,
        room_id: &str,
        host: &str,
        mediator_did: &str,
        expires_at: i64,
    ) -> Result<WatchRecord, AppError> {
        let (address, keys) = mint_address(mediator_did)?;
        Ok(WatchRecord {
            caller: caller.to_string(),
            member: member.to_string(),
            room_id: room_id.to_string(),
            host: host.to_string(),
            address,
            keys,
            expires_at,
        })
    }

    /// Wait until the records change.
    pub async fn changed(&self) {
        self.kick.notified().await
    }

    /// Ask the supervisor to reconcile now.
    pub fn kick(&self) {
        self.kick.notify_one();
    }

    /// The addresses a connection is open for.
    pub fn receiving(&self) -> Vec<String> {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Whether a connection is open for `address`.
    pub fn is_receiving(&self, address: &str) -> bool {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(address)
    }

    /// Record the connection open for `address`.
    pub fn insert_session(&self, address: &str, session: Arc<dyn AddressSession>) {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(address.to_string(), session);
    }

    /// Close the connection for `address`, if one is open.
    pub async fn stop(&self, address: &str) {
        let session = self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(address);
        if let Some(s) = session {
            s.close().await;
        }
    }

    /// Close every connection.
    pub async fn stop_all(&self) {
        for address in self.receiving() {
            self.stop(&address).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_address_is_a_peer_did_naming_only_the_mediator() {
        let (did, keys) = mint_address("did:example:mediator").unwrap();
        assert!(did.starts_with("did:peer:2"), "{did}");
        assert!(
            did.len() <= 1000,
            "a rooms/watch address is at most 1000 characters"
        );
        assert_eq!(keys.len(), 2);
        let (again, _) = mint_address("did:example:mediator").unwrap();
        assert_ne!(did, again, "every arming takes a new address");
    }

    #[test]
    fn the_record_never_prints_its_keys() {
        let r = RoomKeyWatches::new_record(
            "did:key:zCaller",
            "did:key:zMember",
            "did:example:room",
            "did:example:host",
            "did:example:mediator",
            0,
        )
        .unwrap();
        let shown = format!("{r:?}");
        assert!(shown.contains("<redacted>"));
        for k in r.secrets() {
            let private = k.get_private_keymultibase().unwrap();
            assert!(!shown.contains(&private));
        }
    }

    #[test]
    fn the_key_is_one_per_caller_member_host_and_room() {
        let a = watch_key("c", "m", "h", "r");
        assert_eq!(a, watch_key("c", "m", "h", "r"));
        assert_ne!(a, watch_key("c2", "m", "h", "r"));
        assert_ne!(a, watch_key("c", "m", "h", "r2"));
        assert!(a.starts_with(WATCH_PREFIX));
    }
}
