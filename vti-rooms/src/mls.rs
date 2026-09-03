//! The room's group-key layer, on MLS (RFC 9420).
//!
//! # Why MLS rather than a room key per epoch
//!
//! An earlier draft of the design hand-rolled this: one symmetric key per epoch, sealed to
//! each member on every change. Every part of that is something MLS already standardises,
//! and two of the parts it adds are not optional for a system that expects to outlive a
//! compromise:
//!
//! - **Post-compromise security.** A stolen member key stops working at the next commit. The
//!   fan-out design had none — a stolen key read every future epoch until somebody noticed.
//! - **O(log n) membership change.** Fan-out is O(n) per change. Fine for a five-person
//!   room, wrong for one whose membership is a whole community roster.
//!
//! # How it maps onto a room
//!
//! MLS separates an **Authentication Service** (who is this leaf?) from a **Delivery
//! Service** (who stores and orders the group's messages, and is trusted for availability
//! only). That is the room design's own shape, arrived at independently:
//!
//! | MLS | Room |
//! |---|---|
//! | Authentication Service | the DTG — a leaf's credential is the room VMC |
//! | Delivery Service | the room's host, trusted per invariant I2 |
//! | Group | the room |
//! | Epoch | the room's epoch, the number the host stores |
//! | Commit | a membership change — **only the owner commits** |
//! | Exporter secret | the room's storage key |
//!
//! # One leaf per member, not per device
//!
//! A member's leaf is their **VTA**, and devices and agents hang off it through the oracle
//! model rather than joining the group themselves. That sidesteps MLS's multi-device
//! complexity entirely, and it is the same reason the design puts key custody in the VTA:
//! an agent asks its VTA to open a record and never holds the key.
//!
//! # Storage keys come from the exporter, not from the group's message keys
//!
//! Records are sealed with a key derived from [`RoomGroup::storage_key`], which is the MLS
//! exporter under a room-specific label. This is the pattern
//! `draft-sullivan-mls-attachments` uses for encrypted attachments, following SFrame
//! (RFC 9605): the group provides authenticated key agreement, and the application derives
//! its own keys from the exporter rather than borrowing the ones MLS uses for its own
//! messages.
//!
//! # What this module does not do
//!
//! It does not talk to a host. Commits, welcomes and key packages are returned to the
//! caller as bytes to send however it likes — the design's fork risk (a host showing
//! different members different commit sequences) is addressed by anchoring epoch
//! authenticators in the room's witnessed DID log, which is a separate concern from
//! producing them. [`RoomGroup::epoch_authenticator`] is what gets anchored.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as _, Serialize as _};

use crate::error::RoomKeyError;

/// The MLS ciphersuite every room uses.
///
/// One ciphersuite, not a negotiation. A room whose members disagree about the ciphersuite
/// is a room that cannot form, and offering a choice here would mean carrying the weakest
/// option a peer might pick.
pub const ROOM_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Exporter label for a room's record-storage key.
///
/// Domain-separated so that a key derived for record sealing can never collide with one
/// derived for another purpose from the same group. A new purpose gets a new label, never a
/// parameter on this one.
const STORAGE_KEY_LABEL: &str = "openvtc/room/storage/v1";

/// Bytes of the derived storage key — 32, for a ChaCha20-Poly1305 or AES-256 key.
pub const STORAGE_KEY_LEN: usize = 32;

/// A member's MLS identity: their signature keypair and the credential naming them.
///
/// The credential is a basic one carrying the member's DID. In the finished design the
/// leaf's credential is the room VMC; a basic credential carrying the same identifier is
/// the interim, and the swap is confined to this struct.
pub struct RoomIdentity {
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl RoomIdentity {
    /// Create an identity for `member_did`.
    pub fn new(member_did: &str, provider: &impl OpenMlsProvider) -> Result<Self, RoomKeyError> {
        let signer = SignatureKeyPair::new(ROOM_CIPHERSUITE.signature_algorithm())
            .map_err(|e| RoomKeyError::Group(format!("generate MLS signature key: {e:?}")))?;
        signer
            .store(provider.storage())
            .map_err(|e| RoomKeyError::Group(format!("store MLS signature key: {e:?}")))?;

        let credential = Credential::new(CredentialType::Basic, member_did.as_bytes().to_vec());
        Ok(Self {
            credential: CredentialWithKey {
                credential,
                signature_key: signer.public().into(),
            },
            signer,
        })
    }

    /// A key package this member can be added to a room with.
    ///
    /// Published to whoever is inviting them — **over the invitation channel, never through
    /// the host**. A host that collected key packages would learn who is being invited to
    /// what, which un-blinds a sealed room at the door.
    pub fn key_package(&self, provider: &impl OpenMlsProvider) -> Result<KeyPackage, RoomKeyError> {
        KeyPackage::builder()
            .build(
                ROOM_CIPHERSUITE,
                provider,
                &self.signer,
                self.credential.clone(),
            )
            .map(|b| b.key_package().clone())
            .map_err(|e| RoomKeyError::Group(format!("build MLS key package: {e:?}")))
    }
}

/// One member's view of a room's MLS group.
pub struct RoomGroup {
    group: MlsGroup,
    identity: RoomIdentity,
    provider: OpenMlsRustCrypto,
}

/// What a membership change produces.
///
/// The caller sends `commit` to every existing member and `welcome` to whoever was just
/// added. Both are opaque bytes here: this module produces them and takes no view on how
/// they travel.
pub struct MembershipChange {
    /// The commit, for members already in the group.
    pub commit: Vec<u8>,
    /// The welcome, for members just added. `None` on a removal.
    pub welcome: Option<Vec<u8>>,
    /// The epoch the group is in after merging.
    pub epoch: u64,
}

impl RoomGroup {
    /// Create a room's group. The creator is its first member and its owner.
    pub fn create(member_did: &str) -> Result<Self, RoomKeyError> {
        let provider = OpenMlsRustCrypto::default();
        let identity = RoomIdentity::new(member_did, &provider)?;

        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ROOM_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        let group = MlsGroup::new(
            &provider,
            &identity.signer,
            &config,
            identity.credential.clone(),
        )
        .map_err(|e| RoomKeyError::Group(format!("create MLS group: {e:?}")))?;

        Ok(Self {
            group,
            identity,
            provider,
        })
    }

    /// Join a room from the welcome its owner sent.
    pub fn join(member_did: &str, welcome: &[u8]) -> Result<Self, RoomKeyError> {
        let provider = OpenMlsRustCrypto::default();
        let identity = RoomIdentity::new(member_did, &provider)?;
        Self::join_with(identity, provider, welcome)
    }

    /// Join using an identity whose key package the inviter already holds.
    ///
    /// The ordinary path: a member publishes a key package, is added, and joins with the
    /// *same* identity — [`RoomGroup::join`] mints a fresh one, which only works if the
    /// inviter used that identity's key package.
    pub fn join_with(
        identity: RoomIdentity,
        provider: OpenMlsRustCrypto,
        welcome: &[u8],
    ) -> Result<Self, RoomKeyError> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|e| RoomKeyError::Group(format!("parse welcome: {e:?}")))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => {
                return Err(RoomKeyError::Group(
                    "expected a Welcome message, got another MLS body".into(),
                ));
            }
        };

        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&provider, &config, welcome, None)
            .map_err(|e| RoomKeyError::Group(format!("stage welcome: {e:?}")))?;
        let group = staged
            .into_group(&provider)
            .map_err(|e| RoomKeyError::Group(format!("join group from welcome: {e:?}")))?;

        Ok(Self {
            group,
            identity,
            provider,
        })
    }

    /// Add a member and commit.
    ///
    /// Only the owner should call this — the design restricts epoch minting to `admin`
    /// precisely because a group where any key-holder can commit is a group where any
    /// member can evict any other. MLS itself does not enforce that; the room's authority
    /// credentials do, and the host checks them before accepting the epoch advance.
    pub fn add_member(
        &mut self,
        key_package: KeyPackage,
    ) -> Result<MembershipChange, RoomKeyError> {
        let (commit, welcome, _) = self
            .group
            .add_members(&self.provider, &self.identity.signer, &[key_package])
            .map_err(|e| RoomKeyError::Group(format!("add member: {e:?}")))?;

        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| RoomKeyError::Group(format!("merge add commit: {e:?}")))?;

        Ok(MembershipChange {
            commit: commit
                .tls_serialize_detached()
                .map_err(|e| RoomKeyError::Group(format!("serialise commit: {e:?}")))?,
            welcome: Some(
                welcome
                    .tls_serialize_detached()
                    .map_err(|e| RoomKeyError::Group(format!("serialise welcome: {e:?}")))?,
            ),
            epoch: self.group.epoch().as_u64(),
        })
    }

    /// Remove a member and commit — the mechanism of removal.
    ///
    /// **Forward-only, and worth being plain about.** The removed member keeps whatever they
    /// could already read; they held the plaintext. What they lose is everything sealed
    /// under the new epoch. An interface that implies otherwise has mis-stated the
    /// guarantee.
    pub fn remove_member(
        &mut self,
        index: LeafNodeIndex,
    ) -> Result<MembershipChange, RoomKeyError> {
        let (commit, _, _) = self
            .group
            .remove_members(&self.provider, &self.identity.signer, &[index])
            .map_err(|e| RoomKeyError::Group(format!("remove member: {e:?}")))?;

        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| RoomKeyError::Group(format!("merge remove commit: {e:?}")))?;

        Ok(MembershipChange {
            commit: commit
                .tls_serialize_detached()
                .map_err(|e| RoomKeyError::Group(format!("serialise commit: {e:?}")))?,
            welcome: None,
            epoch: self.group.epoch().as_u64(),
        })
    }

    /// Apply a commit produced by another member.
    pub fn apply_commit(&mut self, commit: &[u8]) -> Result<u64, RoomKeyError> {
        let msg = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(|e| RoomKeyError::Group(format!("parse commit: {e:?}")))?;
        let protocol_message: ProtocolMessage = msg
            .try_into_protocol_message()
            .map_err(|e| RoomKeyError::Group(format!("not a protocol message: {e:?}")))?;

        let processed = self
            .group
            .process_message(&self.provider, protocol_message)
            .map_err(|e| RoomKeyError::Group(format!("process commit: {e:?}")))?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&self.provider, *staged)
                    .map_err(|e| RoomKeyError::Group(format!("merge staged commit: {e:?}")))?;
                Ok(self.group.epoch().as_u64())
            }
            _ => Err(RoomKeyError::Group(
                "expected a commit, got another message type".into(),
            )),
        }
    }

    /// The room's current epoch.
    ///
    /// This is the number the host stores so it can serve the right ciphertext. The host
    /// learns the number and never the key.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// The key records in this epoch are sealed with.
    ///
    /// Derived from the MLS exporter under a room-specific label rather than borrowed from
    /// the group's own message keys — so a change to how records are sealed cannot weaken
    /// the group's messaging, and vice versa.
    pub fn storage_key(&self) -> Result<[u8; STORAGE_KEY_LEN], RoomKeyError> {
        let secret = self
            .group
            .export_secret(
                self.provider.crypto(),
                STORAGE_KEY_LABEL,
                &[],
                STORAGE_KEY_LEN,
            )
            .map_err(|e| RoomKeyError::Group(format!("export storage key: {e:?}")))?;
        let mut key = [0u8; STORAGE_KEY_LEN];
        key.copy_from_slice(&secret);
        Ok(key)
    }

    /// The epoch authenticator — what gets anchored in the room's witnessed DID log.
    ///
    /// A host acting as the Delivery Service can attempt to **fork** a group: show one
    /// member one commit sequence and another member a different one, so each believes it
    /// is in the room. Members cannot detect that by comparing through the host, because the
    /// host is what they would be comparing through.
    ///
    /// Anchoring this value where the host cannot forge it — the room's witnessed log —
    /// gives every member a reference to check their own against. Detection latency is the
    /// anchoring cadence, which is why the design makes that a room parameter rather than a
    /// constant.
    pub fn epoch_authenticator(&self) -> Vec<u8> {
        self.group.epoch_authenticator().as_slice().to_vec()
    }

    /// How many members the group has.
    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    /// The leaf index of the member whose credential identity is `member_did`.
    pub fn leaf_of(&self, member_did: &str) -> Option<LeafNodeIndex> {
        self.group.members().find_map(|m| {
            (m.credential.serialized_content() == member_did.as_bytes()).then_some(m.index)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_creator_forms_a_group_of_one() {
        let room = RoomGroup::create("did:key:zAlice").expect("create");
        assert_eq!(room.member_count(), 1);
        assert_eq!(room.epoch(), 0, "a fresh group starts at epoch 0");
    }

    #[test]
    fn a_storage_key_is_derived_and_is_stable_within_an_epoch() {
        let room = RoomGroup::create("did:key:zAlice").expect("create");
        let a = room.storage_key().expect("export");
        let b = room.storage_key().expect("export again");
        assert_eq!(a, b, "the same epoch must derive the same key");
        assert_ne!(a, [0u8; STORAGE_KEY_LEN], "and it must not be zeroes");
    }

    /// The whole point of an epoch: two members reach the same key without it ever
    /// crossing the host.
    #[test]
    fn an_added_member_derives_the_same_storage_key() {
        let mut alice = RoomGroup::create("did:key:zAlice").expect("alice");

        let bob_provider = OpenMlsRustCrypto::default();
        let bob_identity = RoomIdentity::new("did:key:zBob", &bob_provider).expect("bob identity");
        let bob_kp = bob_identity.key_package(&bob_provider).expect("bob kp");

        let change = alice.add_member(bob_kp).expect("add bob");
        let welcome = change.welcome.expect("an add produces a welcome");

        let bob = RoomGroup::join_with(bob_identity, bob_provider, &welcome).expect("bob joins");

        assert_eq!(alice.member_count(), 2);
        assert_eq!(
            alice.storage_key().unwrap(),
            bob.storage_key().unwrap(),
            "both members must derive the same storage key, without the host seeing it"
        );
        assert_eq!(alice.epoch(), bob.epoch());
    }

    /// Removal is forward-only, and this is what "forward" means mechanically: the key
    /// changes, so nothing sealed afterwards is reachable with the old one.
    #[test]
    fn removing_a_member_changes_the_storage_key() {
        let mut alice = RoomGroup::create("did:key:zAlice").expect("alice");

        let bob_provider = OpenMlsRustCrypto::default();
        let bob_identity = RoomIdentity::new("did:key:zBob", &bob_provider).expect("bob identity");
        let bob_kp = bob_identity.key_package(&bob_provider).expect("bob kp");
        let change = alice.add_member(bob_kp).expect("add bob");
        let bob = RoomGroup::join_with(
            bob_identity,
            bob_provider,
            &change.welcome.expect("welcome"),
        )
        .expect("bob joins");

        let shared = alice.storage_key().unwrap();
        assert_eq!(shared, bob.storage_key().unwrap());

        let bob_leaf = alice.leaf_of("did:key:zBob").expect("bob is a member");
        alice.remove_member(bob_leaf).expect("remove bob");

        let after = alice.storage_key().unwrap();
        assert_ne!(
            shared, after,
            "after removal the key must differ, or removal removes nothing"
        );
        assert_ne!(
            bob.storage_key().unwrap(),
            after,
            "and the removed member must not be able to derive the new one"
        );
    }

    /// Every member's view of an epoch must agree, or the anchor cannot detect a fork.
    #[test]
    fn members_in_the_same_epoch_share_an_epoch_authenticator() {
        let mut alice = RoomGroup::create("did:key:zAlice").expect("alice");
        let bob_provider = OpenMlsRustCrypto::default();
        let bob_identity = RoomIdentity::new("did:key:zBob", &bob_provider).expect("bob identity");
        let bob_kp = bob_identity.key_package(&bob_provider).expect("bob kp");
        let change = alice.add_member(bob_kp).expect("add bob");
        let bob = RoomGroup::join_with(
            bob_identity,
            bob_provider,
            &change.welcome.expect("welcome"),
        )
        .expect("bob joins");

        assert_eq!(
            alice.epoch_authenticator(),
            bob.epoch_authenticator(),
            "a member whose authenticator differs from the anchored one has been forked"
        );
        assert!(!alice.epoch_authenticator().is_empty());
    }

    #[test]
    fn an_epoch_advances_on_every_membership_change() {
        let mut alice = RoomGroup::create("did:key:zAlice").expect("alice");
        let start = alice.epoch();

        let p = OpenMlsRustCrypto::default();
        let id = RoomIdentity::new("did:key:zBob", &p).expect("identity");
        alice
            .add_member(id.key_package(&p).expect("kp"))
            .expect("add");

        assert!(
            alice.epoch() > start,
            "a membership change must move the epoch, or the host serves stale ciphertext"
        );
    }
}
