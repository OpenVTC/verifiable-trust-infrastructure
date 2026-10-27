//! A room's own profile: the parts of `RoomProfileStatement` (`rooms/_shared/0.1`) that are
//! arithmetic rather than policy.
//!
//! A room's name and description live **inside the room**, as one record per epoch, sealed
//! like every other record on the `attributed` and `private` tiers. Who may write one, and
//! which one a reader takes, are decided by readers from the statement's own authority chain
//! (`rooms/keys/profile/read`, `rooms/keys/profile/write`); what is here is only what every
//! reader and writer has to compute identically:
//!
//! - **where** the profile written under epoch `E` is stored — [`derive_profile_key`], a key
//!   derived from that epoch's storage key, so it has the shape of any random record key and
//!   the host cannot tell which record names the room; on an `open` room the fixed key
//!   [`OPEN_PROFILE_KEY`];
//! - **how much padding** brings the signed body to a multiple of [`PADDING_BLOCK`] bytes,
//!   so a host comparing ciphertext lengths learns nothing about the name's length;
//! - **the window** a statement's `issuedAt` must fall in against the `updatedAt` its host
//!   reports, so a statement cannot be back-dated into a grant its author no longer holds.
//!
//! The derivation is normative and fixed byte for byte:
//!
//! ```text
//! profile_key(E) = base64url-nopad(HKDF-SHA256(ikm  = storage_key(E),
//!                                              salt = "",
//!                                              info = "openvtc/room/profile/v1" || roomId || u64be(E),
//!                                              L    = 16))
//! ```

/// The HKDF `info` label that separates a profile's location from every other key derived
/// from a storage key. A change no earlier reader could survive is a new label (`…/v2`).
pub const PROFILE_LABEL: &[u8] = b"openvtc/room/profile/v1";

/// The record key of an `open` room's profile. An open room has no storage key and hides
/// nothing from its host, so its profile is at one fixed place.
pub const OPEN_PROFILE_KEY: &str = "room-profile";

/// A writer pads the UTF-8 JSON of the signed body to a multiple of this many bytes.
pub const PADDING_BLOCK: usize = 1024;

/// The most padding `RoomProfileStatement.padding` may carry (its schema's `maxLength`).
pub const MAX_PADDING: usize = 8192;

/// How long before the host's `updatedAt` a statement's `issuedAt` may be, in seconds.
pub const ISSUED_BEFORE_UPDATE_SECS: i64 = 60 * 60;

/// How long after the host's `updatedAt` a statement's `issuedAt` may be, in seconds — the
/// clock skew a writer is allowed against its host.
pub const ISSUED_AFTER_UPDATE_SECS: i64 = 5 * 60;

/// The most links an authority chain in a statement may carry, as in a presentation.
pub const MAX_AUTHORITY_LINKS: usize = 8;

/// The profile's record key for `epoch`, from that epoch's storage key.
///
/// 16 bytes of HKDF-SHA256 output, base64url without padding: 22 characters, the shape of a
/// random record key.
#[cfg(feature = "files")]
#[must_use]
pub fn derive_profile_key(storage_key: &[u8; 32], room_id: &str, epoch: u64) -> String {
    use base64::Engine as _;
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut info = Vec::with_capacity(PROFILE_LABEL.len() + room_id.len() + 8);
    info.extend_from_slice(PROFILE_LABEL);
    info.extend_from_slice(room_id.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut out = [0u8; 16];
    // `salt = ""`. HKDF treats an empty salt exactly as an absent one (a string of zeros
    // the hash's length), so either spelling derives the same key; the empty slice is
    // written because it is what the specification says.
    Hkdf::<Sha256>::new(Some(b""), storage_key)
        .expand(&info, &mut out)
        .expect("16 bytes is a valid HKDF-SHA256 output length");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
}

/// How many padding characters bring a body of `len` bytes to the next multiple of
/// [`PADDING_BLOCK`] — `len` measured **with** the padding already in it, so a writer can
/// re-measure after signing (a proof's length varies by a byte or two) and add the
/// difference. Never more than [`MAX_PADDING`].
#[must_use]
pub fn padding_to_block(len: usize) -> usize {
    let short = (PADDING_BLOCK - len % PADDING_BLOCK) % PADDING_BLOCK;
    short.min(MAX_PADDING)
}

/// Whether a statement issued at `issued_at` may stand for a record its host last updated at
/// `updated_at` (both unix seconds): no earlier than [`ISSUED_BEFORE_UPDATE_SECS`] before it,
/// no later than [`ISSUED_AFTER_UPDATE_SECS`] after it.
#[must_use]
pub fn issued_within_window(issued_at: i64, updated_at: i64) -> bool {
    issued_at >= updated_at.saturating_sub(ISSUED_BEFORE_UPDATE_SECS)
        && issued_at <= updated_at.saturating_add(ISSUED_AFTER_UPDATE_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation, pinned against an independent computation of the formula: HKDF with
    /// an empty salt, the label, the room's bytes and the epoch as eight big-endian bytes,
    /// cut to 16 bytes. A second implementation reading only the specification must find
    /// the same record.
    #[cfg(feature = "files")]
    #[test]
    fn the_profile_key_is_the_specified_derivation() {
        use base64::Engine as _;
        use hkdf::Hkdf;
        use sha2::Sha256;

        let storage_key = [7u8; 32];
        let room = "did:webvh:example.com:rooms:board";
        let key = derive_profile_key(&storage_key, room, 4);

        let mut info = b"openvtc/room/profile/v1".to_vec();
        info.extend_from_slice(room.as_bytes());
        info.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 4]);
        let mut expected = [0u8; 16];
        Hkdf::<Sha256>::new(None, &storage_key)
            .expand(&info, &mut expected)
            .unwrap();
        assert_eq!(
            key,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected),
            "an empty salt and an absent one are the same HKDF"
        );
        assert_eq!(key.len(), 22, "the shape of any random record key");
    }

    /// Every input moves the location: another epoch, another room, another storage key.
    #[cfg(feature = "files")]
    #[test]
    fn the_location_depends_on_epoch_room_and_storage_key() {
        let k = derive_profile_key(&[1; 32], "did:example:room", 3);
        assert_ne!(k, derive_profile_key(&[1; 32], "did:example:room", 4));
        assert_ne!(k, derive_profile_key(&[1; 32], "did:example:other", 3));
        assert_ne!(k, derive_profile_key(&[2; 32], "did:example:room", 3));
        assert_eq!(k, derive_profile_key(&[1; 32], "did:example:room", 3));
    }

    #[test]
    fn padding_reaches_the_next_block_and_no_further() {
        assert_eq!(padding_to_block(1024), 0);
        assert_eq!(padding_to_block(1000), 24);
        assert_eq!(padding_to_block(1025), 1023);
        assert_eq!(padding_to_block(0), 0);
    }

    /// `[updatedAt − 1h, updatedAt + 5m]`, inclusive at both ends.
    #[test]
    fn issued_at_is_bounded_against_the_hosts_update() {
        let updated = 1_000_000;
        assert!(issued_within_window(updated, updated));
        assert!(issued_within_window(updated - 3600, updated));
        assert!(!issued_within_window(updated - 3601, updated));
        assert!(issued_within_window(updated + 300, updated));
        assert!(!issued_within_window(updated + 301, updated));
    }
}
