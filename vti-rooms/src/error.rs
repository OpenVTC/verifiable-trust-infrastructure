//! Failures from a room's key layer.
//!
//! Deliberately not `vti_common::error::AppError`. The rest of this crate speaks `AppError`
//! because storage and authorization *are* a service's concerns; key material is not. A
//! record that does not open is a legitimate outcome with a specific meaning, and folding it
//! into `Internal` would say "this service is broken" about the one case the design most
//! wants to be loud and precise: a host relocated a record.
//!
//! Kept small on purpose. A caller can tell a group-state problem from a sealing problem
//! from a record that did not open, and that is the whole distinction anything needs.

/// What can go wrong holding or using a room's keys.
#[derive(Debug, thiserror::Error)]
pub enum RoomKeyError {
    /// The MLS group could not be created, joined, or advanced.
    #[error("room group: {0}")]
    Group(String),

    /// A record could not be sealed, or its inputs could not be decoded.
    #[error("seal record: {0}")]
    Seal(String),

    /// A record did not open.
    ///
    /// One variant for every reason, and that is the design rather than laziness: the
    /// AEAD cannot distinguish "wrong key" from "relocated record" from "tampered
    /// ciphertext", and a caller that acted on a guess would be acting on nothing. What it
    /// can say is that the bytes are not the bytes that were sealed here, which is the
    /// property the binding exists to give.
    #[error(
        "record did not open: it was sealed under a different key, epoch, or location — a \
         relocated record fails here rather than decrypting wrongly"
    )]
    DidNotOpen,
}
