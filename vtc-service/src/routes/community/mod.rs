//! `/v1/community/*` route handlers.
//!
//! The public reads a visitor needs before any session exists: the
//! community profile, its DID as a QR code, and its stored logo. Everything else about the
//! community is a signed document (`crate::community::ops`).

pub mod did_qr;
pub mod logo;
pub mod profile;
