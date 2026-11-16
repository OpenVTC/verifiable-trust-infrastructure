//! `/v1/community/*` route handlers.
//!
//! The two public reads a visitor needs before any session exists: the
//! community profile and its DID as a QR code. Everything else about the
//! community is a signed document (`crate::community::ops`).

pub mod did_qr;
pub mod profile;
