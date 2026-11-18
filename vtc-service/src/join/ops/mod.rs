//! `/v1/join-requests/*` route handlers (M1.7–M1.10).
//!
//! The applicant's verbs (submit, manifest, status, withdraw, supplement) have
//! no route: they are signed documents the spine serves on every transport.
//! The admin list / show / decide endpoints require AdminAuth.

pub mod decide;
pub mod manifest;
pub mod present;
pub mod read;
pub mod status;
