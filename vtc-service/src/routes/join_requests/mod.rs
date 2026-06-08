//! `/v1/join-requests/*` route handlers (M1.7–M1.10).
//!
//! Submit + applicant-side endpoints are unauthenticated (the
//! holder-binding VP / DIDComm envelope IS the auth). Admin-side
//! list / show / approve / reject endpoints require AdminAuth
//! (Phase 1 simplification — Moderator-tier admission lands in
//! Phase 2's policy surface).

pub mod accept;
pub mod decide;
pub mod manifest;
pub mod present;
pub mod read;
pub mod status;
pub mod submit;
