//! `/v1/members/*` route handlers.
//!
//! Spec §5.2 + §10.1–10.4. Phase 1 shape per
//! `tasks/vtc-mvp/phase-1-todo.md` M1.4–M1.6:
//!
//! - `GET /v1/members` — paginated list.
//! - `GET /v1/members/{did}` — single member.
//! - `PATCH /v1/members/{did}` — role + profile fields, including
//!   role=Admin. That one transition additionally requires a live
//!   step-up elevation on the caller's session (spec §10.4's UV
//!   requirement, now satisfied by the `auth/passkey/login` step-up
//!   ceremony rather than a ceremony of its own).
//!
//! The fused `POST /v1/members/{did}/promote-to-admin/{start,finish}`
//! pair is **gone**: it ran a second implementation of passkey UV
//! inline with the role change. See `update.rs` for the split.
//!
//! All endpoints require `AdminAuth` in Phase 1 (the auth layer
//! still uses vti-common's Role taxonomy until M1.10 introduces
//! non-Admin authenticated sessions; the Member-role policy
//! surface is Phase 2+).

pub mod personhood;
pub mod read;
pub mod relationships;
pub mod remove;
pub mod renew;
pub mod request_vmc;
pub mod rotate;
pub mod update;
