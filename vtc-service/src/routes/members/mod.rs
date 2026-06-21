//! `/v1/members/*` route handlers.
//!
//! Spec §5.2 + §10.1–10.4. Phase 1 shape per
//! `tasks/vtc-mvp/phase-1-todo.md` M1.4–M1.6:
//!
//! - `GET /v1/members` — paginated list.
//! - `GET /v1/members/{did}` — single member.
//! - `PATCH /v1/members/{did}` — role + profile fields. Refuses
//!   role=Admin (use `promote-to-admin`).
//! - `POST /v1/members/{did}/promote-to-admin/{start,finish}` —
//!   two-phase step-up UV ceremony per spec §10.4. Lands in
//!   M1.6 (`promote.rs`).
//!
//! All endpoints require `AdminAuth` in Phase 1 (the auth layer
//! still uses vti-common's Role taxonomy until M1.10 introduces
//! non-Admin authenticated sessions; the Member-role policy
//! surface is Phase 2+).

pub mod personhood;
pub mod promote;
pub mod read;
pub mod relationships;
pub mod remove;
pub mod renew;
pub mod request_vmc;
pub mod rotate;
pub mod update;
