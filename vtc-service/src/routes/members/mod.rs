//! `/v1/members/*` route handlers.
//!
//! Spec §5.2 + §10.1–10.4. Phase 1 shape per
//! `tasks/vtc-mvp/phase-1-todo.md` M1.4–M1.6:
//!
//! - `GET /v1/members` — paginated list.
//! - `GET /v1/members/{did}` — single member.
//! - `GET /v1/members/{did}/credentials` — that member's credential bodies
//!   (`vtc/members/credentials/0.1`, see `credentials.rs`).
//! - `PATCH /v1/members/{did}` — profile fields and non-admin role
//!   changes. `role: admin` is refused here with the task's declared
//!   `adminRoleForbidden`; promotion is `acl/change-role/0.1`
//!   (`PATCH /v1/acl/{did}`), behind the live step-up elevation the
//!   role-change ceremony's host invariant demands. See `update.rs`.
//!
//! The fused `POST /v1/members/{did}/promote-to-admin/{start,finish}`
//! pair is **gone**: it ran a second implementation of passkey UV
//! inline with the role change. See `update.rs` for the history.
//!
//! All endpoints require `AdminAuth` in Phase 1 (the auth layer
//! still uses vti-common's Role taxonomy until M1.10 introduces
//! non-Admin authenticated sessions; the Member-role policy
//! surface is Phase 2+).

pub mod credentials;
pub mod personhood;
pub mod read;
pub mod relationships;
pub mod remove;
pub mod renew;
pub mod request_vmc;
pub mod rotate;
pub mod update;
