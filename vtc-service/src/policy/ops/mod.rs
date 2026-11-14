//! `/v1/policies/*` route handlers (Phase 2 M2.3 — admin
//! endpoints; M2.4 — read endpoints).
//!
//! Spec §7 + plan §§D2, D3, D8. Phase 2 routes the policy upload /
//! activate / test surface through these handlers and emits the
//! `PolicyUploaded` / `PolicyActivated` audit envelopes added in
//! vti-common alongside this milestone.
//!
//! All endpoints require `AdminAuth` — non-admin auth tiers were
//! introduced in Phase 1's M1.10 but policy management is an
//! admin-only operation per spec §10.4.

pub mod admin;
pub mod read;
