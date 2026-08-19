//! `Idempotency-Key` header support.
//!
//! Implements **M0.1.3** of the VTC MVP Phase 0 plan. Every mutating
//! endpoint accepts an optional `Idempotency-Key` header — the workspace
//! caches `(principal, key) → response` so safe retries return the
//! original outcome instead of creating duplicate state.
//!
//! ## Key design properties (spec §9.1 + plan D6)
//!
//! - **Cache key is scoped by principal, never global.** A second
//!   principal that re-uses the same idempotency value gets its own
//!   cache namespace — no cross-principal leakage of cached responses.
//!   The principal identifier is derived from the Authorization
//!   header (hashed) on authenticated requests, or the source IP on
//!   unauthenticated routes. See [`Principal`] for the full
//!   derivation.
//! - **TTL discriminates by op class.** [`IdempotencyClass::NonDestructive`]
//!   caches for 24 h (standard create/update retry window).
//!   [`IdempotencyClass::Destructive`] caches for 60 s only — long
//!   enough to absorb a network-flake retry, short enough that a
//!   later (intentional) re-create with the same UUID is not
//!   accidentally treated as a no-op against an already-deleted
//!   target.
//! - **Same key + different body → 422 `IdempotencyKeyConflict`.**
//!   Prevents a drifting payload from silently returning a stale
//!   cached response.
//! - **Annotation is explicit per-route.** No heuristic on HTTP
//!   method (`DELETE /idempotency/{key}` is itself a meta-op). Each
//!   route opts in to a class at registration via
//!   [`crate::trust_task::TrustTaskRouter::route_idempotent`] (added
//!   to the router builder when the consuming service wires this in).
//!
//! ## What's NOT in this module yet
//!
//! - **Target-state revalidation for `Destructive`**: the spec calls
//!   for the destructive class to re-check that the cached response
//!   still describes accurate state before serving it (e.g. a cached
//!   delete returning 204 after the target has been re-created
//!   should *not* be served). Plumbed-through as an optional closure
//!   on the [`store::IdempotencyStore`] in a follow-up; MVP ships
//!   TTL-only.
//! - **Background eviction sweeper**: expired entries are filtered
//!   out at read time (no stale responses ever served). A sweeper
//!   that reclaims their disk space lands alongside the audit-log
//!   pruner in a later phase.

pub mod class;
pub mod middleware;
pub mod store;

pub use class::IdempotencyClass;
pub use middleware::{
    IDEMPOTENCY_HEADER, IdempotencyLayerState, MAX_BODY_BYTES, idempotency_middleware,
};
pub use store::{
    CacheEntry, ClaimOutcome, CompletedResponse, EntryState, IdempotencyStore, Principal,
    principal_from_request,
};
