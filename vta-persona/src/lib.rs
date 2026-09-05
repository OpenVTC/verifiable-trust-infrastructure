//! VTA persona store — the holder's own identity, and the contacts peers
//! disclose to them.
//!
//! The fourth holder store, beside the secrets vault, the credential vault and
//! application state. It exists as a distinct store because **disclosure
//! control is its point**, and a maintainer that cannot read a record cannot
//! decide which of its members may leave, cannot audit which ones did, and
//! cannot answer "what have I shared with whom". `vta/app-state` promises never
//! to interpret its records, so it cannot host this; and a namespace there is
//! collision avoidance rather than a trust boundary, so a compromised
//! application sharing a context could remove the holder's identity data.
//!
//! # The boundary is one-way
//!
//! The pool and profiles are **agent-scoped**; bindings, contacts and
//! disclosure records are **context-scoped**. Nothing inside a context may read
//! the pool — the holder pushes a materialised projection down, and a context
//! never pulls.
//!
//! That is a rule about *direction* rather than a permission, because the
//! permission form invites the wrong implementation: a guard written as "is this
//! caller an administrator" passes for an administrator scoped to a single
//! context, who then reads identity data belonging to every other context. An
//! access-control failure over a readable pool discloses everything; a pool no
//! context can address has nothing to disclose.
//!
//! Authorization is enforced at dispatch, not here. What this crate provides is
//! a key layout in which the two scopes are *separately addressable*, so the
//! enforcement is expressible — and so a context-scoped enumeration scans a
//! space that structurally cannot contain an agent-scoped record, rather than
//! scanning everything and filtering. A filter is a line of code that can be
//! got wrong; an address space cannot.
//!
//! # What this crate does not do
//!
//! No cryptography beyond the at-rest wrapper and the correlation index's keyed
//! hash. Rung *selection* lives here; proof *derivation* stays in `vta-vault`,
//! so there is one BBS implementation in the workspace rather than two.

pub mod correlation;
pub mod model;
pub mod storage;

pub use model::{
    Attribute, Binding, InlineValue, OverrideValue, Profile, ProfileEntry, ProofRung, Provenance,
    StaleReason, Ulid, ValueType, Version,
};
