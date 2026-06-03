//! VTA credential vault — the format-agnostic credential store
//! (`docs/05-design-notes/vti-credential-architecture.md` §5, task 1.1).
//!
//! This is the credential-architecture data plane the VTA grows in Phase 1:
//! it stores the W3C / SD-JWT-VC credentials a holder *holds* (invitations,
//! memberships, roles, endorsements, …), indexed so the holder's agent can
//! find them by `{type, community_did, issuer_did, purpose, status}` without
//! parsing every body.
//!
//! ## Not the password vault
//!
//! `vti_common::vault` is a *different* vault: the password-manager
//! `VaultEntry` records (site logins, OAuth tokens, passkeys) used by
//! Companions to authenticate against external sites. Both stores share the
//! single `vault` keyspace but use disjoint key namespaces:
//!
//! | Namespace | Owner | Holds |
//! |-----------|-------|-------|
//! | `vault:<id>`     | `vti_common::vault` | password-manager `VaultEntry` |
//! | `cred:<id>`      | this module         | `StoredCredential` (the body, encrypted) |
//! | `idx:<field>:…`  | this module         | credential secondary index (key-only) |
//!
//! ## Scope of task 1.1 (and what is deliberately absent)
//!
//! This module is **format-agnostic** and does **no cryptography**: it
//! stores opaque credential bodies plus an indexed metadata envelope, with
//! encryption-at-rest delegated to the keyspace's AES-256-GCM wrapper. It
//! does **not** verify issuer signatures (task 1.2 receive), search via DCQL
//! (1.3), build presentations or disclose claims (1.4 present), mint (1.5),
//! or resolve status lists (1.6).
//!
//! It also exposes **no wallet-enumeration primitive** — there is no
//! `list_all`. The only discovery path is [`storage::find_by_index`], which
//! requires an explicit indexed field *and* value. This is the storage-layer
//! expression of the no-enumeration invariant
//! (`vti-credential-architecture.md` §14); the route/operation layers built
//! on top in later tasks must preserve it (DCQL-targeted discovery only,
//! never "return the whole set").

pub mod index;
pub mod model;
pub mod storage;

pub use model::{
    CredentialFormat, CredentialPurpose, CredentialStatus, IndexField, StoredCredential,
};
pub use storage::{delete, find_by_index, get, put};
