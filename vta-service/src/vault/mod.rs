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
//! The **storage** layer ([`storage`], [`index`], [`model`]) is
//! format-agnostic and does **no cryptography**: it stores opaque credential
//! bodies plus an indexed metadata envelope, with encryption-at-rest
//! delegated to the keyspace's AES-256-GCM wrapper. The **receive** layer
//! ([`receive`], task 1.2) sits on top of it: it verifies an incoming
//! SD-JWT-VC minimally (issuer signature + temporal validity), maps it into a
//! [`StoredCredential`], and stores + indexes it through the storage layer.
//! The **query** layer ([`query`], task 1.3) is the local DCQL-shaped search:
//! it returns descriptors (never bodies) for credentials matching an explicit
//! filter. The **mint** layer ([`mint`], task 1.5) is the issue path: the VTA
//! signs its *own* SD-JWT-VC (selected claims selectively disclosable, holder
//! key bound as `cnf`) through a sign-only signer abstraction, never exporting
//! the issuer key. The **present** layer ([`present`], task 1.4) is the
//! consent-gated disclosure path: it loads a stored SD-JWT-VC + a signed
//! consent record, gates disclosure on [`consent::authorizes`], refuses any
//! revoked / temporally-invalid credential, and emits a selectively-disclosed
//! presentation revealing **only** the consented claims plus a mandatory holder
//! `kb-jwt`. Still to come: resolve status lists (1.6).
//!
//! It also exposes **no wallet-enumeration primitive** — there is no
//! `list_all`. The only discovery path is [`storage::find_by_index`], which
//! requires an explicit indexed field *and* value. This is the storage-layer
//! expression of the no-enumeration invariant
//! (`vti-credential-architecture.md` §14); the route/operation layers built
//! on top in later tasks must preserve it (DCQL-targeted discovery only,
//! never "return the whole set").

pub mod consent;
pub mod index;
pub mod mint;
pub mod model;
pub mod present;
pub mod query;
pub mod receive;
pub mod status;
pub mod storage;

pub use consent::{
    ConsentGrant, ConsentProcess, ConsentRecord, ConsentStatusEvent, ConsentStatusType, authorizes,
};
pub use mint::{MintRequest, mint_and_store_sd_jwt_vc, mint_sd_jwt_vc};
pub use model::{
    CredentialFormat, CredentialPurpose, CredentialStatus, IndexField, StoredCredential,
};
pub use present::{present_di_vc, present_sd_jwt_vc};
pub use query::{CredentialDescriptor, CredentialQuery, search};
pub use receive::{receive, receive_di_vc, receive_sd_jwt_vc};
pub use status::{
    RefreshOutcome, ResolvedStatusList, StatusListRef, StatusListResolver, extract_status_ref,
    refresh_status,
};
pub use storage::{delete, find_by_index, get, put};
