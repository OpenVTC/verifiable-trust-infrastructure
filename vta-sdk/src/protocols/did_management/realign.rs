//! `POST /webvh/dids/{did}/realign-keys` — the repair for a DID whose key
//! records are not named after the verification methods it publishes.
//!
//! A key record's id **is** a verification-method id, and
//! [`crate::did_secrets::select_secret_kid`] rule 1 depends on it: the record id
//! is the kid a mediator matches inbound JWE recipients against. A DID minted
//! before create read its own document carries records named `#key-0` /
//! `#key-1` whatever the document says — and the `room` / `room-host` templates
//! number their methods from `#key-1`.
//!
//! The repair is not `keys/rename`, and cannot be: that gate exists so a rename
//! is "not a back door into VM-shaped or namespace-colliding names". Here the
//! agent computes every target from the DID's own published log and matches
//! records to methods by `publicKeyMultibase`, so no caller-supplied string
//! becomes a store key — and a key already renamed away from its method id,
//! which no caller-facing call can name again, is still found.

use serde::{Deserialize, Serialize};

/// Ask an agent to realign one DID's key records.
///
/// The DID and a boolean, and deliberately nothing else: a member naming a
/// target identifier would make this a way to write chosen names into a key
/// store, which is exactly what `keys/rename`'s identifier gate exists to
/// prevent. Every name in the outcome comes from the DID's own published log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RealignDidKeysBody {
    pub did: String,
    /// Compute and report the realignment without performing it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dry_run: bool,
}

/// One record whose id did not match the method carrying its public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RealignedKey {
    /// The id the record has today.
    pub from: String,
    /// The verification-method id the document publishes for this key.
    pub to: String,
    /// The public half that identified it. Present so an operator can check a
    /// move against the document themselves rather than trusting this listing.
    pub public_key: String,
}

/// What a realign did, or would do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RealignDidKeysResultBody {
    pub did: String,
    /// Records moved onto the id the document publishes.
    pub moved: Vec<RealignedKey>,
    /// Verification-method ids whose record was already correct.
    pub already_aligned: Vec<String>,
    /// Verification-method ids this agent holds no key for.
    ///
    /// Not an error: a DID may publish a method whose private half lives
    /// somewhere else entirely. Reported rather than skipped silently, because
    /// "nothing to move" and "the key is not here" are different answers and
    /// only one of them means the repair is complete.
    pub unmatched: Vec<String>,
    /// `next_fragment_id` after the repair — one past the highest `#key-N` the
    /// document publishes, so a later rotation cannot allocate over a live one.
    pub next_fragment_id: u32,
    /// True when nothing was written.
    pub dry_run: bool,
}
