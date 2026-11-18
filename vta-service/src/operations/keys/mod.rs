//! Key operations, split by responsibility (#2569):
//!
//! - `records` — create, import, read, list, rename, revoke;
//! - `gates` — the capability gates (`ensure_may_*`, `require_key_nameable`);
//! - `secret` — releasing a private key (export, internal use, exportability);
//! - `sign` — the signing oracle.
//!
//! Everything is re-exported here, so `crate::operations::keys::…` paths are
//! unchanged. The key-custody rules apply to every file: network-reachable code
//! reaches key material only through `operations::key_custody`, and
//! `tests/it/key_custody_census.rs` pins each raw seed access by file.

use crate::audit::{self, audit};
use crate::auth::AuthClaims;
use crate::contexts::get_context;
use crate::error::{AppError, key_derivation_error};
use crate::keys::derivation::Bip32Extension;
use crate::keys::imported;
use crate::keys::paths::allocate_path;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{
    self, KeyOrigin, KeyRecord, KeyStatus, KeyType, encode_private_multibase,
    encode_public_multibase,
};
use crate::store::{KeyspaceHandle, ScanOpts};
use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use base64::Engine;
use chrono::Utc;
use p256::elliptic_curve::sec1::ToSec1Point;
use std::sync::Arc;
use tracing::info;
use vta_sdk::protocols::key_management::{
    create::CreateKeyResultBody,
    derive_and_sign::DeriveAndSignResultBody,
    derive_and_sign_document::DeriveAndSignDocumentResultBody,
    list::ListKeysResultBody,
    rename::RenameKeyResultBody,
    revoke::RevokeKeyResultBody,
    secret::GetKeySecretResultBody,
    sign::{SignAlgorithm, SignResultBody, SigningDomain},
};
use vti_common::acl::Capability;
use zeroize::Zeroize;

mod gates;
mod records;
mod secret;
mod sign;
#[cfg(test)]
mod test_support;

pub(crate) use gates::*;
pub use records::*;
pub use secret::*;
pub use sign::*;
