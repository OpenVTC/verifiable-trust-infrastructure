//! # Key custody: the rules for the master seed, and the only door to a key.
//!
//! **Read this before writing any code that loads the seed, builds a BIP-32
//! root, or derives a key.**
//!
//! Every key the VTA derives is a pure function of the master seed and a
//! derivation path. So deriving a key at a path is as sensitive as holding the
//! key. Whoever can choose the path can hold any key the VTA has ever minted:
//! another tenant's, the VTA's own signing key, the `did:webvh` update key
//! that controls the VTA's identifier. Authorization therefore has to cover the
//! *path*, not just the operation. FTL-29904 and the holes found alongside it
//! were all this one mistake:
//!
//! - seed listing and rotation were gated on the admin *role*, so a
//!   context-scoped admin could rotate the instance-wide seed;
//! - `keys/create` accepted a caller-chosen path and recorded the key under the
//!   caller's own context, so a tenant could derive another context's key (or
//!   the VTA's) and then export it, because the scope check reads the record's
//!   context, which the caller had just chosen;
//! - `keys/derive-and-sign` signed at any path for any admin.
//!
//! ## The rules
//!
//! 1. **Seed state is instance-wide.** Listing, rotating or otherwise touching
//!    seed generations requires unrestricted act authority (a super-admin,
//!    VTI-ACL-022). The specification assigns seed administration to no
//!    narrower authority, and where it is silent a node refuses (VTI-ACL-092).
//! 2. **Root derivation material never leaves the VTA** except through the
//!    backup mechanism (VTI-VTA-001, VTI-KEY-033). Nothing here returns seed
//!    bytes or a BIP-32 root to a caller.
//! 3. **A context's key is derived from that context's base, and from no other
//!    context's** (VTI-KEY-030, VTI-KEY-032). A path belongs to the context
//!    with the *deepest* base strictly above it; see [`owning_context`]. A key
//!    record's `context_id` must name that owner.
//! 4. **Only a super-admin may choose a path.** Every other caller gets one
//!    allocated under the context's base. A super-admin's chosen path is still
//!    held to rule 3: authority to choose is not authority to mislabel.
//! 5. **The delegated-identity subtree [`DELEGATED_IDENTITY_ROOT`] is
//!    sign-only.** `keys/derive-and-sign*` may derive there and nowhere else,
//!    and no key record may ever be created there, so an identity in that subtree
//!    can be used without persisting or exporting its key.
//! 6. **Rules are checked where the key is *used*, not only where it is
//!    created.** A record that violates rule 3 (written by an older build,
//!    restored from a backup, or planted before this module existed) is refused
//!    at derivation time by [`authorize_record_derivation`], so a bad record is
//!    inert rather than exploitable.
//! 7. **A key referenced by id from a context-scoped resource must be in that
//!    context's subtree** ([`check_key_in_scope`]). Loading a key "internally"
//!    (without a caller's claims) is safe only when the *key id* is fixed by the
//!    VTA, such as `{vta_did}#key-0`. When the id comes from stored data a caller
//!    wrote (a vault entry's `signingKeyId`), the loader must hold the key to
//!    the resource's context. Otherwise a vault entry naming the VTA's own key
//!    makes the VTA sign as itself for whoever wrote the entry.
//!
//! ## The doors
//!
//! | Need | Use |
//! |---|---|
//! | Derive the key a stored [`KeyRecord`] names | [`authorize_record_derivation`] → [`AuthorizedRecordDerivation::load`] → [`RecordKey`] |
//! | Accept a caller-chosen path for a new record | [`check_explicit_key_path`] |
//! | Sign as a delegated identity (no record) | [`check_delegated_identity_path`] |
//! | Raw seed bytes | [`crate::seeds::load_seed_bytes`]. **Restricted:** see below |
//!
//! [`RecordKey`] deliberately holds its BIP-32 root privately and exposes only
//! derivations at the record's own path, so a caller given one cannot derive
//! anywhere else.
//!
//! `load_seed_bytes`, `SeedStore::get` and `ExtendedSigningKey::from_seed` are
//! the raw primitives. They remain public because boot, setup, rotation,
//! backup and the offline CLIs legitimately need the whole seed. In
//! `vta-service` a census test (`key_custody_census`) pins every production
//! call site. A new one fails the build until it is reviewed and listed with
//! its reason. **Do not add a raw call site in anything a network caller can
//! reach.** Go through these doors, or add a new one here, where the rules
//! above are enforced once.

use std::fmt;

use p256::elliptic_curve::sec1::ToSec1Point;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use vti_common::error::{AppError, key_derivation_error};
use vti_common::slip10::{ChildIndex, DerivationPath, ExtendedSigningKey};
use vti_common::store::KeyspaceHandle;
use zeroize::Zeroizing;

use crate::derivation::{Bip32Extension, P256Secret};
use crate::seed_store::SeedStore;
use crate::seeds::load_seed_bytes;
use crate::{KeyOrigin, KeyRecord, KeyType, encode_private_multibase, encode_public_multibase};

/// The subtree reserved for delegated identities that `keys/derive-and-sign*`
/// signs as without persisting a key record. For example, a fleet manager's
/// per-VTA super-admin is at `m/26'/9'/<idx>'`. Rule 5 in the module
/// documentation.
pub const DELEGATED_IDENTITY_ROOT: &str = "m/26'/9'";

/// Why a derivation was refused. Every variant is a security refusal and
/// converts to [`AppError::Forbidden`]. Callers that can see a violation should
/// also report it (audit plus a `security_alert` log). `vta-service`'s
/// `operations::key_custody` does both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyViolation {
    /// The path does not parse as a BIP-32 path.
    UnparseablePath { path: String, reason: String },
    /// A delegated-identity signature was requested outside
    /// [`DELEGATED_IDENTITY_ROOT`], or at a non-hardened index.
    OutsideDelegatedRoot { path: String },
    /// A key record was requested inside [`DELEGATED_IDENTITY_ROOT`].
    InsideDelegatedRoot { path: String },
    /// The path belongs to a different context than the one the key would be
    /// recorded under (or to a context when the key would be context-less, or
    /// to none when it names one).
    ForeignPath {
        path: String,
        requested_context: Option<String>,
        owning_context: Option<String>,
    },
    /// A stored record names a context whose base does not contain its path.
    RecordOutsideContext {
        key_id: String,
        path: String,
        context_id: String,
        context_base: String,
    },
    /// A stored record names a context that no longer exists, so its
    /// containment cannot be established. Fails closed.
    RecordContextMissing { key_id: String, context_id: String },
    /// A record whose origin is not `Derived` was presented for derivation.
    NotDerived { key_id: String },
    /// A key referenced from a context-scoped resource (e.g. a vault entry's
    /// `signingKeyId`) is not in that resource's context or a descendant of it.
    /// Rule 7.
    KeyOutsideScope {
        key_id: String,
        record_context: Option<String>,
        scope_context: String,
    },
}

impl fmt::Display for CustodyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnparseablePath { path, reason } => {
                write!(
                    f,
                    "derivation path `{path}` is not a valid BIP-32 path: {reason}"
                )
            }
            Self::OutsideDelegatedRoot { path } => write!(
                f,
                "derive-and-sign is confined to the delegated-identity subtree \
                 {DELEGATED_IDENTITY_ROOT} (all indexes hardened); `{path}` is outside it"
            ),
            Self::InsideDelegatedRoot { path } => write!(
                f,
                "`{path}` is inside the delegated-identity subtree \
                 {DELEGATED_IDENTITY_ROOT}, which is sign-only: no key record may be \
                 created there. Use keys/derive-and-sign instead"
            ),
            Self::ForeignPath {
                path,
                requested_context,
                owning_context,
            } => write!(
                f,
                "derivation path `{path}` belongs to {} and cannot be recorded under {}. \
                 A key must be derived from its own context's base (VTI-KEY-030, \
                 VTI-KEY-032); omit the path to have one allocated",
                describe_context(owning_context.as_deref()),
                describe_context(requested_context.as_deref()),
            ),
            Self::RecordOutsideContext {
                key_id,
                path,
                context_id,
                context_base,
            } => write!(
                f,
                "key `{key_id}` is recorded under context `{context_id}` (base \
                 {context_base}) but its derivation path `{path}` is outside that base; \
                 refusing to derive it (VTI-KEY-032)"
            ),
            Self::RecordContextMissing { key_id, context_id } => write!(
                f,
                "key `{key_id}` names context `{context_id}`, which does not exist; \
                 refusing to derive it"
            ),
            Self::NotDerived { key_id } => {
                write!(f, "key `{key_id}` is not a derived key")
            }
            Self::KeyOutsideScope {
                key_id,
                record_context,
                scope_context,
            } => write!(
                f,
                "key `{key_id}` belongs to {} and cannot be used on behalf of context \
                 `{scope_context}`: a key referenced from a context-scoped resource must \
                 be in that context or a descendant of it (VTI-CTX-002)",
                describe_context(record_context.as_deref()),
            ),
        }
    }
}

fn describe_context(ctx: Option<&str>) -> String {
    match ctx {
        Some(c) => format!("context `{c}`"),
        None => "no context".to_string(),
    }
}

impl std::error::Error for CustodyViolation {}

impl From<CustodyViolation> for AppError {
    fn from(v: CustodyViolation) -> Self {
        AppError::Forbidden(v.to_string())
    }
}

/// Parse a derivation path, reporting a failure as a [`CustodyViolation`].
pub fn parse_path(path: &str) -> Result<DerivationPath, CustodyViolation> {
    path.parse::<DerivationPath>()
        .map_err(|e| CustodyViolation::UnparseablePath {
            path: path.to_string(),
            reason: e.to_string(),
        })
}

/// `true` when `path` lies **strictly** below `base`, comparing whole indexes.
///
/// Never compare path *strings* by prefix: `m/26'/2'/1'` is a string prefix of
/// `m/26'/2'/10'/0'`, which belongs to a different context.
pub fn is_strictly_within(base: &DerivationPath, path: &DerivationPath) -> bool {
    let (b, p) = (base.path(), path.path());
    p.len() > b.len() && p[..b.len()] == *b
}

/// The context that owns `path`: the one whose base is the **deepest** base
/// strictly above it.
///
/// Deepest, because child contexts nest under their parent's base
/// (VTI-CTX-022). A path under a child's base is the child's, not the
/// parent's, even though it is also under the parent's base. Strictly, because
/// a parent's allocator issues `{parent}/<n>'`, which is also a child's *base*
/// (not a key inside the child). Such a key has no chain code in any export,
/// so the child's keys cannot be reached from it.
///
/// `contexts` yields `(context_id, base_path)`. An unparseable base is skipped:
/// it cannot contain anything, and refusing every derivation because one
/// context record is corrupt would turn one bad row into a VTA-wide outage.
pub fn owning_context<'a, I>(path: &DerivationPath, contexts: I) -> Option<&'a str>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut best: Option<(&'a str, usize)> = None;
    for (id, base) in contexts {
        let Ok(base) = base.parse::<DerivationPath>() else {
            continue;
        };
        if is_strictly_within(&base, path) && best.is_none_or(|(_, depth)| base.len() > depth) {
            best = Some((id, base.len()));
        }
    }
    best.map(|(id, _)| id)
}

/// Check a caller-chosen path for a **new key record** against rules 3–5.
///
/// The caller must already have established that the requester is a
/// super-admin (rule 4); this checks only that the path is one the record may
/// honestly carry. `context_id` is the context the record will be stored
/// under; `contexts` is every context's `(id, base_path)`.
pub fn check_explicit_key_path<'a, I>(
    path: &str,
    context_id: Option<&str>,
    contexts: I,
) -> Result<DerivationPath, CustodyViolation>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let parsed = parse_path(path)?;
    let delegated = parse_path(DELEGATED_IDENTITY_ROOT).expect("constant path parses");
    if parsed == delegated || is_strictly_within(&delegated, &parsed) {
        return Err(CustodyViolation::InsideDelegatedRoot {
            path: path.to_string(),
        });
    }
    let owner = owning_context(&parsed, contexts);
    if owner != context_id {
        return Err(CustodyViolation::ForeignPath {
            path: path.to_string(),
            requested_context: context_id.map(str::to_string),
            owning_context: owner.map(str::to_string),
        });
    }
    Ok(parsed)
}

/// Check a path for a delegated-identity signature (`keys/derive-and-sign*`):
/// strictly inside [`DELEGATED_IDENTITY_ROOT`], every index hardened. Rule 5.
///
/// Hardened-only, because a non-hardened child's key can be computed from its
/// parent's extended public key plus the child's private key. Ed25519 SLIP-0010
/// refuses non-hardened derivation anyway, but the rule is stated here rather
/// than inherited from a library's choice.
pub fn check_delegated_identity_path(path: &str) -> Result<DerivationPath, CustodyViolation> {
    let parsed = parse_path(path)?;
    let root = parse_path(DELEGATED_IDENTITY_ROOT).expect("constant path parses");
    let hardened = parsed.path().iter().all(|i| i.is_hardened());
    if !is_strictly_within(&root, &parsed) || !hardened {
        return Err(CustodyViolation::OutsideDelegatedRoot {
            path: path.to_string(),
        });
    }
    Ok(parsed)
}

/// Rule 7: a key referenced from a resource in `scope_context` must be in
/// that context or one of its descendants. A context-less key (the VTA's own)
/// is never in scope for a context-scoped resource.
///
/// Context ids are paths (`acme/eng`), compared segment by segment with
/// [`vta_sdk::context_path::is_ancestor_or_self`], so `acme` does not cover
/// `acme-evil`.
pub fn check_key_in_scope(record: &KeyRecord, scope_context: &str) -> Result<(), CustodyViolation> {
    match record.context_id.as_deref() {
        Some(key_ctx) if vta_sdk::context_path::is_ancestor_or_self(scope_context, key_ctx) => {
            Ok(())
        }
        other => Err(CustodyViolation::KeyOutsideScope {
            key_id: record.key_id.clone(),
            record_context: other.map(str::to_string),
            scope_context: scope_context.to_string(),
        }),
    }
}

/// A stored record whose derivation is authorized by the custody rules.
/// Constructed only by [`authorize_record_derivation`], so holding one proves
/// the containment check ran.
#[derive(Debug)]
pub struct AuthorizedRecordDerivation {
    path: DerivationPath,
    path_str: String,
    key_type: KeyType,
    seed_id: Option<u32>,
}

/// Rule 6: authorize deriving the key a stored record names.
///
/// `context_base` is the base path of `record.context_id`'s context, or `None`
/// when that context was not found. For a context-less record pass `None`: its
/// callers are super-admin-only surfaces, and this check does not widen them.
///
/// This checks the record against its own context's base, which is cheap
/// enough to run on every signature. The stricter descendant rule (a path
/// inside a *child* context's subtree) is enforced where records are created,
/// and by the boot-time scan. A parent's authority covers its descendants
/// (VTI-CTX-017), so a record that breaks only that rule does not widen anyone's
/// reach.
pub fn authorize_record_derivation(
    record: &KeyRecord,
    context_base: Option<&str>,
) -> Result<AuthorizedRecordDerivation, CustodyViolation> {
    if record.origin != KeyOrigin::Derived {
        return Err(CustodyViolation::NotDerived {
            key_id: record.key_id.clone(),
        });
    }
    let path = parse_path(&record.derivation_path)?;
    if let Some(ctx) = record.context_id.as_deref() {
        let Some(base_str) = context_base else {
            return Err(CustodyViolation::RecordContextMissing {
                key_id: record.key_id.clone(),
                context_id: ctx.to_string(),
            });
        };
        let within = parse_path(base_str)
            .map(|base| is_strictly_within(&base, &path))
            .unwrap_or(false);
        if !within {
            return Err(CustodyViolation::RecordOutsideContext {
                key_id: record.key_id.clone(),
                path: record.derivation_path.clone(),
                context_id: ctx.to_string(),
                context_base: base_str.to_string(),
            });
        }
    }
    Ok(AuthorizedRecordDerivation {
        path,
        path_str: record.derivation_path.clone(),
        key_type: record.key_type.clone(),
        seed_id: record.seed_id,
    })
}

impl AuthorizedRecordDerivation {
    /// Load the record's seed generation and return its key. The seed bytes
    /// are dropped (and zeroized) before this returns.
    pub async fn load(
        self,
        keys_ks: &KeyspaceHandle,
        seed_store: &dyn SeedStore,
    ) -> Result<RecordKey, AppError> {
        let seed = load_seed_bytes(keys_ks, seed_store, self.seed_id)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let root = ExtendedSigningKey::from_seed(&seed)
            .map_err(|e| key_derivation_error(format!("failed to create BIP-32 root key: {e}")))?;
        Ok(RecordKey {
            root,
            path: self.path,
            path_str: self.path_str,
            key_type: self.key_type,
        })
    }
}

/// The key material for exactly one authorized record.
///
/// The BIP-32 root is private and every method derives at the record's own
/// path, so code handed a `RecordKey` cannot reach any other key. Don't add an
/// accessor for the root or a method taking a path; that would reopen
/// the hole this type exists to close.
pub struct RecordKey {
    root: ExtendedSigningKey,
    path: DerivationPath,
    path_str: String,
    key_type: KeyType,
}

impl fmt::Debug for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordKey")
            .field("path", &self.path_str)
            .field("key_type", &self.key_type)
            .finish_non_exhaustive()
    }
}

impl RecordKey {
    /// The record's key type.
    pub fn key_type(&self) -> &KeyType {
        &self.key_type
    }

    /// The raw 32-byte Ed25519 signing key (seed form) at the record's path.
    /// This is the SLIP-0010 node, whatever the record's `key_type` says. Callers
    /// that need a typed key should check `key_type` first.
    pub fn ed25519_signing_key_bytes(&self) -> Result<Zeroizing<[u8; 32]>, AppError> {
        let node = self
            .root
            .derive(&self.path)
            .map_err(|e| key_derivation_error(format!("derivation failed: {e}")))?;
        Ok(Zeroizing::new(*node.signing_key.as_bytes()))
    }

    /// Ed25519 [`Secret`] at the record's path.
    pub fn ed25519_secret(&self) -> Result<Secret, AppError> {
        self.root.derive_ed25519(&self.path_str)
    }

    /// X25519 [`Secret`] at the record's path.
    pub fn x25519_secret(&self) -> Result<Secret, AppError> {
        self.root.derive_x25519(&self.path_str)
    }

    /// P-256 secret at the record's path.
    pub fn p256_secret(&self) -> Result<P256Secret, AppError> {
        self.root.derive_p256(&self.path_str)
    }

    /// `(public, private)` multibase for the record's key type. This is the one
    /// place the per-type encoding for export lives.
    pub fn multibase_pair(&self) -> Result<(String, Zeroizing<String>), AppError> {
        let (public, private) = match self.key_type {
            KeyType::Ed25519 => secret_pair(self.root.derive_ed25519(&self.path_str)?)?,
            KeyType::X25519 => secret_pair(self.root.derive_x25519(&self.path_str)?)?,
            KeyType::MlDsa44 => secret_pair(self.root.derive_ml_dsa_44(&self.path_str)?)?,
            KeyType::MlDsa65 => secret_pair(self.root.derive_ml_dsa_65(&self.path_str)?)?,
            KeyType::P256 => {
                let p256 = self.root.derive_p256(&self.path_str)?;
                let point = p256.secret_key.public_key().to_sec1_point(true);
                (
                    encode_public_multibase(&KeyType::P256, point.as_bytes()),
                    encode_private_multibase(&KeyType::P256, &p256.secret_key.to_bytes()),
                )
            }
            // `KeyType` is `#[non_exhaustive]`. Refuse rather than fall back:
            // each arm above uses a scheme-specific derivation and there is no
            // generic one, so a wildcard could only mislabel another algorithm's key.
            ref other => {
                return Err(AppError::Validation(format!(
                    "key derivation does not support {other} yet"
                )));
            }
        };
        Ok((public, Zeroizing::new(private)))
    }
}

fn secret_pair(secret: Secret) -> Result<(String, String), AppError> {
    let public = secret
        .get_public_keymultibase()
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let private = secret
        .get_private_keymultibase()
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    Ok((public, private))
}

/// Every index hardened, e.g. for a path a caller supplies. Exposed for
/// callers that want to state the requirement without re-implementing it.
pub fn is_fully_hardened(path: &DerivationPath) -> bool {
    path.path().iter().all(|i: &ChildIndex| i.is_hardened())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vta_sdk::keys::KeyStatus;

    fn p(s: &str) -> DerivationPath {
        s.parse().unwrap()
    }

    const CONTEXTS: &[(&str, &str)] = &[
        ("vta", "m/26'/2'/0'"),
        ("tenant-a", "m/26'/2'/1'"),
        ("tenant-a-child", "m/26'/2'/1'/0'"),
        ("tenant-j", "m/26'/2'/10'"),
    ];

    fn record(ctx: Option<&str>, path: &str) -> KeyRecord {
        KeyRecord {
            key_id: "k".into(),
            derivation_path: path.into(),
            key_type: KeyType::Ed25519,
            status: KeyStatus::Active,
            public_key: String::new(),
            label: None,
            context_id: ctx.map(str::to_string),
            exportable: None,
            seed_id: Some(0),
            origin: KeyOrigin::Derived,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn containment_compares_indexes_not_strings() {
        // "m/26'/2'/1'" is a string prefix of "m/26'/2'/10'/0'".
        assert!(!is_strictly_within(
            &p("m/26'/2'/1'"),
            &p("m/26'/2'/10'/0'")
        ));
        assert!(is_strictly_within(&p("m/26'/2'/1'"), &p("m/26'/2'/1'/0'")));
        assert!(!is_strictly_within(&p("m/26'/2'/1'"), &p("m/26'/2'/1'")));
    }

    #[test]
    fn owner_is_the_deepest_strict_base() {
        let it = || CONTEXTS.iter().copied();
        assert_eq!(owning_context(&p("m/26'/2'/1'/5'"), it()), Some("tenant-a"));
        assert_eq!(
            owning_context(&p("m/26'/2'/1'/0'/3'"), it()),
            Some("tenant-a-child")
        );
        // The parent's allocator hands out `{parent}/0'`, which is the child's
        // *base*, and still the parent's key.
        assert_eq!(owning_context(&p("m/26'/2'/1'/0'"), it()), Some("tenant-a"));
        assert_eq!(
            owning_context(&p("m/26'/2'/10'/0'"), it()),
            Some("tenant-j")
        );
        assert_eq!(owning_context(&p("m/26'/0'/0'/0'"), it()), None);
    }

    /// VTI-KEY-032: a tenant cannot record another context's path, or a
    /// context-less (VTA) path, under its own context.
    #[test]
    fn vti_key_032_explicit_path_must_belong_to_the_requested_context() {
        let it = || CONTEXTS.iter().copied();
        assert!(check_explicit_key_path("m/26'/2'/1'/7'", Some("tenant-a"), it()).is_ok());
        for (path, ctx) in [
            ("m/26'/2'/0'/0'", Some("tenant-a")),    // the VTA context's key
            ("m/26'/0'/0'/0'", Some("tenant-a")),    // a context-less VTA path
            ("m/26'/2'/1'/0'/2'", Some("tenant-a")), // a child's key
            ("m/26'/2'/1'/7'", None),                // context-less record shadowing a context key
        ] {
            assert!(
                matches!(
                    check_explicit_key_path(path, ctx, it()),
                    Err(CustodyViolation::ForeignPath { .. })
                ),
                "{path} under {ctx:?} must be refused"
            );
        }
    }

    #[test]
    fn no_record_may_be_created_in_the_delegated_subtree() {
        for path in ["m/26'/9'", "m/26'/9'/0'"] {
            assert!(matches!(
                check_explicit_key_path(path, None, CONTEXTS.iter().copied()),
                Err(CustodyViolation::InsideDelegatedRoot { .. })
            ));
        }
    }

    #[test]
    fn delegated_signing_is_confined_to_its_subtree_and_hardened() {
        assert!(check_delegated_identity_path("m/26'/9'/0'").is_ok());
        assert!(check_delegated_identity_path("m/26'/9'/3'/1'").is_ok());
        for bad in [
            "m/26'/9'",
            "m/26'/2'/0'/0'",
            "m/26'/0'/0'/0'",
            "m/26'/9'/0",
            "nonsense",
        ] {
            assert!(check_delegated_identity_path(bad).is_err(), "{bad}");
        }
    }

    /// Rule 6: a record planted before these checks is refused at use.
    #[test]
    fn a_record_outside_its_context_is_refused_at_use() {
        let planted = record(Some("tenant-a"), "m/26'/0'/0'/0'");
        assert!(matches!(
            authorize_record_derivation(&planted, Some("m/26'/2'/1'")),
            Err(CustodyViolation::RecordOutsideContext { .. })
        ));
        let honest = record(Some("tenant-a"), "m/26'/2'/1'/4'");
        assert!(authorize_record_derivation(&honest, Some("m/26'/2'/1'")).is_ok());
        // Missing context fails closed.
        assert!(matches!(
            authorize_record_derivation(&honest, None),
            Err(CustodyViolation::RecordContextMissing { .. })
        ));
        // Context-less records are left to their (super-admin-only) callers.
        assert!(authorize_record_derivation(&record(None, "m/26'/0'/0'/0'"), None).is_ok());
    }

    /// Rule 7: a vault entry in `acme` may name a key in `acme` or below, never
    /// the VTA's context-less key, a sibling's, or a lookalike's.
    #[test]
    fn a_referenced_key_must_be_in_the_resources_subtree() {
        assert!(check_key_in_scope(&record(Some("acme"), "x"), "acme").is_ok());
        assert!(check_key_in_scope(&record(Some("acme/eng"), "x"), "acme").is_ok());
        for key_ctx in [None, Some("vta"), Some("acme-evil"), Some("other")] {
            assert!(
                matches!(
                    check_key_in_scope(&record(key_ctx, "x"), "acme"),
                    Err(CustodyViolation::KeyOutsideScope { .. })
                ),
                "{key_ctx:?}"
            );
        }
        // A child-scoped resource does not reach its parent's keys.
        assert!(check_key_in_scope(&record(Some("acme"), "x"), "acme/eng").is_err());
    }

    #[test]
    fn non_derived_records_are_refused() {
        let mut r = record(None, "internal");
        r.origin = KeyOrigin::Imported;
        assert!(matches!(
            authorize_record_derivation(&r, None),
            Err(CustodyViolation::NotDerived { .. })
        ));
    }
}
