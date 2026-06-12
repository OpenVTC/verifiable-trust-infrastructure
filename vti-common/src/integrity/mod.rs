//! TEE integrity manifest (P0.2a — Layer 0 of the anti-rollback anchor).
//!
//! In the Nitro-Enclave deployment the parent EC2 host owns the on-disk fjall
//! database and can delete or replay whole ciphertexts. KMS attestation gives
//! confidentiality and P0.1 AAD gives location-integrity, but neither gives
//! **freshness**: a covered row deleted, or the store replayed to an
//! inconsistent past snapshot, is not detected. This module pins the
//! security-critical singletons into a single MAC'd record so deletion and
//! inconsistent tamper are caught at boot.
//!
//! Layer 0 alone does **not** catch a fully-consistent rollback (manifest and
//! all covered rows restored together to a genuine past epoch) — that needs the
//! external monotonic counter (P0.2b). See
//! `docs/05-design-notes/tee-anti-rollback-anchor.md`.
//!
//! ## Activation
//!
//! The manifest is **TEE-only**. It is activated solely by [`install_sealer`],
//! which the boot path calls only when a storage-encryption key is present
//! (i.e. in a TEE). Outside a TEE the global sealer is never set, so
//! [`reseal_if_active`] — invoked from the covered mutation chokepoints
//! ([`crate::acl::store_acl_entry`] et al.) — is a cheap no-op. No feature flag
//! is needed; the module compiles everywhere and simply lies dormant.
//!
//! ## Covered singletons (design §5.1)
//!
//! | Singleton | Location | Rollback it blocks |
//! |---|---|---|
//! | Carve-out sentinel | `keys` ▸ [`CARVEOUT_KEY`] | reopen single-use Mode-B carve-out → fresh admin |
//! | JWT fingerprint | `bootstrap` ▸ [`JWT_FINGERPRINT_KEY`] | delete → silent JWT re-baseline |
//! | ACL keyspace root | `acl` ▸ `acl:*` | replay → resurrect a revoked admin |
//! | Path/context counters | `keys` ▸ `path_counter:*`, `contexts` ▸ `ctx_counter*` | rollback → BIP-32 key reuse |

use std::sync::OnceLock;

use hkdf::Hkdf;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::warn;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

type HmacSha256 = Hmac<Sha256>;

/// Carve-out sentinel key (lives in the `keys` keyspace). Must match
/// `vta_service::tee::admin_bootstrap::BOOTSTRAP_CARVEOUT_CLOSED_KEY`; a
/// drift-guard test in vta-service asserts the two stay equal.
pub const CARVEOUT_KEY: &str = "tee:bootstrap-carveout-closed";
/// JWT-fingerprint key (lives in the `bootstrap` keyspace). Must match
/// `vta_service::tee::kms_bootstrap::BOOTSTRAP_JWT_FINGERPRINT_KEY`.
pub const JWT_FINGERPRINT_KEY: &str = "bootstrap:jwt_fingerprint";
/// Manifest record key (lives in the `bootstrap` keyspace).
pub const MANIFEST_KEY: &str = "tee:integrity-manifest";

const ACL_PREFIX: &str = "acl:";
const PATH_COUNTER_PREFIX: &str = "path_counter:";
const CTX_COUNTER_PREFIX: &str = "ctx_counter";

/// HKDF `info` separating the manifest MAC key from the storage-encryption key
/// it is derived from.
const MAC_KEY_INFO: &[u8] = b"vti-integrity-manifest-mac/v1";
/// Domain tag prefixing the MAC input so a manifest blob can't be reinterpreted
/// in another context.
const MAC_DOMAIN: &[u8] = b"vti-integrity-manifest/v1";

/// Serialized manifest length: version(8) + carveout(1) + jwt_fp(16) +
/// acl_root(32) + counters(32) + mac(32).
const MANIFEST_LEN: usize = 8 + 1 + 16 + 32 + 32 + 32;

/// The hashed snapshot of the four covered singletons.
#[derive(Clone, PartialEq, Eq, Debug)]
struct CoveredState {
    carveout_present: bool,
    jwt_fp: [u8; 16],
    acl_root: [u8; 32],
    counters: [u8; 32],
}

impl CoveredState {
    /// Canonical MAC input: domain tag ‖ version ‖ fixed-width fields.
    fn mac_input(&self, version: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MAC_DOMAIN.len() + 8 + 1 + 16 + 32 + 32);
        buf.extend_from_slice(MAC_DOMAIN);
        buf.extend_from_slice(&version.to_le_bytes());
        buf.push(self.carveout_present as u8);
        buf.extend_from_slice(&self.jwt_fp);
        buf.extend_from_slice(&self.acl_root);
        buf.extend_from_slice(&self.counters);
        buf
    }
}

/// A loaded-or-recomputed manifest. The `mac` authenticates `version` + state.
struct Manifest {
    version: u64,
    state: CoveredState,
    mac: [u8; 32],
}

impl Manifest {
    /// Build a manifest for `state` at `version`, computing its MAC.
    fn sealed(mac_key: &[u8; 32], version: u64, state: CoveredState) -> Self {
        let mac = mac_over(mac_key, &state.mac_input(version));
        Self {
            version,
            state,
            mac,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MANIFEST_LEN);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.push(self.state.carveout_present as u8);
        buf.extend_from_slice(&self.state.jwt_fp);
        buf.extend_from_slice(&self.state.acl_root);
        buf.extend_from_slice(&self.state.counters);
        buf.extend_from_slice(&self.mac);
        buf
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != MANIFEST_LEN {
            return None;
        }
        let version = u64::from_le_bytes(b[0..8].try_into().ok()?);
        let carveout_present = match b[8] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let jwt_fp: [u8; 16] = b[9..25].try_into().ok()?;
        let acl_root: [u8; 32] = b[25..57].try_into().ok()?;
        let counters: [u8; 32] = b[57..89].try_into().ok()?;
        let mac: [u8; 32] = b[89..121].try_into().ok()?;
        Some(Self {
            version,
            state: CoveredState {
                carveout_present,
                jwt_fp,
                acl_root,
                counters,
            },
            mac,
        })
    }

    /// Constant-time MAC check against `mac_key`.
    fn mac_valid(&self, mac_key: &[u8; 32]) -> bool {
        let mut h = HmacSha256::new_from_slice(mac_key).expect("hmac accepts 32-byte key");
        h.update(&self.state.mac_input(self.version));
        h.verify_slice(&self.mac).is_ok()
    }
}

fn mac_over(mac_key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new_from_slice(mac_key).expect("hmac accepts 32-byte key");
    h.update(input);
    h.finalize().into_bytes().into()
}

/// Derive the manifest MAC key from the TEE storage-encryption key. Domain-
/// separated so it never coincides with the key's encryption use.
pub fn derive_mac_key(storage_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, storage_key);
    let mut out = [0u8; 32];
    hk.expand(MAC_KEY_INFO, &mut out)
        .expect("32-byte HKDF output is valid");
    out
}

/// Hash a set of key/value rows canonically (sorted by key, length-prefixed),
/// so the digest is independent of iteration order.
fn hash_rows(mut rows: Vec<(Vec<u8>, Vec<u8>)>) -> [u8; 32] {
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (k, v) in rows {
        hasher.update((k.len() as u32).to_le_bytes());
        hasher.update(&k);
        hasher.update((v.len() as u32).to_le_bytes());
        hasher.update(&v);
    }
    hasher.finalize().into()
}

/// The installed sealer. Holds the MAC key and clones of every keyspace the
/// covered singletons live in. Set once at TEE boot via [`install_sealer`].
struct ManifestSealer {
    mac_key: [u8; 32],
    /// carve-out sentinel + `path_counter:*`
    keys_ks: KeyspaceHandle,
    /// JWT fingerprint + the manifest record itself
    bootstrap_ks: KeyspaceHandle,
    /// `acl:*`
    acl_ks: KeyspaceHandle,
    /// `ctx_counter*`
    contexts_ks: KeyspaceHandle,
}

impl ManifestSealer {
    async fn compute_state(&self) -> Result<CoveredState, AppError> {
        let carveout_present = self.keys_ks.get_raw(CARVEOUT_KEY).await?.is_some();

        let jwt_fp = match self.bootstrap_ks.get_raw(JWT_FINGERPRINT_KEY).await? {
            Some(bytes) => {
                let digest = Sha256::digest(&bytes);
                let mut fp = [0u8; 16];
                fp.copy_from_slice(&digest[..16]);
                fp
            }
            None => [0u8; 16],
        };

        let acl_root = hash_rows(self.acl_ks.prefix_iter_raw(ACL_PREFIX).await?);

        // Counters span two keyspaces; tag each row's key with a keyspace
        // discriminant so a `path_counter:x` can never collide with a
        // hypothetical `ctx_counter:x` in the combined digest.
        let mut counter_rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for (k, v) in self.keys_ks.prefix_iter_raw(PATH_COUNTER_PREFIX).await? {
            let mut tagged = b"k:".to_vec();
            tagged.extend_from_slice(&k);
            counter_rows.push((tagged, v));
        }
        for (k, v) in self.contexts_ks.prefix_iter_raw(CTX_COUNTER_PREFIX).await? {
            let mut tagged = b"c:".to_vec();
            tagged.extend_from_slice(&k);
            counter_rows.push((tagged, v));
        }
        let counters = hash_rows(counter_rows);

        Ok(CoveredState {
            carveout_present,
            jwt_fp,
            acl_root,
            counters,
        })
    }

    async fn load_manifest(&self) -> Result<Option<Manifest>, AppError> {
        Ok(self
            .bootstrap_ks
            .get_raw(MANIFEST_KEY)
            .await?
            .and_then(|b| Manifest::from_bytes(&b)))
    }

    async fn write_manifest(&self, m: &Manifest) -> Result<(), AppError> {
        self.bootstrap_ks
            .insert_raw(MANIFEST_KEY, m.to_bytes())
            .await?;
        self.bootstrap_ks.persist().await?;
        Ok(())
    }

    /// Boot check core (no global side effect, so it is unit-testable). See
    /// [`boot_verify_and_install`] for semantics.
    async fn verify_or_baseline(&self, allow_anchor_init: bool) -> Result<BootOutcome, AppError> {
        let current = self.compute_state().await?;
        match self.load_manifest().await? {
            None => {
                if !allow_anchor_init {
                    return Err(AppError::Internal(
                        "TEE integrity manifest is missing and allow_anchor_init is false — \
                         refusing to start. A missing manifest on a configured VTA is \
                         indistinguishable from a parent-deleted one; set \
                         tee.kms.allow_anchor_init = true for ONE boot to establish the \
                         baseline, then set it back to false."
                            .into(),
                    ));
                }
                self.write_manifest(&Manifest::sealed(&self.mac_key, 0, current))
                    .await?;
                warn!(
                    "TEE integrity manifest established (version 0) under allow_anchor_init — \
                     set tee.kms.allow_anchor_init = false now that the baseline exists"
                );
                Ok(BootOutcome::Baselined)
            }
            Some(stored) => {
                if !stored.mac_valid(&self.mac_key) {
                    return Err(AppError::Internal(
                        "TEE integrity manifest MAC verification failed — the manifest was \
                         tampered with or the storage key changed. Refusing to start (P0.2). \
                         Restore a consistent backup or investigate parent-host compromise."
                            .into(),
                    ));
                }
                if stored.state != current {
                    return Err(AppError::Internal(format!(
                        "TEE integrity manifest mismatch — the on-disk state does not match the \
                         last sealed manifest (a covered singleton was deleted or the store was \
                         replayed to an inconsistent snapshot). Refusing to start (P0.2). [{}]",
                        describe_mismatch(&stored.state, &current),
                    )));
                }
                Ok(BootOutcome::Verified)
            }
        }
    }
}

/// Process-global sealer + a lock serializing reseals so concurrent mutations
/// can't lose a manifest update or skip a version.
static SEALER: OnceLock<ManifestSealer> = OnceLock::new();
static RESEAL_LOCK: Mutex<()> = Mutex::const_new(());

/// Re-seal the manifest after a covered-singleton mutation. **No-op unless a
/// sealer is installed** (i.e. always, outside a TEE). Recomputes the covered
/// state from the live store, bumps the version, re-MACs, and persists.
///
/// Called from the covered mutation chokepoints. The cost (a few prefix scans +
/// one HMAC) is paid only in TEE and only on tightening ops, which are
/// infrequent.
pub async fn reseal_if_active() -> Result<(), AppError> {
    let Some(sealer) = SEALER.get() else {
        return Ok(());
    };
    let _guard = RESEAL_LOCK.lock().await;
    let next_version = sealer
        .load_manifest()
        .await?
        .map(|m| m.version + 1)
        .unwrap_or(0);
    let state = sealer.compute_state().await?;
    let manifest = Manifest::sealed(&sealer.mac_key, next_version, state);
    sealer.write_manifest(&manifest).await
}

/// Outcome of the boot check, for logging.
#[derive(Debug, PartialEq, Eq)]
pub enum BootOutcome {
    /// A valid manifest matched the live store.
    Verified,
    /// No manifest existed; a baseline was established (first boot /
    /// `allow_anchor_init`).
    Baselined,
}

/// Verify the integrity manifest against the live store and install the sealer
/// for runtime reseals. Call exactly once at TEE boot, before serving.
///
/// - **No manifest present:** with `allow_anchor_init` true, establish a
///   version-0 baseline over the current state (first boot / migration);
///   otherwise **fail closed** — a silent baseline would accept whatever
///   (possibly rolled-back) state the parent presents.
/// - **Manifest present:** verify its MAC, then recompute the covered state and
///   compare. A MAC failure (forged/tampered manifest) or a state mismatch
///   (a covered row deleted, or an inconsistent snapshot) **fails closed**.
///
/// On success the sealer is installed so subsequent covered mutations reseal.
pub async fn boot_verify_and_install(
    mac_key: [u8; 32],
    keys_ks: KeyspaceHandle,
    bootstrap_ks: KeyspaceHandle,
    acl_ks: KeyspaceHandle,
    contexts_ks: KeyspaceHandle,
    allow_anchor_init: bool,
) -> Result<BootOutcome, AppError> {
    let sealer = ManifestSealer {
        mac_key,
        keys_ks,
        bootstrap_ks,
        acl_ks,
        contexts_ks,
    };
    let outcome = sealer.verify_or_baseline(allow_anchor_init).await?;
    // Install for runtime reseals (only fails if called twice — boot calls once).
    let _ = SEALER.set(sealer);
    Ok(outcome)
}

/// Human-readable diff of which covered component(s) diverged, for the
/// fail-closed boot error. Never includes secret material — only which field.
fn describe_mismatch(stored: &CoveredState, current: &CoveredState) -> String {
    let mut parts = Vec::new();
    if stored.carveout_present != current.carveout_present {
        parts.push(format!(
            "carve-out sentinel (sealed present={}, now present={})",
            stored.carveout_present, current.carveout_present
        ));
    }
    if stored.jwt_fp != current.jwt_fp {
        parts.push("JWT fingerprint".into());
    }
    if stored.acl_root != current.acl_root {
        parts.push("ACL root".into());
    }
    if stored.counters != current.counters {
        parts.push("path/context counters".into());
    }
    if parts.is_empty() {
        "no field differs (internal error)".into()
    } else {
        parts.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    struct Ks {
        keys: KeyspaceHandle,
        bootstrap: KeyspaceHandle,
        acl: KeyspaceHandle,
        contexts: KeyspaceHandle,
        _dir: tempfile::TempDir,
    }

    fn open() -> Ks {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        Ks {
            keys: store.keyspace("keys").unwrap(),
            bootstrap: store.keyspace("bootstrap").unwrap(),
            acl: store.keyspace("acl").unwrap(),
            contexts: store.keyspace("contexts").unwrap(),
            _dir: dir,
        }
    }

    fn sealer(ks: &Ks, mac_key: [u8; 32]) -> ManifestSealer {
        ManifestSealer {
            mac_key,
            keys_ks: ks.keys.clone(),
            bootstrap_ks: ks.bootstrap.clone(),
            acl_ks: ks.acl.clone(),
            contexts_ks: ks.contexts.clone(),
        }
    }

    #[test]
    fn manifest_bytes_round_trip() {
        let mac_key = [3u8; 32];
        let state = CoveredState {
            carveout_present: true,
            jwt_fp: [7u8; 16],
            acl_root: [9u8; 32],
            counters: [11u8; 32],
        };
        let m = Manifest::sealed(&mac_key, 5, state.clone());
        let bytes = m.to_bytes();
        assert_eq!(bytes.len(), MANIFEST_LEN);
        let back = Manifest::from_bytes(&bytes).expect("round trip");
        assert_eq!(back.version, 5);
        assert_eq!(back.state, state);
        assert!(back.mac_valid(&mac_key));
        // Wrong key fails the MAC.
        assert!(!back.mac_valid(&[4u8; 32]));
    }

    #[test]
    fn tampering_any_field_breaks_the_mac() {
        let mac_key = [1u8; 32];
        let state = CoveredState {
            carveout_present: true,
            jwt_fp: [0u8; 16],
            acl_root: [0u8; 32],
            counters: [0u8; 32],
        };
        let m = Manifest::sealed(&mac_key, 1, state);
        let mut bytes = m.to_bytes();
        bytes[8] ^= 1; // flip carveout_present
        let tampered = Manifest::from_bytes(&bytes).expect("decodes");
        assert!(!tampered.mac_valid(&mac_key));
    }

    // NOTE: these tests drive the global-free `verify_or_baseline` (and direct
    // sealer methods) rather than `boot_verify_and_install`, so they never set
    // the process-global SEALER — keeping `reseal_if_active_is_noop` valid
    // regardless of test order.

    #[tokio::test]
    async fn baseline_refused_without_allow_anchor_init() {
        let ks = open();
        let err = sealer(&ks, [2u8; 32])
            .verify_or_baseline(false)
            .await
            .expect_err("missing manifest + flag false must fail closed");
        assert!(format!("{err:?}").contains("allow_anchor_init"), "{err:?}");
    }

    #[tokio::test]
    async fn baseline_then_verify_roundtrips() {
        let ks = open();
        let mac_key = [5u8; 32];
        // Seed some covered state across keyspaces.
        ks.keys
            .insert_raw(CARVEOUT_KEY, b"closed".to_vec())
            .await
            .unwrap();
        crate::store::counter::allocate_u32(&ks.keys, "path_counter:m/26'/0'")
            .await
            .unwrap();
        crate::store::counter::allocate_u32(&ks.contexts, "ctx_counter")
            .await
            .unwrap();
        let s = sealer(&ks, mac_key);

        // First boot establishes the baseline.
        assert_eq!(
            s.verify_or_baseline(true).await.unwrap(),
            BootOutcome::Baselined
        );
        // A second boot against the unchanged store verifies cleanly.
        assert_eq!(
            s.verify_or_baseline(false).await.unwrap(),
            BootOutcome::Verified
        );
    }

    #[tokio::test]
    async fn deleting_a_covered_row_is_detected_at_boot() {
        let ks = open();
        let mac_key = [6u8; 32];
        let s = sealer(&ks, mac_key);

        // Baseline with the carve-out sentinel present.
        ks.keys
            .insert_raw(CARVEOUT_KEY, b"closed".to_vec())
            .await
            .unwrap();
        s.verify_or_baseline(true).await.unwrap();

        // Parent deletes the sentinel (reopen the carve-out) while down.
        ks.keys.remove(CARVEOUT_KEY).await.unwrap();

        let err = s
            .verify_or_baseline(false)
            .await
            .expect_err("deletion must be detected");
        assert!(format!("{err:?}").contains("carve-out"), "{err:?}");
        assert!(format!("{err:?}").contains("mismatch"), "{err:?}");
    }

    #[tokio::test]
    async fn forged_manifest_fails_mac_at_boot() {
        let ks = open();
        let mac_key = [8u8; 32];
        let s = sealer(&ks, mac_key);
        s.verify_or_baseline(true).await.unwrap();

        // Parent overwrites the manifest with a self-consistent one under a
        // DIFFERENT key (it can't forge our MAC key).
        let forged = Manifest::sealed(
            &[0xFFu8; 32],
            99,
            CoveredState {
                carveout_present: false,
                jwt_fp: [0u8; 16],
                acl_root: [0u8; 32],
                counters: [0u8; 32],
            },
        );
        ks.bootstrap
            .insert_raw(MANIFEST_KEY, forged.to_bytes())
            .await
            .unwrap();

        let err = s
            .verify_or_baseline(false)
            .await
            .expect_err("forged manifest must fail the MAC");
        assert!(
            format!("{err:?}").contains("MAC verification failed"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn acl_change_reflected_after_reseal() {
        // A legitimate ACL change followed by a reseal must verify on the next
        // boot (i.e. reseal keeps the manifest in step with covered mutations).
        let ks = open();
        let mac_key = [10u8; 32];
        let s = sealer(&ks, mac_key);
        s.verify_or_baseline(true).await.unwrap();

        // Legitimate ACL write + reseal (simulating the chokepoint).
        ks.acl
            .insert_raw("acl:did:key:zAlice", b"{}".to_vec())
            .await
            .unwrap();
        let next = s
            .load_manifest()
            .await
            .unwrap()
            .map(|m| m.version + 1)
            .unwrap();
        let state = s.compute_state().await.unwrap();
        s.write_manifest(&Manifest::sealed(&mac_key, next, state))
            .await
            .unwrap();

        assert_eq!(
            s.verify_or_baseline(false).await.unwrap(),
            BootOutcome::Verified,
            "post-reseal state must verify"
        );
    }

    #[tokio::test]
    async fn reseal_if_active_is_noop_without_installed_sealer() {
        // No sealer installed (non-TEE) → reseal is a cheap no-op, never errors.
        reseal_if_active().await.expect("no-op when not installed");
    }
}
