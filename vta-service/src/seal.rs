//! VTA Seal — prevents offline CLI commands from modifying state.
//!
//! After the initial admin is bootstrapped, the VTA is "sealed". In sealed
//! mode, all CLI commands that modify ACL, keys, config, or export secrets
//! are refused. Management is only possible via authenticated REST/DIDComm.
//!
//! # Unseal requires proof of admin key ownership
//!
//! The `vta unseal` command uses an offline challenge-response protocol:
//! 1. VTA generates a random challenge and displays it
//! 2. Admin signs the challenge with their private key using `pnm` CLI
//! 3. Admin pastes the signature into the terminal
//! 4. VTA verifies the Ed25519 signature against the admin's public key
//!    (extracted from their DID in the ACL)
//!
//! This ensures an attacker with server access cannot unseal without
//! possessing the admin's private key.
//!
//! # Security Model
//!
//! - Without TEE: The seal is a deterrent. An attacker with deep knowledge
//!   of fjall internals could manipulate raw bytes, but the seal check runs
//!   before any command, and the challenge-response prevents casual bypass.
//!
//! - With TEE (encrypted storage): The seal marker is AES-256-GCM encrypted.
//!   An attacker cannot read or modify it without the storage key, which exists
//!   only inside the enclave. This makes the seal cryptographically enforced.

use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::acl::{self, Role};
use crate::config::StoreConfig;
use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};

const SEAL_KEY: &str = "vta:sealed";

/// Format a UTC `DateTime` as a readable local-timezone string with ISO offset.
fn format_local_datetime(dt: chrono::DateTime<Utc>) -> String {
    dt.with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

/// Marker written to fjall when the VTA is sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealRecord {
    /// DID of the admin who sealed the VTA.
    pub sealed_by: String,
    /// When the VTA was sealed.
    pub sealed_at: chrono::DateTime<Utc>,
    /// Human-readable reason.
    pub reason: String,
}

/// Check if the VTA is sealed. Returns the seal record if so.
pub async fn get_seal(acl_ks: &KeyspaceHandle) -> Result<Option<SealRecord>, AppError> {
    acl_ks.get(SEAL_KEY).await
}

/// Check if the VTA is sealed, and exit with an error if it is.
///
/// Call this at the top of any CLI command that modifies state.
pub async fn require_unsealed(store: &Store) -> Result<(), AppError> {
    let acl_ks = store.keyspace("acl")?;
    if let Some(seal) = get_seal(&acl_ks).await? {
        return Err(AppError::Config(format!(
            "VTA is sealed (by {} on {}). \
             Offline CLI commands are disabled. \
             Manage the VTA via the REST API or DIDComm.\n\
             \n\
             To unseal (requires super admin key): vta unseal",
            seal.sealed_by,
            format_local_datetime(seal.sealed_at),
        )));
    }
    Ok(())
}

/// Seal the VTA, preventing further offline CLI modifications.
pub async fn seal(acl_ks: &KeyspaceHandle, admin_did: &str) -> Result<SealRecord, AppError> {
    // Check not already sealed
    if let Some(existing) = get_seal(acl_ks).await? {
        return Err(AppError::Conflict(format!(
            "VTA is already sealed (by {} on {})",
            existing.sealed_by,
            format_local_datetime(existing.sealed_at),
        )));
    }

    let record = SealRecord {
        sealed_by: admin_did.to_string(),
        sealed_at: Utc::now(),
        reason: "bootstrap-admin completed".to_string(),
    };

    acl_ks.insert(SEAL_KEY, &record).await?;
    Ok(record)
}

/// Snapshot of what `read_unseal_state` pulls from the sealed store
/// before releasing the fjall lock.
#[derive(Debug)]
pub(crate) struct UnsealChallenge {
    pub seal: SealRecord,
    pub super_admins: Vec<acl::AclEntry>,
    pub challenge_bytes: [u8; 32],
}

/// Phase 1 of the unseal flow: open the store, read the seal record
/// and the super-admin list, mint a fresh 32-byte challenge, and
/// **drop the store before returning**. After this call the fjall
/// directory lock is released — a sibling `vta auth sign-challenge` (or
/// any other process) can open the same data dir while the operator is
/// pasting their signature.
pub(crate) async fn read_unseal_state(
    store_config: &StoreConfig,
) -> Result<UnsealChallenge, AppError> {
    let store = Store::open(store_config)?;
    let acl_ks = store.keyspace("acl")?;

    let seal = get_seal(&acl_ks)
        .await?
        .ok_or_else(|| AppError::Config("VTA is not sealed — nothing to unseal".into()))?;

    let entries = acl::list_acl_entries(&acl_ks).await?;
    let super_admins: Vec<acl::AclEntry> = entries
        .into_iter()
        .filter(|e| e.role == Role::Admin && e.allowed_contexts.is_empty())
        .collect();

    if super_admins.is_empty() {
        return Err(AppError::Config(
            "no super admin ACL entries found — cannot unseal".into(),
        ));
    }

    let mut challenge_bytes = [0u8; 32];
    rand::fill(&mut challenge_bytes);

    Ok(UnsealChallenge {
        seal,
        super_admins,
        challenge_bytes,
    })
    // `store` and `acl_ks` drop here — fjall lock released.
}

/// Phase 3 of the unseal flow: reopen the store, remove the seal
/// marker if it's still there, persist. Returns `Ok(true)` if the
/// seal was removed in this call, `Ok(false)` if it had already been
/// removed (e.g. by a concurrent process while the operator was
/// blocked on stdin).
pub(crate) async fn remove_seal_marker(store_config: &StoreConfig) -> Result<bool, AppError> {
    let store = Store::open(store_config)?;
    let acl_ks = store.keyspace("acl")?;
    if get_seal(&acl_ks).await?.is_none() {
        return Ok(false);
    }
    acl_ks.remove(SEAL_KEY).await?;
    store.persist().await?;
    Ok(true)
}

/// Run the interactive unseal challenge-response protocol.
///
/// 1. [`read_unseal_state`] — open store, read seal + super-admins,
///    generate a 32-byte challenge, drop store.
/// 2. Print the challenge and read the admin DID + signature on stdin.
///    **No fjall lock is held during this phase**, so a sibling
///    `vta auth sign-challenge` or `pnm auth sign-challenge` invocation
///    can open the same data dir to produce the signature.
/// 3. Verify the Ed25519 signature; [`remove_seal_marker`] then
///    reopens the store, removes the seal, and persists.
pub async fn run_unseal_challenge(store_config: &StoreConfig) -> Result<(), AppError> {
    let UnsealChallenge {
        seal,
        super_admins,
        challenge_bytes,
    } = read_unseal_state(store_config).await?;

    let challenge_hex = hex::encode(challenge_bytes);

    eprintln!();
    eprintln!("=== VTA Unseal Challenge ===");
    eprintln!();
    eprintln!("  Sealed by: {}", seal.sealed_by);
    eprintln!("  Sealed at: {}", format_local_datetime(seal.sealed_at));
    eprintln!();
    eprintln!("  Authorized super admin DIDs:");
    for admin in &super_admins {
        eprintln!(
            "    - {} ({})",
            admin.did,
            admin.label.as_deref().unwrap_or("no label")
        );
    }
    eprintln!();
    eprintln!("  Challenge (hex):");
    eprintln!("  {challenge_hex}");
    eprintln!();
    eprintln!("  Sign this challenge with your super admin key. Either:");
    eprintln!();
    eprintln!(
        "    pnm auth sign-challenge {challenge_hex}                      # online: \
         signs with PNM's stored admin key"
    );
    eprintln!(
        "    vta auth sign-challenge --did <admin-did> --challenge {challenge_hex}   \
         # offline: signs from this VTA's local keystore"
    );
    eprintln!();
    eprintln!("  Then paste the signature (hex) and your DID below.");
    eprintln!();

    // Read the admin DID.
    //
    // `std::io::stdin().read_line` blocks the current tokio worker. That's
    // intentional here — `run_unseal_challenge` is only ever called from the
    // `vta unseal` CLI subcommand, where the process is exclusively waiting
    // on operator input; there's no concurrent request load to starve. A
    // `tokio::io::stdin()` would pull in an extra async boundary for no real
    // benefit.
    eprint!("  Admin DID: ");
    let mut did_input = String::new();
    std::io::stdin()
        .read_line(&mut did_input)
        .map_err(|e| AppError::Internal(format!("failed to read input: {e}")))?;
    let admin_did = did_input.trim();

    // Verify the DID is a super admin (against the snapshot we read in phase 1).
    let admin_entry = super_admins
        .iter()
        .find(|e| e.did == admin_did)
        .ok_or_else(|| AppError::Forbidden(format!("DID is not a super admin: {admin_did}")))?;

    // Read the signature
    eprint!("  Signature (hex): ");
    let mut sig_input = String::new();
    std::io::stdin()
        .read_line(&mut sig_input)
        .map_err(|e| AppError::Internal(format!("failed to read input: {e}")))?;
    let sig_hex = sig_input.trim();

    // Verify the signature before we reacquire the lock.
    verify_challenge_signature(admin_did, &challenge_bytes, sig_hex)?;

    let removed = remove_seal_marker(store_config).await?;
    if !removed {
        eprintln!();
        eprintln!("  VTA was unsealed concurrently — nothing to do.");
        eprintln!();
        return Ok(());
    }

    info!(admin = %admin_did, "VTA unsealed via challenge-response");

    eprintln!();
    eprintln!("  VTA unsealed successfully.");
    eprintln!(
        "  Authenticated as: {} ({})",
        admin_did,
        admin_entry.label.as_deref().unwrap_or("no label")
    );
    eprintln!();
    eprintln!("  WARNING: Offline CLI commands are now re-enabled.");
    eprintln!("  Re-seal when done: vta bootstrap-admin --did {admin_did}");
    eprintln!();

    Ok(())
}

/// Verify an Ed25519 signature over a challenge using the public key
/// extracted from a did:key DID.
fn verify_challenge_signature(
    did: &str,
    challenge: &[u8; 32],
    signature_hex: &str,
) -> Result<(), AppError> {
    // Extract the multibase-encoded public key from the DID
    let multibase_key = if did.starts_with("did:key:") {
        did.strip_prefix("did:key:").unwrap()
    } else {
        return Err(AppError::Validation(format!(
            "unseal challenge-response only supports did:key DIDs (got: {did}). \
             For other DID methods, unseal via the REST API with a running VTA."
        )));
    };

    // Decode the multibase public key
    let (_, key_bytes) = multibase::decode(multibase_key)
        .map_err(|e| AppError::Validation(format!("invalid multibase in DID: {e}")))?;

    // Strip the multicodec prefix (0xed 0x01 for Ed25519)
    if key_bytes.len() < 2 || key_bytes[0] != 0xed || key_bytes[1] != 0x01 {
        return Err(AppError::Validation(
            "DID public key is not Ed25519 (expected multicodec prefix 0xed01)".into(),
        ));
    }
    let raw_pubkey = &key_bytes[2..];
    if raw_pubkey.len() != 32 {
        return Err(AppError::Validation(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            raw_pubkey.len()
        )));
    }

    let pubkey_bytes: [u8; 32] = raw_pubkey.try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| AppError::Validation(format!("invalid Ed25519 public key: {e}")))?;

    // Decode the signature
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| AppError::Validation(format!("invalid signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(AppError::Validation(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| AppError::Validation(format!("invalid Ed25519 signature: {e}")))?;

    // Verify
    verifying_key.verify(challenge, &signature).map_err(|_| {
        AppError::Forbidden(
            "signature verification failed — challenge was not signed by this DID's private key"
                .into(),
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::AclEntry;

    /// Seal a fresh store under `data_dir` with a single super-admin
    /// ACL entry. The store is opened, populated, and dropped — the
    /// fjall lock is released before this helper returns.
    async fn seal_fresh_store(data_dir: &std::path::Path, admin_did: &str) {
        let config = StoreConfig {
            data_dir: data_dir.to_path_buf(),
        };
        let store = Store::open(&config).expect("open store");
        let acl_ks = store.keyspace("acl").expect("acl keyspace");

        let entry = AclEntry::new(admin_did, Role::Admin, "test")
            .with_label(Some("test-super-admin".into()));
        acl::store_acl_entry(&acl_ks, &entry).await.expect("acl");
        seal(&acl_ks, admin_did).await.expect("seal");
        store.persist().await.expect("persist");
    }

    /// Regression: `read_unseal_state` MUST drop the fjall handle
    /// before returning. The bug it fixes was that
    /// `run_unseal_challenge` kept the store open across the stdin
    /// wait, so `vta auth sign-challenge` (which opens the same data
    /// dir to sign the challenge) failed with `FjallError: Locked`.
    ///
    /// If this test ever starts failing with a fjall lock error on
    /// the second `Store::open`, someone has reintroduced the bug.
    #[tokio::test]
    async fn read_unseal_state_releases_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        seal_fresh_store(dir.path(), "did:key:zTestAdmin").await;

        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };

        // Phase 1: must return without holding the lock.
        let challenge = read_unseal_state(&config).await.expect("read_unseal_state");

        assert_eq!(challenge.seal.sealed_by, "did:key:zTestAdmin");
        assert_eq!(challenge.super_admins.len(), 1);
        assert_eq!(challenge.challenge_bytes.len(), 32);

        // A sibling opener — mimicking `vta auth sign-challenge` — must
        // be able to acquire the lock now. If `read_unseal_state` ever
        // regresses to holding the store across the stdin wait, this
        // open fails with `FjallError: Locked`.
        let _sibling = Store::open(&config).expect(
            "sibling Store::open after read_unseal_state must succeed — \
             the fjall lock from phase 1 should have been released on drop",
        );
    }

    /// `remove_seal_marker` removes the seal on first call, then is
    /// idempotent (returns Ok(false) — useful for the "concurrent
    /// unseal" race in the interactive flow).
    #[tokio::test]
    async fn remove_seal_marker_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        seal_fresh_store(dir.path(), "did:key:zTestAdmin").await;

        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };

        let first = remove_seal_marker(&config).await.expect("first call");
        assert!(first, "first call should report seal removed");

        let second = remove_seal_marker(&config).await.expect("second call");
        assert!(
            !second,
            "second call should report no-op (seal already gone)"
        );

        // Store reopens fine afterwards — lock released.
        let _after = Store::open(&config).expect("reopen after remove");
    }

    /// Phase 1 fails cleanly when the VTA isn't sealed (no marker row).
    #[tokio::test]
    async fn read_unseal_state_rejects_unsealed_vta() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        // Open + drop to create the data dir but don't seal.
        {
            let store = Store::open(&config).expect("open");
            store.persist().await.expect("persist");
        }

        let err = read_unseal_state(&config)
            .await
            .expect_err("must reject unsealed VTA");
        assert!(matches!(err, AppError::Config(_)), "got {err:?}");
    }

    /// Phase 1 fails cleanly when sealed but no super-admin exists
    /// (should not happen in practice — seal always follows admin
    /// seeding — but the guard is worth keeping fenced).
    #[tokio::test]
    async fn read_unseal_state_rejects_missing_super_admin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        {
            let store = Store::open(&config).expect("open");
            let acl_ks = store.keyspace("acl").expect("acl");
            // Seal directly without seeding a super-admin.
            seal(&acl_ks, "did:key:zPhantom").await.expect("seal");
            store.persist().await.expect("persist");
        }

        let err = read_unseal_state(&config)
            .await
            .expect_err("must reject missing super-admin");
        assert!(matches!(err, AppError::Config(_)), "got {err:?}");
    }
}
