use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::error::AppError;
use crate::keys::imported;
use crate::keys::seed_store::SeedStore;
use crate::store::KeyspaceHandle;

const ACTIVE_SEED_ID_KEY: &str = "active_seed_id";
const NONCE_LEN: usize = 12;
/// HKDF `info` for the retired-seed-archive KEK. Distinct from the
/// imported-secret KEK info (`vta-imported-secret-encryption`) so the two
/// share the same per-VTA salt without ever colliding on a key (P0.7b).
const ARCHIVE_KEK_INFO: &[u8] = b"vta-retired-seed-archive";

/// Metadata record for a BIP-32 master seed generation.
///
/// The active generation carries neither ciphertext — its bytes live in the
/// external secure store (keyring, AWS, GCP, …). Retired generations are
/// archived into fjall so keys minted under an old generation stay
/// recoverable.
///
/// Archived bytes are **always ciphertext** (`seed_enc`), encrypted under a
/// KEK derived from the *current active* master seed (P0.7b), so a retired
/// master seed is never at rest in clear — independent of whether keyspace
/// encryption is configured. `seed_hex` is the pre-P0.7b plaintext form: still
/// read for backward compatibility and migrated to `seed_enc` by
/// [`reconcile_archive`], but never written anew.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedRecord {
    pub id: u32,
    /// Legacy plaintext archive (`Some(hex)` on pre-P0.7b records). Read-only:
    /// [`reconcile_archive`] migrates these into `seed_enc` and clears them.
    #[serde(default)]
    pub seed_hex: Option<String>,
    /// Encrypted archive: `nonce ‖ AES-256-GCM(KEK(active_seed), seed_bytes)`,
    /// AAD-bound to the generation id. `None` for the active generation.
    #[serde(default)]
    pub seed_enc: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

fn store_seed_key(id: u32) -> String {
    format!("seed:{id}")
}

/// Derive the retired-seed-archive KEK from the active master seed + salt.
fn derive_archive_kek(active_seed: &[u8], salt: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), active_seed);
    let mut kek = [0u8; 32];
    hkdf.expand(ARCHIVE_KEK_INFO, &mut kek)
        .expect("32-byte output is valid for HKDF-SHA256");
    kek
}

/// AAD binding a ciphertext to the generation it archives, so a blob can't be
/// replayed under a different seed id.
fn archive_aad(seed_id: u32) -> Vec<u8> {
    format!("seed:{seed_id}").into_bytes()
}

/// Encrypt retired generation `seed_id`'s bytes under a KEK derived from
/// `active_seed`. Returns `nonce ‖ ciphertext`.
fn encrypt_archived_seed(
    active_seed: &[u8],
    salt: &[u8],
    seed_id: u32,
    seed_bytes: &[u8],
) -> Result<Vec<u8>, AppError> {
    let mut kek = derive_archive_kek(active_seed, salt);
    let cipher = Aes256Gcm::new_from_slice(&kek)
        .map_err(|e| AppError::Internal(format!("archive aes key: {e}")))?;

    use aes_gcm::aead::rand_core::RngCore;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    aes_gcm::aead::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = archive_aad(seed_id);
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: seed_bytes,
                aad: &aad,
            },
        )
        .map_err(|e| AppError::Internal(format!("encrypt archived seed: {e}")))?;
    kek.zeroize();

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt an archived-seed blob (`nonce ‖ ciphertext`) under a KEK derived
/// from `active_seed`. Returns `None` on any AEAD failure (wrong KEK / AAD /
/// corruption) so callers can tell "stale archive" apart from a hard error.
fn decrypt_archived_seed(
    active_seed: &[u8],
    salt: &[u8],
    seed_id: u32,
    blob: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN + 1 {
        return None;
    }
    let mut kek = derive_archive_kek(active_seed, salt);
    let cipher = Aes256Gcm::new_from_slice(&kek).ok()?;
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let aad = archive_aad(seed_id);
    let pt = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &blob[NONCE_LEN..],
                aad: &aad,
            },
        )
        .ok()
        .map(Zeroizing::new);
    kek.zeroize();
    pt
}

/// Get the active seed generation ID.  Defaults to 0 if not yet set.
pub async fn get_active_seed_id(
    keys_ks: &KeyspaceHandle,
) -> Result<u32, Box<dyn std::error::Error>> {
    match keys_ks.get_raw(ACTIVE_SEED_ID_KEY).await? {
        Some(bytes) => {
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| "active_seed_id is not 4 bytes")?;
            Ok(u32::from_le_bytes(arr))
        }
        None => Ok(0),
    }
}

/// Set the active seed generation ID.
pub async fn set_active_seed_id(
    keys_ks: &KeyspaceHandle,
    id: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    keys_ks
        .insert_raw(ACTIVE_SEED_ID_KEY, id.to_le_bytes().to_vec())
        .await?;
    Ok(())
}

/// Retrieve a seed record by generation ID.
pub async fn get_seed_record(
    keys_ks: &KeyspaceHandle,
    id: u32,
) -> Result<Option<SeedRecord>, Box<dyn std::error::Error>> {
    Ok(keys_ks.get(store_seed_key(id)).await?)
}

/// Persist a seed record.
pub async fn save_seed_record(
    keys_ks: &KeyspaceHandle,
    record: &SeedRecord,
) -> Result<(), Box<dyn std::error::Error>> {
    keys_ks.insert(store_seed_key(record.id), record).await?;
    Ok(())
}

/// List all seed records (prefix scan on `seed:`).
pub async fn list_seed_records(
    keys_ks: &KeyspaceHandle,
) -> Result<Vec<SeedRecord>, Box<dyn std::error::Error>> {
    let raw = keys_ks.prefix_iter_raw("seed:").await?;
    let mut records = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: SeedRecord = serde_json::from_slice(&value)?;
        records.push(record);
    }
    records.sort_by_key(|r| r.id);
    Ok(records)
}

/// Load the BIP-32 master seed for a given generation.
///
/// Resolution (P0.7b — archives are encrypted, see [`SeedRecord`]):
/// - No record for `seed_id` (default 0), or a record with no archive → the
///   generation is active / pre-rotation: load from the external store.
/// - Record with `seed_enc` → retired: decrypt under the **current active
///   seed**'s KEK. On AEAD failure the archive is stale from an interrupted
///   rotation; if the requested generation *is* the active one the external
///   store is authoritative (a seed-swap torn-write window), otherwise we
///   refuse with a reconcile hint rather than return wrong key material.
/// - Record with only legacy `seed_hex` → pre-P0.7b plaintext, still decoded
///   (it is migrated to `seed_enc` by [`reconcile_archive`] at boot).
///
/// Returns the seed wrapped in [`Zeroizing`] so it is wiped on drop (P0.7).
/// Callers use it via `&seed` (deref-coerces to `&[u8]`), so no call site
/// changes.
pub async fn load_seed_bytes(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    seed_id: Option<u32>,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let effective_id = seed_id.unwrap_or(0);

    let external = || async {
        seed_store
            .get()
            .await
            .map_err(|e| format!("{e}"))?
            .ok_or_else(|| "no seed found in external store".into())
            .map(Zeroizing::new)
    };

    let Some(record) = get_seed_record(keys_ks, effective_id).await? else {
        // Pre-rotation: no record yet, seed is in the external store.
        return external().await;
    };

    if let Some(ref blob) = record.seed_enc {
        let active_seed = external().await?;
        let salt = imported::get_or_create_salt(keys_ks).await?;
        if let Some(pt) = decrypt_archived_seed(&active_seed, &salt, effective_id, blob) {
            return Ok(pt);
        }
        // Decrypt failed — the archive is encrypted under some other generation.
        // Only legitimate transiently: during a rotation the just-retired record
        // is written under the new KEK before the external store flips to it, so
        // for the *active* generation the external store still holds the answer.
        let active_id = get_active_seed_id(keys_ks).await?;
        if effective_id == active_id {
            return Ok(active_seed);
        }
        return Err(format!(
            "retired seed generation {effective_id} could not be decrypted — its \
             archive is stale (an interrupted seed rotation?). Restart the VTA to \
             reconcile the seed archive, then retry."
        )
        .into());
    }

    if let Some(ref hex_str) = record.seed_hex {
        // Legacy plaintext archive (pre-P0.7b, or not yet reconciled this boot).
        return Ok(Zeroizing::new(hex::decode(hex_str)?));
    }

    // Record exists but carries no archive → active generation.
    external().await
}

/// Rotate to a new seed generation.
///
/// The retired generation is archived as **ciphertext** (P0.7b) under a KEK
/// derived from the incoming seed, and every older archive is re-encrypted to
/// the same KEK, so the whole archive stays decryptable from the current
/// active seed alone. The step order is chosen so that a crash at any point
/// leaves every generation recoverable (see the inline window notes); an
/// interrupted run is repaired by [`reconcile_archive`] at the next boot.
///
/// Returns the new generation ID.
pub async fn rotate_seed(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    mnemonic: Option<&str>,
) -> Result<u32, Box<dyn std::error::Error>> {
    // Authoritative guard: a backend whose `set` does not survive a
    // restart (the TEE KMS store) would have its rotated seed silently
    // discarded on the next boot, making every post-rotation key
    // unrecoverable. Refuse before mutating any state. The runtime
    // entry point (`operations::seeds::rotate_seed`) checks this too
    // and returns a typed, operator-friendly error first.
    if !seed_store.set_persists_across_restart() {
        return Err(
            "seed rotation is not supported by the active seed store: a \
                    rotated seed would not survive a restart, so every key minted \
                    after rotation would become unrecoverable"
                .into(),
        );
    }

    let old_id = get_active_seed_id(keys_ks).await?;

    // Outgoing master seed (zeroized on drop, P0.7). Still the active seed in
    // the external store at this point.
    let old_seed = Zeroizing::new(
        seed_store
            .get()
            .await
            .map_err(|e| format!("{e}"))?
            .ok_or("no active seed found — cannot rotate")?,
    );

    // Generate or derive the new seed (zeroized on drop, P0.7).
    let new_seed: Zeroizing<Vec<u8>> = if let Some(phrase) = mnemonic {
        let m =
            bip39::Mnemonic::parse(phrase).map_err(|e| format!("invalid BIP-39 mnemonic: {e}"))?;
        Zeroizing::new(m.to_seed("").to_vec())
    } else {
        let mut buf = Zeroizing::new([0u8; 32]);
        rand::Rng::fill_bytes(&mut rand::rng(), &mut *buf);
        Zeroizing::new(buf.to_vec())
    };

    let salt = imported::get_or_create_salt(keys_ks).await?;
    let new_id = old_id + 1;

    // (1) Archive the outgoing seed encrypted under the NEW KEK, *before* the
    // external store flips. Window: external + active_id still point at `old`,
    // so this record can't yet be decrypted — but `load_seed_bytes(old)` sees
    // `old == active_id`, fails the decrypt, and falls back to the external
    // store (still `old`). No plaintext is ever written.
    let mut old_record = get_seed_record(keys_ks, old_id)
        .await?
        .unwrap_or_else(|| SeedRecord {
            id: old_id,
            seed_hex: None,
            seed_enc: None,
            created_at: Utc::now(),
            retired_at: None,
        });
    old_record.seed_hex = None;
    old_record.seed_enc = Some(encrypt_archived_seed(&new_seed, &salt, old_id, &old_seed)?);
    old_record.retired_at = Some(Utc::now());
    save_seed_record(keys_ks, &old_record).await?;
    info!(seed_id = old_id, "archived retired seed (encrypted)");

    // (2) Commit the new seed to the external store. Now the gen-`old` archive
    // from step (1) is decryptable; `load_seed_bytes(old)` decrypts it
    // successfully even while `active_id` still reads `old`.
    seed_store
        .set(&new_seed)
        .await
        .map_err(|e| format!("{e}"))?;

    // (3) Publish the new active generation.
    let new_record = SeedRecord {
        id: new_id,
        seed_hex: None,
        seed_enc: None,
        created_at: Utc::now(),
        retired_at: None,
    };
    save_seed_record(keys_ks, &new_record).await?;
    set_active_seed_id(keys_ks, new_id).await?;

    // (4) Re-encrypt every older archive (gens < old, previously under the
    // `old` KEK) to the new KEK. The external store now holds `new`, so an
    // interruption here is self-healing: `reconcile_archive` recovers `old`
    // from the gen-`old` archive (now under `new`) and finishes the pass.
    let reencrypted = reencrypt_predecessors(keys_ks, &salt, old_id, &old_seed, &new_seed).await?;

    info!(
        old_seed_id = old_id,
        new_seed_id = new_id,
        reencrypted_predecessors = reencrypted,
        "seed rotated successfully"
    );

    Ok(new_id)
}

/// Re-encrypt every archived generation strictly older than `old_id` from the
/// previous active seed's KEK to the new one. Used as step (4) of rotation.
async fn reencrypt_predecessors(
    keys_ks: &KeyspaceHandle,
    salt: &[u8],
    old_id: u32,
    old_seed: &[u8],
    new_seed: &[u8],
) -> Result<u32, AppError> {
    let mut count = 0u32;
    for mut record in list_seed_records(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("list seed records: {e}")))?
    {
        if record.id >= old_id {
            continue;
        }
        // Recover this older generation's bytes: normally `seed_enc` under the
        // previous active seed; tolerate a legacy plaintext predecessor too.
        let plaintext = if let Some(ref blob) = record.seed_enc {
            decrypt_archived_seed(old_seed, salt, record.id, blob)
        } else if let Some(ref hex_str) = record.seed_hex {
            hex::decode(hex_str).ok().map(Zeroizing::new)
        } else {
            None
        };
        let Some(plaintext) = plaintext else {
            warn!(
                seed_id = record.id,
                "could not recover predecessor seed for re-encryption — leaving as-is \
                 (reconcile will retry)"
            );
            continue;
        };
        record.seed_enc = Some(encrypt_archived_seed(
            new_seed, salt, record.id, &plaintext,
        )?);
        record.seed_hex = None;
        save_seed_record(keys_ks, &record)
            .await
            .map_err(|e| AppError::Internal(format!("save re-encrypted seed: {e}")))?;
        count += 1;
    }
    Ok(count)
}

/// Reconcile the seed archive against the current active seed (P0.7b).
///
/// Idempotent boot-time pass that:
/// - **migrates** any legacy plaintext (`seed_hex`) archive into `seed_enc`
///   under the active seed's KEK (closes the pre-P0.7b plaintext-on-disk gap);
/// - **repairs** any archive left under a predecessor's KEK by an interrupted
///   rotation, re-encrypting it under the active seed.
///
/// Recovery uses a fixpoint over the set of seeds we can already decrypt:
/// starting from the active seed, every archive that decrypts under a known
/// seed yields another known seed, until no more can be recovered. Tiny by
/// construction (one record per rotation, rotations rare), so the O(n²) walk
/// is irrelevant. A no-op for the common never-rotated VTA.
///
/// Returns the number of records rewritten. Safe to call when the VTA has no
/// identity yet (no active seed) — it simply does nothing.
pub async fn reconcile_archive(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
) -> Result<u32, AppError> {
    let records = list_seed_records(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("list seed records: {e}")))?;
    let active_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("active seed id: {e}")))?;

    // Nothing retired → nothing to do (the overwhelmingly common case).
    if !records.iter().any(|r| r.id != active_id) {
        return Ok(0);
    }

    let Some(active_seed) = seed_store
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("seed store: {e}")))?
        .map(Zeroizing::new)
    else {
        // No active seed (degraded / not-yet-provisioned boot) — can't derive a
        // KEK, so leave the archive untouched until identity exists.
        return Ok(0);
    };
    let salt = imported::get_or_create_salt(keys_ks).await?;

    // Fixpoint: recover every generation we can decrypt, seeding from `active`.
    let mut known: std::collections::HashMap<u32, Zeroizing<Vec<u8>>> =
        std::collections::HashMap::new();
    known.insert(active_id, active_seed.clone());
    loop {
        let mut progressed = false;
        for r in &records {
            if known.contains_key(&r.id) {
                continue;
            }
            let recovered = if let Some(ref blob) = r.seed_enc {
                known
                    .values()
                    .find_map(|kseed| decrypt_archived_seed(kseed, &salt, r.id, blob))
            } else {
                r.seed_hex
                    .as_deref()
                    .and_then(|h| hex::decode(h).ok())
                    .map(Zeroizing::new)
            };
            if let Some(pt) = recovered {
                known.insert(r.id, pt);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    // Rewrite anything not already ciphertext-under-active.
    let mut rewritten = 0u32;
    for mut r in records {
        if r.id == active_id {
            continue;
        }
        let already_current = r.seed_hex.is_none()
            && r.seed_enc
                .as_deref()
                .is_some_and(|b| decrypt_archived_seed(&active_seed, &salt, r.id, b).is_some());
        if already_current {
            continue;
        }
        let Some(plaintext) = known.get(&r.id) else {
            warn!(
                seed_id = r.id,
                "seed archive reconcile: generation is unrecoverable (neither decryptable \
                 nor plaintext) — leaving untouched"
            );
            continue;
        };
        r.seed_enc = Some(encrypt_archived_seed(&active_seed, &salt, r.id, plaintext)?);
        r.seed_hex = None;
        save_seed_record(keys_ks, &r)
            .await
            .map_err(|e| AppError::Internal(format!("save reconciled seed: {e}")))?;
        rewritten += 1;
    }

    if rewritten > 0 {
        info!(
            rewritten,
            "seed archive reconciled (encrypted retired seeds)"
        );
    }
    Ok(rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::pin::Pin;
    use tokio::sync::Mutex;
    use vti_common::config::StoreConfig;

    /// In-memory seed store whose `set` persists (so rotation is permitted).
    struct MockSeedStore(Mutex<Option<Vec<u8>>>);

    impl SeedStore for MockSeedStore {
        fn get(
            &self,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>>
        {
            Box::pin(async { Ok(self.0.lock().await.clone()) })
        }
        fn set(
            &self,
            seed: &[u8],
        ) -> Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send + '_>> {
            let seed = seed.to_vec();
            Box::pin(async move {
                *self.0.lock().await = Some(seed);
                Ok(())
            })
        }
    }

    /// keys keyspace + a mock store seeded with `gen0` as the active seed and a
    /// generation-0 record, mirroring a freshly-set-up VTA.
    async fn harness(gen0: &[u8]) -> (KeyspaceHandle, MockSeedStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let keys_ks = store.keyspace("keys").unwrap();
        save_seed_record(
            &keys_ks,
            &SeedRecord {
                id: 0,
                seed_hex: None,
                seed_enc: None,
                created_at: Utc::now(),
                retired_at: None,
            },
        )
        .await
        .unwrap();
        (keys_ks, MockSeedStore(Mutex::new(Some(gen0.to_vec()))), dir)
    }

    #[test]
    fn archive_crypto_round_trips_and_binds_id() {
        let active = [7u8; 32];
        let salt = [9u8; 32];
        let secret = [42u8; 32];
        let blob = encrypt_archived_seed(&active, &salt, 3, &secret).unwrap();

        // Correct (seed, salt, id) recovers the bytes.
        let pt = decrypt_archived_seed(&active, &salt, 3, &blob).expect("decrypt");
        assert_eq!(pt.as_slice(), &secret);

        // Wrong generation id (AAD), wrong active seed, and wrong salt all fail.
        assert!(decrypt_archived_seed(&active, &salt, 4, &blob).is_none());
        assert!(decrypt_archived_seed(&[8u8; 32], &salt, 3, &blob).is_none());
        assert!(decrypt_archived_seed(&active, &[1u8; 32], 3, &blob).is_none());
    }

    #[tokio::test]
    async fn rotation_archives_ciphertext_and_recovers_all_generations() {
        let gen0 = [0xA0u8; 32];
        let (keys_ks, store, _dir) = harness(&gen0).await;

        // Two rotations: gen0 → gen1 → gen2.
        rotate_seed(&keys_ks, &store, None).await.unwrap();
        let gen1 = store.0.lock().await.clone().unwrap();
        rotate_seed(&keys_ks, &store, None).await.unwrap();
        let gen2 = store.0.lock().await.clone().unwrap();
        assert_eq!(get_active_seed_id(&keys_ks).await.unwrap(), 2);

        // No retired record is plaintext; every retired record is ciphertext.
        for id in [0u32, 1] {
            let r = get_seed_record(&keys_ks, id).await.unwrap().unwrap();
            assert!(r.seed_hex.is_none(), "gen {id} must not be plaintext");
            assert!(r.seed_enc.is_some(), "gen {id} must be encrypted");
        }

        // Every generation is recoverable as its original bytes.
        let r0 = load_seed_bytes(&keys_ks, &store, Some(0)).await.unwrap();
        let r1 = load_seed_bytes(&keys_ks, &store, Some(1)).await.unwrap();
        let r2 = load_seed_bytes(&keys_ks, &store, Some(2)).await.unwrap();
        assert_eq!(r0.as_slice(), &gen0);
        assert_eq!(r1.as_slice(), gen1.as_slice());
        assert_eq!(r2.as_slice(), gen2.as_slice());
    }

    #[tokio::test]
    async fn reconcile_migrates_legacy_plaintext_archive() {
        // Simulate a pre-P0.7b store: gen-0 retired as PLAINTEXT hex, gen-1 active.
        let gen0 = [0x11u8; 32];
        let gen1 = [0x22u8; 32];
        let (keys_ks, store, _dir) = harness(&gen1).await; // active = gen1
        set_active_seed_id(&keys_ks, 1).await.unwrap();
        save_seed_record(
            &keys_ks,
            &SeedRecord {
                id: 0,
                seed_hex: Some(hex::encode(gen0)),
                seed_enc: None,
                created_at: Utc::now(),
                retired_at: Some(Utc::now()),
            },
        )
        .await
        .unwrap();

        let n = reconcile_archive(&keys_ks, &store).await.unwrap();
        assert_eq!(n, 1, "the one plaintext archive should be migrated");

        let r0 = get_seed_record(&keys_ks, 0).await.unwrap().unwrap();
        assert!(r0.seed_hex.is_none(), "plaintext must be cleared");
        assert!(r0.seed_enc.is_some(), "must now be ciphertext");
        // Still recoverable as the original gen-0 bytes.
        let recovered = load_seed_bytes(&keys_ks, &store, Some(0)).await.unwrap();
        assert_eq!(recovered.as_slice(), &gen0);

        // Idempotent: a second pass rewrites nothing.
        assert_eq!(reconcile_archive(&keys_ks, &store).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn reconcile_repairs_archive_under_a_predecessor() {
        // Torn rotation: active = gen2; gen1 already under gen2, but gen0 still
        // under its predecessor gen1 (step-4 interruption).
        let gen0 = [1u8; 32];
        let gen1 = [2u8; 32];
        let gen2 = [3u8; 32];
        let (keys_ks, store, _dir) = harness(&gen2).await;
        set_active_seed_id(&keys_ks, 2).await.unwrap();
        let salt = imported::get_or_create_salt(&keys_ks).await.unwrap();

        // gen1 archived correctly under the active seed (gen2).
        save_seed_record(
            &keys_ks,
            &SeedRecord {
                id: 1,
                seed_hex: None,
                seed_enc: Some(encrypt_archived_seed(&gen2, &salt, 1, &gen1).unwrap()),
                created_at: Utc::now(),
                retired_at: Some(Utc::now()),
            },
        )
        .await
        .unwrap();
        // gen0 STALE: encrypted under gen1, not the active gen2.
        save_seed_record(
            &keys_ks,
            &SeedRecord {
                id: 0,
                seed_hex: None,
                seed_enc: Some(encrypt_archived_seed(&gen1, &salt, 0, &gen0).unwrap()),
                created_at: Utc::now(),
                retired_at: Some(Utc::now()),
            },
        )
        .await
        .unwrap();

        // Before reconcile, the stale gen-0 archive can't be loaded.
        assert!(load_seed_bytes(&keys_ks, &store, Some(0)).await.is_err());

        let n = reconcile_archive(&keys_ks, &store).await.unwrap();
        assert_eq!(n, 1, "only the stale gen-0 record needs rewriting");

        // Now both retired generations load as their originals.
        assert_eq!(
            load_seed_bytes(&keys_ks, &store, Some(0))
                .await
                .unwrap()
                .as_slice(),
            &gen0
        );
        assert_eq!(
            load_seed_bytes(&keys_ks, &store, Some(1))
                .await
                .unwrap()
                .as_slice(),
            &gen1
        );
    }

    #[tokio::test]
    async fn load_active_generation_falls_back_when_archive_undecryptable() {
        // Models the rotation window where the active generation's record was
        // written under the new KEK before the store flipped: the archive won't
        // decrypt under the current external seed, but the gen IS active, so the
        // external store is authoritative.
        let active = [0x55u8; 32];
        let (keys_ks, store, _dir) = harness(&active).await;
        let salt = imported::get_or_create_salt(&keys_ks).await.unwrap();
        // active_seed_id is 0; write an archive on gen 0 that won't decrypt under
        // the external seed (encrypted under unrelated bytes).
        save_seed_record(
            &keys_ks,
            &SeedRecord {
                id: 0,
                seed_hex: None,
                seed_enc: Some(encrypt_archived_seed(&[0xEEu8; 32], &salt, 0, &[0u8; 32]).unwrap()),
                created_at: Utc::now(),
                retired_at: None,
            },
        )
        .await
        .unwrap();

        let loaded = load_seed_bytes(&keys_ks, &store, Some(0)).await.unwrap();
        assert_eq!(
            loaded.as_slice(),
            &active,
            "active generation falls back to the external store"
        );
    }

    #[tokio::test]
    async fn load_retired_generation_errors_when_archive_stale() {
        // Same undecryptable archive, but on a RETIRED generation (active is 1):
        // we must refuse rather than return the wrong (active) seed.
        let active = [0x66u8; 32];
        let (keys_ks, store, _dir) = harness(&active).await;
        set_active_seed_id(&keys_ks, 1).await.unwrap();
        save_seed_record(
            &keys_ks,
            &SeedRecord {
                id: 1,
                seed_hex: None,
                seed_enc: None,
                created_at: Utc::now(),
                retired_at: None,
            },
        )
        .await
        .unwrap();
        let salt = imported::get_or_create_salt(&keys_ks).await.unwrap();
        save_seed_record(
            &keys_ks,
            &SeedRecord {
                id: 0,
                seed_hex: None,
                seed_enc: Some(encrypt_archived_seed(&[0xEEu8; 32], &salt, 0, &[0u8; 32]).unwrap()),
                created_at: Utc::now(),
                retired_at: Some(Utc::now()),
            },
        )
        .await
        .unwrap();

        let err = load_seed_bytes(&keys_ks, &store, Some(0))
            .await
            .expect_err("stale retired archive must error");
        assert!(
            err.to_string().contains("reconcile"),
            "error should hint at reconciliation: {err}"
        );
    }
}
