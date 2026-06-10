use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::keys::seed_store::SeedStore;
use crate::store::KeyspaceHandle;

const ACTIVE_SEED_ID_KEY: &str = "active_seed_id";

/// Metadata record for a BIP-32 master seed generation.
///
/// Active seeds have `seed_hex: None` — their bytes live in the external
/// secure store (keyring, AWS, GCP, etc.).  Retired seeds are archived
/// into fjall as hex so old keys remain recoverable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedRecord {
    pub id: u32,
    /// `None` = active (bytes in external store), `Some(hex)` = retired (archived).
    pub seed_hex: Option<String>,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

fn store_seed_key(id: u32) -> String {
    format!("seed:{id}")
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

/// Load seed bytes for a given generation.
///
/// - If `seed_id` is `None`, uses generation 0 (pre-rotation default).
/// - If the seed record exists with `seed_hex: Some(hex)` → retired, decode hex.
/// - If the seed record exists with `seed_hex: None` → active, load from external store.
/// - If no seed record exists → pre-rotation state, load from external store.
pub async fn load_seed_bytes(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    seed_id: Option<u32>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let effective_id = seed_id.unwrap_or(0);

    if let Some(record) = get_seed_record(keys_ks, effective_id).await?
        && let Some(ref hex_str) = record.seed_hex
    {
        // Retired seed — archived in fjall
        return Ok(hex::decode(hex_str)?);
    }
    // Active seed or pre-rotation: load from external store
    seed_store
        .get()
        .await
        .map_err(|e| format!("{e}"))?
        .ok_or_else(|| "no seed found in external store".into())
}

/// Rotate to a new seed generation.
///
/// 1. Archives the current active seed's bytes into fjall (hex-encoded).
/// 2. Generates or derives a new seed and stores it in the external store.
/// 3. Creates a new seed record (active) and updates `active_seed_id`.
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

    // Load current seed bytes for archival
    let old_seed = seed_store
        .get()
        .await
        .map_err(|e| format!("{e}"))?
        .ok_or("no active seed found — cannot rotate")?;

    // Archive the old seed into fjall
    let mut old_record = get_seed_record(keys_ks, old_id)
        .await?
        .unwrap_or_else(|| SeedRecord {
            id: old_id,
            seed_hex: None,
            created_at: Utc::now(),
            retired_at: None,
        });
    old_record.seed_hex = Some(hex::encode(&old_seed));
    old_record.retired_at = Some(Utc::now());
    save_seed_record(keys_ks, &old_record).await?;
    info!(seed_id = old_id, "archived retired seed");

    // Generate or derive the new seed
    let new_seed: Vec<u8> = if let Some(phrase) = mnemonic {
        let m =
            bip39::Mnemonic::parse(phrase).map_err(|e| format!("invalid BIP-39 mnemonic: {e}"))?;
        m.to_seed("").to_vec()
    } else {
        let mut buf = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut buf);
        buf.to_vec()
    };

    // Store new seed in external backend
    seed_store
        .set(&new_seed)
        .await
        .map_err(|e| format!("{e}"))?;

    // Create new seed record
    let new_id = old_id + 1;
    let new_record = SeedRecord {
        id: new_id,
        seed_hex: None,
        created_at: Utc::now(),
        retired_at: None,
    };
    save_seed_record(keys_ks, &new_record).await?;
    set_active_seed_id(keys_ks, new_id).await?;

    info!(
        old_seed_id = old_id,
        new_seed_id = new_id,
        "seed rotated successfully"
    );

    Ok(new_id)
}
