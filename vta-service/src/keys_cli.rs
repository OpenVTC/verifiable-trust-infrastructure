use std::path::PathBuf;

use p256::elliptic_curve::sec1::ToEncodedPoint;

use crate::config::AppConfig;
use crate::keys::derivation::Bip32Extension;
use crate::keys::seed_store::create_seed_store;
use crate::keys::seeds::load_seed_bytes;
use crate::keys::{self, KeyRecord, KeyStatus, KeyType};
use crate::store::Store;

/// Format a UTC `DateTime` as a readable local-timezone string with ISO offset.
///
/// Internal representation stays UTC; CLI output converts to operator locale.
fn format_local_datetime(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

pub async fn run_keys_list(
    config_path: Option<PathBuf>,
    context: Option<String>,
    status: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let status_filter = status
        .map(|s| match s.as_str() {
            "active" => Ok(KeyStatus::Active),
            "revoked" => Ok(KeyStatus::Revoked),
            _ => Err(format!("unknown status '{s}', expected active or revoked")),
        })
        .transpose()?;

    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace(crate::keyspaces::KEYS)?;

    let raw = keys_ks.prefix_iter_raw("key:").await?;

    let mut records: Vec<KeyRecord> = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: KeyRecord = serde_json::from_slice(&value)?;
        if let Some(ref status) = status_filter
            && record.status != *status
        {
            continue;
        }
        if let Some(ref ctx) = context
            && record.context_id.as_deref() != Some(ctx.as_str())
        {
            continue;
        }
        records.push(record);
    }

    if records.is_empty() {
        eprintln!("No keys found.");
        return Ok(());
    }

    eprintln!("{} keys:\n", records.len());
    for record in &records {
        print_key_record(record);
    }

    Ok(())
}

pub async fn run_keys_secrets(
    config_path: Option<PathBuf>,
    key_ids: Vec<String>,
    context: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace(crate::keyspaces::KEYS)?;
    let seed_store = create_seed_store(&config)?;

    // Resolve key IDs: explicit args or all active keys in a context
    let resolved_ids: Vec<String> = if key_ids.is_empty() {
        let ctx = context.as_deref().ok_or(
            "provide key IDs as arguments, or use --context to export all active keys in a context",
        )?;
        let raw = keys_ks.prefix_iter_raw("key:").await?;
        let mut ids = Vec::new();
        for (_key, value) in raw {
            let record: KeyRecord = serde_json::from_slice(&value)?;
            if record.status == KeyStatus::Active && record.context_id.as_deref() == Some(ctx) {
                ids.push(record.key_id);
            }
        }
        ids
    } else {
        key_ids
    };

    if resolved_ids.is_empty() {
        eprintln!("No active keys found.");
        return Ok(());
    }

    for (i, key_id) in resolved_ids.iter().enumerate() {
        if i > 0 {
            eprintln!();
        }
        let record: KeyRecord = keys_ks
            .get(keys::store_key(key_id))
            .await?
            .ok_or_else(|| format!("key not found: {key_id}"))?;

        let seed = load_seed_bytes(&keys_ks, &*seed_store, record.seed_id).await?;
        let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed)
            .map_err(|e| format!("failed to create BIP-32 root key: {e}"))?;

        let (public, private) = match record.key_type {
            KeyType::Ed25519 => {
                let secret = bip32
                    .derive_ed25519(&record.derivation_path)
                    .map_err(|e| format!("failed to derive key {key_id}: {e}"))?;
                (
                    secret
                        .get_public_keymultibase()
                        .map_err(|e| format!("{e}"))?,
                    secret
                        .get_private_keymultibase()
                        .map_err(|e| format!("{e}"))?,
                )
            }
            KeyType::X25519 => {
                let secret = bip32
                    .derive_x25519(&record.derivation_path)
                    .map_err(|e| format!("failed to derive key {key_id}: {e}"))?;
                (
                    secret
                        .get_public_keymultibase()
                        .map_err(|e| format!("{e}"))?,
                    secret
                        .get_private_keymultibase()
                        .map_err(|e| format!("{e}"))?,
                )
            }
            KeyType::P256 => {
                let p256_secret = bip32
                    .derive_p256(&record.derivation_path)
                    .map_err(|e| format!("failed to derive key {key_id}: {e}"))?;
                let verifying_key = p256_secret.secret_key.public_key();
                let encoded = verifying_key.to_encoded_point(true);
                (
                    multibase::encode(multibase::Base::Base58Btc, encoded.as_bytes()),
                    multibase::encode(
                        multibase::Base::Base58Btc,
                        p256_secret.secret_key.to_bytes(),
                    ),
                )
            }
        };

        eprintln!("Key ID:               {}", record.key_id);
        eprintln!("Key Type:             {}", record.key_type);
        eprintln!("Public Key Multibase: {public}");
        eprintln!("Secret Key Multibase: {private}");
    }

    Ok(())
}

pub async fn run_keys_seeds_list(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace(crate::keyspaces::KEYS)?;

    let active_id = keys::seeds::get_active_seed_id(&keys_ks).await?;
    let records = keys::seeds::list_seed_records(&keys_ks).await?;

    if records.is_empty() {
        eprintln!("No seed records found.");
        eprintln!("  (pre-rotation state: using external seed store as generation 0)");
        eprintln!("  Active seed ID: {active_id}");
        return Ok(());
    }

    eprintln!("{} seed generation(s):\n", records.len());
    for record in &records {
        let status = if record.retired_at.is_some() {
            "retired"
        } else {
            "active"
        };
        eprintln!("  Seed ID:     {}", record.id);
        eprintln!("  Status:      {status}");
        eprintln!(
            "  Created:     {}",
            format_local_datetime(record.created_at)
        );
        if let Some(retired_at) = record.retired_at {
            eprintln!("  Retired:     {}", format_local_datetime(retired_at));
        }
        if record.seed_hex.is_some() {
            eprintln!("  Storage:     archived in local store");
        } else {
            eprintln!("  Storage:     external seed store");
        }
        eprintln!();
    }
    eprintln!("Active seed ID: {active_id}");

    Ok(())
}

pub async fn run_rotate_seed(
    config_path: Option<PathBuf>,
    mnemonic: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace(crate::keyspaces::KEYS)?;
    let seed_store = create_seed_store(&config)?;

    let current_id = keys::seeds::get_active_seed_id(&keys_ks).await?;

    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  WARNING: Seed rotation is irreversible.                 ║");
    eprintln!("║  The current seed will be archived in the local store.   ║");
    eprintln!("║  All new keys will use the new seed.                     ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
    eprintln!("  Current active seed ID: {current_id}");
    eprintln!();

    let confirmed = dialoguer::Confirm::new()
        .with_prompt("Proceed with seed rotation?")
        .default(false)
        .interact()?;
    if !confirmed {
        eprintln!("Seed rotation cancelled.");
        return Ok(());
    }

    let new_id = keys::seeds::rotate_seed(&keys_ks, &*seed_store, mnemonic.as_deref()).await?;

    store.persist().await?;

    eprintln!();
    eprintln!("\x1b[1;32mSeed rotated successfully.\x1b[0m");
    eprintln!("  Previous seed ID: {current_id} (retired, archived)");
    eprintln!("  New active seed ID: {new_id}");

    Ok(())
}

fn print_key_record(record: &KeyRecord) {
    eprintln!("  Key ID:      {}", record.key_id);
    eprintln!("  Key Type:    {}", record.key_type);
    eprintln!("  Path:        {}", record.derivation_path);
    eprintln!("  Status:      {}", record.status);
    if let Some(label) = &record.label {
        eprintln!("  Label:       {label}");
    }
    if let Some(ctx) = &record.context_id {
        eprintln!("  Context:     {ctx}");
    }
    if let Some(sid) = record.seed_id {
        eprintln!("  Seed ID:     {sid}");
    }
    eprintln!(
        "  Created:     {}",
        format_local_datetime(record.created_at)
    );
    eprintln!();
}
