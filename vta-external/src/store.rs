//! Persistence: account records in `external_accounts`, wrapped secrets in
//! `external_secrets`.
//!
//! Keys:
//! - `acct:<context>:<accountId>` — the [`AccountRecord`].
//! - `retired:<context>:<accountId>` — a deleted id. Never reused: a
//!   provider-side trust policy or an audit row may still name it.
//! - (`external_secrets`) `secret:external:<context>:<accountId>` — the secret,
//!   AES-256-GCM under the seed-derived KEK `vta_keys::imported` uses, bound to
//!   its account by the AAD.
//!
//! Writes go through [`write_lock`], one process-wide lock, so a
//! read-modify-write of an account cannot interleave with another. Management
//! traffic is rare and human-paced; the simplicity is worth more than the
//! concurrency.

use std::sync::LazyLock;

use tokio::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

use vta_keys::seed_store::SeedStore;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::model::AccountRecord;

static WRITE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Serialise account writes. Hold it across the read and the write of one
/// read-modify-write, and release it before anything slow (a provider call).
pub async fn write_lock() -> MutexGuard<'static, ()> {
    WRITE_LOCK.lock().await
}

fn account_key(context: &str, id: &str) -> String {
    format!("acct:{context}:{id}")
}

fn retired_key(context: &str, id: &str) -> String {
    format!("retired:{context}:{id}")
}

/// The key-id the imported-secret wrapper binds into its AAD.
fn secret_key_id(context: &str, id: &str) -> String {
    format!("external:{context}:{id}")
}

const SECRET_KEY_TYPE: &str = "external-secret";

/// One account.
pub async fn get(
    accounts: &KeyspaceHandle,
    context: &str,
    id: &str,
) -> Result<Option<AccountRecord>, AppError> {
    accounts.get(account_key(context, id)).await
}

/// Every account in `context`, ordered by id.
pub async fn list(
    accounts: &KeyspaceHandle,
    context: &str,
) -> Result<Vec<AccountRecord>, AppError> {
    let rows = accounts.prefix_iter_raw(format!("acct:{context}:")).await?;
    let mut out = Vec::with_capacity(rows.len());
    for (_, v) in rows {
        let rec: AccountRecord = serde_json::from_slice(&v)
            .map_err(|e| AppError::Internal(format!("corrupt external account record: {e}")))?;
        out.push(rec);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Whether `id` was deleted in `context`, and so may never be used again.
pub async fn is_retired(
    accounts: &KeyspaceHandle,
    context: &str,
    id: &str,
) -> Result<bool, AppError> {
    Ok(accounts.get_raw(retired_key(context, id)).await?.is_some())
}

/// Store a new account; `false` when the id is taken (live or retired).
pub async fn insert_new(accounts: &KeyspaceHandle, rec: &AccountRecord) -> Result<bool, AppError> {
    if is_retired(accounts, &rec.context, &rec.id).await? {
        return Ok(false);
    }
    accounts
        .insert_if_absent(account_key(&rec.context, &rec.id), rec)
        .await
}

/// Overwrite an existing account. Call under [`write_lock`].
pub async fn put(accounts: &KeyspaceHandle, rec: &AccountRecord) -> Result<(), AppError> {
    accounts
        .insert(account_key(&rec.context, &rec.id), rec)
        .await
}

/// Delete an account for good: its record and secret go, its id is retired.
pub async fn delete(
    accounts: &KeyspaceHandle,
    secrets: &KeyspaceHandle,
    context: &str,
    id: &str,
) -> Result<(), AppError> {
    accounts
        .insert_raw(
            retired_key(context, id),
            chrono::Utc::now().to_rfc3339().into_bytes(),
        )
        .await?;
    vta_keys::imported::delete_secret(secrets, &secret_key_id(context, id)).await?;
    accounts.remove(account_key(context, id)).await
}

/// Wrap and store an account's secret under the active seed generation.
/// Returns the generation, which the record keeps so the secret opens under the
/// generation that sealed it after a seed rotation.
pub async fn store_secret(
    secrets: &KeyspaceHandle,
    keys: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    context: &str,
    id: &str,
    secret: &[u8],
) -> Result<u32, AppError> {
    let seed_id = vta_keys::seeds::get_active_seed_id(keys)
        .await
        .map_err(|e| AppError::Internal(format!("active seed id: {e}")))?;
    let seed = vta_keys::seeds::load_seed_bytes(keys, seed_store, Some(seed_id))
        .await
        .map_err(|e| AppError::Internal(format!("load seed: {e}")))?;
    vta_keys::imported::store_secret(
        secrets,
        keys,
        &seed,
        &secret_key_id(context, id),
        SECRET_KEY_TYPE,
        secret,
    )
    .await?;
    Ok(seed_id)
}

/// Unwrap an account's secret for one use. `None` when none is stored — after
/// a restore, which does not carry secrets.
pub async fn load_secret(
    secrets: &KeyspaceHandle,
    keys: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    context: &str,
    id: &str,
    seed_id: u32,
) -> Result<Option<Zeroizing<String>>, AppError> {
    let key_id = secret_key_id(context, id);
    if secrets.get_raw(format!("secret:{key_id}")).await?.is_none() {
        return Ok(None);
    }
    let seed = vta_keys::seeds::load_seed_bytes(keys, seed_store, Some(seed_id))
        .await
        .map_err(|e| AppError::Internal(format!("load seed: {e}")))?;
    let bytes = Zeroizing::new(
        vta_keys::imported::load_secret(secrets, keys, &seed, &key_id, SECRET_KEY_TYPE).await?,
    );
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| AppError::Internal("stored external secret is not UTF-8".into()))?;
    Ok(Some(Zeroizing::new(text.to_string())))
}
