use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Stored cache entry with TTL metadata.
#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    value: String,
    expires_at: i64,
}

/// Response body for cache retrieval.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CacheGetResponse {
    pub key: String,
    pub value: String,
}

/// Request body for cache storage.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CachePutRequest {
    pub value: String,
    pub ttl_secs: u64,
}

/// Response body for cache storage.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CachePutResponse {
    pub key: String,
    pub expires_at: i64,
}

fn cache_store_key(caller_did: &str, key: &str) -> String {
    format!("cache:{caller_did}:{key}")
}

/// Retrieve a cached value. Returns `None` if expired or absent.
pub async fn get_cached(
    cache_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key: &str,
    channel: &str,
) -> Result<Option<CacheGetResponse>, AppError> {
    let store_key = cache_store_key(&auth.did, key);
    let entry: Option<CacheEntry> = cache_ks.get(store_key.clone()).await?;

    match entry {
        Some(e) if e.expires_at > Utc::now().timestamp() => {
            info!(channel, key, caller = %auth.did, "cache hit");
            Ok(Some(CacheGetResponse {
                key: key.to_string(),
                value: e.value,
            }))
        }
        Some(_) => {
            // Expired — clean up lazily
            cache_ks.remove(store_key).await?;
            info!(channel, key, caller = %auth.did, "cache miss (expired)");
            Ok(None)
        }
        None => {
            info!(channel, key, caller = %auth.did, "cache miss");
            Ok(None)
        }
    }
}

/// Store a value with a TTL in seconds.
pub async fn put_cached(
    cache_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key: &str,
    req: &CachePutRequest,
    channel: &str,
) -> Result<CachePutResponse, AppError> {
    let expires_at = Utc::now().timestamp() + req.ttl_secs as i64;
    let entry = CacheEntry {
        value: req.value.clone(),
        expires_at,
    };
    let store_key = cache_store_key(&auth.did, key);
    cache_ks.insert(store_key, &entry).await?;

    info!(channel, key, caller = %auth.did, ttl = req.ttl_secs, "cache set");

    Ok(CachePutResponse {
        key: key.to_string(),
        expires_at,
    })
}

/// Clear a cached value.
pub async fn delete_cached(
    cache_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key: &str,
    channel: &str,
) -> Result<(), AppError> {
    let store_key = cache_store_key(&auth.did, key);
    cache_ks.remove(store_key).await?;
    info!(channel, key, caller = %auth.did, "cache cleared");
    Ok(())
}
