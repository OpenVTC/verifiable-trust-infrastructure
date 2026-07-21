//! Daemon-REST auth-cache orchestration for webvh hosting servers.
//!
//! Composes three primitives the rest of the workspace already
//! provides:
//!
//! - `webvh_store::{get,store,delete}_server_auth` — persisted token
//!   cache keyed by `server-auth:{id}`.
//! - `WebvhClient::{authenticate,refresh}` — the wire-level
//!   challenge / sign / token flow against the daemon.
//! - `operations::keys::get_key_secret_internal` — loads the VTA's
//!   signing key under an `InternalAuthority` elevation. Works for
//!   both `KeyOrigin::Derived` and `KeyOrigin::Imported` symmetrically.
//!
//! On top of those three, this module adds two things:
//!
//! 1. **Per-server async mutex** — `WebvhAuthLocks` keeps a
//!    `DashMap<server_id, Arc<TokioMutex<()>>>`. Every read-modify-
//!    write of `server-auth:{id}` happens under the lock, so two
//!    concurrent ops against the same server can't both refresh and
//!    clobber each other's writes. The lock is keyed by server id,
//!    not global — so a publish against server A doesn't block a
//!    publish against server B.
//! 2. **Refresh-or-reauth ladder** — when the cached token is stale,
//!    try the refresh endpoint first (cheap, one round-trip). If
//!    refresh returns `Authentication` (token rotated by daemon,
//!    expired refresh window, etc.), fall back to a full
//!    authenticate. The daemon rotates refresh tokens on use, so
//!    every successful refresh writes the new `refresh_token` back
//!    to the cache.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex as TokioMutex;
use tracing::info;
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::operations::internal_authority::InternalAuthority;
use crate::store::KeyspaceHandle;
use crate::webvh_auth::VtaSigningIdentityOwned;
use crate::webvh_client::{TokenData, WebvhClient};
use crate::webvh_store::{
    WebvhServerAuthRecord, delete_server_auth, get_server_auth, store_server_auth,
};
use vta_sdk::did_key::decode_private_key_multibase;
use vta_sdk::webvh::WebvhServerRecord;

/// Refresh tokens at least this many seconds before they expire. A
/// daemon clock slightly ahead of ours can still consider the token
/// valid while we treat it as stale and refresh proactively — better
/// to spend the round-trip than to fail an in-flight operation.
const ACCESS_TOKEN_REFRESH_SKEW_SECS: u64 = 30;

/// Per-server async mutex registry. One `Mutex<()>` per server id,
/// lazily allocated on first use. Serialises the read-modify-write
/// cycle of `server-auth:{id}` records so two concurrent operations
/// against the same server can't both refresh and last-writer-wins.
///
/// Held on `AppState`. Cheap to clone (`Arc` internally).
#[derive(Clone, Default)]
pub struct WebvhAuthLocks {
    inner: Arc<std::sync::Mutex<HashMap<String, Arc<TokioMutex<()>>>>>,
}

impl WebvhAuthLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get-or-insert the async mutex for `server_id`.
    ///
    /// The outer `std::sync::Mutex` here is held only for the
    /// HashMap insert / lookup — never across the inner async
    /// `Mutex<()>` lock. That keeps the synchronous critical
    /// section microscopic.
    pub fn lock_for(&self, server_id: &str) -> Arc<TokioMutex<()>> {
        let mut map = self.inner.lock().expect("WebvhAuthLocks mutex poisoned");
        map.entry(server_id.to_string())
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone()
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn access_token_is_fresh(record: &WebvhServerAuthRecord, now_secs: u64) -> bool {
    record
        .access_expires_at
        .saturating_sub(ACCESS_TOKEN_REFRESH_SKEW_SECS)
        > now_secs
}

/// Bundle of dependencies needed to mint/refresh a daemon REST
/// access token. Constructed once per operation and threaded to
/// every transport-build site within that operation.
pub struct AuthContext<'a> {
    pub webvh_ks: &'a KeyspaceHandle,
    pub identity: &'a VtaSigningIdentityOwned,
    pub locks: &'a WebvhAuthLocks,
}

/// Ensure `client` carries a fresh access token. Returns the token
/// (also set via `client.set_access_token`) so callers can pass it
/// to retry helpers.
///
/// Decision ladder, under the per-server async mutex:
///
/// 1. Read `server-auth:{id}`.
/// 2. If present and `access_expires_at` is in the future plus
///    skew, set the token on the client and return it.
/// 3. Else, if we have a refresh_token, try `client.refresh`.
///    On success, persist the rotated tokens and set the new
///    access token.
/// 4. Else (no cache row, or refresh rejected with
///    `Authentication`), do a full `client.authenticate`.
///    Persist the result.
///
/// The lock guarantees that two concurrent calls for the same
/// server don't both reach step 3 / step 4 and double-write —
/// the loser re-reads inside the lock and sees the winner's
/// fresh record.
pub async fn ensure_fresh_access_token(
    auth_ctx: &AuthContext<'_>,
    server: &WebvhServerRecord,
    client: &mut WebvhClient,
) -> Result<String, AppError> {
    let lock = auth_ctx.locks.lock_for(&server.id);
    let _guard = lock.lock().await;

    // Re-read inside the lock — a previous caller may have just
    // refreshed. We clone `access_token` because `WebvhServerAuthRecord`
    // is `ZeroizeOnDrop`, so individual fields can't be moved out.
    if let Some(record) = get_server_auth(auth_ctx.webvh_ks, &server.id).await?
        && access_token_is_fresh(&record, unix_now_secs())
    {
        let token = record.access_token.clone();
        client.set_access_token(token.clone());
        return Ok(token);
    }

    // Stale or absent. Try refresh first, fall back to full reauth.
    let identity = auth_ctx.identity.as_ref();
    let cached = get_server_auth(auth_ctx.webvh_ks, &server.id).await?;
    if let Some(stale) = cached {
        match client.refresh(&identity, &stale.refresh_token).await {
            Ok(tokens) => {
                let token = tokens.access_token.clone();
                persist_tokens(auth_ctx.webvh_ks, &server.id, &tokens).await?;
                client.set_access_token(token.clone());
                return Ok(token);
            }
            Err(AppError::Authentication(reason)) => {
                info!(
                    server_id = %server.id,
                    reason = %reason,
                    "webvh refresh rejected; falling back to full authenticate"
                );
                // Fall through to full reauth.
            }
            Err(e) => return Err(e),
        }
    }

    let tokens = client.authenticate(&identity).await?;
    let token = tokens.access_token.clone();
    persist_tokens(auth_ctx.webvh_ks, &server.id, &tokens).await?;
    client.set_access_token(token.clone());
    Ok(token)
}

/// Invalidate the cached auth record for `server_id`. Called when
/// a production endpoint returns 401 mid-window — the daemon
/// considers the token revoked, so we drop the cache and force a
/// reauth on the next access.
pub async fn invalidate_cached_token(
    webvh_ks: &KeyspaceHandle,
    server_id: &str,
) -> Result<(), AppError> {
    delete_server_auth(webvh_ks, server_id).await
}

async fn persist_tokens(
    webvh_ks: &KeyspaceHandle,
    server_id: &str,
    tokens: &TokenData,
) -> Result<WebvhServerAuthRecord, AppError> {
    let record = WebvhServerAuthRecord {
        server_id: server_id.to_string(),
        access_token: tokens.access_token.clone(),
        access_expires_at: tokens.access_expires_at,
        refresh_token: tokens.refresh_token.clone(),
        refresh_expires_at: tokens.refresh_expires_at,
    };
    store_server_auth(webvh_ks, &record).await?;
    Ok(record)
}

/// Authenticate against a webvh hosting server and publish a DID log
/// in one call. Encapsulates the entire flow — identity load,
/// auth-cache RMW under the per-server mutex, transport
/// construction, and 401-retry — so operation-layer call sites
/// don't have to re-derive it.
///
/// For DIDComm transports, no auth handshake is performed (DIDComm
/// authcrypt handles the equivalent at the envelope layer) — the
/// helper falls through to the plain `publish_did` path.
pub async fn publish_log_to_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    mnemonic: &str,
    log_content: &str,
    domain: Option<&str>,
) -> Result<(), AppError> {
    let identity = load_vta_webvh_signing_identity(
        deps.keys_ks,
        deps.imported_ks,
        deps.seed_store,
        deps.audit_ks,
        vta_did,
    )
    .await?;
    let auth_ctx = AuthContext {
        webvh_ks: deps.webvh_ks,
        identity: &identity,
        locks: deps.auth_locks,
    };
    let mut transport = super::WebvhTransport::from_server_authenticated(
        server,
        deps.did_resolver,
        deps.didcomm_bridge,
        &auth_ctx,
    )
    .await?;
    transport
        .publish_did_authenticated(mnemonic, log_content, domain, &auth_ctx, server)
        .await
}

/// Authenticate and delete a DID log on the hosting server. Same
/// encapsulation as [`publish_log_to_server`].
pub async fn delete_log_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    mnemonic: &str,
    domain: Option<&str>,
) -> Result<(), AppError> {
    let identity = load_vta_webvh_signing_identity(
        deps.keys_ks,
        deps.imported_ks,
        deps.seed_store,
        deps.audit_ks,
        vta_did,
    )
    .await?;
    let auth_ctx = AuthContext {
        webvh_ks: deps.webvh_ks,
        identity: &identity,
        locks: deps.auth_locks,
    };
    let mut transport = super::WebvhTransport::from_server_authenticated(
        server,
        deps.did_resolver,
        deps.didcomm_bridge,
        &auth_ctx,
    )
    .await?;
    transport
        .delete_did_authenticated(mnemonic, domain, &auth_ctx, server)
        .await
}

/// Authenticate and atomically claim + publish a DID slot on the
/// hosting server. Same encapsulation as [`publish_log_to_server`].
pub async fn register_did_atomic_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    path: &str,
    did_log: &str,
    force: bool,
    domain: Option<&str>,
) -> Result<crate::webvh_client::RequestUriResponse, AppError> {
    let identity = load_vta_webvh_signing_identity(
        deps.keys_ks,
        deps.imported_ks,
        deps.seed_store,
        deps.audit_ks,
        vta_did,
    )
    .await?;
    let auth_ctx = AuthContext {
        webvh_ks: deps.webvh_ks,
        identity: &identity,
        locks: deps.auth_locks,
    };
    let mut transport = super::WebvhTransport::from_server_authenticated(
        server,
        deps.did_resolver,
        deps.didcomm_bridge,
        &auth_ctx,
    )
    .await?;
    transport
        .register_did_atomic_authenticated(path, did_log, force, domain, &auth_ctx, server)
        .await
}

/// Authenticate and park (`enable == false`) or resume (`enable == true`) an
/// agent name on the hosting server, submitting the signed new `did.jsonl`.
/// Same encapsulation as [`publish_log_to_server`].
#[allow(clippy::too_many_arguments)]
pub async fn agent_name_op_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    verb: super::update::AgentNameVerb,
    mnemonic: &str,
    name: &str,
    did_log: &str,
    domain: Option<&str>,
) -> Result<(), AppError> {
    let identity = load_vta_webvh_signing_identity(
        deps.keys_ks,
        deps.imported_ks,
        deps.seed_store,
        deps.audit_ks,
        vta_did,
    )
    .await?;
    let auth_ctx = AuthContext {
        webvh_ks: deps.webvh_ks,
        identity: &identity,
        locks: deps.auth_locks,
    };
    let mut transport = super::WebvhTransport::from_server_authenticated(
        server,
        deps.did_resolver,
        deps.didcomm_bridge,
        &auth_ctx,
    )
    .await?;
    transport
        .agent_name_authenticated(verb, mnemonic, name, did_log, domain, &auth_ctx, server)
        .await
}

/// Load the VTA's signing identity for daemon REST authentication.
///
/// Looks up `{vta_did}#key-0` via `get_key_secret_internal` under
/// an `InternalAuthority` elevation. The helper handles both
/// `KeyOrigin::Derived` (seed-derived) and `KeyOrigin::Imported`
/// (operator-imported) symmetrically — the prior PR's "imported
/// active keys can't sign daemon REST yet" caveat does not apply
/// because we don't differentiate.
///
/// The 32-byte signing seed is wrapped in `Zeroizing` so it wipes
/// on drop. Callers should keep the identity short-lived.
pub async fn load_vta_webvh_signing_identity(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit_ks: &KeyspaceHandle,
    vta_did: &str,
) -> Result<VtaSigningIdentityOwned, AppError> {
    let signing_kid = format!("{vta_did}#key-0");
    let authority = InternalAuthority::new("webvh-rest-auth");
    let resp = crate::operations::keys::get_key_secret_internal(
        keys_ks,
        imported_ks,
        seed_store,
        audit_ks,
        authority,
        &signing_kid,
        "webvh-rest-auth-internal",
    )
    .await?;
    let bytes: [u8; 32] = decode_private_key_multibase(&resp.private_key_multibase)
        .map_err(|e| AppError::Internal(format!("decode VTA signing key for daemon auth: {e}")))?;
    Ok(VtaSigningIdentityOwned {
        vta_did: vta_did.to_string(),
        signing_kid,
        private_key: Zeroizing::new(bytes),
    })
}
