//! Passkey storage layer.
//!
//! Adapted from `webvh-common/src/server/passkey/store.rs`. Adjusts
//! imports to vti-common's paths; the data shapes and key conventions
//! are preserved unchanged.
//!
//! ## Atomic take semantics
//!
//! webvh-common's storage relies on an atomic `take` (get + delete in
//! one step) for race protection: a second concurrent finish-ceremony
//! call must see `None` after the first has consumed the state. The
//! helpers [`take`] / [`take_raw`] here are [`KeyspaceHandle::take_raw`],
//! which reads and deletes under the keyspace's write lock (the vsock
//! store holds the key's lock across both), so of two racing calls
//! exactly one sees `Some(_)`.
//!
//! ## In-flight ceremony state is short-lived and bounded
//!
//! Every row a ceremony writes between its start and its finish (the
//! WebAuthn state, the step-up binding, the registration's user and
//! enrolment links, and a host's own pins written with [`store_pending`])
//! carries an `expiresAt` [`CEREMONY_TTL_SECS`] after it was written:
//!
//! - **On use.** A take or read of a row past its expiry answers `None`,
//!   so a stale challenge cannot be redeemed however long the row lingers.
//!   The take still deletes it, exactly once.
//! - **On a sweep.** [`sweep_expired_ceremonies`] deletes every lapsed row,
//!   each with a compare-and-delete, so a row a finish has just taken (or
//!   that has been rewritten) is never deleted a second time.
//! - **Bounded.** Each ceremony state row (`pk_reg:` / `pk_auth:`) is
//!   counted under its owner — the authenticated DID that started it, or
//!   one shared anonymous owner for an unauthenticated sign-in. A start is
//!   refused when its owner already has [`MAX_PENDING_CEREMONIES_PER_OWNER`]
//!   pending (anonymous: [`MAX_PENDING_ANONYMOUS_CEREMONIES`]), or when
//!   [`MAX_PENDING_CEREMONIES`] are pending in all. Lapsed rows are swept
//!   before a start is refused, so the bounds count only live ceremonies.
//!
//! A row written before rows carried an expiry cannot be read as one and
//! is treated as lapsed: it authorises nothing and the sweep removes it.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::error::AppError;
use crate::store::{Batch, KeyspaceHandle};

// ---------------------------------------------------------------------------
// Ceremony lifetime and bounds
// ---------------------------------------------------------------------------

/// How long the state of an in-flight WebAuthn ceremony is kept, in
/// seconds. A start's challenge can be answered within this window and
/// not after; the browser's own `timeout` (60 s) is advisory only.
pub const CEREMONY_TTL_SECS: u64 = 300;

/// Pending ceremonies one authenticated owner (the DID that started them)
/// may hold at once. Generous enough for a few open tabs; an enrolment
/// holds two rows (registration and user verification).
pub const MAX_PENDING_CEREMONIES_PER_OWNER: usize = 8;

/// Pending unauthenticated sign-in ceremonies, across every caller. These
/// have no owner to count against; the per-address limiter in front of the
/// route bounds one caller, and this bounds them all.
pub const MAX_PENDING_ANONYMOUS_CEREMONIES: usize = 1_000;

/// Pending ceremonies of every kind in one keyspace.
pub const MAX_PENDING_CEREMONIES: usize = 2_000;

/// The prefixes whose rows are in-flight ceremony state, each carrying an
/// expiry. [`sweep_expired_ceremonies`] walks these.
const CEREMONY_PREFIXES: [&str; 6] = [
    "pk_reg:",
    "pk_auth:",
    "pk_auth_stepup:",
    "pk_reg_user:",
    "pk_reg_enroll:",
    OWNER_PREFIX,
];

/// Owner index rows: `pk_owner:{owner tag}:{state key}`, one per ceremony
/// state row, so an owner's pending count is a key-only prefix scan.
const OWNER_PREFIX: &str = "pk_owner:";

/// The tag every unauthenticated ceremony is counted under.
const ANONYMOUS_OWNER_TAG: &str = "anon";

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A ceremony row as stored: the value, when it lapses, and (for a state
/// row) whose pending count it is in.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pending<T> {
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    value: T,
}

/// Just the expiry of a ceremony row, read without parsing its value.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Expiry {
    expires_at: u64,
}

/// The owner tag of a DID: a digest, so one DID's prefix is never another
/// DID's (`did:web:a.example` is a prefix of `did:web:a.example:x`).
fn owner_tag(owner: Option<&str>) -> String {
    match owner {
        None => ANONYMOUS_OWNER_TAG.to_string(),
        Some(did) => {
            use sha2::{Digest, Sha256};
            hex::encode(&Sha256::digest(did.as_bytes())[..16])
        }
    }
}

fn owner_prefix(owner: Option<&str>) -> String {
    format!("{OWNER_PREFIX}{}:", owner_tag(owner))
}

fn owner_index_key(owner: Option<&str>, state_key: &str) -> String {
    format!("{}{state_key}", owner_prefix(owner))
}

async fn count_prefix(ks: &KeyspaceHandle, prefix: &str) -> Result<usize, AppError> {
    Ok(ks.prefix_keys(prefix.as_bytes().to_vec()).await?.len())
}

/// Refuse a new ceremony for `owner` when it, or the keyspace, is at its
/// bound. Lapsed rows are swept first, so only live ceremonies count.
///
/// The count and the later write are not one atomic step: concurrent
/// starts can pass the bound by at most their own number, which the
/// per-address limiter in front of every start keeps small.
async fn admit_ceremony(ks: &KeyspaceHandle, owner: Option<&str>) -> Result<(), AppError> {
    let own_prefix = owner_prefix(owner);
    let own_limit = match owner {
        Some(_) => MAX_PENDING_CEREMONIES_PER_OWNER,
        None => MAX_PENDING_ANONYMOUS_CEREMONIES,
    };
    let within = |own: usize, all: usize| own < own_limit && all < MAX_PENDING_CEREMONIES;

    if within(
        count_prefix(ks, &own_prefix).await?,
        count_prefix(ks, OWNER_PREFIX).await?,
    ) {
        return Ok(());
    }
    sweep_expired_ceremonies(ks, now_secs(), &[]).await?;
    let own = count_prefix(ks, &own_prefix).await?;
    let all = count_prefix(ks, OWNER_PREFIX).await?;
    if within(own, all) {
        return Ok(());
    }
    tracing::warn!(
        owner = owner.unwrap_or("<anonymous>"),
        own,
        all,
        "passkey ceremony refused: too many pending"
    );
    if own >= own_limit && owner.is_some() {
        Err(AppError::ServiceError {
            status: axum::http::StatusCode::TOO_MANY_REQUESTS,
            message: "too many passkey ceremonies in progress for this identity; \
                      finish one or wait a few minutes"
                .into(),
        })
    } else {
        Err(AppError::ResourceExhausted(
            "too many passkey ceremonies in progress; try again in a few minutes".into(),
        ))
    }
}

/// Store an in-flight ceremony row at `key`, expiring
/// [`CEREMONY_TTL_SECS`] from now. Read it back with [`take_pending`] or
/// [`get_pending`]; [`sweep_expired_ceremonies`] removes it once lapsed
/// when its prefix is one of the store's own or is passed to the sweep.
///
/// For a host's own pins beside a ceremony (a registration's subject, a
/// revocation's target). Ceremony *state* goes through
/// [`store_registration_state`] / [`store_auth_state`], which also count
/// it against its owner.
pub async fn store_pending<V: Serialize>(
    ks: &KeyspaceHandle,
    key: String,
    value: &V,
) -> Result<(), AppError> {
    write_pending(ks, key, None, value).await
}

async fn write_pending<V: Serialize>(
    ks: &KeyspaceHandle,
    key: String,
    owner: Option<String>,
    value: &V,
) -> Result<(), AppError> {
    let row = Pending {
        expires_at: now_secs().saturating_add(CEREMONY_TTL_SECS),
        owner,
        value,
    };
    ks.insert(key, &row).await
}

/// Store a ceremony state row, counted against `owner` (`None`: an
/// unauthenticated sign-in). The owner index row is written first, so a
/// crash between the two leaves only an index row, which lapses and is
/// swept, never an uncounted ceremony.
async fn store_ceremony_state<V: Serialize>(
    ks: &KeyspaceHandle,
    key: String,
    owner: Option<&str>,
    value: &V,
) -> Result<(), AppError> {
    admit_ceremony(ks, owner).await?;
    let expiry = Expiry {
        expires_at: now_secs().saturating_add(CEREMONY_TTL_SECS),
    };
    ks.insert(
        owner_index_key(owner, &key),
        &serde_json::json!({ "expiresAt": expiry.expires_at }),
    )
    .await?;
    let row = Pending {
        expires_at: expiry.expires_at,
        owner: owner.map(str::to_string),
        value,
    };
    ks.insert(key, &row).await
}

/// Atomically take the ceremony row at `key`. `None` when there is none,
/// when it has lapsed, or when it predates expiring rows; in every case
/// the row is gone afterwards. A state row's owner index row goes with it.
pub async fn take_pending<V: DeserializeOwned>(
    ks: &KeyspaceHandle,
    key: String,
) -> Result<Option<V>, AppError> {
    let Some(bytes) = take_raw(ks, key.clone()).await? else {
        return Ok(None);
    };
    let row = match serde_json::from_slice::<Pending<V>>(&bytes) {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(error = %e, "discarding an unreadable passkey ceremony row");
            return Ok(None);
        }
    };
    if let Some(owner) = row.owner.as_deref() {
        ks.remove(owner_index_key(Some(owner), &key)).await?;
    } else if key.starts_with("pk_reg:") || key.starts_with("pk_auth:") {
        ks.remove(owner_index_key(None, &key)).await?;
    }
    if now_secs() >= row.expires_at {
        return Ok(None);
    }
    Ok(Some(row.value))
}

/// Read the ceremony row at `key` without consuming it. `None` when there
/// is none, when it has lapsed, or when it predates expiring rows.
pub async fn get_pending<V: DeserializeOwned>(
    ks: &KeyspaceHandle,
    key: String,
) -> Result<Option<V>, AppError> {
    let Some(bytes) = ks.get_raw(key).await? else {
        return Ok(None);
    };
    match serde_json::from_slice::<Pending<V>>(&bytes) {
        Ok(row) if now_secs() < row.expires_at => Ok(Some(row.value)),
        Ok(_) => Ok(None),
        Err(e) => {
            tracing::warn!(error = %e, "ignoring an unreadable passkey ceremony row");
            Ok(None)
        }
    }
}

/// Delete every ceremony row that lapsed at or before `now` (seconds since
/// the epoch) under this store's ceremony prefixes and `extra_prefixes`
/// (a host's own [`store_pending`] rows). Returns how many were deleted.
///
/// Each delete is conditional on the row still holding the bytes the
/// sweep read, so a row a finish took in the meantime, or one rewritten
/// since, is left to its new owner: every row is deleted exactly once.
/// A row with no readable expiry predates expiring rows and is deleted.
pub async fn sweep_expired_ceremonies(
    ks: &KeyspaceHandle,
    now: u64,
    extra_prefixes: &[&str],
) -> Result<usize, AppError> {
    let mut removed = 0;
    for prefix in CEREMONY_PREFIXES.iter().chain(extra_prefixes) {
        for (key, value) in ks.prefix_iter_raw(prefix.as_bytes().to_vec()).await? {
            let lapsed = serde_json::from_slice::<Expiry>(&value)
                .map(|e| now >= e.expires_at)
                .unwrap_or(true);
            if !lapsed {
                continue;
            }
            let mut batch = Batch::new();
            batch.require_unchanged(key.clone(), value).remove(key);
            if ks.apply_batch(batch).await?.is_applied() {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One-time enrolment invitation. The `token` is the bearer credential
/// — embedded in the URL the operator clicks. Manual [`std::fmt::Debug`]
/// keeps the diagnostic fields visible while redacting the token, so a
/// stray `tracing::debug!(?enrollment, …)` never leaks it.
#[derive(Serialize, Deserialize)]
pub struct Enrollment {
    pub token: String,
    pub did: String,
    pub role: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// Set when a route handler has begun the WebAuthn ceremony for
    /// this token. Within [`super::ENROLLMENT_CLAIM_WINDOW_SECS`] of
    /// this timestamp, a second concurrent claim is rejected as
    /// "in progress". Only consumed (via [`take_enrollment`]) once
    /// the ceremony successfully completes.
    ///
    /// `#[serde(default)]` for backwards-compat with persisted
    /// enrolments from pre-claim-window deployments.
    #[serde(default)]
    pub claimed_at: Option<u64>,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("token", &"<redacted>")
            .field("did", &self.did)
            .field("role", &self.role)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("claimed_at", &self.claimed_at)
            .finish()
    }
}

/// Binds an in-flight WebAuthn assertion ceremony to the session that started
/// it, for `purpose: stepUp` ceremonies.
///
/// Written by the login/start handler when the caller asks to step up, read by
/// the matching finish. Without it, an assertion challenge minted for one
/// session could be spent to elevate another — the ceremony proves *a* passkey
/// was used, not *whose session* asked for it. The finish handler refuses when
/// the presented session doesn't match both fields.
///
/// Absent for a plain `purpose: login` ceremony, which has no session yet.
#[derive(Debug, Serialize, Deserialize)]
pub struct StepUpBinding {
    /// The session the elevation applies to.
    pub session_id: String,
    /// The subject that session authenticated as. Checked alongside
    /// `session_id` so a recycled id can't carry an elevation across subjects.
    pub did: String,
}

/// Maps a credential id (hex-encoded) to the owning user UUID. Lets
/// `login_finish` find the right `PasskeyUser` without scanning.
#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialMapping {
    pub user_uuid: Uuid,
}

/// A passkey user. May have multiple credentials (one per registered
/// device). Updated on every successful enrolment + login.
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyUser {
    pub user_uuid: Uuid,
    pub did: String,
    pub display_name: String,
    pub credentials: Vec<Passkey>,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

fn enrollment_key(token: &str) -> String {
    format!("enroll:{token}")
}

fn registration_state_key(id: &str) -> String {
    format!("pk_reg:{id}")
}

fn auth_state_key(id: &str) -> String {
    format!("pk_auth:{id}")
}

fn auth_step_up_key(id: &str) -> String {
    format!("pk_auth_stepup:{id}")
}

fn registration_user_key(reg_id: &str) -> String {
    format!("pk_reg_user:{reg_id}")
}

/// Maps a registration_id to the enrolment token that authorised it.
/// Used by `enroll_finish` to consume the enrolment **after** the
/// WebAuthn ceremony succeeds — so a failed ceremony (browser closed,
/// key not present, RP mismatch, decline-after-click) leaves the
/// invite intact for the legitimate user to retry.
fn registration_enrollment_key(reg_id: &str) -> String {
    format!("pk_reg_enroll:{reg_id}")
}

fn credential_mapping_key(cred_id_hex: &str) -> String {
    format!("pk_cred:{cred_id_hex}")
}

fn passkey_user_key(uuid: &Uuid) -> String {
    format!("pk_user:{uuid}")
}

fn passkey_did_key(did: &str) -> String {
    format!("pk_did:{did}")
}

// ---------------------------------------------------------------------------
// `take` helpers — atomic get + remove (see module docs)
// ---------------------------------------------------------------------------

async fn take<V>(ks: &KeyspaceHandle, key: String) -> Result<Option<V>, AppError>
where
    V: DeserializeOwned + Send + 'static,
{
    match take_raw(ks, key).await? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        None => Ok(None),
    }
}

async fn take_raw(ks: &KeyspaceHandle, key: String) -> Result<Option<Vec<u8>>, AppError> {
    ks.take_raw(key.into_bytes()).await
}

// ---------------------------------------------------------------------------
// Enrolment CRUD
// ---------------------------------------------------------------------------

pub async fn store_enrollment(
    ks: &KeyspaceHandle,
    enrollment: &Enrollment,
) -> Result<(), AppError> {
    ks.insert(enrollment_key(&enrollment.token), enrollment)
        .await
}

/// Atomically (per the module's `take` semantics) retrieve and delete
/// an enrolment by token. Returns `None` if already consumed.
pub async fn take_enrollment(
    ks: &KeyspaceHandle,
    token: &str,
) -> Result<Option<Enrollment>, AppError> {
    take(ks, enrollment_key(token)).await
}

/// Retrieve an enrolment by token **without** consuming it. Used by
/// admin management endpoints (list / update) and by `enroll_start`,
/// which only sets `claimed_at`.
pub async fn get_enrollment(
    ks: &KeyspaceHandle,
    token: &str,
) -> Result<Option<Enrollment>, AppError> {
    ks.get(enrollment_key(token)).await
}

/// List every enrolment currently in the store. Silently skips
/// entries that fail to deserialise (corrupt / old schema) so a
/// single bad row doesn't hide the rest from admins.
pub async fn list_enrollments(ks: &KeyspaceHandle) -> Result<Vec<Enrollment>, AppError> {
    let pairs = ks.prefix_iter_raw(b"enroll:".to_vec()).await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (_key, value) in pairs {
        match serde_json::from_slice::<Enrollment>(&value) {
            Ok(e) => out.push(e),
            Err(e) => tracing::warn!(error = %e, "skipping unparseable enrollment entry"),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Registration state (in-flight WebAuthn ceremony state)
// ---------------------------------------------------------------------------

/// Store a registration ceremony's state for [`CEREMONY_TTL_SECS`],
/// counted against `owner` — the authenticated DID that started it, or
/// `None` for a start with no session. Refused when that owner or the
/// keyspace already holds its bound of pending ceremonies (see the module
/// docs).
pub async fn store_registration_state(
    ks: &KeyspaceHandle,
    id: &str,
    owner: Option<&str>,
    state: &PasskeyRegistration,
) -> Result<(), AppError> {
    store_ceremony_state(ks, registration_state_key(id), owner, state).await
}

/// Take a registration ceremony's state. `None` if absent, already taken,
/// or lapsed.
pub async fn take_registration_state(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<PasskeyRegistration>, AppError> {
    take_pending(ks, registration_state_key(id)).await
}

// ---------------------------------------------------------------------------
// Authentication state (in-flight WebAuthn ceremony state)
// ---------------------------------------------------------------------------

/// Store an assertion ceremony's state for [`CEREMONY_TTL_SECS`], counted
/// against `owner` as [`store_registration_state`] is.
pub async fn store_auth_state(
    ks: &KeyspaceHandle,
    id: &str,
    owner: Option<&str>,
    state: &PasskeyAuthentication,
) -> Result<(), AppError> {
    store_ceremony_state(ks, auth_state_key(id), owner, state).await
}

/// Take an assertion ceremony's state. `None` if absent, already taken,
/// or lapsed.
pub async fn take_auth_state(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<PasskeyAuthentication>, AppError> {
    take_pending(ks, auth_state_key(id)).await
}

/// Record that this assertion ceremony is a step-up for a specific session.
/// Keyed by the same `auth_id` as the ceremony state, so the two are consumed
/// together at finish. Lapses with it.
pub async fn store_auth_step_up(
    ks: &KeyspaceHandle,
    id: &str,
    binding: &StepUpBinding,
) -> Result<(), AppError> {
    store_pending(ks, auth_step_up_key(id), binding).await
}

/// Consume the step-up binding for `id`. `None` means the ceremony was started
/// as a plain login, so the finish handler must not elevate anything.
pub async fn take_auth_step_up(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<StepUpBinding>, AppError> {
    take_pending(ks, auth_step_up_key(id)).await
}

// ---------------------------------------------------------------------------
// Registration-to-user mapping (links reg_id to user UUID during the ceremony)
// ---------------------------------------------------------------------------

pub async fn store_registration_user(
    ks: &KeyspaceHandle,
    reg_id: &str,
    user_uuid: &Uuid,
) -> Result<(), AppError> {
    store_pending(ks, registration_user_key(reg_id), user_uuid).await
}

/// The user a registration ceremony is for. `None` if absent or lapsed.
pub async fn get_registration_user(
    ks: &KeyspaceHandle,
    reg_id: &str,
) -> Result<Option<Uuid>, AppError> {
    get_pending(ks, registration_user_key(reg_id)).await
}

pub async fn delete_registration_user(ks: &KeyspaceHandle, reg_id: &str) -> Result<(), AppError> {
    ks.remove(registration_user_key(reg_id)).await
}

// ---------------------------------------------------------------------------
// Registration-to-enrolment-token mapping (defer-take semantics)
// ---------------------------------------------------------------------------

/// Persist the enrolment token that authorised a registration
/// ceremony so `enroll_finish` can consume it after the WebAuthn
/// ceremony succeeds. A failed ceremony never reaches finish and the
/// invite stays intact. Lapses with the ceremony.
pub async fn store_registration_enrollment(
    ks: &KeyspaceHandle,
    reg_id: &str,
    enrollment_token: &str,
) -> Result<(), AppError> {
    store_pending(ks, registration_enrollment_key(reg_id), &enrollment_token).await
}

pub async fn take_registration_enrollment(
    ks: &KeyspaceHandle,
    reg_id: &str,
) -> Result<Option<String>, AppError> {
    take_pending(ks, registration_enrollment_key(reg_id)).await
}

// ---------------------------------------------------------------------------
// PasskeyUser CRUD
// ---------------------------------------------------------------------------

pub async fn store_passkey_user(ks: &KeyspaceHandle, user: &PasskeyUser) -> Result<(), AppError> {
    ks.insert(passkey_user_key(&user.user_uuid), user).await?;
    // Maintain DID → user UUID reverse index so `get_passkey_user_by_did`
    // can be O(1) instead of a full prefix scan.
    ks.insert_raw(
        passkey_did_key(&user.did),
        user.user_uuid.to_string().into_bytes(),
    )
    .await
}

pub async fn get_passkey_user(
    ks: &KeyspaceHandle,
    uuid: &Uuid,
) -> Result<Option<PasskeyUser>, AppError> {
    ks.get(passkey_user_key(uuid)).await
}

/// Find a [`PasskeyUser`] by credential id (the hex-encoded value the
/// authenticator returned on a successful ceremony).
pub async fn get_passkey_user_by_cred(
    ks: &KeyspaceHandle,
    cred_id_hex: &str,
) -> Result<Option<PasskeyUser>, AppError> {
    let mapping: Option<CredentialMapping> = ks.get(credential_mapping_key(cred_id_hex)).await?;
    match mapping {
        Some(m) => get_passkey_user(ks, &m.user_uuid).await,
        None => Ok(None),
    }
}

/// Find a [`PasskeyUser`] by DID. Tries the `pk_did:` reverse index
/// first, falls back to a linear scan for pre-index data.
pub async fn get_passkey_user_by_did(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<PasskeyUser>, AppError> {
    if let Some(bytes) = ks.get_raw(passkey_did_key(did)).await? {
        let uuid_str = String::from_utf8(bytes)
            .map_err(|e| AppError::Internal(format!("invalid DID index UUID: {e}")))?;
        let uuid = Uuid::parse_str(&uuid_str)
            .map_err(|e| AppError::Internal(format!("invalid DID index UUID: {e}")))?;
        if let Some(user) = get_passkey_user(ks, &uuid).await? {
            return Ok(Some(user));
        }
    }

    // Fallback for any rows persisted before the reverse index existed.
    let entries = ks.prefix_iter_raw(b"pk_user:".to_vec()).await?;
    for (_key, value) in entries {
        if let Ok(user) = serde_json::from_slice::<PasskeyUser>(&value)
            && user.did == did
        {
            return Ok(Some(user));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Credential mapping
// ---------------------------------------------------------------------------

pub async fn store_credential_mapping(
    ks: &KeyspaceHandle,
    cred_id_hex: &str,
    user_uuid: Uuid,
) -> Result<(), AppError> {
    let mapping = CredentialMapping { user_uuid };
    ks.insert(credential_mapping_key(cred_id_hex), &mapping)
        .await
}

/// Collect every stored passkey for discoverable-credential login.
/// Scans the `pk_user:` prefix and flattens out each user's
/// credentials. Tolerates corrupt rows the same way [`list_enrollments`]
/// does.
pub async fn get_all_passkeys(ks: &KeyspaceHandle) -> Result<Vec<Passkey>, AppError> {
    let entries = ks.prefix_iter_raw(b"pk_user:".to_vec()).await?;
    let mut passkeys = Vec::new();
    for (_key, value) in entries {
        if let Ok(user) = serde_json::from_slice::<PasskeyUser>(&value) {
            passkeys.extend(user.credentials);
        }
    }
    Ok(passkeys)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let ks = store.keyspace("passkey-test").expect("keyspace");
        (ks, dir)
    }

    fn sample_enrollment() -> Enrollment {
        Enrollment {
            token: "abcd1234".into(),
            did: "did:key:z6Mk".into(),
            role: "admin".into(),
            created_at: 100,
            expires_at: 200,
            claimed_at: None,
        }
    }

    #[test]
    fn enrollment_debug_redacts_token() {
        let e = sample_enrollment();
        let s = format!("{e:?}");
        assert!(!s.contains("abcd1234"), "raw token leaked: {s}");
        assert!(s.contains("<redacted>"), "redaction marker missing: {s}");
        // Diagnostic fields stay visible.
        assert!(s.contains("did:key:z6Mk"));
        assert!(s.contains("admin"));
    }

    #[tokio::test]
    async fn enrollment_roundtrip() {
        let (ks, _dir) = temp_ks();
        let e = sample_enrollment();

        store_enrollment(&ks, &e).await.unwrap();
        let got = get_enrollment(&ks, &e.token).await.unwrap().expect("found");
        assert_eq!(got.did, e.did);
        assert_eq!(got.role, e.role);

        // Take consumes.
        let taken = take_enrollment(&ks, &e.token)
            .await
            .unwrap()
            .expect("taken");
        assert_eq!(taken.token, e.token);
        let after = get_enrollment(&ks, &e.token).await.unwrap();
        assert!(after.is_none(), "take did not consume");

        // Second take returns None — protects ceremony-finish from races.
        let again = take_enrollment(&ks, &e.token).await.unwrap();
        assert!(again.is_none());
    }

    /// Two finish-ceremony calls racing on one enrolment: exactly one takes
    /// it. A get-then-remove let several consume a single-use invite.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_takes_consume_an_enrollment_exactly_once() {
        let (ks, _dir) = temp_ks();
        for _ in 0..40 {
            store_enrollment(&ks, &sample_enrollment()).await.unwrap();
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(16));
            let mut tasks = Vec::new();
            for _ in 0..16 {
                let (ks, barrier) = (ks.clone(), barrier.clone());
                tasks.push(tokio::spawn(async move {
                    barrier.wait().await;
                    take_enrollment(&ks, "abcd1234").await.unwrap().is_some()
                }));
            }
            let mut taken = 0;
            for t in tasks {
                taken += t.await.unwrap() as usize;
            }
            assert_eq!(taken, 1, "an enrolment must be consumed exactly once");
        }
    }

    #[tokio::test]
    async fn registration_enrollment_mapping_roundtrip() {
        let (ks, _dir) = temp_ks();
        store_registration_enrollment(&ks, "reg-1", "tok-abc")
            .await
            .unwrap();
        let taken = take_registration_enrollment(&ks, "reg-1").await.unwrap();
        assert_eq!(taken.as_deref(), Some("tok-abc"));
        // Idempotent second take.
        let again = take_registration_enrollment(&ks, "reg-1").await.unwrap();
        assert!(again.is_none());
    }

    #[tokio::test]
    async fn registration_user_mapping_roundtrip() {
        let (ks, _dir) = temp_ks();
        let uuid = Uuid::new_v4();
        store_registration_user(&ks, "reg-1", &uuid).await.unwrap();
        let got = get_registration_user(&ks, "reg-1").await.unwrap();
        assert_eq!(got, Some(uuid));
        delete_registration_user(&ks, "reg-1").await.unwrap();
        let gone = get_registration_user(&ks, "reg-1").await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn passkey_user_roundtrip_by_uuid_and_did() {
        let (ks, _dir) = temp_ks();
        let uuid = Uuid::new_v4();
        let user = PasskeyUser {
            user_uuid: uuid,
            did: "did:key:z6Mk1".into(),
            display_name: "did:key:z6Mk1".into(),
            credentials: Vec::new(),
        };

        store_passkey_user(&ks, &user).await.unwrap();

        let by_uuid = get_passkey_user(&ks, &uuid)
            .await
            .unwrap()
            .expect("by uuid");
        assert_eq!(by_uuid.did, user.did);

        let by_did = get_passkey_user_by_did(&ks, &user.did)
            .await
            .unwrap()
            .expect("by did");
        assert_eq!(by_did.user_uuid, uuid);

        let absent = get_passkey_user_by_did(&ks, "did:key:nope").await.unwrap();
        assert!(absent.is_none());
    }

    #[tokio::test]
    async fn credential_mapping_resolves_to_user() {
        let (ks, _dir) = temp_ks();
        let uuid = Uuid::new_v4();
        let user = PasskeyUser {
            user_uuid: uuid,
            did: "did:key:z6Mk2".into(),
            display_name: "did:key:z6Mk2".into(),
            credentials: Vec::new(),
        };
        store_passkey_user(&ks, &user).await.unwrap();
        store_credential_mapping(&ks, "deadbeef", uuid)
            .await
            .unwrap();

        let got = get_passkey_user_by_cred(&ks, "deadbeef")
            .await
            .unwrap()
            .expect("user");
        assert_eq!(got.user_uuid, uuid);

        let missing = get_passkey_user_by_cred(&ks, "0000").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn list_enrollments_returns_all() {
        let (ks, _dir) = temp_ks();
        for token in ["t1", "t2", "t3"] {
            let mut e = sample_enrollment();
            e.token = token.into();
            store_enrollment(&ks, &e).await.unwrap();
        }
        let all = list_enrollments(&ks).await.unwrap();
        assert_eq!(all.len(), 3);
    }

    // ── In-flight ceremony lifetime and bounds ──────────────────────────

    /// Write a ceremony row as `store_ceremony_state` does, but lapsed.
    async fn store_lapsed_state(ks: &KeyspaceHandle, key: &str, owner: Option<&str>) {
        let past = now_secs() - 1;
        ks.insert(
            owner_index_key(owner, key),
            &serde_json::json!({ "expiresAt": past }),
        )
        .await
        .unwrap();
        ks.insert(
            key.to_string(),
            &Pending {
                expires_at: past,
                owner: owner.map(str::to_string),
                value: "state",
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_lapsed_ceremony_is_not_returned_and_is_gone_after_the_take() {
        let (ks, _dir) = temp_ks();
        store_lapsed_state(&ks, "pk_auth:old", Some("did:key:zA")).await;
        let taken: Option<String> = take_pending(&ks, "pk_auth:old".into()).await.unwrap();
        assert!(taken.is_none(), "a lapsed challenge must not be redeemable");
        assert!(ks.get_raw("pk_auth:old").await.unwrap().is_none());
        assert!(
            ks.prefix_keys(owner_prefix(Some("did:key:zA")).into_bytes())
                .await
                .unwrap()
                .is_empty(),
            "its owner count is released with it"
        );
    }

    #[tokio::test]
    async fn a_live_ceremony_is_taken_once() {
        let (ks, _dir) = temp_ks();
        store_ceremony_state(&ks, "pk_auth:live".into(), None, &"state")
            .await
            .unwrap();
        let first: Option<String> = take_pending(&ks, "pk_auth:live".into()).await.unwrap();
        assert_eq!(first.as_deref(), Some("state"));
        let second: Option<String> = take_pending(&ks, "pk_auth:live".into()).await.unwrap();
        assert!(second.is_none());
        assert!(
            ks.prefix_keys(OWNER_PREFIX.as_bytes().to_vec())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_row_written_before_ceremonies_expired_authorises_nothing() {
        let (ks, _dir) = temp_ks();
        // The pre-expiry layout: the bare state, no envelope.
        ks.insert(
            "pk_auth_stepup:legacy",
            &serde_json::json!({"session_id": "s", "did": "d"}),
        )
        .await
        .unwrap();
        assert!(take_auth_step_up(&ks, "legacy").await.unwrap().is_none());
        ks.insert_raw(
            "pk_reg_user:legacy",
            Uuid::new_v4().to_string().into_bytes(),
        )
        .await
        .unwrap();
        assert!(
            get_registration_user(&ks, "legacy")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            sweep_expired_ceremonies(&ks, now_secs(), &[])
                .await
                .unwrap(),
            1
        );
        assert!(ks.get_raw("pk_reg_user:legacy").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_sweep_removes_lapsed_rows_and_keeps_live_ones() {
        let (ks, _dir) = temp_ks();
        store_lapsed_state(&ks, "pk_reg:old", Some("did:key:zA")).await;
        store_ceremony_state(&ks, "pk_reg:new".into(), Some("did:key:zA"), &"state")
            .await
            .unwrap();
        store_pending(&ks, "host_pin:new".into(), &"pin")
            .await
            .unwrap();
        ks.insert(
            "host_pin:old",
            &Pending {
                expires_at: 1,
                owner: None,
                value: "pin",
            },
        )
        .await
        .unwrap();

        // The lapsed state row, its owner row and the host's lapsed pin.
        let removed = sweep_expired_ceremonies(&ks, now_secs(), &["host_pin:"])
            .await
            .unwrap();
        assert_eq!(removed, 3);
        assert!(ks.get_raw("pk_reg:new").await.unwrap().is_some());
        assert!(ks.get_raw("host_pin:new").await.unwrap().is_some());
        assert!(ks.get_raw("host_pin:old").await.unwrap().is_none());
        assert_eq!(
            sweep_expired_ceremonies(&ks, now_secs(), &["host_pin:"])
                .await
                .unwrap(),
            0
        );
    }

    /// A sweep racing a finish over the same lapsed-at-sweep-time rows: each
    /// row is deleted by exactly one of them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_sweep_and_a_take_delete_each_row_exactly_once() {
        let (ks, _dir) = temp_ks();
        for round in 0..20 {
            let keys: Vec<String> = (0..8).map(|i| format!("pk_auth:r{round}-{i}")).collect();
            for key in &keys {
                store_ceremony_state(&ks, key.clone(), None, &"state")
                    .await
                    .unwrap();
            }
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(keys.len() + 1));
            let sweeper = {
                let (ks, barrier) = (ks.clone(), barrier.clone());
                tokio::spawn(async move {
                    barrier.wait().await;
                    // Every row counts as lapsed to this sweep.
                    sweep_expired_ceremonies(&ks, u64::MAX, &[]).await.unwrap()
                })
            };
            let mut takers = Vec::new();
            for key in keys.clone() {
                let (ks, barrier) = (ks.clone(), barrier.clone());
                takers.push(tokio::spawn(async move {
                    barrier.wait().await;
                    ks.take_raw(key.into_bytes()).await.unwrap().is_some()
                }));
            }
            let mut taken = 0;
            for t in takers {
                taken += t.await.unwrap() as usize;
            }
            let swept = sweeper.await.unwrap();
            // The sweep also removes the eight owner index rows.
            assert_eq!(taken + swept, keys.len() * 2, "round {round}");
            for key in &keys {
                assert!(ks.get_raw(key.clone()).await.unwrap().is_none());
            }
        }
    }

    #[tokio::test]
    async fn one_owner_is_held_to_its_bound_and_others_are_not() {
        let (ks, _dir) = temp_ks();
        for i in 0..MAX_PENDING_CEREMONIES_PER_OWNER {
            store_ceremony_state(&ks, format!("pk_auth:a{i}"), Some("did:key:zA"), &"s")
                .await
                .unwrap();
        }
        let refused = store_ceremony_state(&ks, "pk_auth:over".into(), Some("did:key:zA"), &"s")
            .await
            .unwrap_err();
        assert!(
            matches!(&refused, AppError::ServiceError { status, .. }
                if *status == axum::http::StatusCode::TOO_MANY_REQUESTS),
            "{refused:?}"
        );
        assert!(ks.get_raw("pk_auth:over").await.unwrap().is_none());

        // Another owner, and the anonymous owner, are unaffected.
        store_ceremony_state(&ks, "pk_auth:b".into(), Some("did:key:zB"), &"s")
            .await
            .unwrap();
        store_ceremony_state(&ks, "pk_auth:anon".into(), None, &"s")
            .await
            .unwrap();

        // Finishing one frees a place.
        let _: Option<String> = take_pending(&ks, "pk_auth:a0".into()).await.unwrap();
        store_ceremony_state(&ks, "pk_auth:again".into(), Some("did:key:zA"), &"s")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn lapsed_ceremonies_do_not_count_against_the_bound() {
        let (ks, _dir) = temp_ks();
        for i in 0..MAX_PENDING_CEREMONIES_PER_OWNER {
            store_lapsed_state(&ks, &format!("pk_auth:a{i}"), Some("did:key:zA")).await;
        }
        store_ceremony_state(&ks, "pk_auth:fresh".into(), Some("did:key:zA"), &"s")
            .await
            .expect("lapsed ceremonies are swept before a start is refused");
    }

    #[tokio::test]
    async fn unauthenticated_starts_are_bounded_together() {
        let (ks, _dir) = temp_ks();
        for i in 0..MAX_PENDING_ANONYMOUS_CEREMONIES {
            store_ceremony_state(&ks, format!("pk_auth:n{i}"), None, &"s")
                .await
                .unwrap();
        }
        let refused = store_ceremony_state(&ks, "pk_auth:over".into(), None, &"s")
            .await
            .unwrap_err();
        assert!(
            matches!(refused, AppError::ResourceExhausted(_)),
            "{refused:?}"
        );
        // An authenticated owner still has room: the anonymous bound is
        // below the keyspace's.
        store_ceremony_state(&ks, "pk_auth:owned".into(), Some("did:key:zA"), &"s")
            .await
            .unwrap();
    }

    #[test]
    fn one_did_never_counts_against_another_that_extends_it() {
        let a = owner_prefix(Some("did:web:a.example"));
        let b = owner_index_key(Some("did:web:a.example:x"), "pk_auth:1");
        assert!(!b.starts_with(&a));
        assert_ne!(owner_prefix(None), owner_prefix(Some("anon")));
    }
}
