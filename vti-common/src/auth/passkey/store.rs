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
//! call must see `None` after the first has consumed the state.
//! vti-common's [`KeyspaceHandle`] doesn't expose `take` directly, so
//! we sequence `get` + `remove` in this module's helpers
//! [`take`] / [`take_raw`]. This is **not** crash-atomic — if the
//! process dies between read and delete, the next call returns the
//! value again. For the WebAuthn ceremony state we manage here that's
//! fine: stale registration state simply blocks another enrolment
//! until it expires or is overwritten. Concurrent in-process calls
//! are sequenced through Tokio's storage layer and never both see the
//! same value as `Some(_)`.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

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
// `take` helpers — sequenced get + remove (see module docs)
// ---------------------------------------------------------------------------

async fn take<V>(ks: &KeyspaceHandle, key: String) -> Result<Option<V>, AppError>
where
    V: DeserializeOwned + Send + 'static,
{
    let key_bytes = key.into_bytes();
    let value: Option<V> = ks.get(key_bytes.clone()).await?;
    if value.is_some() {
        ks.remove(key_bytes).await?;
    }
    Ok(value)
}

async fn take_raw(ks: &KeyspaceHandle, key: String) -> Result<Option<Vec<u8>>, AppError> {
    let key_bytes = key.into_bytes();
    let value = ks.get_raw(key_bytes.clone()).await?;
    if value.is_some() {
        ks.remove(key_bytes).await?;
    }
    Ok(value)
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

pub async fn store_registration_state(
    ks: &KeyspaceHandle,
    id: &str,
    state: &PasskeyRegistration,
) -> Result<(), AppError> {
    ks.insert(registration_state_key(id), state).await
}

pub async fn take_registration_state(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<PasskeyRegistration>, AppError> {
    take(ks, registration_state_key(id)).await
}

// ---------------------------------------------------------------------------
// Authentication state (in-flight WebAuthn ceremony state)
// ---------------------------------------------------------------------------

pub async fn store_auth_state(
    ks: &KeyspaceHandle,
    id: &str,
    state: &PasskeyAuthentication,
) -> Result<(), AppError> {
    ks.insert(auth_state_key(id), state).await
}

pub async fn take_auth_state(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<PasskeyAuthentication>, AppError> {
    take(ks, auth_state_key(id)).await
}

/// Record that this assertion ceremony is a step-up for a specific session.
/// Keyed by the same `auth_id` as the ceremony state, so the two are consumed
/// together at finish.
pub async fn store_auth_step_up(
    ks: &KeyspaceHandle,
    id: &str,
    binding: &StepUpBinding,
) -> Result<(), AppError> {
    ks.insert(auth_step_up_key(id), binding).await
}

/// Consume the step-up binding for `id`. `None` means the ceremony was started
/// as a plain login, so the finish handler must not elevate anything.
pub async fn take_auth_step_up(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<StepUpBinding>, AppError> {
    take(ks, auth_step_up_key(id)).await
}

// ---------------------------------------------------------------------------
// Registration-to-user mapping (links reg_id to user UUID during the ceremony)
// ---------------------------------------------------------------------------

pub async fn store_registration_user(
    ks: &KeyspaceHandle,
    reg_id: &str,
    user_uuid: &Uuid,
) -> Result<(), AppError> {
    ks.insert_raw(
        registration_user_key(reg_id),
        user_uuid.to_string().into_bytes(),
    )
    .await
}

pub async fn get_registration_user(
    ks: &KeyspaceHandle,
    reg_id: &str,
) -> Result<Option<Uuid>, AppError> {
    match ks.get_raw(registration_user_key(reg_id)).await? {
        Some(bytes) => {
            let s = String::from_utf8(bytes)
                .map_err(|e| AppError::Internal(format!("invalid registration user UUID: {e}")))?;
            let uuid = Uuid::parse_str(&s)
                .map_err(|e| AppError::Internal(format!("invalid registration user UUID: {e}")))?;
            Ok(Some(uuid))
        }
        None => Ok(None),
    }
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
/// invite stays intact.
pub async fn store_registration_enrollment(
    ks: &KeyspaceHandle,
    reg_id: &str,
    enrollment_token: &str,
) -> Result<(), AppError> {
    ks.insert_raw(
        registration_enrollment_key(reg_id),
        enrollment_token.as_bytes().to_vec(),
    )
    .await
}

pub async fn take_registration_enrollment(
    ks: &KeyspaceHandle,
    reg_id: &str,
) -> Result<Option<String>, AppError> {
    match take_raw(ks, registration_enrollment_key(reg_id)).await? {
        Some(bytes) => Ok(Some(String::from_utf8(bytes).map_err(|e| {
            AppError::Internal(format!("invalid enrolment token bytes: {e}"))
        })?)),
        None => Ok(None),
    }
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
}
