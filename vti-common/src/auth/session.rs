use crate::error::AppError;
use crate::store::KeyspaceHandle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Session lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SessionState {
    ChallengeSent,
    Authenticated,
}

/// A session record stored in fjall under `session:{session_id}`.
///
/// `Debug` is hand-written below to redact the `refresh_token`. The raw
/// derive would render it inline — any `tracing::debug!("{session:?}")`,
/// panic backtrace, or `dbg!()` call holding a `Session` would otherwise
/// exfiltrate a bearer-equivalent secret to logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub did: String,
    pub challenge: String,
    pub state: SessionState,
    pub created_at: u64,
    /// Wall-clock epoch seconds of the most recent authenticated request on
    /// this session. Intrinsic-sender (DIDComm/TSP) sessions carry no refresh
    /// token, so this drives their idle-TTL expiry in
    /// [`cleanup_expired_sessions`]. REST sessions set it too but are bounded
    /// by `refresh_expires_at`. `#[serde(default)]` so rows written before this
    /// field existed deserialise with `0`; the sweeper falls back to
    /// `created_at` in that case.
    #[serde(default)]
    pub last_seen: u64,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<u64>,
    /// Whether the **challenge issued for this session** was accompanied
    /// by a successful TEE attestation. Distinct from "this VTA was built
    /// with the TEE feature": a TEE binary running in `TeeMode::Optional`
    /// can serve unattested challenges when the provider errors out, and
    /// the resulting JWT must reflect that.
    ///
    /// `#[serde(default)]` so older session records (written before this
    /// field existed) deserialize as `false` — the conservative default.
    #[serde(default)]
    pub tee_attested: bool,
    /// AAL claims persisted across token rotation. Mirrors the JWT's
    /// `amr` / `acr` so [`/auth/refresh`] mints a new access token at
    /// the same authentication-method-references and assurance level
    /// the session was last issued at. Without this, a session that
    /// was step-upped to `aal2` would be silently dropped back to
    /// `aal1` on every 15-minute refresh.
    ///
    /// `#[serde(default)]` on both: a session row written before this
    /// field landed deserialises with empty vectors / empty string,
    /// which the refresh handler treats as "unknown AAL — fall back
    /// to `aal1`". Same behaviour as pre-migration; the holder can
    /// re-step-up if needed.
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: String,
    /// Epoch-seconds deadline after which a step-up-elevated `acr` lapses back
    /// to `aal1`. Set when a step-up elevates the session; read by the
    /// intrinsic-sender resolver ([`resolve_did_session`]), which downgrades on
    /// read once the window closes. `None` for an un-elevated session — and, in
    /// this phase, for REST sessions, whose short access-token TTL already
    /// bounds elevation (a later phase wires REST into the same read-time
    /// downgrade). `#[serde(default)]` for back-compat with pre-existing rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr_expires_at: Option<u64>,
    /// JWT `jti` rotation pin. Set per-token-issue so old JWTs are
    /// immediately invalidated when a new token is minted for the
    /// same session — the `AuthClaims` extractor compares the JWT's
    /// `jti` against this field and rejects mismatches.
    ///
    /// Optional because not every consumer uses per-token-issue
    /// rotation; the canonical extractor checks this only when
    /// `Some(_)`. `#[skip_serializing_if = "Option::is_none"]`
    /// keeps the field out of the serialised form when unused so
    /// existing storage rows do not gain a `token_id: null` column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// Ephemeral session pubkey for Data Integrity proof binding
    /// (`eddsa-jcs-2022`). Ed25519 multikey, base58btc with the
    /// `z` prefix (e.g. `z6MkfBwQrx…`). The corresponding
    /// `did:key:<this>` is the verificationMethod the holder uses
    /// when signing trust-task envelopes for this session.
    ///
    /// `None` for clients that did not register a session pubkey;
    /// REQUIRED-spec dispatch then rejects proofless envelopes per
    /// the trust-task framework's IS_PROOF_REQUIRED gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_pubkey_b58btc: Option<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("did", &self.did)
            .field("challenge", &"<redacted>")
            .field("state", &self.state)
            .field("created_at", &self.created_at)
            .field("last_seen", &self.last_seen)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("tee_attested", &self.tee_attested)
            .field("amr", &self.amr)
            .field("acr", &self.acr)
            .field("acr_expires_at", &self.acr_expires_at)
            .field("token_id", &self.token_id.as_ref().map(|_| "<redacted>"))
            .field("session_pubkey_b58btc", &self.session_pubkey_b58btc)
            .finish()
    }
}

fn session_key(session_id: &str) -> String {
    format!("session:{session_id}")
}

/// Key the refresh-token reverse-index by SHA-256 of the token rather
/// than the token itself. An attacker with raw read access to the
/// sessions keyspace (storage dump, vsock proxy compromise) sees only
/// hashes, not live tokens. The lookup path hashes the presented token
/// before probing the store.
///
/// Hash length (32 bytes → 64 hex chars) is fine for collision
/// resistance; UUIDv4 refresh tokens have 122 bits of entropy, so
/// pre-image resistance is what we rely on here, not second-preimage.
fn refresh_key(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("refresh:{}", hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

/// Store a new session in the `sessions` keyspace.
pub async fn store_session(sessions: &KeyspaceHandle, session: &Session) -> Result<(), AppError> {
    sessions
        .insert(session_key(&session.session_id), session)
        .await?;
    debug!(session_id = %session.session_id, did = %session.did, "session stored");
    Ok(())
}

/// Load a session by session_id.
pub async fn get_session(
    sessions: &KeyspaceHandle,
    session_id: &str,
) -> Result<Option<Session>, AppError> {
    sessions.get(session_key(session_id)).await
}

/// Update an existing session (overwrites).
pub async fn update_session(sessions: &KeyspaceHandle, session: &Session) -> Result<(), AppError> {
    sessions
        .insert(session_key(&session.session_id), session)
        .await
}

/// Idle lifetime for an intrinsic-sender (DIDComm/TSP) session. Such a session
/// carries no refresh token, so it is reaped this many seconds after its last
/// authenticated request rather than at a refresh-token deadline. REST sessions
/// are bounded by `refresh_expires_at` and ignore this.
pub const INTRINSIC_SESSION_IDLE_TTL_SECS: u64 = 86_400; // 24h

/// Resolve the canonical session for an intrinsic-sender (DIDComm/TSP) caller,
/// creating it on first sight. Keyed on the authenticated `did` so the same
/// identity resolves **one** persistent session across messages and transports.
/// That persistence is what lets a step-up elevation performed while handling
/// one message be observed by the caller's subsequent messages — the whole
/// point of a transport-agnostic session.
///
/// Semantics:
/// - **Absent** → create an `Authenticated`, `aal1` session (single `did`
///   factor), stamped `created_at = last_seen = now`, no refresh token.
/// - **Present** → bump `last_seen`; if a step-up elevation has lapsed
///   (`acr_expires_at` now in the past) downgrade `acr` back to `aal1` and drop
///   the elevated factors, so the caller must re-step-up.
///
/// Returns the session as the caller should be seen *now* (post-downgrade) and
/// persists any mutation. The returned `acr`/`amr` are what the AAL-gating
/// handlers must trust — not a hardcoded `aal1`.
pub async fn resolve_did_session(
    sessions: &KeyspaceHandle,
    did: &str,
    now: u64,
) -> Result<Session, AppError> {
    if let Some(mut session) = get_session(sessions, did).await? {
        session.last_seen = now;
        if let Some(deadline) = session.acr_expires_at
            && now >= deadline
        {
            session.acr = "aal1".to_string();
            session.acr_expires_at = None;
            session.amr = vec!["did".to_string()];
        }
        update_session(sessions, &session).await?;
        Ok(session)
    } else {
        let session = Session {
            session_id: did.to_string(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now,
            last_seen: now,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec!["did".to_string()],
            acr: "aal1".to_string(),
            acr_expires_at: None,
            token_id: None,
            session_pubkey_b58btc: None,
        };
        store_session(sessions, &session).await?;
        Ok(session)
    }
}

/// Store a reverse index from refresh token to session_id.
pub async fn store_refresh_index(
    sessions: &KeyspaceHandle,
    token: &str,
    session_id: &str,
) -> Result<(), AppError> {
    sessions
        .insert_raw(refresh_key(token), session_id.as_bytes().to_vec())
        .await
}

/// Look up a session_id by refresh token.
pub async fn get_session_by_refresh(
    sessions: &KeyspaceHandle,
    token: &str,
) -> Result<Option<String>, AppError> {
    match sessions.get_raw(refresh_key(token)).await? {
        Some(bytes) => {
            let session_id = String::from_utf8(bytes)
                .map_err(|e| AppError::Internal(format!("invalid session_id bytes: {e}")))?;
            Ok(Some(session_id))
        }
        None => Ok(None),
    }
}

/// Delete a refresh-token reverse index entry. Used by the rotation
/// path on `/auth/refresh` so a presented refresh token works exactly
/// once — replay returns "refresh token not found", same as a stolen-
/// then-revoked token.
pub async fn delete_refresh_index(sessions: &KeyspaceHandle, token: &str) -> Result<(), AppError> {
    sessions.remove(refresh_key(token)).await
}

/// Atomically claim-and-delete the `refresh_token → session_id`
/// reverse index. The classic Redis-`GETDEL` shape — exactly one
/// concurrent caller observes `Some`, even under retries.
///
/// Used by the canonical `/auth/refresh` handler to close the
/// rotation TOCTOU: a leaked refresh token cannot be presented
/// twice. On single-process fjall the atomicity comes from
/// running both ops in one `blocking_with_timeout` closure; on
/// the vsock backend the fallback is non-atomic
/// (see [`crate::store::KeyspaceHandle::take_raw`]).
pub async fn take_session_id_by_refresh(
    sessions: &KeyspaceHandle,
    token: &str,
) -> Result<Option<String>, AppError> {
    match sessions.take_raw(refresh_key(token)).await? {
        Some(bytes) => {
            let session_id = String::from_utf8(bytes)
                .map_err(|e| AppError::Internal(format!("invalid session_id bytes: {e}")))?;
            Ok(Some(session_id))
        }
        None => Ok(None),
    }
}

/// Count `ChallengeSent` sessions belonging to `did`. The
/// canonical `/auth/challenge` handler invokes this to enforce
/// `AuthBackend::max_pending_challenges_per_did` and reject
/// callers that try to exhaust the keyspace with a churn of
/// pending challenges.
///
/// Default implementation is an O(N) prefix scan over `session:`.
/// Backends with a per-DID tracker keyspace (like did-hosting's
/// `pending_challenges:` index) can override the corresponding
/// `SessionStore::count_pending_challenges` method to return O(1).
/// Suitable for the current keyspace sizes vti-common consumers
/// operate at; revisit when sessions cross five-figure cardinality.
pub async fn count_pending_challenges(
    sessions: &KeyspaceHandle,
    did: &str,
) -> Result<usize, AppError> {
    let entries = sessions.prefix_iter_raw("session:").await?;
    let mut count = 0usize;
    for (_key, value) in entries {
        if let Ok(s) = serde_json::from_slice::<Session>(&value)
            && s.did == did
            && s.state == SessionState::ChallengeSent
        {
            count += 1;
        }
    }
    Ok(count)
}

/// Returns the current UNIX epoch timestamp in seconds.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Delete a single session and its refresh index.
pub async fn delete_session(sessions: &KeyspaceHandle, session_id: &str) -> Result<(), AppError> {
    let session: Option<Session> = sessions.get(session_key(session_id)).await?;
    if let Some(session) = session {
        if let Some(ref token) = session.refresh_token {
            sessions.remove(refresh_key(token)).await?;
        }
        sessions.remove(session_key(session_id)).await?;
        debug!(session_id, "session deleted");
    }
    Ok(())
}

/// List all active sessions.
pub async fn list_sessions(sessions: &KeyspaceHandle) -> Result<Vec<Session>, AppError> {
    let raw = sessions.prefix_iter_raw("session:").await?;
    let mut result = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        if let Ok(session) = serde_json::from_slice::<Session>(&value) {
            result.push(session);
        }
    }
    Ok(result)
}

/// Remove expired sessions from the store.
///
/// - `ChallengeSent` sessions expire after `challenge_ttl` seconds from `created_at`.
/// - `Authenticated` **REST** sessions (UUID `session_id`) expire when
///   `refresh_expires_at` has passed — unchanged.
/// - `Authenticated` **intrinsic-sender** sessions (DIDComm/TSP), identified by
///   `session_id == did`, expire after [`INTRINSIC_SESSION_IDLE_TTL_SECS`] of
///   idle since `last_seen` (falling back to `created_at` for rows written
///   before the `last_seen` field existed). Without this branch such a session
///   — which has `refresh_expires_at == None` — would hit the REST rule and be
///   swept on the very next pass.
pub async fn cleanup_expired_sessions(
    sessions: &KeyspaceHandle,
    challenge_ttl: u64,
) -> Result<(), AppError> {
    let entries = sessions.prefix_iter_raw("session:").await?;
    let now = now_epoch();
    let mut removed = 0u64;
    let mut live_sessions: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(entries.len());

    for (key, value) in entries {
        let session: Session = match serde_json::from_slice(&value) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let expired = match session.state {
            SessionState::ChallengeSent => now.saturating_sub(session.created_at) > challenge_ttl,
            SessionState::Authenticated => {
                if session.session_id == session.did {
                    // Intrinsic-sender (DIDComm/TSP) canonical session — keyed on
                    // the DID itself (session_id == did), no refresh token,
                    // reaped on idle. Fall back to created_at for pre-migration
                    // rows whose last_seen is unset (0).
                    let last = session.last_seen.max(session.created_at);
                    now.saturating_sub(last) > INTRINSIC_SESSION_IDLE_TTL_SECS
                } else {
                    // REST/JWT session (UUID session_id): bounded by its
                    // refresh-token deadline. Unchanged behaviour, including
                    // recognise-style sessions with no refresh token, which
                    // still expire on the next pass.
                    session
                        .refresh_expires_at
                        .is_none_or(|expires| now > expires)
                }
            }
        };

        if expired {
            sessions.remove(key).await?;
            if let Some(ref token) = session.refresh_token {
                sessions.remove(refresh_key(token)).await?;
            }
            removed += 1;
        } else {
            live_sessions.insert(session.session_id);
        }
    }

    // GC orphan `nonce:{challenge}` index entries. `auth::challenge` writes
    // these on every challenge issue but never deletes them, so without
    // this sweep the keyspace grows unbounded over a long-running TEE.
    // A nonce is orphan if its session record is gone (either expired-in-
    // this-pass or already cleaned up). Decoding the value is safe because
    // it's UTF-8 ASCII (the session_id) by construction.
    let nonce_entries = sessions.prefix_iter_raw("nonce:").await?;
    let mut nonce_removed = 0u64;
    for (key, value) in nonce_entries {
        let session_id = match std::str::from_utf8(&value) {
            Ok(s) => s,
            Err(_) => {
                // Malformed; treat as orphan and clean up.
                sessions.remove(key).await?;
                nonce_removed += 1;
                continue;
            }
        };
        if !live_sessions.contains(session_id) {
            sessions.remove(key).await?;
            nonce_removed += 1;
        }
    }

    debug!(
        removed,
        nonces_removed = nonce_removed,
        "session cleanup complete"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    fn temp_sessions_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&config).expect("open store");
        let ks = store.keyspace("sessions").expect("keyspace");
        (ks, dir)
    }

    fn sample_session(session_id: &str, did: &str, state: SessionState) -> Session {
        Session {
            session_id: session_id.to_string(),
            did: did.to_string(),
            challenge: "test-challenge-hex".into(),
            state,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: Vec::new(),
            acr: String::new(),
            acr_expires_at: None,
            token_id: None,
            session_pubkey_b58btc: None,
        }
    }

    #[test]
    fn debug_redacts_refresh_token() {
        // Regression: Session derives a manual Debug that must hide
        // refresh_token. A `tracing::debug!("{session:?}")` in any code
        // path holding a Session must not exfiltrate the bearer-
        // equivalent secret.
        let mut s = sample_session("sess-1", "did:key:zA", SessionState::Authenticated);
        s.refresh_token = Some("super-secret-refresh-uuid".into());
        let rendered = format!("{s:?}");
        assert!(
            !rendered.contains("super-secret-refresh-uuid"),
            "raw refresh token must not appear in Debug output, got: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "expected redaction marker, got: {rendered}"
        );
    }

    // ── Session key helpers ─────────────────────────────────────────

    #[test]
    fn session_key_is_prefixed_for_scan() {
        assert_eq!(session_key("abc"), "session:abc");
    }

    #[test]
    fn refresh_key_hashes_token_not_stores_raw() {
        // S-7 invariant: a storage dump must not yield live refresh
        // tokens. The reverse-index key is keyed by SHA-256 hex, not
        // the raw token. Regressions that revert to raw-token keying
        // leak credentials on any backup / memory dump.
        let key = refresh_key("very-secret-uuid-v4-12345");
        assert!(
            key.starts_with("refresh:"),
            "prefix must survive for prefix scans"
        );
        let hash_part = key.strip_prefix("refresh:").unwrap();
        assert_eq!(
            hash_part.len(),
            64,
            "SHA-256 as hex is 64 chars; got {hash_part}"
        );
        assert!(
            !hash_part.contains("very-secret"),
            "raw token must not appear in the index key — got {key}"
        );

        // Same input → same hash (deterministic lookup).
        assert_eq!(refresh_key("very-secret-uuid-v4-12345"), key);
        // Different input → different hash.
        assert_ne!(refresh_key("other-token"), key);
    }

    // ── Store round-trip ────────────────────────────────────────────

    #[tokio::test]
    async fn store_and_load_session() {
        let (ks, _dir) = temp_sessions_ks();
        let session = sample_session("sess-1", "did:key:zA", SessionState::ChallengeSent);
        store_session(&ks, &session).await.unwrap();

        let loaded = get_session(&ks, "sess-1")
            .await
            .unwrap()
            .expect("session must be present");
        assert_eq!(loaded.session_id, "sess-1");
        assert_eq!(loaded.did, "did:key:zA");
        assert_eq!(loaded.state, SessionState::ChallengeSent);
    }

    #[tokio::test]
    async fn get_session_returns_none_for_missing() {
        let (ks, _dir) = temp_sessions_ks();
        let result = get_session(&ks, "never-existed").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn update_session_overwrites_state() {
        let (ks, _dir) = temp_sessions_ks();
        let mut session = sample_session("sess-1", "did:key:zA", SessionState::ChallengeSent);
        store_session(&ks, &session).await.unwrap();

        session.state = SessionState::Authenticated;
        update_session(&ks, &session).await.unwrap();

        let loaded = get_session(&ks, "sess-1").await.unwrap().unwrap();
        assert_eq!(loaded.state, SessionState::Authenticated);
    }

    // ── Refresh-token index ─────────────────────────────────────────

    #[tokio::test]
    async fn refresh_index_lookup_round_trip() {
        let (ks, _dir) = temp_sessions_ks();
        store_refresh_index(&ks, "refresh-token-abc", "sess-1")
            .await
            .unwrap();

        let session_id = get_session_by_refresh(&ks, "refresh-token-abc")
            .await
            .unwrap()
            .expect("refresh token must resolve to session id");
        assert_eq!(session_id, "sess-1");
    }

    #[tokio::test]
    async fn refresh_index_returns_none_for_unknown_token() {
        let (ks, _dir) = temp_sessions_ks();
        let result = get_session_by_refresh(&ks, "bogus-token").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_refresh_index_removes_only_the_named_token() {
        // Rotation invariant: deleting a presented refresh token's
        // index must not affect any other live tokens. Two sessions
        // with separate tokens — deleting one leaves the other usable.
        let (ks, _dir) = temp_sessions_ks();
        store_refresh_index(&ks, "token-a", "sess-a").await.unwrap();
        store_refresh_index(&ks, "token-b", "sess-b").await.unwrap();

        delete_refresh_index(&ks, "token-a").await.unwrap();

        assert!(
            get_session_by_refresh(&ks, "token-a")
                .await
                .unwrap()
                .is_none(),
            "deleted token must no longer resolve"
        );
        assert_eq!(
            get_session_by_refresh(&ks, "token-b")
                .await
                .unwrap()
                .as_deref(),
            Some("sess-b"),
            "untouched token must still resolve"
        );
    }

    #[tokio::test]
    async fn delete_refresh_index_is_idempotent() {
        // Deleting a token that was never stored — and deleting twice —
        // must succeed silently. The rotation path calls delete on the
        // presented token after writing the new index; a double-call
        // (e.g. retry after partial failure) must not error.
        let (ks, _dir) = temp_sessions_ks();
        delete_refresh_index(&ks, "never-existed").await.unwrap();

        store_refresh_index(&ks, "once", "sess-x").await.unwrap();
        delete_refresh_index(&ks, "once").await.unwrap();
        delete_refresh_index(&ks, "once").await.unwrap();
    }

    #[tokio::test]
    async fn refresh_index_is_keyed_by_hash_not_raw_token() {
        // Integration-level assertion of S-7: the stored key contains
        // the hash, not the raw token. A `prefix_iter_raw("refresh:")`
        // on a compromised store must not yield a usable token.
        let (ks, _dir) = temp_sessions_ks();
        store_refresh_index(&ks, "super-secret-token-value", "sess-xyz")
            .await
            .unwrap();

        let all: Vec<_> = ks.prefix_iter_raw("refresh:").await.unwrap();
        assert_eq!(all.len(), 1, "exactly one refresh index entry");
        let (key_bytes, _value_bytes) = &all[0];
        let key = String::from_utf8_lossy(key_bytes);
        assert!(
            !key.contains("super-secret-token-value"),
            "raw token must not appear in stored key — got {key}"
        );
    }

    // ── Delete ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_session_removes_session_and_refresh_index() {
        let (ks, _dir) = temp_sessions_ks();
        let mut session = sample_session("sess-1", "did:key:zA", SessionState::Authenticated);
        session.refresh_token = Some("refresh-token-abc".into());
        session.refresh_expires_at = Some(now_epoch() + 86400);
        store_session(&ks, &session).await.unwrap();
        store_refresh_index(&ks, "refresh-token-abc", "sess-1")
            .await
            .unwrap();

        delete_session(&ks, "sess-1").await.unwrap();

        assert!(get_session(&ks, "sess-1").await.unwrap().is_none());
        assert!(
            get_session_by_refresh(&ks, "refresh-token-abc")
                .await
                .unwrap()
                .is_none(),
            "refresh-index entry must be removed alongside the session"
        );
    }

    #[tokio::test]
    async fn delete_missing_session_is_a_noop() {
        let (ks, _dir) = temp_sessions_ks();
        // No session with this id; delete must succeed silently.
        delete_session(&ks, "never-existed")
            .await
            .expect("delete of missing session must not error");
    }

    // ── List ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_sessions_returns_all_records() {
        let (ks, _dir) = temp_sessions_ks();
        for i in 0..3 {
            let session = sample_session(
                &format!("sess-{i}"),
                &format!("did:key:z{i}"),
                SessionState::Authenticated,
            );
            store_session(&ks, &session).await.unwrap();
        }

        let listed = list_sessions(&ks).await.unwrap();
        assert_eq!(listed.len(), 3);
    }

    #[tokio::test]
    async fn list_sessions_ignores_refresh_index_entries() {
        // Both session:... and refresh:... share the keyspace. The
        // "session:" prefix scan must not pull refresh entries into
        // the listing, or the JSON decode would silently skip them
        // (fine) but an off-by-one in the prefix would break the scan.
        let (ks, _dir) = temp_sessions_ks();
        store_session(
            &ks,
            &sample_session("sess-1", "did:key:zA", SessionState::Authenticated),
        )
        .await
        .unwrap();
        store_refresh_index(&ks, "refresh-token-1", "sess-1")
            .await
            .unwrap();

        let listed = list_sessions(&ks).await.unwrap();
        assert_eq!(listed.len(), 1, "only the session entry should appear");
        assert_eq!(listed[0].session_id, "sess-1");
    }

    // ── Cleanup ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn cleanup_removes_challenge_sent_past_ttl() {
        let (ks, _dir) = temp_sessions_ks();
        let challenge_ttl = 300u64;

        let mut expired = sample_session("sess-stale", "did:key:zA", SessionState::ChallengeSent);
        expired.created_at = now_epoch().saturating_sub(challenge_ttl + 60);
        store_session(&ks, &expired).await.unwrap();

        let mut fresh = sample_session("sess-fresh", "did:key:zB", SessionState::ChallengeSent);
        fresh.created_at = now_epoch();
        store_session(&ks, &fresh).await.unwrap();

        cleanup_expired_sessions(&ks, challenge_ttl).await.unwrap();

        assert!(
            get_session(&ks, "sess-stale").await.unwrap().is_none(),
            "stale ChallengeSent session must be removed"
        );
        assert!(
            get_session(&ks, "sess-fresh").await.unwrap().is_some(),
            "fresh ChallengeSent session must remain"
        );
    }

    #[tokio::test]
    async fn cleanup_removes_authenticated_past_refresh_expiry() {
        let (ks, _dir) = temp_sessions_ks();

        let mut expired = sample_session("sess-expired", "did:key:zA", SessionState::Authenticated);
        expired.refresh_token = Some("expired-token".into());
        expired.refresh_expires_at = Some(now_epoch().saturating_sub(10));
        store_session(&ks, &expired).await.unwrap();
        store_refresh_index(&ks, "expired-token", "sess-expired")
            .await
            .unwrap();

        cleanup_expired_sessions(&ks, 300).await.unwrap();

        assert!(
            get_session(&ks, "sess-expired").await.unwrap().is_none(),
            "expired Authenticated session must be removed"
        );
        assert!(
            get_session_by_refresh(&ks, "expired-token")
                .await
                .unwrap()
                .is_none(),
            "refresh index must be cleaned up alongside the session"
        );
    }

    #[tokio::test]
    async fn cleanup_removes_authenticated_with_no_refresh_expiry() {
        // A defensive invariant: Authenticated sessions without a
        // refresh_expires_at should be treated as expired (the None
        // branch uses `is_none_or` which returns true). This prevents
        // a buggy code path from leaving sessions that never expire.
        let (ks, _dir) = temp_sessions_ks();
        let mut odd = sample_session("sess-odd", "did:key:zA", SessionState::Authenticated);
        odd.refresh_token = Some("odd-token".into());
        odd.refresh_expires_at = None;
        store_session(&ks, &odd).await.unwrap();

        cleanup_expired_sessions(&ks, 300).await.unwrap();

        assert!(
            get_session(&ks, "sess-odd").await.unwrap().is_none(),
            "Authenticated session with no expiry must be garbage-collected"
        );
    }

    #[tokio::test]
    async fn cleanup_gc_orphan_nonce_indices() {
        // Regression: `auth::challenge` writes `nonce:{challenge}` →
        // `session_id` reverse indexes but never deletes them. Without
        // this sweep, the keyspace grows linearly with every challenge
        // ever issued — significant in a long-running TEE.
        let (ks, _dir) = temp_sessions_ks();

        // Live session: `nonce:` index for it must survive.
        let live = sample_session("sess-live", "did:key:zA", SessionState::ChallengeSent);
        store_session(&ks, &live).await.unwrap();
        ks.insert_raw("nonce:live-challenge".to_string(), b"sess-live".to_vec())
            .await
            .unwrap();

        // Orphan: nonce points at a session_id that doesn't exist.
        ks.insert_raw(
            "nonce:orphan-challenge".to_string(),
            b"sess-vanished".to_vec(),
        )
        .await
        .unwrap();

        // Stale challenge: session past TTL — its nonce should be cleaned
        // up alongside the session itself.
        let mut stale = sample_session("sess-stale", "did:key:zB", SessionState::ChallengeSent);
        stale.created_at = now_epoch().saturating_sub(3600);
        store_session(&ks, &stale).await.unwrap();
        ks.insert_raw("nonce:stale-challenge".to_string(), b"sess-stale".to_vec())
            .await
            .unwrap();

        cleanup_expired_sessions(&ks, 300).await.unwrap();

        let nonces = ks.prefix_iter_raw("nonce:").await.unwrap();
        let nonce_keys: Vec<String> = nonces
            .iter()
            .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
            .collect();

        assert!(
            nonce_keys.iter().any(|k| k == "nonce:live-challenge"),
            "live session's nonce must survive — got {nonce_keys:?}"
        );
        assert!(
            !nonce_keys.iter().any(|k| k == "nonce:orphan-challenge"),
            "orphan nonce must be removed — got {nonce_keys:?}"
        );
        assert!(
            !nonce_keys.iter().any(|k| k == "nonce:stale-challenge"),
            "stale-session nonce must be removed — got {nonce_keys:?}"
        );
    }

    #[tokio::test]
    async fn cleanup_preserves_active_authenticated_session() {
        let (ks, _dir) = temp_sessions_ks();
        let mut active = sample_session("sess-live", "did:key:zA", SessionState::Authenticated);
        active.refresh_token = Some("live-token".into());
        active.refresh_expires_at = Some(now_epoch() + 86400);
        store_session(&ks, &active).await.unwrap();
        store_refresh_index(&ks, "live-token", "sess-live")
            .await
            .unwrap();

        cleanup_expired_sessions(&ks, 300).await.unwrap();

        let loaded = get_session(&ks, "sess-live").await.unwrap();
        assert!(loaded.is_some(), "live session must not be cleaned up");
    }

    // ── resolve_did_session (intrinsic-sender / DIDComm-TSP) ─────────

    #[tokio::test]
    async fn resolve_did_session_creates_aal1_keyed_on_did() {
        let (ks, _dir) = temp_sessions_ks();
        let did = "did:key:zResolveNew";
        let now = now_epoch();
        let s = resolve_did_session(&ks, did, now).await.unwrap();
        assert_eq!(s.session_id, did, "canonical session_id is the DID itself");
        assert_eq!(s.did, did);
        assert_eq!(s.state, SessionState::Authenticated);
        assert_eq!(s.acr, "aal1");
        assert_eq!(s.amr, vec!["did".to_string()]);
        assert!(
            s.refresh_token.is_none(),
            "intrinsic session has no refresh token"
        );
        assert_eq!(s.last_seen, now);
        // Persisted under session:{did}: a second resolve reads the same row.
        assert!(get_session(&ks, did).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn resolve_did_session_reports_elevation_within_window() {
        let (ks, _dir) = temp_sessions_ks();
        let did = "did:key:zResolveElevated";
        let now = now_epoch();
        // Create, then elevate the row exactly as the step-up handler does.
        let mut s = resolve_did_session(&ks, did, now).await.unwrap();
        s.acr = "aal2".into();
        s.amr.push("did-signed".into());
        s.acr_expires_at = Some(now + 900);
        update_session(&ks, &s).await.unwrap();
        // A later message (within the window) observes the elevation — the
        // property that makes intrinsic-sender step-up take effect at all.
        let seen = resolve_did_session(&ks, did, now + 60).await.unwrap();
        assert_eq!(seen.acr, "aal2");
        assert!(seen.amr.iter().any(|m| m == "did-signed"));
    }

    #[tokio::test]
    async fn resolve_did_session_downgrades_after_window() {
        let (ks, _dir) = temp_sessions_ks();
        let did = "did:key:zResolveLapsed";
        let now = now_epoch();
        let mut s = resolve_did_session(&ks, did, now).await.unwrap();
        s.acr = "aal2".into();
        s.amr = vec!["did".into(), "did-signed".into()];
        s.acr_expires_at = Some(now + 900);
        update_session(&ks, &s).await.unwrap();
        // Past the deadline → downgraded to aal1, factors reset, downgrade
        // persisted so a single approval can't grant permanent aal2.
        let seen = resolve_did_session(&ks, did, now + 901).await.unwrap();
        assert_eq!(seen.acr, "aal1");
        assert_eq!(seen.acr_expires_at, None);
        assert_eq!(seen.amr, vec!["did".to_string()]);
        let stored = get_session(&ks, did).await.unwrap().unwrap();
        assert_eq!(stored.acr, "aal1");
        assert_eq!(stored.acr_expires_at, None);
    }

    #[tokio::test]
    async fn intrinsic_session_reaped_only_after_idle_ttl() {
        let (ks, _dir) = temp_sessions_ks();
        let did = "did:key:zIdle";
        let mut s = resolve_did_session(&ks, did, now_epoch()).await.unwrap();
        // Fresh: survives a sweep (session_id == did → idle-TTL branch).
        cleanup_expired_sessions(&ks, 60).await.unwrap();
        assert!(
            get_session(&ks, did).await.unwrap().is_some(),
            "a just-seen intrinsic session must not be reaped"
        );
        // Idle beyond the TTL: reaped.
        s.last_seen = now_epoch().saturating_sub(INTRINSIC_SESSION_IDLE_TTL_SECS + 10);
        s.created_at = s.last_seen;
        update_session(&ks, &s).await.unwrap();
        cleanup_expired_sessions(&ks, 60).await.unwrap();
        assert!(
            get_session(&ks, did).await.unwrap().is_none(),
            "an idle intrinsic session must be reaped"
        );
    }

    #[tokio::test]
    async fn rest_session_sweep_rule_unchanged_for_uuid_sessions() {
        let (ks, _dir) = temp_sessions_ks();
        // UUID session_id != did → REST branch, bounded by refresh deadline.
        let mut live = sample_session("uuid-live", "did:key:zRest", SessionState::Authenticated);
        live.refresh_token = Some("rt-live".into());
        live.refresh_expires_at = Some(now_epoch() + 3600);
        store_session(&ks, &live).await.unwrap();
        let mut dead = sample_session("uuid-dead", "did:key:zRest", SessionState::Authenticated);
        dead.refresh_token = Some("rt-dead".into());
        dead.refresh_expires_at = Some(now_epoch().saturating_sub(10));
        store_session(&ks, &dead).await.unwrap();
        cleanup_expired_sessions(&ks, 60).await.unwrap();
        assert!(get_session(&ks, "uuid-live").await.unwrap().is_some());
        assert!(get_session(&ks, "uuid-dead").await.unwrap().is_none());
    }

    // ── now_epoch ───────────────────────────────────────────────────

    #[test]
    fn now_epoch_is_monotonic() {
        // Guard against the fallback path (0 on clock < UNIX_EPOCH)
        // silently returning without the test noticing. If this test
        // fires on a machine with a broken clock, the fallback is
        // doing its job — rerun on a sane host.
        let t = now_epoch();
        assert!(t > 1_700_000_000, "epoch should be post-2023; got {t}");
    }
}
