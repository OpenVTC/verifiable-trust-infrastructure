//! Install-token state machine.
//!
//! Implements **M0.4.2** of the VTC MVP Phase 0 plan. Adopts the
//! claim-window pattern from `webvh-common::server::passkey::store`
//! (plan **D12**): an in-flight WebAuthn ceremony locks out
//! concurrent claims for [`ENROLLMENT_CLAIM_WINDOW_SECS`] (5
//! minutes) but is **not** consumed until the ceremony succeeds —
//! a failed ceremony leaves the token redeemable by the legitimate
//! operator after the window expires.
//!
//! Storage:
//!
//! - `install:token:<jti>` → [`InstallTokenState`] (`Issued` /
//!   `Consumed`).
//!
//! Every install token (first-admin setup and ongoing
//! `vtc admin invite`s) carries the same row shape. The earlier
//! "carve-out" global lockdown is gone — invites are now gated by
//! the per-row [`InstallTokenState::Issued::claim_secret_hash`]
//! out-of-band secret + the existing `AdminAuth` on the
//! invite-mint endpoint. See `claim_secret` module for the hashing
//! helpers.
//!
//! Concurrency: every transition takes [`super::INSTALL_TOKEN_LOCK`]
//! before reading + writing state. The lock serialises across
//! Axum tasks so two `start_claim` calls on the same JTI cannot
//! both pass the "claimed_at not set within the window" check.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::INSTALL_TOKEN_LOCK;
use crate::error::AppError;
use vti_common::store::KeyspaceHandle;

/// How long an in-flight WebAuthn ceremony locks out concurrent
/// claims on the same install token. Tracks the same value as
/// `vti_common::auth::passkey::ENROLLMENT_CLAIM_WINDOW_SECS` (300 s).
/// Duplicated locally rather than depending on the `passkey` feature
/// of `vti-common` — the install state machine doesn't need anything
/// else from that module, and feature-gating one constant through
/// the dependency tree adds more friction than it's worth. M0.5 will
/// switch to the shared constant when it enables the `passkey`
/// feature.
pub const ENROLLMENT_CLAIM_WINDOW_SECS: u64 = 300;

const TOKEN_KEY_PREFIX: &[u8] = b"install:token:";
const EMERGENCY_PENDING_KEY: &[u8] = b"install:emergency_pending";

fn token_key(jti: &Uuid) -> Vec<u8> {
    let mut out = TOKEN_KEY_PREFIX.to_vec();
    out.extend_from_slice(jti.to_string().as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Per-token state held in the `install` keyspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InstallTokenState {
    /// Issued but not yet successfully consumed. `claimed_at` is set
    /// when a `start_claim` call is in progress; the window
    /// expires after [`ENROLLMENT_CLAIM_WINDOW_SECS`] so a failed
    /// ceremony doesn't permanently lock the token.
    Issued {
        /// Wall-clock expiry; once exceeded, the token cannot
        /// progress to `Consumed`.
        exp: DateTime<Utc>,
        /// Raw 32 cnonce bytes; the WebAuthn ceremony's
        /// `clientDataJSON.challenge` is validated against this.
        #[serde(with = "raw_bytes_b64")]
        cnonce: [u8; 32],
        /// Raw 32 ephemeral Ed25519 private key bytes. Only present
        /// in `Issued`; nulled on transition to `Consumed`.
        #[serde(with = "raw_bytes_b64")]
        ephemeral_signing_key: [u8; 32],
        /// Wall-clock when an in-flight `start_claim` set the
        /// ceremony lock. `None` means no ceremony has been
        /// initiated since issuance.
        claimed_at: Option<DateTime<Utc>>,
        /// Argon2id PHC hash of the out-of-band claim code the
        /// invitee must supply at claim-start. `None` for
        /// pre-claim-secret rows (legacy data and first-admin
        /// install tokens minted by older builds); the route
        /// handler treats `None` as "no secret required" so the
        /// migration is friction-free. New invites always set
        /// this. See `super::claim_secret`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claim_secret_hash: Option<String>,
        /// Target admin DID the invite was minted for. Mirrors
        /// the JWT's `admin_did` claim so the daemon can surface
        /// it on the invites list without decoding the (gone)
        /// install URL. `None` for legacy rows persisted before
        /// this field landed. New invites always set it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        admin_did: Option<String>,
    },
    /// Ceremony succeeded — token is permanently spent. Retained for
    /// idempotency / audit; a later `start_claim` for the same JTI
    /// returns [`AppError::Unauthorized`].
    Consumed {
        at: DateTime<Utc>,
        /// Target admin DID the invite was minted for, copied
        /// forward from the `Issued` state on transition so the
        /// invites-list UI can render the consumer alongside the
        /// jti. `None` on legacy rows persisted before this field
        /// landed; new consumptions always set it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        admin_did: Option<String>,
    },
}

mod raw_bytes_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// Successful [`InstallTokenStore::start_claim`] outcome. The
/// caller hands `ephemeral_signing_key` + `cnonce` to the WebAuthn
/// route handler; on ceremony success the route calls
/// [`InstallTokenStore::finish_claim`] to consume.
#[derive(Debug)]
pub struct StartClaimOutcome {
    pub ephemeral_signing_key: Zeroizing<[u8; 32]>,
    pub cnonce: [u8; 32],
    /// Stored Argon2id PHC hash of the out-of-band claim code.
    /// `None` for legacy / no-secret rows; the route handler
    /// MUST verify the operator-supplied code against this when
    /// present, before issuing the WebAuthn challenge.
    pub claim_secret_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Wraps the `install` keyspace with the state-machine semantics.
/// Cheap to clone (the underlying handle is `Arc`-shared).
#[derive(Clone)]
pub struct InstallTokenStore {
    ks: KeyspaceHandle,
}

impl InstallTokenStore {
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self { ks }
    }

    /// Persist a freshly-minted token's state.
    ///
    /// `claim_secret_hash` is the Argon2id PHC string for the
    /// out-of-band code the invitee must supply at claim-start.
    /// Pass `None` to mint a "URL-only" install token — kept for
    /// the legacy first-admin path and tests; new code paths
    /// always supply a hash.
    ///
    /// `admin_did` is the target DID the invite is for. Mirrors
    /// the JWT's `admin_did` claim so the daemon can surface it
    /// on the invites list. `None` is accepted for backwards
    /// compatibility with tests that didn't track the DID; the
    /// production mint paths always pass it.
    ///
    /// Caller must hold no other lock on the install keyspace; we
    /// take [`INSTALL_TOKEN_LOCK`] internally for the write so
    /// concurrent mints + transitions on the same JTI serialise.
    pub async fn record_issued(
        &self,
        jti: &Uuid,
        cnonce: [u8; 32],
        ephemeral_signing_key: [u8; 32],
        exp: DateTime<Utc>,
        claim_secret_hash: Option<String>,
        admin_did: Option<String>,
    ) -> Result<(), AppError> {
        let _guard = INSTALL_TOKEN_LOCK.lock().await;
        let state = InstallTokenState::Issued {
            exp,
            cnonce,
            ephemeral_signing_key,
            claimed_at: None,
            claim_secret_hash,
            admin_did,
        };
        self.ks.insert(token_key(jti), &state).await
    }

    /// Begin a WebAuthn ceremony on `jti`.
    ///
    /// Returns `Ok(StartClaimOutcome)` if the token is `Issued`,
    /// not expired, and no concurrent ceremony has set `claimed_at`
    /// within the [`ENROLLMENT_CLAIM_WINDOW_SECS`] window. Sets
    /// `claimed_at` as a side-effect so a second concurrent caller
    /// sees the in-progress lock. The `StartClaimOutcome` carries
    /// the stored `claim_secret_hash` (if any) so the route
    /// handler can verify the operator-supplied claim code before
    /// issuing the WebAuthn challenge.
    ///
    /// Errors with [`AppError::Unauthorized`] on every other state
    /// — the structured detail stays out of the response for
    /// defence in depth.
    pub async fn start_claim(&self, jti: &Uuid) -> Result<StartClaimOutcome, AppError> {
        let _guard = INSTALL_TOKEN_LOCK.lock().await;

        let key = token_key(jti);
        let state: Option<InstallTokenState> = self.ks.get(key.clone()).await?;
        let state =
            state.ok_or_else(|| AppError::Unauthorized("install token not found".into()))?;

        match state {
            InstallTokenState::Consumed { .. } => {
                Err(AppError::Unauthorized("install token consumed".into()))
            }
            InstallTokenState::Issued {
                exp,
                cnonce,
                ephemeral_signing_key,
                claimed_at,
                claim_secret_hash,
                admin_did,
            } => {
                let now = Utc::now();
                if now >= exp {
                    return Err(AppError::Unauthorized("install token expired".into()));
                }
                if let Some(prev) = claimed_at {
                    let elapsed = now - prev;
                    if elapsed < Duration::seconds(ENROLLMENT_CLAIM_WINDOW_SECS as i64) {
                        return Err(AppError::Conflict(
                            "install ceremony already in progress".into(),
                        ));
                    }
                }
                let next = InstallTokenState::Issued {
                    exp,
                    cnonce,
                    ephemeral_signing_key,
                    claimed_at: Some(now),
                    claim_secret_hash: claim_secret_hash.clone(),
                    admin_did,
                };
                self.ks.insert(key, &next).await?;
                Ok(StartClaimOutcome {
                    cnonce,
                    ephemeral_signing_key: Zeroizing::new(ephemeral_signing_key),
                    claim_secret_hash,
                })
            }
        }
    }

    /// Complete the ceremony — transitions `Issued` → `Consumed`.
    /// Errors with [`AppError::Unauthorized`] if the token is already
    /// consumed or expired.
    ///
    /// The caller (M0.5 `/install/claim/finish` handler) calls this
    /// **only** after the WebAuthn assertion validates against the
    /// `cnonce` and the candidate DID signature has been verified.
    pub async fn finish_claim(&self, jti: &Uuid) -> Result<(), AppError> {
        let _guard = INSTALL_TOKEN_LOCK.lock().await;
        let key = token_key(jti);
        let state: Option<InstallTokenState> = self.ks.get(key.clone()).await?;
        let state =
            state.ok_or_else(|| AppError::Unauthorized("install token not found".into()))?;
        match state {
            InstallTokenState::Consumed { .. } => {
                Err(AppError::Unauthorized("install token consumed".into()))
            }
            InstallTokenState::Issued { exp, admin_did, .. } => {
                let now = Utc::now();
                if now >= exp {
                    return Err(AppError::Unauthorized("install token expired".into()));
                }
                let next = InstallTokenState::Consumed { at: now, admin_did };
                self.ks.insert(key, &next).await
            }
        }
    }

    /// Stamp the `install:emergency_pending` marker carrying the
    /// operator's hostname + the wall-clock at CLI-invoke time. The
    /// daemon reads + consumes the marker on next boot via
    /// [`Self::take_pending_emergency`] and emits the
    /// `EmergencyBootstrapInvoked` audit event from it.
    pub async fn mark_emergency_pending(
        &self,
        pending: PendingEmergencyBootstrap,
    ) -> Result<(), AppError> {
        self.ks
            .insert(EMERGENCY_PENDING_KEY.to_vec(), &pending)
            .await
    }

    /// Read + delete the pending-emergency-bootstrap marker. The
    /// daemon calls this once at startup; a returned `Some(...)`
    /// fires the `EmergencyBootstrapInvoked` audit event. Subsequent
    /// startups (after the marker is consumed) see `None`.
    ///
    /// Held under [`INSTALL_TOKEN_LOCK`] so a concurrent caller (a
    /// second boot path racing with a CLI invocation, or two test
    /// helpers in the same process) can't both observe the marker
    /// and emit two audit envelopes for the same emergency. Mirrors
    /// the read-then-write discipline every other transition in this
    /// module follows.
    pub async fn take_pending_emergency(
        &self,
    ) -> Result<Option<PendingEmergencyBootstrap>, AppError> {
        let _guard = INSTALL_TOKEN_LOCK.lock().await;
        let key = EMERGENCY_PENDING_KEY.to_vec();
        let value: Option<PendingEmergencyBootstrap> = self.ks.get(key.clone()).await?;
        if value.is_some() {
            self.ks.remove(key).await?;
        }
        Ok(value)
    }

    /// List every persisted install-token state row keyed by `jti`.
    /// Used by the `/v1/admin/invites` list surface. Returns the
    /// (jti, state) pairs; the handler derives status (Issued /
    /// Consumed / Expired) and strips secret material before
    /// emitting wire JSON.
    pub async fn list_tokens(&self) -> Result<Vec<(Uuid, InstallTokenState)>, AppError> {
        let raw = self.ks.prefix_iter_raw(TOKEN_KEY_PREFIX.to_vec()).await?;
        let mut out = Vec::with_capacity(raw.len());
        for (k, v) in raw {
            let Some(suffix) = k.strip_prefix(TOKEN_KEY_PREFIX) else {
                continue;
            };
            let Ok(jti_str) = std::str::from_utf8(suffix) else {
                continue;
            };
            let Ok(jti) = jti_str.parse::<Uuid>() else {
                continue;
            };
            match serde_json::from_slice::<InstallTokenState>(&v) {
                Ok(state) => out.push((jti, state)),
                Err(e) => {
                    tracing::warn!(error = %e, %jti, "skipping unparseable install token state")
                }
            }
        }
        Ok(out)
    }

    /// Peek a token's state row without mutating it. Used by the
    /// invite revoke surface to refuse `Consumed` rows before any
    /// destructive call.
    pub async fn get_token(&self, jti: &Uuid) -> Result<Option<InstallTokenState>, AppError> {
        self.ks.get(token_key(jti)).await
    }

    /// Delete a token's state row. Used by the invite revoke
    /// surface after a [`Self::get_token`] check has confirmed
    /// the row is not `Consumed`. Returns `true` if a row was
    /// removed.
    pub async fn delete_token(&self, jti: &Uuid) -> Result<bool, AppError> {
        let _guard = INSTALL_TOKEN_LOCK.lock().await;
        let key = token_key(jti);
        let existed: Option<InstallTokenState> = self.ks.get(key.clone()).await?;
        if existed.is_some() {
            self.ks.remove(key).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// State persisted to `install:emergency_pending` by the
/// `vtc admin emergency-bootstrap` CLI. The daemon consumes it on
/// next boot and feeds it into [`crate::audit`]'s
/// `EmergencyBootstrapInvoked` event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEmergencyBootstrap {
    pub operator_hostname: String,
    pub invoked_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn temp_store() -> (InstallTokenStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let ks = store.keyspace("install-test").expect("ks");
        (InstallTokenStore::new(ks), dir)
    }

    async fn issue(store: &InstallTokenStore, ttl: i64) -> Uuid {
        issue_with_hash(store, ttl, None).await
    }

    async fn issue_with_hash(
        store: &InstallTokenStore,
        ttl: i64,
        claim_secret_hash: Option<String>,
    ) -> Uuid {
        let jti = Uuid::new_v4();
        let exp = Utc::now() + Duration::seconds(ttl);
        store
            .record_issued(
                &jti,
                [0xAB; 32],
                [0xCD; 32],
                exp,
                claim_secret_hash,
                Some("did:key:zTestAdmin".to_string()),
            )
            .await
            .unwrap();
        jti
    }

    #[tokio::test]
    async fn start_then_finish_consumes_token() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;

        let outcome = store.start_claim(&jti).await.unwrap();
        assert_eq!(outcome.cnonce, [0xAB; 32]);
        assert_eq!(*outcome.ephemeral_signing_key, [0xCD; 32]);

        store.finish_claim(&jti).await.unwrap();
        // Second finish returns "consumed".
        let err = store.finish_claim(&jti).await.expect_err("second finish");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn finish_preserves_admin_did_in_consumed_row() {
        // Regression: the consumed-state row used to drop the target
        // DID, which made the invites-list UI render "unknown" for
        // every successfully-claimed invite. The DID must survive
        // the Issued → Consumed transition so the audit surface
        // stays useful.
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;
        store.start_claim(&jti).await.unwrap();
        store.finish_claim(&jti).await.unwrap();

        let row = store.get_token(&jti).await.unwrap().expect("token row");
        match row {
            InstallTokenState::Consumed { admin_did, .. } => {
                assert_eq!(admin_did.as_deref(), Some("did:key:zTestAdmin"));
            }
            _ => panic!("expected Consumed state after finish_claim"),
        }
    }

    #[tokio::test]
    async fn second_concurrent_start_within_window_is_rejected() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;

        let _first = store.start_claim(&jti).await.unwrap();
        // Immediately try a second start — the claim window is 5
        // minutes, so this must be rejected.
        let err = store.start_claim(&jti).await.expect_err("conflict");
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn retry_after_window_succeeds() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;

        let _first = store.start_claim(&jti).await.unwrap();
        // Backdate `claimed_at` past the window so the next call
        // sees a stale lock and overwrites it.
        let key = token_key(&jti);
        let mut state: InstallTokenState = store.ks.get(key.clone()).await.unwrap().unwrap();
        if let InstallTokenState::Issued {
            ref mut claimed_at, ..
        } = state
        {
            *claimed_at =
                Some(Utc::now() - Duration::seconds((ENROLLMENT_CLAIM_WINDOW_SECS as i64) + 10));
        }
        store.ks.insert(key, &state).await.unwrap();

        let _retry = store.start_claim(&jti).await.expect("retry after window");
    }

    #[tokio::test]
    async fn expired_token_rejected_on_start() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, -1).await;
        let err = store.start_claim(&jti).await.expect_err("expired");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn expired_token_rejected_on_finish() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;
        let _ = store.start_claim(&jti).await.unwrap();

        // Backdate the expiry to now-1s.
        let key = token_key(&jti);
        let mut state: InstallTokenState = store.ks.get(key.clone()).await.unwrap().unwrap();
        if let InstallTokenState::Issued { ref mut exp, .. } = state {
            *exp = Utc::now() - Duration::seconds(1);
        }
        store.ks.insert(key, &state).await.unwrap();

        let err = store.finish_claim(&jti).await.expect_err("expired");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn claim_secret_hash_is_surfaced_in_outcome() {
        let (store, _dir) = temp_store();
        let hash = "$argon2id$test-stub".to_string();
        let jti = issue_with_hash(&store, 600, Some(hash.clone())).await;
        let outcome = store.start_claim(&jti).await.unwrap();
        assert_eq!(outcome.claim_secret_hash.as_deref(), Some(hash.as_str()));
    }

    #[tokio::test]
    async fn no_hash_when_token_minted_without_secret() {
        let (store, _dir) = temp_store();
        let jti = issue(&store, 600).await;
        let outcome = store.start_claim(&jti).await.unwrap();
        assert!(outcome.claim_secret_hash.is_none());
    }

    #[tokio::test]
    async fn missing_token_returns_unauthorized() {
        let (store, _dir) = temp_store();
        let phantom_jti = Uuid::new_v4();
        let err = store
            .start_claim(&phantom_jti)
            .await
            .expect_err("not found");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn state_machine_serde_round_trip() {
        let state = InstallTokenState::Issued {
            exp: Utc::now() + Duration::seconds(60),
            cnonce: [0xAB; 32],
            ephemeral_signing_key: [0xCD; 32],
            claimed_at: Some(Utc::now()),
            claim_secret_hash: Some("$argon2id$stub".into()),
            admin_did: Some("did:key:zSerdeRoundTrip".into()),
        };
        let s = serde_json::to_string(&state).unwrap();
        let back: InstallTokenState = serde_json::from_str(&s).unwrap();
        assert_eq!(back, state);
    }

    #[tokio::test]
    async fn issued_row_without_hash_field_deserializes() {
        // Legacy rows persisted before the claim-secret field
        // existed must still parse — `serde(default)` on the
        // new field makes this work.
        let legacy_json = serde_json::json!({
            "status": "issued",
            "exp": "2099-01-01T00:00:00Z",
            "cnonce": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo",
            "ephemeral_signing_key": "zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0",
            "claimed_at": null
        });
        let state: InstallTokenState = serde_json::from_value(legacy_json).unwrap();
        match state {
            InstallTokenState::Issued {
                claim_secret_hash, ..
            } => {
                assert!(claim_secret_hash.is_none());
            }
            _ => panic!("expected Issued"),
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// P0.7 accept criterion: the on-disk bytes for an issued install
    /// token do not contain the (base64) ephemeral signing key — i.e. the
    /// `install` keyspace is encrypted at rest. We prove it by writing the
    /// *same* token to a bare and an encrypted store and showing the
    /// plaintext fragment present in the former is absent in the latter.
    #[tokio::test]
    async fn issued_token_is_encrypted_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).unwrap();
        let exp = Utc::now() + Duration::seconds(600);
        let admin = "did:key:zTestAdmin".to_string();

        // Bare write — confirms the secret is plaintext-visible without
        // encryption (the pre-P0.7 state we're fixing).
        let plain_jti = Uuid::new_v4();
        let plain_ks = store.keyspace("install-plain").unwrap();
        InstallTokenStore::new(plain_ks.clone())
            .record_issued(
                &plain_jti,
                [0xAB; 32],
                [0xCD; 32],
                exp,
                None,
                Some(admin.clone()),
            )
            .await
            .unwrap();
        let plaintext = plain_ks
            .get_raw(token_key(&plain_jti))
            .await
            .unwrap()
            .unwrap();
        assert!(
            contains(&plaintext, admin.as_bytes()),
            "sanity: admin DID is plaintext-visible in an unencrypted store"
        );

        // Encrypted write — the same secret must not be on disk in clear.
        let key = [0x77; 32];
        let enc_jti = Uuid::new_v4();
        let enc_store =
            InstallTokenStore::new(store.keyspace("install").unwrap().with_encryption(key));
        enc_store
            .record_issued(
                &enc_jti,
                [0xAB; 32],
                [0xCD; 32],
                exp,
                None,
                Some(admin.clone()),
            )
            .await
            .unwrap();

        let on_disk = store
            .keyspace("install")
            .unwrap()
            .get_raw(token_key(&enc_jti))
            .await
            .unwrap()
            .unwrap();
        assert!(on_disk.starts_with(b"VAE1"), "value must be encrypted");
        assert!(
            !contains(&on_disk, admin.as_bytes()),
            "admin DID must not appear in ciphertext"
        );
        assert!(
            !contains(&on_disk, &plaintext),
            "the plaintext token blob must not appear verbatim on disk"
        );

        // And the encrypted store reads the token back intact.
        assert!(enc_store.get_token(&enc_jti).await.unwrap().is_some());
    }

    /// P0.7: a boot over a pre-encryption store still reads existing rows.
    /// A token written in plaintext is migrated in place and an encrypted
    /// store then reads it back.
    #[tokio::test]
    async fn legacy_plaintext_token_survives_migration() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).unwrap();
        let exp = Utc::now() + Duration::seconds(600);

        // Legacy plaintext write.
        let jti = Uuid::new_v4();
        InstallTokenStore::new(store.keyspace("install").unwrap())
            .record_issued(&jti, [0xAB; 32], [0xCD; 32], exp, None, None)
            .await
            .unwrap();

        // Boot-time migration (mirrors what `server::run` does).
        let key = [0x99; 32];
        let migrated = store
            .keyspace("install")
            .unwrap()
            .migrate_to_encrypted(key)
            .await
            .unwrap();
        assert_eq!(migrated, 1);

        // The encrypted store reads the pre-existing token.
        let enc_store =
            InstallTokenStore::new(store.keyspace("install").unwrap().with_encryption(key));
        let outcome = enc_store.start_claim(&jti).await.unwrap();
        assert_eq!(*outcome.ephemeral_signing_key, [0xCD; 32]);
    }
}
