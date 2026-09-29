//! Canonical `POST /auth/refresh` handler.
//!
//! Flow:
//! 1. **Atomic claim** of the `refresh_token → session_id`
//!    reverse-index via [`SessionStore::take_session_id_by_refresh`].
//!    Exactly one concurrent caller succeeds per token (cross-replica
//!    safe). Closes the rotation TOCTOU. A token that is *not* in the
//!    index diverts to [`handle_unclaimed_refresh`] — the reuse
//!    detection path.
//! 2. Load session by the claimed `session_id`, and refuse the token
//!    unless it is the one the session currently issues
//!    ([`SessionStore::current_refresh_hash`]) — one live chain per
//!    session.
//! 3. (DIDComm transports) Verify signer DID matches session DID.
//!    REST transports can skip this — the refresh token itself is
//!    the credential.
//! 4. Reject sessions in non-`Authenticated` state.
//! 5. Refresh-token expiry check, then the idle timeout — measured
//!    against `last_seen`, which only genuine activity advances, so a
//!    client renewing on a timer cannot hold a session open
//!    indefinitely.
//! 6. Preserve `(amr, acr)` from the pre-rotation session — a
//!    step-upped `aal2` session stays at `aal2` across the rotation
//!    instead of silently dropping to `aal1`.
//! 7. Re-look-up ACL role (propagates revocation).
//! 8. Rewrite the session in place with a new access token and
//!    refresh token. The `session_id` is **kept**, not regenerated —
//!    it is the DID-keyed canonical handle, and every tombstone in a
//!    chain points at it, which is what lets a replay of an older
//!    token still find and revoke the live session. The row is
//!    overwritten rather than deleted-and-recreated, so a concurrent
//!    authed request never observes a momentarily-missing session.
//!    The rewritten session inherits the preserved `(amr, acr)`.
//! 9. Tombstone the spent token.
//! 10. Emit the `Refreshed` audit event and return the canonical
//!     `AuthenticateResponse`.
//!
//! ## Reuse detection
//!
//! Rotation alone makes a stolen refresh token worth exactly one
//! access token, but it says nothing about the theft. Deleting the
//! index leaves a replayed token and a token this node never issued
//! looking identical — both simply absent — so the single clearest
//! sign of compromise, a token presented after it was spent, arrives
//! as an ordinary 401.
//!
//! Each rotation therefore leaves a [`RefreshTombstone`] behind, and a
//! token that misses the live index is checked against it. A hit means
//! this node issued the token and has already spent it, which is
//! either theft or one specific non-attack: a client whose rotation
//! response never arrived, retrying the only token it has. The two are
//! separated in [`handle_unclaimed_refresh`]; genuine reuse revokes
//! the session and raises
//! [`AuthAuditEvent::RefreshReuseDetected`].
//!
//! Both outcomes return the same [`AuthError::RefreshTokenInvalid`] a
//! stranger's token gets. Reporting detection to the caller would tell
//! an attacker precisely when to stop, and the party that needs to
//! know is the operator, who learns it from the audit event.

use uuid::Uuid;
use vta_sdk::protocols::auth::{
    AuthenticateResponse, Session as WireSession, TokenBundle, epoch_to_rfc3339,
};

use crate::auth::AuthError;
use crate::auth::backend::{
    AuthAuditEvent, AuthBackend, RefreshInput, RefreshReuseReason, SessionStore,
};
use crate::auth::session::{
    RefreshTombstone, Session, SessionState, TombstoneCause, now_epoch, refresh_token_hash,
};

/// Process a `/auth/refresh` request.
pub async fn handle_refresh<B: AuthBackend>(
    backend: &B,
    input: RefreshInput,
) -> Result<AuthenticateResponse, B::Error> {
    // ---- 1. Atomic claim of refresh-token index ----

    let claimed = backend
        .sessions()
        .take_session_id_by_refresh(&input.refresh_token)
        .await
        .map_err(|e| AuthError::Internal(format!("take_session_id_by_refresh failed: {e:?}")))?;

    let Some(session_id) = claimed else {
        // Not live. Either never ours, or ours and already spent —
        // only the tombstone can say which.
        return handle_unclaimed_refresh(backend, &input).await;
    };

    // ---- 2. Load session ----

    let old_session = backend
        .sessions()
        .get_session(&session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("get_session failed: {e:?}")))?
        .ok_or(AuthError::SessionNotFound)?;

    // ---- 2a. The claimed token must be the one the session issues ----
    //
    // Claiming the index proves only that the token was issued here at some
    // point. A session issues one refresh token at a time, and without this
    // check any index entry that outlived its currency — the one before a
    // re-login, or one written by a rotation that lost a race with a login —
    // would still mint, into a second chain that never collides with the
    // first, so reuse detection never fires. Retiring the old entry at login
    // is best-effort and cannot close that race; refusing here does.
    //
    // Currency comes from the store's own record, not `session.refresh_token`:
    // the row is read-modify-written by activity touches and step-up, which
    // can put an older token back into it. The row is used only for sessions
    // issued before the record existed.
    let presented_hash = refresh_token_hash(&input.refresh_token);
    let current_hash = match backend
        .sessions()
        .current_refresh_hash(&session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("current_refresh_hash failed: {e:?}")))?
    {
        Some(hash) => Some(hash),
        None => old_session.refresh_token.as_deref().map(refresh_token_hash),
    };
    if current_hash.as_deref() != Some(presented_hash.as_str()) {
        let now = now_epoch();
        // The claim above already removed its index entry, so the token is
        // dead either way; the tombstone is what lets a later replay be
        // recognised instead of looking like a stranger's token.
        if let Err(e) = backend
            .sessions()
            .store_refresh_tombstone(
                &input.refresh_token,
                &RefreshTombstone {
                    session_id: old_session.session_id.clone(),
                    did: old_session.did.clone(),
                    rotated_at: now,
                    expires_at: now.saturating_add(backend.refresh_token_ttl()),
                    successor_hash: current_hash.unwrap_or_default(),
                    cause: TombstoneCause::Superseded,
                },
            )
            .await
        {
            tracing::error!(
                session_id = %old_session.session_id,
                did = %old_session.did,
                "failed to tombstone a superseded refresh token: {e:?}",
            );
        }
        // Same outcome as a replay of a token a login retired, for the same
        // reasons (see `handle_unclaimed_refresh`): refused, reported, and the
        // current session left running.
        backend.audit(AuthAuditEvent::RefreshSuperseded {
            did: &old_session.did,
            session_id: &old_session.session_id,
            rotated_at: now,
        });
        return Err(AuthError::RefreshTokenInvalid.into());
    }

    // ---- 3. (DIDComm) Signer-DID-matches-session-DID ----

    if let Some(signer) = &input.signer_did
        && *signer != old_session.did
    {
        tracing::warn!(
            session_id = %old_session.session_id,
            session_did = %old_session.did,
            signer = %signer,
            "refresh rejected: signer DID does not match session DID",
        );
        return Err(AuthError::SignerMismatch.into());
    }

    // ---- 4. State check ----

    if old_session.state != SessionState::Authenticated {
        tracing::warn!(
            session_id = %old_session.session_id,
            did = %old_session.did,
            "refresh rejected: session not authenticated",
        );
        return Err(AuthError::SessionStateMismatch.into());
    }

    // ---- 5. Refresh-token expiry ----

    let now = now_epoch();
    if let Some(expires_at) = old_session.refresh_expires_at
        && now > expires_at
    {
        tracing::warn!(
            session_id = %old_session.session_id,
            did = %old_session.did,
            "refresh rejected: refresh token expired",
        );
        return Err(AuthError::RefreshTokenExpired.into());
    }

    // ---- 5a. Idle timeout ----
    //
    // Measured against `last_seen`, which only genuine user activity
    // writes (`SessionStore::touch_session`). It is deliberately not
    // measured against the access token's expiry: a browser that renews
    // on a timer would otherwise keep a session alive for as long as
    // the tab stayed open, however long the operator had been away —
    // which is the whole thing an idle timeout prevents.
    //
    // `last_seen == 0` means a row written before the field existed
    // (`#[serde(default)]`); fall back to `created_at`, matching what
    // `cleanup_expired_sessions` does for the same case.
    if let Some(idle_ttl) = backend.idle_timeout() {
        let last_activity = if old_session.last_seen == 0 {
            old_session.created_at
        } else {
            old_session.last_seen
        };
        if now.saturating_sub(last_activity) > idle_ttl {
            tracing::warn!(
                session_id = %old_session.session_id,
                did = %old_session.did,
                idle_for = now.saturating_sub(last_activity),
                idle_ttl,
                "refresh rejected: session idle past the timeout",
            );
            return Err(AuthError::SessionIdleTimeout.into());
        }
    }

    // ---- 6. Preserve AAL across rotation ----

    let (amr, acr) = super::refresh_amr_acr(&old_session);

    // ---- 7. Re-look-up ACL role ----

    let role_resolution = backend.check_acl(&old_session.did).await?;

    // ---- 8. Mint rotated tokens ----
    //
    // The `session_id` is **stable** — it is the caller's DID, the canonical
    // transport-agnostic session key. Only the refresh token and the access
    // token's `jti` (`token_id`) rotate; the old refresh index was already
    // claimed-and-deleted atomically in step 1, and the old access token is
    // superseded by the new `token_id` pin. We overwrite `session:{did}` in
    // place rather than delete-then-recreate, so a concurrent authed request
    // never observes a momentarily-missing session.
    let new_session_id = old_session.session_id.clone();
    let new_refresh_token = Uuid::new_v4().to_string();
    let new_token_id = Uuid::new_v4().to_string();
    let new_refresh_expires_at = now.saturating_add(backend.refresh_token_ttl());
    // M2: stepped-up sessions keep the shorter `aal2` TTL
    // across rotation (was previously dropping back to the
    // base TTL on every refresh).
    let access_ttl = if acr == "aal2" {
        backend.access_token_ttl_for_aal2()
    } else {
        backend.access_token_ttl()
    };
    let access_expires_at = now.saturating_add(access_ttl);

    let access_token = backend
        .mint_access_token(
            &old_session.did,
            &new_session_id,
            &role_resolution.role,
            &role_resolution.contexts,
            &amr,
            &acr,
            old_session.tee_attested,
            access_ttl,
            &new_token_id,
        )
        .await?;

    let new_session = Session {
        session_id: new_session_id.clone(),
        did: old_session.did.clone(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now,
        // Carried forward, **not** reset to `now`. Rotating a token is
        // the client's timer firing, not the operator doing something,
        // and a renewal that refreshed `last_seen` would push the idle
        // deadline out on every cycle — the timeout could then never
        // fire, which is the exact failure this field exists to prevent.
        // Only `SessionStore::touch_session` advances it.
        //
        // Safe for the sweeper: `cleanup_expired_sessions` judges an
        // `Authenticated` row that *has* a refresh token by
        // `refresh_expires_at` and never reads `last_seen`, and the
        // refresh-less intrinsic sessions that do use `last_seen` never
        // reach this handler.
        last_seen: old_session.last_seen,
        refresh_token: Some(new_refresh_token.clone()),
        refresh_expires_at: Some(new_refresh_expires_at),
        tee_attested: old_session.tee_attested,
        amr: amr.clone(),
        acr: acr.clone(),
        acr_expires_at: old_session.acr_expires_at,
        // Pin the rotated access token to the new session row.
        token_id: Some(new_token_id.clone()),
        // Inherit the per-session ephemeral pubkey across rotation;
        // the holder's DI-proof key didn't change.
        session_pubkey_b58btc: old_session.session_pubkey_b58btc.clone(),
    };

    backend
        .sessions()
        .store_session(&new_session)
        .await
        .map_err(|e| AuthError::Internal(format!("store_session failed: {e:?}")))?;
    backend
        .sessions()
        .store_refresh_index(&new_refresh_token, &new_session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("store_refresh_index failed: {e:?}")))?;

    // ---- 9. Tombstone the spent token ----
    //
    // Ordered last, after the replacement is durable. A crash here
    // costs the ability to attribute a future replay of the spent
    // token — it is still refused, since its index is gone — whereas
    // writing the tombstone first and crashing would leave the caller
    // holding a token the store no longer honours.
    //
    // A write *error* is treated the same way as the crash: logged, not
    // returned. The rotation above is already committed, so failing the
    // request here would withhold the only live refresh token from the
    // client that owns it — its retry with the spent token then finds
    // no tombstone and is refused, signing the user out over a record
    // that exists only for detection.
    if let Err(e) = backend
        .sessions()
        .store_refresh_tombstone(
            &input.refresh_token,
            &RefreshTombstone {
                session_id: new_session_id.clone(),
                did: old_session.did.clone(),
                rotated_at: now,
                expires_at: now.saturating_add(backend.refresh_token_ttl()),
                successor_hash: refresh_token_hash(&new_refresh_token),
                cause: TombstoneCause::Rotated,
            },
        )
        .await
    {
        tracing::error!(
            session_id = %new_session_id,
            did = %old_session.did,
            "failed to tombstone a rotated refresh token; a replay of it \
             will be refused but not attributed: {e:?}",
        );
    }

    backend.audit(AuthAuditEvent::Refreshed {
        did: &old_session.did,
        old_session_id: &old_session.session_id,
        new_session_id: &new_session_id,
        amr: &amr,
        acr: &acr,
    });

    // ---- 10. Canonical response ----

    Ok(AuthenticateResponse {
        session: WireSession {
            id: new_session_id,
            subject: old_session.did,
            issued_at: epoch_to_rfc3339(now),
            expires_at: epoch_to_rfc3339(access_expires_at),
            amr,
            acr,
        },
        tokens: TokenBundle {
            access_token,
            refresh_token: Some(new_refresh_token),
            token_type: "Bearer".to_string(),
            expires_in: access_ttl,
            refresh_expires_in: Some(backend.refresh_token_ttl()),
            scope: role_resolution
                .contexts
                .into_iter()
                .map(|c| format!("ctx:{c}"))
                .collect(),
        },
    })
}

// ---------------------------------------------------------------------------
// Reuse detection
// ---------------------------------------------------------------------------

/// Decide what a refresh token that is **not** in the live index means.
///
/// Four outcomes:
///
/// - **No tombstone** — this node never issued the token, or issued it
///   so long ago that both the index and the tombstone have aged out.
///   Nothing to attribute; plain rejection, exactly as before detection
///   existed.
/// - **Tombstone, and the replay is an innocent retry** — see
///   [`is_innocent_retry`]. The original rotation is replayed
///   idempotently; nothing is revoked and nothing rotates.
/// - **Tombstone with cause [`TombstoneCause::Superseded`]** — the
///   token was retired by a newer login rather than spent. Refused and
///   audited as [`AuthAuditEvent::RefreshSuperseded`], but the session
///   is **left running**: the retired token is already dead, and the
///   usual cause is a second device still holding what it was issued
///   before the user signed in elsewhere.
/// - **Tombstone, anything else** — reuse. The session is revoked and
///   [`AuthAuditEvent::RefreshReuseDetected`] fires.
async fn handle_unclaimed_refresh<B: AuthBackend>(
    backend: &B,
    input: &RefreshInput,
) -> Result<AuthenticateResponse, B::Error> {
    let tombstone = backend
        .sessions()
        .get_refresh_tombstone(&input.refresh_token)
        .await
        .map_err(|e| AuthError::Internal(format!("get_refresh_tombstone failed: {e:?}")))?;

    let Some(tombstone) = tombstone else {
        return Err(AuthError::RefreshTokenInvalid.into());
    };

    let session = backend
        .sessions()
        .get_session(&tombstone.session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("get_session failed: {e:?}")))?;

    let now = now_epoch();

    if let Some(session) = session.as_ref()
        && is_innocent_retry(session, &tombstone, now, backend.refresh_reuse_grace())
    {
        // Bind the signer even here. The token is the credential, so
        // this can only ever reject a caller who already holds it —
        // but the strict path checks it, and a concession granted to
        // lost responses must not quietly become the looser of the two
        // doors into the same session.
        if let Some(signer) = &input.signer_did
            && *signer != session.did
        {
            return Err(AuthError::SignerMismatch.into());
        }
        tracing::info!(
            audit = true,
            session_id = %session.session_id,
            did = %session.did,
            age = now.saturating_sub(tombstone.rotated_at),
            "refresh retried with the pre-rotation token inside the grace \
             window — replaying the original rotation",
        );
        return replay_rotation(backend, session, now).await;
    }

    // ---- Retired by a newer login ----
    //
    // Handled before the reuse ladder below, and with a different
    // outcome: refused, audited, session left running.
    //
    // The token is already dead — the login removed its index entry —
    // so the security question is settled before we get here, and the
    // only thing left to decide is whether to also kill the session
    // that replaced it. Revoking would sign out the client that is
    // demonstrably the live one in order to punish a client whose
    // token has already stopped working, and the most common cause is
    // not theft at all: a second device that logged in while the first
    // sat idle leaves the first holding a retired token, and
    // presenting it is the only way that client can find out. A
    // re-login would then start the cycle over.
    //
    // It is still reported at `security_alert`, because a pre-login
    // theft looks exactly like a stale device from here and only an
    // operator correlating the two can say which it was.
    if tombstone.cause == TombstoneCause::Superseded {
        backend.audit(AuthAuditEvent::RefreshSuperseded {
            did: &tombstone.did,
            session_id: &tombstone.session_id,
            rotated_at: tombstone.rotated_at,
        });
        return Err(AuthError::RefreshTokenInvalid.into());
    }

    // ---- Reuse ----

    let reason = if session.is_none() {
        RefreshReuseReason::SessionGone
    } else if now.saturating_sub(tombstone.rotated_at) >= backend.refresh_reuse_grace() {
        RefreshReuseReason::GraceExpired
    } else {
        RefreshReuseReason::ChainAdvanced
    };

    // Revoke the whole session, not just the presented token. Two
    // parties hold the chain and the node has no way to tell which is
    // the owner, so keeping the session alive keeps it alive for the
    // attacker too. Both are signed out; the owner re-authenticates
    // with a key the attacker does not have, and the attacker has
    // nothing left to replay. `delete_session` takes the live refresh
    // index down with the row, which kills every descendant of the
    // replayed token in one step.
    //
    // Best-effort: a store failure here must not swallow the alert, so
    // it is logged and the audit event still fires. Nothing is granted
    // either way — this path only ever returns an error.
    if session.is_some()
        && let Err(e) = backend
            .sessions()
            .delete_session(&tombstone.session_id)
            .await
    {
        tracing::error!(
            session_id = %tombstone.session_id,
            "failed to revoke session after refresh-token reuse: {e:?}",
        );
    }

    backend.audit(AuthAuditEvent::RefreshReuseDetected {
        // From the tombstone, not the session: on the `SessionGone`
        // path the row is absent by definition, and an alert that
        // cannot name the account is not actionable.
        did: &tombstone.did,
        session_id: &tombstone.session_id,
        rotated_at: tombstone.rotated_at,
        reason,
    });

    Err(AuthError::RefreshTokenInvalid.into())
}

/// Whether presenting an already-retired token is a retry rather than
/// reuse.
///
/// Every condition has to hold:
///
/// - the token was retired by **rotation**, not by a re-login. The
///   concession answers a lost rotation response; a client that has
///   just logged in holds its new token and has no reason to present
///   the old one, so allowing it there would hand the new token to
///   whoever replayed a pre-login theft;
/// - the session is still alive and `Authenticated` — there is
///   something to retry *into*;
/// - the replay arrived **inside** the grace window — a client retrying
///   a lost response does so in seconds. Strictly inside, so a grace of
///   `0` admits nothing at all;
/// - the successor recorded at rotation is **still** the session's live
///   refresh token.
///
/// The last is what makes the concession narrow. It holds only while
/// the successor has never been used, which is precisely the situation
/// of a client that never received it. Once anyone spends the successor
/// the window shuts early, so a stolen token replayed seconds after a
/// legitimate refresh is still caught.
///
/// Conformance with VTI-SES-030 (exactly one concurrent claimant
/// succeeds): the claim itself is still the atomic take in
/// [`handle_refresh`], and a caller racing it misses the index before
/// the tombstone exists and is refused. What passes here is a caller
/// arriving *after* that claim completed, and it is handed the claim's
/// own result — no second session, no second refresh token — which is
/// the outcome the requirement's rationale rules out.
fn is_innocent_retry(
    session: &Session,
    tombstone: &RefreshTombstone,
    now: u64,
    grace: u64,
) -> bool {
    tombstone.cause == TombstoneCause::Rotated
        && session.state == SessionState::Authenticated
        && now.saturating_sub(tombstone.rotated_at) < grace
        && session
            .refresh_token
            .as_deref()
            .is_some_and(|live| refresh_token_hash(live) == tombstone.successor_hash)
}

/// Re-serve the rotation the caller missed.
///
/// Returns the session's *current* pair, which the guard conditions in
/// [`is_innocent_retry`] have already established is the very pair the
/// lost response carried. Nothing rotates: the access token is re-minted
/// against the session's existing `token_id`, so the copy that was lost
/// in flight and this one are the same token as far as the `jti` pin is
/// concerned, and a client that somehow received both can use either.
///
/// The ACL is re-checked exactly as on the rotation path, so a DID
/// revoked in between is refused here too.
async fn replay_rotation<B: AuthBackend>(
    backend: &B,
    session: &Session,
    now: u64,
) -> Result<AuthenticateResponse, B::Error> {
    let (amr, acr) = super::refresh_amr_acr(session);
    let role_resolution = backend.check_acl(&session.did).await?;

    let access_ttl = if acr == "aal2" {
        backend.access_token_ttl_for_aal2()
    } else {
        backend.access_token_ttl()
    };
    let access_expires_at = now.saturating_add(access_ttl);

    // Both are `Some` on any session reachable here — `is_innocent_retry`
    // matched the live refresh token, and a session with a refresh token
    // was minted with a `token_id`. Treated as a rejection rather than
    // asserted: a hand-written or pre-migration row must not panic an
    // unauthenticated endpoint.
    let (Some(refresh_token), Some(token_id)) =
        (session.refresh_token.clone(), session.token_id.clone())
    else {
        return Err(AuthError::RefreshTokenInvalid.into());
    };

    let access_token = backend
        .mint_access_token(
            &session.did,
            &session.session_id,
            &role_resolution.role,
            &role_resolution.contexts,
            &amr,
            &acr,
            session.tee_attested,
            access_ttl,
            &token_id,
        )
        .await?;

    // An access token was issued, so the refresh is audited like any
    // other (VTI-SES-041). The session id does not change on rotation
    // either, so old == new here is the same shape a rotation records.
    backend.audit(AuthAuditEvent::Refreshed {
        did: &session.did,
        old_session_id: &session.session_id,
        new_session_id: &session.session_id,
        amr: &amr,
        acr: &acr,
    });

    Ok(AuthenticateResponse {
        session: WireSession {
            id: session.session_id.clone(),
            subject: session.did.clone(),
            issued_at: epoch_to_rfc3339(now),
            expires_at: epoch_to_rfc3339(access_expires_at),
            amr,
            acr,
        },
        tokens: TokenBundle {
            access_token,
            refresh_token: Some(refresh_token),
            token_type: "Bearer".to_string(),
            // Time actually left on the unrotated refresh token, not a
            // fresh full TTL — a retry must not extend the session's
            // life beyond what the rotation it replays had granted.
            refresh_expires_in: session
                .refresh_expires_at
                .map(|expires| expires.saturating_sub(now)),
            expires_in: access_ttl,
            scope: role_resolution
                .contexts
                .into_iter()
                .map(|c| format!("ctx:{c}"))
                .collect(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::backend::{RoleResolution, SessionStore};
    use crate::error::AppError;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// In-memory stand-in for the `sessions` keyspace.
    ///
    /// Faithful on the two behaviours the detection logic rests on:
    /// `take_session_id_by_refresh` is claim-and-delete, and
    /// `delete_session` takes the live refresh index down with the row.
    #[derive(Default)]
    struct MemStore {
        sessions: Mutex<HashMap<String, Session>>,
        refresh_index: Mutex<HashMap<String, String>>,
        /// `session_id → hash` of the token it currently issues, written
        /// only by `store_refresh_index` — as `KeyspaceSessionStore` does.
        current: Mutex<HashMap<String, String>>,
        tombstones: Mutex<HashMap<String, RefreshTombstone>>,
    }

    #[async_trait]
    impl SessionStore for MemStore {
        type Error = AppError;

        async fn store_session(&self, s: &Session) -> Result<(), AppError> {
            self.sessions
                .lock()
                .unwrap()
                .insert(s.session_id.clone(), s.clone());
            Ok(())
        }

        async fn get_session(&self, id: &str) -> Result<Option<Session>, AppError> {
            Ok(self.sessions.lock().unwrap().get(id).cloned())
        }

        async fn delete_session(&self, id: &str) -> Result<(), AppError> {
            self.current.lock().unwrap().remove(id);
            if let Some(s) = self.sessions.lock().unwrap().remove(id)
                && let Some(t) = s.refresh_token
            {
                self.refresh_index.lock().unwrap().remove(&t);
            }
            Ok(())
        }

        async fn store_refresh_index(&self, token: &str, id: &str) -> Result<(), AppError> {
            self.current
                .lock()
                .unwrap()
                .insert(id.to_string(), refresh_token_hash(token));
            self.refresh_index
                .lock()
                .unwrap()
                .insert(token.to_string(), id.to_string());
            Ok(())
        }

        async fn take_session_id_by_refresh(
            &self,
            token: &str,
        ) -> Result<Option<String>, AppError> {
            Ok(self.refresh_index.lock().unwrap().remove(token))
        }

        async fn current_refresh_hash(&self, id: &str) -> Result<Option<String>, AppError> {
            Ok(self.current.lock().unwrap().get(id).cloned())
        }

        async fn count_pending_challenges(&self, _: &str) -> Result<usize, AppError> {
            Ok(0)
        }

        async fn store_refresh_tombstone(
            &self,
            rotated: &str,
            tombstone: &RefreshTombstone,
        ) -> Result<(), AppError> {
            self.tombstones
                .lock()
                .unwrap()
                .insert(rotated.to_string(), tombstone.clone());
            Ok(())
        }

        async fn get_refresh_tombstone(
            &self,
            token: &str,
        ) -> Result<Option<RefreshTombstone>, AppError> {
            Ok(self.tombstones.lock().unwrap().get(token).cloned())
        }
    }

    impl MemStore {
        /// Rewind a tombstone's rotation time so a test can cross the
        /// grace window without sleeping.
        fn backdate_tombstone(&self, token: &str, secs: u64) {
            let mut t = self.tombstones.lock().unwrap();
            let entry = t.get_mut(token).expect("tombstone exists");
            entry.rotated_at = entry.rotated_at.saturating_sub(secs);
        }

        fn session_count(&self) -> usize {
            self.sessions.lock().unwrap().len()
        }
    }

    struct MockBackend<S: SessionStore<Error = AppError>> {
        store: S,
        grace: u64,
        alerts: Arc<Mutex<Vec<(String, RefreshReuseReason)>>>,
        /// `RefreshSuperseded` events, kept apart from `alerts` so a
        /// test can assert that a superseded replay raised the *lower*
        /// signal and did **not** raise a reuse alert.
        superseded: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl<S: SessionStore<Error = AppError>> AuthBackend for MockBackend<S> {
        type Store = S;
        type Error = AppError;
        type Role = String;

        fn sessions(&self) -> &S {
            &self.store
        }

        #[allow(clippy::too_many_arguments)]
        async fn mint_access_token(
            &self,
            _subject: &str,
            _session_id: &str,
            _role: &String,
            _contexts: &[String],
            _amr: &[String],
            _acr: &str,
            _tee_attested: bool,
            _ttl_secs: u64,
            jti: &str,
        ) -> Result<String, AppError> {
            // Echo the jti so a test can tell a re-mint of the same
            // token apart from a rotation to a new one.
            Ok(format!("access:{jti}"))
        }

        async fn check_acl(&self, _did: &str) -> Result<RoleResolution<String>, AppError> {
            Ok(RoleResolution::new("reader".to_string()))
        }

        fn challenge_ttl(&self) -> u64 {
            60
        }
        fn access_token_ttl(&self) -> u64 {
            900
        }
        fn refresh_token_ttl(&self) -> u64 {
            86_400
        }
        fn refresh_reuse_grace(&self) -> u64 {
            self.grace
        }

        fn audit(&self, event: AuthAuditEvent<'_>) {
            match event {
                AuthAuditEvent::RefreshReuseDetected {
                    session_id, reason, ..
                } => {
                    self.alerts
                        .lock()
                        .unwrap()
                        .push((session_id.to_string(), reason));
                }
                AuthAuditEvent::RefreshSuperseded { session_id, .. } => {
                    self.superseded.lock().unwrap().push(session_id.to_string());
                }
                _ => {}
            }
        }
    }

    const DID: &str = "did:key:zHolder";

    /// An authenticated session row + its live refresh index, as
    /// `/auth/authenticate` would have left them, in whichever store
    /// the test wants to exercise.
    async fn seed<S: SessionStore<Error = AppError>>(store: &S) -> String {
        let token = "refresh-0".to_string();
        let now = now_epoch();
        let session = Session {
            session_id: DID.to_string(),
            did: DID.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now,
            last_seen: now,
            refresh_token: Some(token.clone()),
            refresh_expires_at: Some(now + 86_400),
            tee_attested: false,
            amr: vec!["did".to_string()],
            acr: "aal1".to_string(),
            acr_expires_at: None,
            token_id: Some("jti-0".to_string()),
            session_pubkey_b58btc: None,
        };
        store.store_session(&session).await.unwrap();
        store.store_refresh_index(&token, DID).await.unwrap();
        token
    }

    async fn logged_in(grace: u64) -> (MockBackend<MemStore>, String) {
        let b = MockBackend {
            store: MemStore::default(),
            grace,
            alerts: Arc::new(Mutex::new(Vec::new())),
            superseded: Arc::new(Mutex::new(Vec::new())),
        };
        let token = seed(&b.store).await;
        (b, token)
    }

    fn input(token: &str) -> RefreshInput {
        RefreshInput {
            refresh_token: token.to_string(),
            signer_did: None,
        }
    }

    fn alerts<S: SessionStore<Error = AppError>>(
        b: &MockBackend<S>,
    ) -> Vec<(String, RefreshReuseReason)> {
        b.alerts.lock().unwrap().clone()
    }

    /// Session ids named by `RefreshSuperseded` events.
    fn superseded_alerts<S: SessionStore<Error = AppError>>(b: &MockBackend<S>) -> Vec<String> {
        b.superseded.lock().unwrap().clone()
    }

    /// `AuthError::RefreshTokenInvalid` surfaces through the backend's
    /// error type as an authentication failure with a fixed message —
    /// the same one an unrecognised token produces.
    fn assert_refused(err: &AppError) {
        assert!(matches!(err, AppError::Authentication(_)), "got {err:?}");
    }

    // ── Rotation (the RFC 9700 §4.14.2 baseline) ────────────────────

    /// The property the original finding was about: the token that was
    /// presented does not come back, and it does not work twice.
    #[tokio::test]
    async fn refresh_rotates_the_token_and_spends_the_one_presented() {
        let (b, first) = logged_in(30).await;

        let resp = handle_refresh(&b, input(&first)).await.unwrap();
        let second = resp.tokens.refresh_token.clone().expect("rotated token");

        assert_ne!(second, first, "the presented token must not be re-issued");
        assert!(
            !b.store.refresh_index.lock().unwrap().contains_key(&first),
            "the spent token must leave the live index",
        );
        assert!(
            b.store.tombstones.lock().unwrap().contains_key(&first),
            "the spent token must be tombstoned so a replay is attributable",
        );

        // And the replacement is itself usable exactly once.
        assert!(handle_refresh(&b, input(&second)).await.is_ok());
    }

    // ── Detection ───────────────────────────────────────────────────

    /// A token this node never issued is refused, and — crucially — is
    /// *not* reported as a compromise. Nothing was stolen; someone
    /// guessed or a client held a token from a wiped store.
    #[tokio::test]
    async fn an_unrecognised_token_is_refused_without_raising_an_alert() {
        let (b, _) = logged_in(30).await;

        let err = handle_refresh(&b, input("never-issued")).await.unwrap_err();

        assert_refused(&err);
        assert!(alerts(&b).is_empty(), "a stranger's token is not an alert");
        assert_eq!(b.store.session_count(), 1, "nothing revoked");
    }

    /// The headline case from the finding: an attacker sits on a stolen
    /// token and replays it later. Past the grace window it is reuse.
    #[tokio::test]
    async fn replaying_a_spent_token_after_the_grace_window_revokes_the_session() {
        let (b, first) = logged_in(30).await;
        handle_refresh(&b, input(&first)).await.unwrap();

        // Sat on it for five minutes.
        b.store.backdate_tombstone(&first, 300);

        let err = handle_refresh(&b, input(&first)).await.unwrap_err();

        assert_refused(&err);
        assert_eq!(
            alerts(&b),
            vec![(DID.to_string(), RefreshReuseReason::GraceExpired)],
        );
        assert_eq!(b.store.session_count(), 0, "session must be revoked");
    }

    /// Revocation has to be of the *session*, not merely of the token
    /// that was replayed — otherwise the attacker's descendant token
    /// (or the victim's) would survive the detection.
    #[tokio::test]
    async fn detection_kills_every_token_descended_from_the_replayed_one() {
        let (b, first) = logged_in(30).await;
        let live = handle_refresh(&b, input(&first))
            .await
            .unwrap()
            .tokens
            .refresh_token
            .unwrap();

        b.store.backdate_tombstone(&first, 300);
        handle_refresh(&b, input(&first)).await.unwrap_err();

        // The token that was still legitimately in flight is now dead too.
        let err = handle_refresh(&b, input(&live)).await.unwrap_err();
        assert_refused(&err);
    }

    /// Someone kept a token past the end of the session it belonged to.
    #[tokio::test]
    async fn replaying_a_token_from_an_already_dead_session_raises_an_alert() {
        let (b, first) = logged_in(30).await;
        handle_refresh(&b, input(&first)).await.unwrap();
        b.store.delete_session(DID).await.unwrap();

        handle_refresh(&b, input(&first)).await.unwrap_err();

        assert_eq!(
            alerts(&b),
            vec![(DID.to_string(), RefreshReuseReason::SessionGone)],
        );
    }

    // ── The lenient concession ──────────────────────────────────────

    /// The non-attack this grace window exists for: the rotation
    /// response was lost in flight, so the client still holds only the
    /// old token and retries with it. It must get the same pair back,
    /// and must NOT be signed out.
    #[tokio::test]
    async fn a_retry_inside_the_grace_window_replays_the_original_rotation() {
        let (b, first) = logged_in(3600).await;
        let lost = handle_refresh(&b, input(&first)).await.unwrap();

        let retried = handle_refresh(&b, input(&first)).await.unwrap();

        assert_eq!(
            retried.tokens.refresh_token, lost.tokens.refresh_token,
            "the retry must replay the same refresh token, not rotate again",
        );
        assert_eq!(
            retried.tokens.access_token, lost.tokens.access_token,
            "re-minted against the same jti, so the session pin still matches",
        );
        assert!(alerts(&b).is_empty(), "a lost response is not a compromise");
        assert_eq!(b.store.session_count(), 1, "the client stays signed in");
    }

    // ── Tokens retired by a re-login ────────────────────────────────

    /// Stand in for what `/auth/` does when a fresh login supersedes the
    /// previous token: the old index entry goes, and a `Superseded`
    /// tombstone is left in its place.
    async fn supersede(b: &MockBackend<MemStore>, old: &str, successor: &str) {
        b.store.take_session_id_by_refresh(old).await.unwrap();
        let now = now_epoch();
        b.store
            .store_refresh_tombstone(
                old,
                &RefreshTombstone {
                    session_id: DID.to_string(),
                    did: DID.to_string(),
                    rotated_at: now,
                    expires_at: now + 86_400,
                    successor_hash: refresh_token_hash(successor),
                    cause: TombstoneCause::Superseded,
                },
            )
            .await
            .unwrap();
    }

    /// The whole point of separating the causes. The grace window is a
    /// concession to a lost *rotation* response; a client that has just
    /// logged in holds its new token, so a replay of the pre-login one
    /// has no innocent reading. Were the concession allowed here, this
    /// call would hand the caller the freshly minted token — a theft
    /// before the re-login would be rewarded with the token that
    /// replaced it.
    #[tokio::test]
    async fn a_superseded_token_is_never_treated_as_an_innocent_retry() {
        // A wide grace and an unspent successor: every *other* condition
        // for the concession is satisfied, so only the cause can refuse it.
        let (b, stolen) = logged_in(3600).await;
        let fresh_login_token = "token-from-the-second-login";
        supersede(&b, &stolen, fresh_login_token).await;

        let err = handle_refresh(&b, input(&stolen)).await.unwrap_err();

        assert_refused(&err);
        assert_eq!(
            superseded_alerts(&b),
            vec![DID.to_string()],
            "it must raise the superseded signal, inside the grace window",
        );
    }

    /// The security consequence of the case above, stated directly: the
    /// replay must not yield a usable token under any circumstances.
    #[tokio::test]
    async fn replaying_a_superseded_token_never_yields_the_new_token() {
        let (b, stolen) = logged_in(3600).await;
        supersede(&b, &stolen, "token-from-the-second-login").await;

        assert!(
            handle_refresh(&b, input(&stolen)).await.is_err(),
            "the pre-login token must never mint or replay a pair",
        );
    }

    /// Superseded is *not* routed through reuse detection, and so does
    /// not revoke.
    ///
    /// The retired token is already dead — the login took its index
    /// entry — so revoking adds nothing against a thief, while the
    /// ordinary cause is a second device presenting what it was issued
    /// before the user signed in elsewhere. Killing the session there
    /// would sign out the client that is demonstrably live, and the
    /// re-login it forces would set the same trap again.
    #[tokio::test]
    async fn replaying_a_superseded_token_leaves_the_live_session_running() {
        let (b, stolen) = logged_in(3600).await;
        supersede(&b, &stolen, "token-from-the-second-login").await;

        let _ = handle_refresh(&b, input(&stolen)).await;

        assert_eq!(
            b.store.session_count(),
            1,
            "the session that replaced the token must survive the replay",
        );
        assert_eq!(
            alerts(&b),
            vec![],
            "and it must not be reported as reuse — the consequence differs",
        );
        assert_eq!(superseded_alerts(&b), vec![DID.to_string()]);
    }

    /// The retry must not buy the session a fresh 24 hours; it replays a
    /// rotation that already happened.
    /// The residual risk on #1683: a token whose index entry outlived a
    /// re-login — the retirement at login is best-effort and a racing
    /// rotation can slip past it — must not mint into a second chain.
    ///
    /// Remove the currency check in `handle_refresh` and this succeeds,
    /// handing the holder of the old token a live chain beside the owner's.
    #[tokio::test]
    async fn a_surviving_index_entry_for_a_non_current_token_is_refused() {
        let (b, stale) = logged_in(30).await;
        // A later login makes `refresh-1` current. Put the old entry back,
        // as a retirement that lost its race would leave it.
        b.store.store_refresh_index("refresh-1", DID).await.unwrap();
        b.store
            .refresh_index
            .lock()
            .unwrap()
            .insert(stale.clone(), DID.to_string());

        let err = handle_refresh(&b, input(&stale)).await.unwrap_err();
        assert_refused(&err);
        assert_eq!(superseded_alerts(&b), vec![DID.to_string()]);
        assert!(alerts(&b).is_empty(), "a superseded token is not reuse");

        // The current chain is untouched, and a replay of the refused
        // token is still recognised rather than looking like a stranger's.
        handle_refresh(&b, input("refresh-1")).await.unwrap();
        let tomb = b.store.tombstones.lock().unwrap().get(&stale).cloned();
        assert_eq!(tomb.map(|t| t.cause), Some(TombstoneCause::Superseded));
    }

    /// A read-modify-write of the session row (an activity touch, a
    /// DIDComm message resolving the session, a step-up) can write an older
    /// `refresh_token` back into it after a rotation. Currency must not be
    /// read from the row, or the owner's current token is refused and they
    /// are signed out.
    #[tokio::test]
    async fn a_stale_row_does_not_refuse_the_current_token() {
        let (b, first) = logged_in(30).await;
        let rotated = handle_refresh(&b, input(&first)).await.unwrap();
        let current = rotated.tokens.refresh_token.unwrap();

        // The lost-update: a writer that read the row before the rotation
        // saves its copy back.
        let mut row = b.store.get_session(DID).await.unwrap().unwrap();
        row.refresh_token = Some(first.clone());
        b.store.store_session(&row).await.unwrap();

        handle_refresh(&b, input(&current))
            .await
            .expect("the token the client holds is still current");
        assert!(superseded_alerts(&b).is_empty());
    }

    #[tokio::test]
    async fn a_retry_does_not_extend_the_refresh_deadline() {
        let (b, first) = logged_in(3600).await;
        handle_refresh(&b, input(&first)).await.unwrap();

        let retried = handle_refresh(&b, input(&first)).await.unwrap();

        let remaining = retried.tokens.refresh_expires_in.expect("a deadline");
        assert!(
            remaining <= b.refresh_token_ttl(),
            "retry reported {remaining}s left, more than a full TTL",
        );
    }

    /// The narrowing condition. Inside the window in wall-clock terms,
    /// but the session has already moved past the successor — so the
    /// party replaying the old token is not the party that received the
    /// response, and this is theft after all.
    #[tokio::test]
    async fn a_replay_is_reuse_once_the_chain_has_advanced_even_inside_the_window() {
        let (b, first) = logged_in(3600).await;
        let second = handle_refresh(&b, input(&first))
            .await
            .unwrap()
            .tokens
            .refresh_token
            .unwrap();
        // The legitimate client got the response and used it.
        handle_refresh(&b, input(&second)).await.unwrap();

        let err = handle_refresh(&b, input(&first)).await.unwrap_err();

        assert_refused(&err);
        assert_eq!(
            alerts(&b),
            vec![(DID.to_string(), RefreshReuseReason::ChainAdvanced)],
        );
        assert_eq!(b.store.session_count(), 0, "session must be revoked");
    }

    /// A grace of zero turns every replay into a compromise signal, for
    /// deployments that would rather sign a user out than miss a theft.
    #[tokio::test]
    async fn a_zero_grace_treats_an_immediate_retry_as_reuse() {
        let (b, first) = logged_in(0).await;
        handle_refresh(&b, input(&first)).await.unwrap();

        handle_refresh(&b, input(&first)).await.unwrap_err();

        assert_eq!(alerts(&b).len(), 1, "no concession at grace 0");
    }

    /// The caller must not be able to tell a detected replay from an
    /// unrecognised token — that difference would tell an attacker
    /// exactly when they had been caught.
    #[tokio::test]
    async fn reuse_and_an_unknown_token_look_identical_to_the_caller() {
        let (b, first) = logged_in(30).await;
        handle_refresh(&b, input(&first)).await.unwrap();
        b.store.backdate_tombstone(&first, 300);

        let reused = handle_refresh(&b, input(&first)).await.unwrap_err();
        let (b2, _) = logged_in(30).await;
        let unknown = handle_refresh(&b2, input("never-issued"))
            .await
            .unwrap_err();

        assert_eq!(format!("{reused}"), format!("{unknown}"));
    }

    /// A backend that leaves the tombstone hooks at their defaults keeps
    /// exactly the pre-detection behaviour: replay refused, no alert, no
    /// revocation. Guards the "degrade to rotation-only" contract that
    /// lets an out-of-tree `SessionStore` adopt this release unchanged.
    #[tokio::test]
    async fn a_backend_without_tombstone_support_degrades_to_rotation_only() {
        /// Delegates everything except the two tombstone hooks, which
        /// are left at their trait defaults.
        #[derive(Default)]
        struct NoTombstones(MemStore);

        #[async_trait]
        impl SessionStore for NoTombstones {
            type Error = AppError;
            async fn store_session(&self, s: &Session) -> Result<(), AppError> {
                self.0.store_session(s).await
            }
            async fn get_session(&self, id: &str) -> Result<Option<Session>, AppError> {
                self.0.get_session(id).await
            }
            async fn delete_session(&self, id: &str) -> Result<(), AppError> {
                self.0.delete_session(id).await
            }
            async fn store_refresh_index(&self, t: &str, id: &str) -> Result<(), AppError> {
                self.0.store_refresh_index(t, id).await
            }
            async fn take_session_id_by_refresh(
                &self,
                t: &str,
            ) -> Result<Option<String>, AppError> {
                self.0.take_session_id_by_refresh(t).await
            }
            async fn count_pending_challenges(&self, d: &str) -> Result<usize, AppError> {
                self.0.count_pending_challenges(d).await
            }
            // store_refresh_tombstone / get_refresh_tombstone: defaults.
        }

        let b = MockBackend {
            store: NoTombstones::default(),
            grace: 30,
            alerts: Arc::new(Mutex::new(Vec::new())),
            superseded: Arc::new(Mutex::new(Vec::new())),
        };
        let first = seed(&b.store).await;

        // Rotation still works and still spends the presented token.
        let second = handle_refresh(&b, input(&first))
            .await
            .unwrap()
            .tokens
            .refresh_token
            .unwrap();
        assert_ne!(second, first);

        // The replay is refused — just not attributed, and nothing is
        // revoked, because there is no record to attribute it to.
        let err = handle_refresh(&b, input(&first)).await.unwrap_err();
        assert_refused(&err);
        assert!(alerts(&b).is_empty(), "no tombstone, no alert");
        assert_eq!(b.store.0.session_count(), 1, "session survives");
    }

    /// A tombstone write that fails must not fail a rotation that is
    /// already committed. Returning the error would withhold the only
    /// live refresh token from its owner, whose retry with the spent one
    /// then finds no tombstone and is refused — a sign-out caused by a
    /// record that exists only for detection.
    #[tokio::test]
    async fn a_failed_tombstone_write_does_not_fail_the_rotation() {
        #[derive(Default)]
        struct FailingTombstones(MemStore);

        #[async_trait]
        impl SessionStore for FailingTombstones {
            type Error = AppError;
            async fn store_session(&self, s: &Session) -> Result<(), AppError> {
                self.0.store_session(s).await
            }
            async fn get_session(&self, id: &str) -> Result<Option<Session>, AppError> {
                self.0.get_session(id).await
            }
            async fn delete_session(&self, id: &str) -> Result<(), AppError> {
                self.0.delete_session(id).await
            }
            async fn store_refresh_index(&self, t: &str, id: &str) -> Result<(), AppError> {
                self.0.store_refresh_index(t, id).await
            }
            async fn take_session_id_by_refresh(
                &self,
                t: &str,
            ) -> Result<Option<String>, AppError> {
                self.0.take_session_id_by_refresh(t).await
            }
            async fn count_pending_challenges(&self, d: &str) -> Result<usize, AppError> {
                self.0.count_pending_challenges(d).await
            }
            async fn store_refresh_tombstone(
                &self,
                _: &str,
                _: &RefreshTombstone,
            ) -> Result<(), AppError> {
                Err(AppError::Internal("tombstone store unavailable".into()))
            }
            async fn get_refresh_tombstone(
                &self,
                t: &str,
            ) -> Result<Option<RefreshTombstone>, AppError> {
                self.0.get_refresh_tombstone(t).await
            }
        }

        let b = MockBackend {
            store: FailingTombstones::default(),
            grace: 30,
            alerts: Arc::new(Mutex::new(Vec::new())),
            superseded: Arc::new(Mutex::new(Vec::new())),
        };
        let first = seed(&b.store).await;

        let second = handle_refresh(&b, input(&first))
            .await
            .expect("the rotation is committed, so the refresh must succeed")
            .tokens
            .refresh_token
            .unwrap();

        // The token it handed out is the live one.
        handle_refresh(&b, input(&second))
            .await
            .expect("the rotated token must work");
        assert!(alerts(&b).is_empty());
    }
}
