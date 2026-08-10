//! Pending step-up store.
//!
//! When an AAL1 session hits a step-up-gated operation, the relying party
//! (the VTA) mints a **pending step-up**: a short-lived, single-use record
//! binding a fresh `challenge` to the `session_id`/`subject` being elevated and
//! the `targetAcr` requested. It is keyed by the challenge so the matching
//! `auth/step-up/approve-response/0.1` can be located by its echoed challenge.
//!
//! Stored under `stepup:{challenge}` in the sessions keyspace, mirroring the
//! `nonce:`/`refresh:` index conventions in [`crate::auth::session`]. Records
//! are consumed exactly once on a successful (or expired) match so an
//! approve-response cannot be replayed.

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

use super::session::now_epoch;

/// A pending AAL step-up awaiting an `approve-response`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingStepUp {
    /// base64url challenge the approver echoes + signs/asserts over. The
    /// store key is `stepup:{challenge}`.
    pub challenge: String,
    /// The session being elevated.
    pub session_id: String,
    /// The VID whose session is being elevated; the approve-response's
    /// `subject` MUST equal this.
    pub subject: String,
    /// The VID authorized to *sign* the approve-response — the document
    /// `issuer` / proof VM DID (or credential subject) the relying party will
    /// accept. Equals [`Self::subject`] for **self** step-up; the delegated
    /// `AclEntry.stepUp.approver` the request was addressed to for
    /// **delegated** step-up. The relying party elevates only when the signer
    /// equals this.
    ///
    /// `#[serde(default)]` so an in-flight record written before this field
    /// existed deserializes with an empty approver; the handler treats an empty
    /// approver as self (issuer MUST equal subject), preserving the prior
    /// contract for the ≤TTL window after a deploy.
    #[serde(default)]
    pub approver: String,
    /// `true` for **`delegated-any`** mode: the approve-response is authorized
    /// not against a single bound [`Self::approver`] but against the relying
    /// party's approver *criterion* (the issuer must be an admin covering the
    /// subject's contexts — see `acl::delegated_any_approver_covers`).
    /// [`Self::approver`] is empty in this mode. `#[serde(default)]` so older
    /// records deserialize as `false` (the self/delegated single-approver path).
    #[serde(default)]
    pub approver_any: bool,
    /// The acr the relying party requested. The elevated session MUST reach
    /// at least this, else `acr_unsatisfied`.
    pub target_acr: String,
    /// Evidence kinds the relying party will accept (`did-signed`,
    /// `webauthn`). Empty = any supported kind.
    #[serde(default)]
    pub acceptable_evidence: Vec<String>,
    pub created_at: u64,
    /// Unix seconds after which the step-up is no longer valid.
    pub expires_at: u64,
}

// The `op_class` module lived here: eleven slugs (`acl/grant`,
// `context/delete`, `vault/release`, …) that a `[auth.step_up]` floor keyed on,
// plus the `*` catch-all. It is retired along with the floors it addressed. A
// rule names the task URI itself, so there is no closed list to keep in step
// with the dispatch table — and no way for a gated task to fall outside it.

/// Step-up enforcement mode.
///
/// Retained **only** as the type of `AclEntry.stepUp.require`, a published wire
/// field. Nothing reads it to make a decision any more: the floors that
/// composed a system mode with this per-entry override are gone, and the gate
/// asks the rules. Removing the field is a separate slice with its own wire
/// consequences (~35 vta-sdk sites and the CLI flags that set it), so it stays
/// serialisable and inert rather than half-removed.
///
/// Strictness (least → most): `None` < `SelfApprove` < `DelegatedAny` <
/// `Delegated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum StepUpMode {
    /// AAL1 permitted — no step-up required.
    #[default]
    None,
    /// The caller elevates its own session (AAL2 via its own authenticator).
    #[serde(rename = "self")]
    SelfApprove,
    /// A specific approver (the caller's `AclEntry.stepUp.approver`) must
    /// ratify the elevation.
    Delegated,
    /// Any VID meeting the maintainer's approver criterion may ratify.
    DelegatedAny,
}

// `rank`, `requires_aal2`, and `strictest` lived here. They composed a system
// floor with a per-entry override — "an override may raise, never lower" — and
// there is no system floor left to compose with. The enum survives as a wire
// shape, not as a decision procedure.

// `StepUpFloor` and `StepUpPolicy` lived here — the `{enabled, floors[]}` shape
// the VTA serialised under `[auth.step_up]`, and the resolution that picked the
// most specific floor for an op-class. Both are retired; `AuthConfig` now
// refuses a config that still carries the section rather than parse one nothing
// reads.

fn step_up_key(challenge: &str) -> String {
    format!("stepup:{challenge}")
}

/// Outcome of consuming a pending step-up by challenge.
#[derive(Debug, PartialEq)]
pub enum ConsumeOutcome {
    /// No pending step-up matched the challenge (`challenge_unknown`).
    NotFound,
    /// A match existed but had expired (`challenge_expired`). The stale
    /// record is removed as a side effect.
    Expired,
    /// A live match; the record was removed (single-use).
    Found(Box<PendingStepUp>),
}

/// Store a pending step-up keyed by its challenge.
pub async fn store_pending_step_up(
    sessions: &KeyspaceHandle,
    pending: &PendingStepUp,
) -> Result<(), AppError> {
    sessions
        .insert(step_up_key(&pending.challenge), pending)
        .await
}

/// Read a pending step-up by challenge without consuming it. Returns the raw
/// record (no expiry filtering) — callers that want single-use semantics
/// should use [`consume_pending_step_up`].
pub async fn get_pending_step_up(
    sessions: &KeyspaceHandle,
    challenge: &str,
) -> Result<Option<PendingStepUp>, AppError> {
    sessions.get(step_up_key(challenge)).await
}

/// Locate and **consume** the pending step-up matching `challenge` (single
/// use). On a live match the record is removed and returned; on an expired
/// match the stale record is removed and [`ConsumeOutcome::Expired`] returned;
/// a miss yields [`ConsumeOutcome::NotFound`].
///
/// Typed records are stored encrypted-aware via `insert`, so consumption is a
/// `get` (which decrypts) + `remove`, matching how the rest of the session
/// layer handles typed rows. The remove makes the challenge single-use.
pub async fn consume_pending_step_up(
    sessions: &KeyspaceHandle,
    challenge: &str,
    now: u64,
) -> Result<ConsumeOutcome, AppError> {
    let key = step_up_key(challenge);
    let Some(pending): Option<PendingStepUp> = sessions.get(key.clone()).await? else {
        return Ok(ConsumeOutcome::NotFound);
    };
    // Single-use either way: remove before returning so neither a live nor an
    // expired challenge can be presented twice.
    sessions.remove(key).await?;
    if now >= pending.expires_at {
        return Ok(ConsumeOutcome::Expired);
    }
    Ok(ConsumeOutcome::Found(Box::new(pending)))
}

/// Convenience: build a pending step-up expiring `ttl_secs` from now.
pub fn new_pending_step_up(
    challenge: impl Into<String>,
    session_id: impl Into<String>,
    subject: impl Into<String>,
    approver: impl Into<String>,
    approver_any: bool,
    target_acr: impl Into<String>,
    acceptable_evidence: Vec<String>,
    ttl_secs: u64,
) -> PendingStepUp {
    let created_at = now_epoch();
    PendingStepUp {
        challenge: challenge.into(),
        session_id: session_id.into(),
        subject: subject.into(),
        approver: approver.into(),
        approver_any,
        target_acr: target_acr.into(),
        acceptable_evidence,
        created_at,
        expires_at: created_at.saturating_add(ttl_secs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    async fn ks() -> KeyspaceHandle {
        let dir = tempfile::tempdir().expect("tempdir");
        // Leak the tempdir for the test's lifetime so the fjall files survive.
        let dir = Box::leak(Box::new(dir));
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        store.keyspace("sessions").expect("keyspace")
    }

    fn sample(challenge: &str, expires_at: u64) -> PendingStepUp {
        PendingStepUp {
            challenge: challenge.to_string(),
            session_id: "sess-1".to_string(),
            subject: "did:key:zHolder".to_string(),
            approver: "did:key:zHolder".to_string(),
            approver_any: false,
            target_acr: "aal2".to_string(),
            acceptable_evidence: vec!["did-signed".into(), "webauthn".into()],
            created_at: 1000,
            expires_at,
        }
    }

    #[tokio::test]
    async fn round_trips_and_consumes_once() {
        let ks = ks().await;
        let p = sample("VHJhbnNmZXJDb25maXJtTm9uY2VYWQ", now_epoch() + 300);
        store_pending_step_up(&ks, &p).await.unwrap();

        // get does not consume
        assert_eq!(
            get_pending_step_up(&ks, &p.challenge).await.unwrap(),
            Some(p.clone())
        );

        // first consume returns it
        match consume_pending_step_up(&ks, &p.challenge, now_epoch())
            .await
            .unwrap()
        {
            ConsumeOutcome::Found(found) => assert_eq!(*found, p),
            other => panic!("expected Found, got {other:?}"),
        }
        // second consume is a miss (single-use)
        assert_eq!(
            consume_pending_step_up(&ks, &p.challenge, now_epoch())
                .await
                .unwrap(),
            ConsumeOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn unknown_challenge_is_not_found() {
        let ks = ks().await;
        assert_eq!(
            consume_pending_step_up(&ks, "no-such-challenge", now_epoch())
                .await
                .unwrap(),
            ConsumeOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn expired_challenge_is_consumed_and_reported_expired() {
        let ks = ks().await;
        let p = sample("RXhwaXJlZENoYWxsZW5nZVZhbHVlWA", 1000); // expires_at in the past
        store_pending_step_up(&ks, &p).await.unwrap();
        assert_eq!(
            consume_pending_step_up(&ks, &p.challenge, now_epoch())
                .await
                .unwrap(),
            ConsumeOutcome::Expired
        );
        // expired record was removed
        assert_eq!(get_pending_step_up(&ks, &p.challenge).await.unwrap(), None);
    }

    #[test]
    fn new_pending_sets_expiry() {
        let p = new_pending_step_up(
            "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
            "sess-1",
            "did:key:zHolder",
            "did:key:zApprover",
            false,
            "aal2",
            vec!["webauthn".into()],
            300,
        );
        assert_eq!(p.expires_at, p.created_at + 300);
        assert_eq!(p.target_acr, "aal2");
        assert_eq!(p.approver, "did:key:zApprover");
        assert!(!p.approver_any);
    }

    #[test]
    fn legacy_record_without_approver_defaults_empty() {
        // A record serialized before `approver` existed must still deserialize
        // (serde default) with an empty approver — the handler treats that as
        // self (issuer MUST equal subject), preserving the prior contract.
        let legacy = r#"{
            "challenge":"VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
            "session_id":"sess-1",
            "subject":"did:key:zHolder",
            "target_acr":"aal2",
            "acceptable_evidence":["did-signed"],
            "created_at":1000,
            "expires_at":2000
        }"#;
        let p: PendingStepUp = serde_json::from_str(legacy).expect("legacy record deserializes");
        assert_eq!(p.approver, "");
        assert_eq!(p.subject, "did:key:zHolder");
    }

    /// The wire tokens are the reason [`StepUpMode`] survives at all —
    /// `AclEntry.stepUp.require` is a published field, and its spellings have to
    /// keep round-tripping even though nothing acts on the value any more.
    #[test]
    fn mode_serde_uses_spec_wire_tokens() {
        assert_eq!(
            serde_json::to_string(&StepUpMode::SelfApprove).unwrap(),
            "\"self\""
        );
        assert_eq!(
            serde_json::to_string(&StepUpMode::DelegatedAny).unwrap(),
            "\"delegated-any\""
        );
        assert_eq!(
            serde_json::from_str::<StepUpMode>("\"none\"").unwrap(),
            StepUpMode::None
        );
    }
}
