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

/// Canonical operation-class slugs the VTA gates with a step-up floor.
///
/// A policy `floor.operation` MUST be one of these or `*` (the catch-all);
/// anything else is rejected as `unknownOperation` when a policy is set. Single
/// source of truth shared by the gate (`routes::trust_tasks::step_up::op`
/// re-exports these) and the policy-management validation.
pub mod op_class {
    pub const ACL_GRANT: &str = "acl/grant";
    pub const ACL_CHANGE_ROLE: &str = "acl/change-role";
    pub const ACL_REVOKE: &str = "acl/revoke";
    pub const ACL_SWAP_KEY: &str = "acl/swap-key";
    pub const CONTEXT_DELETE: &str = "context/delete";
    pub const KEY_REVOKE: &str = "key/revoke";

    /// Every recognized operation-class (excludes the `*` catch-all).
    pub const ALL: &[&str] = &[
        ACL_GRANT,
        ACL_CHANGE_ROLE,
        ACL_REVOKE,
        ACL_SWAP_KEY,
        CONTEXT_DELETE,
        KEY_REVOKE,
    ];

    /// Whether `operation` is a floor target the maintainer recognizes: a known
    /// op-class or the `*` catch-all.
    pub fn is_recognized(operation: &str) -> bool {
        operation == "*" || ALL.contains(&operation)
    }
}

/// Step-up enforcement mode for an operation-class — the assurance the
/// relying party requires before the operation runs. Mirrors the
/// `auth/step-up/policy/0.1` `FloorMode`. Strictness (least → most):
/// `None` < `SelfApprove` < `DelegatedAny` < `Delegated`.
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

impl StepUpMode {
    /// Strictness rank for floor/override composition (higher = stricter).
    fn rank(self) -> u8 {
        match self {
            StepUpMode::None => 0,
            StepUpMode::SelfApprove => 1,
            StepUpMode::DelegatedAny => 2,
            StepUpMode::Delegated => 3,
        }
    }

    /// Whether this mode demands AAL2 (anything stricter than `None`).
    pub fn requires_aal2(self) -> bool {
        self != StepUpMode::None
    }

    /// The stricter of two modes — used to compose a system floor with a
    /// per-entry override (additive-only: an override may raise, never lower).
    pub fn strictest(self, other: StepUpMode) -> StepUpMode {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// A per-operation-class step-up floor. Mirrors `auth/step-up/policy/0.1`
/// `Floor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepUpFloor {
    /// Operation-class this floor governs: a stable op-class id (e.g.
    /// `acl/grant`, `acl/swap-key`, `context/delete`, `key/revoke`,
    /// `vault/release`) or `*` for the catch-all default.
    pub operation: String,
    /// Minimum mode required to perform the operation.
    pub mode: StepUpMode,
    /// Admit a non-escalating self-service request at AAL1 even when `mode`
    /// requires AAL2 — the rotation/enrolment carve-out. Default `false`
    /// (fail-closed for escalating operations).
    #[serde(default)]
    pub allow_aal1_if_non_escalating: bool,
}

/// The relying party's system-wide step-up policy.
///
/// **Ships disabled.** A freshly-provisioned VTA has no registered approver
/// and could not otherwise be administered (it could not even register the
/// first approver), so until an operator turns it on every operation proceeds
/// at AAL1. Mirrors the `auth/step-up/policy/0.1` payload; the VTA serializes
/// it under `[auth.step_up]` in its config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StepUpPolicy {
    /// Master switch. `false` (the default) ⇒ step-up is NOT enforced
    /// anywhere; every operation proceeds at AAL1 regardless of `floors`.
    #[serde(default)]
    pub enabled: bool,
    /// Per-operation-class floors. Empty ⇒ nothing is gated even when
    /// `enabled`.
    #[serde(default)]
    pub floors: Vec<StepUpFloor>,
}

impl StepUpPolicy {
    /// Resolve the system-floor mode for an operation-class: the most
    /// specific matching floor, else the `*` catch-all, else `None`. Always
    /// `None` when the policy is disabled.
    pub fn floor_for(&self, operation: &str) -> StepUpMode {
        self.floor_record(operation)
            .map(|f| f.mode)
            .unwrap_or(StepUpMode::None)
    }

    /// The matching floor record (exact match preferred over the `*`
    /// catch-all), or `None` when disabled or unmatched. Carries the
    /// `allow_aal1_if_non_escalating` flag for the carve-out.
    pub fn floor_record(&self, operation: &str) -> Option<&StepUpFloor> {
        if !self.enabled {
            return None;
        }
        self.floors
            .iter()
            .find(|f| f.operation == operation)
            .or_else(|| self.floors.iter().find(|f| f.operation == "*"))
    }
}

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

    fn floor(op: &str, mode: StepUpMode) -> StepUpFloor {
        StepUpFloor {
            operation: op.to_string(),
            mode,
            allow_aal1_if_non_escalating: false,
        }
    }

    #[test]
    fn default_policy_is_disabled_and_never_gates() {
        let p = StepUpPolicy::default();
        assert!(!p.enabled);
        // Disabled ⇒ every operation resolves to None regardless of floors.
        assert_eq!(p.floor_for("acl/grant"), StepUpMode::None);
        assert_eq!(p.floor_for("*"), StepUpMode::None);
        assert!(!p.floor_for("anything").requires_aal2());
    }

    #[test]
    fn disabled_policy_ignores_configured_floors() {
        let p = StepUpPolicy {
            enabled: false,
            floors: vec![floor("*", StepUpMode::Delegated)],
        };
        assert_eq!(p.floor_for("acl/grant"), StepUpMode::None);
        assert!(p.floor_record("acl/grant").is_none());
    }

    #[test]
    fn enabled_resolves_exact_then_catch_all() {
        let p = StepUpPolicy {
            enabled: true,
            floors: vec![
                floor("*", StepUpMode::SelfApprove),
                floor("acl/grant", StepUpMode::Delegated),
            ],
        };
        // Exact match wins over `*`.
        assert_eq!(p.floor_for("acl/grant"), StepUpMode::Delegated);
        // Unlisted op falls back to the catch-all.
        assert_eq!(p.floor_for("context/delete"), StepUpMode::SelfApprove);
    }

    #[test]
    fn enabled_without_catch_all_is_none_for_unlisted() {
        let p = StepUpPolicy {
            enabled: true,
            floors: vec![floor("acl/grant", StepUpMode::Delegated)],
        };
        assert_eq!(p.floor_for("acl/swap-key"), StepUpMode::None);
        assert_eq!(p.floor_for("acl/grant"), StepUpMode::Delegated);
    }

    #[test]
    fn mode_strictness_is_additive() {
        // Override may raise, never lower (strictest wins).
        assert_eq!(
            StepUpMode::SelfApprove.strictest(StepUpMode::Delegated),
            StepUpMode::Delegated
        );
        assert_eq!(
            StepUpMode::Delegated.strictest(StepUpMode::SelfApprove),
            StepUpMode::Delegated
        );
        assert_eq!(
            StepUpMode::None.strictest(StepUpMode::SelfApprove),
            StepUpMode::SelfApprove
        );
        assert!(!StepUpMode::None.requires_aal2());
        assert!(StepUpMode::SelfApprove.requires_aal2());
        assert!(StepUpMode::DelegatedAny.requires_aal2());
    }

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
