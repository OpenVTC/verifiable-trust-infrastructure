//! Second-party consent for unrestricted admin authority — **VTI-APV-014**.
//!
//! > Creating an entry with unrestricted act scope, or widening an entry to
//! > unrestricted act scope, MUST require consent from a party other than the
//! > requester.
//!
//! Unrestricted authority is the grant every other grant is made from, including
//! the removal of the controls that govern it, so one stolen credential must not
//! be enough to make one. The requester's own passkey gesture proves the
//! requester is present; it says nothing about whether anyone else agrees. This
//! module is the anyone-else.
//!
//! Design: `docs/05-design-notes/vtc-operation-bound-step-up.md` §4.
//!
//! ## One model, not a parallel one (VTI-VTC-020)
//!
//! It is the VTA's DTTE ceremony — `task-consent/{request,decision}/0.1` over the
//! same store ([`vti_common::task_consent`]) — with the approver set fixed by the
//! requirement rather than by a configured rule:
//!
//! - **Trigger** ([`confers_unrestricted`]): an `acl/grant` or `acl/change-role`
//!   whose resulting entry is an admin with `ActScope::All`, where the entry
//!   before it was not a live unrestricted admin.
//! - **Approvers**: every other live unrestricted admin — `excludeRequester` is
//!   always on (VTI-APV-007), and approving an unrestricted entry takes
//!   unrestricted approve authority, which only they hold (VTI-APV-006).
//! - **Threshold**: [`crate::config_store::UNRESTRICTED_ADMIN_CONSENT_THRESHOLD`],
//!   default and minimum 1. A value the community cannot meet is refused when it
//!   is written ([`check_threshold_meetable`], VTI-APV-009).
//!
//! ## The loop
//!
//! 1. The operation arrives and every other check passes. [`require`] finds no
//!    grant for `(requester, digest)`, so it raises a pending request (or finds
//!    the one already raised), pushes a VTC-signed `task-consent/request/0.1` to
//!    each approver, and refuses with `auth:consent_required`.
//! 2. An approver answers `task-consent/decision/0.1`, DI-signed ([`decide`]).
//!    Once enough distinct approvers have approved, the pending becomes a grant.
//! 3. The requester sends the **same** operation again. [`require`] finds the
//!    grant, re-checks it against the community *now* — the approvers must still
//!    be unrestricted admins, the threshold must still be met, and the subject's
//!    entry must not have moved since the approvers saw it — and hands back a
//!    [`ReadyGrant`], which the caller spends with the write.
//!
//! The grant binds the payload digest (VTI-APV-004) and is spent exactly once.
//! It elevates nothing (VTI-APV-005): another operation, or the same one with a
//! different payload, finds no grant.
//!
//! ## Composing with the passkey gesture
//!
//! On the signed door both are needed and they are **keyed on the same
//! operation**: the requester's operation-bound step-up
//! ([`super::bound_step_up`]) and this consent. The gesture is asked for first,
//! so a party holding only the requester's signing key cannot make the other
//! admins' devices ring. Neither is spent until both are present.

use std::time::Duration;

use serde_json::{Value, json};
use tracing::{debug, info, warn};
use trust_tasks_rs::specs::task_consent::decision::v0_1 as decision;
use trust_tasks_rs::specs::task_consent::request::v0_1 as request;
use vti_common::audit::{AuditEvent, TaskConsentData};
use vti_common::capability_client::{TRUST_TASK_ENVELOPE_TYPE, build_document};
use vti_common::error::AppError;
use vti_common::task_consent::effects::{Effect, StatePin};
use vti_common::task_consent::{self, PendingTaskConsent, TaskConsentGrant};

use super::{VtcAclEntry, VtcRole, as_vti_role, get_acl_entry, list_acl_entries};
use crate::auth::session::now_epoch;
use crate::config_store::{ConfigStore, UNRESTRICTED_ADMIN_CONSENT_THRESHOLD};
use crate::server::AppState;

/// The approver set a request names. Not configurable: VTI-APV-014 fixes who
/// may consent, so there is no rule to look it up in.
pub const APPROVER_SET: &str = "unrestricted-admins";

/// How long a raised request waits for its approvals. Matches the VTA's gate:
/// a human has to be reached, so minutes rather than seconds.
pub const PENDING_TTL_SECS: u64 = 900;

/// How long a completed consent waits for the requester to send the operation
/// again.
pub const GRANT_TTL_SECS: u64 = 600;

/// The refusal's machine-readable reason, the same string the VTA's gate uses,
/// so one client parses both (`vta_sdk`'s `VtaError::ConsentRequired`).
pub const CONSENT_REQUIRED: &str = "auth:consent_required";

/// `task-consent/request/0.1` — what this service signs and sends approvers.
pub(crate) const REQUEST_TYPE: &str = <request::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `task-consent/decision/0.1` — what an approver answers with.
pub(crate) const DECISION_TYPE: &str = <decision::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Domain tag for the [`StatePin`] version over a subject's ACL entry.
const STATE_DOMAIN: &[u8] = b"vtc/acl-entry-state/v1\0";

/// The operation being consented to: its task type and the payload the digest
/// is taken over.
///
/// Each door passes the payload it would execute. The signed door passes the
/// document's own payload; the bearer routes pass the canonical task payload
/// their body describes, so the digest names the subject as well as the change.
#[derive(Debug, Clone, Copy)]
pub struct Operation<'a> {
    pub type_uri: &'a str,
    pub payload: &'a Value,
}

/// Whether writing an entry of `role` over `scopes` makes its subject an
/// unrestricted admin who was not one — the case VTI-APV-014 gates.
///
/// Decided through `ActScope` rather than by testing `scopes.is_empty()`: an
/// empty list means *unrestricted* for an admin and *nowhere* for every other
/// role, and a check that forgets the role gets one of them backwards.
///
/// An expired unrestricted entry is not unrestricted any more, so granting it
/// again is a new conferral.
#[must_use]
pub fn confers_unrestricted(
    prev: Option<&VtcAclEntry>,
    role: &VtcRole,
    scopes: &[String],
    now: u64,
) -> bool {
    let next = vti_common::acl::act_scope_for(&as_vti_role(role), scopes);
    next.is_unrestricted() && !prev.is_some_and(|p| p.is_super_admin() && !p.is_expired(now))
}

/// The DIDs of every live unrestricted admin.
pub async fn unrestricted_admins(state: &AppState, now: u64) -> Result<Vec<String>, AppError> {
    Ok(list_acl_entries(&state.acl_ks)
        .await?
        .into_iter()
        .filter(|e| e.is_super_admin() && !e.is_expired(now))
        .map(|e| e.did)
        .collect())
}

/// The threshold in force **now**.
///
/// Read through the config layers rather than from the in-memory `AppConfig`: a
/// runtime `config/patch` writes the database layer, and the in-memory copy only
/// follows on `config/reload`. A raised threshold must bind the next request,
/// not the one after the next reload.
pub async fn threshold(state: &AppState) -> Result<u64, AppError> {
    let fallback = state
        .config
        .read()
        .await
        .acl
        .unrestricted_admin_consent_threshold;
    crate::config_store::live_consent_threshold(
        fallback,
        &ConfigStore::new(state.config_ks.clone()),
    )
    .await
}

/// Refuse a threshold the community cannot meet (VTI-APV-009) — checked where
/// the value is written, not discovered when a grant is blocked by it.
///
/// A requester is always an unrestricted admin (only one can confer unrestricted
/// authority), and never counts, so at most `admins - 1` can approve. The
/// minimum, 1, is always accepted: refusing it would not make the community able
/// to meet it, and there is no lower value to choose instead.
pub async fn check_threshold_meetable(state: &AppState, threshold: u64) -> Result<(), AppError> {
    if threshold <= 1 {
        return Ok(());
    }
    let admins = unrestricted_admins(state, now_epoch()).await?.len() as u64;
    if threshold > admins.saturating_sub(1) {
        return Err(AppError::Validation(format!(
            "{UNRESTRICTED_ADMIN_CONSENT_THRESHOLD} = {threshold} could never be met: a grant of \
             unrestricted admin would need {threshold} unrestricted admins besides the one asking, \
             and this community has {admins} in total. Grant more unrestricted admins first, or \
             set it to at most {}",
            admins.saturating_sub(1).max(1)
        )));
    }
    Ok(())
}

/// Whether `entry` is a live unrestricted admin — one of the approvers.
#[must_use]
pub fn is_live_unrestricted(entry: &VtcAclEntry, now: u64) -> bool {
    entry.is_super_admin() && !entry.is_expired(now)
}

/// Refuse a change that takes `subject` — a live unrestricted admin — out of the
/// approvers, when what is left could never consent to anything: no other
/// unrestricted admin at all, or fewer than the threshold needs.
///
/// The attrition half of VTI-APV-009: a rule must not become unsatisfiable by
/// removal any more than by being written that way. Callers are every door that
/// can end an unrestricted admin — a revocation, a removal from the community, a
/// demotion, a grant rewrite that narrows the entry — and each must hold the
/// admin-set lock ([`crate::ceremony::lock_admin_set`]) from this check through
/// its write, or two such changes could each pass it and together strand the
/// community.
///
/// A threshold of 1 needs only one other unrestricted admin, the same bound the
/// write-time check accepts, so a two-admin community can still remove a
/// compromised one. Above 1 the threshold has to come down first.
pub async fn check_attrition(state: &AppState, subject: &str) -> Result<(), AppError> {
    let remaining = unrestricted_admins(state, now_epoch())
        .await?
        .into_iter()
        .filter(|d| d != subject)
        .count() as u64;
    if remaining == 0 {
        return Err(AppError::Conflict(format!(
            "refusing to end the last unrestricted admin ({subject}): nobody would be left who \
             could consent to another (VTI-APV-014). Make another unrestricted admin first"
        )));
    }
    let threshold = threshold(state).await?;
    if threshold > 1 && threshold > remaining.saturating_sub(1) {
        return Err(AppError::Conflict(format!(
            "refusing to end unrestricted admin {subject}: {remaining} would remain, so \
             {UNRESTRICTED_ADMIN_CONSENT_THRESHOLD} = {threshold} could never be met again \
             (VTI-APV-009). Lower it first — config/patch \
             {{\"{UNRESTRICTED_ADMIN_CONSENT_THRESHOLD}\": {}}} — then retry",
            remaining.saturating_sub(1).max(1)
        )));
    }
    Ok(())
}

/// A consent found live and still authorizing, not yet spent.
#[derive(Debug)]
#[must_use = "a ReadyGrant authorizes nothing until it is spent with the write"]
pub struct ReadyGrant {
    requester: String,
    subject: String,
    type_uri: String,
    digest: String,
}

impl ReadyGrant {
    /// Spend the consent. Call it with the write, after every other check —
    /// including the requester's own gesture — has been settled.
    ///
    /// Single-use: a second spend of the same consent, or a spend racing
    /// another, finds nothing and is refused.
    pub async fn spend(self, state: &AppState) -> Result<(), AppError> {
        // `consume_grant` reads, then removes. Two spends of one grant racing
        // between those steps would both find it, so they are serialised. The
        // signed door's replay record already stops two copies of one document;
        // the bearer routes have nothing like it.
        let _spend = SPEND_LOCK.lock().await;
        let now = now_epoch();
        let Some(grant) = task_consent::consume_grant(
            &state.task_consent_ks,
            &self.requester,
            &self.type_uri,
            &self.digest,
            now,
        )
        .await?
        else {
            return Err(AppError::Conflict(
                "the consent for this operation was spent or lapsed while it was being checked; \
                 send the operation again"
                    .into(),
            ));
        };
        audit(
            state,
            &self.requester,
            "consumed",
            &self.type_uri,
            &self.requester,
            &self.subject,
            "",
            grant.approvers.len() as u32,
            grant.approvers,
        )
        .await?;
        info!(requester = %self.requester, task = %self.type_uri, "unrestricted-admin consent spent");
        Ok(())
    }
}

/// Serialises [`ReadyGrant::spend`] across every door in this process. fjall is
/// not multi-process safe, so a process-wide lock is the right granularity.
static SPEND_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What the signed door has once it has asked for both things an unrestricted
/// grant needs.
#[derive(Debug)]
pub enum SignedGate {
    /// The requester's gesture is spent and another admin's consent is live.
    /// Spend the consent with the write.
    Ready(ReadyGrant),
    /// No gesture yet. A ceremony is parked; refuse with it inline. Nothing
    /// was asked of any other admin.
    StepUpRequired(Box<trust_tasks_rs::specs::auth::step_up::approve_request::v0_3::Payload>),
}

/// The signed door's gate for an unrestricted grant: the requester's
/// operation-bound gesture **and** another admin's consent, both keyed on `op`.
///
/// The gesture comes first. Asking the other admins only once the requester has
/// proved presence with their own passkey means a party holding just the
/// requester's signing key — a console key, say — cannot make every other
/// admin's device ring. And neither is spent while the other is missing: a
/// gesture made while consent is still outstanding waits (its mark lives five
/// minutes; one that lapses before the approvals land is asked for again).
///
/// Consent refused or pending comes back as [`AppError::ApprovalRequired`].
pub async fn gesture_then_consent(
    state: &AppState,
    requester: &str,
    subject: &str,
    op: Operation<'_>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<SignedGate, AppError> {
    use super::bound_step_up::{self, Gate};

    // A consent nobody can give makes the gesture pointless, so say so before
    // asking the requester for one.
    let possible = unrestricted_admins(state, now_epoch())
        .await?
        .iter()
        .filter(|d| d.as_str() != requester)
        .count() as u64;
    refuse_if_unmeetable(possible, threshold(state).await?, consent_summary)?;

    if !bound_step_up::has_mark(state, requester, op.type_uri, op.payload).await? {
        return match bound_step_up::redeem_or_request(
            state,
            requester,
            op.type_uri,
            op.payload,
            gesture_reason,
        )
        .await?
        {
            Gate::Required(request) => Ok(SignedGate::StepUpRequired(request)),
            // A gesture landed between the look and the redeem, and is now
            // spent. Carry on to the consent; if that is still outstanding the
            // gesture has to be made again, which is the cost of the race and
            // not a way around either requirement.
            Gate::Satisfied => require(state, requester, subject, op, consent_summary)
                .await
                .map(SignedGate::Ready),
        };
    }

    let ready = require(state, requester, subject, op, consent_summary).await?;
    match bound_step_up::redeem_or_request(
        state,
        requester,
        op.type_uri,
        op.payload,
        gesture_reason,
    )
    .await?
    {
        Gate::Satisfied => Ok(SignedGate::Ready(ready)),
        // The mark lapsed while the consent was being checked.
        Gate::Required(request) => Ok(SignedGate::StepUpRequired(request)),
    }
}

/// Find the consent for this operation, or ask for it.
///
/// Call it after every check that decides whether the operation is allowed, so
/// no approver is asked about an act that would be refused anyway. It spends
/// nothing: a [`ReadyGrant`] comes back, and the caller spends it with the write.
///
/// Without a live consent this raises (or re-finds) the pending request, pushes
/// it to the approvers when it is new, and returns
/// [`AppError::ApprovalRequired`] carrying what a client needs to follow it.
/// `summary` is what the approvers' devices show, so it must name the act.
pub async fn require(
    state: &AppState,
    requester: &str,
    subject: &str,
    op: Operation<'_>,
    summary: &str,
) -> Result<ReadyGrant, AppError> {
    let now = now_epoch();
    let ks = &state.task_consent_ks;
    let digest = task_consent::payload_digest(op.type_uri, op.payload)?;
    let threshold = threshold(state).await?;
    let approvers: Vec<String> = unrestricted_admins(state, now)
        .await?
        .into_iter()
        .filter(|d| d != requester)
        .collect();
    let pin = state_pin(state, subject).await?;

    if let Some(grant) = task_consent::get_grant(ks, requester, &digest, now).await? {
        if still_authorizes(&grant, &approvers, threshold, &pin) {
            return Ok(ReadyGrant {
                requester: requester.to_string(),
                subject: subject.to_string(),
                type_uri: op.type_uri.to_string(),
                digest,
            });
        }
        // The community moved under the consent: an approver lost their
        // authority, the threshold rose, or the subject's entry changed after
        // the approvers saw it. What they agreed to is no longer what would
        // happen, so it is not agreement to this — ask again.
        warn!(
            requester,
            task = op.type_uri,
            "unrestricted-admin consent no longer authorizes the operation; asking again"
        );
        task_consent::discard_grant(ks, requester, &digest).await?;
    }

    refuse_if_unmeetable(approvers.len() as u64, threshold, summary)?;

    let (pending, raised) = match task_consent::get_pending(ks, &digest, now).await? {
        // Same ask, same world: the same challenge goes back and nobody is
        // pushed again. A request that re-rang every approver on each retry
        // would train them to approve to make it stop.
        Some(p)
            if p.requester_did == requester
                && p.state_pin.as_ref() == Some(&pin)
                && u64::from(p.min_approvals) == threshold =>
        {
            (p, false)
        }
        stale => {
            if let Some(p) = stale {
                task_consent::delete_pending(ks, &p).await?;
            }
            let p = mint_pending(requester, op, &digest, threshold, pin, now)?;
            task_consent::store_pending(ks, &p).await?;
            (p, true)
        }
    };

    let requests = sign_requests(state, &pending, &approvers, subject, summary).await?;
    if raised {
        audit(
            state,
            requester,
            "requested",
            op.type_uri,
            requester,
            subject,
            &pending.wire_digest,
            pending.min_approvals,
            Vec::new(),
        )
        .await?;
        push(state, &requests).await;
        info!(
            requester,
            task = op.type_uri,
            approvers = approvers.len(),
            min = pending.min_approvals,
            "unrestricted-admin consent requested"
        );
    }

    Err(AppError::ApprovalRequired {
        code: CONSENT_REQUIRED,
        details: refusal_details(&pending, requests),
    })
}

/// Refuse, naming the fix, when there are fewer possible approvers than the
/// threshold needs. The operator's way out is the offline break-glass, which is
/// not reachable by a stolen session or key.
fn refuse_if_unmeetable(approvers: u64, threshold: u64, summary: &str) -> Result<(), AppError> {
    if approvers < threshold {
        return Err(AppError::Forbidden(format!(
            "{summary} needs consent from {threshold} other unrestricted admin(s), and this \
             community has {approvers} (VTI-APV-014). Add another unrestricted admin with the \
             offline break-glass while the daemon is stopped — `vtc acl add --did <did> --role \
             admin` — and send this again"
        )));
    }
    Ok(())
}

/// The refusal's `details`: the VTA gate's shape, so a client written for one
/// follows the other.
///
/// The signed requests ride along for a requester to relay when they fit the
/// framework's bound on `details`. When they do not, they are left out and
/// counted: a `details` over the bound is dropped whole, and the reason and
/// digest must survive. The approvers still get them by push.
fn refusal_details(pending: &PendingTaskConsent, requests: Vec<Value>) -> Value {
    let mut details = json!({
        "reason": CONSENT_REQUIRED,
        "payloadDigest": pending.wire_digest,
        "correlator": pending.correlator,
        "challenge": pending.challenge,
        "approverSet": pending.approver_set,
        "minApprovals": pending.min_approvals,
        "excludeRequester": pending.exclude_requester,
    });
    let count = requests.len();
    details["consentRequests"] = Value::Array(requests);
    let fits = serde_json_canonicalizer::to_string(&details)
        .is_ok_and(|jcs| jcs.len() <= crate::trust_tasks::DETAILS_MAX_JCS_BYTES);
    if !fits {
        details
            .as_object_mut()
            .expect("built as an object")
            .remove("consentRequests");
        details["consentRequestsOmitted"] = json!(count);
    }
    details
}

fn mint_pending(
    requester: &str,
    op: Operation<'_>,
    digest: &str,
    threshold: u64,
    pin: StatePin,
    now: u64,
) -> Result<PendingTaskConsent, AppError> {
    // 256 bits: the challenge is both the replay nonce and the salt that keeps
    // the wire digest from confirming a guess at a short, predictable payload.
    let challenge = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let min_approvals = u32::try_from(threshold)
        .map_err(|_| AppError::Internal(format!("consent threshold {threshold} out of range")))?;
    Ok(PendingTaskConsent {
        digest: digest.to_string(),
        wire_digest: task_consent::wire_digest(op.type_uri, op.payload, &challenge)?,
        type_uri: op.type_uri.to_string(),
        requester_did: requester.to_string(),
        approver_set: APPROVER_SET.to_string(),
        min_approvals,
        exclude_requester: true,
        challenge,
        correlator: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        approvals: Vec::new(),
        state_pin: Some(pin),
        guards: Default::default(),
        subject_context: None,
        requester_authorized: true,
        created_at: now,
        expires_at: now.saturating_add(PENDING_TTL_SECS),
    })
}

/// The subject's ACL entry as the approvers see it, pinned. Any change to the
/// entry between the request and the write — its role, scopes, expiry, even its
/// label — changes the version, and a consent given over the old one is asked
/// for again.
async fn state_pin(state: &AppState, subject: &str) -> Result<StatePin, AppError> {
    let entry = get_acl_entry(&state.acl_ks, subject).await?;
    let value = serde_json::to_value(&entry)
        .map_err(|e| AppError::Internal(format!("serialise ACL entry for its state pin: {e}")))?;
    Ok(StatePin {
        resource: subject.to_string(),
        version: task_consent::domain_digest(STATE_DOMAIN, subject, &value, None)?,
    })
}

/// Whether a grant still authorizes the operation against the community as it
/// is now. An approver who has since lost unrestricted authority no longer
/// counts, and the threshold is the current one.
fn still_authorizes(
    grant: &TaskConsentGrant,
    approvers_now: &[String],
    threshold: u64,
    pin: &StatePin,
) -> bool {
    let valid = grant
        .approvers
        .iter()
        .filter(|a| approvers_now.contains(a))
        .count() as u64;
    valid >= threshold && grant.state_pin.as_ref() == Some(pin)
}

/// One VTC-signed `task-consent/request/0.1` per approver, each addressed to
/// that approver so a device can tell a request meant for it from one replayed
/// at it. The requester is never asked (VTI-APV-007).
async fn sign_requests(
    state: &AppState,
    pending: &PendingTaskConsent,
    approvers: &[String],
    subject: &str,
    summary: &str,
) -> Result<Vec<Value>, AppError> {
    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;
    let signer = state
        .credential_signer
        .clone()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;
    let expires_at = chrono::DateTime::from_timestamp(pending.expires_at as i64, 0)
        .ok_or_else(|| AppError::Internal("consent expiry out of range".into()))?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let effect = Effect::new("authorityGrant", summary).detail(
        json!({ "subject": subject, "actScope": "all", "role": "admin" })
            .as_object()
            .cloned()
            .unwrap_or_default(),
    );

    let payload = json!({
        "challenge": pending.challenge,
        "taskType": pending.type_uri,
        "payloadDigest": pending.wire_digest,
        "sideEffects": "mutating",
        "exposure": { "actsAsSubject": false, "discloses": "none" },
        "effects": [effect],
        "consequences": [
            "The subject can grant and remove any authority in this community, including yours."
        ],
        "requester": pending.requester_did,
        "approverSet": pending.approver_set,
        "minApprovals": pending.min_approvals,
        "excludeRequester": pending.exclude_requester,
        "expiresAt": expires_at,
        "subject": subject,
        "statePin": pending.state_pin,
    });
    // Read back through the generated type, so a request this service emits is
    // one the specification admits.
    {
        use trust_tasks_rs::validate::ValidatedPayload as _;
        request::Payload::validate_value(&payload).map_err(|e| {
            AppError::Internal(format!("task-consent request does not conform: {e}"))
        })?;
    }

    let mut signed = Vec::with_capacity(approvers.len());
    for approver in approvers {
        let doc = build_document(&vtc_did, approver, REQUEST_TYPE, payload.clone());
        let mut doc = serde_json::to_value(&doc)
            .map_err(|e| AppError::Internal(format!("serialise task-consent request: {e}")))?;
        // The operational key, under `authentication`: this is a request
        // the VTC sends as itself, not a credential it issues (VTI-KEY-106).
        signer.sign_operational_doc(&mut doc).await?;
        signed.push(doc);
    }
    Ok(signed)
}

/// Push each signed request to its approver. Best-effort: the requester holds
/// the relay copy, an approver answers later with a separate decision, and a
/// push failure must never become a refusal of something else.
async fn push(state: &AppState, requests: &[Value]) {
    let Some(vtc_did) = state.config.read().await.vtc_did.clone() else {
        return;
    };
    for doc in requests {
        let Some(approver) = doc.get("recipient").and_then(Value::as_str) else {
            continue;
        };
        let envelope = affinidi_messaging_didcomm::Message::build(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            TRUST_TASK_ENVELOPE_TYPE.to_string(),
            doc.clone(),
        )
        .from(vtc_did.clone())
        .to(approver.to_string())
        .finalize();
        if let Err(e) = state
            .send_to_member_by(approver, envelope, Duration::from_secs(PENDING_TTL_SECS))
            .await
        {
            // Queued-locally is all an `Ok` would have meant anyway (R1.1).
            debug!(approver, error = %e, "consent request not pushed; the requester can relay it");
        }
    }
}

/// What a processed decision amounts to.
#[derive(Debug)]
pub enum Decided {
    /// Enough distinct approvers have approved; the requester may send the
    /// operation again.
    Granted {
        payload_digest: String,
        approvals: u64,
    },
    /// Recorded, and more approvals are needed.
    Pending {
        payload_digest: String,
        approvals: u64,
        needed: u64,
    },
    /// Declined. The request is gone; another ask raises a new one.
    Denied { payload_digest: String },
}

/// Why a decision was refused — one of `task-consent/decision`'s declared codes.
#[derive(Debug)]
pub enum DecisionError {
    NoPending,
    ChallengeMismatch,
    NotAnApprover,
    RequesterExcluded,
    Internal(AppError),
}

impl From<AppError> for DecisionError {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

/// Process a `task-consent/decision/0.1` from `approver`, the document's proven
/// signer resolved to the admin it acts for.
///
/// The approver's authority is read now: an unrestricted admin at the moment of
/// deciding, and not the requester. Which operation the decision concerns is
/// read from this service's record of the request, found by the salted digest,
/// never from the decision.
pub async fn decide(
    state: &AppState,
    approver: &str,
    payload: &decision::Payload,
) -> Result<Decided, DecisionError> {
    let now = now_epoch();
    let ks = &state.task_consent_ks;
    let wire = payload.payload_digest.to_string();
    let Some(pending) = task_consent::pending_by_wire_digest(ks, &wire, now).await? else {
        return Err(DecisionError::NoPending);
    };
    if payload.challenge.as_str() != pending.challenge {
        return Err(DecisionError::ChallengeMismatch);
    }
    if approver == pending.requester_did {
        return Err(DecisionError::RequesterExcluded);
    }
    if !unrestricted_admins(state, now)
        .await?
        .iter()
        .any(|d| d == approver)
    {
        return Err(DecisionError::NotAnApprover);
    }
    let subject = pending
        .state_pin
        .as_ref()
        .map(|p| p.resource.clone())
        .unwrap_or_default();

    if payload.decision == decision::Decision::Deny {
        task_consent::delete_pending(ks, &pending).await?;
        audit(
            state,
            approver,
            "declined",
            &pending.type_uri,
            &pending.requester_did,
            &subject,
            &wire,
            pending.min_approvals,
            vec![approver.to_string()],
        )
        .await?;
        info!(approver, requester = %pending.requester_did, "unrestricted-admin consent declined");
        return Ok(Decided::Denied {
            payload_digest: wire,
        });
    }

    let Some(pending) = task_consent::add_approval(ks, &pending.digest, approver, now).await?
    else {
        return Err(DecisionError::NoPending);
    };
    audit(
        state,
        approver,
        "approved",
        &pending.type_uri,
        &pending.requester_did,
        &subject,
        &wire,
        pending.min_approvals,
        vec![approver.to_string()],
    )
    .await?;

    let approvals = pending.approvals.len() as u64;
    let needed = u64::from(pending.min_approvals);
    if approvals < needed {
        return Ok(Decided::Pending {
            payload_digest: wire,
            approvals,
            needed,
        });
    }

    task_consent::store_grant(
        ks,
        &TaskConsentGrant {
            digest: pending.digest.clone(),
            requester_did: pending.requester_did.clone(),
            type_uri: pending.type_uri.clone(),
            approvers: pending.approvals.clone(),
            state_pin: pending.state_pin.clone(),
            guards: pending.guards.clone(),
            delegated_contexts: Vec::new(),
            granted_at: now,
            expires_at: now.saturating_add(GRANT_TTL_SECS),
        },
    )
    .await?;
    task_consent::delete_pending(ks, &pending).await?;
    audit(
        state,
        approver,
        "granted",
        &pending.type_uri,
        &pending.requester_did,
        &subject,
        &wire,
        pending.min_approvals,
        pending.approvals.clone(),
    )
    .await?;
    info!(
        requester = %pending.requester_did,
        approvals,
        "unrestricted-admin consent granted"
    );
    Ok(Decided::Granted {
        payload_digest: wire,
        approvals,
    })
}

#[allow(clippy::too_many_arguments)]
async fn audit(
    state: &AppState,
    actor: &str,
    stage: &str,
    task: &str,
    requester: &str,
    subject: &str,
    payload_digest: &str,
    min_approvals: u32,
    approvers: Vec<String>,
) -> Result<(), AppError> {
    let Some(writer) = state.audit_writer.as_ref() else {
        return Ok(());
    };
    writer
        .write(
            actor,
            (!subject.is_empty()).then_some(subject),
            AuditEvent::TaskConsentRecorded(TaskConsentData {
                stage: stage.to_string(),
                task: task.to_string(),
                requester: requester.to_string(),
                subject: subject.to_string(),
                payload_digest: payload_digest.to_string(),
                min_approvals,
                approvers,
            }),
        )
        .await?;
    Ok(())
}

/// Remove every lapsed pending request and grant. A storage bound: both reads
/// above already treat an expired record as absent.
pub async fn sweep_expired(
    ks: &vti_common::store::KeyspaceHandle,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<usize, AppError> {
    task_consent::sweep_expired(ks, now.timestamp().max(0) as u64).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(role: VtcRole, scopes: &[&str], expires_at: Option<u64>) -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zSubject".into(),
            role,
            label: None,
            allowed_contexts: scopes.iter().map(|s| s.to_string()).collect(),
            created_at: 0,
            created_by: "did:key:zAdmin".into(),
            updated_at: None,
            updated_by: None,
            expires_at,
        }
    }

    /// The four ways an entry can come to be unrestricted, and the ones that
    /// only look like it.
    #[test]
    fn confers_unrestricted_only_where_act_scope_becomes_all() {
        let now = 1_000;
        // A new entry, unrestricted admin.
        assert!(confers_unrestricted(None, &VtcRole::Admin, &[], now));
        // A scoped admin widened to community-wide.
        let scoped = entry(VtcRole::Admin, &["ctx-a"], None);
        assert!(confers_unrestricted(
            Some(&scoped),
            &VtcRole::Admin,
            &[],
            now
        ));
        // A scopeless member promoted — the `is_empty()` trap: empty means
        // "nowhere" for the member and "everywhere" for the admin it becomes.
        let member = entry(VtcRole::Member, &[], None);
        assert!(confers_unrestricted(
            Some(&member),
            &VtcRole::Admin,
            &[],
            now
        ));
        // An expired unrestricted admin, granted again.
        let lapsed = entry(VtcRole::Admin, &[], Some(now));
        assert!(confers_unrestricted(
            Some(&lapsed),
            &VtcRole::Admin,
            &[],
            now
        ));

        // Already unrestricted and live: a label edit confers nothing.
        let live = entry(VtcRole::Admin, &[], None);
        assert!(!confers_unrestricted(
            Some(&live),
            &VtcRole::Admin,
            &[],
            now
        ));
        // A scoped admin grant is not unrestricted.
        assert!(!confers_unrestricted(
            None,
            &VtcRole::Admin,
            &["ctx-a".into()],
            now
        ));
        // A scopeless non-admin acts nowhere.
        assert!(!confers_unrestricted(None, &VtcRole::Member, &[], now));
    }

    fn grant(approvers: &[&str], pin: &StatePin) -> TaskConsentGrant {
        TaskConsentGrant {
            digest: "d".into(),
            requester_did: "did:key:zReq".into(),
            type_uri: "t".into(),
            approvers: approvers.iter().map(|s| s.to_string()).collect(),
            state_pin: Some(pin.clone()),
            guards: Default::default(),
            delegated_contexts: Vec::new(),
            granted_at: 0,
            expires_at: 10,
        }
    }

    /// A grant is re-judged against the community as it is when it is spent.
    #[test]
    fn a_grant_stops_authorizing_when_the_community_moves() {
        let pin = StatePin {
            resource: "did:key:zSubject".into(),
            version: "v1".into(),
        };
        let now_admins = vec!["did:key:zB".to_string(), "did:key:zC".to_string()];
        let g = grant(&["did:key:zB"], &pin);
        assert!(still_authorizes(&g, &now_admins, 1, &pin));

        // The threshold rose after the approval.
        assert!(!still_authorizes(&g, &now_admins, 2, &pin));
        // The approver has since lost unrestricted authority.
        assert!(!still_authorizes(&g, &["did:key:zC".to_string()], 1, &pin));
        // The subject's entry changed after the approver saw it.
        let moved = StatePin {
            version: "v2".into(),
            ..pin.clone()
        };
        assert!(!still_authorizes(&g, &now_admins, 1, &moved));
    }

    /// Too many signed requests to fit the framework's bound: they are left out
    /// and counted, so the reason and digest still reach the requester.
    #[test]
    fn refusal_details_stay_within_the_framework_bound() {
        let pending = mint_pending(
            "did:key:zReq",
            Operation {
                type_uri: "https://trusttasks.org/spec/acl/grant/0.1",
                payload: &json!({ "subject": "did:key:zS" }),
            },
            "zDigest",
            1,
            StatePin {
                resource: "did:key:zS".into(),
                version: "v".into(),
            },
            0,
        )
        .unwrap();

        let small = refusal_details(&pending, vec![json!({ "id": "a" })]);
        assert_eq!(small["consentRequests"].as_array().map(Vec::len), Some(1));

        let big = vec![json!({ "blob": "x".repeat(3000) }); 3];
        let details = refusal_details(&pending, big);
        assert!(details.get("consentRequests").is_none());
        assert_eq!(details["consentRequestsOmitted"], 3);
        assert_eq!(details["reason"], CONSENT_REQUIRED);
        assert_eq!(details["payloadDigest"], pending.wire_digest.as_str());
    }
}
