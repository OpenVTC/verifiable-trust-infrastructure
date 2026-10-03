//! Operation-bound step-up — the passkey gesture a **signed document** needs
//! before it may confer administrative authority, bound to that one operation
//! rather than to a session.
//!
//! Design: `docs/05-design-notes/vtc-operation-bound-step-up.md` (#1641).
//! Requirements: VTI-APV-003 as amended by dtgwg-vti-spec#40 and VTI-APV-015 —
//! a re-authentication MAY be bound to exactly one operation by payload digest,
//! in which case it elevates nothing and is consumed by that operation.
//!
//! ## Why not the session
//!
//! [`super::elevation::verified`] reads a live session's `acr`, and a signed
//! document has no session: `admin_signer` builds its claims with an empty
//! `session_id`. Reading *some* session of the signer's instead would widen the
//! gate past what the bearer route checks, and would open the 15-minute window
//! a process holding the signer's key (a console key, say) could spend on acts
//! the operator never saw. So the gesture authorizes exactly one act, named by
//! digest, and nothing else.
//!
//! ## The flow
//!
//! 1. A signed document arrives for a gated verb. The handler has run every
//!    check that decides *whether* the act is allowed, then asks
//!    [`redeem_or_request`]. No mark exists for `(acting admin, digest)`, so a
//!    WebAuthn ceremony is started over the acting admin's own passkeys and
//!    parked as a **pending mark**; the handler refuses `permissionDenied` with
//!    the ceremony inline as `details.stepUpRequest` — an
//!    `auth/step-up/approve-request/0.3` payload with `boundTo` and no
//!    `sessionId` ([`refusal`]). The spine releases the refused document's `id`,
//!    so the identical document can be sent again.
//! 2. The admin answers with `auth/step-up/approve-response/0.4` carrying
//!    `evidence.kind = webauthn` ([`approve`]). The assertion is verified against
//!    the parked ceremony, must assert user verification, and must come from a
//!    passkey registered to the acting admin. The pending mark becomes a
//!    **redeemable mark**; the answer is `recorded`, and nothing is elevated.
//! 3. The same document is re-sent. [`redeem_or_request`] finds the mark,
//!    **removes it before the operation runs**, and the handler commits. A
//!    different payload has a different digest and finds nothing; the same
//!    payload a second time finds the mark gone.
//!
//! ## Who can create a mark
//!
//! Only the passkey. A console key can sign the document and can redeem a mark,
//! but a mark exists only after a user-verified assertion from a passkey
//! registered to the admin the key acts for — possession of a signing key is
//! one factor, and it is never allowed to stand in for the second.
//!
//! Both marks live [`MARK_TTL_SECS`]: a mark authorizes one known act, so there
//! is no reason for it to outlast the moment it was made for.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::specs::auth::step_up::approve_request::v0_3 as approve_request;
use trust_tasks_rs::specs::auth::step_up::approve_response::v0_4 as approve_response;
use vti_common::audit::{AuditEvent, OperationStepUpData};
use vti_common::auth::passkey::store::{
    get_passkey_user_by_cred, get_passkey_user_by_did, store_passkey_user,
};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential};

use crate::auth::session::now_epoch;
use crate::server::AppState;

/// How long a pending mark waits for its gesture, and how long a recorded one
/// waits to be spent. Shorter than a session elevation's 900 s on purpose: a
/// mark authorizes one known act (design note §7).
pub const MARK_TTL_SECS: u64 = 300;

/// Domain separation for [`operation_digest`], so this digest cannot collide
/// with any other SHA-256 over a canonical payload in the system — the VTA's
/// task-consent digest in particular, which is built the same way under
/// `vta/task-consent/v1\0`.
const DIGEST_DOMAIN: &[u8] = b"vtc/step-up/v1\0";

const PENDING_PREFIX: &str = "pending:";
const MARK_PREFIX: &str = "mark:";

/// The operation's digest: SHA-256 over the domain tag, the length-prefixed
/// type URI and the length-prefixed RFC 8785 canonical payload, as a
/// base58btc multibase multihash.
///
/// The type URI is inside the digest, and length-prefixed so the boundary
/// cannot shift, because two tasks can share a payload shape: a gesture taken
/// for one must not authorize the other.
///
/// Internal. It keys the redeemable mark and never leaves the process — see
/// [`wire_digest`] for the value an approver sees.
pub fn operation_digest(type_uri: &str, payload: &Value) -> Result<String, AppError> {
    digest_with(type_uri, payload, None)
}

/// [`operation_digest`] salted with the step-up `challenge` — the `boundTo` the
/// approver is shown and the refusal carries.
///
/// Salted because an `acl/grant` payload is short and predictable, so an
/// unsalted digest in transit is a confirmation oracle for which grant was
/// being authorized (approve-request 0.3, step 4a).
pub fn wire_digest(type_uri: &str, payload: &Value, challenge: &str) -> Result<String, AppError> {
    digest_with(type_uri, payload, Some(challenge))
}

fn digest_with(
    type_uri: &str,
    payload: &Value,
    challenge: Option<&str>,
) -> Result<String, AppError> {
    vti_common::task_consent::domain_digest(DIGEST_DOMAIN, type_uri, payload, challenge)
}

/// The inline `auth/step-up/approve-request/0.3` payload a gated operation
/// refuses with.
pub type ApproveRequest = approve_request::Payload;

/// A parked WebAuthn ceremony for one refused operation, keyed by its
/// challenge.
#[derive(Serialize, Deserialize)]
struct PendingMark {
    /// The admin the operation acts as — the signer, or the admin a console
    /// key's delegation names. Only their passkeys were offered.
    admin_did: String,
    /// [`operation_digest`] of the refused operation.
    digest: String,
    /// [`wire_digest`] — what the approver was shown, echoed as `boundTo`.
    bound_to: String,
    type_uri: String,
    /// webauthn-rs's own ceremony state. Its challenge *is* the step-up
    /// challenge, so the assertion binds the nonce this record is keyed by.
    auth_state: PasskeyAuthentication,
    expires_at: u64,
    /// The key that asked, for a gesture requested before the actor's standing
    /// is known — a signing-key enrolment ([`request_for_enrolment`]). Absent
    /// for every other gate, whose document is signed by the actor itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester: Option<String>,
}

// Hand-written so a stray `?pending` in a log line prints the binding and not
// the ceremony state.
impl std::fmt::Debug for PendingMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingMark")
            .field("admin_did", &self.admin_did)
            .field("bound_to", &self.bound_to)
            .field("type_uri", &self.type_uri)
            .field("expires_at", &self.expires_at)
            .field("requester", &self.requester)
            .finish_non_exhaustive()
    }
}

/// A recorded gesture, waiting for the one operation it authorizes.
#[derive(Debug, Serialize, Deserialize)]
struct RedeemableMark {
    expires_at: u64,
    /// Which passkey answered, and what it was shown — carried so an act that
    /// must record its step-up evidence (a git break-glass,
    /// `git-ns/right/break-glass/0.1` step 9) can. Absent on a mark written
    /// before this was recorded; such a mark still authorizes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bound_to: Option<String>,
}

/// What a spent mark shows about the gesture behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpEvidence {
    /// Credential id (hex) of the passkey that asserted user verification.
    pub credential_id: String,
    /// The salted digest the approver was shown.
    pub bound_to: String,
}

impl From<StepUpEvidence> for vti_common::audit::StepUpEvidence {
    fn from(e: StepUpEvidence) -> Self {
        Self {
            kind: "webauthn".into(),
            credential_id: e.credential_id,
            bound_to: e.bound_to,
        }
    }
}

/// [`Gate`], with the spent gesture's evidence.
#[derive(Debug)]
pub enum EvidencedGate {
    Satisfied(StepUpEvidence),
    Required(Box<approve_request::Payload>),
}

/// Read and remove `key` in one step ([`KeyspaceHandle::take_raw`]), so of two
/// concurrent callers exactly one gets the row.
async fn take<T: serde::de::DeserializeOwned>(
    ks: &KeyspaceHandle,
    key: String,
) -> Result<Option<T>, AppError> {
    ks.take_raw(key)
        .await?
        .map(|raw| serde_json::from_slice(&raw))
        .transpose()
        .map_err(|e| AppError::Internal(format!("step-up mark does not parse: {e}")))
}

fn pending_key(challenge: &str) -> String {
    format!("{PENDING_PREFIX}{challenge}")
}

fn mark_key(admin_did: &str, digest: &str) -> String {
    format!("{MARK_PREFIX}{admin_did}:{digest}")
}

/// What [`redeem_or_request`] found.
#[derive(Debug)]
pub enum Gate {
    /// A recorded gesture for exactly this operation existed and has now been
    /// **spent**. The caller commits the operation.
    Satisfied,
    /// No gesture yet. A ceremony is parked; the caller refuses with
    /// [`refusal_details`] over this request.
    Required(Box<approve_request::Payload>),
}

/// Spend the recorded gesture for `(admin_did, this operation)`, or park a
/// ceremony and return the approve-request that asks for one.
///
/// Call it **after** every check that decides whether the operation is allowed
/// and **before** anything is written: a mark is removed here, so an operation
/// refused afterwards needs another gesture, and an operation that would be
/// refused anyway should never ask the human for one.
///
/// `reason` is what the approver's device shows and what the human consents to,
/// so it must name the act specifically.
pub async fn redeem_or_request(
    state: &AppState,
    admin_did: &str,
    type_uri: &str,
    payload: &Value,
    reason: &str,
) -> Result<Gate, AppError> {
    Ok(
        match redeem_or_request_with_evidence(state, admin_did, type_uri, payload, reason).await? {
            EvidencedGate::Satisfied(_) => Gate::Satisfied,
            EvidencedGate::Required(r) => Gate::Required(r),
        },
    )
}

/// [`redeem_or_request`], returning the spent gesture's evidence — for an act
/// whose audit record must carry it.
pub async fn redeem_or_request_with_evidence(
    state: &AppState,
    admin_did: &str,
    type_uri: &str,
    payload: &Value,
    reason: &str,
) -> Result<EvidencedGate, AppError> {
    let ks = &state.step_up_marks_ks;
    let digest = operation_digest(type_uri, payload)?;
    let key = mark_key(admin_did, &digest);

    // Removed before it is honoured, so two concurrent re-sends of the same
    // document cannot both find it. An expired mark is removed the same way and
    // then treated as absent.
    if let Some(mark) = take::<RedeemableMark>(ks, key).await?
        && now_epoch() < mark.expires_at
    {
        info!(admin = %admin_did, task = %type_uri, "operation-bound step-up spent");
        return Ok(EvidencedGate::Satisfied(StepUpEvidence {
            credential_id: mark.credential_id.unwrap_or_default(),
            bound_to: mark.bound_to.unwrap_or_default(),
        }));
    }

    let webauthn = state.webauthn.as_ref().ok_or_else(|| {
        AppError::StepUpRequired(
            "this operation needs a passkey gesture, and this community has no WebAuthn \
             relying party configured"
                .into(),
        )
    })?;
    // Only the actor's own credentials. A signed document names one actor;
    // any other principal's passkey answering for them would be exactly the
    // substitution the gate exists to stop. Either way the answer must also
    // carry the actor's own signature
    // (`trust_tasks::handle_step_up_approve_response`): the passkey is beside
    // the proof, never instead of it.
    //
    // Once `admin_did` holds a dedicated step-up passkey
    // (`crate::step_up_passkey`), it is the **only** passkey this gesture may
    // come from — their ordinary session/console passkey stops counting for
    // them (security decision 2026-09-30): a step-up passkey exists precisely
    // so a subject's second factor cannot be satisfied by whatever else they
    // happen to hold. A subject with no step-up passkey keeps today's route —
    // any of their registered (session) passkeys — so enrolling nobody else's
    // is never a lockout. A member who is no console user holds only a
    // step-up passkey, and this is the one place it counts at all.
    let step_up_passkeys = crate::step_up_passkey::credentials_of(state, admin_did).await?;
    let passkeys = if step_up_passkeys.is_empty() {
        get_passkey_user_by_did(&state.passkey_ks, admin_did)
            .await?
            .map(|u| u.credentials)
            .unwrap_or_default()
    } else {
        step_up_passkeys
    };
    if passkeys.is_empty() {
        return Err(AppError::StepUpRequired(format!(
            "this operation needs a passkey gesture from {admin_did}, who has no passkey \
             registered with this community — a community administrator can invite them to \
             enrol a step-up passkey (Members → the member → Step-up passkeys), then retry"
        )));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(format!("webauthn authentication start failed: {e}")))?;
    let options = serde_json::to_value(&rcr.public_key)
        .map_err(|e| AppError::Internal(format!("webauthn options serialise: {e}")))?;
    let challenge = options["challenge"]
        .as_str()
        .ok_or_else(|| AppError::Internal("webauthn options carry no challenge".into()))?
        .to_string();
    let bound_to = wire_digest(type_uri, payload, &challenge)?;

    let pending = PendingMark {
        admin_did: admin_did.to_string(),
        digest,
        bound_to: bound_to.clone(),
        type_uri: type_uri.to_string(),
        auth_state,
        expires_at: now_epoch().saturating_add(MARK_TTL_SECS),
        requester: None,
    };
    ks.insert(pending_key(&challenge), &pending).await?;

    let request = approve_request_payload(admin_did, &challenge, &bound_to, reason, &options)?;
    info!(admin = %admin_did, task = %type_uri, %bound_to, "operation-bound step-up requested");
    Ok(EvidencedGate::Required(Box::new(request)))
}

/// Park a ceremony for a signing-key enrolment (`auth/signing-key/enroll/0.1`)
/// of a key acting for `identity_did`, requested by `requester` — the key
/// being enrolled — and return the inline approve-request.
///
/// The enrolment's standing is not yet known, so the answer must not depend
/// on it: the ceremony offers **every** registered console passkey, exactly as
/// an unauthenticated passkey login does, so a stranger's enrolment against
/// any DID gets the same kind of answer (enroll, *The refusal is not an
/// oracle*). It is delivered only inline, to the requester, and reaches none
/// of the identity's devices (enroll item 5). Only a passkey registered to
/// `identity_did` can then answer it ([`approve`]).
pub async fn request_for_enrolment(
    state: &AppState,
    identity_did: &str,
    requester: &str,
    type_uri: &str,
    payload: &Value,
    reason: &str,
) -> Result<approve_request::Payload, AppError> {
    let webauthn = state.webauthn.as_ref().ok_or_else(|| {
        AppError::StepUpRequired(
            "enrolling a signing key needs a passkey gesture, and this community has no \
             WebAuthn relying party configured"
                .into(),
        )
    })?;
    let passkeys = vti_common::auth::passkey::store::get_all_passkeys(&state.passkey_ks).await?;
    if passkeys.is_empty() {
        return Err(AppError::StepUpRequired(
            "enrolling a signing key needs a passkey gesture, and no passkey is registered \
             with this community"
                .into(),
        ));
    }
    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(format!("webauthn authentication start failed: {e}")))?;
    let options = serde_json::to_value(&rcr.public_key)
        .map_err(|e| AppError::Internal(format!("webauthn options serialise: {e}")))?;
    let challenge = options["challenge"]
        .as_str()
        .ok_or_else(|| AppError::Internal("webauthn options carry no challenge".into()))?
        .to_string();
    let bound_to = wire_digest(type_uri, payload, &challenge)?;
    let pending = PendingMark {
        admin_did: identity_did.to_string(),
        digest: operation_digest(type_uri, payload)?,
        bound_to: bound_to.clone(),
        type_uri: type_uri.to_string(),
        auth_state,
        expires_at: now_epoch().saturating_add(MARK_TTL_SECS),
        requester: Some(requester.to_string()),
    };
    state
        .step_up_marks_ks
        .insert(pending_key(&challenge), &pending)
        .await?;
    info!(identity = %identity_did, %requester, %bound_to, "signing-key enrolment step-up requested");
    approve_request_payload(identity_did, &challenge, &bound_to, reason, &options)
}

/// Spend the recorded gesture for `(admin_did, this operation)`: `true` when a
/// live one existed and is now gone. Removed before it is honoured, so two
/// concurrent re-sends cannot both spend it.
pub async fn spend_mark(
    state: &AppState,
    admin_did: &str,
    type_uri: &str,
    payload: &Value,
) -> Result<bool, AppError> {
    let key = mark_key(admin_did, &operation_digest(type_uri, payload)?);
    let ks = &state.step_up_marks_ks;
    Ok(take::<RedeemableMark>(ks, key)
        .await?
        .is_some_and(|mark| now_epoch() < mark.expires_at))
}

/// Whether a recorded gesture for `(admin_did, this operation)` is waiting,
/// **without spending it**.
///
/// For a gate that needs the gesture *and* something else — another admin's
/// consent, for unrestricted authority (`super::admin_consent`). It asks for the
/// gesture first, then the consent, and spends neither until both are present,
/// so a missing consent never costs the requester the gesture they already
/// made. [`redeem_or_request`] is still the spend: a mark this reports may have
/// lapsed or been spent by the time the caller redeems it.
pub async fn has_mark(
    state: &AppState,
    admin_did: &str,
    type_uri: &str,
    payload: &Value,
) -> Result<bool, AppError> {
    let digest = operation_digest(type_uri, payload)?;
    Ok(state
        .step_up_marks_ks
        .get::<RedeemableMark>(mark_key(admin_did, &digest))
        .await?
        .is_some_and(|mark| now_epoch() < mark.expires_at))
}

/// The inline `auth/step-up/approve-request/0.3` payload: `boundTo` present,
/// `sessionId` absent, webauthn the only acceptable evidence.
///
/// Built as JSON and read back through the generated type's schema check, so a
/// request this service emits is one the specification admits.
fn approve_request_payload(
    admin_did: &str,
    challenge: &str,
    bound_to: &str,
    reason: &str,
    options: &Value,
) -> Result<approve_request::Payload, AppError> {
    // The WebAuthn options narrowed to the members the published
    // `CredentialRequestOptions` carries. webauthn-rs adds members of its own
    // (`hints`, an empty `extensions`) that the component does not define.
    let allow_credentials: Vec<Value> = options["allowCredentials"]
        .as_array()
        .map(|creds| {
            creds
                .iter()
                .map(|c| json!({ "type": "public-key", "id": c["id"] }))
                .collect()
        })
        .unwrap_or_default();
    let mut webauthn = json!({
        "challenge": challenge,
        "allowCredentials": allow_credentials,
        // The gate refuses a silent assertion, so ask for UV rather than let a
        // platform decide it was not needed.
        "userVerification": "required",
    });
    if let Some(rp_id) = options.get("rpId").filter(|v| v.is_string()) {
        webauthn["rpId"] = rp_id.clone();
    }
    if let Some(timeout) = options.get("timeout").filter(|v| v.is_u64()) {
        webauthn["timeout"] = timeout.clone();
    }

    let value = json!({
        "subject": admin_did,
        "challenge": challenge,
        "boundTo": bound_to,
        "reason": reason,
        "targetAcr": "aal2",
        "acceptableEvidence": ["webauthn"],
        "webauthn": webauthn,
        "ttl": MARK_TTL_SECS,
    });
    use trust_tasks_rs::validate::ValidatedPayload as _;
    approve_request::Payload::validate_value(&value)
        .map_err(|e| AppError::Internal(format!("approve-request does not conform: {e}")))?;
    serde_json::from_value(value)
        .map_err(|e| AppError::Internal(format!("approve-request does not parse: {e}")))
}

/// The refusal a gated operation answers with while no gesture is recorded:
/// `permissionDenied`, with the ceremony inline (approve-request 0.3, *Inline
/// delivery*).
pub fn refusal_details(request: &approve_request::Payload) -> Value {
    json!({ "stepUpRequest": request })
}

/// Why an approve-response was refused. Each maps onto a code
/// `auth/step-up/approve-response` declares.
#[derive(Debug)]
pub enum ApproveError {
    ChallengeUnknown,
    ChallengeExpired,
    SubjectMismatch,
    /// The approver answered with a factor this gate does not accept. A
    /// `didSigned` approval proves possession of a signing key — which is the
    /// one thing a console key already has — so only a passkey counts.
    NoGate,
    /// The assertion failed. The hint is the machine-readable
    /// `details.reason` the code declares; the cause is logged, not sent.
    AssertionInvalid(&'static str),
    /// The answer needs its approver's own signature and carries none: a
    /// refusal is an approver-signed statement, and a member's step-up passkey
    /// is only ever beside the member's proof, never instead of it.
    ProofRequired,
    Internal(AppError),
}

impl From<AppError> for ApproveError {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

/// What a processed approve-response amounts to.
#[derive(Debug)]
pub enum Approved {
    /// The gesture is recorded against the operation `bound_to` names.
    Recorded { bound_to: String },
    /// A signed refusal. Nothing is recorded, and the pending ceremony is gone.
    Declined { reason: String },
}

/// Process an `auth/step-up/approve-response/0.4` for a pending mark.
///
/// The pending mark is removed first, whatever follows, so a challenge is
/// answerable once. The operation the gesture authorizes is read from **this
/// service's own record** of the refusal, never from the approve-response,
/// whose producer could otherwise nominate a different act (approve-request 0.3,
/// *A bound step-up elevates nothing*).
pub async fn approve(
    state: &AppState,
    payload: &approve_response::Payload,
    signed_by_subject: bool,
) -> Result<Approved, ApproveError> {
    let ks = &state.step_up_marks_ks;
    let challenge = payload.challenge.to_string();
    let key = pending_key(&challenge);
    // Taken atomically: an unsigned answer carries no proof, so its `id` is
    // the sender's to choose and the spine's replay cache cannot stop two
    // concurrent copies of one assertion. Only one of them may find the
    // ceremony, or a second mark could be recorded after the first is spent.
    let Some(pending) = take::<PendingMark>(ks, key).await? else {
        return Err(ApproveError::ChallengeUnknown);
    };
    if now_epoch() >= pending.expires_at {
        return Err(ApproveError::ChallengeExpired);
    }
    // A bound step-up is for the operation's actor, and it has no session: a
    // response naming either a different subject or a session answers a request
    // this service did not make.
    if payload.subject.as_str() != pending.admin_did || payload.session_id.is_some() {
        return Err(ApproveError::SubjectMismatch);
    }

    if payload.decision == approve_response::PayloadDecision::Denied {
        if !signed_by_subject {
            return Err(ApproveError::ProofRequired);
        }
        info!(admin = %pending.admin_did, task = %pending.type_uri, "operation-bound step-up declined");
        return Ok(Approved::Declined {
            reason: payload
                .denied_reason
                .as_ref()
                .map(|r| r.to_string())
                .unwrap_or_else(|| "declined by the approver".to_string()),
        });
    }

    let assertion = match payload.evidence.as_ref() {
        Some(approve_response::Evidence::Webauthn(assertion)) => assertion,
        // `didSigned` explicitly or by omission, and any kind this build does
        // not know. `Evidence` is generated from a tagged union that may grow,
        // so there is no arm here that could fall through to a gate the
        // approver did not present.
        _ => return Err(ApproveError::NoGate),
    };
    let credential = public_key_credential(assertion)?;

    let webauthn = state.webauthn.as_ref().ok_or_else(|| {
        ApproveError::Internal(AppError::Internal("WebAuthn not configured".into()))
    })?;
    let result = webauthn
        .finish_passkey_authentication(&credential, &pending.auth_state)
        .map_err(|e| {
            warn!(admin = %pending.admin_did, error = %e, "operation-bound step-up assertion did not verify");
            ApproveError::AssertionInvalid("verificationFailed")
        })?;

    // Possession alone is one factor. The design's whole premise is a human
    // gesture, and a silent assertion is not one.
    if !result.user_verified() {
        return Err(ApproveError::AssertionInvalid("userNotVerified"));
    }

    // The ceremony only offered the admin's own credentials, and webauthn-rs
    // refuses one it did not offer — but the offer is state this service wrote,
    // and "whose passkey answered" is the question the gate turns on, so it is
    // answered from the registration record rather than inferred.
    //
    // A session passkey, or a step-up passkey of the subject's. A step-up
    // passkey revoked since the ceremony began has lost its mapping, so it
    // resolves to nobody and is refused here.
    let cred_id_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(result.cred_id()));
    let (mut user, step_up) =
        match get_passkey_user_by_cred(&state.passkey_ks, &cred_id_hex).await? {
            Some(u) => (u, false),
            None => (
                get_passkey_user_by_cred(&state.step_up_passkeys_ks, &cred_id_hex)
                    .await?
                    .ok_or(ApproveError::AssertionInvalid("credentialUnregistered"))?,
                true,
            ),
        };
    // A member's step-up passkey is only ever beside the member's own proof.
    // An unsigned answer is a console user's session passkey, the one gate an
    // administrator's browser holds that script in the origin cannot forge.
    if step_up && !signed_by_subject {
        return Err(ApproveError::ProofRequired);
    }
    if user.did != pending.admin_did {
        warn!(
            admin = %pending.admin_did,
            asserted = %user.did,
            "operation-bound step-up refused: another subject's passkey answered"
        );
        return Err(ApproveError::AssertionInvalid("notSubjectPasskey"));
    }
    // Belt and suspenders on the priority `redeem_or_request_with_evidence`
    // already enforces by never offering a session passkey once a step-up
    // passkey exists (so webauthn-rs itself would refuse an assertion over
    // one): if the subject now holds a step-up passkey, only one may have
    // answered. Unreachable through this door alone, but the record is this
    // service's own and worth trusting rather than assuming.
    if !step_up
        && !crate::step_up_passkey::credentials_of(state, &pending.admin_did)
            .await?
            .is_empty()
    {
        warn!(
            admin = %pending.admin_did,
            "operation-bound step-up refused: a session passkey answered for a subject who \
             holds a step-up passkey"
        );
        return Err(ApproveError::AssertionInvalid("notSubjectPasskey"));
    }
    // WebAuthn's replay defence is the signature counter, so persist it.
    if step_up {
        crate::step_up_passkey::record_use(&state.step_up_passkeys_ks, user, &result).await?;
    } else {
        for cred in &mut user.credentials {
            cred.update_credential(&result);
        }
        store_passkey_user(&state.passkey_ks, &user).await?;
    }

    let expires_at = now_epoch().saturating_add(MARK_TTL_SECS);
    ks.insert(
        mark_key(&pending.admin_did, &pending.digest),
        &RedeemableMark {
            expires_at,
            credential_id: Some(cred_id_hex.clone()),
            bound_to: Some(pending.bound_to.clone()),
        },
    )
    .await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &pending.admin_did,
                None,
                AuditEvent::OperationStepUpRecorded(OperationStepUpData {
                    task: pending.type_uri.clone(),
                    bound_to: pending.bound_to.clone(),
                    credential_id: cred_id_hex,
                    expires_at: DateTime::<Utc>::from_timestamp(expires_at as i64, 0)
                        .unwrap_or_default(),
                }),
            )
            .await?;
    }
    info!(admin = %pending.admin_did, task = %pending.type_uri, bound_to = %pending.bound_to, "operation-bound step-up recorded");
    Ok(Approved::Recorded {
        bound_to: pending.bound_to,
    })
}

/// The published `AssertionResponse` as webauthn-rs's `PublicKeyCredential`.
///
/// The two describe the same `navigator.credentials.get` result; they differ
/// only in naming the client extension outputs, which a passkey assertion does
/// not depend on.
fn public_key_credential(
    assertion: &approve_response::AssertionResponse,
) -> Result<PublicKeyCredential, ApproveError> {
    let r = &assertion.response;
    let mut response = json!({
        "authenticatorData": r.authenticator_data,
        "clientDataJSON": r.client_data_json,
        "signature": r.signature,
    });
    if let Some(handle) = &r.user_handle {
        response["userHandle"] = json!(handle);
    }
    // `rawId` is the credential id's bytes, and `id` is the same bytes in
    // base64url. Taking `rawId` from the published member rather than
    // re-deriving it means a producer that sent two different values is caught
    // by webauthn-rs rather than papered over here.
    let value = json!({
        "id": assertion.id,
        "rawId": assertion.raw_id,
        "response": response,
        "type": "public-key",
        "extensions": {},
    });
    serde_json::from_value(value).map_err(|e| {
        warn!(error = %e, "operation-bound step-up assertion does not parse");
        ApproveError::AssertionInvalid("unparseable")
    })
}

/// Verify a WebAuthn assertion whose challenge is `challenge` — bytes this
/// service chose and handed out, not ones webauthn-rs minted — against `did`'s
/// own registered passkeys (session passkeys, and step-up passkeys),
/// user verification required. The credential id (hex) on success; a short
/// machine-readable hint on failure.
///
/// For `task-consent/decision/0.2`'s `webauthn` evidence, whose challenge the
/// specification fixes as the UTF-8 bytes of the decision's `challenge`
/// (VTI-APV-015's gesture, offered by an approver as an additional factor on
/// top of their own proof). webauthn-rs only verifies against a state it
/// started, so a state is started over exactly these credentials and its
/// challenge replaced with the one the approver was given; every check
/// webauthn-rs makes — origin, RP id hash, signature, user verification,
/// credential offered — still runs.
pub(crate) async fn verify_assertion_over_challenge(
    state: &AppState,
    did: &str,
    challenge: &[u8],
    assertion: &Value,
) -> Result<String, &'static str> {
    use base64::Engine as _;
    let webauthn = state.webauthn.as_ref().ok_or("noRelyingParty")?;
    let mut passkeys = crate::step_up_passkey::credentials_of(state, did)
        .await
        .map_err(|_| "internal")?;
    passkeys.extend(
        get_passkey_user_by_did(&state.passkey_ks, did)
            .await
            .map_err(|_| "internal")?
            .map(|u| u.credentials)
            .unwrap_or_default(),
    );
    if passkeys.is_empty() {
        return Err("noPasskey");
    }
    let (_, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| "internal")?;
    let mut state_json = serde_json::to_value(&auth_state).map_err(|_| "internal")?;
    let slot = state_json.pointer_mut("/ast/challenge").ok_or("internal")?;
    *slot = Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge));
    let auth_state: PasskeyAuthentication =
        serde_json::from_value(state_json).map_err(|_| "internal")?;

    let r = &assertion["response"];
    let mut response = json!({
        "authenticatorData": r["authenticatorData"],
        "clientDataJSON": r["clientDataJSON"],
        "signature": r["signature"],
    });
    if r["userHandle"].is_string() {
        response["userHandle"] = r["userHandle"].clone();
    }
    let credential: PublicKeyCredential = serde_json::from_value(json!({
        "id": assertion["id"],
        "rawId": assertion["rawId"],
        "response": response,
        "type": "public-key",
        "extensions": {},
    }))
    .map_err(|_| "unparseable")?;
    let result = webauthn
        .finish_passkey_authentication(&credential, &auth_state)
        .map_err(|e| {
            warn!(%did, error = %e, "decision evidence assertion did not verify");
            "verificationFailed"
        })?;
    if !result.user_verified() {
        return Err("userNotVerified");
    }
    let cred_id_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(result.cred_id()));
    // The signature counter is WebAuthn's replay defence: persist it, on
    // whichever store the credential lives in.
    if let Ok(Some(mut user)) = get_passkey_user_by_cred(&state.passkey_ks, &cred_id_hex).await
        && user.did == did
    {
        for cred in &mut user.credentials {
            cred.update_credential(&result);
        }
        store_passkey_user(&state.passkey_ks, &user)
            .await
            .map_err(|_| "internal")?;
    } else if let Ok(Some(user)) =
        get_passkey_user_by_cred(&state.step_up_passkeys_ks, &cred_id_hex).await
        && user.did == did
    {
        crate::step_up_passkey::record_use(&state.step_up_passkeys_ks, user, &result)
            .await
            .map_err(|_| "internal")?;
    } else {
        return Err("credentialUnregistered");
    }
    Ok(cred_id_hex)
}

/// Remove every mark, pending or redeemable, whose life has ended. A storage
/// bound only: both reads above already treat an expired mark as absent.
pub async fn sweep_expired(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    let now = now.timestamp().max(0) as u64;
    let mut removed = 0;
    for (prefix, expiry) in [
        (
            PENDING_PREFIX,
            expiry_of::<PendingMark> as fn(&[u8]) -> Option<u64>,
        ),
        (MARK_PREFIX, expiry_of::<RedeemableMark>),
    ] {
        for (key, value) in ks.prefix_iter_raw(prefix.as_bytes().to_vec()).await? {
            // An unreadable row can never be honoured, so it goes too.
            if expiry(&value).is_none_or(|at| now >= at) {
                ks.remove(key).await?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

trait Expiring {
    fn expires_at(&self) -> u64;
}
impl Expiring for PendingMark {
    fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
impl Expiring for RedeemableMark {
    fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

fn expiry_of<T: Expiring + serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<T>(bytes)
        .ok()
        .map(|m| m.expires_at())
}

/// Record a spent-able gesture for `(admin_did, this operation)` as if the
/// admin had answered the ceremony — for tests of the acts it gates, which
/// have no authenticator.
#[cfg(test)]
pub async fn record_mark_for_test(
    state: &AppState,
    admin_did: &str,
    type_uri: &str,
    payload: &Value,
) -> Result<(), AppError> {
    let digest = operation_digest(type_uri, payload)?;
    state
        .step_up_marks_ks
        .insert(
            mark_key(admin_did, &digest),
            &RedeemableMark {
                expires_at: now_epoch().saturating_add(MARK_TTL_SECS),
                credential_id: Some("c0ffee".into()),
                bound_to: Some("zTestBound".into()),
            },
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
    const CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";

    fn payload(subject: &str) -> Value {
        json!({ "entry": { "subject": subject, "role": "admin", "scopes": [] } })
    }

    #[test]
    fn the_digest_is_stable_across_member_order() {
        let a = json!({ "entry": { "role": "admin", "subject": "did:key:z1", "scopes": [] } });
        let b = payload("did:key:z1");
        assert_eq!(
            operation_digest(GRANT, &a).unwrap(),
            operation_digest(GRANT, &b).unwrap()
        );
    }

    #[test]
    fn the_digest_binds_the_payload_and_the_task() {
        let p = payload("did:key:z1");
        let d = operation_digest(GRANT, &p).unwrap();
        assert_ne!(d, operation_digest(GRANT, &payload("did:key:z2")).unwrap());
        assert_ne!(
            d,
            operation_digest(CHANGE_ROLE, &p).unwrap(),
            "a gesture for one task must not authorize another with the same payload"
        );
    }

    #[test]
    fn the_wire_digest_is_salted_and_never_the_internal_one() {
        let p = payload("did:key:z1");
        let internal = operation_digest(GRANT, &p).unwrap();
        let a = wire_digest(GRANT, &p, "challenge-a").unwrap();
        let b = wire_digest(GRANT, &p, "challenge-b").unwrap();
        assert_ne!(a, internal);
        assert_ne!(
            a, b,
            "the salt is the challenge, so two requests do not link"
        );
    }

    #[test]
    fn the_digest_is_a_base58btc_sha256_multihash() {
        let d = operation_digest(GRANT, &payload("did:key:z1")).unwrap();
        let (base, bytes) = multibase::decode(&d).unwrap();
        assert_eq!(base, multibase::Base::Base58Btc);
        assert_eq!(&bytes[..2], &[0x12, 0x20], "sha2-256 multihash prefix");
        assert_eq!(bytes.len(), 34);
    }

    #[test]
    fn the_inline_request_conforms_and_carries_no_session() {
        let options = json!({
            "challenge": "Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2U",
            "rpId": "vtc.example.com",
            "timeout": 60000,
            "allowCredentials": [{ "type": "public-key", "id": "Y3JlZA", "transports": ["usb"] }],
            "userVerification": "preferred",
            "hints": [],
        });
        let req = approve_request_payload(
            "did:key:zAdmin",
            "Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2U",
            "zBound",
            "Grant the administrator role to did:key:zOther",
            &options,
        )
        .expect("a conforming approve-request");
        let v = serde_json::to_value(&req).unwrap();
        assert!(v.get("sessionId").is_none(), "{v}");
        assert_eq!(v["boundTo"], "zBound");
        assert_eq!(v["webauthn"]["challenge"], v["challenge"]);
        assert_eq!(v["webauthn"]["userVerification"], "required");
        assert_eq!(v["acceptableEvidence"], json!(["webauthn"]));
    }

    /// A recorded gesture is spent once, however many copies of the act race
    /// for it — the take is atomic, not a read followed by a remove.
    #[tokio::test]
    async fn concurrent_spends_of_one_mark_succeed_once() {
        let tv = crate::test_support::build_test_vtc().await;
        let p = payload("did:key:zRaced");
        record_mark_for_test(&tv.state, "did:key:zAdmin", GRANT, &p)
            .await
            .unwrap();
        let spends = (0..16).map(|_| spend_mark(&tv.state, "did:key:zAdmin", GRANT, &p));
        let won = futures_util::future::join_all(spends)
            .await
            .into_iter()
            .filter(|r| matches!(r, Ok(true)))
            .count();
        assert_eq!(won, 1);
    }
}
