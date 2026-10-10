//! Wallet sign-in started by a trigger link: `auth/oob/{request,claim,prove,
//! respond,redeem,cancel}/0.1` on the signed-document spine.
//!
//! The state, clocks and connection plumbing are
//! [`crate::member_portal::oob`]; this module is the check order of base
//! design §7.3–7.6 (`design-docs/vtc-qr-login-design.md`), with the trigger
//! link contract's changes (C5):
//!
//! - the claim carries `parentThreadId` equal to `payload.requestId`
//!   (VTI-LNK-054);
//! - `identify` is verified against the member's `authentication`
//!   relationship, `grant` against `assertionMethod`;
//! - the step 1 and step 2 responses are signed with this VTC's
//!   `assertionMethod` key.
//!
//! # No ACL pre-filter, and why that is safe
//!
//! Every signer here is a fresh Ed25519 `did:key` no ACL names: the browser's
//! `K_b` (`request`, `redeem`, `cancel`) and the wallet's per-scan `K_a`
//! (`claim`, `prove`, `respond`, `cancel`). [`precheck`] refuses any other
//! key before the spine verifies a proof (T21). Authority comes only from
//! the documents a member's DID signs inside `prove` and `respond`, and only
//! the holder of `K_b` can turn the result into a session.
//!
//! # Transports
//!
//! `request` needs the browser's `Origin` (T19), address and `User-Agent`, and
//! `redeem` sets cookies, so both are served only on the HTTPS door, which
//! supplies an [`HttpContext`]. The wallet's tasks travel on any transport
//! this spine serves; `sameNetwork` is `"unknown"` off HTTPS.

use serde::Serialize;
use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, StandardCode, TrustTask, TrustTaskCode};
use vti_common::audit::{AuditEvent, MemberWalletSignInData};
use vti_common::auth::session::{
    Session, SessionState, now_epoch, store_refresh_index, store_session,
};

use super::JoinAuthCtx;
use super::helpers::{
    TrustTaskOutcome, extended_code, parse_payload, reject_with, reject_with_code, success_response,
};
use crate::member_portal::oob::types::{
    CANCEL_TYPE, CLAIM_TYPE, GRANT_TYPE, GrantPayload, IDENTIFY_TYPE, IdentifyPayload, PROVE_TYPE,
    ProvePayload, REDEEM_TYPE, REQUEST_TYPE, RESPOND_TYPE, RedeemResponse, RequestIdPayload,
    RequestPayload, RequestResponse, Requester, RespondPayload, ServiceRef, StatusResponse, Step1,
    Step2,
};
use crate::member_portal::oob::{
    self, CLAIM_WINDOW_SECS, DECISION_WINDOW_SECS, HttpContext, MAX_PENDING_PER_ADDRESS, NOTIFIER,
    OobRequest, OobState, PollGuard, PollRefused, RequesterDetails, TransitionError,
};
use crate::member_portal::{MemberAuthBackend, active_member, cookies};
use crate::server::AppState;

/// Exactly what [`dispatch`] routes. `identify` and `grant` are not here: they
/// are only ever carried inside `prove` and `respond`, and one sent by itself
/// is refused as an unsupported type.
pub(crate) const URIS: &[&str] = &[
    REQUEST_TYPE,
    CLAIM_TYPE,
    PROVE_TYPE,
    RESPOND_TYPE,
    REDEEM_TYPE,
    CANCEL_TYPE,
];

/// A declared error code: `auth/oob/<task>:<local>` for the codes one task
/// declares, `auth/oob:<local>` for the family's shared ones (the published
/// `auth/oob` specifications, dtgwg-trust-tasks-tf `feat/auth-oob`).
// TODO: replace with generated trust-tasks types (their `error_codes`).
fn code(task: &str, local: &str) -> TrustTaskCode {
    const TASK_CODES: &[(&str, &str)] = &[
        ("claim", "alreadyClaimed"),
        ("prove", "numberMismatch"),
        ("redeem", "declined"),
        ("redeem", "pending"),
        ("request", "modeUnsupported"),
        ("request", "purposeUnsupported"),
        ("respond", "contextMismatch"),
    ];
    if TASK_CODES.contains(&(task, local)) {
        extended_code(&format!("auth/oob/{task}:{local}"))
    } else {
        extended_code(&format!("auth/oob:{local}"))
    }
}

fn task_of(type_uri: &str) -> &'static str {
    match type_uri {
        REQUEST_TYPE => "request",
        CLAIM_TYPE => "claim",
        PROVE_TYPE => "prove",
        RESPOND_TYPE => "respond",
        REDEEM_TYPE => "redeem",
        _ => "cancel",
    }
}

/// Run before the spine verifies the proof of an `auth/oob` document: the
/// signer must be an Ed25519 `did:key` (T21, decided from the identifier
/// alone), and `proof` and `recipient` are required. `None` lets the document
/// through. Until `trust-tasks-rs` publishes these specifications the spine's
/// `spec_policy_for` has no policy for them, so this is where their
/// `proofRequirement` and `recipient` rules are held.
pub(super) fn precheck(doc: &TrustTask<Value>, type_uri: &str) -> Option<TrustTaskOutcome> {
    if !URIS.contains(&type_uri) {
        return None;
    }
    let task = task_of(type_uri);
    if !doc.issuer.as_deref().is_some_and(oob::is_ed25519_did_key) {
        return Some(reject_with_code(
            doc,
            code(task, "keyUnsupported"),
            "the issuer must be an Ed25519 did:key generated for this exchange",
            None,
        ));
    }
    if doc.proof.is_none() {
        return Some(reject_with(doc, RejectReason::ProofRequired));
    }
    if doc.recipient.is_none() {
        return Some(reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::WrongRecipient),
            "recipient is required: address the document to this community's DID",
            None,
        ));
    }
    None
}

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    // The spine verified the proof against `issuer`; `precheck` required one.
    let signer = ctx.verified_signer.clone().unwrap_or_default();
    Some(match type_uri {
        REQUEST_TYPE => handle_request(state, doc, signer).await,
        CLAIM_TYPE => handle_claim(state, doc, signer).await,
        PROVE_TYPE => handle_prove(state, doc, signer).await,
        RESPOND_TYPE => handle_respond(state, doc, signer).await,
        REDEEM_TYPE => handle_redeem(state, doc, signer).await,
        CANCEL_TYPE => handle_cancel(state, doc, signer).await,
        _ => return None,
    })
}

// ── Shared ──────────────────────────────────────────────────────────────────

async fn audit(
    state: &AppState,
    actor: &str,
    stage: &str,
    rec: &OobRequest,
    member: Option<&str>,
    reason: Option<&str>,
    grant: Option<Value>,
) {
    let Some(writer) = state.audit_writer.as_ref() else {
        tracing::warn!(
            stage,
            "audit writer not configured; wallet sign-in step not audited"
        );
        return;
    };
    let event = AuditEvent::MemberWalletSignIn(MemberWalletSignInData {
        stage: stage.into(),
        request_id: rec.request_id.clone(),
        member: member.map(str::to_string),
        reason: reason.map(str::to_string),
        location: Some(rec.requester.location.clone()),
        grant,
    });
    if let Err(e) = writer.write(actor, member, event).await {
        tracing::warn!(stage, error = %e, "could not audit a wallet sign-in step");
    }
}

/// The `requestId` a wallet document is about: `parentThreadId` when the
/// document carries one, else the carried document's own `payload.requestId`
/// — only a lookup key here; every check below compares against the record.
fn request_id_hint(doc: &TrustTask<Value>, carried: &Value) -> Option<String> {
    doc.parent_thread_id.clone().or_else(|| {
        carried
            .get("payload")
            .and_then(|p| p.get("requestId"))
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

/// Sign a success payload as this VTC's attestation (`assertionMethod`), and
/// return the signed document with the outcome carrying it.
async fn attested<R: Serialize>(
    state: &AppState,
    doc: &TrustTask<Value>,
    payload: R,
) -> Result<(Value, TrustTaskOutcome), TrustTaskOutcome> {
    let internal = |reason: String| reject_with(doc, RejectReason::InternalError { reason });
    let Some(signer) = state.credential_signer.clone() else {
        return Err(internal(
            "this community has no signing key, so it cannot sign the sign-in response".into(),
        ));
    };
    let unsigned = success_response(doc, payload);
    let mut value: Value =
        serde_json::from_slice(&unsigned.body).map_err(|e| internal(e.to_string()))?;
    signer
        .sign_attested_response(&mut value)
        .await
        .map_err(|e| internal(e.to_string()))?;
    let body = serde_json::to_vec(&value).map_err(|e| internal(e.to_string()))?;
    Ok((
        value,
        TrustTaskOutcome {
            status: axum::http::StatusCode::OK,
            body,
        },
    ))
}

fn not_found(doc: &TrustTask<Value>, task: &str) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        code(task, "requestNotFound"),
        "no such sign-in request",
        None,
    )
}

fn expired(doc: &TrustTask<Value>, task: &str) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        code(task, "requestExpired"),
        "this sign-in request has expired; refresh the code on the website and scan again",
        None,
    )
}

/// The one refusal for a non-member, a bad signature, a stale or replayed
/// carried document, or a mismatched lock (T15): which of them failed is not
/// the caller's to learn.
fn not_authorized(doc: &TrustTask<Value>, task: &str) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        code(task, "notAuthorized"),
        "this sign-in was not authorised",
        None,
    )
}

/// End a request as declined after a failed step from the lock holder — one
/// attempt per request (base design §7.2). Only from `from`; a request some
/// other caller already moved on is left alone.
async fn decline(
    state: &AppState,
    rec: &OobRequest,
    from: OobState,
    member: Option<&str>,
    reason: &str,
) {
    let now = now_epoch();
    let lock = rec.approver_key.clone();
    let res = oob::transition(&state.member_sessions_ks, &rec.request_id, |r| {
        if r.state != from || r.approver_key != lock {
            return Err(());
        }
        r.end(OobState::Declined, now);
        Ok(())
    })
    .await;
    if let Ok((_, ended)) = res {
        let actor = lock.as_deref().unwrap_or("unknown");
        audit(
            state,
            actor,
            "proofFailed",
            &ended,
            member,
            Some(reason),
            None,
        )
        .await;
    }
}

/// A carried, member-signed document, checked as the spine checks an outer
/// one: its type, its recipient, its age, its `id` not seen before, and a
/// proof by its own issuer made for `purpose`. Returns the parsed document.
///
/// The caller has already checked the issuer string against the ACL — before
/// this resolves anything (T15).
async fn verify_carried(
    state: &AppState,
    received: &Value,
    expected_type: &str,
    issuer: &str,
    purpose: vti_common::auth::ProofPurpose,
) -> Result<TrustTask<Value>, &'static str> {
    let inner: TrustTask<Value> =
        serde_json::from_value(received.clone()).map_err(|_| "not a Trust Task document")?;
    if inner.type_uri.to_string() != expected_type {
        return Err("wrong carried document type");
    }
    if inner.issuer.as_deref() != Some(issuer) {
        return Err("carried document issuer mismatch");
    }
    let now = chrono::Utc::now();
    let vtc_did = state.config.read().await.vtc_did.clone();
    let Some(vtc_did) = vtc_did else {
        return Err("community DID not configured");
    };
    if inner.recipient.as_deref() != Some(vtc_did.as_str()) {
        return Err("carried document not addressed to this community");
    }
    inner
        .validate_freshness(now, &super::freshness_policy())
        .map_err(|_| "carried document is stale")?;
    let declared = inner
        .proof
        .as_ref()
        .map(|p| p.proof_purpose.clone())
        .ok_or("carried document is unsigned")?;
    if declared != purpose.as_str() {
        return Err("carried document signed for the wrong purpose");
    }
    let signer = match purpose {
        vti_common::auth::ProofPurpose::AssertionMethod => {
            super::helpers::verify_received_approval_proof(state, received, expected_type).await
        }
        _ => super::helpers::verify_received_trust_task_proof(state, received).await,
    }
    .map_err(|_| "carried document proof does not verify")?;
    if signer != issuer {
        return Err("carried document signed by another DID");
    }
    // Replay of the carried document's own `id` (T7), in the same record the
    // spine keeps for outer documents.
    match state
        .accepted_ids()
        .claim(&inner, super::retain_until(&inner, now), now)
        .await
    {
        Ok(super::accepted_ids::Acceptance::Fresh(claim)) => {
            claim.completed(None).await;
            Ok(inner)
        }
        _ => Err("carried document replayed"),
    }
}

// ── request ─────────────────────────────────────────────────────────────────

async fn handle_request(
    state: &AppState,
    doc: TrustTask<Value>,
    start_key: String,
) -> TrustTaskOutcome {
    let Some(http) = HttpContext::current() else {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            "auth/oob/request is accepted only over HTTPS from the member portal",
            None,
        );
    };
    let payload: RequestPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if payload.purpose != "login" {
        return reject_with_code(
            &doc,
            code("request", "purposeUnsupported"),
            format!(
                "purpose `{}` is not served; v1 serves `login`",
                payload.purpose
            ),
            None,
        );
    }
    if payload.mode != "scan" {
        return reject_with_code(
            &doc,
            code("request", "modeUnsupported"),
            format!("mode `{}` is not served; v1 serves `scan`", payload.mode),
            None,
        );
    }
    let (public_url, vtc_did) = {
        let cfg = state.config.read().await;
        (cfg.public_url.clone(), cfg.vtc_did.clone())
    };
    if vtc_did.is_none() {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::Unavailable),
            "this community has not finished setting up",
            None,
        );
    }
    // T19: only the portal's own page may open a request, so another website
    // cannot start one through the member's browser.
    let origin = match (
        oob::portal_origin(public_url.as_deref(), &http),
        http.origin.as_deref(),
    ) {
        (Some(portal), Some(sent)) if portal == sent => portal,
        _ => {
            return reject_with_code(
                &doc,
                TrustTaskCode::Standard(StandardCode::PermissionDenied),
                "auth/oob/request is accepted only from the member portal's origin",
                None,
            );
        }
    };
    let address = http.client_ip.to_string();
    match oob::open_requests_from(&state.member_sessions_ks, &address).await {
        Ok(n) if n >= MAX_PENDING_PER_ADDRESS => {
            return reject_with_code(
                &doc,
                code("request", "rateLimited"),
                "too many sign-in codes are open from this network; use one or wait for it to expire",
                None,
            );
        }
        Ok(_) => {}
        Err(e) => return super::helpers::app_error_to_reject(&doc, &e),
    }

    let now = now_epoch();
    let (browser, os) = oob::browser_and_os(http.user_agent.as_deref());
    let rec = OobRequest {
        request_id: oob::new_request_id(),
        state: OobState::Pending,
        start_key: start_key.clone(),
        start_network: Some(address),
        approver_key: None,
        purpose: payload.purpose,
        mode: payload.mode,
        origin,
        match_number: None,
        match_number_delivered: false,
        requester: RequesterDetails {
            location: oob::locate(http.client_ip).unwrap_or_else(|| "unknown".into()),
            browser,
            os,
            created_at: oob::rfc3339(now),
        },
        identified_did: None,
        step2_digest: None,
        step1: None,
        created_at: now,
        claim_deadline: now + CLAIM_WINDOW_SECS,
        decision_deadline: None,
        grant: None,
        ended_at: None,
    };
    if let Err(e) = oob::create(&state.member_sessions_ks, &rec).await {
        return super::helpers::app_error_to_reject(&doc, &e);
    }
    audit(state, &start_key, "requested", &rec, None, None, None).await;
    success_response(
        &doc,
        RequestResponse {
            ext: None,
            request_id: rec.request_id.clone(),
            claim_deadline: rec.claim_deadline,
        },
    )
}

// ── claim ───────────────────────────────────────────────────────────────────

async fn handle_claim(
    state: &AppState,
    doc: TrustTask<Value>,
    approver: String,
) -> TrustTaskOutcome {
    let payload: RequestIdPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // VTI-LNK-054: the first request carries the handle as `parentThreadId`.
    if doc.parent_thread_id.as_deref() != Some(payload.request_id.as_str()) {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::MalformedRequest),
            "parentThreadId must equal payload.requestId (VTI-LNK-054)",
            None,
        );
    }
    let ks = &state.member_sessions_ks;
    let rec = match oob::load(ks, &payload.request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(&doc, "claim"),
        Err(e) => return super::helpers::app_error_to_reject(&doc, &e),
    };
    let now = now_epoch();
    match rec.effective_state(now) {
        OobState::Pending => {}
        OobState::Expired => {
            if let Ok(true) = oob::settle_expiry(ks, &rec.request_id).await {
                audit(state, &approver, "expired", &rec, None, None, None).await;
            }
            return expired(&doc, "claim");
        }
        // No details: the bystander learns nothing about who holds it (T3).
        _ => {
            return reject_with_code(
                &doc,
                code("claim", "alreadyClaimed"),
                "this code was already used by another device",
                None,
            );
        }
    }

    let (vtc_did, vtc_name, profile) = {
        let cfg = state.config.read().await;
        let did = cfg.vtc_did.clone().unwrap_or_default();
        let name = cfg.vtc_name.clone();
        drop(cfg);
        let profile = crate::community::load_profile(&state.community_ks)
            .await
            .ok()
            .flatten();
        (did, name, profile)
    };
    let decision_deadline = now + DECISION_WINDOW_SECS;
    let step1 = Step1 {
        ext: None,
        request_id: rec.request_id.clone(),
        service: ServiceRef {
            // The schema requires a name: the profile's, the configured one,
            // else the DID itself.
            name: profile
                .map(|p| p.name)
                .filter(|n| !n.is_empty())
                .or(vtc_name.filter(|n| !n.is_empty()))
                .unwrap_or_else(|| vtc_did.chars().take(128).collect()),
            did: vtc_did,
        },
        origin: rec.origin.clone(),
        purpose: rec.purpose.clone(),
        decision_deadline,
    };
    // Signed before the lock is taken, so a request is never claimed with no
    // response to show for it.
    let (_, outcome) = match attested(state, &doc, &step1).await {
        Ok(signed) => signed,
        Err(e) => return e,
    };
    let number = oob::new_match_number();
    let res = oob::transition(ks, &rec.request_id, |r| {
        if r.effective_state(now_epoch()) != OobState::Pending {
            return Err(());
        }
        r.state = OobState::Claimed;
        r.approver_key = Some(approver.clone());
        r.match_number = Some(number.clone());
        r.decision_deadline = Some(decision_deadline);
        r.step1 = Some(step1.clone());
        Ok(())
    })
    .await;
    match res {
        Ok((_, claimed)) => {
            audit(state, &approver, "claimed", &claimed, None, None, None).await;
            outcome
        }
        Err(TransitionError::Store(e)) => super::helpers::app_error_to_reject(&doc, &e),
        Err(TransitionError::NotFound) => not_found(&doc, "claim"),
        Err(TransitionError::Refused(())) => reject_with_code(
            &doc,
            code("claim", "alreadyClaimed"),
            "this code was already used by another device",
            None,
        ),
    }
}

// ── prove ───────────────────────────────────────────────────────────────────

async fn handle_prove(
    state: &AppState,
    doc: TrustTask<Value>,
    approver: String,
) -> TrustTaskOutcome {
    let payload: ProvePayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let Some(request_id) = request_id_hint(&doc, &payload.identify) else {
        return not_found(&doc, "prove");
    };
    let ks = &state.member_sessions_ks;
    let rec = match oob::load(ks, &request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(&doc, "prove"),
        Err(e) => return super::helpers::app_error_to_reject(&doc, &e),
    };

    // 1. The outer document is the lock holder's, and the request is claimed
    //    and inside its decision window. A stranger's failure changes nothing.
    if rec.approver_key.as_deref() != Some(approver.as_str()) {
        return reject_with_code(
            &doc,
            code("prove", "notClaimant"),
            "this device does not hold this sign-in request",
            None,
        );
    }
    match rec.effective_state(now_epoch()) {
        OobState::Claimed => {}
        OobState::Expired => {
            if let Ok(true) = oob::settle_expiry(ks, &rec.request_id).await {
                audit(state, &approver, "expired", &rec, None, None, None).await;
            }
            return expired(&doc, "prove");
        }
        // One proof attempt per request.
        _ => return not_authorized(&doc, "prove"),
    }

    // From here every failure declines the request (base design §7.4).
    let fail = |member: Option<String>, reason: &'static str| {
        let rec = rec.clone();
        async move {
            decline(state, &rec, OobState::Claimed, member.as_deref(), reason).await;
        }
    };

    // 2. The carried identify names this request and this lock.
    let identify_issuer = payload
        .identify
        .get("issuer")
        .and_then(Value::as_str)
        .map(str::to_string);
    let identify_payload: Option<IdentifyPayload> = payload
        .identify
        .get("payload")
        .cloned()
        .and_then(|p| serde_json::from_value(p).ok());
    let (Some(member), Some(identify_payload)) = (identify_issuer, identify_payload) else {
        fail(None, "identify is malformed").await;
        return not_authorized(&doc, "prove");
    };
    if identify_payload.request_id != rec.request_id || identify_payload.approver_key != approver {
        fail(Some(member), "identify names another request or lock").await;
        return not_authorized(&doc, "prove");
    }

    // 3. The issuer string is an active member — read from the ACL and member
    //    records, before any DID is resolved (T15).
    match active_member(state, &member).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            fail(Some(member), "not an active member").await;
            return not_authorized(&doc, "prove");
        }
        Err(e) => return super::helpers::app_error_to_reject(&doc, &e),
    }

    // 4. The proof verifies against the member's `authentication` key
    //    (contract C5); recipient, freshness and replay as for any document.
    if let Err(reason) = verify_carried(
        state,
        &payload.identify,
        IDENTIFY_TYPE,
        &member,
        vti_common::auth::ProofPurpose::Authentication,
    )
    .await
    {
        tracing::info!(reason, "auth/oob/prove: identify refused");
        fail(Some(member), reason).await;
        return not_authorized(&doc, "prove");
    }

    // 5. The number the member typed.
    if Some(identify_payload.entered_number.as_str()) != rec.match_number.as_deref() {
        fail(Some(member), "wrong number").await;
        return reject_with_code(
            &doc,
            code("prove", "numberMismatch"),
            "that is not the number on the screen; refresh the code on the website and scan again",
            None,
        );
    }

    // 6. Step 2: step 1 repeated, plus the starter.
    let Some(step1) = rec.step1.clone() else {
        return reject_with(
            &doc,
            RejectReason::InternalError {
                reason: "claimed request has no step 1".into(),
            },
        );
    };
    let approver_ip = HttpContext::current().map(|h| h.client_ip);
    let step2 = Step2 {
        ext: None,
        request_id: step1.request_id,
        service: step1.service,
        origin: step1.origin,
        purpose: step1.purpose,
        decision_deadline: step1.decision_deadline,
        session_key: rec.start_key.clone(),
        requester: Requester {
            location: rec.requester.location.clone(),
            browser: rec.requester.browser.clone(),
            os: rec.requester.os.clone(),
            created_at: rec.requester.created_at.clone(),
            same_network: oob::same_network(rec.start_network.as_deref(), approver_ip),
        },
        identified_as: member.clone(),
    };
    let (signed, outcome) = match attested(state, &doc, &step2).await {
        Ok(s) => s,
        Err(e) => return e,
    };
    let digest = match oob::context_digest(&signed) {
        Ok(d) => d,
        Err(e) => return super::helpers::app_error_to_reject(&doc, &e),
    };
    let res = oob::transition(ks, &rec.request_id, |r| {
        if r.effective_state(now_epoch()) != OobState::Claimed
            || r.approver_key.as_deref() != Some(approver.as_str())
        {
            return Err(());
        }
        r.state = OobState::Identified;
        r.identified_did = Some(member.clone());
        r.step2_digest = Some(digest.clone());
        Ok(())
    })
    .await;
    match res {
        Ok((_, identified)) => {
            audit(
                state,
                &member,
                "proved",
                &identified,
                Some(&member),
                None,
                None,
            )
            .await;
            outcome
        }
        Err(TransitionError::Store(e)) => super::helpers::app_error_to_reject(&doc, &e),
        Err(_) => expired(&doc, "prove"),
    }
}

// ── respond ─────────────────────────────────────────────────────────────────

async fn handle_respond(
    state: &AppState,
    doc: TrustTask<Value>,
    approver: String,
) -> TrustTaskOutcome {
    let payload: RespondPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let Some(request_id) = request_id_hint(&doc, &payload.grant) else {
        return not_found(&doc, "respond");
    };
    let ks = &state.member_sessions_ks;
    let rec = match oob::load(ks, &request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(&doc, "respond"),
        Err(e) => return super::helpers::app_error_to_reject(&doc, &e),
    };

    // 1. The lock holder, an identified request, inside the decision window.
    if rec.approver_key.as_deref() != Some(approver.as_str()) {
        return reject_with_code(
            &doc,
            code("respond", "notClaimant"),
            "this device does not hold this sign-in request",
            None,
        );
    }
    match rec.effective_state(now_epoch()) {
        OobState::Identified => {}
        OobState::Expired => {
            if let Ok(true) = oob::settle_expiry(ks, &rec.request_id).await {
                audit(state, &approver, "expired", &rec, None, None, None).await;
            }
            return expired(&doc, "respond");
        }
        OobState::Claimed => return not_authorized(&doc, "respond"),
        _ => {
            return reject_with_code(
                &doc,
                code("respond", "alreadyDecided"),
                "this sign-in request has already been decided",
                None,
            );
        }
    }
    let Some(member) = rec.identified_did.clone() else {
        return not_authorized(&doc, "respond");
    };
    let fail = |reason: &'static str| {
        let rec = rec.clone();
        let member = member.clone();
        async move {
            decline(state, &rec, OobState::Identified, Some(&member), reason).await;
        }
    };

    // 2. The grant is the identified DID's, signed for `assertionMethod`,
    //    fresh, and new.
    if payload.grant.get("issuer").and_then(Value::as_str) != Some(member.as_str()) {
        fail("grant from another identity").await;
        return not_authorized(&doc, "respond");
    }
    if let Err(reason) = verify_carried(
        state,
        &payload.grant,
        GRANT_TYPE,
        &member,
        vti_common::auth::ProofPurpose::AssertionMethod,
    )
    .await
    {
        tracing::info!(reason, "auth/oob/respond: grant refused");
        fail(reason).await;
        return not_authorized(&doc, "respond");
    }
    let grant: GrantPayload = match payload
        .grant
        .get("payload")
        .cloned()
        .map(serde_json::from_value)
    {
        Some(Ok(g)) => g,
        _ => {
            fail("grant payload is malformed").await;
            return not_authorized(&doc, "respond");
        }
    };

    // 3–4. The lock, the browser key, the origin and the context it was shown.
    let context_ok = grant.request_id == rec.request_id
        && grant.approver_key == approver
        && grant.session_key == rec.start_key
        && grant.origin == rec.origin
        && rec
            .step2_digest
            .as_deref()
            .is_some_and(|d| oob::same_digest(d, &grant.context_digest));
    if !context_ok {
        fail("grant context mismatch").await;
        return reject_with_code(
            &doc,
            code("respond", "contextMismatch"),
            "the grant does not match this sign-in request",
            None,
        );
    }
    let decision = match grant.decision.as_str() {
        "approve" => OobState::Approved,
        "decline" => OobState::Declined,
        _ => {
            fail("unknown decision").await;
            return not_authorized(&doc, "respond");
        }
    };
    if decision == OobState::Approved {
        let not_after = grant.not_after;
        if not_after <= now_epoch() {
            fail("grant notAfter has passed").await;
            return not_authorized(&doc, "respond");
        }
        // 5. Still a member.
        match active_member(state, &member).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                fail("no longer an active member").await;
                return not_authorized(&doc, "respond");
            }
            Err(e) => return super::helpers::app_error_to_reject(&doc, &e),
        }
    }

    // 6. Decide, once.
    let signed_grant = payload.grant.clone();
    let now = now_epoch();
    let res = oob::transition(ks, &rec.request_id, |r| {
        if r.effective_state(now) != OobState::Identified
            || r.approver_key.as_deref() != Some(approver.as_str())
        {
            return Err(());
        }
        r.grant = Some(signed_grant.clone());
        if decision == OobState::Declined {
            r.end(OobState::Declined, now);
        } else {
            r.state = OobState::Approved;
        }
        Ok(())
    })
    .await;
    match res {
        Ok((_, decided)) => {
            let stage = if decision == OobState::Approved {
                "approved"
            } else {
                "declined"
            };
            audit(
                state,
                &member,
                stage,
                &decided,
                Some(&member),
                None,
                Some(signed_grant),
            )
            .await;
            success_response(
                &doc,
                StatusResponse {
                    ext: None,
                    status: stage.into(),
                },
            )
        }
        Err(TransitionError::Store(e)) => super::helpers::app_error_to_reject(&doc, &e),
        Err(_) => reject_with_code(
            &doc,
            code("respond", "alreadyDecided"),
            "this sign-in request has already been decided",
            None,
        ),
    }
}

// ── cancel ──────────────────────────────────────────────────────────────────

async fn handle_cancel(
    state: &AppState,
    doc: TrustTask<Value>,
    signer: String,
) -> TrustTaskOutcome {
    let payload: RequestIdPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ks = &state.member_sessions_ks;
    let now = now_epoch();
    let res = oob::transition(ks, &payload.request_id, |r| {
        if r.start_key != signer && r.approver_key.as_deref() != Some(signer.as_str()) {
            return Err("notAuthorized");
        }
        if r.state.is_final() {
            return Err("alreadyDecided");
        }
        if r.effective_state(now) == OobState::Expired {
            r.end(OobState::Expired, now);
            return Ok(OobState::Expired);
        }
        r.end(OobState::Cancelled, now);
        Ok(OobState::Cancelled)
    })
    .await;
    match res {
        Ok((OobState::Cancelled, rec)) => {
            audit(
                state,
                &signer,
                "cancelled",
                &rec,
                rec.identified_did.as_deref(),
                None,
                None,
            )
            .await;
            success_response(
                &doc,
                StatusResponse {
                    ext: None,
                    status: "cancelled".into(),
                },
            )
        }
        Ok((_, rec)) => {
            audit(state, &signer, "expired", &rec, None, None, None).await;
            expired(&doc, "cancel")
        }
        Err(TransitionError::NotFound) => not_found(&doc, "cancel"),
        Err(TransitionError::Store(e)) => super::helpers::app_error_to_reject(&doc, &e),
        Err(TransitionError::Refused("notAuthorized")) => not_authorized(&doc, "cancel"),
        Err(TransitionError::Refused(local)) => reject_with_code(
            &doc,
            code("cancel", local),
            "this sign-in request has already ended",
            None,
        ),
    }
}

// ── redeem ──────────────────────────────────────────────────────────────────

fn pending(doc: &TrustTask<Value>, rec: &OobRequest, now: u64) -> TrustTaskOutcome {
    let state = rec.effective_state(now);
    let mut details = json!({ "state": state.as_str() });
    // Only the holder of K_b ever receives the number (T16).
    if let Some(n) = &rec.match_number {
        details["matchNumber"] = Value::String(n.clone());
    }
    reject_with_code(
        doc,
        code("redeem", "pending"),
        "waiting for the wallet; poll again",
        Some(details),
    )
}

async fn handle_redeem(
    state: &AppState,
    doc: TrustTask<Value>,
    starter: String,
) -> TrustTaskOutcome {
    let Some(http) = HttpContext::current() else {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            "auth/oob/redeem is served only over HTTPS, where the session is set as cookies",
            None,
        );
    };
    let payload: RequestIdPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ks = &state.member_sessions_ks;
    let rec = match oob::load(ks, &payload.request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(&doc, "redeem"),
        Err(e) => return super::helpers::app_error_to_reject(&doc, &e),
    };
    if rec.start_key != starter {
        return reject_with_code(
            &doc,
            code("redeem", "notStarter"),
            "only the browser that started this sign-in can redeem it",
            None,
        );
    }

    let _poll = match PollGuard::open(&rec.request_id, http.client_ip) {
        Ok(g) => Some(g),
        // A second poll on one request answers at once rather than holding.
        Err(PollRefused::AlreadyOpen) => None,
        Err(PollRefused::AddressCap) => {
            return reject_with_code(
                &doc,
                code("redeem", "rateLimited"),
                "too many sign-in polls are open from this network",
                None,
            );
        }
    };
    let deadline = tokio::time::Instant::now() + oob::redeem_hold();
    let entry_state = rec.effective_state(now_epoch());

    loop {
        let notify = NOTIFIER.handle(&rec.request_id);
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let current = match oob::load(ks, &rec.request_id).await {
            Ok(Some(r)) => r,
            Ok(None) => return not_found(&doc, "redeem"),
            Err(e) => return super::helpers::app_error_to_reject(&doc, &e),
        };
        let now = now_epoch();
        match current.effective_state(now) {
            OobState::Approved => return redeem_approved(state, &doc, &http, &current).await,
            OobState::Consumed => {
                return reject_with_code(
                    &doc,
                    code("redeem", "alreadyDecided"),
                    "this sign-in has already been used",
                    None,
                );
            }
            OobState::Declined => {
                return reject_with_code(
                    &doc,
                    code("redeem", "declined"),
                    "the sign-in was declined",
                    Some(json!({ "state": "declined" })),
                );
            }
            // Contract C9: `declined`, with the state saying why.
            OobState::Cancelled => {
                return reject_with_code(
                    &doc,
                    code("redeem", "declined"),
                    "the sign-in was cancelled",
                    Some(json!({ "state": "cancelled" })),
                );
            }
            OobState::Expired => {
                if let Ok(true) = oob::settle_expiry(ks, &current.request_id).await {
                    audit(state, &starter, "expired", &current, None, None, None).await;
                }
                return expired(&doc, "redeem");
            }
            s @ (OobState::Pending | OobState::Claimed | OobState::Identified) => {
                let number_owed = s == OobState::Claimed && !current.match_number_delivered;
                if s != entry_state || number_owed || _poll.is_none() {
                    if current.match_number.is_some() && !current.match_number_delivered {
                        let _ = oob::transition(ks, &current.request_id, |r| {
                            r.match_number_delivered = true;
                            Ok::<_, ()>(())
                        })
                        .await;
                    }
                    return pending(&doc, &current, now);
                }
            }
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            let current = match oob::load(ks, &rec.request_id).await {
                Ok(Some(r)) => r,
                _ => return not_found(&doc, "redeem"),
            };
            return pending(&doc, &current, now_epoch());
        }
    }
}

/// `approved → consumed` once, then the session: subject the DID that signed
/// the grant, session key `K_b`, `amr = ["did", "oob", "uv"]`, ending at the
/// earlier of the grant's `notAfter` and the member session limit.
async fn redeem_approved(
    state: &AppState,
    doc: &TrustTask<Value>,
    http: &HttpContext,
    rec: &OobRequest,
) -> TrustTaskOutcome {
    let ks = &state.member_sessions_ks;
    let now = now_epoch();
    let res = oob::transition(ks, &rec.request_id, |r| {
        if r.effective_state(now) != OobState::Approved {
            return Err(());
        }
        r.end(OobState::Consumed, now);
        Ok(())
    })
    .await;
    let consumed = match res {
        Ok((_, r)) => r,
        Err(TransitionError::Store(e)) => return super::helpers::app_error_to_reject(doc, &e),
        Err(_) => {
            return reject_with_code(
                doc,
                code("redeem", "alreadyDecided"),
                "this sign-in has already been used",
                None,
            );
        }
    };
    let Some(member_did) = consumed.identified_did.clone() else {
        return not_authorized(doc, "redeem");
    };
    // Membership again, now (T18).
    let member = match active_member(state, &member_did).await {
        Ok(Some(m)) => m,
        Ok(None) => return not_authorized(doc, "redeem"),
        Err(e) => return super::helpers::app_error_to_reject(doc, &e),
    };
    let not_after = consumed
        .grant
        .as_ref()
        .and_then(|g| g.get("payload"))
        .and_then(|p| p.get("notAfter"))
        .and_then(oob::epoch_of)
        .unwrap_or(now);
    if not_after <= now {
        return not_authorized(doc, "redeem");
    }

    match mint_session(state, &member_did, &consumed.start_key, not_after).await {
        Ok((_session_id, session_end, set)) => {
            http.set_cookies(set);
            audit(
                state,
                &member_did,
                "redeemed",
                &consumed,
                Some(&member_did),
                None,
                None,
            )
            .await;
            success_response(
                doc,
                RedeemResponse {
                    ext: None,
                    subject: member_did.clone(),
                    display_name: member
                        .entry
                        .label
                        .clone()
                        .filter(|l| !l.is_empty())
                        .unwrap_or_else(|| member_did.chars().take(128).collect()),
                    not_after: session_end,
                    amr: amr(),
                },
            )
        }
        Err(e) => super::helpers::app_error_to_reject(doc, &e),
    }
}

fn amr() -> Vec<String> {
    vec!["did".into(), "oob".into(), "uv".into()]
}

/// Create the member session and the cookies that carry it, through the same
/// backend, keyspace and cookie shapes as every portal sign-in
/// (`crate::member_portal`).
async fn mint_session(
    state: &AppState,
    did: &str,
    session_key: &str,
    not_after: u64,
) -> Result<(String, u64, Vec<String>), crate::error::AppError> {
    let backend = MemberAuthBackend::from_state(state).await?;
    let session_id = uuid::Uuid::new_v4().to_string();
    let amr = amr();
    let acr = "aal2".to_string();
    let minted = vti_common::auth::handlers::mint_session_tokens(
        &backend,
        did,
        &session_id,
        &crate::acl::Role::Reader,
        &[],
        &amr,
        &acr,
        false,
    )
    .await?;
    // The grant's `notAfter` bounds the session: refreshing cannot extend it.
    let refresh_expires_at = minted.refresh_expires_at.min(not_after);
    let access_expires_at = minted.access_expires_at.min(not_after);
    store_session(
        &state.member_sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: minted.issued_at,
            last_seen: minted.issued_at,
            refresh_token: Some(minted.refresh_token.clone()),
            refresh_expires_at: Some(refresh_expires_at),
            tee_attested: false,
            amr,
            acr,
            acr_expires_at: None,
            token_id: Some(minted.token_id.clone()),
            session_pubkey_b58btc: oob::did_key_multikey(session_key).map(str::to_string),
        },
    )
    .await?;
    store_refresh_index(
        &state.member_sessions_ks,
        &minted.refresh_token,
        &session_id,
    )
    .await?;
    let now = now_epoch();
    let access_max_age = access_expires_at.saturating_sub(now).max(1);
    let refresh_max_age = refresh_expires_at.saturating_sub(now).max(1);
    Ok((
        session_id,
        refresh_expires_at,
        vec![
            cookies::session_cookie(&minted.access_token, access_max_age),
            cookies::refresh_cookie(&minted.refresh_token, refresh_max_age),
            cookies::csrf_cookie(&cookies::new_csrf(), refresh_max_age),
        ],
    ))
}
