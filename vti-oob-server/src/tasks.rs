//! The handlers: `auth/oob/request/0.2`, `claim/0.2`, `prove/0.3`,
//! `respond/0.3` (carrying a `grant/0.3`), `redeem/0.2` and `cancel/0.1` on
//! the signed-document spine. Earlier versions are not served.
//!
//! This module is the check order of base design §7.3–7.6
//! (`design-docs/vtc-qr-login-design.md`), with the trigger link contract's
//! changes (C5):
//!
//! - the claim carries `parentThreadId` equal to `payload.requestId`
//!   (VTI-LNK-054);
//! - `identify` is verified against the approver's `authentication`
//!   relationship, `grant` against `assertionMethod`;
//! - the step 1 and step 2 responses are signed with the service's
//!   `assertionMethod` key ([`OobHost::sign_step`]).
//!
//! # No ACL pre-filter, and why that is safe
//!
//! Every signer here is a fresh Ed25519 `did:key` no ACL names: the browser's
//! `K_b` (`request`, `redeem`, `cancel`) and the wallet's per-scan `K_a`
//! (`claim`, `prove`, `respond`, `cancel`). [`precheck`] refuses any other
//! key before the spine verifies a proof (T21). Authority comes only from
//! the documents an approver's DID signs inside `prove` and `respond`, and
//! only the holder of `K_b` can turn the result into anything.
//!
//! # Audiences
//!
//! The audience is fixed at `request`, stored on the record, and repeated by
//! the service in the signed step 1 and step 2 responses, so the grant's
//! `contextDigest` covers it: an approval given for one audience cannot be
//! redeemed as another (T19). Each audience has its own gate
//! ([`OobHost::gate`]), and `redeem` hands the host the audience the approver
//! approved, never another.
//!
//! # Transports
//!
//! `request` needs the browser's `Origin` (T19), address and `User-Agent`,
//! and `redeem` holds a long poll and may set cookies, so both are served only
//! on the HTTPS door, which supplies an [`HttpContext`]. The wallet's tasks
//! travel on any transport the spine serves; `sameNetwork` is `"unknown"` off
//! HTTPS.

use serde::Serialize;
use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, StandardCode, TrustTask, TrustTaskCode};
use vti_common::auth::session::now_epoch;
use vti_trust_task_server::TrustTaskOutcome;
use vti_trust_task_server::reject::{
    extended_code, parse_payload, reject_with, reject_with_code, success_response,
};

use crate::audience::Audience;
use crate::host::{Approved, Completion, Eligibility, Gate, OobHost, SignInEvent};
use crate::http::HttpContext;
use crate::poll::{NOTIFIER, PollGuard, PollRefused};
use crate::record::{
    self, CLAIM_WINDOW_SECS, DECISION_WINDOW_SECS, MAX_PENDING_PER_ADDRESS, OobRequest, OobState,
    RequesterDetails, TransitionError,
};
use crate::types::{
    CANCEL_TYPE, CLAIM_TYPE, CancelPayload, CancelResponse, ClaimPayload, GRANT_TYPE,
    GrantDecision, GrantPayload, IDENTIFY_TYPE, IdentifyPayload, PROVE_TYPE, ProvePayload,
    REDEEM_TYPE, REQUEST_TYPE, RESPOND_TYPE, RedeemPayload, RedeemResponse, RequestPayload,
    RequestResponse, RespondPayload, RespondResponse, Step1, Step2,
};
use crate::util;

/// Exactly what [`dispatch`] routes. `identify` and `grant` are not here: they
/// are only ever carried inside `prove` and `respond`, and one sent by itself
/// is refused as an unsupported type.
pub const URIS: &[&str] = &[
    REQUEST_TYPE,
    CLAIM_TYPE,
    PROVE_TYPE,
    RESPOND_TYPE,
    REDEEM_TYPE,
    CANCEL_TYPE,
];

/// The `amr` a redeemed sign-in reports: a DID, out of band, with user
/// verification.
pub const AMR: &[&str] = &["did", "oob", "uv"];

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
/// alone; `auth/oob:keyUnsupported`). `None` lets the document through, and
/// is the answer for any type not in [`URIS`]. The proof and recipient
/// requirements are the specifications' own, enforced by the spine from the
/// spec policy like any other published task.
pub fn precheck(doc: &TrustTask<Value>, type_uri: &str) -> Option<TrustTaskOutcome> {
    if !URIS.contains(&type_uri) {
        return None;
    }
    let task = task_of(type_uri);
    if !doc.issuer.as_deref().is_some_and(util::is_ed25519_did_key) {
        return Some(reject_with_code(
            doc,
            code(task, "keyUnsupported"),
            "the issuer must be an Ed25519 did:key generated for this exchange",
            None,
        ));
    }
    None
}

/// Handle one `auth/oob` document the spine has verified. `signer` is the
/// proven issuer ([`precheck`] required one). `None` for a type not in
/// [`URIS`].
pub async fn dispatch<H: OobHost>(
    host: &H,
    doc: TrustTask<Value>,
    type_uri: &str,
    signer: String,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        REQUEST_TYPE => handle_request(host, doc, signer).await,
        CLAIM_TYPE => handle_claim(host, doc, signer).await,
        PROVE_TYPE => handle_prove(host, doc, signer).await,
        RESPOND_TYPE => handle_respond(host, doc, signer).await,
        REDEEM_TYPE => handle_redeem(host, doc, signer).await,
        CANCEL_TYPE => handle_cancel(host, doc, signer).await,
        _ => return None,
    })
}

// ── Shared ──────────────────────────────────────────────────────────────────

async fn audit<H: OobHost>(
    host: &H,
    actor: &str,
    stage: &str,
    rec: &OobRequest<H::Audience>,
    member: Option<&str>,
    reason: Option<&str>,
    grant: Option<Value>,
) {
    host.audit(SignInEvent {
        actor,
        stage,
        record: rec,
        member,
        reason,
        grant,
    })
    .await;
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

/// Build a generated `auth/oob` type from the JSON this module assembles. The
/// generated types are `#[non_exhaustive]` and validate their members' patterns,
/// so going through JSON is how a value is constructed and checked against the
/// specification at once. A failure is this service's own bug, never the
/// caller's, so it is an internal error.
fn wire<T: serde::de::DeserializeOwned>(
    doc: &TrustTask<Value>,
    what: &str,
    value: Value,
) -> Result<T, TrustTaskOutcome> {
    serde_json::from_value(value).map_err(|e| {
        reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{what} does not match its specification: {e}"),
            },
        )
    })
}

/// Sign a success payload as this service's attestation (`assertionMethod`),
/// and return the signed document with the outcome carrying it.
async fn attested<H: OobHost, R: Serialize>(
    host: &H,
    doc: &TrustTask<Value>,
    payload: R,
) -> Result<(Value, TrustTaskOutcome), TrustTaskOutcome> {
    let internal = |reason: String| reject_with(doc, RejectReason::InternalError { reason });
    let unsigned = success_response(doc, payload);
    let mut value: Value =
        serde_json::from_slice(&unsigned.body).map_err(|e| internal(e.to_string()))?;
    host.sign_step(&mut value).await.map_err(internal)?;
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

/// The one refusal for an identity the service does not accept, a bad
/// signature, a stale or replayed carried document, or a mismatched lock
/// (T15): which of them failed is not the caller's to learn.
fn not_authorized(doc: &TrustTask<Value>, task: &str) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        code(task, "notAuthorized"),
        "this sign-in was not authorised",
        None,
    )
}

/// The refusal for an identity that has proved it holds its DID but may not
/// sign in for this audience, saying why: the family's generic
/// `notAuthorized` code, with `details.reason`.
fn refused_telling(
    doc: &TrustTask<Value>,
    task: &str,
    told: &str,
    message: &str,
) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        code(task, "notAuthorized"),
        message,
        Some(json!({ "reason": told })),
    )
}

/// End a request as declined after a failed step from the lock holder — one
/// attempt per request (base design §7.2). Only from `from`; a request some
/// other caller already moved on is left alone.
async fn decline<H: OobHost>(
    host: &H,
    rec: &OobRequest<H::Audience>,
    from: OobState,
    member: Option<&str>,
    reason: &str,
) {
    decline_telling(host, rec, from, member, reason, None).await;
}

/// [`decline`], recording a reason `redeem` passes on to the starter
/// (`details.reason`). Only for a reason the identity that signed has
/// already proved it holds, never one that would tell a bystander anything
/// about someone else's DID (T15).
async fn decline_telling<H: OobHost>(
    host: &H,
    rec: &OobRequest<H::Audience>,
    from: OobState,
    member: Option<&str>,
    reason: &str,
    starter_reason: Option<&str>,
) {
    let now = now_epoch();
    let lock = rec.approver_key.clone();
    let res = record::transition::<H::Audience, _, _>(host.records(), &rec.request_id, |r| {
        if r.state != from || r.approver_key != lock {
            return Err(());
        }
        r.decline_reason = starter_reason.map(str::to_string);
        r.end(OobState::Declined, now);
        Ok(())
    })
    .await;
    if let Ok((_, ended)) = res {
        // The operator's half of the story: the wire answer stays the
        // deliberately vague `notAuthorized` (T15), and until this line the
        // reason reached only the audit log, so a refused sign-in could not be
        // diagnosed from the service log at all. The request id and the stage
        // are enough to find the audit row; no DID is logged here, as no other
        // line in this module logs one.
        tracing::info!(
            request_id = %rec.request_id,
            stage = from.as_str(),
            audience = ?rec.audience,
            reason,
            "wallet sign-in declined"
        );
        let actor = lock.as_deref().unwrap_or("unknown");
        audit(
            host,
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

/// A carried, approver-signed document, checked as the spine checks an outer
/// one: its type, its recipient, its age, its `id` not seen before, and a
/// proof by its own issuer made for `purpose`. Returns the parsed document.
///
/// The caller has already put the issuer string through [`Gate::Known`] —
/// before this resolves anything (T15).
async fn verify_carried<H: OobHost>(
    host: &H,
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
    let Some(service_did) = host.service_did().await else {
        return Err("community DID not configured");
    };
    if inner.recipient.as_deref() != Some(service_did.as_str()) {
        return Err("carried document not addressed to this community");
    }
    let policy = host.freshness_policy();
    inner
        .validate_freshness(now, &policy)
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
            host.verify_assertion(received, expected_type).await
        }
        _ => host.verify_authentication(received).await,
    }
    .map_err(|_| "carried document proof does not verify")?;
    if signer != issuer {
        return Err("carried document signed by another DID");
    }
    // Replay of the carried document's own `id` (T7), in the same record the
    // spine keeps for outer documents.
    match host
        .accepted_ids()
        .claim(
            &inner,
            vti_trust_task_server::retain_until(&policy, &inner, now),
            now,
        )
        .await
    {
        Ok(vti_trust_task_server::Acceptance::Fresh(claim)) => {
            claim.completed(None).await;
            Ok(inner)
        }
        _ => Err("carried document replayed"),
    }
}

// ── request ─────────────────────────────────────────────────────────────────

async fn handle_request<H: OobHost>(
    host: &H,
    doc: TrustTask<Value>,
    start_key: String,
) -> TrustTaskOutcome {
    let messages = host.messages();
    let Some(http) = HttpContext::current() else {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            messages.request_https_only,
            None,
        );
    };
    // A purpose or mode this service does not serve has its own code (auth/oob/
    // request 0.2), so it is read before the generated payload, whose enums
    // would refuse it as malformed.
    let raw = |k: &str| {
        doc.payload
            .get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    if let Some(purpose) = raw("purpose").filter(|p| p != "login") {
        return reject_with_code(
            &doc,
            code("request", "purposeUnsupported"),
            format!("purpose `{purpose}` is not served; v1 serves `login`"),
            None,
        );
    }
    if let Some(mode) = raw("mode").filter(|m| m != "scan") {
        return reject_with_code(
            &doc,
            code("request", "modeUnsupported"),
            format!("mode `{mode}` is not served; v1 serves `scan`"),
            None,
        );
    }
    let payload: RequestPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // Which audience the page asks for (`ext["org.openvtc.session"]`); none
    // is the host's default.
    let audience = match H::Audience::from_ext(doc.payload.get("ext")) {
        Ok(a) => a,
        Err(message) => {
            return reject_with_code(
                &doc,
                TrustTaskCode::Standard(StandardCode::MalformedRequest),
                message,
                None,
            );
        }
    };
    let public_url = host.public_url().await;
    if host.service_did().await.is_none() {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::Unavailable),
            messages.not_set_up,
            None,
        );
    }
    // T19: only the service's own page may open a request, so another website
    // cannot start one through the user's browser. The origin is what the
    // wallet checks against the `SignInPortal` service.
    let origin = match (
        util::portal_origin(public_url.as_deref(), &http),
        http.origin.as_deref(),
    ) {
        (Some(portal), Some(sent)) if portal == sent => portal,
        _ => {
            return reject_with_code(
                &doc,
                TrustTaskCode::Standard(StandardCode::PermissionDenied),
                messages.request_wrong_origin,
                None,
            );
        }
    };
    let ks = host.records();
    let address = http.client_ip.to_string();
    match record::open_requests_from::<H::Audience>(ks, &address).await {
        Ok(n) if n >= MAX_PENDING_PER_ADDRESS => {
            return reject_with_code(
                &doc,
                code("request", "rateLimited"),
                "too many sign-in codes are open from this network; use one or wait for it to expire",
                None,
            );
        }
        Ok(_) => {}
        Err(e) => return host.reject_app_error(&doc, &e),
    }

    let now = now_epoch();
    let (browser, os) = util::browser_and_os(http.user_agent.as_deref());
    let rec = OobRequest {
        request_id: util::new_request_id(),
        state: OobState::Pending,
        start_key: start_key.clone(),
        start_network: Some(address),
        approver_key: None,
        purpose: payload.purpose.to_string(),
        mode: payload.mode.to_string(),
        origin,
        match_number: None,
        match_number_delivered: false,
        requester: RequesterDetails {
            // From a local database only (base design §12.6); `"unknown"` the
            // wallet shows as a warning, not as neutral.
            location: host
                .locate(http.client_ip)
                .unwrap_or_else(|| "unknown".into()),
            browser,
            os,
            created_at: util::rfc3339(now),
        },
        identified_did: None,
        step2_digest: None,
        step1: None,
        created_at: now,
        claim_deadline: now + CLAIM_WINDOW_SECS,
        decision_deadline: None,
        grant: None,
        ended_at: None,
        audience,
        decline_reason: None,
        signing_scope: None,
    };
    if let Err(e) = record::create(ks, &rec).await {
        return host.reject_app_error(&doc, &e);
    }
    audit(host, &start_key, "requested", &rec, None, None, None).await;
    let response: RequestResponse = match wire(&doc, "the request response", {
        let mut r = serde_json::json!({ "requestId": rec.request_id, "claimClosesAt": util::rfc3339(rec.claim_deadline) });
        // Echoed for a non-default audience, so the page knows this service
        // read the extension: one that predates it carries `ext` through
        // unread and would open a default sign-in instead.
        if let Some(ext) = audience.to_ext() {
            r["ext"] = ext;
        }
        r
    }) {
        Ok(r) => r,
        Err(e) => return e,
    };
    success_response(&doc, response)
}

// ── claim ───────────────────────────────────────────────────────────────────

async fn handle_claim<H: OobHost>(
    host: &H,
    doc: TrustTask<Value>,
    approver: String,
) -> TrustTaskOutcome {
    let payload: ClaimPayload = match parse_payload(&doc) {
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
    let ks = host.records();
    let rec: OobRequest<H::Audience> = match record::load(ks, &payload.request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(&doc, "claim"),
        Err(e) => return host.reject_app_error(&doc, &e),
    };
    let now = now_epoch();
    match rec.effective_state(now) {
        OobState::Pending => {}
        OobState::Expired => {
            if let Ok(true) = record::settle_expiry::<H::Audience>(ks, &rec.request_id).await {
                audit(host, &approver, "expired", &rec, None, None, None).await;
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

    let service_did = host.service_did().await.unwrap_or_default();
    let decision_deadline = now + DECISION_WINDOW_SECS;
    // The schema requires a name: the host's, else the DID itself.
    let service_name: String = host
        .service_name()
        .await
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| service_did.chars().take(128).collect());
    let step1_json = serde_json::json!({
        "requestId": rec.request_id,
        "service": { "did": service_did, "name": service_name },
        "origin": rec.origin,
        "purpose": rec.purpose,
        "decisionClosesAt": util::rfc3339(decision_deadline),
    });
    // The audience, signed: the wallet can show it, and step 2 repeats it so
    // the grant's `contextDigest` binds it. None for the default audience,
    // whose step 1 carries no extension.
    let mut step1_json = step1_json;
    if let Some(ext) = rec.audience.to_ext() {
        step1_json["ext"] = ext;
    }
    let step1: Step1 = match wire(&doc, "step 1", step1_json.clone()) {
        Ok(s) => s,
        Err(e) => return e,
    };
    // Signed before the lock is taken, so a request is never claimed with no
    // response to show for it.
    let (_, outcome) = match attested(host, &doc, &step1).await {
        Ok(signed) => signed,
        Err(e) => return e,
    };
    let number = util::new_match_number();
    let res = record::transition::<H::Audience, _, _>(ks, &rec.request_id, |r| {
        if r.effective_state(now_epoch()) != OobState::Pending {
            return Err(());
        }
        r.state = OobState::Claimed;
        r.approver_key = Some(approver.clone());
        r.match_number = Some(number.clone());
        r.decision_deadline = Some(decision_deadline);
        r.step1 = Some(step1_json.clone());
        Ok(())
    })
    .await;
    match res {
        Ok((_, claimed)) => {
            audit(host, &approver, "claimed", &claimed, None, None, None).await;
            outcome
        }
        Err(TransitionError::Store(e)) => host.reject_app_error(&doc, &e),
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

async fn handle_prove<H: OobHost>(
    host: &H,
    doc: TrustTask<Value>,
    approver: String,
) -> TrustTaskOutcome {
    let identify = match parse_payload::<ProvePayload>(&doc) {
        Ok(p) => Value::Object(p.identify),
        Err(e) => return e,
    };
    let Some(request_id) = request_id_hint(&doc, &identify) else {
        return not_found(&doc, "prove");
    };
    let ks = host.records();
    let rec: OobRequest<H::Audience> = match record::load(ks, &request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(&doc, "prove"),
        Err(e) => return host.reject_app_error(&doc, &e),
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
            if let Ok(true) = record::settle_expiry::<H::Audience>(ks, &rec.request_id).await {
                audit(host, &approver, "expired", &rec, None, None, None).await;
            }
            return expired(&doc, "prove");
        }
        // One proof attempt per request.
        _ => return not_authorized(&doc, "prove"),
    }

    // From here every failure declines the request (base design §7.4).
    let fail = |member: Option<String>, reason: String| {
        let rec = rec.clone();
        async move {
            decline(host, &rec, OobState::Claimed, member.as_deref(), &reason).await;
        }
    };

    // 2. The carried identify names this request and this lock.
    let identify_issuer = identify
        .get("issuer")
        .and_then(Value::as_str)
        .map(str::to_string);
    let identify_payload: Option<IdentifyPayload> = identify
        .get("payload")
        .cloned()
        .and_then(|p| serde_json::from_value(p).ok());
    let (Some(member), Some(identify_payload)) = (identify_issuer, identify_payload) else {
        fail(None, "identify is malformed".into()).await;
        return not_authorized(&doc, "prove");
    };
    if identify_payload.request_id.as_str() != rec.request_id
        || identify_payload.approver_key.as_str() != approver
    {
        fail(
            Some(member),
            "identify names another request or lock".into(),
        )
        .await;
        return not_authorized(&doc, "prove");
    }

    // 3. The issuer string is someone this service knows for the audience —
    //    read from its local records, before any DID is resolved (T15). A DID
    //    the service does not know at all is refused here, unresolved.
    match host.gate(Gate::Known, rec.audience, &member).await {
        Ok(Eligibility::Eligible) => {}
        Ok(Eligibility::Refused { reason } | Eligibility::RefusedTelling { reason, .. }) => {
            fail(Some(member), reason).await;
            return not_authorized(&doc, "prove");
        }
        Err(e) => return host.reject_app_error(&doc, &e),
    }

    // 4. The proof verifies against the approver's `authentication` key
    //    (contract C5); recipient, freshness and replay as for any document.
    if let Err(reason) = verify_carried(
        host,
        &identify,
        IDENTIFY_TYPE,
        &member,
        vti_common::auth::ProofPurpose::Authentication,
    )
    .await
    {
        tracing::info!(reason, "auth/oob/prove: identify refused");
        fail(Some(member), reason.into()).await;
        return not_authorized(&doc, "prove");
    }

    // 5. The number the approver typed.
    if Some(identify_payload.entered_number.as_str()) != rec.match_number.as_deref() {
        fail(Some(member), "wrong number".into()).await;
        return reject_with_code(
            &doc,
            code("prove", "numberMismatch"),
            "that is not the number on the screen; refresh the code on the website and scan again",
            None,
        );
    }

    // 5a. The audience's own gate, now the DID has proved it is theirs, so
    //     saying why is no oracle about anyone else (T15), and the browser
    //     that started it is told too (`redeem`'s `details.reason`).
    match host.gate(Gate::Proved, rec.audience, &member).await {
        Ok(Eligibility::Eligible) => {}
        Ok(Eligibility::Refused { reason }) => {
            fail(Some(member), reason).await;
            return not_authorized(&doc, "prove");
        }
        Ok(Eligibility::RefusedTelling {
            reason,
            told,
            message,
        }) => {
            decline_telling(
                host,
                &rec,
                OobState::Claimed,
                Some(&member),
                &reason,
                Some(&told),
            )
            .await;
            return refused_telling(&doc, "prove", &told, &message);
        }
        Err(e) => return host.reject_app_error(&doc, &e),
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
    // Step 1 as stored, `ext` included: the audience is inside what the
    // grant's `contextDigest` covers.
    let Value::Object(mut step2_json) = step1 else {
        return reject_with(
            &doc,
            RejectReason::InternalError {
                reason: "stored step 1 is not an object".into(),
            },
        );
    };
    step2_json.insert("sessionKey".into(), Value::String(rec.start_key.clone()));
    step2_json.insert(
        "requester".into(),
        serde_json::json!({
            "location": rec.requester.location,
            "browser": rec.requester.browser,
            "os": rec.requester.os,
            "createdAt": rec.requester.created_at,
            "sameNetwork": util::same_network(rec.start_network.as_deref(), approver_ip),
        }),
    );
    step2_json.insert("identifiedAs".into(), Value::String(member.clone()));
    // The audience's signing scope, if it offers one.
    let offered: Option<Vec<String>> = host.signing_scope(rec.audience);
    if let Some(scope) = &offered {
        step2_json.insert("signingScope".into(), serde_json::json!(scope));
    }
    let attested_step2 = match wire::<Step2>(&doc, "step 2", Value::Object(step2_json)) {
        Ok(s) => attested(host, &doc, &s).await,
        Err(e) => return e,
    };
    let (signed, outcome) = match attested_step2 {
        Ok(s) => s,
        Err(e) => return e,
    };
    let digest = match util::context_digest(&signed) {
        Ok(d) => d,
        Err(e) => return host.reject_app_error(&doc, &e),
    };
    let res = record::transition::<H::Audience, _, _>(ks, &rec.request_id, |r| {
        if r.effective_state(now_epoch()) != OobState::Claimed
            || r.approver_key.as_deref() != Some(approver.as_str())
        {
            return Err(());
        }
        r.state = OobState::Identified;
        r.identified_did = Some(member.clone());
        r.step2_digest = Some(digest.clone());
        r.signing_scope = offered.clone();
        Ok(())
    })
    .await;
    match res {
        Ok((_, identified)) => {
            audit(
                host,
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
        Err(TransitionError::Store(e)) => host.reject_app_error(&doc, &e),
        Err(_) => expired(&doc, "prove"),
    }
}

// ── respond ─────────────────────────────────────────────────────────────────

async fn handle_respond<H: OobHost>(
    host: &H,
    doc: TrustTask<Value>,
    approver: String,
) -> TrustTaskOutcome {
    let grant_doc = match parse_payload::<RespondPayload>(&doc) {
        Ok(p) => Value::Object(p.grant),
        Err(e) => return e,
    };
    let grant_type = GRANT_TYPE;
    let Some(request_id) = request_id_hint(&doc, &grant_doc) else {
        return not_found(&doc, "respond");
    };
    let ks = host.records();
    let rec: OobRequest<H::Audience> = match record::load(ks, &request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(&doc, "respond"),
        Err(e) => return host.reject_app_error(&doc, &e),
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
            if let Ok(true) = record::settle_expiry::<H::Audience>(ks, &rec.request_id).await {
                audit(host, &approver, "expired", &rec, None, None, None).await;
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
    let fail = |reason: String| {
        let rec = rec.clone();
        let member = member.clone();
        async move {
            decline(host, &rec, OobState::Identified, Some(&member), &reason).await;
        }
    };

    // 2. The grant is the identified DID's, signed for `assertionMethod`,
    //    fresh, and new.
    if grant_doc.get("issuer").and_then(Value::as_str) != Some(member.as_str()) {
        fail("grant from another identity".into()).await;
        return not_authorized(&doc, "respond");
    }
    if let Err(reason) = verify_carried(
        host,
        &grant_doc,
        grant_type,
        &member,
        vti_common::auth::ProofPurpose::AssertionMethod,
    )
    .await
    {
        tracing::info!(reason, "auth/oob/respond: grant refused");
        fail(reason.into()).await;
        return not_authorized(&doc, "respond");
    }
    let Some(grant) = GrantView::read(&grant_doc) else {
        fail("grant payload is malformed".into()).await;
        return not_authorized(&doc, "respond");
    };

    // 3–4. The lock, the browser key, the origin and the context it was shown.
    // Item 3: the grant's `signingScope` is step 2's, both absent or the same
    // families in the same order.
    let context_ok = grant.request_id == rec.request_id
        && grant.approver_key == approver
        && grant.session_key == rec.start_key
        && grant.origin == rec.origin
        && rec
            .step2_digest
            .as_deref()
            .is_some_and(|d| util::same_digest(d, &grant.context_digest))
        && grant.signing_scope == rec.signing_scope;
    if !context_ok {
        fail("grant context mismatch".into()).await;
        return reject_with_code(
            &doc,
            code("respond", "contextMismatch"),
            "the grant does not match this sign-in request",
            None,
        );
    }
    let decision = if grant.approve {
        OobState::Approved
    } else {
        OobState::Declined
    };
    if decision == OobState::Approved {
        let not_after = grant.not_after;
        if not_after <= now_epoch() {
            fail("grant sessionEndsAt has passed".into()).await;
            return not_authorized(&doc, "respond");
        }
        // 5. Still eligible for the audience, now.
        match host.gate(Gate::Decided, rec.audience, &member).await {
            Ok(Eligibility::Eligible) => {}
            Ok(Eligibility::Refused { reason }) => {
                fail(reason).await;
                return not_authorized(&doc, "respond");
            }
            Ok(Eligibility::RefusedTelling {
                reason,
                told,
                message,
            }) => {
                decline_telling(
                    host,
                    &rec,
                    OobState::Identified,
                    Some(&member),
                    &reason,
                    Some(&told),
                )
                .await;
                return refused_telling(&doc, "respond", &told, &message);
            }
            Err(e) => return host.reject_app_error(&doc, &e),
        }
    }

    // 6. Decide, once.
    let signed_grant = grant_doc.clone();
    let now = now_epoch();
    let res = record::transition::<H::Audience, _, _>(ks, &rec.request_id, |r| {
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
                host,
                &member,
                stage,
                &decided,
                Some(&member),
                None,
                Some(signed_grant),
            )
            .await;
            // Signed like steps 1 and 2: every reply to the wallet is this
            // service's attestation, and the wallet refuses one that is not.
            let body = serde_json::json!({ "status": stage });
            let answered = match wire::<RespondResponse>(&doc, "the respond response", body) {
                Ok(r) => attested(host, &doc, &r).await,
                Err(e) => return e,
            };
            match answered {
                Ok((_, outcome)) => outcome,
                Err(e) => e,
            }
        }
        Err(TransitionError::Store(e)) => host.reject_app_error(&doc, &e),
        Err(_) => reject_with_code(
            &doc,
            code("respond", "alreadyDecided"),
            "this sign-in request has already been decided",
            None,
        ),
    }
}

/// What a grant says, read from its `auth/oob/grant/0.3` generated payload.
struct GrantView {
    request_id: String,
    approver_key: String,
    session_key: String,
    origin: String,
    context_digest: String,
    approve: bool,
    /// `sessionEndsAt`, as epoch seconds.
    not_after: u64,
    /// The families `K_b` may sign for as the approver.
    signing_scope: Option<Vec<String>>,
}

impl GrantView {
    /// `None` for a payload the schema does not admit, or an unknown decision.
    fn read(grant_doc: &Value) -> Option<Self> {
        let payload = grant_doc.get("payload")?.clone();
        let g: GrantPayload = serde_json::from_value(payload).ok()?;
        let approve = match g.decision {
            GrantDecision::Approve => true,
            GrantDecision::Decline => false,
            #[allow(unreachable_patterns)]
            _ => return None,
        };
        Some(Self {
            request_id: g.request_id.to_string(),
            approver_key: g.approver_key.to_string(),
            session_key: g.session_key.to_string(),
            origin: g.origin.to_string(),
            context_digest: g.context_digest.to_string(),
            approve,
            not_after: u64::try_from(g.session_ends_at.timestamp()).unwrap_or(0),
            signing_scope: g
                .signing_scope
                .map(|s| s.iter().map(|f| f.to_string()).collect()),
        })
    }
}

// ── cancel ──────────────────────────────────────────────────────────────────

async fn handle_cancel<H: OobHost>(
    host: &H,
    doc: TrustTask<Value>,
    signer: String,
) -> TrustTaskOutcome {
    let payload: CancelPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ks = host.records();
    let now = now_epoch();
    let res = record::transition::<H::Audience, _, _>(ks, &payload.request_id, |r| {
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
                host,
                &signer,
                "cancelled",
                &rec,
                rec.identified_did.as_deref(),
                None,
                None,
            )
            .await;
            // Signed like steps 1 and 2: every reply to the wallet is this
            // service's attestation, and the wallet refuses one that is not.
            let r: CancelResponse = match wire(
                &doc,
                "the cancel response",
                serde_json::json!({ "status": "cancelled" }),
            ) {
                Ok(r) => r,
                Err(e) => return e,
            };
            match attested(host, &doc, &r).await {
                Ok((_, outcome)) => outcome,
                Err(e) => e,
            }
        }
        Ok((_, rec)) => {
            audit(host, &signer, "expired", &rec, None, None, None).await;
            expired(&doc, "cancel")
        }
        Err(TransitionError::NotFound) => not_found(&doc, "cancel"),
        Err(TransitionError::Store(e)) => host.reject_app_error(&doc, &e),
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

fn pending<A: Audience>(doc: &TrustTask<Value>, rec: &OobRequest<A>, now: u64) -> TrustTaskOutcome {
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

/// `redeem`'s `declined`, with `details.reason` when the starter is told why
/// ([`Eligibility::RefusedTelling`], [`Completion::Declined`]).
fn declined<H: OobHost>(
    host: &H,
    doc: &TrustTask<Value>,
    reason: Option<&str>,
) -> TrustTaskOutcome {
    let mut details = json!({ "state": "declined" });
    let message = match reason {
        Some(r) => {
            details["reason"] = Value::String(r.to_string());
            host.told_message(r)
                .unwrap_or_else(|| "the sign-in was declined".into())
        }
        None => "the sign-in was declined".into(),
    };
    reject_with_code(doc, code("redeem", "declined"), message, Some(details))
}

async fn handle_redeem<H: OobHost>(
    host: &H,
    doc: TrustTask<Value>,
    starter: String,
) -> TrustTaskOutcome {
    let Some(http) = HttpContext::current() else {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            host.messages().redeem_https_only,
            None,
        );
    };
    let payload: RedeemPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ks = host.records();
    let rec: OobRequest<H::Audience> = match record::load(ks, &payload.request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(&doc, "redeem"),
        Err(e) => return host.reject_app_error(&doc, &e),
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
    let deadline = tokio::time::Instant::now() + record::redeem_hold();
    let entry_state = rec.effective_state(now_epoch());

    loop {
        let notify = NOTIFIER.handle(&rec.request_id);
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let current: OobRequest<H::Audience> = match record::load(ks, &rec.request_id).await {
            Ok(Some(r)) => r,
            Ok(None) => return not_found(&doc, "redeem"),
            Err(e) => return host.reject_app_error(&doc, &e),
        };
        let now = now_epoch();
        match current.effective_state(now) {
            OobState::Approved => return redeem_approved(host, &doc, &http, &current).await,
            OobState::Consumed => {
                return reject_with_code(
                    &doc,
                    code("redeem", "alreadyDecided"),
                    "this sign-in has already been used",
                    None,
                );
            }
            OobState::Declined => {
                return declined(host, &doc, current.decline_reason.as_deref());
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
                if let Ok(true) =
                    record::settle_expiry::<H::Audience>(ks, &current.request_id).await
                {
                    audit(host, &starter, "expired", &current, None, None, None).await;
                }
                return expired(&doc, "redeem");
            }
            s @ (OobState::Pending | OobState::Claimed | OobState::Identified) => {
                let number_owed = s == OobState::Claimed && !current.match_number_delivered;
                if s != entry_state || number_owed || _poll.is_none() {
                    if current.match_number.is_some() && !current.match_number_delivered {
                        let _ =
                            record::transition::<H::Audience, _, _>(ks, &current.request_id, |r| {
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
            let current: OobRequest<H::Audience> = match record::load(ks, &rec.request_id).await {
                Ok(Some(r)) => r,
                _ => return not_found(&doc, "redeem"),
            };
            return pending(&doc, &current, now_epoch());
        }
    }
}

/// `approved → consumed` once, then what the host issues for the audience
/// the approver approved: subject the DID that signed the grant, key `K_b`,
/// `amr = ["did", "oob", "uv"]`, ending no later than the grant's
/// `sessionEndsAt` ([`OobHost::complete`]).
///
/// Never another audience's result (T19).
async fn redeem_approved<H: OobHost>(
    host: &H,
    doc: &TrustTask<Value>,
    http: &HttpContext,
    rec: &OobRequest<H::Audience>,
) -> TrustTaskOutcome {
    let ks = host.records();
    let now = now_epoch();
    let res = record::transition::<H::Audience, _, _>(ks, &rec.request_id, |r| {
        if r.effective_state(now) != OobState::Approved {
            return Err(());
        }
        r.end(OobState::Consumed, now);
        Ok(())
    })
    .await;
    let consumed = match res {
        Ok((_, r)) => r,
        Err(TransitionError::Store(e)) => return host.reject_app_error(doc, &e),
        Err(_) => {
            return reject_with_code(
                doc,
                code("redeem", "alreadyDecided"),
                "this sign-in has already been used",
                None,
            );
        }
    };
    let Some(subject) = consumed.identified_did.clone() else {
        return not_authorized(doc, "redeem");
    };
    // What is issued is what the approver approved: the audience on the
    // record must be the one signed into step 1, which step 2 repeats and the
    // grant's `contextDigest` covers. They are written once and never apart,
    // so a difference means the record was altered; issue nothing.
    if consumed.signed_audience() != Some(consumed.audience) {
        tracing::error!(
            request_id = %consumed.request_id,
            security_alert = true,
            "auth/oob/redeem: the stored audience differs from the one the member approved"
        );
        audit(
            host,
            &subject,
            "proofFailed",
            &consumed,
            Some(&subject),
            Some("audience differs from the approved one"),
            None,
        )
        .await;
        return not_authorized(doc, "redeem");
    }
    let not_after = consumed
        .grant
        .as_ref()
        .and_then(|g| g.get("payload"))
        .and_then(|p| p.get("sessionEndsAt"))
        .and_then(util::epoch_of)
        .unwrap_or(now);
    if not_after <= now {
        return not_authorized(doc, "redeem");
    }
    let completion = host
        .complete(Approved {
            doc,
            http,
            record: &consumed,
            subject: &subject,
            not_after,
        })
        .await;
    match completion {
        Ok(Completion::Issued {
            display_name,
            ends_at,
        }) => {
            audit(
                host,
                &subject,
                "redeemed",
                &consumed,
                Some(&subject),
                None,
                None,
            )
            .await;
            let mut body = serde_json::json!({
                "subject": subject,
                "displayName": display_name,
                "sessionEndsAt": util::rfc3339(ends_at),
                "amr": AMR,
            });
            // Says which audience this is, so the page can refuse to carry on
            // if it ever got anything else. None for the default.
            if let Some(ext) = consumed.audience.to_ext() {
                body["ext"] = ext;
            }
            match wire::<RedeemResponse>(doc, "the redeem response", body) {
                Ok(r) => success_response(doc, r),
                Err(e) => e,
            }
        }
        Ok(Completion::NotAuthorized) => not_authorized(doc, "redeem"),
        Ok(Completion::Declined { told }) => declined(host, doc, Some(&told)),
        Err(e) => host.reject_app_error(doc, &e),
    }
}
