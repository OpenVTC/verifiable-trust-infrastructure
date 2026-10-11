//! `vtc/join-requests/wallet-session/{start,status}/0.1` — an applicant opens
//! an OpenID4VP presentation session for a join criterion, and reads its
//! outcome (#1988).
//!
//! The authority both tasks assume is being the applicant: the proof signer,
//! proven by [`super::resolve_holder`] on every transport. `start` binds the
//! session to that signer; `status` answers only that signer, and an unknown
//! session and somebody else's are the same `notFound` — the session id
//! travels in a QR code, so holding it proves nothing. The work is
//! [`crate::oid4vp::wallet`]; this module maps the wire to it.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::vtc::join_requests::wallet_session::{
    start::v0_1 as start, status::v0_1 as status,
};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, parse_payload, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, resolve_holder};
use crate::oid4vp::session::{self, RefusalReason, SessionPhase};
use crate::oid4vp::wallet::{self, StartRefusal};
use crate::server::AppState;

/// `wallet-session/start/0.1`.
pub(super) async fn handle_start(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let applicant_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: start::Payload = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let prefix = body.client_id_prefix.map(|p| p.to_string());
    let started = wallet::start(
        state,
        &applicant_did,
        body.criterion.as_str(),
        body.request_id.as_deref().map(String::as_str),
        prefix.as_deref(),
        chrono::Utc::now(),
    )
    .await;
    let started = match started {
        Ok(s) => s,
        Err(refusal) => return start_refusal(&doc, refusal),
    };

    let dcql_query = match started.session.dcql_query {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    let response: start::Response = match start::Response::builder()
        .session_id(started.session.id.clone())
        .wallet_uri(started.wallet_uri)
        .client_id(started.session.client_id.clone())
        .dcql_query(dcql_query)
        .expires_at(started.session.expires_at)
        .try_into()
    {
        Ok(r) => r,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                &vti_common::error::AppError::Internal(format!(
                    "wallet-session/start response failed its own schema: {e}"
                )),
            );
        }
    };
    success_response::<_, start::Response>(&doc, response)
}

fn start_refusal(doc: &TrustTask<Value>, refusal: StartRefusal) -> TrustTaskOutcome {
    let (code, message) = match refusal {
        StartRefusal::CriterionNotFound => (
            start::error_codes::CRITERION_NOT_FOUND.code,
            "no criterion this community publishes, or still honours, has that \
             requirementsDigest; read vtc/join-requests/manifest/0.3 again"
                .to_string(),
        ),
        StartRefusal::NoWalletPresentation => (
            start::error_codes::NO_WALLET_PRESENTATION.code,
            "that criterion asks for no credential a wallet can present over OpenID4VP \
             (an SD-JWT VC)"
                .to_string(),
        ),
        StartRefusal::VerifierNotConfigured(what) => {
            (start::error_codes::VERIFIER_NOT_CONFIGURED.code, what)
        }
        StartRefusal::RequestNotFound => (
            start::error_codes::REQUEST_NOT_FOUND.code,
            "no join request of yours has that requestId".to_string(),
        ),
        StartRefusal::RequestClosed => (
            start::error_codes::REQUEST_CLOSED.code,
            "that join request has been decided or withdrawn and takes no more evidence"
                .to_string(),
        ),
        StartRefusal::TooManySessions => (
            start::error_codes::TOO_MANY_SESSIONS.code,
            "you already hold as many open wallet sessions as this community allows; \
             retry once one has been answered or has expired"
                .to_string(),
        ),
        StartRefusal::Other(e) => return app_error_to_reject(doc, &e),
    };
    reject_with_code(doc, extended_code(code), message, None)
}

/// `wallet-session/status/0.1`.
pub(super) async fn handle_status(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let applicant_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: status::Payload = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let not_found = |doc: &TrustTask<Value>| {
        reject_with_code(
            doc,
            extended_code(status::error_codes::NOT_FOUND.code),
            "no wallet session of yours has that sessionId",
            None,
        )
    };
    let found = match session::get(&state.oid4vp_sessions_ks, &body.session_id).await {
        Ok(found) => found,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Consumer rule 1: unknown and somebody else's are the same answer.
    let Some(s) = found.filter(|s| s.applicant_did == applicant_did) else {
        return not_found(&doc);
    };

    // A session past `expiresAt` reads as expired even before the sweeper has
    // closed it.
    let now = chrono::Utc::now();
    let phase = if s.phase.is_open() && now >= s.expires_at {
        SessionPhase::Expired
    } else {
        s.phase
    };
    let state_value = match phase {
        SessionPhase::AwaitingWallet => status::ResponseState::AwaitingWallet,
        // `verifying` is the gap between a wallet's answer and its outcome: the
        // wallet has the request, and the outcome is not yet known.
        SessionPhase::RequestRetrieved | SessionPhase::Verifying => {
            status::ResponseState::RequestRetrieved
        }
        SessionPhase::Presented => status::ResponseState::Presented,
        SessionPhase::Refused => status::ResponseState::Refused,
        SessionPhase::Expired => status::ResponseState::Expired,
    };

    let mut builder = status::Response::builder()
        .session_id(s.id.clone())
        .state(state_value)
        .expires_at(s.expires_at);
    if let Some(request_id) = s.request_id {
        builder = builder.request_id(Some(
            request_id
                .to_string()
                .try_into()
                .expect("a UUID is a valid requestId"),
        ));
    }
    // Consumer rules 3–4: evidence only when presented, and never a claim.
    if phase == SessionPhase::Presented
        && let Some(evidence) = &s.evidence
    {
        let credentials: Result<Vec<status::PresentedCredential>, _> = evidence
            .credentials
            .iter()
            .map(|c| {
                let vct = c
                    .vct
                    .clone()
                    .map(status::PresentedCredentialVct::try_from)
                    .transpose()?;
                status::PresentedCredential::builder()
                    .credential_query_id(c.credential_query_id.clone())
                    .format(c.format.clone())
                    .issuer(c.issuer.clone())
                    .vct(vct)
                    .try_into()
            })
            .collect();
        let evidence = credentials.and_then(|credentials| {
            status::Evidence::builder()
                .satisfied(evidence.satisfied)
                .holder(evidence.holder.clone())
                .credentials(credentials)
                .held_until(s.held_until)
                .try_into()
        });
        match evidence {
            Ok(e) => builder = builder.evidence(Some(e)),
            Err(e) => {
                return app_error_to_reject(
                    &doc,
                    &vti_common::error::AppError::Internal(format!(
                        "wallet-session/status evidence failed its own schema: {e}"
                    )),
                );
            }
        }
    }
    if phase == SessionPhase::Refused {
        builder = builder.reason(s.reason.map(|r| match r {
            RefusalReason::PresentationInvalid => status::ResponseReason::PresentationInvalid,
            RefusalReason::QueryNotSatisfied => status::ResponseReason::QueryNotSatisfied,
            RefusalReason::IssuerNotTrusted => status::ResponseReason::IssuerNotTrusted,
            RefusalReason::StatusNotValid => status::ResponseReason::StatusNotValid,
            RefusalReason::WalletDeclined => status::ResponseReason::WalletDeclined,
        }));
    }
    let response: status::Response = match builder.try_into() {
        Ok(r) => r,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                &vti_common::error::AppError::Internal(format!(
                    "wallet-session/status response failed its own schema: {e}"
                )),
            );
        }
    };
    success_response::<_, status::Response>(&doc, response)
}
