//! The Trust Tasks that carry hidden vetting's community half.
//!
//! [`super::pcs_issue`] mints, [`super::pcs_challenge`] issues and [`super::pcs_event`] decides
//! who may draw at an event's rate; this is how a vetter and an applicant reach them. Four
//! exchanges, each a published specification, generated (`trust-tasks-rs` 0.22+) rather than
//! hand-written — see [`trust_tasks_rs::specs::vtc::vetting`]:
//!
//! - `vtc/vetting/vetters/pcs-root/0.1` — a vetter enrols for a class label.
//! - `vtc/vetting/vetters/pcs-tokens/0.1` — a vetter draws its tick of the drip.
//! - `vtc/vetting/vetters/event-mode/0.1` — a vetter asks to vet at a named event.
//! - `vtc/vetting/pcs-challenge/0.1` — an applicant asks for the nonce its proof must bind.

use chrono::{Duration, Utc};
use serde_json::Value as JsonValue;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::vtc::vetting::pcs_challenge::v0_1 as pcs_challenge_spec;
use trust_tasks_rs::specs::vtc::vetting::vetters::event_mode::v0_1 as event_mode_spec;
use trust_tasks_rs::specs::vtc::vetting::vetters::pcs_root::v0_1 as pcs_root_spec;
use trust_tasks_rs::specs::vtc::vetting::vetters::pcs_tokens::v0_1 as pcs_tokens_spec;

use vti_vetting_pcs::issuer::{
    RootCredentialWire, RootRequestWire, TokenBatchRequestWire, TokenBatchWire, TokenRequestWire,
};

use super::{pcs_challenge, pcs_event, pcs_issue};
use crate::error::TaskError;
use crate::server::AppState;

/// `vtc/vetting/vetters/pcs-root/0.1` — a vetter asks for its class credential.
pub const PCS_ROOT_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/pcs-root/0.1";
/// `vtc/vetting/vetters/pcs-tokens/0.1` — a vetter draws its tick of the drip.
pub const PCS_TOKENS_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/pcs-tokens/0.1";
/// `vtc/vetting/vetters/event-mode/0.1` — a vetter asks to vet at a named event.
pub const EVENT_MODE_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/event-mode/0.1";
/// `vtc/vetting/pcs-challenge/0.1` — an applicant asks for a submission challenge.
pub const PCS_CHALLENGE_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/pcs-challenge/0.1";
/// `vtc/vetting/hidden/publish/0.1` — an admin turns on (or rotates) hidden-vetter admission for
/// a criterion. Was `POST /vetting/hidden`, served by `crate::trust_tasks::handle_hidden_publish`.
pub const HIDDEN_PUBLISH_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/hidden/publish/0.1";

// --- declared error codes --------------------------------------------------------------------
//
// Returned as `TaskError`, never `AppError`: an `AppError` renders as the framework's own
// vocabulary and the declared code is dropped on the way out.

/// `vtc/vetting/vetters/pcs-root:notAVetter`
pub const ROOT_ERR_NOT_A_VETTER: &str = "vtc/vetting/vetters/pcs-root:notAVetter";
/// `vtc/vetting/vetters/pcs-root:wrongLabel`
pub const ROOT_ERR_WRONG_LABEL: &str = "vtc/vetting/vetters/pcs-root:wrongLabel";
/// `vtc/vetting/vetters/pcs-root:alreadyEnrolled`
pub const ROOT_ERR_ALREADY_ENROLLED: &str = "vtc/vetting/vetters/pcs-root:alreadyEnrolled";
/// `vtc/vetting/vetters/pcs-root:identifierRebound`
pub const ROOT_ERR_IDENTIFIER_REBOUND: &str = "vtc/vetting/vetters/pcs-root:identifierRebound";
/// `vtc/vetting/vetters/pcs-root:badRequest`
pub const ROOT_ERR_BAD_REQUEST: &str = "vtc/vetting/vetters/pcs-root:badRequest";
/// `vtc/vetting/vetters/pcs-tokens:notAVetter`
pub const TOKENS_ERR_NOT_A_VETTER: &str = "vtc/vetting/vetters/pcs-tokens:notAVetter";
/// `vtc/vetting/vetters/pcs-tokens:labelNotLive`
pub const TOKENS_ERR_LABEL_NOT_LIVE: &str = "vtc/vetting/vetters/pcs-tokens:labelNotLive";
/// `vtc/vetting/vetters/pcs-tokens:alreadyServed`
pub const TOKENS_ERR_ALREADY_SERVED: &str = "vtc/vetting/vetters/pcs-tokens:alreadyServed";
/// `vtc/vetting/vetters/pcs-tokens:overQuota`
pub const TOKENS_ERR_OVER_QUOTA: &str = "vtc/vetting/vetters/pcs-tokens:overQuota";
/// `vtc/vetting/vetters/pcs-tokens:badOpeningProof`
pub const TOKENS_ERR_BAD_OPENING_PROOF: &str = "vtc/vetting/vetters/pcs-tokens:badOpeningProof";
/// `vtc/vetting/vetters/pcs-tokens:eventRefused`
pub const TOKENS_ERR_EVENT_REFUSED: &str = "vtc/vetting/vetters/pcs-tokens:eventRefused";
/// `vtc/vetting/vetters/event-mode:notAVetter`
pub const EVENT_ERR_NOT_A_VETTER: &str = "vtc/vetting/vetters/event-mode:notAVetter";
/// `vtc/vetting/vetters/event-mode:unknownEvent`
pub const EVENT_ERR_UNKNOWN_EVENT: &str = "vtc/vetting/vetters/event-mode:unknownEvent";
/// `vtc/vetting/vetters/event-mode:unknownTier`
pub const EVENT_ERR_UNKNOWN_TIER: &str = "vtc/vetting/vetters/event-mode:unknownTier";
/// `vtc/vetting/vetters/event-mode:badWindow`
pub const EVENT_ERR_BAD_WINDOW: &str = "vtc/vetting/vetters/event-mode:badWindow";
/// `vtc/vetting/hidden/publish:noSuchCriterion`, read from the generated bindings.
pub const HIDDEN_PUBLISH_ERR_NO_SUCH_CRITERION: &str =
    trust_tasks_rs::specs::vtc::vetting::hidden::publish::v0_1::error_codes::NO_SUCH_CRITERION.code;
/// `vtc/vetting/hidden/publish:noVetting`, read from the generated bindings.
pub const HIDDEN_PUBLISH_ERR_NO_VETTING: &str =
    trust_tasks_rs::specs::vtc::vetting::hidden::publish::v0_1::error_codes::NO_VETTING.code;
/// `vtc/vetting/vetters/event-mode:alreadyRequested`
pub const EVENT_ERR_ALREADY_REQUESTED: &str = "vtc/vetting/vetters/event-mode:alreadyRequested";
/// `vtc/vetting/vetters/event-mode:eventClosed`
pub const EVENT_ERR_EVENT_CLOSED: &str = "vtc/vetting/vetters/event-mode:eventClosed";
/// `vtc/vetting/pcs-challenge:notHiddenVetting`
pub const CHALLENGE_ERR_NOT_HIDDEN: &str = "vtc/vetting/pcs-challenge:notHiddenVetting";

// --- handlers --------------------------------------------------------------------------------

/// Where this community's hidden-vetting parameters come from at request time.
///
/// They hang off a stored criterion rather than the config, because a community may publish more
/// than one and each carries its own labels. The first criterion that declares them wins: a
/// deployment running two hidden criteria under different parameters is not a shape this branch
/// serves, and serving it silently under the wrong one is the failure worth avoiding.
async fn config_for(state: &AppState) -> Result<super::pcs::HiddenVettingConfig, TaskError> {
    let criteria = crate::schemas::accepts::list_accepts(&state.schemas_ks)
        .await
        .map_err(TaskError::from)?;
    for stored in criteria {
        if let Some(raw) = stored.hidden_vetting {
            return serde_json::from_value(raw).map_err(|e| {
                TaskError::from(vti_common::error::AppError::Internal(format!(
                    "stored hidden-vetting parameters: {e}"
                )))
            });
        }
    }
    Err(TaskError::declared(
        CHALLENGE_ERR_NOT_HIDDEN,
        vti_common::error::AppError::Validation(
            "this community publishes no criterion that accepts a hidden-vetting proof".into(),
        ),
    ))
}

/// Serve a vetter's enrolment request.
///
/// # Errors
///
/// The task's declared codes, each mapped from the store-backed check that produced it
/// ([`pcs_issue::enrol`]).
pub async fn handle_pcs_root(
    state: &AppState,
    member_did: &str,
    doc: &TrustTask<JsonValue>,
) -> Result<JsonValue, TaskError> {
    let payload: pcs_root_spec::Payload = parse(doc)?;
    let config = config_for(state).await?;
    let community = community_did(state).await;
    let request = RootRequestWire {
        label: payload.label.to_string(),
        id: payload.id.to_string(),
        // Opaque to `pcs_issue::enrol` beyond verifying it, so the generated, validated shape is
        // re-serialised rather than read apart — the library's own suite defines its members.
        request: serde_json::to_value(&payload.request).map_err(|e| {
            TaskError::from(vti_common::error::AppError::Validation(format!(
                "request: {e}"
            )))
        })?,
    };
    let answer: RootCredentialWire =
        pcs_issue::enrol(state, &community, &config, member_did, &request, Utc::now())
            .await
            .map_err(root_error)?;
    to_value(build::<_, pcs_root_spec::Response>(
        pcs_root_spec::Response::builder()
            .label(answer.label)
            .pre_credential(answer.pre_credential),
    )?)
}

/// Serve a vetter's drip tick.
///
/// # Errors
///
/// The task's declared codes, from [`pcs_issue::drip`].
pub async fn handle_pcs_tokens(
    state: &AppState,
    member_did: &str,
    doc: &TrustTask<JsonValue>,
) -> Result<JsonValue, TaskError> {
    let payload: pcs_tokens_spec::Payload = parse(doc)?;
    let config = config_for(state).await?;
    let community = community_did(state).await;
    let batch = TokenBatchRequestWire {
        label: payload.label.to_string(),
        // The wire batch is `u32` (a request never asks for more tokens than the drip could ever
        // hand out); the specification's `u64` is the JSON integer's full range. `pcs_issue::drip`
        // itself refuses an over-quota `tick`, so a value that cannot fit is refused there, not
        // silently truncated here.
        tick: u32::try_from(payload.tick).unwrap_or(u32::MAX),
        requests: payload
            .requests
            .iter()
            .map(|r| TokenRequestWire {
                commitment: r.commitment.to_string(),
                opening_proof: r.opening_proof.to_string(),
            })
            .collect(),
    };
    let served: TokenBatchWire =
        pcs_issue::drip(state, &community, &config, member_did, &batch, Utc::now())
            .await
            .map_err(tokens_error)?;
    let pre_credentials: Vec<pcs_tokens_spec::ResponsePreCredentialsItem> =
        convert_vec(served.pre_credentials)?;
    to_value(build::<_, pcs_tokens_spec::Response>(
        pcs_tokens_spec::Response::builder()
            .label(served.label)
            .tick(u64::from(served.tick))
            .pre_credentials(pre_credentials),
    )?)
}

/// Record a vetter's request to vet at a named event, and say where it stands.
///
/// The answer is never a grant. A vetter cannot raise their own cap — that is exactly what a
/// coerced vetter would be made to do — so this records the request and reports `pending` until
/// an approver has acted and the group has reached the community's floor. `pending` is an answer,
/// not a refusal.
///
/// # Errors
///
/// The task's declared codes, from [`pcs_event::request`].
pub async fn handle_event_mode(
    state: &AppState,
    member_did: &str,
    doc: &TrustTask<JsonValue>,
) -> Result<JsonValue, TaskError> {
    let payload: event_mode_spec::Payload = parse(doc)?;
    let config = config_for(state).await?;
    let event_id = payload.event_id.to_string();
    let tier = payload.tier.to_string();
    let (event_state, group_size, event) = pcs_event::request(
        state,
        &config,
        member_did,
        &event_id,
        &tier,
        (payload.window.start_date, payload.window.end_date),
        Utc::now(),
    )
    .await
    .map_err(event_error)?;

    let approved = event_state == pcs_event::EventState::Approved;
    let mut builder = event_mode_spec::Response::builder()
        .event_id(event_id.clone())
        .state(event_state.as_str())
        .tier(tier.clone())
        .window(payload.window)
        .group_size(group_size as u64)
        // `usize` here is always small (a community's own approver-configured floor), so the
        // generated `i64` never actually truncates; the cast is honest about the type, not the
        // range.
        .group_floor(i64::try_from(event.group_floor).unwrap_or(i64::MAX));
    // The three members that only mean anything once the label is live. Sending them while the
    // request is pending would read as permission to draw.
    if approved {
        let label: event_mode_spec::ResponseLabel =
            event
                .label()
                .try_into()
                .map_err(|e: event_mode_spec::error::ConversionError| {
                    TaskError::from(vti_common::error::AppError::Internal(format!(
                        "response: {e}"
                    )))
                })?;
        builder = builder
            .label(Some(label))
            .drip_per_tick(
                event
                    .tier(&tier)
                    .and_then(|t| std::num::NonZeroU64::new(t.drip_per_tick as u64)),
            )
            .closes_after(event.closes_after());
    }
    to_value(build::<_, event_mode_spec::Response>(builder)?)
}

/// Issue an applicant the challenge its proof must bind.
///
/// One open challenge per applicant: asking again replaces the previous one rather than adding
/// to it, so an applicant cannot accumulate challenges and spend them across submissions.
///
/// # Errors
///
/// `notHiddenVetting` when this community publishes no hidden-vetting criterion.
pub async fn handle_pcs_challenge(
    state: &AppState,
    applicant_did: &str,
    doc: &TrustTask<JsonValue>,
) -> Result<JsonValue, TaskError> {
    let _payload: pcs_challenge_spec::Payload = parse(doc)?;
    // Refuses with the declared code when there is nothing to challenge for.
    config_for(state).await?;
    let now = Utc::now();
    let ttl = pcs_challenge::DEFAULT_CHALLENGE_TTL;
    let challenge = pcs_challenge::issue(&state.join_requests_ks, applicant_did, ttl, now)
        .await
        .map_err(TaskError::from)?;
    to_value(build::<_, pcs_challenge_spec::Response>(
        pcs_challenge_spec::Response::builder()
            .challenge(challenge)
            .expires_at(now + ttl),
    )?)
}

// --- plumbing --------------------------------------------------------------------------------

async fn community_did(state: &AppState) -> String {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default()
}

fn parse<P: serde::de::DeserializeOwned>(doc: &TrustTask<JsonValue>) -> Result<P, TaskError> {
    serde_json::from_value(doc.payload.clone()).map_err(|e| {
        TaskError::from(vti_common::error::AppError::Validation(format!(
            "payload: {e}"
        )))
    })
}

fn to_value<T: serde::Serialize>(response: T) -> Result<JsonValue, TaskError> {
    serde_json::to_value(response).map_err(|e| {
        TaskError::from(vti_common::error::AppError::Internal(format!(
            "response: {e}"
        )))
    })
}

/// Finish a generated response builder into its `#[non_exhaustive]` type. The generated types
/// cannot be built as struct literals from outside their crate; this is the `TryFrom<Builder>`
/// conversion every one of them defines, with the field-validation failure (a value that does
/// not match the specification's own pattern, which should never happen for a value this service
/// produced itself) mapped onto the same error vocabulary as a bad request.
fn build<B, T: TryFrom<B>>(builder: B) -> Result<T, TaskError>
where
    T::Error: std::fmt::Display,
{
    T::try_from(builder).map_err(|e| {
        TaskError::from(vti_common::error::AppError::Internal(format!(
            "response: {e}"
        )))
    })
}

/// Convert every element of a plain `Vec` into a generated newtype, for a builder field the
/// codegen does not give a blanket `Vec<String> -> Vec<Item>` conversion for.
fn convert_vec<T, U: TryFrom<T>>(items: Vec<T>) -> Result<Vec<U>, TaskError>
where
    U::Error: std::fmt::Display,
{
    items
        .into_iter()
        .map(|item| {
            U::try_from(item).map_err(|e| {
                TaskError::from(vti_common::error::AppError::Internal(format!(
                    "response: {e}"
                )))
            })
        })
        .collect()
}

/// Map an enrolment refusal onto the code the specification declares for it.
///
/// The text is matched rather than a typed error because `pcs_issue` answers in `AppError`,
/// which is the vocabulary its REST callers need; the mapping lives here, with the task that
/// declares the codes, so adding a caller cannot silently lose them.
fn root_error(e: vti_common::error::AppError) -> TaskError {
    let text = e.to_string();
    let code = if matches!(e, vti_common::error::AppError::Forbidden(_)) {
        ROOT_ERR_NOT_A_VETTER
    } else if text.contains("is issuing") {
        ROOT_ERR_WRONG_LABEL
    } else if text.contains("already holds a credential") {
        ROOT_ERR_ALREADY_ENROLLED
    } else if text.contains("bound to another PCS identifier") {
        ROOT_ERR_IDENTIFIER_REBOUND
    } else if text.contains("does not verify") {
        ROOT_ERR_BAD_REQUEST
    } else {
        return TaskError::from(e);
    };
    TaskError::declared(code, vti_common::error::AppError::Validation(text))
}

/// The same for the drip.
fn tokens_error(e: vti_common::error::AppError) -> TaskError {
    let text = e.to_string();
    // Ordered before the `Forbidden` arm: every event-gate refusal is a `Forbidden` too, and
    // reporting one as `notAVetter` would send a vetter to chase a grant they already hold.
    let code = if text.contains("event `") {
        TOKENS_ERR_EVENT_REFUSED
    } else if matches!(e, vti_common::error::AppError::Forbidden(_)) {
        TOKENS_ERR_NOT_A_VETTER
    } else if text.contains("not a live token label") {
        TOKENS_ERR_LABEL_NOT_LIVE
    } else if text.contains("already served") {
        TOKENS_ERR_ALREADY_SERVED
    } else if text.contains("drips") {
        TOKENS_ERR_OVER_QUOTA
    } else if text.contains("opening proof") {
        TOKENS_ERR_BAD_OPENING_PROOF
    } else {
        return TaskError::from(e);
    };
    TaskError::declared(code, vti_common::error::AppError::Validation(text))
}

/// The same for an event-mode request.
fn event_error(e: vti_common::error::AppError) -> TaskError {
    let text = e.to_string();
    let code = if matches!(e, vti_common::error::AppError::NotFound(_)) {
        EVENT_ERR_UNKNOWN_EVENT
    } else if matches!(e, vti_common::error::AppError::Forbidden(_)) {
        EVENT_ERR_NOT_A_VETTER
    } else if text.contains("is not a tier") {
        EVENT_ERR_UNKNOWN_TIER
    } else if text.contains("is not inside") {
        EVENT_ERR_BAD_WINDOW
    } else if text.contains("has already asked") {
        EVENT_ERR_ALREADY_REQUESTED
    } else if text.contains("closed after") {
        EVENT_ERR_EVENT_CLOSED
    } else {
        return TaskError::from(e);
    };
    TaskError::declared(code, vti_common::error::AppError::Validation(text))
}

/// How long a challenge stands, re-exported so a client can show it.
pub use pcs_challenge::DEFAULT_CHALLENGE_TTL as CHALLENGE_TTL;

/// The window a client should treat as the deadline for building a proof.
#[must_use]
pub fn challenge_window() -> Duration {
    CHALLENGE_TTL
}
