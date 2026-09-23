//! The Trust Tasks that carry hidden vetting's community half.
//!
//! [`super::pcs_issue`] mints, [`super::pcs_challenge`] issues and [`super::pcs_event`] decides
//! who may draw at an event's rate; this is how a vetter and an applicant reach them. Four
//! exchanges, each a published specification:
//!
//! - `vtc/vetting/vetters/pcs-root/0.1` — a vetter enrols for a class label.
//! - `vtc/vetting/vetters/pcs-tokens/0.1` — a vetter draws its tick of the drip.
//! - `vtc/vetting/vetters/event-mode/0.1` — a vetter asks to vet at a named event.
//! - `vtc/vetting/pcs-challenge/0.1` — an applicant asks for the nonce its proof must bind.
//!
//! # Why these payload types are hand-written
//!
//! All four specifications are merged upstream (`dtgwg-trust-tasks-tf` #618 and #620) and their
//! bindings generated — into `trust-tasks-rs` **0.22**. This graph is on **0.21.17**, and not by choice:
//! `affinidi-messaging-sdk`, the mediator, and the `trust-tasks-{proof,https,tsp,
//! capability-client}` companions all sit on the 0.21 line and carry `trust-tasks-rs` types in
//! their own public APIs. Two nodes of it cannot unify, so a `patch.crates-io` bridges nothing.
//!
//! So the wait is **not** for a release of `trust-tasks-rs` — 0.22 is already published, and the
//! open release PR publishes the line carrying these specs. It is for the 0.22 line to reach this graph,
//! which means those five crates moving first. Until then, the types are written here.
//!
//! That is a hazard the workspace has a rule against, so it is held down rather than waved at:
//! [`tests`] validates every one of these types against the **published schema**, carried in
//! `schemas/` as a verbatim copy of the spec repo's `payload.schema.json`. A member that drifts
//! from the specification fails a test here rather than in a deployment. When the release lands,
//! these types are deleted and the generated ones imported; the handlers do not change.

use chrono::{Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use trust_tasks_rs::TrustTask;

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
/// `vtc/vetting/vetters/event-mode:alreadyRequested`
pub const EVENT_ERR_ALREADY_REQUESTED: &str = "vtc/vetting/vetters/event-mode:alreadyRequested";
/// `vtc/vetting/vetters/event-mode:eventClosed`
pub const EVENT_ERR_EVENT_CLOSED: &str = "vtc/vetting/vetters/event-mode:eventClosed";
/// `vtc/vetting/pcs-challenge:notHiddenVetting`
pub const CHALLENGE_ERR_NOT_HIDDEN: &str = "vtc/vetting/pcs-challenge:notHiddenVetting";

// --- payloads --------------------------------------------------------------------------------

/// `vtc/vetting/vetters/pcs-root/0.1` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcsRootPayload {
    /// The class label asked for, `vetter/<YYYY-MM>`.
    pub label: String,
    /// The vetter's PCS identifier, multibase.
    pub id: String,
    /// The blinded root request, as the suite serialises it.
    pub request: JsonValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<JsonValue>,
}

/// `vtc/vetting/vetters/pcs-root/0.1#response` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcsRootResponse {
    pub label: String,
    pub pre_credential: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<JsonValue>,
}

/// `vtc/vetting/vetters/pcs-tokens/0.1` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcsTokensPayload {
    pub label: String,
    pub tick: u32,
    pub requests: Vec<PcsTokenRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<JsonValue>,
}

/// One blinded serial with its opening proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcsTokenRequest {
    pub commitment: String,
    pub opening_proof: String,
}

/// `vtc/vetting/vetters/pcs-tokens/0.1#response` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcsTokensResponse {
    pub label: String,
    pub tick: u32,
    pub pre_credentials: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<JsonValue>,
}

/// `vtc/vetting/vetters/event-mode/0.1` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventModePayload {
    pub event_id: String,
    pub tier: String,
    pub window: EventWindow,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<JsonValue>,
}

/// The days a vetter expects to be vetting at an event.
///
/// Dates, never timestamps, for the same reason an attestation carries dates: an hour would say
/// when a particular vetter expects to be at a desk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventWindow {
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
}

/// `vtc/vetting/vetters/event-mode/0.1#response` payload.
///
/// `group_size` is a count and never a list: who else is at the event **is** the anonymity set,
/// so the number is the most a member may be told — enough to tell "nobody has approved it" from
/// "not enough people have asked", which are the two reasons a request sits pending.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventModeResponse {
    pub event_id: String,
    pub state: String,
    pub tier: String,
    pub window: EventWindow,
    pub group_size: usize,
    pub group_floor: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drip_per_tick: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closes_after: Option<NaiveDate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<JsonValue>,
}

/// `vtc/vetting/pcs-challenge/0.1` request payload. Every member is optional: the applicant is
/// identified by `issuer`, and that is the whole input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcsChallengePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criterion_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<JsonValue>,
}

/// `vtc/vetting/pcs-challenge/0.1#response` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PcsChallengeResponse {
    pub challenge: String,
    pub expires_at: chrono::DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<JsonValue>,
}

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
    let payload: PcsRootPayload = parse(doc)?;
    let config = config_for(state).await?;
    let community = community_did(state).await;
    let request = RootRequestWire {
        label: payload.label.clone(),
        id: payload.id.clone(),
        request: payload.request.clone(),
    };
    let answer: RootCredentialWire =
        pcs_issue::enrol(state, &community, &config, member_did, &request, Utc::now())
            .await
            .map_err(root_error)?;
    to_value(PcsRootResponse {
        label: answer.label,
        pre_credential: answer.pre_credential,
        ext: None,
    })
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
    let payload: PcsTokensPayload = parse(doc)?;
    let config = config_for(state).await?;
    let community = community_did(state).await;
    let batch = TokenBatchRequestWire {
        label: payload.label.clone(),
        tick: payload.tick,
        requests: payload
            .requests
            .iter()
            .map(|r| TokenRequestWire {
                commitment: r.commitment.clone(),
                opening_proof: r.opening_proof.clone(),
            })
            .collect(),
    };
    let served: TokenBatchWire =
        pcs_issue::drip(state, &community, &config, member_did, &batch, Utc::now())
            .await
            .map_err(tokens_error)?;
    to_value(PcsTokensResponse {
        label: served.label,
        tick: served.tick,
        pre_credentials: served.pre_credentials,
        ext: None,
    })
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
    let payload: EventModePayload = parse(doc)?;
    let config = config_for(state).await?;
    let (event_state, group_size, event) = pcs_event::request(
        state,
        &config,
        member_did,
        &payload.event_id,
        &payload.tier,
        (payload.window.start_date, payload.window.end_date),
        Utc::now(),
    )
    .await
    .map_err(event_error)?;

    let approved = event_state == pcs_event::EventState::Approved;
    to_value(EventModeResponse {
        event_id: payload.event_id,
        state: event_state.as_str().to_string(),
        tier: payload.tier.clone(),
        window: payload.window,
        group_size,
        group_floor: event.group_floor,
        // The three members that only mean anything once the label is live. Sending them while
        // the request is pending would read as permission to draw.
        label: approved.then(|| event.label()),
        drip_per_tick: approved
            .then(|| event.tier(&payload.tier).map(|t| t.drip_per_tick))
            .flatten(),
        closes_after: approved.then(|| event.closes_after()),
        ext: None,
    })
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
    let _payload: PcsChallengePayload = parse(doc)?;
    // Refuses with the declared code when there is nothing to challenge for.
    config_for(state).await?;
    let now = Utc::now();
    let ttl = pcs_challenge::DEFAULT_CHALLENGE_TTL;
    let challenge = pcs_challenge::issue(&state.join_requests_ks, applicant_did, ttl, now)
        .await
        .map_err(TaskError::from)?;
    to_value(PcsChallengeResponse {
        challenge,
        expires_at: now + ttl,
        ext: None,
    })
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

fn to_value<T: Serialize>(response: T) -> Result<JsonValue, TaskError> {
    serde_json::to_value(response).map_err(|e| {
        TaskError::from(vti_common::error::AppError::Internal(format!(
            "response: {e}"
        )))
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The published schemas, carried verbatim from the spec repo. These are the pin: a member
    /// that drifts from the specification fails here.
    const ROOT_SCHEMA: &str = include_str!("schemas/pcs-root-0.1.payload.schema.json");
    const TOKENS_SCHEMA: &str = include_str!("schemas/pcs-tokens-0.1.payload.schema.json");
    const CHALLENGE_SCHEMA: &str = include_str!("schemas/pcs-challenge-0.1.payload.schema.json");
    const EVENT_SCHEMA: &str = include_str!("schemas/event-mode-0.1.payload.schema.json");

    /// Validate `value` against the request half of `schema`, with `$ref`s to the framework's
    /// shared `Ext` stripped: those resolve by relative path in the spec repo's tree and carry
    /// nothing this check is about (`ext` is an open object either way).
    fn check(schema: &str, value: &serde_json::Value, response: bool) {
        let mut doc: serde_json::Value = serde_json::from_str(schema).expect("schema parses");
        strip_ext_refs(&mut doc);
        let sub = if response {
            // A `$ref` into the spec's own `$defs` (`#/$defs/Window`) only resolves if `$defs`
            // travels with the extracted sub-schema, so the response is validated as a reference
            // into the whole document rather than as a document of its own.
            doc.get("$defs")
                .and_then(|d| d.get("Response"))
                .expect("the spec declares a response");
            serde_json::json!({
                "$defs": doc.get("$defs").cloned().unwrap_or_default(),
                "$ref": "#/$defs/Response",
            })
        } else {
            doc
        };
        let compiled = jsonschema::validator_for(&sub).expect("schema compiles");
        if let Err(e) = compiled.validate(value) {
            panic!("{value:#} does not satisfy the published schema: {e}");
        }
    }

    fn strip_ext_refs(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                if map
                    .get("$ref")
                    .and_then(|r| r.as_str())
                    .is_some_and(|r| r.contains("framework.schema.json"))
                {
                    map.clear();
                    map.insert("type".into(), serde_json::json!("object"));
                    return;
                }
                for (_, v) in map.iter_mut() {
                    strip_ext_refs(v);
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(strip_ext_refs),
            _ => {}
        }
    }

    #[test]
    fn the_root_types_match_the_published_schema() {
        let request = PcsRootPayload {
            label: "vetter/2026-09".into(),
            id: "z5jokfsiZx1sk1mJyQnBnR519B9mcQhw9a8LrF9VQdAj".into(),
            request: serde_json::json!({ "proof": "zSzFTCny3qaXpSHTsTE877ffQfSuF9T5zo53iuZ" }),
            ext: None,
        };
        check(ROOT_SCHEMA, &serde_json::to_value(&request).unwrap(), false);

        let response = PcsRootResponse {
            label: "vetter/2026-09".into(),
            pre_credential: "z3Xef1JY2x1s2vY6yKWfLu8Ap2vKuoZGwaQLZ2tjq8Qk".into(),
            ext: None,
        };
        check(ROOT_SCHEMA, &serde_json::to_value(&response).unwrap(), true);
    }

    #[test]
    fn the_token_types_match_the_published_schema() {
        let request = PcsTokensPayload {
            label: "token/2026-09".into(),
            tick: 1,
            requests: vec![PcsTokenRequest {
                commitment: "z2umykFwGKzcv489j6kMGJnPTgKqAqMvCSPVkpyPCqAKA".into(),
                opening_proof: "zP3kHy6ZpnVAaRt7Y3PQRa2AeKkFSHJpQnoAneHhnDQxEJ".into(),
            }],
            ext: None,
        };
        check(
            TOKENS_SCHEMA,
            &serde_json::to_value(&request).unwrap(),
            false,
        );

        let response = PcsTokensResponse {
            label: "token/2026-09".into(),
            tick: 1,
            pre_credentials: vec!["z26q5oFrp6i2aTKLp6Y6jsLESJMoNfZQwk8VKXc37c24".into()],
            ext: None,
        };
        check(
            TOKENS_SCHEMA,
            &serde_json::to_value(&response).unwrap(),
            true,
        );
    }

    #[test]
    fn the_challenge_types_match_the_published_schema() {
        let request = PcsChallengePayload {
            criterion_id: Some("kernel-developer-private".into()),
            ext: None,
        };
        check(
            CHALLENGE_SCHEMA,
            &serde_json::to_value(&request).unwrap(),
            false,
        );

        // The challenge is 16 bytes as lowercase hex, and the schema says so with a pattern —
        // this is the member most likely to drift, because "a random string" is the obvious
        // implementation and it is not what the specification says.
        let response = PcsChallengeResponse {
            challenge: "a961aa3e63df4d15c9ad565feed87c46".into(),
            expires_at: Utc::now(),
            ext: None,
        };
        check(
            CHALLENGE_SCHEMA,
            &serde_json::to_value(&response).unwrap(),
            true,
        );
    }

    #[test]
    fn the_event_mode_types_match_the_published_schema() {
        let window = EventWindow {
            start_date: NaiveDate::from_ymd_opt(2026, 10, 12).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2026, 10, 14).unwrap(),
        };
        let request = EventModePayload {
            event_id: "kernel-summit-2026".into(),
            tier: "desk".into(),
            window,
            ext: None,
        };
        check(
            EVENT_SCHEMA,
            &serde_json::to_value(&request).unwrap(),
            false,
        );

        // Pending: the three members that only mean anything once the label is live are absent,
        // and the schema has to accept that — a response carrying `label` while `state` is
        // `pending` would read as permission to draw.
        let pending = EventModeResponse {
            event_id: "kernel-summit-2026".into(),
            state: pcs_event::EventState::Pending.as_str().into(),
            tier: "desk".into(),
            window: EventWindow {
                start_date: NaiveDate::from_ymd_opt(2026, 10, 12).unwrap(),
                end_date: NaiveDate::from_ymd_opt(2026, 10, 14).unwrap(),
            },
            group_size: 2,
            group_floor: 3,
            label: None,
            drip_per_tick: None,
            closes_after: None,
            ext: None,
        };
        check(EVENT_SCHEMA, &serde_json::to_value(&pending).unwrap(), true);

        let approved = EventModeResponse {
            state: pcs_event::EventState::Approved.as_str().into(),
            group_size: 5,
            label: Some("token/event/kernel-summit-2026".into()),
            drip_per_tick: Some(20),
            closes_after: Some(NaiveDate::from_ymd_opt(2026, 10, 28).unwrap()),
            ..pending
        };
        check(
            EVENT_SCHEMA,
            &serde_json::to_value(&approved).unwrap(),
            true,
        );
    }

    /// The two words the specification allows, and nothing else. `state` is a plain `String` on
    /// the response type — a member the schema constrains and the type does not — so the values
    /// it is built from are pinned here.
    #[test]
    fn the_event_states_are_the_two_the_schema_names() {
        let schema: serde_json::Value = serde_json::from_str(EVENT_SCHEMA).unwrap();
        let states = schema["$defs"]["Response"]["properties"]["state"]["enum"]
            .as_array()
            .expect("the schema constrains `state`")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(states, ["pending", "approved"]);
        assert_eq!(pcs_event::EventState::Pending.as_str(), "pending");
        assert_eq!(pcs_event::EventState::Approved.as_str(), "approved");
    }

    /// An empty request is legal: the applicant is identified by `issuer`.
    #[test]
    fn a_challenge_request_needs_nothing_at_all() {
        check(
            CHALLENGE_SCHEMA,
            &serde_json::to_value(PcsChallengePayload::default()).unwrap(),
            false,
        );
    }
}
