//! The three Trust Tasks that carry hidden vetting's community half.
//!
//! [`super::pcs_issue`] mints and [`super::pcs_challenge`] issues; this is how a vetter and an
//! applicant reach them. Three exchanges, each a published specification:
//!
//! - `vtc/vetting/vetters/pcs-root/0.1` — a vetter enrols for a class label.
//! - `vtc/vetting/vetters/pcs-tokens/0.1` — a vetter draws its tick of the drip.
//! - `vtc/vetting/pcs-challenge/0.1` — an applicant asks for the nonce its proof must bind.
//!
//! # Why these payload types are hand-written
//!
//! The specifications are authored and their bindings generated (`dtgwg-trust-tasks-tf`, branch
//! `hidden-vetting-tasks`), but the generated crate is `trust-tasks-rs` **0.22**, and published
//! crates in this graph pin `^0.21` — two nodes that do not unify, so a `patch.crates-io` cannot
//! bridge them. Until the release lands, the types are written here.
//!
//! That is a hazard the workspace has a rule against, so it is held down rather than waved at:
//! [`tests`] validates every one of these types against the **published schema**, carried in
//! `schemas/` as a verbatim copy of the spec repo's `payload.schema.json`. A member that drifts
//! from the specification fails a test here rather than in a deployment. When the release lands,
//! these types are deleted and the generated ones imported; the handlers do not change.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use trust_tasks_rs::TrustTask;

use vti_vetting_pcs::issuer::{
    RootCredentialWire, RootRequestWire, TokenBatchRequestWire, TokenBatchWire, TokenRequestWire,
};

use super::{pcs_challenge, pcs_issue};
use crate::error::TaskError;
use crate::server::AppState;

/// `vtc/vetting/vetters/pcs-root/0.1` — a vetter asks for its class credential.
pub const PCS_ROOT_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/pcs-root/0.1";
/// `vtc/vetting/vetters/pcs-tokens/0.1` — a vetter draws its tick of the drip.
pub const PCS_TOKENS_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/pcs-tokens/0.1";
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
    let code = if matches!(e, vti_common::error::AppError::Forbidden(_)) {
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

    /// Validate `value` against the request half of `schema`, with `$ref`s to the framework's
    /// shared `Ext` stripped: those resolve by relative path in the spec repo's tree and carry
    /// nothing this check is about (`ext` is an open object either way).
    fn check(schema: &str, value: &serde_json::Value, response: bool) {
        let mut doc: serde_json::Value = serde_json::from_str(schema).expect("schema parses");
        strip_ext_refs(&mut doc);
        let sub = if response {
            doc.get("$defs")
                .and_then(|d| d.get("Response"))
                .cloned()
                .expect("the spec declares a response")
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
