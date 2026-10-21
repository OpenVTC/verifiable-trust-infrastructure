//! `vtc/admin/events/subscribe/0.1`, `/0.2` and `/0.3` — an administrator's
//! console opens its live channel of hints (`crate::admin_events`).
//!
//! All three versions are served, each answered at its own version: 0.2 adds
//! the `rooms` topic and 0.3 the `directory` and `groups` topics, and nothing
//! else, so an older console keeps working unchanged (subscribe 0.2 *What 0.2
//! adds*, 0.3 *What 0.3 adds*).
//!
//! The task's success response opens a stream, which only the HTTPS door can
//! carry (binding 0.3 §2.1). This handler decides everything a refusal could
//! be — every one of them answered as an ordinary JSON `trust-task-error`,
//! before a byte of stream is written — and on success leaves the granted
//! stream in the door's [`admin_events::StreamSlot`]. The door then writes the
//! signed `#response` as the stream's first event and the hints after it.
//!
//! In the order the specification's consumer rules give them:
//!
//! 1. the payload, against its published schema;
//! 2. `issuedAt` inside a window of at most five minutes (rule 2) — tighter
//!    than the spine's ten, because a subscribe is signed at the moment of
//!    connecting and a wider window serves only a replay;
//! 3. a delivery that can carry the stream, or `streamUnavailable` (rule 3);
//! 4. the proven caller holds an administrative role, or `notAdministrator`
//!    (rule 1);
//! 5. a `Last-Event-ID` header that disagrees with `since` is
//!    `malformedRequest` (binding 0.3 §2.1.3 item 3) — resumption is in-band
//!    only;
//! 6. at least one requested topic the caller may read, or `permissionDenied`
//!    (rule 4);
//! 7. room under the stream caps, or `tooManyStreams` (rule 11).
//!
//! The response is never recorded for redelivery ([`UNRECORDED_RESPONSES`]):
//! a `#response` that is not followed by its stream would be one the community
//! cannot follow with events (rule 3), so a replayed document is answered
//! `204` and opens nothing.

use std::collections::BTreeSet;

use serde_json::Value;
use trust_tasks_rs::specs::vtc::admin::events::subscribe::v0_1 as subscribe;
use trust_tasks_rs::specs::vtc::admin::events::subscribe::v0_2 as subscribe_v0_2;
use trust_tasks_rs::specs::vtc::admin::events::subscribe::v0_3 as subscribe_v0_3;
use trust_tasks_rs::{ErrorPayload, Payload, RejectReason, TrustTask};

use super::helpers::{
    app_error_to_reject, error_response, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, TrustTaskOutcome, parse_spec_payload};
use crate::admin_events::{self, Refusal, Topic, Version};
use crate::server::AppState;

pub(crate) const SUBSCRIBE_TYPE: &str = <subscribe::Payload as Payload>::TYPE_URI;
pub(crate) const SUBSCRIBE_V0_2_TYPE: &str = <subscribe_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const SUBSCRIBE_V0_3_TYPE: &str = <subscribe_v0_3::Payload as Payload>::TYPE_URI;
/// Responses the duplicate-execution record keeps no body for: answering a
/// replayed subscribe with its old `#response` and no stream behind it would
/// break subscribe consumer rule 3 (every version).
pub(crate) const UNRECORDED_RESPONSES: &[&str] =
    &[SUBSCRIBE_TYPE, SUBSCRIBE_V0_2_TYPE, SUBSCRIBE_V0_3_TYPE];

/// The subscribe acceptance window: four minutes of age plus the spine's
/// 60 seconds of skew — five minutes in all (consumer rule 2).
const MAX_SUBSCRIBE_AGE: chrono::TimeDelta = chrono::TimeDelta::minutes(4);

fn refuse(doc: &TrustTask<Value>, code: &str, message: &str) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

pub(super) async fn handle_subscribe(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Every version declares the same codes under the same names.
    use subscribe::error_codes as codes;

    // The payload against its version's schema — which is where a `rooms`
    // topic in a 0.1 subscribe is refused — then one shape for both.
    let type_uri = doc.type_uri.to_string();
    let (version, requested, since): (Version, BTreeSet<Topic>, Option<String>) =
        if type_uri == SUBSCRIBE_V0_3_TYPE {
            let payload: subscribe_v0_3::Payload = match parse_spec_payload(&doc) {
                Ok(p) => p,
                Err(reject) => return reject,
            };
            (
                Version::V0_3,
                payload
                    .topics
                    .iter()
                    .filter_map(Topic::from_subscribe_v0_3)
                    .collect(),
                payload.since.as_ref().map(|t| t.as_str().to_string()),
            )
        } else if type_uri == SUBSCRIBE_V0_2_TYPE {
            let payload: subscribe_v0_2::Payload = match parse_spec_payload(&doc) {
                Ok(p) => p,
                Err(reject) => return reject,
            };
            (
                Version::V0_2,
                payload
                    .topics
                    .iter()
                    .filter_map(Topic::from_subscribe_v0_2)
                    .collect(),
                payload.since.as_ref().map(|t| t.as_str().to_string()),
            )
        } else {
            let payload: subscribe::Payload = match parse_spec_payload(&doc) {
                Ok(p) => p,
                Err(reject) => return reject,
            };
            (
                Version::V0_1,
                payload
                    .topics
                    .iter()
                    .filter_map(Topic::from_subscribe)
                    .collect(),
                payload.since.as_ref().map(|t| t.as_str().to_string()),
            )
        };

    let mut window = super::freshness_policy();
    window.max_age = Some(MAX_SUBSCRIBE_AGE);
    if let Err(reason) = doc.validate_freshness(chrono::Utc::now(), &window) {
        return reject_with(&doc, reason);
    }

    let slot = match admin_events::current_slot() {
        Some(slot) if slot.accepts_stream() => slot,
        Some(_) => {
            return refuse(
                &doc,
                codes::STREAM_UNAVAILABLE.code,
                "This request did not ask for an event stream (Accept: text/event-stream).",
            );
        }
        None => {
            return refuse(
                &doc,
                codes::STREAM_UNAVAILABLE.code,
                "This delivery cannot carry an event stream; only HTTPS binding 0.3 defines one.",
            );
        }
    };

    let Some(signer) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let standing = match admin_events::standing(state, &signer).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return refuse(
                &doc,
                codes::NOT_ADMINISTRATOR.code,
                "only an administrator of this community has a live console channel",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    let since = since.as_deref();
    if let (Some(header), Some(since)) = (slot.last_event_id(), since)
        && header != since
    {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "Last-Event-ID disagrees with the payload's `since`; resumption is \
                         in-band only (HTTPS binding 0.3 §2.1.3)"
                    .to_string(),
            },
        );
    }

    let parent_thread = doc.thread_id.clone().unwrap_or_else(|| doc.id.clone());
    let opened = match admin_events::open(
        state,
        &signer,
        &standing,
        version,
        &requested,
        since,
        parent_thread,
        doc.expires_at,
    )
    .await
    {
        Ok(opened) => opened,
        Err(Refusal::NoTopics) => {
            return reject_with(
                &doc,
                RejectReason::PermissionDenied {
                    reason: "none of the requested topics is one this caller may read".to_string(),
                },
            );
        }
        Err(Refusal::TooMany) => {
            // Declared `retryable: true`; an extended code defaults to false.
            let err = ErrorPayload::new(extended_code(codes::TOO_MANY_STREAMS.code))
                .with_message(format!(
                    "no room for another stream: this community allows {} per administrator and \
                     {} in all; close one (another tab or device), or poll",
                    admin_events::MAX_STREAMS_PER_SUBJECT,
                    admin_events::MAX_STREAMS_TOTAL,
                ))
                .with_retryable(codes::TOO_MANY_STREAMS.retryable);
            return error_response(
                doc.reject_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), err),
            );
        }
        Err(Refusal::Internal(e)) => return app_error_to_reject(&doc, &e),
    };

    let outcome = success_response(&doc, opened.response);
    if outcome.status.is_success() {
        slot.grant(opened.grant);
    }
    outcome
}
