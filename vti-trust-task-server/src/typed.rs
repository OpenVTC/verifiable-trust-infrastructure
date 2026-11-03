//! Typed payloads in, typed responses out, both held to the published schema.
//!
//! The generated payload types (`trust-tasks-build`) carry
//! `deny_unknown_fields` and the required set; `validate_value` adds what serde
//! cannot see — `const`, `enum`, `pattern`, `minLength`. A handler that reads
//! its payload through [`parse_spec_payload`] and answers through [`respond`]
//! cannot accept or emit a shape its specification does not describe.

use serde_json::Value;
use trust_tasks_rs::validate::ValidatedPayload;
use trust_tasks_rs::{RejectReason, TrustTask};

use crate::TrustTaskOutcome;
use crate::reject::{parse_payload, reject_with, success_response};

/// Validate `doc`'s payload against its published schema and hand back the
/// generated type, or a `malformedRequest` refusal.
pub fn parse_spec_payload<P>(doc: &TrustTask<Value>) -> Result<P, TrustTaskOutcome>
where
    P: ValidatedPayload + serde::de::DeserializeOwned,
{
    if let Err(e) = P::validate_value(&doc.payload) {
        return Err(reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("payload: {e}"),
            },
        ));
    }
    parse_payload::<P>(doc)
}

/// Answer with `body` held to the generated `#response` type `R` and its
/// schema.
///
/// A mismatch is the service's own fault, so it is an `internalError` (logged),
/// never a reply that claims a schema it does not satisfy.
pub fn respond<R>(doc: &TrustTask<Value>, body: Value) -> TrustTaskOutcome
where
    R: serde::de::DeserializeOwned + serde::Serialize + ValidatedPayload,
{
    let checked = R::validate_value(&body)
        .map_err(|e| e.to_string())
        .and_then(|()| serde_json::from_value::<R>(body).map_err(|e| e.to_string()));
    match checked {
        Ok(response) => success_response(doc, response),
        Err(e) => {
            tracing::error!(task = %doc.type_uri, error = %e, "response does not match its published schema");
            reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("response does not match its published schema: {e}"),
                },
            )
        }
    }
}
