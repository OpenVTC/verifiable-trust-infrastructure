//! The community's link to ballot boxes: one signed `voting/*` request, one signed answer.
//!
//! Over TSP, then DIDComm, whichever both DID documents advertise (VTI-VOT-005), through
//! [`PeerTasks`]: signed as this community, and released only on a reply the ballot box itself
//! signed. Never HTTPS — the ballot box's HTTPS door exists for sessionless casts, and a
//! community holds an identifier.

use std::time::Duration;

use serde_json::Value;

use crate::outbound::{PeerError, PeerTasks};

/// How long a ballot box has to answer one request.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(20);

/// What came back from a ballot box.
#[derive(Debug, Clone, PartialEq)]
pub enum BoxAnswer {
    /// Its `#response`: the payload, and the whole document as the ballot box signed it (a
    /// board head is kept as a checkpoint with the document that carried it).
    Success { payload: Value, document: Value },
    /// A `trust-task-error`: its code and message.
    Refused { code: String, message: String },
}

/// Why nothing came back.
#[derive(Debug, Clone)]
pub enum LinkError {
    /// Worth another attempt: messaging not up, no reply in the window.
    Unavailable(String),
    /// No transport in common: it changes only when one side advertises another.
    NoMatchingProtocol(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(m) | Self::NoMatchingProtocol(m) => f.write_str(m),
        }
    }
}

/// One exchange with a ballot box. A trait so tests can stand an in-process ballot box behind
/// it; the service's is [`BallotBoxLink`].
#[async_trait::async_trait]
pub trait BallotBoxChannel: Send + Sync {
    /// Send `payload` as a `type_uri` request to `ballot_box`, and wait for its answer.
    async fn exchange(
        &self,
        ballot_box: &str,
        type_uri: &str,
        payload: &Value,
    ) -> Result<BoxAnswer, LinkError>;
}

/// [`BallotBoxChannel`] over this VTC's messaging.
pub struct BallotBoxLink {
    pub(crate) peers: PeerTasks,
}

#[async_trait::async_trait]
impl BallotBoxChannel for BallotBoxLink {
    async fn exchange(
        &self,
        ballot_box: &str,
        type_uri: &str,
        payload: &Value,
    ) -> Result<BoxAnswer, LinkError> {
        let reply = self
            .peers
            .exchange(ballot_box, type_uri, payload, REPLY_TIMEOUT)
            .await
            .map_err(|e| match e {
                PeerError::Transient(m) => LinkError::Unavailable(m),
                PeerError::NoMatchingProtocol(m) => LinkError::NoMatchingProtocol(m),
            })?;
        let document = serde_json::to_value(&reply).unwrap_or(Value::Null);
        Ok(classify(
            &reply.type_uri.to_string(),
            reply.payload,
            document,
        ))
    }
}

/// A reply document as an answer: a `#response` is success, anything else (a
/// `trust-task-error`) a refusal carrying its code and message.
#[must_use]
pub fn classify(type_uri: &str, payload: Value, document: Value) -> BoxAnswer {
    if type_uri.ends_with("#response") {
        return BoxAnswer::Success { payload, document };
    }
    BoxAnswer::Refused {
        code: payload["code"].as_str().unwrap_or("unknown").to_string(),
        message: payload["message"].as_str().unwrap_or_default().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_response_is_success_and_anything_else_a_refusal() {
        let ok = classify(
            "https://trusttasks.org/spec/voting/election/register/0.1#response",
            json!({ "state": "registration" }),
            json!({ "signed": true }),
        );
        assert_eq!(
            ok,
            BoxAnswer::Success {
                payload: json!({ "state": "registration" }),
                document: json!({ "signed": true })
            }
        );
        let refused = classify(
            "https://trusttasks.org/spec/trust-task-error/0.5",
            json!({ "code": "voting/election/register:alreadyRegistered", "message": "no" }),
            Value::Null,
        );
        assert_eq!(
            refused,
            BoxAnswer::Refused {
                code: "voting/election/register:alreadyRegistered".into(),
                message: "no".into()
            }
        );
    }
}
