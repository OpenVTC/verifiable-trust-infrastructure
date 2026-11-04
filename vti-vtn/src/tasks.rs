//! The network's API: `vtn/*` Trust Tasks (trusttasks.org, `vtn/*/0.1`), sent to
//! [`TRUST_TASKS_PATH`].
//!
//! Every request is a Trust Task document signed by the caller for `authentication`. The
//! proof's signer is the caller: there is no session to sign in to. A Trust Task answer is
//! never evidence of a relationship; the credentials it carries are (`docs/trust-tasks.md`,
//! A19), and the caller verifies those as it would from anywhere else.
//!
//! The payload and response types are the generated ones in [`specs`]
//! (`vti_specs_vtn::vtn`), so a request names its version by its type:
//!
//! ```ignore
//! use vti_vtn::tasks::specs::groups::register::v0_1 as register;
//! let answer: register::Response = client.task(&me, &network_did, &payload).await?;
//! ```

use serde::de::DeserializeOwned;
use serde_json::Value;
use trust_tasks_rs::{Payload, RequestPayload};

use crate::client::{ClientError, Result, VtnClient};
use crate::identity::Party;

/// The generated `vtn/*` payload and response types, one module per pinned version.
pub use crate::specs;

/// Where a network takes Trust Tasks.
pub const TRUST_TASKS_PATH: &str = "/v1/trust-tasks";

/// The prefix of the framework's error document Type URI, whatever its version.
const ERROR_TYPE_PREFIX: &str = "https://trusttasks.org/spec/trust-task-error/";

/// An unsigned request from `issuer` to `network_did` carrying `payload`.
pub fn request_document<P: Payload>(
    issuer: Option<&str>,
    network_did: &str,
    payload: &P,
) -> Result<Value> {
    crate::request::request_document(issuer, network_did, payload)
        .map_err(|e| ClientError::Unexpected(format!("build {}: {e}", P::TYPE_URI)))
}

/// `payload` as a request signed by `who` for `network_did`. Keep the result when the
/// signed document is itself what is recorded (`vtn/groups/register`: the network binds
/// its acceptance to this document's digest).
pub async fn sign_request<P: Payload>(
    who: &dyn Party,
    network_did: &str,
    payload: &P,
) -> Result<Value> {
    crate::request::sign_request(who, network_did, payload)
        .await
        .map_err(|e| ClientError::Unexpected(format!("sign {}: {e}", P::TYPE_URI)))
}

/// Read a network's answer to `request`: the response payload, or
/// [`ClientError::Refused`] for a `trust-task-error`.
///
/// The answer must be the `#response` of `request`'s type, from `network_did`, addressed
/// to the requester when there was one, and on the request's thread.
pub fn read_answer<R: DeserializeOwned>(
    status: u16,
    body: &[u8],
    request: &Value,
    network_did: &str,
) -> Result<R> {
    let answer: Value = serde_json::from_slice(body).map_err(|e| ClientError::Http {
        status,
        message: format!("not a Trust Task document: {e}"),
    })?;
    let member = |name: &str| answer.get(name).and_then(Value::as_str);
    let kind = member("type").unwrap_or_default();
    if kind.starts_with(ERROR_TYPE_PREFIX) {
        let payload = &answer["payload"];
        return Err(ClientError::Refused {
            status,
            code: payload["code"].as_str().unwrap_or("unknown").to_string(),
            message: payload["message"]
                .as_str()
                .unwrap_or("no message")
                .to_string(),
            details: payload.get("details").cloned(),
        });
    }
    let expected = format!("{}#response", request["type"].as_str().unwrap_or_default());
    if kind != expected {
        return Err(ClientError::Unexpected(format!(
            "answered with {kind:?}, expected {expected}"
        )));
    }
    if member("issuer").is_some_and(|issuer| issuer != network_did) {
        return Err(ClientError::Unexpected(format!(
            "answered by {}, not {network_did}",
            answer["issuer"]
        )));
    }
    if let Some(requester) = request["issuer"].as_str()
        && member("recipient").is_some_and(|to| to != requester)
    {
        return Err(ClientError::Unexpected(format!(
            "answer addressed to {}, not {requester}",
            answer["recipient"]
        )));
    }
    let thread = request
        .get("threadId")
        .or_else(|| request.get("id"))
        .and_then(Value::as_str);
    if member("threadId").is_some_and(|t| Some(t) != thread) {
        return Err(ClientError::Unexpected(format!(
            "answer is on thread {}, not this request's",
            answer["threadId"]
        )));
    }
    serde_json::from_value(answer["payload"].clone())
        .map_err(|e| ClientError::Unexpected(format!("{expected}: {e}")))
}

impl VtnClient {
    /// Send `payload` signed by `who` to the network `network_did` and return its answer.
    ///
    /// `network_did` is the network the caller expects, never what the server claims: the
    /// document names it as `recipient`, so a request cannot be replayed to another network.
    pub async fn task<P: RequestPayload>(
        &self,
        who: &dyn Party,
        network_did: &str,
        payload: &P,
    ) -> Result<P::Response> {
        let request = sign_request(who, network_did, payload).await?;
        self.send_request(&request, network_did).await
    }

    /// Send `payload` unsigned: for a read the network answers anyone
    /// (`[directory] visibility = "public"`).
    pub async fn read_task<P: RequestPayload>(
        &self,
        network_did: &str,
        payload: &P,
    ) -> Result<P::Response> {
        let request = request_document(None, network_did, payload)?;
        self.send_request(&request, network_did).await
    }

    /// Send a request someone already signed (see [`sign_request`]), unchanged, and read
    /// the answer as `R`.
    pub async fn send_request<R: DeserializeOwned>(
        &self,
        request: &Value,
        network_did: &str,
    ) -> Result<R> {
        self.send_request_to(&self.task_url(), request, network_did)
            .await
    }

    /// [`Self::send_request`] to another network's Trust Task URL: a relay onward.
    pub async fn send_request_to<R: DeserializeOwned>(
        &self,
        url: &str,
        request: &Value,
        network_did: &str,
    ) -> Result<R> {
        let res = self
            .http()
            .post(url)
            .json(request)
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let status = res.status().as_u16();
        let body = res
            .bytes()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        read_answer(status, &body, request, network_did)
    }

    /// This network's Trust Task URL.
    pub fn task_url(&self) -> String {
        format!("{}{TRUST_TASKS_PATH}", self.base())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::verify::{AUTHENTICATION, LocalDidKeyResolver, verify_document};
    use serde_json::json;
    use specs::groups::register::v0_1 as register;

    const NETWORK: &str = "did:example:network";

    fn payload() -> register::Payload {
        serde_json::from_value(json!({
            "role": "clinical",
            "group": "did:example:group",
            "endpoint": "https://community.example/relay",
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn a_request_is_signed_by_the_caller_for_authentication() {
        let me = Identity::generate();
        let doc = sign_request(&me, NETWORK, &payload()).await.unwrap();
        assert_eq!(doc["type"], register::Payload::TYPE_URI);
        assert_eq!(doc["issuer"], me.did());
        assert_eq!(doc["recipient"], NETWORK);
        assert!(doc["issuedAt"].is_string());
        assert_eq!(doc["proof"]["proofPurpose"], AUTHENTICATION);
        verify_document(&doc, me.did(), AUTHENTICATION, &LocalDidKeyResolver)
            .await
            .unwrap();
    }

    fn request() -> Value {
        json!({
            "id": "urn:uuid:1",
            "type": register::Payload::TYPE_URI,
            "issuer": "did:example:me",
            "recipient": NETWORK,
        })
    }

    #[test]
    fn an_answer_is_read_from_the_network_on_the_request_thread() {
        let answer = json!({
            "id": "urn:uuid:2",
            "type": format!("{}#response", register::Payload::TYPE_URI),
            "issuer": NETWORK,
            "recipient": "did:example:me",
            "threadId": "urn:uuid:1",
            "payload": { "ok": true },
        });
        let body = serde_json::to_vec(&answer).unwrap();
        let read: Value = read_answer(200, &body, &request(), NETWORK).unwrap();
        assert_eq!(read, json!({ "ok": true }));

        let mut other = answer.clone();
        other["issuer"] = json!("did:example:elsewhere");
        let body = serde_json::to_vec(&other).unwrap();
        assert!(matches!(
            read_answer::<Value>(200, &body, &request(), NETWORK),
            Err(ClientError::Unexpected(_))
        ));

        let mut other = answer;
        other["threadId"] = json!("urn:uuid:9");
        let body = serde_json::to_vec(&other).unwrap();
        assert!(read_answer::<Value>(200, &body, &request(), NETWORK).is_err());
    }

    #[test]
    fn a_refusal_carries_its_code_and_details() {
        let answer = json!({
            "id": "urn:uuid:3",
            "type": "https://trusttasks.org/spec/trust-task-error/0.6",
            "issuer": NETWORK,
            "threadId": "urn:uuid:1",
            "payload": {
                "code": "vtn/membership/acknowledge:rolesUnregistered",
                "message": "register a group for clinical first",
                "details": { "roles": ["clinical"] },
            },
        });
        let body = serde_json::to_vec(&answer).unwrap();
        match read_answer::<Value>(409, &body, &request(), NETWORK) {
            Err(ClientError::Refused {
                status,
                code,
                details,
                ..
            }) => {
                assert_eq!(status, 409);
                assert_eq!(code, "vtn/membership/acknowledge:rolesUnregistered");
                assert_eq!(details.unwrap()["roles"][0], "clinical");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
