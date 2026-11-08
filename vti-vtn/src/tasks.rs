//! The network's API: `vtn/*` Trust Tasks (trusttasks.org, `vtn/*/0.1`), sent to
//! [`TRUST_TASKS_PATH`].
//!
//! Every request is a Trust Task document signed by the caller for `authentication`. The
//! proof's signer is the caller: there is no session to sign in to. The network signs its
//! answer for `authentication` in turn, and the client verifies it ([`read_answer`]) with
//! the resolver it was given ([`VtnClient::verifying`]). A Trust Task answer is
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
use crate::verify::{AUTHENTICATION, KeyResolver, verify_document};

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
/// The answer must be the `#response` of `request`'s type, issued by `network_did` and
/// signed by it for `authentication` ([`ClientError::Unverified`] otherwise), addressed to
/// the requester when there was one, and on the request's thread.
///
/// A refusal is verified when it carries a proof. An unsigned one is still read as a
/// refusal: it grants nothing, and a network answers unsigned when it has no key to sign
/// with yet or signing failed (`vti_trust_task_server::sign_response`).
pub async fn read_answer<R: DeserializeOwned>(
    status: u16,
    body: &[u8],
    request: &Value,
    network_did: &str,
    resolver: &dyn KeyResolver,
) -> Result<R> {
    let answer: Value = serde_json::from_slice(body).map_err(|e| ClientError::Http {
        status,
        message: format!("not a Trust Task document: {e}"),
    })?;
    let member = |name: &str| answer.get(name).and_then(Value::as_str);
    let kind = member("type").unwrap_or_default();
    if member("issuer").is_some_and(|issuer| issuer != network_did) {
        return Err(ClientError::Unexpected(format!(
            "answered by {}, not {network_did}",
            answer["issuer"]
        )));
    }
    if kind.starts_with(ERROR_TYPE_PREFIX) {
        if answer.get("proof").is_some() {
            verify_answer(&answer, network_did, resolver).await?;
        }
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
    if member("issuer").is_none() {
        return Err(ClientError::Unverified(format!(
            "{expected} names no issuer"
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
    verify_answer(&answer, network_did, resolver).await?;
    serde_json::from_value(answer["payload"].clone())
        .map_err(|e| ClientError::Unexpected(format!("{expected}: {e}")))
}

/// `answer` carries `network_did`'s `authentication` proof, and it verifies.
async fn verify_answer(
    answer: &Value,
    network_did: &str,
    resolver: &dyn KeyResolver,
) -> Result<()> {
    verify_document(answer, network_did, AUTHENTICATION, resolver)
        .await
        .map_err(|e| ClientError::Unverified(format!("{network_did}'s proof: {e}")))
}

impl VtnClient {
    /// Send `payload` signed by `who` to the network `network_did` and return its answer.
    ///
    /// `network_did` is the network the caller expects, never what the server claims: the
    /// document names it as `recipient`, so a request cannot be replayed to another network,
    /// and the answer must be signed by it ([`read_answer`]). The client must be
    /// [`VtnClient::verifying`].
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
        // Checked before sending: a task whose answer cannot be verified is not sent at all.
        let resolver = self.answer_resolver()?;
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
        read_answer(status, &body, request, network_did, resolver).await
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
    use crate::verify::{ASSERTION_METHOD, LocalDidKeyResolver};
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
            "recipient": "did:example:network",
        })
    }

    /// `answer` as `network` sends it: issued by it, signed for `authentication`.
    async fn signed(network: &Identity, mut answer: Value) -> Vec<u8> {
        answer["issuer"] = json!(network.did());
        let doc = network
            .sign_document_for(answer, AUTHENTICATION)
            .await
            .unwrap();
        serde_json::to_vec(&doc).unwrap()
    }

    fn response() -> Value {
        json!({
            "id": "urn:uuid:2",
            "type": format!("{}#response", register::Payload::TYPE_URI),
            "recipient": "did:example:me",
            "threadId": "urn:uuid:1",
            "payload": { "ok": true },
        })
    }

    async fn read(body: &[u8], network: &str) -> Result<Value> {
        read_answer(200, body, &request(), network, &LocalDidKeyResolver).await
    }

    #[tokio::test]
    async fn an_answer_is_read_from_the_network_on_the_request_thread() {
        let network = Identity::generate();
        let body = signed(&network, response()).await;
        assert_eq!(
            read(&body, network.did()).await.unwrap(),
            json!({ "ok": true })
        );

        let other = Identity::generate();
        assert!(matches!(
            read(&body, other.did()).await,
            Err(ClientError::Unexpected(_))
        ));

        let mut elsewhere = response();
        elsewhere["threadId"] = json!("urn:uuid:9");
        let body = signed(&network, elsewhere).await;
        assert!(read(&body, network.did()).await.is_err());
    }

    #[tokio::test]
    async fn an_answer_must_be_signed_by_the_network_for_authentication() {
        let network = Identity::generate();
        let unverified = |r: Result<Value>| matches!(r, Err(ClientError::Unverified(_)));

        // Unsigned, with or without naming the network.
        let mut unsigned = response();
        assert!(unverified(
            read(&serde_json::to_vec(&unsigned).unwrap(), network.did()).await
        ));
        unsigned["issuer"] = json!(network.did());
        assert!(unverified(
            read(&serde_json::to_vec(&unsigned).unwrap(), network.did()).await
        ));

        // Naming the network, signed by someone else.
        let forger = Identity::generate();
        let mut forged = response();
        forged["issuer"] = json!(network.did());
        let forged = forger
            .sign_document_for(forged, AUTHENTICATION)
            .await
            .unwrap();
        assert!(unverified(
            read(&serde_json::to_vec(&forged).unwrap(), network.did()).await
        ));

        // The network's key, for another purpose.
        let mut asserted = response();
        asserted["issuer"] = json!(network.did());
        let asserted = network
            .sign_document_for(asserted, ASSERTION_METHOD)
            .await
            .unwrap();
        assert!(unverified(
            read(&serde_json::to_vec(&asserted).unwrap(), network.did()).await
        ));

        // Changed after signing.
        let mut tampered: Value =
            serde_json::from_slice(&signed(&network, response()).await).unwrap();
        tampered["payload"]["ok"] = json!(false);
        assert!(unverified(
            read(&serde_json::to_vec(&tampered).unwrap(), network.did()).await
        ));
    }

    fn refusal() -> Value {
        json!({
            "id": "urn:uuid:3",
            "type": "https://trusttasks.org/spec/trust-task-error/0.6",
            "threadId": "urn:uuid:1",
            "payload": {
                "code": "vtn/membership/acknowledge:rolesUnregistered",
                "message": "register a group for clinical first",
                "details": { "roles": ["clinical"] },
            },
        })
    }

    #[tokio::test]
    async fn a_refusal_carries_its_code_and_details() {
        let network = Identity::generate();
        let body = signed(&network, refusal()).await;
        match read_answer::<Value>(409, &body, &request(), network.did(), &LocalDidKeyResolver)
            .await
        {
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

    #[tokio::test]
    async fn an_unsigned_refusal_is_a_refusal_and_a_forged_one_is_not() {
        let network = Identity::generate();
        let body = serde_json::to_vec(&refusal()).unwrap();
        assert!(matches!(
            read(&body, network.did()).await,
            Err(ClientError::Refused { .. })
        ));

        let mut forged = refusal();
        forged["issuer"] = json!(network.did());
        let forged = Identity::generate()
            .sign_document_for(forged, AUTHENTICATION)
            .await
            .unwrap();
        assert!(matches!(
            read(&serde_json::to_vec(&forged).unwrap(), network.did()).await,
            Err(ClientError::Unverified(_))
        ));
    }

    #[tokio::test]
    async fn a_client_with_no_resolver_sends_no_task() {
        // Nothing listens here: a send would fail as transport, not as unverified.
        let client = VtnClient::new("http://127.0.0.1:9");
        let me = Identity::generate();
        let sent = client.task(&me, "did:example:network", &payload()).await;
        assert!(matches!(sent, Err(ClientError::Unverified(_))), "{sent:?}");
    }
}
