//! The generic sender: any **pinned** Trust Task by Type URI, which transport
//! it rides, and discovery of what the community serves.
//!
//! Every typed method on [`VtcClient`] is one signed Trust Task document sent
//! by the private `document` helper — over the mediated session when the
//! client holds one, otherwise signed with the operator's own key and posted
//! to the community's document endpoint. [`VtcClient::send_task`] is that same
//! sender with the task named by its Type URI, for a caller that has no typed
//! method for the task — the whole `vtc/groups/*`, `vtc/directory/*` and
//! `vtc/notifications/*` families have none — or that is itself generic, such
//! as an MCP bridge (`docs/05-design-notes/vtc-mcp.md`, D2).
//!
//! Three things it does that a typed method does by construction:
//!
//! - **Only a pinned version is sent.** The Type URI must be one
//!   `vti_specs::schema_index` knows. `None` there means "not pinned", and a
//!   sender that read it as "nothing to check" would fail open for exactly the
//!   versions nobody has looked at; so it is [`VtcError::UnpinnedTask`] and
//!   nothing leaves the process.
//! - **The payload is checked against the pinned schema before it is sent**,
//!   so a refusal says what is wrong, locally and naming the task, rather than
//!   arriving as the community's `malformedRequest` after a signed send.
//! - **The declared error codes and response size bound are the
//!   specification's own**, read from the same index, so a `notFound` the task
//!   declares becomes [`VtcError::NotFound`] exactly as it does from the typed
//!   method.
//!
//! The bridge's retry story is unchanged by this module: over a session the
//! SDK's `VtaClient` owns the attempt and its document id; over HTTPS the post
//! is one attempt. The community claims a document's `id` before dispatching
//! it and answers a redelivery with the recorded response, so what keeps a
//! retry safe is the **same document**, never a classification table here.

use serde_json::Value;
use trust_tasks_rs::specs::trust_task_discovery::v0_4 as discovery;

use crate::{MAX_DOCUMENT_RESPONSE_BYTES, VtcClient, VtcError, decode_payload};

/// Which wire a client's Trust Tasks ride.
///
/// Workspace preference order, highest first: TSP, DIDComm, HTTPS. A session
/// client reports the leg its session uses; a keyed client reports HTTPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VtcTransport {
    /// TSP on the mediated session (the TSP leg of the one mediator socket).
    Tsp,
    /// DIDComm authcrypt on the mediated session.
    Didcomm,
    /// A signed document posted to the community's HTTPS document endpoint.
    Https,
}

impl std::fmt::Display for VtcTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tsp => "TSP",
            Self::Didcomm => "DIDComm",
            Self::Https => "HTTPS",
        })
    }
}

/// The `#response` Type URI of the bare request URI `type_uri`.
fn response_uri(type_uri: &str) -> String {
    format!("{type_uri}#response")
}

impl VtcClient {
    /// The transport this client's Trust Tasks ride, or `None` when this
    /// crate cannot name one: no session and no HTTPS base, or a session leg
    /// newer than this crate.
    ///
    /// A session client answers the leg its session uses, so a dual-transport
    /// community is reported as TSP when the TSP leg is enabled and DIDComm
    /// otherwise. A client built with a key or anonymously answers HTTPS
    /// while it has a base URL to post to.
    pub fn transport(&self) -> Option<VtcTransport> {
        #[cfg(feature = "didcomm")]
        if let Some(documents) = &self.documents {
            use vta_sdk::client::SurfaceTransport;
            return match documents.trust_task_transport() {
                SurfaceTransport::Tsp => Some(VtcTransport::Tsp),
                SurfaceTransport::Didcomm => Some(VtcTransport::Didcomm),
                SurfaceTransport::Rest => Some(VtcTransport::Https),
                // A leg the SDK added after this crate: not guessed at.
                _ => None,
            };
        }
        (!self.base_url.is_empty()).then_some(VtcTransport::Https)
    }

    /// Send any pinned Trust Task by its bare Type URI and return the
    /// `#response` document's payload.
    ///
    /// The one generic sender behind every admin verb, for a task with no
    /// typed method here or for a caller that is itself generic. It goes over
    /// the mediated session when this client holds one — the TSP leg when
    /// enabled, DIDComm otherwise — and is signed with the operator's own key
    /// and posted to `POST {base}/trust-tasks` only when it does not.
    ///
    /// # Errors
    ///
    /// - [`VtcError::UnpinnedTask`] for a Type URI `vti_specs::schema_index`
    ///   does not pin, and for a `#response` URI. Nothing is sent.
    /// - [`VtcError::InvalidPayload`] when `payload` does not satisfy the
    ///   pinned payload schema. Nothing is sent.
    /// - [`VtcError::NotAuthenticated`] for a client with neither a session
    ///   nor a key, and [`VtcError::NoRestTransport`] for one with a key and
    ///   no base URL.
    /// - [`VtcError::Parked`] when the community parked the operation for
    ///   other administrators' approval: not a refusal, nothing to resend.
    /// - [`VtcError::NotFound`] for a refusal carrying one of the task's
    ///   declared codes that says the thing is absent; otherwise
    ///   [`VtcError::Refused`] over a session or [`VtcError::Http`] over
    ///   HTTPS, carrying the `trust-task-error` document.
    pub async fn send_task(&self, type_uri: &str, payload: Value) -> Result<Value, VtcError> {
        if type_uri.contains('#') {
            return Err(VtcError::UnpinnedTask {
                type_uri: type_uri.to_string(),
                reason: "a request is sent by its bare Type URI, never a `#response` one".into(),
            });
        }
        let Some(entry) = vti_specs::schema_index::entry(type_uri) else {
            return Err(VtcError::UnpinnedTask {
                type_uri: type_uri.to_string(),
                reason: "not a Trust Task version this client pins (vti_specs::schema_index); \
                         a framework specification such as discovery has its own method"
                    .into(),
            });
        };
        let Some(schema) = entry.schema else {
            // A pinned version always generates with its payload schema; a
            // missing one is a build defect, and sending unchecked would hide
            // it behind the community's `malformedRequest`.
            return Err(VtcError::UnpinnedTask {
                type_uri: type_uri.to_string(),
                reason: "pinned without a payload schema; refusing to send unchecked".into(),
            });
        };
        trust_tasks_rs::validate::against_schema(schema, &payload).map_err(|e| {
            VtcError::InvalidPayload(format!(
                "does not conform to {type_uri}: {e} (an unset optional member is absent, \
                 never `null`)"
            ))
        })?;
        let declared = entry.error_codes.unwrap_or(&[]);
        let max_bytes = vti_specs::schema_index::max_document_bytes_for(&response_uri(type_uri))
            .unwrap_or(MAX_DOCUMENT_RESPONSE_BYTES);
        self.document(type_uri, payload, declared, max_bytes).await
    }

    /// Ask which Trust Tasks the community serves — `trust-task-discovery/0.4`.
    ///
    /// `patterns` are slug globs (`*`, `vtc/groups/*`, or an exact slug);
    /// empty means everything. The community answers only a caller it can
    /// identify — a session, or a signed document — so an anonymous client is
    /// [`VtcError::NotAuthenticated`].
    ///
    /// The answer says whether the community knows a task at a version, read
    /// off its own routing table. It is not a wire-compatibility check and is
    /// not the catalog: what this client may *send* is what it pins
    /// ([`send_task`](Self::send_task)), and the two are intersected by the
    /// caller. [`supported_type_uris`] flattens the answer to bare URIs.
    pub async fn discover(&self, patterns: &[&str]) -> Result<discovery::Response, VtcError> {
        use trust_tasks_rs::Payload as _;
        use trust_tasks_rs::validate::ValidatedPayload;
        let payload = serde_json::json!({ "patterns": patterns });
        discovery::Payload::validate_value(&payload)
            .map_err(|e| VtcError::InvalidPayload(e.to_string()))?;
        let reply = self
            .document(
                discovery::Payload::TYPE_URI,
                payload,
                &[],
                MAX_DOCUMENT_RESPONSE_BYTES,
            )
            .await?;
        decode_payload(reply, "trust-task-discovery")
    }
}

/// The bare Type URIs a discovery answer lists, whichever form each entry
/// took. An entry form this crate's framework version does not know is left
/// out rather than guessed at.
pub fn supported_type_uris(response: &discovery::Response) -> Vec<&str> {
    response
        .supported_types
        .iter()
        .filter_map(|item| match item {
            discovery::ResponseSupportedTypesItem::Uri(uri) => Some(uri.as_str()),
            discovery::ResponseSupportedTypesItem::Object { type_, .. } => Some(type_.as_str()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HolderKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const VTC_DID: &str = "did:web:vtc.example.com";
    const MEMBERS_LIST: &str = "https://trusttasks.org/spec/vtc/members/list/0.2";
    const GROUPS_CREATE: &str = "https://trusttasks.org/spec/vtc/groups/create/0.1";

    /// A deterministic Ed25519 `did:key` holder for signing in tests.
    fn holder() -> (String, HolderKey) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
        );
        let private = multibase::encode(multibase::Base::Base58Btc, signing.to_bytes());
        let key = HolderKey::from_did_key(&did, private).unwrap();
        (did, key)
    }

    /// One HTTP/1.1 request, read whole: the head to the blank line, then
    /// `Content-Length` bytes of body.
    async fn read_request(sock: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let head_end = loop {
            let mut chunk = [0u8; 4096];
            let n = sock.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before the request head");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let length: usize = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(str::to_owned)
            })
            .map(|v| v.trim().parse().unwrap())
            .unwrap_or(0);
        let mut body = buf[head_end..].to_vec();
        while body.len() < length {
            let mut chunk = [0u8; 4096];
            let n = sock.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before the request body");
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(length);
        (head, body)
    }

    /// A one-request VTC that answers the given `#response` document and hands
    /// back what it received.
    async fn one_shot_vtc(
        reply_type: &str,
        reply_payload: Value,
    ) -> (String, tokio::task::JoinHandle<(String, Value)>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let reply = serde_json::json!({
            "id": "urn:uuid:4d2c3f4e-1b2a-4c3d-8e9f-0a1b2c3d4e5f",
            "type": reply_type,
            "issuer": VTC_DID,
            "issuedAt": "2026-11-06T00:00:00Z",
            "payload": reply_payload,
        })
        .to_string();
        let served = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (head, body) = read_request(&mut sock).await;
            let document: Value = serde_json::from_slice(&body).expect("a JSON request body");
            sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            sock.shutdown().await.ok();
            (head, document)
        });
        (format!("http://127.0.0.1:{port}/v1"), served)
    }

    #[tokio::test]
    async fn an_unpinned_type_uri_is_refused_before_anything_is_sent() {
        let (_, key) = holder();
        // An unroutable base: a send would fail as a transport error, not as
        // the refusal this test expects.
        let client = VtcClient::with_key("http://192.0.2.1:9/v1", VTC_DID, key);
        let err = client
            .send_task(
                "https://trusttasks.org/spec/vtc/members/list/9.9",
                serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, VtcError::UnpinnedTask { ref type_uri, .. } if type_uri.ends_with("/9.9")),
            "{err}"
        );
        // Framework specifications are not in the pinned index either.
        let err = client
            .send_task(
                "https://trusttasks.org/spec/trust-task-discovery/0.4",
                serde_json::json!({ "patterns": [] }),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, VtcError::UnpinnedTask { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_response_type_uri_is_refused() {
        let (_, key) = holder();
        let client = VtcClient::with_key("http://192.0.2.1:9/v1", VTC_DID, key);
        let err = client
            .send_task(&format!("{MEMBERS_LIST}#response"), serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, VtcError::UnpinnedTask { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_payload_the_schema_rejects_is_refused_before_anything_is_sent() {
        let (_, key) = holder();
        let client = VtcClient::with_key("http://192.0.2.1:9/v1", VTC_DID, key);
        let err = client
            .send_task(MEMBERS_LIST, serde_json::json!({ "role": 5 }))
            .await
            .unwrap_err();
        assert!(
            matches!(err, VtcError::InvalidPayload(ref m) if m.contains(MEMBERS_LIST) && m.contains("string")),
            "{err}"
        );
        // A family with no typed method is checked the same way.
        let err = client
            .send_task(GROUPS_CREATE, serde_json::json!({ "name": "x" }))
            .await
            .unwrap_err();
        assert!(matches!(err, VtcError::InvalidPayload(_)), "{err}");
    }

    #[tokio::test]
    async fn without_a_key_or_session_nothing_is_sent() {
        let client = VtcClient::anonymous("http://192.0.2.1:9/v1", VTC_DID);
        assert!(matches!(
            client.send_task(MEMBERS_LIST, serde_json::json!({})).await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.discover(&["vtc/*"]).await,
            Err(VtcError::NotAuthenticated)
        ));
    }

    #[tokio::test]
    async fn a_pinned_task_is_signed_posted_and_its_response_payload_returned() {
        let (did, key) = holder();
        let (base, served) = one_shot_vtc(
            &response_uri(GROUPS_CREATE),
            serde_json::json!({ "group": { "groupId": "g1" } }),
        )
        .await;
        let client = VtcClient::with_key(&base, VTC_DID, key);
        assert_eq!(client.transport(), Some(VtcTransport::Https));

        let payload = serde_json::json!({
            "name": "Gardeners",
            "kind": "static",
            "joinPolicy": "open",
            "visibility": "members",
            "showMembers": "members",
            "issuesCredentials": false,
            "reason": "the allotment working group",
        });
        let reply = client
            .send_task(GROUPS_CREATE, payload.clone())
            .await
            .unwrap();
        assert_eq!(reply["group"]["groupId"], "g1");

        let (head, document) = served.await.unwrap();
        assert!(head.starts_with("POST /v1/trust-tasks HTTP/1.1"), "{head}");
        assert_eq!(document["type"], GROUPS_CREATE);
        assert_eq!(document["payload"], payload);
        assert_eq!(document["issuer"], did);
        assert_eq!(document["recipient"], VTC_DID);
        assert!(document["proof"].is_object(), "the document is signed");
    }

    #[tokio::test]
    async fn a_declared_not_found_is_typed() {
        let (_, key) = holder();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let refusal = serde_json::json!({
            "id": "urn:uuid:4d2c3f4e-1b2a-4c3d-8e9f-0a1b2c3d4e50",
            "type": "https://trusttasks.org/spec/trust-task-error/0.3",
            "issuer": VTC_DID,
            "issuedAt": "2026-11-06T00:00:00Z",
            "payload": {
                "code": "vtc/groups/show:notFound",
                "message": "no such group",
                "details": { "reason": "notFound" }
            },
        })
        .to_string();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut sock).await;
            sock.write_all(
                format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{refusal}",
                    refusal.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        });
        let client = VtcClient::with_key(&format!("http://127.0.0.1:{port}/v1"), VTC_DID, key);
        let err = client
            .send_task(
                "https://trusttasks.org/spec/vtc/groups/show/0.1",
                serde_json::json!({ "groupId": "grp_0123456789abcdef" }),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, VtcError::NotFound { ref code, .. } if code == "vtc/groups/show:notFound"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn discovery_asks_0_4_and_flattens_the_answer() {
        let (_, key) = holder();
        let (base, served) = one_shot_vtc(
            "https://trusttasks.org/spec/trust-task-discovery/0.4#response",
            serde_json::json!({
                "frameworkVersion": "0.6.0",
                "supportedTypes": [
                    MEMBERS_LIST,
                    {
                        "type": GROUPS_CREATE,
                        "acceptanceWindow": { "clockSkewSeconds": 30, "maxAgeSeconds": 300 }
                    }
                ]
            }),
        )
        .await;
        let client = VtcClient::with_key(&base, VTC_DID, key);
        let answer = client.discover(&["vtc/*"]).await.unwrap();
        assert_eq!(
            supported_type_uris(&answer),
            vec![MEMBERS_LIST, GROUPS_CREATE]
        );
        let (_, document) = served.await.unwrap();
        assert_eq!(
            document["type"],
            "https://trusttasks.org/spec/trust-task-discovery/0.4"
        );
        assert_eq!(
            document["payload"]["patterns"],
            serde_json::json!(["vtc/*"])
        );
    }

    #[test]
    fn a_client_with_no_base_has_no_transport() {
        let (_, key) = holder();
        assert_eq!(VtcClient::with_key("", VTC_DID, key).transport(), None);
        assert_eq!(
            VtcClient::anonymous("https://vtc.example.com/v1", VTC_DID).transport(),
            Some(VtcTransport::Https)
        );
    }
}
