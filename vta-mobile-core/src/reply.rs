//! The two ends of a request the device sends to its VTA: what may leave, and
//! what may be read when the answer comes back.
//!
//! **Outbound.** [`require_signed_request`] is checked by every transport send
//! in this crate ([`crate::mediator`], [`crate::tsp`]). The VTA and the VTC
//! accept a Trust Task over DIDComm or TSP only when it carries a Data
//! Integrity proof that verifies as its `issuer`, and that issuer is the
//! transport sender; the transport sender alone authorizes nothing. A document
//! that cannot pass that check is refused here, before it is sent, so the
//! failure names the document rather than arriving later as a `proofRequired`
//! from the peer.
//!
//! **Inbound.** [`verify_trust_task_reply`] is the gate a reply passes before
//! anything reads it: a proof by the expected peer under `authentication`,
//! threaded to the request, addressed to this device. The DIDComm transport
//! calls it itself ([`crate::mediator::MediatorSession::send_trust_task`]).
//! Over TSP the reply arrives on the inbox and is correlated natively, so the
//! native layer calls this export once it has matched the reply.

use crate::error::FfiError;

/// Verify `reply_json`, the reply to `request_json`, as the word of
/// `expected_signer` (the peer the request was sent to — the VTA DID).
///
/// Returns `Ok(())` only when the reply answers this request (`type` and
/// `threadId`), is issued by `expected_signer` to the request's issuer, and
/// carries a verifying `eddsa-jcs-2022` proof made by `expected_signer` with a
/// key it lists under `authentication`, under proof purpose `authentication`.
/// Error replies must pass too. Anything else is
/// [`FfiError::UnverifiedReply`]: discard the reply unread.
#[uniffi::export(async_runtime = "tokio")]
pub async fn verify_trust_task_reply(
    request_json: String,
    reply_json: String,
    expected_signer: String,
) -> Result<(), FfiError> {
    let request: serde_json::Value =
        serde_json::from_str(&request_json).map_err(|e| FfiError::InvalidInput {
            reason: format!("the request is not JSON: {e}"),
        })?;
    let reply: serde_json::Value =
        serde_json::from_str(&reply_json).map_err(|e| FfiError::UnverifiedReply {
            reason: format!("the reply is not JSON: {e}"),
        })?;
    crate::proof::verify_reply(&request, &reply, &expected_signer).await
}

/// Refuse to send `doc` unless it is a signed request from `holder_did` to
/// `peer_did`: it carries a `proof`, a non-empty `id`, an `issuedAt`, names
/// `holder_did` as `issuer` and `peer_did` as `recipient`.
///
/// This checks shape, not the signature: the builders in this crate are the
/// only producers and sign what they build. What it catches is a document that
/// was never signed, or one addressed or issued in a name other than this
/// session's, which the peer would refuse or — worse — which would be sent in
/// the wrong name.
pub(crate) fn require_signed_request(
    doc: &serde_json::Value,
    holder_did: &str,
    peer_did: &str,
) -> Result<(), FfiError> {
    let refuse = |reason: String| {
        Err(FfiError::InvalidInput {
            reason: format!("refusing to send the Trust Task: {reason}"),
        })
    };
    let field = |name: &str| doc.get(name).and_then(serde_json::Value::as_str);

    if doc.get("proof").is_none() {
        return refuse("it carries no proof".into());
    }
    if field("id").is_none_or(str::is_empty) {
        return refuse("it has no `id`".into());
    }
    if field("issuedAt").is_none() {
        return refuse("it has no `issuedAt`".into());
    }
    match field("issuer") {
        Some(issuer) if issuer == holder_did => {}
        Some(issuer) => {
            return refuse(format!(
                "it is issued by `{issuer}`, not by this session's holder `{holder_did}`"
            ));
        }
        None => return refuse("it names no issuer".into()),
    }
    match field("recipient") {
        Some(recipient) if recipient == peer_did => {}
        Some(recipient) => {
            return refuse(format!(
                "it is addressed to `{recipient}`, not to `{peer_did}`"
            ));
        }
        None => return refuse("it names no recipient".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::proof::REPLY_PROOF_PURPOSE;
    use crate::proof::test_support::{did_for, sign_as_with_purpose};

    const VTA: u8 = 21;
    const OTHER: u8 = 22;
    const HOLDER: u8 = 23;

    fn request() -> Value {
        json!({
            "id": "urn:uuid:request-1",
            "type": "https://trusttasks.org/spec/auth/whoami/0.1",
            "issuer": did_for(HOLDER),
            "recipient": did_for(VTA),
            "issuedAt": "2026-09-25T10:00:00Z",
            "payload": {},
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    /// The reply the VTA builds for [`request`] (`respond_with`: issuer and
    /// recipient swapped, `threadId` = request id), unsigned.
    fn reply() -> Value {
        json!({
            "id": "urn:uuid:reply-1",
            "type": "https://trusttasks.org/spec/auth/whoami/0.1#response",
            "threadId": "urn:uuid:request-1",
            "issuer": did_for(VTA),
            "recipient": did_for(HOLDER),
            "issuedAt": "2026-09-25T10:00:01Z",
            "payload": { "session": { "id": "s-1" } }
        })
    }

    async fn signed(mut doc: Value, seed: u8, purpose: &str) -> Value {
        sign_as_with_purpose(&mut doc, seed, purpose).await;
        doc
    }

    async fn verify(reply: &Value) -> Result<(), FfiError> {
        verify_trust_task_reply(request().to_string(), reply.to_string(), did_for(VTA)).await
    }

    fn refused(r: Result<(), FfiError>, needle: &str) {
        match r {
            Err(FfiError::UnverifiedReply { reason }) => assert!(
                reason.contains(needle),
                "expected a refusal mentioning `{needle}`, got `{reason}`"
            ),
            other => panic!("expected UnverifiedReply mentioning `{needle}`, got {other:?}"),
        }
    }

    // One runtime for the process-wide resolver, as in `resolver.rs`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reply_verification() {
        // Accepted: the peer's proof, under `authentication`, bound to this request.
        let good = signed(reply(), VTA, REPLY_PROOF_PURPOSE).await;
        verify(&good)
            .await
            .expect("a reply signed by the VTA verifies");

        // A signed error reply is accepted too — and an unsigned one is not.
        let mut error = reply();
        error["type"] = json!("https://trusttasks.org/spec/trust-task-error/0.5");
        error["payload"] = json!({ "code": "permissionDenied", "message": "no" });
        verify(&signed(error.clone(), VTA, REPLY_PROOF_PURPOSE).await)
            .await
            .expect("a signed refusal verifies");
        refused(verify(&error).await, "no proof");

        // Unsigned.
        refused(verify(&reply()).await, "no proof");

        // Signed under the wrong purpose.
        refused(
            verify(&signed(reply(), VTA, "assertionMethod").await).await,
            "proof purpose",
        );

        // Signed by somebody else, whether or not they also claim the issuer.
        refused(
            verify(&signed(reply(), OTHER, REPLY_PROOF_PURPOSE).await).await,
            "signed by",
        );
        let mut impostor = reply();
        impostor["issuer"] = json!(did_for(OTHER));
        refused(
            verify(&signed(impostor, OTHER, REPLY_PROOF_PURPOSE).await).await,
            "issued by",
        );

        // Threaded to another request (a replayed reply), or not threaded.
        let mut other_thread = reply();
        other_thread["threadId"] = json!("urn:uuid:request-0");
        refused(
            verify(&signed(other_thread, VTA, REPLY_PROOF_PURPOSE).await).await,
            "threaded to",
        );
        let mut no_thread = reply();
        no_thread.as_object_mut().unwrap().remove("threadId");
        refused(
            verify(&signed(no_thread, VTA, REPLY_PROOF_PURPOSE).await).await,
            "threadId",
        );

        // Addressed to another device.
        let mut elsewhere = reply();
        elsewhere["recipient"] = json!(did_for(OTHER));
        refused(
            verify(&signed(elsewhere, VTA, REPLY_PROOF_PURPOSE).await).await,
            "addressed to",
        );

        // An answer to a different question.
        let mut wrong_type = reply();
        wrong_type["type"] = json!("https://trusttasks.org/spec/device/set-wake/0.2#response");
        refused(
            verify(&signed(wrong_type, VTA, REPLY_PROOF_PURPOSE).await).await,
            "does not answer",
        );

        // Tampered after signing.
        let mut tampered = good.clone();
        tampered["payload"]["session"]["id"] = json!("s-2");
        refused(verify(&tampered).await, "verification failed");

        // A request that itself carried a `threadId` is answered on that thread.
        let mut threaded_request = request();
        threaded_request["threadId"] = json!("urn:uuid:thread-7");
        let mut threaded_reply = reply();
        threaded_reply["threadId"] = json!("urn:uuid:thread-7");
        let threaded_reply = signed(threaded_reply, VTA, REPLY_PROOF_PURPOSE).await;
        verify_trust_task_reply(
            threaded_request.to_string(),
            threaded_reply.to_string(),
            did_for(VTA),
        )
        .await
        .expect("a reply on the request's own thread verifies");
    }

    #[test]
    fn only_signed_requests_from_the_holder_to_the_peer_are_sent() {
        let holder = did_for(HOLDER);
        let vta = did_for(VTA);
        require_signed_request(&request(), &holder, &vta).expect("a signed request is sent");

        let refused = |doc: Value, needle: &str| match require_signed_request(&doc, &holder, &vta) {
            Err(FfiError::InvalidInput { reason }) => assert!(
                reason.contains(needle),
                "expected `{needle}`, got `{reason}`"
            ),
            other => panic!("expected a refusal mentioning `{needle}`, got {other:?}"),
        };

        let mut unsigned = request();
        unsigned.as_object_mut().unwrap().remove("proof");
        refused(unsigned, "no proof");

        let mut foreign = request();
        foreign["issuer"] = json!(did_for(OTHER));
        refused(foreign, "issued by");

        let mut misaddressed = request();
        misaddressed["recipient"] = json!(did_for(OTHER));
        refused(misaddressed, "addressed to");

        let mut undated = request();
        undated.as_object_mut().unwrap().remove("issuedAt");
        refused(undated, "issuedAt");

        let mut anonymous = request();
        anonymous["id"] = json!("");
        refused(anonymous, "`id`");
    }
}
