//! TSP (Trust Spanning Protocol) inbound handling.
//!
//! [`dispatch_one`] receives TSP messages off the VTA's **single** mediator
//! websocket — the *same* socket the DIDComm listener uses — and feeds each one
//! into the shared [`dispatch_trust_task_core`](crate::trust_tasks) spine that
//! REST and DIDComm also use. TSP is the highest-preference transport
//! (TSP > DIDComm > REST); this is its receive side.
//!
//! ## One socket, multiplexed
//!
//! The mediator permits **one websocket per DID**. The delivery-layer
//! `DidCommTransport` (D2 P2a) owns that socket and its `inbound()` surfaces
//! BOTH DIDComm and TSP frames off it (`Inbound.message.protocol` tags which);
//! the inbound loop (`super::service::handle_tsp`) hands each TSP frame's
//! cleartext payload + proven `sender_vid` to [`dispatch_one`]. There is **no
//! second websocket** — opening one (as the earlier standalone loop did) made
//! the mediator evict a connection as `w.websocket.duplicate-channel`, flapping
//! the VTA.
//!
//! ## Round-trip: the reply routes back over the same socket
//!
//! Each received Trust Task is dispatched on the shared spine and its response
//! envelope is returned to the sender **over TSP** — the inbound loop seals the
//! returned bytes to the proven `sender_vid` and routes them back over the same
//! mediator socket (`atm.tsp().send_routed([mediator_did, sender_vid])`). This
//! mirrors the DIDComm `handle_trust_task` bridge, which returns the same
//! framework document as its reply, so TSP and DIDComm callers get
//! byte-identical round-trip semantics off the shared `dispatch_trust_task_core`.

use affinidi_messaging_core::RelationshipRequest;
use tracing::info;

use crate::server::AppState;
use vta_sdk::tsp_binding::{open_envelope, wrap_envelope};

/// Per-message bridge: turn one unpacked TSP message into a dispatched Trust
/// Task on the shared spine and return the framework response envelope bytes.
///
/// `sender_vid` is the **proven** sender DID returned by TSP `unpack_bytes`
/// (verification already happened inside the TSP stack), so this only needs
/// to resolve the sender's ACL grant — exactly like the DIDComm
/// `handle_trust_task` bridge resolves its authcrypt sender. `payload` is
/// the Trust-Task envelope bytes (identical to the REST `POST
/// /api/trust-tasks` body and the DIDComm message body).
///
/// The returned `Vec<u8>` is the self-describing framework trust-task document
/// (its own `type` + status `code`); the caller seals + routes it back to the
/// sender over TSP. On an unknown / unauthorized sender (no ACL entry, or an
/// expired grant) the reply is a Trust-Task `permission_denied` **envelope**,
/// not a drop — the sender VID is cryptographically proven, so there is no
/// enumeration exposure, and a conformant Trust-Task client only understands
/// binding envelopes (identical to the DIDComm path).
pub async fn dispatch_one(app_state: &AppState, payload: &[u8], sender_vid: &str) -> Vec<u8> {
    // Learn-from-inbound: this frame is proof `sender_vid` is reachable over TSP
    // right now (the VID is cryptographically proven by TSP unpack), so record it
    // — device-push then prefers TSP over DIDComm for this DID while the record
    // stays fresh. Recorded regardless of authorization: reachability is a
    // transport fact, and only DIDs we later push to are ever queried.
    app_state.tsp_reach.record(sender_vid);
    tracing::debug!(sender = %sender_vid, "recorded TSP reachability (learn-from-inbound)");
    // The binding envelope comes off first: everything below — authorization,
    // dispatch, the reply — works on the Trust-Task document, exactly as the
    // REST and DIDComm paths do. Carriage is opened here and nowhere else.
    let document = match open_envelope(payload) {
        Ok(d) => d,
        Err(reason) => {
            info!(sender = %sender_vid, %reason, "refused a TSP frame that is not a binding envelope");
            // Not `reject_trust_task`: it re-parses the body and, when that
            // fails, replaces the caller's reason with its own "body did not
            // parse as a Trust Task document". Here the document may be
            // perfectly good and merely unwrapped, so that message would send
            // the sender to inspect the wrong thing.
            return wrap_envelope(&crate::trust_tasks::malformed_request_response(reason).body);
        }
    };
    let payload = document.as_slice();

    // The document and the VID we proved, and no decision of our own. Whether
    // this is a request to authorize, a response to deliver, or an error to stop
    // at is a fact about the document, so the spine reads it —
    // `accept_from_proven_sender` explains why that is not the transport's call
    // to make, and what it cost when it was. TSP seals to the recipient VID,
    // same guarantee as authcrypt.
    let outcome = crate::trust_tasks::transport::with_binding(
        "tsp",
        crate::trust_tasks::accept_from_proven_sender(
            app_state,
            sender_vid,
            payload,
            crate::trust_tasks::transport::TransportConfidentiality::EndToEnd,
        ),
    )
    .await;
    info!(
        sender = %sender_vid,
        status = %outcome.status,
        "TSP trust-task dispatched"
    );
    // "Nothing goes back" has to survive the wrapper. An empty body is the
    // signal `handle_tsp` reads to drop the reply rather than seal one, and
    // wrapping it unconditionally produced `{"type":…,"document":}` — a
    // malformed frame in place of silence. Only reachable since responses and
    // errors became outcomes that answer nothing.
    if outcome.body.is_empty() {
        return Vec::new();
    }
    // Sealed back in the same envelope it arrived in. A reply that dropped the
    // wrapper would make this binding asymmetric — conformant one way and not
    // the other — which is harder to notice than being wrong in both.
    wrap_envelope(&outcome.body)
}

// The delivery-layer inbound loop (`super::service::handle_tsp`) unpacks the
// TSP frame off the shared mediator websocket (via `DidCommTransport`) into a
// neutral `Inbound` with the proven `sender_vid`, calls [`dispatch_one`]
// directly, and seals + routes the reply back — so the framework
// `TspHandler`/`TspResponse` wrapper the old `start_with_tsp` path required is
// no longer needed.

/// What the VTA does about an inbound TSP relationship request (§7.2).
///
/// Separated from the sends so the *policy* can be tested without a mediator or
/// a socket. Every arm is a decision someone has to defend; one buried in an
/// `if` beside two `await`s is one nobody reviews.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlDecision {
    /// Send an accept (`XRFA`). The transport has already recorded the
    /// relationship; this completes it.
    Accept,
    /// Send a cancellation (`XRFD`), carrying why.
    ///
    /// Named for the wire action rather than the intent, because it serves
    /// **answering** a peer's cancellation of a mutual relationship (§7.3)
    /// rather than refusing anything. Calling it `Refuse` would make a courtesy
    /// read as hostility.
    ///
    /// Since affinidi-messaging-sdk 0.27.1 the transport sends that answer
    /// itself, while recording the peer's cancellation, so this fires only
    /// when *its* send failed and the answer is still owed. The relationship
    /// is already forgotten by then, so it is sent with
    /// `TspOps::answer_cancellation` — `cancel_relationship` would run the
    /// state machine and refuse `SendCancel` out of `None` (Keyring VTI-38).
    Cancel(&'static str),
    /// Send nothing. The message needed recording and nothing else.
    Nothing,
}

/// Decide what to do about a relationship request.
///
/// # Why there is no ACL check here
///
/// This was the open question in the Rev 3 plan, and it was settled by building
/// the alternative and watching it fail.
///
/// The ACL gate was first put *here*, refusing an invite from a sender with no
/// entry. The justification was diagnosability: §7.2.2 prescribes *drop*, so an
/// endpoint that stays silent is indistinguishable from a broken transport, and
/// an explicit refusal turns silence into an answer.
///
/// Building it showed the argument runs the other way. A peer sends its invite
/// and its first Trust Task together (§3.6 permits exactly that). Refusing the
/// invite means §7.2.2 then drops the Trust Task — so the peer's actual request
/// goes unanswered, and the `XRFD` it does get is a *control* message its
/// application layer never sees. The gate produced the silence it was meant to
/// prevent. `tsp_vta_trust_task`'s
/// `an_unauthorized_sender_is_refused_over_tsp_not_met_with_silence` caught it.
///
/// So the relationship is formed with any sender TSP has authenticated, and
/// **the ACL remains the only gate, where it already lives** — at the Trust
/// Task layer, which answers with a named `permissionDenied` envelope the peer
/// can act on. This costs nothing: a relationship grants no authority on its
/// own, every task behind it is still checked, and the sender VID is
/// cryptographically proven by `unpack`, so there is no enumeration exposure.
///
/// That is the explicit refusal the decision asked for. It is simply at the
/// layer that can express it.
pub fn decide_control(request: RelationshipRequest, reply_expected: bool) -> ControlDecision {
    match request {
        // §7.2.5: an invite may introduce a VID, whose signature the transport
        // verified before this was reached. Not gated here either, for the same
        // reason — the introduced VID gains a relationship and no authority,
        // and its own tasks meet the same ACL.
        RelationshipRequest::Invite => ControlDecision::Accept,
        // The peer accepted an invite this VTA sent. The transport recorded the
        // state change; answering an accept would start a loop.
        RelationshipRequest::Accept => ControlDecision::Nothing,
        // §7.3: a cancellation for a relationship held in both directions is
        // answered with one of our own before forgetting it. The transport
        // (affinidi-messaging-sdk 0.27.1+) sends that answer itself, and
        // `reply_expected` means "the answer is still owed": false once it
        // went out, or when none was due; true only when the transport's own
        // send failed. So this retries a failed answer and never sends a
        // second one. The condition is the transport's reading, deliberately
        // not re-derived here.
        RelationshipRequest::Cancel => {
            if reply_expected {
                ControlDecision::Cancel("the peer cancelled a mutual relationship (§7.3)")
            } else {
                ControlDecision::Nothing
            }
        }
        // `RelationshipRequest` is `#[non_exhaustive]`, so a request type this
        // build does not know is one upstream minor release away.
        //
        // Record and say nothing, rather than guess. Answering a request whose
        // meaning is unknown is how an endpoint agrees to something it cannot
        // describe; the transport has already recorded whatever state change
        // the message implied, so silence here loses nothing a later release
        // cannot add deliberately.
        _ => ControlDecision::Nothing,
    }
}

#[cfg(test)]
mod tests {

    use super::{ControlDecision, decide_control};
    use affinidi_messaging_core::RelationshipRequest;

    /// An invite is accepted from any sender TSP authenticated, because the ACL
    /// gate lives at the Trust Task layer.
    ///
    /// Gating it here was built first and then removed. A peer sends its invite
    /// and its first task together (§3.6 permits exactly that), so refusing the
    /// invite makes §7.2.2 drop the task — the peer's actual request goes
    /// unanswered and the `XRFD` it gets is a control message its application
    /// never sees. The gate produced the silence it existed to prevent. See
    /// `decide_control`'s docs, and
    /// `tsp_vta_trust_task::an_unauthorized_sender_is_refused_over_tsp_not_met_with_silence`,
    /// which is the test that caught it.
    #[test]
    fn an_invite_is_accepted_and_the_acl_gate_stays_at_the_task_layer() {
        assert_eq!(
            decide_control(RelationshipRequest::Invite, false),
            ControlDecision::Accept,
            "refusing here drops the peer's first task and answers it with nothing"
        );
    }

    /// Answering an accept would start a loop: the peer answers our answer.
    #[test]
    fn an_accept_is_not_answered() {
        assert_eq!(
            decide_control(RelationshipRequest::Accept, false),
            ControlDecision::Nothing
        );
    }

    /// §7.3 — and `reply_expected` is the transport's reading of the condition,
    /// deliberately not re-derived here. Since affinidi-messaging-sdk 0.27.1 it
    /// means "the answer is still owed": the transport answers a mutual
    /// cancellation itself, so `false` also covers "already answered", and
    /// answering then would send the peer a second cancellation.
    #[test]
    fn a_cancellation_is_answered_only_when_the_answer_is_still_owed() {
        assert_eq!(
            decide_control(RelationshipRequest::Cancel, false),
            ControlDecision::Nothing
        );
        assert!(matches!(
            decide_control(RelationshipRequest::Cancel, true),
            ControlDecision::Cancel(_)
        ));
    }

    use super::*;
    use crate::acl::{AclEntry, Role, store_acl_entry};
    use crate::test_support::build_signing_test_app_state;

    /// A frame carrying `document`, wrapped as the binding requires.
    fn framed(document: &str) -> Vec<u8> {
        wrap_envelope(document.as_bytes())
    }

    /// Open a reply and return the document inside, asserting the wrapper is
    /// there. Every one of these tests asserts on the *document*, so the
    /// wrapper has to come off in one shared place or three tests quietly stop
    /// checking it.
    fn document_of(reply: &[u8]) -> serde_json::Value {
        let envelope: serde_json::Value = serde_json::from_slice(reply).expect("reply is JSON");
        assert_eq!(
            envelope.get("type").and_then(|t| t.as_str()),
            Some(trust_tasks_tsp::ENVELOPE_TYPE),
            "a reply must be sealed in the binding envelope it arrived in: {envelope}"
        );
        envelope
            .get("document")
            .cloned()
            .expect("the envelope carries a document")
    }

    /// A sender with no ACL entry still gets a Trust-Task error **envelope**
    /// back (not a silent drop) — the sender VID is proven, so we reply like the
    /// DIDComm path. With this unparseable `{}` body the reject degrades to a
    /// `malformedRequest` envelope (a well-formed-but-unauthorized request would
    /// yield `permissionDenied`); either way the round-trip invariant under test
    /// holds: a non-empty error envelope is produced for the service to route
    /// back over TSP.
    #[tokio::test]
    async fn dispatch_one_unknown_sender_replies_with_error_envelope() {
        let (app_state, _dir) = build_signing_test_app_state().await;

        let body = dispatch_one(&app_state, &framed("{}"), "did:key:zUnauthorizedTspSender").await;

        assert!(
            !body.is_empty(),
            "unauthorized sender must get a reply envelope"
        );
        let doc = document_of(&body);
        assert!(
            doc.get("type").is_some() && doc.get("payload").is_some(),
            "reply should be a trust-task error document, got: {doc}"
        );
    }

    /// The live failure, pinned: a DID hosting server answering a task the VTA
    /// had itself sent came back and was ACL-refused as an unsolicited request,
    /// because the transport authorized before the spine could see it was a
    /// reply. It read as a missing ACL entry — and the fix that suggests itself,
    /// granting the peer standing, would hand it the right to send *requests*
    /// when all it ever needed was to answer.
    ///
    /// The sender has no ACL entry on purpose. A waiter is holding the thread,
    /// so the answer must reach it and nothing may go back.
    #[tokio::test]
    async fn a_reply_reaches_its_waiter_without_the_sender_needing_acl_standing() {
        let (app_state, _dir) = build_signing_test_app_state().await;

        const THREAD: &str = "urn:uuid:11111111-1111-1111-1111-111111111111";
        let mut waiting = app_state.pending_replies.register(THREAD);

        let response = serde_json::json!({
            "id": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "threadId": THREAD,
            "type": "https://trusttasks.org/spec/did-management/did/problem-report/0.1",
            "payload": {},
        })
        .to_string();

        let body = dispatch_one(
            &app_state,
            &framed(&response),
            "did:webvh:zHostingServerWithNoAclEntry",
        )
        .await;

        assert!(
            body.is_empty(),
            "a reply is delivered to its waiter, never answered — got: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            waiting.try_recv().is_ok(),
            "the waiting request must receive the answer it asked for"
        );
    }

    /// The other half of that rule, and the reason threading alone cannot settle
    /// it: a step-up `approve-response` and a `task-consent/decision` thread to
    /// the request that provoked them and are still *requests* — they carry the
    /// approval. With nobody waiting on the thread this must reach the normal
    /// pipeline, not be swallowed as a reply, or every ceremony waiting on a
    /// human would strand.
    #[tokio::test]
    async fn a_threaded_document_with_no_waiter_is_still_dispatched() {
        let (app_state, _dir) = build_signing_test_app_state().await;

        let threaded = serde_json::json!({
            "id": "urn:uuid:44444444-4444-4444-4444-444444444444",
            "threadId": "urn:uuid:nobody-is-waiting-on-this",
            "type": "https://trusttasks.org/spec/keys/create/0.1",
            "payload": {},
        })
        .to_string();

        let body = dispatch_one(&app_state, &framed(&threaded), "did:key:zSomeApprover").await;

        assert!(
            !body.is_empty(),
            "a threaded document nobody is waiting for is an ordinary request \
             and must still be answered"
        );
    }

    /// The loop: an error dispatched as a request, refused, and answered with
    /// another error — which the peer then does too. Neither side recognised the
    /// other's error as terminal, so one failure became a permanent exchange
    /// that stopped only when the mediator began rate-limiting.
    ///
    /// Nothing may go back here, whatever the sender's ACL standing.
    #[tokio::test]
    async fn an_inbound_error_is_terminal_and_is_never_answered() {
        let (app_state, _dir) = build_signing_test_app_state().await;

        let error_doc = serde_json::json!({
            "id": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "threadId": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "type": "https://trusttasks.org/spec/trust-task-error/0.5",
            "payload": {"code": "e.p.did.validation-error", "message": "nope"},
        })
        .to_string();

        let body = dispatch_one(&app_state, &framed(&error_doc), "did:key:zAnyPeer").await;

        assert!(
            body.is_empty(),
            "answering an error is the loop — got: {}",
            String::from_utf8_lossy(&body)
        );
    }

    /// An authorized sender reaches `dispatch_trust_task_core` and the bridge
    /// returns the framework response envelope bytes for the service to route
    /// back over TSP. The empty `{}` body is rejected by the core's envelope
    /// parser, but the point under test is that the ACL grant resolves and the
    /// spine produces a non-empty reply document.
    #[tokio::test]
    async fn dispatch_one_authorized_sender_returns_reply_envelope() {
        let (app_state, _dir) = build_signing_test_app_state().await;

        let did = "did:key:zAuthorizedTspSender";
        store_acl_entry(&app_state.acl_ks, &AclEntry::new(did, Role::Admin, "test"))
            .await
            .unwrap();

        let body = dispatch_one(&app_state, &framed("{}"), did).await;

        assert!(
            !body.is_empty(),
            "authorized sender must get a reply envelope"
        );
        document_of(&body);
    }

    /// The learn-from-inbound hook: dispatching any inbound TSP frame records its
    /// **proven** `sender_vid` as TSP-reachable, so subsequent device-push
    /// prefers TSP for that DID. Reachability is a transport fact recorded
    /// regardless of the auth outcome, so an unknown sender (which still gets a
    /// reply envelope) is marked reachable just the same.
    #[tokio::test]
    async fn dispatch_one_records_sender_as_tsp_reachable() {
        let (app_state, _dir) = build_signing_test_app_state().await;
        let did = "did:key:zTspDevice";

        assert!(
            !app_state.tsp_reach.fresh(did),
            "a DID we've never seen over TSP is not reachable"
        );

        let _ = dispatch_one(&app_state, &framed("{}"), did).await;

        assert!(
            app_state.tsp_reach.fresh(did),
            "an inbound TSP frame must mark its proven sender TSP-reachable"
        );
    }

    // ── The binding itself ──────────────────────────────────────────────────

    /// A frame sealed the way this workspace used to seal them — the bare
    /// document, no wrapper — is refused. Accepting it would keep the private
    /// dialect alive on the wire for as long as anyone spoke it.
    #[tokio::test]
    async fn a_bare_document_is_refused_as_carriage() {
        let (app_state, _dir) = build_signing_test_app_state().await;
        let bare = br#"{"id":"urn:uuid:1","type":"https://example.org/t","issuedAt":"2026-01-01T00:00:00Z","payload":{}}"#;

        let reply = dispatch_one(&app_state, bare, "did:key:zLegacySender").await;
        let doc = document_of(&reply);

        assert_eq!(doc["payload"]["code"], "malformedRequest");
    }

    /// And it is refused **for the right reason**. This is the one that earns
    /// its place: the obvious implementation routes the refusal through
    /// `reject_trust_task`, which re-parses the body and, on failure, replaces
    /// the caller's reason with "body did not parse as a Trust Task document".
    /// Here the document parses perfectly — it is the carriage that is wrong —
    /// so that message sends the sender to inspect the one thing that is fine.
    /// During a binding cutover it is the most misleading sentence this service
    /// could say.
    #[tokio::test]
    async fn the_refusal_names_the_carriage_not_the_document() {
        let (app_state, _dir) = build_signing_test_app_state().await;
        let bare = br#"{"id":"urn:uuid:1","type":"https://example.org/t","issuedAt":"2026-01-01T00:00:00Z","payload":{}}"#;

        let reply = dispatch_one(&app_state, bare, "did:key:zLegacySender").await;
        let message = document_of(&reply)["payload"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        assert!(
            message.contains("envelope"),
            "the refusal must name the envelope, not the document: {message}"
        );
        assert!(
            !message.contains("did not parse as a Trust Task document"),
            "this points the sender at a document that is perfectly well formed: {message}"
        );
    }

    /// A wrapper carrying someone else's binding is not ours to open.
    #[tokio::test]
    async fn an_envelope_of_the_wrong_type_is_refused() {
        let (app_state, _dir) = build_signing_test_app_state().await;
        let wrong =
            br#"{"type":"https://trusttasks.org/binding/didcomm/0.1/envelope","document":{}}"#;

        let reply = dispatch_one(&app_state, wrong, "did:key:zConfusedSender").await;
        let message = document_of(&reply)["payload"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        assert!(
            message.contains("binding/didcomm"),
            "the refusal must name what arrived, so a misconfigured peer can see it: {message}"
        );
    }
}
