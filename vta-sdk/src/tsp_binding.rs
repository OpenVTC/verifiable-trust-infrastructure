//! The TSP transport binding: how a Trust Task is carried in a TSP payload.
//!
//! One module, both directions, **one workspace**. Inbound frames are opened
//! here and outbound ones wrapped here, so the binding is a single fact rather
//! than a convention each path remembers. That is the whole point of a binding
//! being a *thing* — the next transport added should be a module beside this
//! one, not an edit spread across every sender and receiver.
//!
//! ## Why this lives in the SDK
//!
//! It was `vta-service`'s, which made it a single fact about *one side*. The
//! VTA's receiver started requiring the envelope while every Rust client in
//! this workspace — `session::TspSession`, `didcomm_session`'s TSP leg, and so
//! the `pnm health` probe, the mobile approver and `VtaClient`'s TSP trust
//! tasks — kept sealing the bare document, and the service refused every one of
//! them:
//!
//! ```text
//! refused a TSP frame that is not a binding envelope
//!   reason=TSP payload is not a `…/binding/tsp/0.1/envelope` envelope
//!          (got `…/spec/messaging/ping/0.1`)
//! ```
//!
//! A binding that only one end of the workspace can see is the same private
//! dialect it exists to end. `vta-sdk` is the leaf both sides already depend
//! on, so it is where a fact shared by both belongs.
//!
//! Spec: `https://trusttasks.org/binding/tsp/0.1`, and the constant comes from
//! `trust-tasks-tsp` rather than a literal here so it moves when the binding
//! does.
//!
//! ## Who this binding is *not* for
//!
//! The recipient decides, and today exactly one peer on the TSP wire does not
//! speak it: the **mediator's own management surface**. Its TSP arm parses the
//! bare document and claims it only when the type is one it serves
//! (`affinidi-messaging-mediator`'s `trust_tasks::parse_if_served`), so it has
//! no envelope to open and would file a wrapped frame as ordinary mail. That is
//! why [`crate::acl_setup::set_client_acl_over_tsp`] sends bare and must keep
//! doing so until the mediator adopts the binding. Every VTA/VTC-addressed
//! Trust Task goes through the wrapper.

use serde_json::Value;

/// The TSP binding's envelope type URI, re-exported so a caller that needs to
/// name it (a test, a log line) takes it from the same place the wrapper does.
pub use trust_tasks_tsp::ENVELOPE_TYPE;

/// The TSP binding's payload wrapper: `{"type": ENVELOPE_TYPE, "document": …}`.
///
/// ## Why TSP has a wrapper when the other two bindings do not
///
/// Each binding has to say "this payload is a Trust Task" somewhere the
/// framework can read before parsing. HTTPS says it with the request path
/// (`POST …/trust-tasks`); DIDComm says it with the message `type`. TSP has
/// neither — a TSP message carries a sender VID, a recipient VID and opaque
/// bytes — so the binding puts it in the JSON. The wrapper is not ceremony; it
/// is the only place TSP has to put it.
///
/// ## What this replaces
///
/// Both ends of this workspace used to seal the **bare document**, and said so
/// out loud: this module's own header called the payload "identical to the REST
/// body", and the browser wallet's `tsp-channel.ts` carried the comment "TSP
/// plaintext = the Trust-Task envelope JSON (no binding wrapper)". They agreed
/// with each other and with nothing else. A conformant peer built on
/// `trust-tasks-tsp` would have rejected every frame with `WrongEnvelopeType`,
/// and we would have rejected all of theirs — and neither side could have used
/// the binding crate at all, which is what makes "a new transport is a new
/// binding" untrue in practice.
#[must_use]
pub fn wrap_envelope(document: &[u8]) -> Vec<u8> {
    // Serialised by hand rather than through `serde_json::to_vec` on a struct:
    // the document is already JSON bytes and reparsing it to re-serialise it
    // would be the only place in this path that could change what was signed.
    let mut out = Vec::with_capacity(document.len() + 96);
    out.extend_from_slice(br#"{"type":""#);
    out.extend_from_slice(ENVELOPE_TYPE.as_bytes());
    out.extend_from_slice(br#"","document":"#);
    out.extend_from_slice(document);
    out.push(b'}');
    out
}

/// Open a TSP binding envelope, returning the Trust-Task document bytes.
///
/// A payload that is not an envelope, or carries the wrong `type`, is refused
/// rather than read as a document: accepting a bare document "just in case"
/// would keep the private dialect alive on the wire for as long as anyone spoke
/// it, and nothing is deployed that needs the kindness.
///
/// The two sides act on a refusal differently, and both are right. The VTA
/// *answers* it — the sender VID is proven, so a `malformedRequest` envelope
/// naming the carriage tells a misconfigured peer exactly what is wrong. A
/// client *skips* it: the frame arrived on a socket that also carries mediator
/// traffic and control frames, so "not our binding" there means "not addressed
/// to this layer", not "malformed".
pub fn open_envelope(payload: &[u8]) -> Result<Vec<u8>, String> {
    let envelope: Value =
        serde_json::from_slice(payload).map_err(|e| format!("TSP payload is not JSON: {e}"))?;
    let envelope_type = envelope
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if envelope_type != ENVELOPE_TYPE {
        return Err(format!(
            "TSP payload is not a `{ENVELOPE_TYPE}` envelope (got `{envelope_type}`)"
        ));
    }
    let document = envelope
        .get("document")
        .ok_or_else(|| "TSP envelope carries no `document`".to_string())?;
    serde_json::to_vec(document).map_err(|e| format!("re-serialise the document: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round trip: what goes in comes back out unchanged. The wrapper adds
    /// framing and must not reshape the document — the proof is taken over the
    /// document, so a wrapper that re-serialised it differently would break
    /// every signature while looking identical.
    #[test]
    fn wrapping_and_opening_returns_the_same_document_bytes() {
        let document = br#"{"id":"urn:uuid:1","payload":{"a":1,"b":[2,3]}}"#;
        let opened = open_envelope(&wrap_envelope(document)).expect("opens");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&opened).unwrap(),
            serde_json::from_slice::<serde_json::Value>(document).unwrap(),
        );
    }

    /// The shape this workspace used to put on the wire is not an envelope.
    /// Stated here as well as at the VTA's receiver because the *client* now
    /// depends on it too: `wrap_envelope` at every send is only load-bearing if
    /// a bare document is something the other end can tell apart.
    #[test]
    fn a_bare_document_is_not_an_envelope() {
        let bare = br#"{"id":"urn:uuid:1","type":"https://trusttasks.org/spec/messaging/ping/0.1","payload":{}}"#;

        let err = open_envelope(bare).expect_err("a bare document is not carriage");

        assert!(
            err.contains("binding/tsp"),
            "the refusal must name the binding that was expected: {err}"
        );
        assert!(
            err.contains("messaging/ping"),
            "and what actually arrived, so a misconfigured peer can see it: {err}"
        );
    }
}
