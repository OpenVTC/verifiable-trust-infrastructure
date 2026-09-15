//! The TSP transport binding: how a Trust Task is carried in a TSP payload.
//!
//! One module, both directions. Inbound frames are opened here and outbound
//! ones wrapped here, so the binding is a single fact about this service rather
//! than a convention each path remembers. That is the whole point of a binding
//! being a *thing* — the next transport added should be a module beside this
//! one, not an edit spread across every sender and receiver.
//!
//! Spec: `https://trusttasks.org/binding/tsp/0.1`, and the constant comes from
//! `trust-tasks-tsp` rather than a literal here so it moves when the binding
//! does.

use serde_json::Value;

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
pub(crate) fn wrap_envelope(document: &[u8]) -> Vec<u8> {
    // Serialised by hand rather than through `serde_json::to_vec` on a struct:
    // the document is already JSON bytes and reparsing it to re-serialise it
    // would be the only place in this path that could change what was signed.
    let mut out = Vec::with_capacity(document.len() + 96);
    out.extend_from_slice(br#"{"type":""#);
    out.extend_from_slice(trust_tasks_tsp::ENVELOPE_TYPE.as_bytes());
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
pub(crate) fn open_envelope(payload: &[u8]) -> Result<Vec<u8>, String> {
    let envelope: Value =
        serde_json::from_slice(payload).map_err(|e| format!("TSP payload is not JSON: {e}"))?;
    let envelope_type = envelope
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if envelope_type != trust_tasks_tsp::ENVELOPE_TYPE {
        return Err(format!(
            "TSP payload is not a `{}` envelope (got `{envelope_type}`)",
            trust_tasks_tsp::ENVELOPE_TYPE
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
}
