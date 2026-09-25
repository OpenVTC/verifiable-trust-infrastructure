//! The envelope members a document this node signs as itself must carry
//! (VTI-KEY-107): `issuer` (this node), `recipient`, a unique `id` and a
//! whole-second `issuedAt`.
//!
//! [`seal_envelope`] runs immediately before the operational-key proof is
//! attached, so a proof never covers a document that is missing a member or
//! names another party as its issuer.

use serde_json::Value;

/// Which kind of document is being sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeRole {
    /// A request this node originates to a peer. It must already name this
    /// node as `issuer`, its `recipient`, and an `id`.
    Request,
    /// A response (success or `trust-task-error`) this node returns. It is
    /// issued by this node whatever the request named, and gets an `id` when
    /// the builder left one out. `recipient` is kept as the spine set it,
    /// because an early refusal may have no party to address.
    Response,
}

/// Why a document cannot be sealed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("the document is not a JSON object")]
    NotAnObject,
    #[error("the document names {found} as issuer, not this node ({expected})")]
    ForeignIssuer { found: String, expected: String },
    #[error("the document has no {0}")]
    Missing(&'static str),
    #[error("issuedAt is not an RFC 3339 time: {0}")]
    BadIssuedAt(String),
}

/// Complete and check the envelope of `doc` before `signer_did` signs it.
///
/// - `issuer`: a request must name `signer_did` (set when absent); a response
///   is set to `signer_did`.
/// - `id`: a request must carry one; a response gets a fresh `urn:uuid:` id
///   when it has none.
/// - `recipient`: a request must carry one.
/// - `issuedAt`: set to now when absent, and truncated to whole seconds in
///   `Z` form, the only form every verifier in the ecosystem accepts.
pub fn seal_envelope(
    doc: &mut Value,
    signer_did: &str,
    role: EnvelopeRole,
) -> Result<(), EnvelopeError> {
    let obj = doc.as_object_mut().ok_or(EnvelopeError::NotAnObject)?;

    let present = |v: Option<&Value>| v.and_then(Value::as_str).is_some_and(|s| !s.is_empty());

    match role {
        EnvelopeRole::Request => match obj.get("issuer").and_then(Value::as_str) {
            Some(found) if !found.is_empty() && found != signer_did => {
                return Err(EnvelopeError::ForeignIssuer {
                    found: found.to_string(),
                    expected: signer_did.to_string(),
                });
            }
            Some(found) if !found.is_empty() => {}
            _ => {
                obj.insert("issuer".into(), Value::String(signer_did.to_string()));
            }
        },
        EnvelopeRole::Response => {
            obj.insert("issuer".into(), Value::String(signer_did.to_string()));
        }
    }

    if !present(obj.get("id")) {
        match role {
            EnvelopeRole::Request => return Err(EnvelopeError::Missing("id")),
            EnvelopeRole::Response => {
                obj.insert(
                    "id".into(),
                    Value::String(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
                );
            }
        }
    }

    if role == EnvelopeRole::Request && !present(obj.get("recipient")) {
        return Err(EnvelopeError::Missing("recipient"));
    }

    let issued_at = match obj.get("issuedAt") {
        None | Some(Value::Null) => chrono::Utc::now(),
        Some(Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|_| EnvelopeError::BadIssuedAt(s.clone()))?
            .with_timezone(&chrono::Utc),
        Some(other) => return Err(EnvelopeError::BadIssuedAt(other.to_string())),
    };
    obj.insert(
        "issuedAt".into(),
        Value::String(issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ME: &str = "did:example:me";

    #[test]
    fn a_request_keeps_its_members_and_gets_whole_seconds() {
        let mut doc = json!({
            "id": "urn:uuid:1", "issuer": ME, "recipient": "did:example:peer",
            "issuedAt": "2026-09-25T10:11:12.987654+02:00",
        });
        seal_envelope(&mut doc, ME, EnvelopeRole::Request).unwrap();
        assert_eq!(doc["issuedAt"], "2026-09-25T08:11:12Z");
        assert_eq!(doc["id"], "urn:uuid:1");
        assert_eq!(doc["issuer"], ME);
    }

    #[test]
    fn a_request_naming_another_issuer_is_refused() {
        let mut doc = json!({ "id": "x", "issuer": "did:example:other", "recipient": "r" });
        assert!(matches!(
            seal_envelope(&mut doc, ME, EnvelopeRole::Request),
            Err(EnvelopeError::ForeignIssuer { .. })
        ));
    }

    #[test]
    fn a_request_without_id_or_recipient_is_refused() {
        let mut doc = json!({ "issuer": ME, "recipient": "r" });
        assert_eq!(
            seal_envelope(&mut doc, ME, EnvelopeRole::Request),
            Err(EnvelopeError::Missing("id"))
        );
        let mut doc = json!({ "id": "x", "issuer": ME });
        assert_eq!(
            seal_envelope(&mut doc, ME, EnvelopeRole::Request),
            Err(EnvelopeError::Missing("recipient"))
        );
    }

    #[test]
    fn a_response_is_issued_by_this_node_and_gets_an_id_and_time() {
        let mut doc = json!({ "type": "t", "issuer": "did:example:other", "payload": {} });
        seal_envelope(&mut doc, ME, EnvelopeRole::Response).unwrap();
        assert_eq!(doc["issuer"], ME);
        assert!(doc["id"].as_str().unwrap().starts_with("urn:uuid:"));
        let at = doc["issuedAt"].as_str().unwrap();
        assert!(at.ends_with('Z') && !at.contains('.'), "{at}");
    }

    #[test]
    fn an_unreadable_issued_at_is_refused() {
        let mut doc = json!({ "id": "x", "issuer": ME, "recipient": "r", "issuedAt": "soon" });
        assert!(matches!(
            seal_envelope(&mut doc, ME, EnvelopeRole::Request),
            Err(EnvelopeError::BadIssuedAt(_))
        ));
    }
}
