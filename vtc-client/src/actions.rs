//! The approver's side of the VTC's administrator action list
//! (`vtc/admin/actions/*`, `task-consent/decision/0.2`).
//!
//! An action carries the exact payload that will execute, its digest, and a
//! summary whose every field is a JSON Pointer into that payload. Before an
//! approver decides, [`verify_action`] recomputes the digest and re-derives
//! each field, refusing on any mismatch (VTI-APV-011 / -013): what the approver
//! reads is derived from what will run, not asserted beside it.
//! [`decision_for`] builds the decision over this approver's own challenge.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// `task-consent/decision/0.2`'s generated types, for a caller that decides.
pub use trust_tasks_rs::specs::task_consent::decision::v0_2 as decision_v0_2;

/// Domain tag of the challenge-salted digest an approver signs —
/// `vti_common::task_consent`'s, which the VTC and VTA share.
const DIGEST_DOMAIN: &[u8] = b"vta/task-consent/v1\0";

fn multihash(bytes: &[u8]) -> String {
    let mut mh = vec![0x12, 0x20];
    mh.extend_from_slice(&Sha256::digest(bytes));
    multibase::encode(multibase::Base::Base58Btc, mh)
}

fn jcs(payload: &Value) -> Result<String, String> {
    serde_json_canonicalizer::to_string(payload).map_err(|e| e.to_string())
}

/// An action's `payloadDigest`: SHA-256 over the payload's RFC 8785
/// canonicalisation, as a base58btc multihash.
pub fn payload_digest(payload: &Value) -> Result<String, String> {
    Ok(multihash(jcs(payload)?.as_bytes()))
}

/// The digest an approver's decision echoes: the type URI and canonical
/// payload, length-prefixed, salted with that approver's challenge.
pub fn wire_digest(type_uri: &str, payload: &Value, challenge: &str) -> Result<String, String> {
    let canonical = jcs(payload)?;
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update((type_uri.len() as u64).to_be_bytes());
    h.update(type_uri.as_bytes());
    h.update((canonical.len() as u64).to_be_bytes());
    h.update(canonical.as_bytes());
    h.update(challenge.as_bytes());
    let mut mh = vec![0x12, 0x20];
    mh.extend_from_slice(&h.finalize());
    Ok(multibase::encode(multibase::Base::Base58Btc, mh))
}

/// An action whose summary was re-derived from its payload.
#[derive(Debug, Clone)]
pub struct VerifiedAction {
    /// The title, its placeholders filled from the re-derived fields.
    pub title: String,
    /// The effect, likewise.
    pub effect: Option<String>,
    /// Each field's name and re-derived value, in name order.
    pub fields: Vec<(String, Value)>,
    /// The action as the VTC sent it.
    pub action: Value,
}

fn display(v: &Value) -> String {
    match v {
        Value::Null => "—".into(),
        Value::String(s) => s.clone(),
        Value::Array(items) if items.is_empty() => "none".into(),
        Value::Array(items) => items.iter().map(display).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

/// Recompute `payloadDigest` and re-derive every summary field from
/// `payload`. Refused on any mismatch: an action whose summary does not
/// follow from its payload must not be decided.
pub fn verify_action(action: &Value) -> Result<VerifiedAction, String> {
    let payload = &action["payload"];
    let claimed = action["payloadDigest"].as_str().unwrap_or_default();
    if payload_digest(payload)? != claimed {
        return Err("the action's payloadDigest does not match its payload".into());
    }
    let summary = &action["summary"];
    let mut fields = Vec::new();
    if let Some(map) = summary["fields"].as_object() {
        for (name, field) in map {
            let pointer = field["pointer"].as_str().unwrap_or_default();
            let derived = payload.pointer(pointer).cloned().unwrap_or(Value::Null);
            if derived != field["value"] {
                return Err(format!(
                    "the summary's {name} does not match the payload at {pointer}"
                ));
            }
            fields.push((name.clone(), derived));
        }
    }
    let fill = |prose: &str| {
        let mut out = prose.to_string();
        for (name, value) in &fields {
            out = out.replace(&format!("{{{name}}}"), &display(value));
        }
        out
    };
    Ok(VerifiedAction {
        title: fill(summary["title"].as_str().unwrap_or_default()),
        effect: summary["effect"].as_str().map(fill),
        fields,
        action: action.clone(),
    })
}

/// The `task-consent/decision/0.2` payload deciding `action`, over the
/// challenge this approver was shown. `None` when the action offers this
/// caller no challenge — they may not decide it now.
pub fn decision_for(
    action: &Value,
    approve: bool,
    reason: Option<&str>,
) -> Result<Option<trust_tasks_rs::specs::task_consent::decision::v0_2::Payload>, String> {
    let Some(challenge) = action["challenge"].as_str() else {
        return Ok(None);
    };
    let type_uri = action["typeUri"].as_str().unwrap_or_default();
    let mut payload = json!({
        "challenge": challenge,
        "payloadDigest": wire_digest(type_uri, &action["payload"], challenge)?,
        "decision": if approve { "approve" } else { "deny" },
        "actionId": action["actionId"],
    });
    if let Some(r) = reason {
        payload["reason"] = json!(r);
    }
    serde_json::from_value(payload)
        .map(Some)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action() -> Value {
        let payload =
            json!({ "subject": "did:key:z6MkSubject", "fromRole": "member", "toRole": "admin" });
        json!({
            "actionId": "act-0123456789abcdef",
            "typeUri": "https://trusttasks.org/spec/acl/change-role/0.1",
            "payload": payload,
            "payloadDigest": payload_digest(&payload).unwrap(),
            "challenge": "c".repeat(64),
            "summary": {
                "title": "Promote {subject} from {fromRole} to unrestricted administrator",
                "templateDigest": "zQmQX9Dx7cDqLtcoTNuDSWWo5nJTGecB9CqRLKgpd4es1c9",
                "fields": {
                    "subject": { "pointer": "/subject", "format": "did", "value": "did:key:z6MkSubject" },
                    "fromRole": { "pointer": "/fromRole", "format": "text", "value": "member" },
                },
            },
        })
    }

    #[test]
    fn a_summary_that_follows_from_its_payload_verifies() {
        let v = verify_action(&action()).unwrap();
        assert_eq!(
            v.title,
            "Promote did:key:z6MkSubject from member to unrestricted administrator"
        );
    }

    #[test]
    fn a_summary_that_does_not_is_refused() {
        let mut a = action();
        a["summary"]["fields"]["subject"]["value"] = json!("did:key:z6MkSomeoneElse");
        assert!(verify_action(&a).is_err());
        let mut a = action();
        a["payload"]["toRole"] = json!("moderator");
        assert!(verify_action(&a).is_err(), "digest no longer matches");
    }

    #[test]
    fn the_decision_echoes_the_salted_digest() {
        let a = action();
        let d = decision_for(&a, true, Some("ok")).unwrap().unwrap();
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["decision"], "approve");
        assert_eq!(v["actionId"], "act-0123456789abcdef");
        assert_ne!(v["payloadDigest"], a["payloadDigest"], "salted");
        let mut no = a.clone();
        no.as_object_mut().unwrap().remove("challenge");
        assert!(decision_for(&no, true, None).unwrap().is_none());
    }
}
