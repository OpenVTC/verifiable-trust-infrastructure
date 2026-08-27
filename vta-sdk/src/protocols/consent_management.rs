//! Canonical `consent/*` request bodies.
//!
//! The #888 fold, applied to the family `device/*` went through in #925. Same
//! reasoning, restated because it is the whole point: these methods built their
//! payloads as an inline `json!` plus a conditional insert per optional member,
//! which keeps `null` off the wire correctly but leaves the invariant living in
//! the shape of an `if let`. Nothing checks that — `vta-sdk`'s null census walks
//! structs under `protocols/`, and an inline map is invisible to it — and a
//! conformance witness has no type to point at, so it hand-writes the JSON and
//! stops tracking the producer.
//!
//! Members mirror `consent/*/1.0`. `subject` stays a `Value`: `ConsentSubject`
//! is a four-member object the caller already assembles, and modelling it is an
//! API change rather than a fold. `scope`, `effect` and `route` are schema
//! enums carried as `String` for the same reason — the producers take `&str`
//! today, and narrowing that is a separate, caller-visible decision.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `consent/request/1.0` — ask whether an inbound conversation may reach an agent.
///
/// `Default` is for the three optional members: `subject`, `scope` and
/// `challenge` are required by the schema, so a defaulted value of this struct
/// is not a valid payload — build it as `ConsentRequestBody { subject, scope,
/// challenge, ..Default::default() }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentRequestBody {
    pub subject: Value,
    /// `receive` | `converse`.
    pub scope: String,
    /// base64url nonce, `minLength` 16 — echoed by the matching decision.
    pub challenge: String,
    /// Operator-facing label for the approval prompt (e.g. `Signal group
    /// 'Family'`). MUST NOT carry a raw platform address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_hint: Option<String>,
    /// Multibase multihash over the JCS canonicalization of the held first
    /// message, binding the request to concrete content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_message_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_hint: Option<String>,
}

/// `consent/decision/1.0` — the operator's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentDecisionBody {
    pub subject: Value,
    /// The decision itself (`allow` / `deny` per the spec's `Effect`).
    pub effect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// `consent/revoke/1.0` — withdraw a previously granted consent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentRevokeBody {
    pub subject: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `consent/list/1.0` — enumerate consents, optionally filtered.
///
/// Every member is optional: an unfiltered list is the common call and must
/// serialize to `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentListBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Value>,
}

/// `consent/approver-set/1.0` — nominate the approver for a platform+context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentApproverSetBody {
    pub platform: String,
    pub context: String,
    pub approver: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_hint: Option<String>,
}

/// `consent/approver-list/1.0` — list configured approvers, optionally filtered.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentApproverListBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the fold makes enforceable: an unfiltered list is `{}`,
    /// not a map of nulls. The inline builders got this right by construction;
    /// nothing checked it, and `keys/create` is what that costs when someone
    /// later reaches for a struct instead (#919).
    #[test]
    fn unfiltered_list_bodies_are_empty_objects() {
        assert_eq!(
            serde_json::to_value(ConsentListBody::default()).expect("serialises"),
            serde_json::json!({})
        );
        assert_eq!(
            serde_json::to_value(ConsentApproverListBody::default()).expect("serialises"),
            serde_json::json!({})
        );
    }

    /// A request with no optional member set carries none of them — the
    /// required trio and nothing else.
    #[test]
    fn an_unset_hint_is_absent_from_a_request() {
        let body = ConsentRequestBody {
            subject: serde_json::json!({
                "platform": "signal",
                "conversationRef": "sig-1a2b3c4d",
                "kind": "dm",
                "agent": "did:key:z6MkAgent",
            }),
            scope: "converse".into(),
            challenge: "Y2hhbGxlbmdlLW5vbmNlLTEyOA".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&body).expect("serialises");
        assert!(v.get("displayHint").is_none());
        assert!(v.get("firstMessageDigest").is_none());
        assert!(v.get("contextHint").is_none());
        assert_eq!(v.as_object().expect("object").len(), 3);
    }

    /// …and every optional member reaches the wire under its camelCase name
    /// when set. `firstMessageDigest` is the one this was added for: the VTA
    /// dropped it and the SDK could not send it, so nothing in the stack named
    /// it and nothing failed.
    #[test]
    fn a_request_carries_every_optional_member_when_set() {
        let body = ConsentRequestBody {
            subject: serde_json::json!({"platform": "signal"}),
            scope: "converse".into(),
            challenge: "Y2hhbGxlbmdlLW5vbmNlLTEyOA".into(),
            display_hint: Some("Signal group 'Family'".into()),
            first_message_digest: Some("zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ".into()),
            context_hint: Some("ctx-a".into()),
        };
        let v = serde_json::to_value(&body).expect("serialises");
        assert_eq!(v["displayHint"], "Signal group 'Family'");
        assert_eq!(
            v["firstMessageDigest"],
            "zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ"
        );
        assert_eq!(v["contextHint"], "ctx-a");
        assert_eq!(v.as_object().expect("object").len(), 6);
    }

    /// Set members reach the wire under their canonical camelCase names — the
    /// skip must not be reachable for `Some`.
    #[test]
    fn set_members_serialise_camel_case() {
        let body = ConsentApproverSetBody {
            platform: "signal".into(),
            context: "openvtc".into(),
            approver: "did:key:z6MkApprover".into(),
            route: Some("push".into()),
            route_hint: Some("apns".into()),
        };
        let v = serde_json::to_value(&body).expect("serialises");
        assert_eq!(v.get("routeHint").and_then(Value::as_str), Some("apns"));
    }
}
