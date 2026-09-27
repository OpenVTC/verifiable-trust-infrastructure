//! `auth/passkey/admin-list/0.1` — an administrator lists one member's
//! passkeys of one purpose. Specified upstream in
//! trustoverip/dtgwg-trust-tasks-tf#658.
//!
//! TODO(trust-tasks release carrying trust-tasks #658): replace this module
//! with the generated `trust_tasks_rs::specs::auth::passkey::admin_list::v0_1`
//! (its `Payload`, `Response`, `ListedCredential` and `error_codes`), drop its
//! entry from `UNPUBLISHED_CANONICAL_OK` in `tests/trust_task_manifest.rs`, and
//! raise the spine's proof census by one — the generated policy declares a
//! proof REQUIRED, which this build's registry cannot yet tell the spine.
//! Until then the handler refuses an unsigned document itself.
//!
//! A hand-written copy of the published schema: the same members, the same
//! required set, `additionalProperties: false` everywhere, and the framework's
//! `ext` rule (at least one member, each key a reverse-DNS namespace).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The bare type URI.
pub const TYPE_URI: &str = "https://trusttasks.org/spec/auth/passkey/admin-list/0.1";

/// The codes the specification declares.
pub mod error_codes {
    /// `notAdministrator` — the producer holds no administrator standing.
    pub const NOT_ADMINISTRATOR: &str = "auth/passkey/admin-list:notAdministrator";
    /// `subjectNotMember` — known, within authority, not a current member.
    pub const SUBJECT_NOT_MEMBER: &str = "auth/passkey/admin-list:subjectNotMember";
    /// `subjectUnknown` — no such subject within the administrator's
    /// authority, whether or not they exist elsewhere.
    pub const SUBJECT_UNKNOWN: &str = "auth/passkey/admin-list:subjectUnknown";
    /// `purposeNotSupported` — not disclosed to administrators here.
    pub const PURPOSE_NOT_SUPPORTED: &str = "auth/passkey/admin-list:purposeNotSupported";
}

/// `purpose`: which credentials to list. REQUIRED, no default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Purpose {
    Session,
    StepUp,
}

/// The request payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub subject: String,
    pub purpose: Purpose,
    #[serde(default)]
    pub ext: Option<Map<String, Value>>,
}

impl Payload {
    /// Parse and check `value` against the published schema.
    pub fn parse(value: &Value) -> Result<Self, String> {
        let p: Payload = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        if p.subject.is_empty() {
            return Err("/subject: must not be empty".into());
        }
        if let Some(ext) = &p.ext {
            check_ext(ext)?;
        }
        Ok(p)
    }
}

/// SPEC §4.5.1's `Ext`: at least one member, each key a reverse-DNS
/// namespace (`^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$`).
fn check_ext(ext: &Map<String, Value>) -> Result<(), String> {
    if ext.is_empty() {
        return Err("/ext: must have at least one member".into());
    }
    let segment = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    for key in ext.keys() {
        let mut parts = key.split('.');
        let first = parts.next().unwrap_or_default();
        let rest: Vec<&str> = parts.collect();
        let ok = first.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && segment(first)
            && !rest.is_empty()
            && rest.iter().all(|s| segment(s));
        if !ok {
            return Err(format!("/ext: key {key:?} is not a reverse-DNS namespace"));
        }
    }
    Ok(())
}

/// One credential, as the administrator sees it. Never key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListedCredential {
    pub credential_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    pub registered_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_count: Option<u32>,
}

/// The response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    pub subject: String,
    pub purpose: Purpose,
    pub credentials: Vec<ListedCredential>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CAROL: &str = "did:webvh:QmCarolScid3:acme-vtc.example:carol";

    #[test]
    fn accepts_what_the_schema_accepts() {
        let p = Payload::parse(&json!({ "subject": CAROL, "purpose": "stepUp" })).unwrap();
        assert_eq!(p.purpose, Purpose::StepUp);
        Payload::parse(&json!({
            "subject": CAROL, "purpose": "session", "ext": { "org.example": { "a": 1 } }
        }))
        .unwrap();
    }

    /// The published `payload.invalid-examples.json`, one for one.
    #[test]
    fn refuses_the_published_invalid_examples() {
        for bad in [
            json!({ "purpose": "stepUp" }),
            json!({ "subject": CAROL }),
            json!({ "subject": "", "purpose": "stepUp" }),
            json!({ "subject": CAROL, "purpose": "recovery" }),
            json!({ "subject": [CAROL, CAROL], "purpose": "stepUp" }),
            json!({ "subject": CAROL, "purpose": "stepUp", "includePublicKeys": true }),
            json!({ "subject": CAROL, "purpose": "stepUp", "ext": { "bare-key": { "anything": "here" } } }),
            json!({ "subject": CAROL, "purpose": "stepUp", "ext": {} }),
        ] {
            assert!(Payload::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_response_carries_only_the_listed_members() {
        let r = Response {
            subject: CAROL.into(),
            purpose: Purpose::StepUp,
            credentials: vec![ListedCredential {
                credential_id: "abc".into(),
                device_label: None,
                registered_at: "2026-09-25T10:04:00Z".into(),
                last_used_at: None,
                sign_count: Some(0),
            }],
        };
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({
                "subject": CAROL,
                "purpose": "stepUp",
                "credentials": [{ "credentialId": "abc", "registeredAt": "2026-09-25T10:04:00Z", "signCount": 0 }],
            })
        );
    }
}
