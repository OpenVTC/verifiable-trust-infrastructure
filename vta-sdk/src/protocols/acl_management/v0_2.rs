//! The canonical AclEntry **0.2** family — `acl/_shared/0.2/acl-entry` and the
//! `acl/{grant,show,update,change-role,revoke}/0.2` and `acl/list/0.3` bodies.
//!
//! 0.2 states every authority axis explicitly (CONVENTIONS §4–§5): `act`,
//! `keys` and `capabilities` are REQUIRED and each takes one of three shapes,
//! and an empty list is never a fourth one. That is the whole point of the
//! revision — 0.1's `scopes: []` meant *unrestricted* for an admin and
//! *nowhere* for every other role, so the authority a document conferred
//! depended on a convention the document did not carry.
//!
//! Every scope here is a closed sum type with **no `Default`**
//! (CONVENTIONS §5: "SHOULD NOT give any of them a default value"), so a
//! caller cannot build an entry without saying what it grants.
//!
//! These are the wire shapes only. How a VTA *stores* an entry — role plus a
//! context list, read through the role — and which 0.2 values it can hold is
//! server-side (`vta_service::operations::acl`); the client-side reading of a
//! VTA's answer back into [`crate::client::AclEntryResponse`] is in
//! `client::types`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::entry::StepUp;
use crate::acl::{ActScope, ApproveScope, ContextDirection};

/// `act` / `approve` — `acl/_shared/0.2/acl-entry#AuthorityScope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum AuthorityScope {
    /// Every context the maintainer holds.
    All,
    /// No context at all.
    None,
    /// The named contexts and their descendants. Never empty.
    Contexts { contexts: Vec<String> },
}

impl AuthorityScope {
    /// The shared [`ActScope`] this denotes.
    pub fn to_act_scope(&self) -> ActScope {
        match self {
            Self::All => ActScope::All,
            Self::None => ActScope::None,
            Self::Contexts { contexts } => ActScope::Contexts(contexts.clone()),
        }
    }

    /// The wire form of an [`ActScope`].
    pub fn from_act_scope(scope: &ActScope) -> Self {
        match scope {
            ActScope::All => Self::All,
            ActScope::None => Self::None,
            ActScope::Contexts(cs) if cs.is_empty() => Self::None,
            ActScope::Contexts(cs) => Self::Contexts {
                contexts: cs.clone(),
            },
        }
    }

    /// The internal [`ApproveScope`] this denotes, read as an approve scope.
    pub fn to_approve_scope(&self) -> ApproveScope {
        match self {
            Self::All => ApproveScope::All,
            Self::None => ApproveScope::None,
            Self::Contexts { contexts } => ApproveScope::Contexts(contexts.clone()),
        }
    }

    /// The wire form of an [`ApproveScope`].
    pub fn from_approve_scope(scope: &ApproveScope) -> Self {
        match scope {
            ApproveScope::All => Self::All,
            ApproveScope::None => Self::None,
            ApproveScope::Contexts(cs) if cs.is_empty() => Self::None,
            ApproveScope::Contexts(cs) => Self::Contexts {
                contexts: cs.clone(),
            },
        }
    }

    /// The contexts a `contexts` scope names; empty for `all` and `none`.
    pub fn contexts(&self) -> &[String] {
        match self {
            Self::Contexts { contexts } => contexts,
            _ => &[],
        }
    }

    /// Whether every context `other` reaches, this one reaches too — segment-
    /// aware ancestry, the order `acl/update/0.2` and `acl/revoke/0.2` compare
    /// act scopes by.
    pub fn includes(&self, other: &AuthorityScope) -> bool {
        match (self, other) {
            (Self::All, _) | (_, Self::None) => true,
            (_, Self::All) | (Self::None, _) => false,
            (Self::Contexts { contexts: mine }, Self::Contexts { contexts: theirs }) => {
                theirs.iter().all(|t| {
                    mine.iter()
                        .any(|m| crate::context_path::is_ancestor_or_self(m, t))
                })
            }
        }
    }
}

/// `keys` — `acl/_shared/0.2/acl-entry#KeyScope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum KeyScope {
    /// Every key the entry's act scope reaches.
    All,
    /// No key at all.
    None,
    /// Exactly these key ids. Never empty.
    Listed { keys: Vec<String> },
}

impl KeyScope {
    /// The wire form of the VTA's stored `allowed_keys`, where `None` is no
    /// filter and `Some(∅)` is no keys.
    pub fn from_allowed_keys(keys: Option<&[String]>) -> Self {
        match keys {
            None => Self::All,
            Some([]) => Self::None,
            Some(keys) => Self::Listed {
                keys: keys.to_vec(),
            },
        }
    }

    /// The stored `allowed_keys` form of this scope.
    pub fn to_allowed_keys(&self) -> Option<Vec<String>> {
        match self {
            Self::All => None,
            Self::None => Some(Vec::new()),
            Self::Listed { keys } => Some(keys.clone()),
        }
    }
}

/// A capability, optionally qualified — `#CapabilityRef`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityRef {
    pub capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// A capability held by an entry — `#CapabilityGrant`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityGrant {
    pub capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// `true`: a capability no role implies, held beside the role.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub additive: bool,
}

impl CapabilityGrant {
    /// An unqualified grant of `capability`.
    pub fn new(capability: impl Into<String>, additive: bool) -> Self {
        Self {
            capability: capability.into(),
            resource: None,
            additive,
        }
    }
}

/// `capabilities` — `#CapabilityScope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum CapabilityScope {
    /// The role's full ceiling.
    Ceiling,
    /// Nothing.
    None,
    /// `(ceiling ∩ non-additive grants) ∪ additive grants`. Never empty.
    Listed { grants: Vec<CapabilityGrant> },
}

/// `approveCapabilities` — `#ApproveCapabilityScope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum ApproveCapabilityScope {
    /// The role's full approve ceiling.
    Ceiling,
    /// Nothing.
    None,
    /// Exactly these. Never empty.
    Listed { grants: Vec<CapabilityRef> },
}

/// One access-control entry — `acl/_shared/0.2/acl-entry#AclEntry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AclEntry {
    pub subject: String,
    pub role: String,
    pub act: AuthorityScope,
    /// Absent confers nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve: Option<AuthorityScope>,
    pub capabilities: CapabilityScope,
    /// Absent confers nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve_capabilities: Option<ApproveCapabilityScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<String>,
    pub keys: KeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up: Option<StepUp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

impl AclEntry {
    /// An entry stating the three REQUIRED axes. Every other member starts
    /// absent: `approve` and `approveCapabilities` then confer nothing.
    pub fn new(
        subject: impl Into<String>,
        role: impl Into<String>,
        act: AuthorityScope,
        keys: KeyScope,
        capabilities: CapabilityScope,
    ) -> Self {
        Self {
            subject: subject.into(),
            role: role.into(),
            act,
            approve: None,
            capabilities,
            approve_capabilities: None,
            delegated_by: None,
            keys,
            label: None,
            created_at: None,
            created_by: None,
            updated_at: None,
            updated_by: None,
            expires_at: None,
            step_up: None,
            ext: None,
        }
    }

    /// The approve scope, absent read as none.
    pub fn approve_scope(&self) -> ApproveScope {
        self.approve
            .as_ref()
            .map(AuthorityScope::to_approve_scope)
            .unwrap_or_default()
    }
}

// ─── payloads ────────────────────────────────────────────────────────────
//
// The task payloads themselves are the generated `trust_tasks_rs::specs::acl`
// types; these build them as JSON from the shared components above, so a
// client and the VTA spell each member one way.

/// An `acl/grant/0.2` payload granting `entry`. `rollover` asks the VTA to
/// exercise the caller's hand-off marker instead (VTI-ACL-054), flagged by
/// [`HANDOFF_ROLLOVER_EXT_MEMBER`](super::create::HANDOFF_ROLLOVER_EXT_MEMBER).
pub fn grant_payload(entry: &AclEntry, reason: Option<&str>, rollover: bool) -> Value {
    let mut p = serde_json::json!({ "entry": entry });
    if let Some(r) = reason {
        p["reason"] = Value::String(r.to_string());
    }
    if rollover {
        p["ext"] = serde_json::json!({
            super::create::OPENVTC_EXT_NAMESPACE: {
                super::create::HANDOFF_ROLLOVER_EXT_MEMBER: true
            }
        });
    }
    p
}

/// An `acl/show/0.2` payload.
pub fn show_payload(subject: &str) -> Value {
    serde_json::json!({ "subject": subject })
}

/// An `acl/list/0.3` payload. `context` carries its direction, which 0.3
/// requires with a context and refuses without one.
pub fn list_payload(
    context: Option<(&str, ListDirection)>,
    cursor: Option<&str>,
    limit: Option<u64>,
) -> Value {
    let mut p = serde_json::Map::new();
    if let Some((ctx, d)) = context {
        p.insert("context".into(), Value::String(ctx.to_string()));
        p.insert("direction".into(), Value::String(d.as_str().to_string()));
    }
    if let Some(c) = cursor {
        p.insert("cursor".into(), Value::String(c.to_string()));
    }
    if let Some(l) = limit {
        p.insert("limit".into(), Value::from(l));
    }
    Value::Object(p)
}

/// An `acl/revoke/0.2` payload.
pub fn revoke_payload(subject: &str, revocation: &Revocation, reason: Option<&str>) -> Value {
    let mut p = serde_json::json!({ "subject": subject, "revocation": revocation });
    if let Some(r) = reason {
        p["reason"] = Value::String(r.to_string());
    }
    p
}

// ─── acl/update/0.2 members ──────────────────────────────────────────────

/// A replacement `stepUp` member of an `acl/update/0.2` amendment: `null`
/// clears a member, absence leaves it unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepUpReplacement {
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub approver: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub require: Option<Option<String>>,
}

// ─── acl/list/0.3 direction, acl/revoke/0.2 revocation ───────────────────

/// `acl/list/0.3` `direction` — 0.1's three questions, lowerCamelCase, and
/// with **no default**: it is required whenever `context` or `resource` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ListDirection {
    ActingIn,
    Subtree,
    Any,
}

impl From<ListDirection> for ContextDirection {
    fn from(d: ListDirection) -> Self {
        match d {
            ListDirection::ActingIn => ContextDirection::ActingIn,
            ListDirection::Subtree => ContextDirection::Subtree,
            ListDirection::Any => ContextDirection::Any,
        }
    }
}

impl From<ContextDirection> for ListDirection {
    fn from(d: ContextDirection) -> Self {
        match d {
            ContextDirection::ActingIn => ListDirection::ActingIn,
            ContextDirection::Subtree => ListDirection::Subtree,
            ContextDirection::Any => ListDirection::Any,
        }
    }
}

impl ListDirection {
    /// The wire spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ActingIn => "actingIn",
            Self::Subtree => "subtree",
            Self::Any => "any",
        }
    }
}

/// What `acl/revoke/0.2` takes away (its `Revocation` definition).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Revocation {
    /// Remove the entry entirely.
    Entry,
    /// Narrow the act scope to `act`, strictly narrower than the stored one.
    Act { act: AuthorityScope },
}

fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry() -> AclEntry {
        AclEntry::new(
            "did:key:z6MkSubject",
            "admin",
            AuthorityScope::Contexts {
                contexts: vec!["ctx-a".into()],
            },
            KeyScope::All,
            CapabilityScope::Ceiling,
        )
    }

    #[test]
    fn scopes_are_tagged_by_scope() {
        assert_eq!(
            serde_json::to_value(AuthorityScope::All).unwrap(),
            json!({"scope": "all"})
        );
        assert_eq!(
            serde_json::to_value(KeyScope::Listed {
                keys: vec!["k".into()]
            })
            .unwrap(),
            json!({"scope": "listed", "keys": ["k"]})
        );
        assert_eq!(
            serde_json::to_value(CapabilityScope::Listed {
                grants: vec![CapabilityGrant::new("persona-holder", true)]
            })
            .unwrap(),
            json!({"scope": "listed", "grants": [{"capability": "persona-holder", "additive": true}]})
        );
        assert_eq!(
            serde_json::to_value(Revocation::Act {
                act: AuthorityScope::None
            })
            .unwrap(),
            json!({"kind": "act", "act": {"scope": "none"}})
        );
    }

    /// An entry without one of the REQUIRED axes is malformed, never read as
    /// unrestricted or as none (CONVENTIONS §4 rule 2).
    #[test]
    fn a_missing_axis_does_not_decode() {
        for missing in ["act", "keys", "capabilities"] {
            let mut v = serde_json::to_value(entry()).unwrap();
            v.as_object_mut().unwrap().remove(missing);
            assert!(
                serde_json::from_value::<AclEntry>(v).is_err(),
                "an entry without `{missing}` decoded"
            );
        }
    }

    #[test]
    fn includes_orders_act_scopes() {
        let ctx = |cs: &[&str]| AuthorityScope::Contexts {
            contexts: cs.iter().map(|s| s.to_string()).collect(),
        };
        assert!(AuthorityScope::All.includes(&ctx(&["a"])));
        assert!(!ctx(&["a"]).includes(&AuthorityScope::All));
        assert!(ctx(&["a"]).includes(&AuthorityScope::None));
        assert!(ctx(&["a"]).includes(&ctx(&["a/b"])));
        assert!(!ctx(&["a/b"]).includes(&ctx(&["a"])));
        assert!(!ctx(&["a"]).includes(&ctx(&["b"])));
        assert!(!AuthorityScope::None.includes(&ctx(&["a"])));
    }

    #[test]
    fn step_up_replacement_distinguishes_null_from_absent() {
        let r: StepUpReplacement = serde_json::from_value(json!({"approver": null})).unwrap();
        assert_eq!(r.approver, Some(None));
        assert_eq!(r.require, None);
    }

    #[cfg(feature = "client")]
    #[test]
    fn payloads_conform_to_the_published_schemas() {
        use crate::trust_tasks::*;
        let check = |uri: &str, v: Value| {
            let schema = trust_tasks_rs::schema_index::schema_for(uri)
                .unwrap_or_else(|| panic!("{uri} has a published schema"));
            trust_tasks_rs::validate::against_schema(schema, &v)
                .unwrap_or_else(|e| panic!("not canonical {uri}: {e}\n{v:#}"));
        };
        let mut e = entry();
        e.approve = Some(AuthorityScope::None);
        e.step_up = Some(StepUp {
            approver: Some("did:key:z6MkApprover".into()),
            require: None,
        });
        check(
            TASK_ACL_GRANT_0_2,
            grant_payload(&e, Some("onboarding"), false),
        );
        check(TASK_ACL_GRANT_0_2, grant_payload(&e, None, true));
        check(TASK_ACL_SHOW_0_2, show_payload("did:key:zA"));
        check(
            TASK_ACL_LIST_0_3,
            list_payload(Some(("ctx-a", ListDirection::Subtree)), Some("c"), Some(10)),
        );
        check(TASK_ACL_LIST_0_3, list_payload(None, None, None));
        check(
            TASK_ACL_UPDATE_0_2,
            json!({
                "subject": "did:key:zA",
                "act": AuthorityScope::All,
                "keys": KeyScope::None,
                "label": null,
                "expiresAt": null,
                "stepUp": StepUpReplacement { approver: Some(None), require: None },
            }),
        );
        check(
            TASK_ACL_REVOKE_0_2,
            revoke_payload("did:key:zA", &Revocation::Entry, None),
        );
        check(
            TASK_ACL_REVOKE_0_2,
            revoke_payload(
                "did:key:zA",
                &Revocation::Act {
                    act: AuthorityScope::None,
                },
                Some("offboarding"),
            ),
        );
    }
}
