//! The canonical `AclEntry` — `acl/_shared/0.1/acl-entry`.
//!
//! Every `acl/*` task carries this one shape, which is what let the VTA's
//! private `vta/acl/*` family fold onto the canonical one (#840 phase A).
//!
//! Three things differ from the pre-fold VTA wire form, and each is the
//! canonical spelling rather than a rename for its own sake:
//!
//! - `did` → `subject`, `allowedContexts` → `scopes`. The canonical vocabulary
//!   is deliberately generic: a scope is an opaque identifier, which is what
//!   lets one ACL family serve a VTA's contexts, a hosting service's domains,
//!   and anything else with a containment relation.
//! - `expiresAt` is **RFC 3339**, not Unix epoch seconds. A timestamp that a
//!   human can read in a signed document is worth the conversion; the internal
//!   store keeps epoch seconds.
//! - `stepUpApprover` / `stepUpRequire` and the approve-authority pair are
//!   nested under [`StepUp`] and [`Approve`], grouping each per-entry
//!   sub-concern instead of flattening five loosely-related members.

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::acl::ApproveScope;

use super::create::CreateAclResultBody;

/// Per-entry step-up configuration — canonical `AclEntry.stepUp`.
///
/// **Additive only.** A per-entry setting may raise the assurance required of
/// this subject above the maintainer's system-wide floor; it must never lower
/// it. The effective requirement is the strictest of (floor, entry).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StepUp {
    /// VID that ratifies step-up for this subject. Absent → the subject is its
    /// own approver, when it holds a usable authenticator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    /// Minimum step-up mode: `self` or `delegated`. Absent → the system floor
    /// applies unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require: Option<String>,
}

impl StepUp {
    fn is_empty(&self) -> bool {
        self.approver.is_none() && self.require.is_none()
    }
}

/// Approve-authority — canonical `AclEntry.approve`.
///
/// What the subject may **confer on others** by ratifying an approval, as
/// distinct from `scopes`, which is what it may **exercise itself**. The two
/// are independent, which is what expresses a least-privilege approver: a party
/// that can authorize an operation in a scope it has no authority to perform.
///
/// Omission confers nothing — absent, `all: false` and an empty `scopes` all
/// mean "may ratify nothing", so a consumer that ignores this member grants
/// *less* than intended.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Approve {
    /// May confer any scope. Takes precedence over `scopes`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
    /// Scopes the subject may confer. Empty confers nothing; not a wildcard.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

impl Approve {
    fn is_empty(&self) -> bool {
        !self.all && self.scopes.is_empty()
    }

    /// The internal [`ApproveScope`] this wire form denotes.
    pub fn to_scope(&self) -> ApproveScope {
        if self.all {
            ApproveScope::All
        } else if self.scopes.is_empty() {
            ApproveScope::None
        } else {
            ApproveScope::Contexts(self.scopes.clone())
        }
    }

    /// The wire form of an internal [`ApproveScope`].
    pub fn from_scope(scope: &ApproveScope) -> Self {
        match scope {
            ApproveScope::None => Self::default(),
            ApproveScope::All => Self {
                all: true,
                scopes: Vec::new(),
            },
            ApproveScope::Contexts(cs) => Self {
                all: false,
                scopes: cs.clone(),
            },
        }
    }
}

/// One access-control entry — canonical `acl/_shared/0.1/acl-entry#AclEntry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AclEntry {
    /// VID of the party in the ACL.
    pub subject: String,
    /// Role identifier, interpreted by the maintainer.
    pub role: String,
    /// Opaque scope identifiers. For a VTA these are trust contexts.
    ///
    /// **Never read emptiness as "unrestricted".** An empty list means
    /// unrestricted only for an admin role and *authorized nowhere* for every
    /// other, so a check that ignores the role gets one of the two backwards.
    /// Resolve through the role, as `AclEntry::act_scope` does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
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
    /// When the entry stops being effective. RFC 3339 on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up: Option<StepUp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve: Option<Approve>,
}

/// Unix epoch seconds → RFC 3339, for the wire.
fn to_rfc3339(epoch: u64) -> Option<DateTime<Utc>> {
    i64::try_from(epoch)
        .ok()
        .and_then(|s| Utc.timestamp_opt(s, 0).single())
}

/// RFC 3339 → Unix epoch seconds, for the store. Pre-epoch instants clamp to
/// 0 rather than wrapping, which for an `expiresAt` reads as "already expired"
/// — the safe direction for a timestamp that gates authority.
pub fn to_epoch(ts: DateTime<Utc>) -> u64 {
    u64::try_from(ts.timestamp()).unwrap_or(0)
}

impl AclEntry {
    /// Build the wire form from the internal result body.
    pub fn from_result(r: &CreateAclResultBody) -> Self {
        let step_up = StepUp {
            approver: r.step_up_approver.clone(),
            require: r.step_up_require.clone(),
        };
        let approve = Approve {
            all: r.approve_all_contexts,
            scopes: r.approve_contexts.clone(),
        };
        Self {
            subject: r.did.clone(),
            role: r.role.clone(),
            scopes: r.allowed_contexts.clone(),
            label: r.label.clone(),
            created_at: to_rfc3339(r.created_at),
            created_by: Some(r.created_by.clone()),
            updated_at: None,
            updated_by: None,
            expires_at: r.expires_at.and_then(to_rfc3339),
            step_up: (!step_up.is_empty()).then_some(step_up),
            approve: (!approve.is_empty()).then_some(approve),
        }
    }

    /// The step-up approver this entry names, if any.
    pub fn step_up_approver(&self) -> Option<String> {
        self.step_up.as_ref().and_then(|s| s.approver.clone())
    }

    /// The per-entry step-up mode override, if any.
    pub fn step_up_require(&self) -> Option<String> {
        self.step_up.as_ref().and_then(|s| s.require.clone())
    }

    /// The approve-authority this entry carries. Absent → confers nothing.
    pub fn approve_scope(&self) -> ApproveScope {
        self.approve
            .as_ref()
            .map(Approve::to_scope)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_approve_and_step_up_are_omitted_not_emitted() {
        let e = AclEntry {
            subject: "did:key:z6MkA".into(),
            role: "reader".into(),
            scopes: vec![],
            label: None,
            created_at: None,
            created_by: None,
            updated_at: None,
            updated_by: None,
            expires_at: None,
            step_up: None,
            approve: None,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("approve").is_none(), "{v}");
        assert!(v.get("stepUp").is_none(), "{v}");
        assert!(v.get("scopes").is_none(), "empty scopes are omitted: {v}");
    }

    /// Omission and "confers nothing" must agree, so a consumer that drops the
    /// member grants less rather than more.
    #[test]
    fn absent_approve_confers_nothing() {
        let e: AclEntry =
            serde_json::from_value(serde_json::json!({"subject": "did:key:zA", "role": "admin"}))
                .unwrap();
        assert_eq!(e.approve_scope(), ApproveScope::None);
    }

    #[test]
    fn approve_all_takes_precedence_over_scopes() {
        let a = Approve {
            all: true,
            scopes: vec!["ctx-a".into()],
        };
        assert_eq!(a.to_scope(), ApproveScope::All);
    }

    #[test]
    fn approve_scope_round_trips() {
        for s in [
            ApproveScope::None,
            ApproveScope::All,
            ApproveScope::Contexts(vec!["a".into(), "b".into()]),
        ] {
            assert_eq!(Approve::from_scope(&s).to_scope(), s);
        }
    }

    #[test]
    fn expiry_round_trips_through_rfc3339() {
        let epoch = 1_800_000_000u64;
        let ts = to_rfc3339(epoch).expect("representable");
        assert_eq!(to_epoch(ts), epoch);
        assert_eq!(ts.to_rfc3339(), "2027-01-15T08:00:00+00:00");
    }

    /// The wire form is camelCase; the pre-fold snake_case names are gone.
    #[test]
    fn wire_form_is_camel_case() {
        let e = AclEntry {
            subject: "did:key:zA".into(),
            role: "admin".into(),
            scopes: vec!["ctx".into()],
            label: None,
            created_at: None,
            created_by: None,
            updated_at: None,
            updated_by: None,
            expires_at: to_rfc3339(1_800_000_000),
            step_up: Some(StepUp {
                approver: Some("did:key:zB".into()),
                require: Some("delegated".into()),
            }),
            approve: None,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("expiresAt").is_some(), "{v}");
        assert!(v.get("stepUp").is_some(), "{v}");
        assert!(v.get("allowed_contexts").is_none(), "{v}");
        assert!(v.get("did").is_none(), "subject, not did: {v}");
    }
}
