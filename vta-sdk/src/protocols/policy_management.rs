//! `policy/*` — runtime management of the VTA's Policy Decision Point.
//!
//! The canonical family (`policy/list/0.2`, `policy/get/0.1`,
//! `policy/upsert/0.2`, `policy/delete/0.1`, `policy/evaluate/0.3`). Before
//! this, the VTA had **no** runtime policy surface at all: the only way to
//! change what the PDP enforced was to edit `config.toml` and restart, which is
//! why the declarative approvals model now lives in a policy row instead of a
//! config section.
//!
//! # Members this maintainer does not implement
//!
//! `policy/activate/0.1` and `policy/active/0.1` are **deliberately absent**.
//! Canonical models an activation pointer — one active module per slot — which
//! VTC needs (`active_policies:<purpose>`) but the VTA does not have: here the
//! active set is *every enabled row*, evaluated in priority order, so there is
//! no pointer to flip. Implementing `activate` would mean inventing a slot
//! concept purely to satisfy a URI, and `active` would return the same list
//! `policy/list` already returns. Absence is the honest answer; a caller gets
//! `UnsupportedType` rather than a surface that pretends.
//!
//! Correspondingly, `enabled` and `priority` **are** carried here (VTC omits
//! them) — they are exactly how this maintainer selects.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical `policy/_shared` **PolicyModule** — the projection of a stored
/// policy row returned by `list`, `get`, and `upsert`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PolicyModuleView {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Rego source. Entry point is the package's `decision` rule.
    pub module: String,
    /// Trust contexts this policy applies to; empty ⇒ all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to: Vec<String>,
    /// Higher runs first; the first non-null `decision` wins.
    pub priority: i32,
    pub enabled: bool,
    /// Monotone revision counter, and the optimistic-concurrency token
    /// `upsert`/`delete` check `expectedVersion` against.
    pub version: u64,
    pub created_at: String,
    pub updated_at: String,
    /// Ecosystem extension members. Carries the declarative approvals model
    /// (`openvtc.approvals` / `openvtc.approver-sets`) on the reserved row —
    /// see [`crate::approvals`].
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub ext: serde_json::Value,
}

/// `policy/list/0.2` request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListPoliciesBody {
    /// Restrict to policies applying in this context (an unscoped policy
    /// applies everywhere, so it matches every filter).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `policy/list/0.2` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListPoliciesResultBody {
    pub policies: Vec<PolicyModuleView>,
    /// Canonical-required: more matching modules exist beyond this page.
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `policy/get/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetPolicyBody {
    pub id: String,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `policy/get/0.1` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetPolicyResultBody {
    pub policy: PolicyModuleView,
}

/// `policy/upsert/0.2` request.
///
/// `module` is the Rego source and is **authoritative** — the maintainer
/// validates it, never invents it. A declarative approvals row additionally
/// carries its rules in `ext`, and the VTA re-derives the module from them and
/// refuses the write if the two disagree; see [`crate::approvals`] for why that
/// check exists rather than server-side synthesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpsertPolicyBody {
    /// Target row. Omit to let the maintainer allocate one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub module: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    /// Optional on the wire, defaulting to `true`, as `policy/upsert/0.2`
    /// declares (`"enabled": {"type": "boolean", "default": true}`).
    ///
    /// It was a bare `bool` here, so a conforming client that omitted it got
    /// `malformedRequest` — the same shape as `keys/create`'s `derivationPath`
    /// before #1123. A policy you bothered to write is one you meant to switch
    /// on, which is why the specification defaults it that way rather than
    /// making it required.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Optimistic concurrency: when present it MUST equal the row's current
    /// version, else the caller is overwriting a revision it never saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub ext: serde_json::Value,
}

/// `policy/upsert/0.2` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpsertPolicyResultBody {
    pub policy: PolicyModuleView,
    /// True when this call created a new row rather than revising one.
    pub created: bool,
}

/// `policy/delete/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeletePolicyBody {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Operator rationale, recorded in the audit row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `policy/delete/0.1` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeletePolicyResultBody {
    /// Id of the removed module.
    pub id: String,
    /// RFC 3339 removal timestamp.
    pub deleted_at: String,
}

/// `policy/upsert/0.2` declares `enabled` with `"default": true`.
fn enabled_by_default() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_body_is_camel_case_and_strict() {
        let body = UpsertPolicyBody {
            id: Some("approvals".into()),
            name: "n".into(),
            description: None,
            module: "package vta.policy".into(),
            applies_to: vec![],
            priority: Some(100),
            enabled: true,
            expected_version: Some(3),
            ext: serde_json::json!({ "openvtc.approvals": [] }),
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["expectedVersion"], 3);
        assert!(v.get("appliesTo").is_none(), "empty vec must be omitted");

        // snake_case must not deserialize — the recurring casing-drift defect
        // class (#656/#658) is exactly this.
        let snake = serde_json::json!({
            "name": "n", "module": "m", "enabled": true, "expected_version": 3
        });
        assert!(serde_json::from_value::<UpsertPolicyBody>(snake).is_err());
    }

    /// Canonical `policy/delete/0.1` names the removed module `id` and requires
    /// a `deletedAt`; an earlier draft here called it `deleted`, which the
    /// conformance witness caught.
    #[test]
    fn delete_result_matches_the_canonical_member_names() {
        let v = serde_json::to_value(DeletePolicyResultBody {
            id: "approvals".into(),
            deleted_at: "2026-08-09T00:00:00Z".into(),
        })
        .unwrap();
        assert_eq!(v["id"], "approvals");
        assert_eq!(v["deletedAt"], "2026-08-09T00:00:00Z");
    }
}
