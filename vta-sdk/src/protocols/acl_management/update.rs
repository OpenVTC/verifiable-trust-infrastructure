use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::acl::ApproveScope;

use super::create::CreateAclResultBody;
use super::entry::{Approve, StepUp};

/// Request payload for canonical `acl/update/0.1`.
///
/// **The wire form is the canonical one** (#856): the Rust field names keep
/// their historical spellings, mapped onto the canonical members with serde
/// renames — the same compatibility-layer treatment #842 gave the response
/// via [`super::entry::AclEntry`]. `did` serializes as `subject`,
/// `allowed_contexts` as `scopes`, and the step-up / approve-authority
/// sub-concerns nest under the shared canonical [`StepUp`] / [`Approve`]
/// components rather than flattening into five loosely-related members.
///
/// Carries no `role`: canonical gives the role transition its own
/// task (`acl/change-role/0.1`) so it can be compare-and-swapped
/// against the subject's current role, which is what stops two admins
/// on a stale read from silently overwriting one another on the one
/// attribute where that is a privilege change.
///
/// Patch semantics throughout: `Some` sets, absent leaves unchanged. The
/// canonical spec's explicit-`null` clears (`label`, `expiresAt`,
/// `stepUp.approver`) are not expressible through plain `Option` fields —
/// absent and `null` deserialize identically — so clearing those members is
/// not offered here, consistent with the pre-canonical body. `allowedKeys` is
/// the exception: it carries a `double_option` so absent, explicit `null` and
/// an array stay three distinct intentions (#818).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateAclBody {
    /// VID of the entry to amend — canonical wire member `subject`.
    #[serde(rename = "subject")]
    pub did: String,
    /// Replacement human-readable label; omitted leaves it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Replacement scope set — canonical wire member `scopes`. Applied
    /// wholesale rather than merged; omitted leaves the set unchanged.
    #[serde(rename = "scopes", default, skip_serializing_if = "Option::is_none")]
    pub allowed_contexts: Option<Vec<String>>,
    /// Replacement expiry — canonical `expiresAt`, RFC 3339 on the wire
    /// (the store keeps epoch seconds; see [`super::entry::to_epoch`]).
    /// Omitted leaves the expiry unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional human-readable rationale, recorded with the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Replacement per-entry step-up configuration — canonical `stepUp`,
    /// the same shared component the response carries. `Some` sets the
    /// members it names; omitted leaves the configuration unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up: Option<StepUp>,
    /// Replacement approve-authority — canonical `approve`, the shared
    /// component from [`super::entry`]. Omit to leave it unchanged.
    ///
    /// **Clearing has to be expressible**, and it is: `Some(Approve::default())`
    /// serializes as `"approve": {}` — confers nothing — which is the wire
    /// spelling of "revoke this approver's authority". Before this existed,
    /// the only way to narrow or drop an approve scope was to delete the ACL
    /// entry and recreate it, which leaves the DID with no entry at all if
    /// the recreate fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve: Option<Approve>,
    /// Replace the signing-oracle key filter (#818). Three intentions, three
    /// spellings, exactly as `acl/update/0.1` specifies:
    ///
    /// - **omitted** → `None` — leave the filter unchanged;
    /// - **explicit `null`** → `Some(None)` — clear the filter (the subject
    ///   may again reach every key in its contexts — a privilege *increase*);
    /// - **an array** → `Some(Some(keys))` — set the filter to exactly these
    ///   ids; **the empty array is "no keys at all"**, never a wildcard.
    ///
    /// Replacement, not merge; a narrowing replacement is a privilege
    /// reduction (enforcement reads the stored row live in `sign_payload`
    /// gate 4, so it binds the subject's next sign request).
    ///
    /// The wire name is pinned to the canonical `allowedKeys` explicitly,
    /// rather than left to the struct's `rename_all` (#856 made the rest of
    /// this body canonical too): casing drift on this exact struct family once
    /// let an empty `allowed_contexts` mint a super-admin (#656/#658), so the
    /// rename is spelled out here and the round-trip test below pins it.
    #[serde(
        rename = "allowedKeys",
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_keys: Option<Option<Vec<String>>>,
}

/// Deserialize a member where **absent** and **explicit `null`** mean
/// different things: absent → `None` (field default), `null` → `Some(None)`,
/// a value → `Some(Some(v))`. Plain `Option<Option<T>>` cannot make the
/// distinction — serde folds `null` into the outer `None`.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

impl UpdateAclBody {
    /// The delegated step-up approver to set, if the request names one.
    /// `None` leaves it unchanged (the historical flat-field accessor).
    pub fn step_up_approver(&self) -> Option<String> {
        self.step_up.as_ref().and_then(|s| s.approver.clone())
    }

    /// The per-entry step-up override to set (`"self"` | `"delegated"`),
    /// if the request names one. `None` leaves it unchanged.
    pub fn step_up_require(&self) -> Option<String> {
        self.step_up.as_ref().and_then(|s| s.require.clone())
    }

    /// The approve-authority to set. `None` leaves it unchanged; clear is
    /// `Some(ApproveScope::None)` — an explicit value, not absence.
    pub fn approve_scope(&self) -> Option<ApproveScope> {
        self.approve.as_ref().map(Approve::to_scope)
    }
}

pub type UpdateAclResultBody = CreateAclResultBody;

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: serde_json::Value) -> UpdateAclBody {
        serde_json::from_value(json).unwrap()
    }

    /// Trap 2 (#818): pin the wire casing. `CreateAclBody` is the struct
    /// family where a camelCase/snake_case mismatch once let an empty
    /// `allowed_contexts` silently mint a super-admin (#656/#658) — the new
    /// member must round-trip under exactly one spelling.
    #[test]
    fn allowed_keys_round_trips_as_camel_case() {
        let b = UpdateAclBody {
            did: "did:key:zA".into(),
            label: None,
            allowed_contexts: None,
            expires_at: None,
            reason: None,
            step_up: None,
            approve: None,
            allowed_keys: Some(Some(vec!["key-1".into(), "key-2".into()])),
        };
        let v = serde_json::to_value(&b).unwrap();
        assert!(v.get("allowedKeys").is_some(), "{v}");
        assert!(v.get("allowed_keys").is_none(), "one spelling only: {v}");
        let back: UpdateAclBody = serde_json::from_value(v).unwrap();
        assert_eq!(
            back.allowed_keys,
            Some(Some(vec!["key-1".to_string(), "key-2".to_string()]))
        );
        // The snake_case spelling is NOT accepted — a misspelled member must
        // not silently read as "leave unchanged" under the pinned name while
        // the caller believes they narrowed the filter. (This body does not
        // deny unknown fields, matching its siblings, so the member is
        // ignored — the test documents that the pinned name is the only one
        // that takes effect.)
        let b = body(serde_json::json!({
            "subject": "did:key:zA", "allowed_keys": ["key-1"]
        }));
        assert_eq!(b.allowed_keys, None);
    }

    /// The three intentions decode to three different values: omitted =
    /// leave alone, explicit null = clear the filter, empty array = no keys.
    #[test]
    fn allowed_keys_distinguishes_absent_null_and_empty() {
        let absent = body(serde_json::json!({ "subject": "did:key:zA" }));
        assert_eq!(absent.allowed_keys, None, "omitted = leave unchanged");

        let null = body(serde_json::json!({ "subject": "did:key:zA", "allowedKeys": null }));
        assert_eq!(null.allowed_keys, Some(None), "null = clear the filter");

        let empty = body(serde_json::json!({ "subject": "did:key:zA", "allowedKeys": [] }));
        assert_eq!(
            empty.allowed_keys,
            Some(Some(vec![])),
            "empty array = authorized on NO keys — not a wildcard, not a clear"
        );
    }

    /// Serialization keeps the same three-way distinction (the SDK client
    /// sends this body): `Some(None)` must emit an explicit null.
    #[test]
    fn allowed_keys_clear_serializes_as_explicit_null() {
        let b = UpdateAclBody {
            did: "did:key:zA".into(),
            label: None,
            allowed_contexts: None,
            expires_at: None,
            reason: None,
            step_up: None,
            approve: None,
            allowed_keys: Some(None),
        };
        let v = serde_json::to_value(&b).unwrap();
        assert!(v.get("allowedKeys").is_some_and(|k| k.is_null()), "{v}");

        let untouched = UpdateAclBody {
            allowed_keys: None,
            ..b
        };
        let v = serde_json::to_value(&untouched).unwrap();
        assert!(v.get("allowedKeys").is_none(), "omitted stays omitted: {v}");
    }
}
