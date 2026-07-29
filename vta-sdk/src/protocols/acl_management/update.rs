use serde::{Deserialize, Serialize};

use crate::acl::ApproveScope;

use super::create::CreateAclResultBody;

/// Request payload for canonical `acl/update/0.1`.
///
/// Carries no `role`: canonical gives the role transition its own
/// task (`acl/change-role/0.1`) so it can be compare-and-swapped
/// against the subject's current role, which is what stops two admins
/// on a stale read from silently overwriting one another on the one
/// attribute where that is a privilege change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateAclBody {
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_contexts: Option<Vec<String>>,
    /// Set the delegated step-up approver VID. `Some` sets it; `None` leaves
    /// it unchanged (matching the other fields — clearing an existing
    /// approver isn't expressible here, consistent with `label`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_approver: Option<String>,
    /// Set the per-entry step-up override (`"self"` | `"delegated"`). `Some`
    /// sets it; `None` leaves it unchanged (consistent with the other fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_require: Option<String>,
    /// Set the approve scope to exactly this value; omit to leave unchanged.
    ///
    /// Unlike the create body — which takes `approve_all_contexts` +
    /// `approve_contexts` as two independent fields — this carries the enum
    /// itself, because **clearing has to be expressible**. With two flat fields
    /// there is no way to distinguish "revoke this approver's authority" from
    /// "leave it alone", and revoking is the case that matters most: before
    /// this existed, the only way to narrow or drop an approve scope was to
    /// delete the ACL entry and recreate it, which leaves the DID with no entry
    /// at all if the recreate fails.
    ///
    /// Clear is `Some(ApproveScope::None)` — an explicit value, not absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve_scope: Option<ApproveScope>,
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
    /// The wire name is pinned to the canonical `allowedKeys` (the rest of
    /// this body is snake_case pending the #856 rename): casing drift on this
    /// exact struct family once let an empty `allowed_contexts` mint a
    /// super-admin (#656/#658), so the round-trip test below pins it.
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
            step_up_approver: None,
            step_up_require: None,
            approve_scope: None,
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
            "did": "did:key:zA", "allowed_keys": ["key-1"]
        }));
        assert_eq!(b.allowed_keys, None);
    }

    /// The three intentions decode to three different values: omitted =
    /// leave alone, explicit null = clear the filter, empty array = no keys.
    #[test]
    fn allowed_keys_distinguishes_absent_null_and_empty() {
        let absent = body(serde_json::json!({ "did": "did:key:zA" }));
        assert_eq!(absent.allowed_keys, None, "omitted = leave unchanged");

        let null = body(serde_json::json!({ "did": "did:key:zA", "allowedKeys": null }));
        assert_eq!(null.allowed_keys, Some(None), "null = clear the filter");

        let empty = body(serde_json::json!({ "did": "did:key:zA", "allowedKeys": [] }));
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
            step_up_approver: None,
            step_up_require: None,
            approve_scope: None,
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
