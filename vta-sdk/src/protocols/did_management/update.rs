//! Wire types for the webvh DID update + key rotation messages.
//!
//! Both REST (`POST /contexts/{ctx_id}/dids/{scid}/update`) and DIDComm
//! (`update-did-webvh` / `rotate-did-webvh-keys`) carry these bodies.
//! The result body is identical for both operations — `rotate_did_webvh_keys`
//! is a thin wrapper that drives the same flow as `update_did_webvh`
//! after rebuilding the document with fresh key bytes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Caller-supplied parameters for an update.
///
/// `witnesses` is carried as opaque JSON to keep this crate free of a
/// `didwebvh-rs` dependency. The vta-service handler deserializes it
/// into the library's `Witnesses` enum at intake.
/// Caller-supplied parameters for a webvh DID update.
///
/// **camelCase on the wire.** Every other Trust-Task payload in this SDK is
/// camelCase and so is every published spec; this type was the outlier, and the
/// cost of that was not theoretical. A caller sending the framework-conventional
/// `expectedVersionId` had it **silently discarded** — serde matched no field and
/// nothing rejected the unknown member — so the optimistic-concurrency
/// precondition simply never applied, and a concurrent update was overwritten by
/// a chain in which every signature still verified. That is the exact lost-update
/// this field exists to prevent.
///
/// The snake_case names remain accepted as aliases, so callers written against
/// the old shape keep working.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateDidWebvhBody {
    /// New DID document. `None` = keep existing. When `Some`, the VTA
    /// rotates `update_keys` + pre-rotation commitments as a parallel
    /// consequence.
    #[serde(default)]
    pub document: Option<Value>,
    /// Override pre-rotation count. `None` = keep current; `Some(0)`
    /// disables pre-rotation; `Some(n)` uses `n` new commitments.
    #[serde(default, alias = "pre_rotation_count")]
    pub pre_rotation_count: Option<u32>,
    /// New witness configuration as raw JSON (matches the library's
    /// `Witnesses` enum on the wire). The vta-service handler
    /// deserializes into the typed shape.
    #[serde(default)]
    pub witnesses: Option<Value>,
    /// New watcher URLs. `None` = keep current; `Some(vec![])` disables.
    #[serde(default)]
    pub watchers: Option<Vec<String>>,
    /// New TTL in seconds. `None` = keep current.
    #[serde(default)]
    pub ttl: Option<u32>,
    /// Operator-facing audit label.
    #[serde(default)]
    pub label: Option<String>,
    /// Optimistic-concurrency precondition. When `Some`, the VTA refuses
    /// the update if the DID's latest log entry no longer matches this
    /// versionId — i.e. someone else updated the DID between the
    /// caller's `GetDid` and this save. Lets a `get → edit → save` flow
    /// detect lost updates instead of silently overwriting another
    /// operator's edits with a chain that's structurally valid but
    /// content-wise based on a stale read.
    ///
    /// `None` (default) preserves prior behaviour for scripted callers
    /// that don't care about concurrent edits.
    #[serde(default, alias = "expected_version_id")]
    pub expected_version_id: Option<String>,
}

/// Caller-supplied parameters for a rotate-keys call.
///
/// camelCase on the wire, snake_case accepted as an alias — see
/// [`UpdateDidWebvhBody`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RotateDidWebvhKeysBody {
    /// Override pre-rotation count for the new commitment set.
    #[serde(default, alias = "pre_rotation_count")]
    pub pre_rotation_count: Option<u32>,
    /// Operator-facing audit label.
    #[serde(default)]
    pub label: Option<String>,
}

/// Result of a successful update or rotate-keys call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateDidWebvhResultBody {
    pub did: String,
    pub new_version_id: String,
    pub new_scid: String,
    pub new_log_entry: String,
    pub update_keys_count: u32,
    pub pre_rotation_key_count: u32,
    /// True when the DID is self-hosted (the VTA's stored
    /// `server_id` is `"serverless"`). The new log entry is
    /// persisted locally but NOT pushed to any webvh host — the
    /// operator must fetch the updated `did.jsonl` and redeploy it.
    /// `false` when the VTA published to a registered host as part
    /// of this call.
    ///
    /// `#[serde(default)]` for back-compat with VTAs that don't
    /// emit the field; absent → `false` (i.e. assume hosted, which
    /// keeps old CLIs from showing a spurious self-host hint).
    #[serde(default)]
    pub serverless: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_body_round_trips_minimal() {
        let body = UpdateDidWebvhBody::default();
        let json = serde_json::to_string(&body).unwrap();
        let restored: UpdateDidWebvhBody = serde_json::from_str(&json).unwrap();
        assert!(restored.document.is_none());
        assert!(restored.pre_rotation_count.is_none());
    }

    #[test]
    fn update_body_round_trips_full() {
        let body = UpdateDidWebvhBody {
            document: Some(serde_json::json!({"id": "did:webvh:abc"})),
            pre_rotation_count: Some(2),
            witnesses: None,
            watchers: Some(vec!["https://watcher.example.com".into()]),
            ttl: Some(3600),
            label: Some("rotate after audit".into()),
            expected_version_id: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        let restored: UpdateDidWebvhBody = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pre_rotation_count, Some(2));
        assert_eq!(restored.ttl, Some(3600));
        assert_eq!(restored.label.as_deref(), Some("rotate after audit"));
    }

    #[test]
    fn update_body_expected_version_id_round_trips_and_defaults_none() {
        // Absent on the wire → defaults to None (back-compat).
        let body: UpdateDidWebvhBody =
            serde_json::from_str(r#"{"document":{"id":"did:webvh:abc"}}"#).unwrap();
        assert!(body.expected_version_id.is_none());

        // Present → preserved.
        let body = UpdateDidWebvhBody {
            expected_version_id: Some("2-QmHash".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&body).unwrap();
        let restored: UpdateDidWebvhBody = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.expected_version_id.as_deref(), Some("2-QmHash"));
    }

    #[test]
    fn rotate_body_round_trips() {
        let body = RotateDidWebvhKeysBody {
            pre_rotation_count: Some(3),
            label: Some("scheduled".into()),
        };
        let json = serde_json::to_string(&body).unwrap();
        let restored: RotateDidWebvhKeysBody = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pre_rotation_count, Some(3));
    }

    #[test]
    fn result_body_round_trips() {
        let r = UpdateDidWebvhResultBody {
            did: "did:webvh:abc".into(),
            new_version_id: "3-zVer".into(),
            new_scid: "abc".into(),
            new_log_entry: "{\"versionId\":\"3-...\"}".into(),
            update_keys_count: 1,
            pre_rotation_key_count: 2,
            serverless: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let restored: UpdateDidWebvhResultBody = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.update_keys_count, 1);
        assert_eq!(restored.new_version_id, "3-zVer");
        assert!(restored.serverless);
    }

    /// Old VTA → new client: `serverless` absent on the wire must
    /// default to `false`, not fail deserialization. Pins the
    /// back-compat guarantee `#[serde(default)]` provides.
    #[test]
    fn result_body_serverless_defaults_to_false_when_absent() {
        let legacy = r#"{
            "did": "did:webvh:abc",
            "new_version_id": "3-zVer",
            "new_scid": "abc",
            "new_log_entry": "{}",
            "update_keys_count": 1,
            "pre_rotation_key_count": 2
        }"#;
        let r: UpdateDidWebvhResultBody = serde_json::from_str(legacy).unwrap();
        assert!(!r.serverless);
    }
}

#[cfg(test)]
mod casing_tests {
    use super::*;

    /// The bug this casing fixes, pinned.
    ///
    /// `expectedVersionId` is the optimistic-concurrency precondition: it is what
    /// stops a `get → edit → save` cycle from overwriting somebody else's edit
    /// with a chain that is structurally valid but based on a stale read.
    ///
    /// Before this, the field was snake_case only. A caller sending the
    /// framework-conventional camelCase had it **silently discarded** — serde
    /// matched no field, and with no `deny_unknown_fields` nothing rejected the
    /// unknown member. The precondition never applied. The lost update it exists
    /// to prevent happened anyway, and every signature in the resulting chain
    /// still verified.
    ///
    /// A silently-ignored safety precondition is worse than an absent one: it
    /// reads, in the caller's source, as though the danger were handled.
    #[test]
    fn the_concurrency_precondition_is_read_from_the_wire() {
        let camel: UpdateDidWebvhBody =
            serde_json::from_str(r#"{"expectedVersionId":"3-QmPrior"}"#).expect("camelCase parses");
        assert_eq!(
            camel.expected_version_id.as_deref(),
            Some("3-QmPrior"),
            "the framework's camelCase is the wire form and MUST reach the field"
        );

        // Callers written against the old shape keep working.
        let snake: UpdateDidWebvhBody =
            serde_json::from_str(r#"{"expected_version_id":"3-QmPrior"}"#)
                .expect("snake_case still parses");
        assert_eq!(snake.expected_version_id.as_deref(), Some("3-QmPrior"));
    }

    #[test]
    fn pre_rotation_count_reads_from_either_casing() {
        let camel: UpdateDidWebvhBody =
            serde_json::from_str(r#"{"preRotationCount":2}"#).expect("camelCase");
        assert_eq!(camel.pre_rotation_count, Some(2));

        let snake: UpdateDidWebvhBody =
            serde_json::from_str(r#"{"pre_rotation_count":2}"#).expect("snake_case");
        assert_eq!(snake.pre_rotation_count, Some(2));

        let rotate: RotateDidWebvhKeysBody =
            serde_json::from_str(r#"{"preRotationCount":3}"#).expect("camelCase");
        assert_eq!(rotate.pre_rotation_count, Some(3));
    }

    /// Single-word members are identical in both casings — no alias needed, and
    /// this pins that they were not broken by the rename.
    #[test]
    fn single_word_members_are_unaffected() {
        let b: UpdateDidWebvhBody =
            serde_json::from_str(r#"{"document":{"id":"did:webvh:x"},"ttl":600,"label":"l"}"#)
                .expect("parses");
        assert!(b.document.is_some());
        assert_eq!(b.ttl, Some(600));
        assert_eq!(b.label.as_deref(), Some("l"));
    }
}
