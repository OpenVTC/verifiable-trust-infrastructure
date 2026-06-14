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
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateDidWebvhBody {
    /// New DID document. `None` = keep existing. When `Some`, the VTA
    /// rotates `update_keys` + pre-rotation commitments as a parallel
    /// consequence.
    #[serde(default)]
    pub document: Option<Value>,
    /// Override pre-rotation count. `None` = keep current; `Some(0)`
    /// disables pre-rotation; `Some(n)` uses `n` new commitments.
    #[serde(default)]
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
    #[serde(default)]
    pub expected_version_id: Option<String>,
}

/// Caller-supplied parameters for a rotate-keys call.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RotateDidWebvhKeysBody {
    /// Override pre-rotation count for the new commitment set.
    #[serde(default)]
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
