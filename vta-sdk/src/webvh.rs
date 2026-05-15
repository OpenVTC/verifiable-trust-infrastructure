use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebvhServerRecord {
    pub id: String,
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebvhDidRecord {
    pub did: String,
    pub server_id: String,
    pub mnemonic: String,
    pub scid: String,
    pub context_id: String,
    pub portable: bool,
    pub log_entry_count: u32,
    /// Number of pre-rotation keys committed by the most recent log
    /// entry (matches `next_key_hashes.len()` of that entry). `0` means
    /// pre-rotation is disabled. Defaults to `0` for legacy records
    /// written before this field existed; the next update reads the
    /// effective value off the loaded log entry and persists it back.
    #[serde(default)]
    pub pre_rotation_count: u32,
    /// Next monotonically-increasing fragment id to use when minting a
    /// new verificationMethod (`#key-{n}`). Stays stable for the
    /// lifetime of the DID; never decremented. Defaults to `1` for
    /// legacy records — the next rotate-keys call performs a one-shot
    /// scan of the existing document and persists the correct value.
    #[serde(default = "default_next_fragment_id")]
    pub next_fragment_id: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_next_fragment_id() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_server_record_ignores_embedded_auth_fields() {
        let json = r#"{
            "id": "srv",
            "did": "did:webvh:Q...:vta.example.com:primary",
            "label": "edge",
            "access_token": "leaky-access",
            "access_expires_at": 42,
            "refresh_token": "leaky-refresh",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }"#;

        let record: WebvhServerRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.id, "srv");
        assert_eq!(record.did, "did:webvh:Q...:vta.example.com:primary");
        assert_eq!(record.label.as_deref(), Some("edge"));

        let serialized = serde_json::to_value(&record).unwrap();
        assert!(serialized.get("access_token").is_none());
        assert!(serialized.get("access_expires_at").is_none());
        assert!(serialized.get("refresh_token").is_none());
    }

    #[test]
    fn server_record_round_trips_as_metadata_only() {
        let record = WebvhServerRecord {
            id: "srv".into(),
            did: "did:webvh:abc:vta.example.com:primary".into(),
            label: Some("edge".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_value(&record).unwrap();
        assert!(json.get("access_token").is_none());
        assert!(json.get("access_expires_at").is_none());
        assert!(json.get("refresh_token").is_none());

        let restored: WebvhServerRecord = serde_json::from_value(json).unwrap();
        assert_eq!(restored.id, "srv");
        assert_eq!(restored.did, "did:webvh:abc:vta.example.com:primary");
        assert_eq!(restored.label.as_deref(), Some("edge"));
    }

    #[test]
    fn legacy_record_loads_with_default_pre_rotation_and_fragment_id() {
        // A record written by an earlier version of the VTA carries
        // neither `pre_rotation_count` nor `next_fragment_id`. Serde
        // defaults must let it deserialize cleanly so existing DIDs
        // keep working.
        let json = r#"{
            "did": "did:webvh:Q...:vta.example.com:primary",
            "server_id": "serverless",
            "mnemonic": "",
            "scid": "Q...",
            "context_id": "primary",
            "portable": false,
            "log_entry_count": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }"#;
        let r: WebvhDidRecord = serde_json::from_str(json).unwrap();
        assert_eq!(r.pre_rotation_count, 0);
        assert_eq!(r.next_fragment_id, 1);
    }

    #[test]
    fn record_with_new_fields_round_trips() {
        let r = WebvhDidRecord {
            did: "did:webvh:abc:vta.example.com:primary".into(),
            server_id: "serverless".into(),
            mnemonic: "".into(),
            scid: "abc".into(),
            context_id: "primary".into(),
            portable: false,
            log_entry_count: 3,
            pre_rotation_count: 2,
            next_fragment_id: 5,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let restored: WebvhDidRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pre_rotation_count, 2);
        assert_eq!(restored.next_fragment_id, 5);
        assert_eq!(restored.log_entry_count, 3);
    }
}
