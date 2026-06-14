use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Operator-visible metadata for a registered webvh hosting server.
///
/// **Public surface — never carry secret material.** Bearer tokens,
/// refresh tokens, and token-expiry timestamps for the daemon REST
/// auth flow live in a separate service-internal record
/// (`vta_service::webvh_store::WebvhServerAuthRecord`, keyspace prefix
/// `server-auth:`), not on this type. The split keeps tokens out of:
///
/// - REST `GET /webvh/servers` list responses,
/// - DIDComm `webvh.servers.list` results,
/// - Backup export payloads,
/// - Any future SDK consumer that reads `WebvhServerRecord`.
///
/// Legacy records on disk may still carry `access_token` /
/// `access_expires_at` / `refresh_token` fields embedded inline.
/// Serde's default behaviour ignores unknown fields, so those
/// legacy records deserialize cleanly into the new shape — the
/// embedded tokens are silently dropped on read. The VTA's restore
/// path explicitly wipes the `server-auth:` keyspace so a backup
/// from another VTA can't replay stale tokens here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WebvhServerRecord {
    pub id: String,
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

    /// `WebvhServerRecord` must never serialise token material on the
    /// wire, even if somehow given a record with those fields populated.
    /// We removed the fields from the struct entirely so the type
    /// system itself enforces this — pin the invariant.
    #[test]
    fn server_record_round_trips_without_token_fields() {
        let now = Utc::now();
        let r = WebvhServerRecord {
            id: "prod".into(),
            did: "did:web:daemon.example".into(),
            label: Some("prod hosting".into()),
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("access_token"),
            "access_token must not appear in serialised form: {json}"
        );
        assert!(
            !json.contains("refresh_token"),
            "refresh_token must not appear: {json}"
        );
        assert!(
            !json.contains("access_expires_at"),
            "access_expires_at must not appear: {json}"
        );
    }

    /// Legacy on-disk records (and legacy backups) may have embedded
    /// token fields. Serde's default behaviour ignores unknown fields,
    /// so the load path drops them silently — the new shape doesn't
    /// hold those values. Pin the invariant so a future
    /// `#[serde(deny_unknown_fields)]` doesn't reintroduce the leak.
    #[test]
    fn legacy_server_record_with_embedded_tokens_deserializes_cleanly() {
        let json = r#"{
            "id": "prod",
            "did": "did:web:daemon.example",
            "label": "prod",
            "access_token": "leaky-access-token",
            "access_expires_at": 9999999999,
            "refresh_token": "leaky-refresh-token",
            "created_at": "2026-05-01T00:00:00Z",
            "updated_at": "2026-05-01T00:00:00Z"
        }"#;
        let r: WebvhServerRecord = serde_json::from_str(json).expect("must accept legacy fields");
        assert_eq!(r.id, "prod");
        assert_eq!(r.did, "did:web:daemon.example");
        // Round-tripping the deserialised form drops the legacy fields.
        let reserialised = serde_json::to_string(&r).unwrap();
        assert!(
            !reserialised.contains("access_token"),
            "legacy fields must be dropped on re-serialise: {reserialised}"
        );
        assert!(
            !reserialised.contains("refresh_token"),
            "legacy fields must be dropped: {reserialised}"
        );
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
