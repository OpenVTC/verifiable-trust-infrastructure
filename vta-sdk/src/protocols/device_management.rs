//! Canonical `device/*` request bodies.
//!
//! The #888 fold, applied to the family it did not reach. These methods used to
//! build their payloads as an inline `json!` plus a conditional insert per
//! optional member:
//!
//! ```ignore
//! let mut payload = json!({ "consumerKind": …, "displayName": … });
//! if let Some(p) = platform { payload["platform"] = json!(p); }
//! ```
//!
//! That shape is not wrong — the conditional insert is what kept `null` off the
//! wire — but it is unguarded and untestable. Unguarded because the invariant
//! lives in the shape of an `if let` rather than in an attribute, so nothing
//! checks it: the `vta-sdk` null census walks these structs and would have
//! caught `keys/create`, and it cannot see an inline map. Untestable because a
//! conformance witness has no type to point at, so it hand-writes the JSON and
//! stops tracking the producer the moment the producer changes.
//!
//! With a body struct both fall out for free: `skip_serializing_if` is what
//! keeps the member absent, the census enforces it, and the witness is built
//! rather than transcribed.
//!
//! Members mirror `device/*/0.1`. Only what the client can actually send is
//! modelled — `attestation` and `keyCustody` are in the schema but have no
//! producer here yet, and a field nothing sets is a claim the type should not
//! make.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `device/register/0.1` — claim a `DeviceBinding` on the caller's ACL entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRegisterBody {
    /// The tagged `ConsumerKind` union (`{kind: "service", serviceKind: …}`).
    ///
    /// Stays a `Value` because the caller supplies it as one and the union has
    /// no Rust model here yet; modelling it is an API change, not a fold.
    pub consumer_kind: Value,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hpke_public_key: Option<String>,
}

/// `device/heartbeat/0.1` — refresh `lastSeenAt`, and `platform` if supplied.
///
/// Every member is optional: an empty body is the common case (a bare "still
/// here"), and it must serialize to `{}`, not to a map of nulls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceHeartbeatBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_seq: Option<u64>,
}

/// `device/disable/0.1` — disable a device by id; the record is kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDisableBody {
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `device/wipe/0.1` — remote-wipe a compromised or lost device.
///
/// `scope` and `reason` are both required by the spec: a wipe with no recorded
/// reason is an audit gap, and the schema refuses one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceWipeBody {
    pub device_id: String,
    /// `cache` | `cache-and-keys` | `full`.
    pub scope: String,
    pub reason: String,
}

/// The device's opaque push handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeHandle {
    pub gateway: String,
    pub handle: String,
}

/// `device/set-wake/0.1` — convey the device's `WakeHandle`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSetWakeBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_handle: Option<WakeHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_triggers: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the fold exists to make enforceable: an unset optional is
    /// absent, so a bare heartbeat is `{}` rather than a map of nulls.
    ///
    /// The old inline builder got this right by construction. Nothing checked
    /// it, and `keys/create` is what that costs when someone later reaches for
    /// a struct instead (#919).
    #[test]
    fn a_bare_heartbeat_is_an_empty_object() {
        assert_eq!(
            serde_json::to_value(DeviceHeartbeatBody::default()).expect("serialises"),
            serde_json::json!({})
        );
    }

    #[test]
    fn an_unset_register_member_is_absent() {
        let minimal = DeviceRegisterBody {
            consumer_kind: serde_json::json!({"kind": "companion", "formFactor": "desktop"}),
            display_name: "laptop".into(),
            platform: None,
            hpke_public_key: None,
        };
        assert_eq!(
            serde_json::to_value(&minimal).expect("serialises"),
            serde_json::json!({
                "consumerKind": {"kind": "companion", "formFactor": "desktop"},
                "displayName": "laptop",
            })
        );
    }

    /// Set members still reach the wire under their canonical camelCase names —
    /// the skip must not be reachable for `Some`.
    #[test]
    fn set_members_serialise_camel_case() {
        let full = DeviceRegisterBody {
            consumer_kind: serde_json::json!({"kind": "service", "serviceKind": "ai-agent"}),
            display_name: "agent".into(),
            platform: Some("macos".into()),
            hpke_public_key: Some("zHpke".into()),
        };
        let v = serde_json::to_value(&full).expect("serialises");
        assert_eq!(v.get("platform").and_then(Value::as_str), Some("macos"));
        assert_eq!(
            v.get("hpkePublicKey").and_then(Value::as_str),
            Some("zHpke")
        );
    }

    #[test]
    fn a_wake_handle_nests_under_its_camel_case_member() {
        let body = DeviceSetWakeBody {
            wake_handle: Some(WakeHandle {
                gateway: "apns".into(),
                handle: "opaque".into(),
            }),
            suggested_triggers: Some(vec!["message".into()]),
        };
        assert_eq!(
            serde_json::to_value(&body).expect("serialises"),
            serde_json::json!({
                "wakeHandle": {"gateway": "apns", "handle": "opaque"},
                "suggestedTriggers": ["message"],
            })
        );
    }
}
