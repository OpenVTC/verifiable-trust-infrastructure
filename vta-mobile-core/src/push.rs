//! Push registration — builds the DIDComm `set-device-info` / `delete-device-info`
//! messages a backgrounded mobile agent sends to its **mediator** to register or
//! clear its push channel (push wake-up binding,
//! `https://trusttasks.org/binding/push/0.1`; adopts Aries RFC 0699 APNs /
//! 0734 FCM as DIDComm v2 messages).
//!
//! The engine builds the message core (`{type, body}`); the native layer adds
//! envelope headers (`id`/`from`/`to`) and authcrypt-packs it onto the live
//! DIDComm channel. These messages only tell the mediator *where* to push — the
//! wake-up push itself is contentless and never carries Trust Task content.

use crate::error::FfiError;

const APNS_PROTOCOL: &str = "https://didcomm.org/push-notifications-apns/1.0";
const FCM_PROTOCOL: &str = "https://didcomm.org/push-notifications-fcm/1.0";

/// Which APNs environment issued the token — the mediator routes to the matching
/// Apple endpoint.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum ApnsEnvironment {
    Sandbox,
    Production,
}

/// A device's platform push channel — the body of a `set-device-info` message.
/// Mirrors the `PushRegistration` shape in the device-binding shared schema.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PushRegistration {
    /// Apple Push Notification service.
    Apns {
        token: String,
        topic: String,
        environment: ApnsEnvironment,
    },
    /// Firebase Cloud Messaging.
    Fcm { token: String },
    /// Web Push (RFC 8030). Carried out-of-band, not via a DIDComm
    /// `set-device-info` — the Aries push-notification protocols cover APNs/FCM
    /// only. Present here so the type mirrors the schema; building a message for
    /// it returns [`FfiError::Unimplemented`].
    WebPush {
        endpoint: String,
        p256dh: String,
        auth: String,
    },
}

/// The platform discriminator, for messages whose body carries no token
/// (e.g. `delete-device-info`).
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PushPlatform {
    Apns,
    Fcm,
    WebPush,
}

/// Builds the DIDComm `set-device-info` message (`{type, body}` JSON) the agent
/// sends to its mediator to register or refresh its push channel. The native
/// layer adds envelope headers and authcrypt-packs it before sending.
#[uniffi::export]
pub fn build_set_device_info(registration: PushRegistration) -> Result<String, FfiError> {
    let (protocol, body) = match registration {
        PushRegistration::Apns {
            token,
            topic,
            environment,
        } => {
            let service = match environment {
                ApnsEnvironment::Sandbox => "apns_sandbox",
                ApnsEnvironment::Production => "apns",
            };
            (
                APNS_PROTOCOL,
                serde_json::json!({
                    "device_token": token,
                    "service": service,
                    "topic": topic,
                }),
            )
        }
        PushRegistration::Fcm { token } => (
            FCM_PROTOCOL,
            serde_json::json!({ "device_token": token, "service": "fcm" }),
        ),
        PushRegistration::WebPush { .. } => {
            return Err(FfiError::Unimplemented {
                what: "web push registration uses RFC 8030 directly, not a DIDComm \
                       set-device-info message; APNs/FCM only"
                    .to_string(),
            });
        }
    };
    message(protocol, "set-device-info", body)
}

/// Builds the DIDComm `delete-device-info` message to unregister this device's
/// push channel (e.g. on logout).
#[uniffi::export]
pub fn build_delete_device_info(platform: PushPlatform) -> Result<String, FfiError> {
    let protocol = match platform {
        PushPlatform::Apns => APNS_PROTOCOL,
        PushPlatform::Fcm => FCM_PROTOCOL,
        PushPlatform::WebPush => {
            return Err(FfiError::Unimplemented {
                what: "web push is not registered via DIDComm set-device-info".to_string(),
            });
        }
    };
    message(protocol, "delete-device-info", serde_json::json!({}))
}

/// Assemble the `{type, body}` DIDComm message core and serialize it.
fn message(protocol: &str, verb: &str, body: serde_json::Value) -> Result<String, FfiError> {
    let msg = serde_json::json!({
        "type": format!("{protocol}/{verb}"),
        "body": body,
    });
    serde_json::to_string(&msg).map_err(|e| FfiError::InvalidInput {
        reason: format!("failed to serialize push message: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apns_set_device_info_shape() {
        let json = build_set_device_info(PushRegistration::Apns {
            token: "abc123".to_string(),
            topic: "org.openvtc.vta.agent".to_string(),
            environment: ApnsEnvironment::Production,
        })
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["type"],
            "https://didcomm.org/push-notifications-apns/1.0/set-device-info"
        );
        assert_eq!(v["body"]["device_token"], "abc123");
        assert_eq!(v["body"]["service"], "apns");
        assert_eq!(v["body"]["topic"], "org.openvtc.vta.agent");
    }

    #[test]
    fn apns_sandbox_maps_to_service() {
        let json = build_set_device_info(PushRegistration::Apns {
            token: "t".to_string(),
            topic: "x".to_string(),
            environment: ApnsEnvironment::Sandbox,
        })
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["body"]["service"], "apns_sandbox");
    }

    #[test]
    fn fcm_set_device_info_shape() {
        let json = build_set_device_info(PushRegistration::Fcm {
            token: "fcm-tok".to_string(),
        })
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["type"],
            "https://didcomm.org/push-notifications-fcm/1.0/set-device-info"
        );
        assert_eq!(v["body"]["service"], "fcm");
        assert_eq!(v["body"]["device_token"], "fcm-tok");
    }

    #[test]
    fn delete_device_info_shape() {
        let json = build_delete_device_info(PushPlatform::Fcm).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["type"],
            "https://didcomm.org/push-notifications-fcm/1.0/delete-device-info"
        );
        assert!(v["body"].as_object().unwrap().is_empty());
    }

    #[test]
    fn webpush_set_device_info_is_unimplemented() {
        let err = build_set_device_info(PushRegistration::WebPush {
            endpoint: "https://push.example/x".to_string(),
            p256dh: "k".to_string(),
            auth: "a".to_string(),
        })
        .unwrap_err();
        assert!(matches!(err, FfiError::Unimplemented { .. }));
    }
}
