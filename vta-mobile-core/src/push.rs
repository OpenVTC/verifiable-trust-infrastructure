//! Push wake-up — the **gateway / trigger / device** model
//! (push wake-up binding, `https://trusttasks.org/binding/push/0.1`).
//!
//! A backgrounded mobile agent can't hold a mediator WebSocket open across OS
//! suspension, so it must be *woken*. The wake is a **contentless doorbell**; the
//! real (encrypted) Trust Task is still pulled from the mediator over DIDComm
//! pickup once the app is awake. Push never carries Trust-Task content.
//!
//! Three roles (see the binding): the **push gateway** holds the app's platform
//! push credentials (APNs / FCM / Web Push) and the `handle → token` map and is
//! the only party that can deliver a push; a **trigger** (the device's mediator
//! or its VTA) asks the gateway to wake a handle; the **device** registers its
//! token with the gateway and conveys the resulting opaque handle to its VTA.
//!
//! This module builds the two Trust Task documents the **device** sends; transport
//! (HTTPS for a URL gateway, or DIDComm authcrypt for a DID gateway / the VTA's
//! mediator) is the native layer's job, exactly as for the `auth/*` documents:
//!
//! 1. `build_push_register` → `push/register` to the **gateway**: register a
//!    platform token, get back an opaque [`WakeHandle`]. **No proof** — register
//!    is unauthenticated; the handle is opaque and useless until the controller
//!    VTA provisions a trigger for it. The raw token never leaves the gateway.
//! 2. `parse_push_register_response` → read the issued [`WakeHandle`].
//! 3. `build_device_set_wake` → `device/set-wake` to the **VTA**: convey the
//!    handle so the VTA can own the trigger allowlist and provision the gateway.
//!    **Proof-REQUIRED** — holder-signed via the native [`Signer`] (the VTA
//!    binds the wake channel to the subject). Omitting the handle clears the
//!    channel (the device becomes non-wakeable).
//! 4. `parse_device_set_wake_response` → whether the device is now push-capable
//!    and the effective allowlist the VTA provisioned.
//!
//! `push/provision` and `push/wake` are *not* device operations (they are
//! VTA→gateway and trigger→gateway respectively), so they are not built here.

use chrono::DateTime;
use trust_tasks_rs::specs::device::set_wake::v0_2 as set_wake;
use trust_tasks_rs::specs::push::register::v0_2 as register;
use trust_tasks_rs::{Payload, TrustTask};

use crate::error::FfiError;
use crate::keys::Signer;
use crate::proof::attach_did_signed_proof;

/// Which APNs environment issued the token — the gateway routes to the matching
/// Apple endpoint.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum ApnsEnvironment {
    Sandbox,
    Production,
}

/// A device's platform push channel — the token the device registers with its
/// push **gateway** (`push/register`). The gateway holds it in exchange for an
/// opaque [`WakeHandle`]; the raw token never leaves the gateway. Mirrors the
/// `PushRegistration` shape in the device-binding shared schema.
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
    /// Web Push (RFC 8030 endpoint + RFC 8291 encryption keys). Self-hostable
    /// via the gateway's VAPID keypair — no Apple/Google account required.
    WebPush {
        endpoint: String,
        p256dh: String,
        auth: String,
    },
}

/// The platform discriminator, for the advisory `pushPlatform` hint on
/// `device/set-wake` (the VTA never sees the token).
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PushPlatform {
    Apns,
    Fcm,
    WebPush,
}

/// Envelope fields the native layer supplies for a push / device Trust Task
/// (`id` / `issued_at` — the native layer owns identifiers and the clock).
/// `issuer` / `recipient` are optional because `push/register` is unauthenticated
/// and a REST gateway is addressed by URL (no recipient DID); `device/set-wake`
/// sets both (issuer = device holder DID, recipient = the VTA DID).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PushEnvelope {
    pub id: String,
    pub issued_at: String,
    pub issuer: Option<String>,
    pub recipient: Option<String>,
}

/// The opaque gateway-issued reference to a device's push channel. Reveals no
/// platform token. `gateway` is a DID (DIDComm gateway) or an https URL (REST
/// gateway); the device conveys this — never the token — to its VTA.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WakeHandle {
    pub gateway: String,
    pub handle: String,
}

/// Outcome of a `device/set-wake` — whether the device now has a usable wake
/// channel, and the effective trigger allowlist the VTA provisioned (absent when
/// the channel was cleared).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SetWakeOutcome {
    pub push_capable: bool,
    pub allowed_triggers: Option<Vec<String>>,
}

/// Build an unauthenticated `push/register/0.2` document the device sends to its
/// push **gateway** to register a platform token. **No proof** — the handle is
/// opaque and only becomes usable once the `controller_vta_did` provisions a
/// trigger for it. `controller_vta_did` is the DID of the VTA permitted to
/// provision this handle's allowlist (the device conveys the handle there next
/// via [`build_device_set_wake`]).
#[uniffi::export]
pub fn build_push_register(
    env: PushEnvelope,
    registration: PushRegistration,
    controller_vta_did: String,
) -> Result<String, FfiError> {
    let payload = register::Payload {
        registration: to_wire_registration(registration)?,
        controller_vta_did: register::PayloadControllerVtaDid::try_from(controller_vta_did)
            .map_err(conv)?,
        ext: None,
    };
    serialize(&envelope_doc(&env, payload)?)
}

/// Parse a `push/register/0.2#response` — the opaque [`WakeHandle`] the gateway
/// issued for the registered token.
#[uniffi::export]
pub fn parse_push_register_response(json: String) -> Result<WakeHandle, FfiError> {
    let doc: TrustTask<register::Response> = serde_json::from_str(&json).map_err(decode)?;
    Ok(WakeHandle {
        gateway: doc.payload.wake_handle.gateway.to_string(),
        handle: doc.payload.wake_handle.handle.to_string(),
    })
}

/// Build a signed `device/set-wake/0.2` the device sends to its **VTA** to convey
/// the opaque [`WakeHandle`] it obtained from the gateway. The VTA owns the
/// trigger allowlist and provisions the gateway on the device's behalf.
/// **Proof-REQUIRED** — holder-signed via the native [`Signer`], so the VTA binds
/// the wake channel to the subject. Pass `wake_handle: None` to **clear** the
/// channel (the VTA empties the gateway allowlist; the device becomes
/// non-wakeable). `push_platform` and `suggested_triggers` are advisory hints the
/// VTA MAY ignore (it never sees the token; it owns the final allowlist).
#[uniffi::export]
pub fn build_device_set_wake(
    env: PushEnvelope,
    wake_handle: Option<WakeHandle>,
    push_platform: Option<PushPlatform>,
    suggested_triggers: Vec<String>,
    signer: Box<dyn Signer>,
) -> Result<String, FfiError> {
    let wake_handle = wake_handle
        .map(|h| -> Result<set_wake::WakeHandle, FfiError> {
            Ok(set_wake::WakeHandle {
                gateway: set_wake::WakeHandleGateway::try_from(h.gateway).map_err(conv)?,
                handle: set_wake::WakeHandleHandle::try_from(h.handle).map_err(conv)?,
            })
        })
        .transpose()?;
    let push_platform = push_platform.map(|p| match p {
        PushPlatform::Apns => set_wake::PayloadPushPlatform::Apns,
        PushPlatform::Fcm => set_wake::PayloadPushPlatform::Fcm,
        PushPlatform::WebPush => set_wake::PayloadPushPlatform::Webpush,
    });
    // Empty → omit (the field skip-serializes when absent).
    let suggested_triggers = if suggested_triggers.is_empty() {
        None
    } else {
        Some(
            suggested_triggers
                .into_iter()
                .map(set_wake::PayloadSuggestedTriggersItem::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(conv)?,
        )
    };
    let payload = set_wake::Payload {
        wake_handle,
        push_platform,
        suggested_triggers,
        ext: None,
    };
    let mut doc = envelope_doc(&env, payload)?;
    attach_did_signed_proof(&mut doc, &*signer, &env.issued_at)?;
    serialize(&doc)
}

/// Parse a `device/set-wake/0.2#response` — whether the device is now
/// push-capable and the effective allowlist the VTA provisioned to the gateway.
#[uniffi::export]
pub fn parse_device_set_wake_response(json: String) -> Result<SetWakeOutcome, FfiError> {
    let doc: TrustTask<set_wake::Response> = serde_json::from_str(&json).map_err(decode)?;
    Ok(SetWakeOutcome {
        push_capable: doc.payload.push_capable,
        allowed_triggers: doc
            .payload
            .trigger_policy
            .map(|p| p.allowed_triggers.iter().map(|t| t.to_string()).collect()),
    })
}

/// Map the FFI [`PushRegistration`] to the wire `push/register` registration.
fn to_wire_registration(reg: PushRegistration) -> Result<register::PushRegistration, FfiError> {
    Ok(match reg {
        PushRegistration::Apns {
            token,
            topic,
            environment,
        } => register::PushRegistration::Apns {
            token: register::PushRegistrationToken::try_from(token).map_err(conv)?,
            topic: register::PushRegistrationTopic::try_from(topic).map_err(conv)?,
            environment: Some(match environment {
                ApnsEnvironment::Sandbox => register::PushRegistrationEnvironment::Sandbox,
                ApnsEnvironment::Production => register::PushRegistrationEnvironment::Production,
            }),
        },
        PushRegistration::Fcm { token } => register::PushRegistration::Fcm {
            token: register::PushRegistrationToken::try_from(token).map_err(conv)?,
        },
        PushRegistration::WebPush {
            endpoint,
            p256dh,
            auth,
        } => register::PushRegistration::Webpush {
            endpoint,
            keys: register::PushRegistrationKeys {
                auth: register::PushRegistrationKeysAuth::try_from(auth).map_err(conv)?,
                p256dh: register::PushRegistrationKeysP256dh::try_from(p256dh).map_err(conv)?,
            },
        },
    })
}

/// Build the request envelope (issuer/recipient/issuedAt) for a push payload.
fn envelope_doc<P: Payload>(env: &PushEnvelope, payload: P) -> Result<TrustTask<P>, FfiError> {
    let issued_at = DateTime::parse_from_rfc3339(&env.issued_at)
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("issued_at is not an RFC 3339 timestamp: {e}"),
        })?
        .with_timezone(&chrono::Utc);
    let mut doc = TrustTask::for_payload(env.id.clone(), payload);
    doc.issuer = env.issuer.clone();
    doc.recipient = env.recipient.clone();
    doc.issued_at = Some(issued_at);
    Ok(doc)
}

fn serialize<P: serde::Serialize>(doc: &TrustTask<P>) -> Result<String, FfiError> {
    serde_json::to_string(doc).map_err(|e| FfiError::InvalidInput {
        reason: format!("failed to serialize push document: {e}"),
    })
}

fn conv<E: ::std::fmt::Display>(e: E) -> FfiError {
    FfiError::InvalidInput {
        reason: e.to_string(),
    }
}

fn decode<E: ::std::fmt::Display>(e: E) -> FfiError {
    FfiError::Decode {
        reason: format!("not a valid push document: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> PushEnvelope {
        PushEnvelope {
            id: "push-1".to_string(),
            issued_at: "2026-05-30T10:00:00Z".to_string(),
            issuer: Some("did:key:zDevice".to_string()),
            recipient: None,
        }
    }

    /// A test `Signer` standing in for the native enclave, with a `did:key`
    /// derived from an Ed25519 test key.
    fn enclave_signer(seed: u8) -> (Box<dyn Signer>, ed25519_dalek::VerifyingKey, String) {
        use ed25519_dalek::{Signer as _, SigningKey};
        use multibase::Base;

        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key();
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(pk.as_bytes());
        let mb = multibase::encode(Base::Base58Btc, mc);
        let did = format!("did:key:{mb}");

        struct EnclaveStub {
            sk: SigningKey,
            did: String,
        }
        impl Signer for EnclaveStub {
            fn did(&self) -> String {
                self.did.clone()
            }
            fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
                Ok(self.sk.sign(&payload).to_bytes().to_vec())
            }
        }
        (Box::new(EnclaveStub { sk, did }), pk, mb)
    }

    #[test]
    fn push_register_has_no_proof_right_type_and_payload() {
        let json = build_push_register(
            env(),
            PushRegistration::Apns {
                token: "abc123".to_string(),
                topic: "org.openvtc.vta.agent".to_string(),
                environment: ApnsEnvironment::Production,
            },
            "did:web:vta.example".to_string(),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "https://trusttasks.org/spec/push/register/0.2");
        assert_eq!(v["issuer"], "did:key:zDevice");
        // No recipient (a REST gateway is addressed by URL, out-of-band).
        assert!(v.get("recipient").is_none());
        assert_eq!(v["payload"]["controllerVtaDid"], "did:web:vta.example");
        assert_eq!(v["payload"]["registration"]["platform"], "apns");
        assert_eq!(v["payload"]["registration"]["token"], "abc123");
        assert_eq!(
            v["payload"]["registration"]["topic"],
            "org.openvtc.vta.agent"
        );
        assert_eq!(v["payload"]["registration"]["environment"], "production");
        // register is unauthenticated — IS_PROOF_REQUIRED == false.
        assert!(v.get("proof").is_none());
    }

    #[test]
    fn push_register_webpush_maps_endpoint_and_keys() {
        let json = build_push_register(
            env(),
            PushRegistration::WebPush {
                endpoint: "https://push.example/x".to_string(),
                p256dh: "p256dh-key".to_string(),
                auth: "auth-secret".to_string(),
            },
            "did:web:vta.example".to_string(),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let reg = &v["payload"]["registration"];
        assert_eq!(reg["platform"], "webpush");
        assert_eq!(reg["endpoint"], "https://push.example/x");
        assert_eq!(reg["keys"]["p256dh"], "p256dh-key");
        assert_eq!(reg["keys"]["auth"], "auth-secret");
    }

    #[test]
    fn parses_push_register_response_wake_handle() {
        let json = r#"{
          "id": "r-1",
          "type": "https://trusttasks.org/spec/push/register/0.2#response",
          "issuer": "did:web:gateway.example",
          "recipient": "did:key:zDevice",
          "payload": {
            "wakeHandle": { "gateway": "https://gw.example", "handle": "z6MkHandle" }
          }
        }"#;
        let h = parse_push_register_response(json.to_string()).unwrap();
        assert_eq!(h.gateway, "https://gw.example");
        assert_eq!(h.handle, "z6MkHandle");
    }

    #[test]
    fn device_set_wake_is_signed_carries_handle_and_verifies() {
        let (signer, pk, mb) = enclave_signer(7);
        let did = signer.did();
        let e = PushEnvelope {
            id: "sw-1".to_string(),
            issued_at: "2026-05-30T10:00:00Z".to_string(),
            issuer: Some(did.clone()),
            recipient: Some("did:web:vta.example".to_string()),
        };
        let json = build_device_set_wake(
            e,
            Some(WakeHandle {
                gateway: "https://gw.example".to_string(),
                handle: "z6MkHandle".to_string(),
            }),
            Some(PushPlatform::WebPush),
            vec!["did:web:mediator.example".to_string()],
            signer,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "https://trusttasks.org/spec/device/set-wake/0.2");
        assert_eq!(v["payload"]["wakeHandle"]["gateway"], "https://gw.example");
        assert_eq!(v["payload"]["wakeHandle"]["handle"], "z6MkHandle");
        assert_eq!(v["payload"]["pushPlatform"], "webpush");
        assert_eq!(
            v["payload"]["suggestedTriggers"][0],
            "did:web:mediator.example"
        );

        // device/set-wake is IS_PROOF_REQUIRED == true — holder-signed.
        let doc: TrustTask<set_wake::Payload> = serde_json::from_str(&json).unwrap();
        let proof = doc.proof.clone().expect("set-wake must be signed");
        let di: affinidi_data_integrity::DataIntegrityProof =
            serde_json::from_value(serde_json::to_value(&proof).unwrap()).unwrap();
        assert_eq!(di.verification_method, format!("{did}#{mb}"));
        let mut unsigned = doc;
        unsigned.proof = None;
        di.verify_with_public_key(
            &unsigned,
            pk.as_bytes(),
            affinidi_data_integrity::VerifyOptions::default(),
        )
        .expect("the set-wake proof must verify against the holder key");
    }

    #[test]
    fn device_set_wake_clear_omits_handle_and_optional_fields() {
        let (signer, _pk, _mb) = enclave_signer(8);
        let e = PushEnvelope {
            id: "sw-2".to_string(),
            issued_at: "2026-05-30T10:00:00Z".to_string(),
            issuer: Some(signer.did()),
            recipient: Some("did:web:vta.example".to_string()),
        };
        let json = build_device_set_wake(e, None, None, vec![], signer).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Clearing the channel: no handle, and the advisory fields skip-serialize.
        assert!(v["payload"].get("wakeHandle").is_none());
        assert!(v["payload"].get("pushPlatform").is_none());
        assert!(v["payload"].get("suggestedTriggers").is_none());
        // Still holder-signed.
        assert!(v.get("proof").is_some());
    }

    #[test]
    fn parses_device_set_wake_response_with_policy() {
        let json = r#"{
          "id": "swr-1",
          "type": "https://trusttasks.org/spec/device/set-wake/0.2#response",
          "issuer": "did:web:vta.example",
          "recipient": "did:key:zDevice",
          "payload": {
            "pushCapable": true,
            "triggerPolicy": { "allowedTriggers": ["did:web:mediator.example", "did:web:vta.example"] }
          }
        }"#;
        let o = parse_device_set_wake_response(json.to_string()).unwrap();
        assert!(o.push_capable);
        assert_eq!(
            o.allowed_triggers.unwrap(),
            vec![
                "did:web:mediator.example".to_string(),
                "did:web:vta.example".to_string()
            ]
        );
    }

    #[test]
    fn parses_device_set_wake_response_cleared() {
        let json = r#"{
          "id": "swr-2",
          "type": "https://trusttasks.org/spec/device/set-wake/0.2#response",
          "issuer": "did:web:vta.example",
          "recipient": "did:key:zDevice",
          "payload": { "pushCapable": false }
        }"#;
        let o = parse_device_set_wake_response(json.to_string()).unwrap();
        assert!(!o.push_capable);
        assert!(o.allowed_triggers.is_none());
    }
}
