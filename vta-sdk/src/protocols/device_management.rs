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
    /// Namespaced extension members (SPEC §4.5.1). Carries
    /// `org.openvtc.device-name` when the device is correcting its own
    /// `displayName`, which registration set once and nothing else updates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// Extension member a device uses to correct its own `displayName` on a
/// heartbeat. Its value is `{ "displayName": "…" }`.
///
/// Reverse-DNS namespaced per SPEC §4.5.1, named the way this ecosystem already
/// names its extensions (`org.openvtc.vault-session`,
/// `org.openvtc.authorization-context`). **Defined once, here**, and imported by
/// the VTA that honours it: the two sides otherwise agree by string, and a typo
/// on either would be a rename that silently never happens.
///
/// # Why an extension and not `device/register`
///
/// `displayName` exists "to help a human pick their own laptop out of a list"
/// (dtgwg `device/register/0.2` §Security & Privacy) and is set exactly once, at
/// registration, because re-registration is **intentionally** refused
/// (`device/register:alreadyRegistered`). Nothing in the device family updates
/// it, so a renamed machine keeps announcing a name that no longer identifies
/// it. Heartbeat is where the spec already puts metadata drift — `platform` is
/// defined there as "updated platform descriptor if it changed since
/// registration" — and `ext` is the slot it provides for the rest.
pub const EXT_DEVICE_NAME: &str = "org.openvtc.device-name";

/// The `ext` member that corrects this device's `displayName` — see
/// [`EXT_DEVICE_NAME`].
///
/// A constructor rather than a literal at the call site, so the key is written
/// once on this side of the wire.
#[must_use]
pub fn device_name_ext(display_name: &str) -> Value {
    serde_json::json!({ EXT_DEVICE_NAME: { "displayName": display_name } })
}

/// Extension member that enrols (on `device/register`) or replaces (on
/// `device/heartbeat`) a device's **user-verification (UV) key**. Its value is
/// a [`UvKeyEnrolment`].
///
/// A UV key is the one key a device can only use after the person holding it
/// passes a biometric (or, for a passkey, the authenticator's own user
/// verification). The VTA signs an `auth/oob/grant` only on a
/// `task-consent/decision` that this key approved, so a compromised wallet
/// process cannot approve a sign-in on its own (sign-in trigger-link contract
/// C6; base design §5 and §11).
///
/// An extension because `device/register/0.2` and `device/heartbeat/0.2` are
/// closed schemas (`additionalProperties: false`) and the registry has no UV
/// key member yet. A replacement is accepted on heartbeat only, which the
/// device's transport key authenticates: no other caller can reach that row.
// TODO: replace with generated trust-tasks types once device/* carries a UV key.
pub const EXT_UV_KEY: &str = "org.openvtc.uv-key";

/// Extension member of a `vault/sign-trust-task` payload that carries the
/// device's UV approval of the envelope being signed. Its value depends on the
/// device's UV key kind:
///
/// - `{ "decision": <signed task-consent/decision/0.2 document> }` for
///   `hardwareKey`, `prfSealedKey` and `webauthn`;
/// - `{ "decision": …, "pinProof": "<base64url HMAC>" }` for `vtaPin` (see
///   [`uv_pin_grant_message`]);
/// - `{ "remote": true }` for `remoteApprover`: the VTA asks the approver's
///   phone and answers `oobUvPending` until it has.
///
/// Required for an `auth/oob/grant` envelope and ignored for every other type.
// TODO: replace with generated trust-tasks types once vault/sign-trust-task
// carries a consent member.
pub const EXT_UV_CONSENT: &str = "org.openvtc.uv-consent";

/// Extension member of a `device/heartbeat` payload that authorises replacing a
/// [`UvKeyMaterial::VtaPin`] UV key: `{ "pinProof": "<base64url HMAC>" }` over
/// [`uv_pin_change_message`] of the new enrolment, made with the **current**
/// PIN. Counted against the same guess limit as a sign-in approval.
pub const EXT_UV_KEY_CHANGE: &str = "org.openvtc.uv-key-change";

/// Extension member of a `device/heartbeat` payload asking which DIDs this
/// device may name as a [`UvKeyMaterial::RemoteApprover`]. Its value is `{}`;
/// the response carries the same member as
/// `{ "approvers": [{ "did", "displayName"?, "formFactor"? }] }`.
pub const EXT_UV_APPROVERS: &str = "org.openvtc.uv-approvers";

/// Domain prefix of every message a `vtaPin` proof is an HMAC over.
pub const UV_PIN_DOMAIN: &str = "org.openvtc.uv-pin/v1|";

/// The message a `vtaPin` approval of grant digest `digest` is an HMAC-SHA256
/// over, keyed by the PIN-derived key: `org.openvtc.uv-pin/v1|<digest>`.
#[must_use]
pub fn uv_pin_grant_message(digest: &str) -> String {
    format!("{UV_PIN_DOMAIN}{digest}")
}

/// Prefix of the message a PIN change proof is an HMAC-SHA256 over, keyed by
/// the **current** PIN-derived key. The full message is this followed by the
/// lowercase hex SHA-256 of the RFC 8785 (JCS) form of the new uv-key
/// enrolment, exactly as sent under [`EXT_UV_KEY`].
pub const UV_PIN_CHANGE_PREFIX: &str = "org.openvtc.uv-pin/v1|change|";

/// Lowest PBKDF2 iteration count a `vtaPin` enrolment may name (OWASP's
/// PBKDF2-HMAC-SHA256 floor).
pub const UV_PIN_MIN_ITERATIONS: u32 = 600_000;
/// Highest iteration count a `vtaPin` enrolment may name, so a stored salt
/// cannot make a recovering browser spin for minutes.
pub const UV_PIN_MAX_ITERATIONS: u32 = 10_000_000;

/// What a device sends under [`EXT_UV_KEY`]: the public half of its UV key and
/// the device's own account of how the private half is held.
///
/// `hardwareBacked` and `biometricGated` are **claims** — recorded, shown and
/// available to policy, but not proven unless `attestation` is verified (it is
/// stored, not yet verified, exactly as `device/register`'s own `attestation`).
// TODO: replace with generated trust-tasks types once device/* carries a UV key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// Not `deny_unknown_fields`: serde cannot combine it with `flatten`.
// [`UvKeyEnrolment::from_ext_value`] refuses unknown members itself.
#[serde(rename_all = "camelCase")]
pub struct UvKeyEnrolment {
    /// The key itself, by kind.
    #[serde(flatten)]
    pub key: UvKeyMaterial,
    /// The private key is non-exportable in a secure element.
    pub hardware_backed: bool,
    /// The platform refuses to use the key without a fresh biometric.
    pub biometric_gated: bool,
    /// Platform attestation of the key, opaque here (Android key attestation
    /// chain, App Attest object, WebAuthn attestation object).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Value>,
}

/// The kinds of UV key.
// TODO: replace with generated trust-tasks types once device/* carries a UV key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[non_exhaustive]
pub enum UvKeyMaterial {
    /// A raw key in the phone's Secure Enclave / StrongBox, named as a
    /// `did:key` (P-256, `did:key:zDn…`, as the Secure Enclave requires; or
    /// Ed25519). It signs the `task-consent/decision` document itself.
    #[serde(rename_all = "camelCase")]
    HardwareKey {
        /// The UV key as a `did:key`.
        did: String,
    },
    /// A WebAuthn passkey (the browser plugin). The decision document is
    /// signed by the device's transport key and carries a WebAuthn assertion
    /// from this credential, made with `userVerification: "required"`.
    #[serde(rename_all = "camelCase")]
    Webauthn {
        /// The credential id, base64url without padding.
        credential_id: String,
        /// The credential's public key as a P-256 Multikey (`zDn…`) — the only
        /// algorithm `vti-webauthn` verifies.
        public_key_multibase: String,
        /// The relying-party id the credential is scoped to (for an extension,
        /// its runtime id).
        rp_id: String,
        /// The origin `clientDataJSON.origin` must carry
        /// (`chrome-extension://<id>`, `https://…`).
        origin: String,
    },
    /// A key the wallet holds sealed under its own WebAuthn PRF passkey (the
    /// browser plugin), named as a `did:key` (Ed25519 or P-256). The seed is
    /// unsealed only by a PRF output, which the authenticator yields only
    /// after user verification, for one signature; the key then signs the
    /// `task-consent/decision` document itself, as a [`Self::HardwareKey`]
    /// does. Unlike one, no secure element holds it, so it is recorded as its
    /// own kind: policy and the audit trail can tell the two apart.
    #[serde(rename_all = "camelCase")]
    PrfSealedKey {
        /// The UV key as a `did:key`.
        did: String,
    },
    /// A PIN the **VTA** checks (the browser plugin, where no PRF passkey is
    /// usable). The browser derives `K = PBKDF2-HMAC-SHA256(NFC(pin), salt,
    /// iterations, 32)` and enrols `verifier = K`; an approval carries
    /// `HMAC-SHA256(K, uv_pin_grant_message(D))`. The VTA enforces a persisted,
    /// escalating guess limit, which is what makes a short PIN safe against a
    /// copied browser profile. Malware in the browser can capture the PIN, so
    /// it is recorded as its own kind: policy and the audit trail can tell it
    /// from a key a secure element or an authenticator holds.
    #[serde(rename_all = "camelCase")]
    VtaPin {
        /// PBKDF2 salt, base64url, 16 to 64 bytes. Not secret.
        salt: String,
        /// PBKDF2 iteration count.
        iterations: u32,
        /// `K` itself, base64url, exactly 32 bytes. Password-equivalent: never
        /// returned, audited or logged ([`PinVerifier`]'s `Debug` redacts it).
        verifier: PinVerifier,
    },
    /// Approval on another of the member's devices — their phone — through
    /// the VTA's task-consent machinery: the VTA pushes a VTA-signed
    /// `task-consent/request` to `approver` and signs the grant once that
    /// device's `task-consent/decision` approves it.
    #[serde(rename_all = "camelCase")]
    RemoteApprover {
        /// The approving device's DID, as its ACL entry names it.
        approver: String,
    },
}

/// The `vtaPin` verifier (`K`). A newtype so that no `Debug` of a binding, an
/// ACL entry or an enrolment can print it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PinVerifier(pub String);

impl std::fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinVerifier(<redacted>)")
    }
}

impl PinVerifier {
    /// The 32 key bytes, if the stored value is well formed.
    #[must_use]
    pub fn key_bytes(&self) -> Option<[u8; 32]> {
        decode_b64url(&self.0).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
    }
}

/// Base64url, with or without padding.
fn decode_b64url(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()
}

/// Why a [`UvKeyEnrolment`] was refused. The text names the rule, never the
/// key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvKeyError(pub &'static str);

impl std::fmt::Display for UvKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for UvKeyError {}

/// Multicodec prefixes (varint) of the key types a UV key may be.
const MULTICODEC_P256: [u8; 2] = [0x80, 0x24];
const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];

fn is_p256_multikey(multibase_value: &str) -> bool {
    match multibase::decode(multibase_value) {
        Ok((multibase::Base::Base58Btc, bytes)) => {
            bytes.len() == 35 && bytes[..2] == MULTICODEC_P256 && matches!(bytes[2], 0x02 | 0x03)
        }
        _ => false,
    }
}

fn is_ed25519_multikey(multibase_value: &str) -> bool {
    match multibase::decode(multibase_value) {
        Ok((multibase::Base::Base58Btc, bytes)) => {
            bytes.len() == 34 && bytes[..2] == MULTICODEC_ED25519
        }
        _ => false,
    }
}

impl UvKeyEnrolment {
    /// Read an enrolment from an `ext` value, refusing anything a UV key
    /// cannot be.
    pub fn from_ext_value(value: &Value) -> Result<Self, UvKeyError> {
        let enrolment: Self = serde_json::from_value(value.clone())
            .map_err(|_| UvKeyError("uv-key is not a UV key enrolment"))?;
        // A member this type does not keep would be silently dropped from the
        // stored record; refuse it instead (the schema it stands in for would
        // be `additionalProperties: false`).
        let kept = serde_json::to_value(&enrolment)
            .map_err(|_| UvKeyError("uv-key is not a UV key enrolment"))?;
        let unknown = value
            .as_object()
            .into_iter()
            .flatten()
            .any(|(k, _)| kept.get(k).is_none());
        if unknown {
            return Err(UvKeyError(
                "uv-key carries a member a UV key enrolment does not define",
            ));
        }
        enrolment.validate()?;
        Ok(enrolment)
    }

    /// The structural rules: a key the VTA can verify, and for a raw hardware
    /// key, the device's statement that it is biometric-gated (a key the
    /// platform will use without one is not a user-verification key).
    pub fn validate(&self) -> Result<(), UvKeyError> {
        match &self.key {
            UvKeyMaterial::HardwareKey { did } => {
                let id = did
                    .strip_prefix("did:key:")
                    .ok_or(UvKeyError("a hardware UV key must be a did:key"))?;
                if !(is_p256_multikey(id) || is_ed25519_multikey(id)) {
                    return Err(UvKeyError(
                        "a hardware UV key must be a P-256 or Ed25519 did:key",
                    ));
                }
                if !self.biometric_gated {
                    return Err(UvKeyError(
                        "a hardware UV key must be biometric-gated; a key usable without user \
                         verification cannot approve a grant",
                    ));
                }
            }
            UvKeyMaterial::PrfSealedKey { did } => {
                let id = did
                    .strip_prefix("did:key:")
                    .ok_or(UvKeyError("a PRF-sealed UV key must be a did:key"))?;
                if !(is_p256_multikey(id) || is_ed25519_multikey(id)) {
                    return Err(UvKeyError(
                        "a PRF-sealed UV key must be a P-256 or Ed25519 did:key",
                    ));
                }
                // Nothing a browser can show makes it hardware-backed.
                if self.hardware_backed {
                    return Err(UvKeyError(
                        "a PRF-sealed UV key is not hardware-backed; no secure element holds it",
                    ));
                }
            }
            UvKeyMaterial::VtaPin {
                salt,
                iterations,
                verifier,
            } => {
                let salt = decode_b64url(salt)
                    .ok_or(UvKeyError("a PIN UV key's salt must be base64url"))?;
                if !(16..=64).contains(&salt.len()) {
                    return Err(UvKeyError("a PIN UV key's salt must be 16 to 64 bytes"));
                }
                if !(UV_PIN_MIN_ITERATIONS..=UV_PIN_MAX_ITERATIONS).contains(iterations) {
                    return Err(UvKeyError(
                        "a PIN UV key's iterations must be 600000 to 10000000",
                    ));
                }
                if verifier.key_bytes().is_none() {
                    return Err(UvKeyError(
                        "a PIN UV key's verifier must be exactly 32 bytes of base64url",
                    ));
                }
                if self.hardware_backed || self.biometric_gated {
                    return Err(UvKeyError(
                        "a PIN UV key is neither hardware-backed nor biometric-gated",
                    ));
                }
            }
            UvKeyMaterial::RemoteApprover { approver } => {
                let well_formed = approver.len() <= 2048
                    && approver
                        .strip_prefix("did:")
                        .and_then(|rest| rest.split_once(':'))
                        .is_some_and(|(method, id)| {
                            !method.is_empty()
                                && method
                                    .chars()
                                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                                && !id.is_empty()
                        })
                    && !approver
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control());
                if !well_formed {
                    return Err(UvKeyError("a remote approver must be a DID"));
                }
                // The approval is the phone's; the browser holds no key at all.
                if self.hardware_backed || self.biometric_gated {
                    return Err(UvKeyError(
                        "a remote-approver UV key names another device; it makes no hardware \
                         or biometric claim of its own",
                    ));
                }
            }
            UvKeyMaterial::Webauthn {
                credential_id,
                public_key_multibase,
                rp_id,
                origin,
            } => {
                use base64::Engine as _;
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(credential_id)
                    .map_err(|_| UvKeyError("credentialId must be base64url without padding"))?;
                if raw.is_empty() || raw.len() > 1023 {
                    return Err(UvKeyError("credentialId must be 1 to 1023 bytes"));
                }
                if !is_p256_multikey(public_key_multibase) {
                    return Err(UvKeyError(
                        "a passkey UV key must be a P-256 Multikey (ES256 credential)",
                    ));
                }
                if rp_id.is_empty() || rp_id.len() > 253 || rp_id.contains(['/', ':', ' ']) {
                    return Err(UvKeyError("rpId must be a bare relying-party id"));
                }
                if !is_origin(origin) {
                    return Err(UvKeyError(
                        "origin must be a scheme://host[:port] origin with no path",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `scheme://host[:port]` and nothing more — the form `clientDataJSON.origin`
/// carries.
fn is_origin(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
        && !rest.is_empty()
        && !rest.contains(['/', '?', '#', '@', ' '])
}

/// The `ext` member that enrols or replaces a UV key — see [`EXT_UV_KEY`].
#[must_use]
pub fn uv_key_ext(enrolment: &UvKeyEnrolment) -> Value {
    serde_json::json!({ EXT_UV_KEY: enrolment })
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

    /// The name correction rides in the spec's own extension slot, under the
    /// key the VTA matches on.
    #[test]
    fn a_named_heartbeat_carries_the_device_name_extension() {
        let body = DeviceHeartbeatBody {
            platform: None,
            vault_seq: None,
            ext: Some(device_name_ext("OpenVTC on new-host (default)")),
        };
        assert_eq!(
            serde_json::to_value(&body).expect("serialises"),
            serde_json::json!({
                "ext": {
                    "org.openvtc.device-name": {
                        "displayName": "OpenVTC on new-host (default)"
                    }
                }
            })
        );
    }

    const P256_DID_KEY: &str = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";

    fn hardware(did: &str, gated: bool) -> Value {
        serde_json::json!({ "kind": "hardwareKey", "did": did,
                            "hardwareBacked": true, "biometricGated": gated })
    }

    #[test]
    fn a_biometric_gated_hardware_key_enrols() {
        let e = UvKeyEnrolment::from_ext_value(&hardware(P256_DID_KEY, true)).expect("valid");
        assert!(matches!(e.key, UvKeyMaterial::HardwareKey { .. }));
        // Round trip: what is stored is what was sent.
        assert_eq!(
            serde_json::to_value(&e).unwrap(),
            hardware(P256_DID_KEY, true)
        );
        UvKeyEnrolment::from_ext_value(&hardware(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            true,
        ))
        .expect("an Ed25519 did:key is accepted too");
    }

    #[test]
    fn a_hardware_key_that_is_not_biometric_gated_is_refused() {
        assert!(UvKeyEnrolment::from_ext_value(&hardware(P256_DID_KEY, false)).is_err());
    }

    #[test]
    fn a_hardware_key_must_be_a_signing_did_key() {
        for bad in [
            "did:web:example.com",
            "did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc", // X25519
            "did:key:not-multibase",
        ] {
            assert!(
                UvKeyEnrolment::from_ext_value(&hardware(bad, true)).is_err(),
                "{bad}"
            );
        }
    }

    fn prf_sealed(did: &str, hardware_backed: bool) -> Value {
        serde_json::json!({ "kind": "prfSealedKey", "did": did,
                            "hardwareBacked": hardware_backed, "biometricGated": false })
    }

    #[test]
    fn a_prf_sealed_key_enrols_as_its_own_kind() {
        let ed = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let e = UvKeyEnrolment::from_ext_value(&prf_sealed(ed, false)).expect("valid");
        assert!(matches!(e.key, UvKeyMaterial::PrfSealedKey { .. }));
        assert_eq!(serde_json::to_value(&e).unwrap(), prf_sealed(ed, false));
        UvKeyEnrolment::from_ext_value(&prf_sealed(P256_DID_KEY, false))
            .expect("a P-256 did:key is accepted too");
    }

    #[test]
    fn a_prf_sealed_key_cannot_claim_hardware_backing() {
        assert!(UvKeyEnrolment::from_ext_value(&prf_sealed(P256_DID_KEY, true)).is_err());
    }

    #[test]
    fn a_prf_sealed_key_must_be_a_signing_did_key() {
        for bad in [
            "did:web:example.com",
            "did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc", // X25519
        ] {
            assert!(
                UvKeyEnrolment::from_ext_value(&prf_sealed(bad, false)).is_err(),
                "{bad}"
            );
        }
    }

    fn passkey(origin: &str, key: &str) -> Value {
        serde_json::json!({
            "kind": "webauthn",
            "credentialId": "AAECAwQFBgc",
            "publicKeyMultibase": key,
            "rpId": "abcdefghijklmnopabcdefghijklmnop",
            "origin": origin,
            "hardwareBacked": false,
            "biometricGated": false,
        })
    }

    #[test]
    fn a_p256_passkey_enrols_and_others_are_refused() {
        let key = P256_DID_KEY.strip_prefix("did:key:").unwrap();
        UvKeyEnrolment::from_ext_value(&passkey(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            key,
        ))
        .expect("an ES256 passkey");
        // EdDSA passkeys cannot be verified by vti-webauthn.
        assert!(
            UvKeyEnrolment::from_ext_value(&passkey(
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
                "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            ))
            .is_err()
        );
        for bad_origin in ["https://a.example/path", "a.example", "https://"] {
            assert!(
                UvKeyEnrolment::from_ext_value(&passkey(bad_origin, key)).is_err(),
                "{bad_origin}"
            );
        }
    }

    fn b64(n: usize) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![7u8; n])
    }

    fn pin(salt: usize, iterations: u64, verifier: usize) -> Value {
        serde_json::json!({
            "kind": "vtaPin", "salt": b64(salt), "iterations": iterations,
            "verifier": b64(verifier), "hardwareBacked": false, "biometricGated": false,
        })
    }

    #[test]
    fn a_pin_enrols_and_round_trips() {
        let v = pin(16, 600_000, 32);
        let e = UvKeyEnrolment::from_ext_value(&v).expect("valid");
        assert!(matches!(e.key, UvKeyMaterial::VtaPin { .. }));
        assert_eq!(serde_json::to_value(&e).unwrap(), v);
        UvKeyEnrolment::from_ext_value(&pin(64, 10_000_000, 32)).expect("upper bounds");
    }

    #[test]
    fn a_pin_out_of_bounds_is_refused() {
        for bad in [
            pin(15, 600_000, 32),
            pin(65, 600_000, 32),
            pin(16, 599_999, 32),
            pin(16, 10_000_001, 32),
            pin(16, 600_000, 31),
            pin(16, 600_000, 33),
        ] {
            assert!(UvKeyEnrolment::from_ext_value(&bad).is_err(), "{bad}");
        }
        let mut claims = pin(16, 600_000, 32);
        claims["biometricGated"] = serde_json::json!(true);
        assert!(UvKeyEnrolment::from_ext_value(&claims).is_err());
        let mut claims = pin(16, 600_000, 32);
        claims["hardwareBacked"] = serde_json::json!(true);
        assert!(UvKeyEnrolment::from_ext_value(&claims).is_err());
        let mut not_b64 = pin(16, 600_000, 32);
        not_b64["verifier"] = serde_json::json!("not base64url!");
        assert!(UvKeyEnrolment::from_ext_value(&not_b64).is_err());
    }

    /// The verifier is password-equivalent: no `Debug` of the enrolment (and so
    /// of a binding or an ACL entry that holds one) may print it.
    #[test]
    fn debug_never_prints_the_pin_verifier() {
        let v = pin(16, 600_000, 32);
        let e = UvKeyEnrolment::from_ext_value(&v).unwrap();
        let printed = format!("{e:?}");
        assert!(!printed.contains(&b64(32)), "{printed}");
        assert!(printed.contains("redacted"), "{printed}");
    }

    fn remote(approver: &str) -> Value {
        serde_json::json!({ "kind": "remoteApprover", "approver": approver,
                            "hardwareBacked": false, "biometricGated": false })
    }

    #[test]
    fn a_remote_approver_must_be_a_did() {
        let v = remote(P256_DID_KEY);
        let e = UvKeyEnrolment::from_ext_value(&v).expect("valid");
        assert!(matches!(e.key, UvKeyMaterial::RemoteApprover { .. }));
        assert_eq!(serde_json::to_value(&e).unwrap(), v);
        UvKeyEnrolment::from_ext_value(&remote("did:webvh:scid:example.com:phone"))
            .expect("any DID method");
        for bad in [
            "",
            "phone",
            "did:",
            "did::x",
            "did:key:",
            "did:key:a b",
            "did:KEY:x",
        ] {
            assert!(
                UvKeyEnrolment::from_ext_value(&remote(bad)).is_err(),
                "{bad}"
            );
        }
        let mut claims = remote(P256_DID_KEY);
        claims["biometricGated"] = serde_json::json!(true);
        assert!(UvKeyEnrolment::from_ext_value(&claims).is_err());
    }

    #[test]
    fn the_pin_messages_are_the_contracts() {
        assert_eq!(uv_pin_grant_message("zAbc"), "org.openvtc.uv-pin/v1|zAbc");
        assert_eq!(UV_PIN_CHANGE_PREFIX, "org.openvtc.uv-pin/v1|change|");
    }

    #[test]
    fn unknown_members_and_kinds_are_refused() {
        let mut v = hardware(P256_DID_KEY, true);
        v["extra"] = serde_json::json!(1);
        assert!(UvKeyEnrolment::from_ext_value(&v).is_err());
        let mut v = hardware(P256_DID_KEY, true);
        v["kind"] = serde_json::json!("softwareKey");
        assert!(UvKeyEnrolment::from_ext_value(&v).is_err());
    }

    #[test]
    fn the_uv_extension_keys_match_the_schema_pattern() {
        for key in [
            EXT_UV_KEY,
            EXT_UV_CONSENT,
            EXT_UV_KEY_CHANGE,
            EXT_UV_APPROVERS,
        ] {
            assert!(
                key.split('.').count() >= 2
                    && key.starts_with(|c: char| c.is_ascii_lowercase())
                    && key.split('.').all(|s| !s.is_empty()
                        && s.chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')),
                "{key}"
            );
        }
    }

    /// The `ext` key has to satisfy the schema's reverse-DNS pattern
    /// (`^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$`) or a conforming maintainer rejects
    /// the whole heartbeat — taking `lastSeenAt` down with it, so a bad key here
    /// is a liveness bug, not a cosmetic one.
    #[test]
    fn the_extension_key_matches_the_schema_pattern() {
        let segments: Vec<&str> = EXT_DEVICE_NAME.split('.').collect();
        assert!(segments.len() >= 2, "{EXT_DEVICE_NAME} needs a namespace");
        assert!(
            EXT_DEVICE_NAME.starts_with(|c: char| c.is_ascii_lowercase()),
            "{EXT_DEVICE_NAME} must start with a lowercase letter"
        );
        for segment in segments {
            assert!(
                !segment.is_empty(),
                "{EXT_DEVICE_NAME} has an empty segment"
            );
            assert!(
                segment
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{segment} may only hold [a-z0-9-]"
            );
        }
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
