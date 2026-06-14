//! Wire types for the passkey-as-verificationMethod endpoints.
//!
//! Enables a browser wallet (e.g. `pnm-browser-plugin`) to enroll a
//! WebAuthn passkey as a `Multikey` verificationMethod (purpose
//! `authentication`) on a VTA-managed DID. Any verifier that
//! resolves the DID can then validate a WebAuthn assertion against
//! the embedded public key — no callback to the VTA, no shared
//! secret.
//!
//! Full design + ceremony spec: `docs/02-vta/passkey-verification-methods.md`.
//!
//! Endpoint contract:
//!
//! - `POST /did/verification-methods/passkey/challenge?did=<did>`
//!   → [`EnrollPasskeyChallengeResponse`]
//! - `POST /did/verification-methods/passkey`
//!   ↳ body [`EnrollPasskeySubmitBody`]
//!   → [`EnrollPasskeySubmitResponse`]
//! - `GET /did/verification-methods/passkey?did=<did>`
//!   → [`ListPasskeyVmsResponse`]
//! - `DELETE /did/verification-methods/passkey/{fragment}?did=<did>`
//!   → 204 No Content
//!
//! Auth model: bearer JWT with admin role on the DID's context.
//! First-time enrolment uses a short-lived enrolment token minted
//! by `pnm passkey-enroll-token`; subsequent calls use a
//! passkey-derived session JWT.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Trust-task payload for `spec/vta/passkey-vms/enroll-challenge/0.1`.
/// Requests a fresh WebAuthn registration challenge for a DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EnrollPasskeyChallengeBody {
    /// DID the new VM will be added to. Caller must have admin role
    /// on the DID's context.
    pub did: String,
    /// Optional operator-supplied label for the new passkey
    /// (e.g. `"MacBook Touch ID"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Trust-task payload for `spec/vta/passkey-vms/list/0.1`.
/// Lists every passkey VM currently on a DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListPasskeyVmsBody {
    /// DID whose passkey VMs to enumerate.
    pub did: String,
}

/// Trust-task payload for `spec/vta/passkey-vms/revoke/0.1`.
/// Removes a passkey VM from a DID document via a WebVH log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokePasskeyVmBody {
    /// DID the VM lives on.
    pub did: String,
    /// VM URL fragment (everything after `#` in the VM id).
    pub fragment: String,
}

/// Trust-task payload for `spec/vta/passkey-vms/revoke/0.1` response —
/// empty success body. Modelled as a struct so future additive fields
/// don't bump the wire version.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokePasskeyVmResponse {}

/// Server-issued WebAuthn registration challenge. Returned by
/// `POST /did/verification-methods/passkey/challenge`.
///
/// All byte-valued fields are base64url-encoded (no padding). The
/// browser passes the decoded bytes to `navigator.credentials.create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EnrollPasskeyChallengeResponse {
    /// Opaque ceremony id — pass back via the `Idempotency-Key` /
    /// `X-Pnm-Ceremony-Id` header on submit. Stored server-side
    /// against the `PasskeyRegistration` state.
    #[serde(rename = "ceremonyId")]
    pub ceremony_id: String,

    /// WebAuthn challenge (base64url, ≥32 random bytes).
    pub challenge: String,

    /// Relying-Party identifier. A DNS name that matches the origin
    /// the browser is served from.
    #[serde(rename = "rpId")]
    pub rp_id: String,

    /// Human-readable RP name.
    #[serde(rename = "rpName")]
    pub rp_name: String,

    /// Stable WebAuthn user handle (base64url). Opaque to the
    /// client — the VTA derives a per-DID handle.
    #[serde(rename = "userHandle")]
    pub user_handle: String,

    /// WebAuthn user name (e.g. the DID or operator-supplied label).
    #[serde(rename = "userName")]
    pub user_name: String,

    /// WebAuthn user display name.
    #[serde(rename = "userDisplayName")]
    pub user_display_name: String,

    /// Suggested ceremony timeout, milliseconds.
    #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
}

/// Browser-supplied enrolment payload posted to
/// `POST /did/verification-methods/passkey`.
///
/// All bytes are base64url (no padding). The VTA re-derives the
/// multikey from `attestation_object.authData` and rejects on
/// mismatch with `public_key_multibase` — the browser's value is
/// **not** trusted as the authoritative public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EnrollPasskeySubmitBody {
    /// DID the new VM is to be added to. Must match the DID
    /// associated with `ceremony_id`.
    pub did: String,

    /// Ceremony id returned by the challenge endpoint.
    #[serde(rename = "ceremonyId")]
    pub ceremony_id: String,

    /// WebAuthn `credential.id` (base64url).
    #[serde(rename = "credentialId")]
    pub credential_id: String,

    /// Browser-computed Multikey. Re-derived server-side and
    /// rejected on mismatch.
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,

    /// COSE algorithm identifier (`-7` ES256, `-8` EdDSA, etc.).
    #[serde(rename = "coseAlgorithm")]
    pub cose_algorithm: i64,

    /// Raw WebAuthn attestationObject (base64url-encoded CBOR).
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,

    /// Raw WebAuthn clientDataJSON (base64url).
    #[serde(rename = "clientDataJson")]
    pub client_data_json: String,

    /// Raw WebAuthn authenticatorData (base64url).
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,

    /// Transport hints reported by the authenticator (e.g.
    /// `"internal"`, `"hybrid"`).
    #[serde(default)]
    pub transports: Vec<String>,

    /// Optional human-friendly label (e.g. `"MacBook Touch ID"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Successful enrolment response. The VM has already been appended
/// to the DID document via a WebVH log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EnrollPasskeySubmitResponse {
    /// The full verificationMethod entry as it now appears in the
    /// DID document.
    #[serde(rename = "verificationMethod")]
    pub verification_method: PasskeyVerificationMethod,

    /// WebVH log entry version that recorded the change (e.g.
    /// `"3-Qm…"`).
    #[serde(rename = "webvhVersion")]
    pub webvh_version: String,
}

/// `GET` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListPasskeyVmsResponse {
    #[serde(rename = "verificationMethods")]
    pub verification_methods: Vec<PasskeyVerificationMethod>,
}

/// A passkey verification-method entry as published in the DID
/// document. Mirrors the wallet-side
/// `@pnm/core` `PasskeyVerificationMethod` type byte-for-byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PasskeyVerificationMethod {
    /// `<did>#passkey-<base64url(sha256(credential_id))>`.
    pub id: String,
    /// Always `"Multikey"`.
    #[serde(rename = "type")]
    pub vm_type: String,
    /// The DID being augmented.
    pub controller: String,
    /// W3C Multikey form of the WebAuthn public key.
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
    /// WebAuthn `credential.id` (base64url) — lets a verifier find
    /// this VM by recomputing `sha256(credential.id)`.
    #[serde(rename = "webauthnCredentialId")]
    pub webauthn_credential_id: String,
    /// Transport hints; advisory only.
    #[serde(
        rename = "webauthnTransports",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub webauthn_transports: Vec<String>,
    /// Optional operator-supplied label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl PasskeyVerificationMethod {
    /// Render as a JSON `Value` for embedding in a DID document.
    pub fn to_json_value(&self) -> Value {
        serde_json::to_value(self).expect("PasskeyVerificationMethod is always serialisable")
    }
}
