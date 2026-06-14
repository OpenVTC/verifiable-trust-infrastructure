//! Passkey-based login wire types.
//!
//! Maps to the trust-task URIs declared in
//! [`crate::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_START_0_1`] and
//! [`crate::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_FINISH_0_1`].
//!
//! ## Flow
//!
//! 1. Client → `POST /auth/passkey-login/start` with
//!    [`PasskeyLoginStartRequest`]. Server replies
//!    [`PasskeyLoginStartResponse`] with a challenge nonce + the list
//!    of credential IDs the browser may present.
//!
//! 2. Browser runs `navigator.credentials.get(challenge)` and
//!    produces a WebAuthn assertion.
//!
//! 3. Client → `POST /auth/passkey-login/finish` with
//!    [`PasskeyLoginFinishRequest`] carrying the assertion bytes.
//!    Server replies
//!    [`crate::protocols::auth::AuthenticateResponse`] (same shape
//!    as the legacy auth flow's tokens) on success.
//!
//! All byte fields are base64url-encoded (no padding) on the wire.
//! Server-side handlers decode before handing to the verifier.

use serde::{Deserialize, Serialize};

/// Client → server: request a passkey-login challenge.
///
/// Wire shape conforms to `spec/auth/passkey/login/start/0.1`: the
/// `did` field serialises as `subject` per the canonical schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PasskeyLoginStartRequest {
    /// The DID the holder claims they control. Server resolves the
    /// DID document, locates passkey VMs, and returns their
    /// credential IDs as `allow_credentials`.
    #[serde(rename = "subject", alias = "did")]
    pub did: String,
}

/// Server → client: challenge + allowable credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PasskeyLoginStartResponse {
    /// Opaque session id; client returns it in
    /// [`PasskeyLoginFinishRequest`].
    pub session_id: String,
    /// Hex-encoded 32-byte challenge. The browser passes this (after
    /// base64url-encoding) to `navigator.credentials.get(...)` as the
    /// `challenge` field. Server stores it on the session and
    /// verifies against `clientData.challenge` at finish time.
    pub challenge: String,
    /// Base64url-encoded credential IDs the server expects to see.
    /// May be empty in v0.1 (browser uses discoverable credentials);
    /// Phase 3 hardening adds real credential-ID enumeration.
    #[serde(default)]
    pub allow_credentials: Vec<String>,
}

/// Client → server: present a WebAuthn assertion for verification.
///
/// All byte fields are base64url-encoded (no padding) when serialised.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PasskeyLoginFinishRequest {
    /// The session id returned by `start`.
    pub session_id: String,
    /// The credential id the browser used to sign (raw assertion `id`).
    pub credential_id: String,
    /// WebAuthn `authenticatorData`.
    pub authenticator_data: String,
    /// WebAuthn `clientDataJSON`. Serde's `camelCase` would lowercase
    /// the "JSON" acronym; we override to match what browsers actually
    /// emit (uppercase JSON suffix).
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// WebAuthn `signature`.
    pub signature: String,
    /// The verificationMethod URL whose key signed the assertion.
    pub verification_method: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_response_camel_case() {
        let json = r#"{
            "sessionId": "sess-1",
            "challenge": "deadbeef",
            "allowCredentials": ["abc","def"]
        }"#;
        let parsed: PasskeyLoginStartResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.session_id, "sess-1");
        assert_eq!(parsed.challenge, "deadbeef");
        assert_eq!(parsed.allow_credentials, vec!["abc", "def"]);
    }

    #[test]
    fn finish_request_camel_case() {
        let json = r#"{
            "sessionId": "sess-1",
            "credentialId": "cred-id-b64",
            "authenticatorData": "ad-b64",
            "clientDataJSON": "cd-b64",
            "signature": "sig-b64",
            "verificationMethod": "did:webvh:example.com:alice#passkey-abc"
        }"#;
        let parsed: PasskeyLoginFinishRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.session_id, "sess-1");
        assert_eq!(parsed.credential_id, "cred-id-b64");
        assert_eq!(
            parsed.verification_method,
            "did:webvh:example.com:alice#passkey-abc"
        );
    }
}
