//! VTA auth wire types.
//!
//! Conforms to the cross-cutting `spec/auth/*/0.1` canonical
//! Trust-Task specs in the trusttasks-tf registry. Field names mirror
//! OIDC Core §2 / RFC 8176 / RFC 6749 §5.1 so off-the-shelf identity
//! libraries can deserialise the wire payloads into their native
//! types unchanged.
//!
//! - [`ChallengeResponse`] mirrors `spec/auth/challenge/0.1#response`.
//! - [`AuthenticateResponse`] mirrors
//!   `spec/auth/authenticate/0.1#response`; carries the canonical
//!   [`Session`] + [`TokenBundle`] structures from
//!   `auth/_shared/0.1/`.
//!
//! VTA-specific extensions: [`ChallengeResponse::tee_attestation`]
//! surfaces Nitro-Enclave attestation evidence top-level for
//! ergonomic access; documented as a VTA extension in
//! `docs/02-vta/tee-architecture.md`.

use serde::{Deserialize, Serialize};

/// Client sends to `POST /auth/challenge`.
///
/// Wire shape conforms to `spec/auth/challenge/0.1`: the `did` field
/// serialises as `subject` per the canonical payload schema. The Rust
/// identifier stays `did` for consistency with `AuthClaims.did` and
/// the rest of the codebase. `alias = "did"` keeps clients that still
/// send the legacy name working through one upgrade cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ChallengeRequest {
    #[serde(rename = "subject", alias = "did")]
    pub did: String,
}

/// Trust-task payload for `spec/auth/revoke-session/0.1` (request)
/// — revoke a single session by id.
///
/// Authorisation: the caller (via `AuthClaims`) must own the session
/// OR have `Role::Admin`. Enforced in the dispatcher handler, not the
/// schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeSessionRequest {
    /// Identifier of the session to revoke.
    pub session_id: String,
}

/// Trust-task payload for `spec/auth/revoke-session/0.1#response`
/// — empty success body modelled as a struct so future fields
/// (e.g. `revokedAt`) can be added without a wire-format version bump.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeSessionResponse {}

/// Server responds from `POST /auth/challenge`.
///
/// Canonical shape: `{ challenge, sessionId, expiresAt }`.
/// `teeAttestation` is a VTA-specific top-level field documented as
/// a vendor extension — Nitro-Enclave deployments populate it; non-
/// TEE deployments omit it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ChallengeResponse {
    /// base64url-encoded one-time nonce.
    pub challenge: String,
    /// Opaque session identifier the producer echoes into the matching
    /// `authenticate` document.
    pub session_id: String,
    /// ISO-8601 timestamp after which the challenge MUST NOT be honored.
    pub expires_at: String,
    /// VTA-specific (optional): TEE attestation evidence bound to the
    /// challenge nonce. Present when the VTA is running inside a Nitro
    /// Enclave; proves the challenge was generated within the trusted
    /// boundary. Absent for non-TEE deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_attestation: Option<serde_json::Value>,
}

/// Canonical `Session` from `spec/auth/_shared/0.1/session.schema.json`.
///
/// Aligns with OIDC Core §2 / RFC 8176:
/// - `amr`: authentication method references. VTI vocabulary uses
///   `"did"` (challenge-response), `"passkey"` (WebAuthn assertion),
///   `"vta"` (verifiable-trust-agent approval).
/// - `acr`: authentication context class reference. Typical values
///   `"aal1"` (single-factor DID), `"aal2"` (second possession/
///   biometric factor), `"aal3"` (hardware-bound second factor).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Session {
    pub id: String,
    pub subject: String,
    /// ISO-8601 timestamp the session was created.
    pub issued_at: String,
    /// ISO-8601 timestamp the session ceases to be valid.
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub acr: String,
}

/// Canonical `TokenBundle` from `spec/auth/_shared/0.1/tokens.schema.json`.
///
/// OAuth 2.0 (RFC 6749 §5.1)-shaped: `expiresIn` is seconds from
/// issuance, not an absolute timestamp. Clients compute the absolute
/// expiry as `now() + expires_in` immediately after issuance, or
/// store the issuance moment alongside the bundle.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TokenBundle {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_expires_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
}

// Manual Debug — `access_token` and `refresh_token` are bearer
// credentials. Any tracing or panic that captures a `TokenBundle`
// via `{:?}` would otherwise leak them straight into logs. Serialize
// is unchanged so the wire format / on-disk session cache still
// round-trips.
impl std::fmt::Debug for TokenBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBundle")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_expires_in", &self.refresh_expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Server responds from `POST /auth/`. Conforms to
/// `spec/auth/authenticate/0.1#response`: `{ session, tokens }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthenticateResponse {
    pub session: Session,
    pub tokens: TokenBundle,
}

impl AuthenticateResponse {
    /// Absolute Unix-second expiry of the access token, computed from
    /// `session.issued_at + tokens.expires_in`. Convenience for
    /// callers that need an epoch (e.g. JWT exp comparison, audit
    /// logs). Returns `None` if `session.issued_at` fails to parse as
    /// RFC 3339.
    pub fn access_expires_at_epoch(&self) -> Option<u64> {
        let issued = chrono::DateTime::parse_from_rfc3339(&self.session.issued_at).ok()?;
        let issued_epoch = u64::try_from(issued.timestamp()).ok()?;
        Some(issued_epoch.saturating_add(self.tokens.expires_in))
    }

    /// Absolute Unix-second expiry of the refresh token, when one was
    /// issued. Returns `None` if no refresh token or if the issued-at
    /// timestamp fails to parse.
    pub fn refresh_expires_at_epoch(&self) -> Option<u64> {
        let refresh_secs = self.tokens.refresh_expires_in?;
        let issued = chrono::DateTime::parse_from_rfc3339(&self.session.issued_at).ok()?;
        let issued_epoch = u64::try_from(issued.timestamp()).ok()?;
        Some(issued_epoch.saturating_add(refresh_secs))
    }
}

/// Convert a Unix-epoch second timestamp to the RFC 3339 / ISO-8601
/// string the canonical wire format uses. Hot-path helper for
/// handlers that have epoch values internally and need to emit
/// canonical strings.
pub fn epoch_to_rfc3339(epoch_secs: u64) -> String {
    let secs = i64::try_from(epoch_secs).unwrap_or(0);
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_session_request_round_trips() {
        let req = RevokeSessionRequest {
            session_id: "sess-abc-123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"sessionId\":\"sess-abc-123\""), "{json}");
        let parsed: RevokeSessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "sess-abc-123");
    }

    #[test]
    fn revoke_session_response_is_empty_object() {
        let resp = RevokeSessionResponse::default();
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, "{}", "empty success body");
    }

    #[test]
    fn challenge_response_canonical_shape() {
        let json = r#"{
            "challenge": "nonce-bytes-base64url",
            "sessionId": "sess-abc",
            "expiresAt": "2026-05-23T10:02:00Z"
        }"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.challenge, "nonce-bytes-base64url");
        assert_eq!(resp.session_id, "sess-abc");
        assert_eq!(resp.expires_at, "2026-05-23T10:02:00Z");
        assert!(resp.tee_attestation.is_none());
    }

    #[test]
    fn challenge_response_with_tee_attestation_serialises_camel_case() {
        let resp = ChallengeResponse {
            challenge: "n".into(),
            session_id: "s".into(),
            expires_at: "2026-05-23T10:02:00Z".into(),
            tee_attestation: Some(serde_json::json!({ "kind": "nitro" })),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["teeAttestation"]["kind"], "nitro");
        assert_eq!(json["sessionId"], "s");
        assert_eq!(json["expiresAt"], "2026-05-23T10:02:00Z");
    }

    #[test]
    fn authenticate_response_canonical_shape() {
        let json = r#"{
            "session": {
                "id": "sess-abc",
                "subject": "did:web:alice.example",
                "issuedAt": "2026-05-23T10:00:31Z",
                "expiresAt": "2026-05-23T10:15:31Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "eyJhbGc",
                "refreshToken": "rt_abc",
                "tokenType": "Bearer",
                "expiresIn": 900,
                "refreshExpiresIn": 86400
            }
        }"#;
        let resp: AuthenticateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session.id, "sess-abc");
        assert_eq!(resp.session.subject, "did:web:alice.example");
        assert_eq!(resp.session.amr, vec!["did".to_string()]);
        assert_eq!(resp.session.acr, "aal1");
        assert_eq!(resp.tokens.access_token, "eyJhbGc");
        assert_eq!(resp.tokens.expires_in, 900);
        assert_eq!(resp.tokens.token_type, "Bearer");

        // Convenience helpers compute absolute epoch expiries from
        // session.issuedAt + tokens.expiresIn. Computed-vs-asserted so
        // the test is robust to chrono encoding choices.
        let issued = chrono::DateTime::parse_from_rfc3339("2026-05-23T10:00:31Z").unwrap();
        let issued_epoch = issued.timestamp() as u64;
        assert_eq!(resp.access_expires_at_epoch(), Some(issued_epoch + 900));
        assert_eq!(resp.refresh_expires_at_epoch(), Some(issued_epoch + 86400));
    }

    #[test]
    fn epoch_to_rfc3339_round_trip() {
        // Round-trip the helper through chrono's RFC3339 parser. The
        // exact string is `chrono`-encoding-dependent (e.g. `Z` vs
        // `+00:00` suffix), so assert on the round-trip, not the
        // string form.
        let epoch = 1779184831u64;
        let s = epoch_to_rfc3339(epoch);
        let back = chrono::DateTime::parse_from_rfc3339(&s).unwrap();
        assert_eq!(back.timestamp() as u64, epoch);
    }

    #[test]
    fn test_challenge_request_serialize() {
        let req = ChallengeRequest {
            did: "did:key:z6Mk123".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["subject"], "did:key:z6Mk123");
        assert!(json.get("did").is_none());

        let legacy: ChallengeRequest = serde_json::from_str(r#"{"did":"did:key:legacy"}"#).unwrap();
        assert_eq!(legacy.did, "did:key:legacy");
    }
}
