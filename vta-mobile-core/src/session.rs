//! VTA authentication, expressed as `auth/*` Trust Tasks.
//!
//! The agent authenticates to its VTA the custody-correct way — composing the
//! engine's own primitives rather than reusing `vta-sdk`'s session (which holds
//! the raw private key + is REST/keyring-backed, incompatible with the
//! `Signer`-callback / enclave custody model). The flow:
//!
//! 1. `build_auth_challenge` → request a nonce (`auth/challenge`, no proof).
//! 2. `parse_auth_challenge_response` → read the challenge + session id.
//! 3. `build_authenticate` → present the challenge; the framework **proof**,
//!    signed by the holder via the native [`Signer`] (reusing the DID-signed
//!    proof machinery in [`crate::proof`]), IS the authentication.
//! 4. `parse_authenticate_response` → the issued access/refresh tokens.
//!
//! Once the access token nears expiry the agent refreshes without re-prompting
//! the user:
//!
//! 5. `build_refresh` → present the refresh token (`auth/refresh`, **no proof**
//!    — the opaque refresh token is itself the credential, verified
//!    server-side, exactly as `IS_PROOF_REQUIRED == false` on the spec says).
//! 6. `parse_refresh_response` → the rotated tokens (+ an optional session
//!    snapshot, e.g. an `acr` bump after a step-up).
//!
//! Introspection, callable any time the agent holds a session, to reconcile its
//! local view (acr after a step-up, roles/scopes after a policy edit) without
//! re-issuing tokens:
//!
//! - `build_whoami` → ask the auth service for its view of the holder
//!   (`auth/whoami`). Like authenticate it is `IS_PROOF_REQUIRED == true`: the
//!   request carries an empty payload but a holder-signed framework **proof**,
//!   so the introspection itself proves who is asking.
//! - `parse_whoami_response` → the current session + roles + scopes
//!   ([`SessionInfo`]).
//!
//! Transport is the [`crate::didcomm::DidcommSession`]; these functions only
//! build/parse the JSON.

use chrono::DateTime;
use trust_tasks_rs::specs::auth::{
    authenticate::v0_1 as authenticate, challenge::v0_1 as challenge, refresh::v0_1 as refresh,
    whoami::v0_1 as whoami,
};
use trust_tasks_rs::{Payload, TrustTask};

use crate::error::FfiError;
use crate::keys::Signer;
use crate::proof::attach_did_signed_proof;

/// Envelope fields shared by the auth request documents. `id` / `issued_at` are
/// supplied by the native layer (it owns identifiers and the clock).
#[derive(Debug, Clone, uniffi::Record)]
pub struct AuthEnvelope {
    /// Document id (e.g. a fresh UUID).
    pub id: String,
    /// The holder DID — the subject authenticating (document `issuer`).
    pub holder_did: String,
    /// The VTA / auth-service DID (document `recipient`).
    pub vta_did: String,
    /// RFC 3339 timestamp for `issuedAt` (and the authenticate proof's `created`).
    pub issued_at: String,
}

/// Parsed `auth/challenge` response.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AuthChallenge {
    pub challenge: String,
    pub session_id: String,
    pub expires_at: String,
}

/// Parsed token bundle (+ session summary) from an `authenticate` response.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AuthTokens {
    pub access_token: String,
    /// Token presentation scheme — almost always `"Bearer"`. The native layer
    /// uses it as the `Authorization` header scheme.
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub refresh_expires_in: Option<u64>,
    /// Authentication context class of the issued session (e.g. `"aal2"`).
    pub acr: Option<String>,
    /// Authentication methods references (e.g. `["did"]`).
    pub amr: Vec<String>,
}

/// The auth service's view of the holder, from a `whoami` response — the full
/// current session plus the roles/scopes the service holds. The native layer
/// uses it to reconcile local AAL/authorization state after a step-up or policy
/// edit without re-issuing tokens.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SessionInfo {
    /// Opaque, server-chosen session id.
    pub session_id: String,
    /// The authenticated party's VID (typically a DID URL).
    pub subject: String,
    /// RFC 3339 timestamp the session was created.
    pub issued_at: String,
    /// RFC 3339 timestamp the session ceases to be valid.
    pub expires_at: String,
    /// Authentication context class of the session (e.g. `"aal2"`).
    pub acr: Option<String>,
    /// Authentication methods references (e.g. `["did", "passkey"]`).
    pub amr: Vec<String>,
    /// Role assignments the auth service holds for the holder.
    pub roles: Vec<String>,
    /// Capability tags effective on the holder's current session.
    pub scopes: Vec<String>,
}

/// Build an `auth/challenge/0.1` request to start VTA authentication. No proof —
/// the response carries the nonce the holder will sign in `authenticate`.
#[uniffi::export]
pub fn build_auth_challenge(
    env: AuthEnvelope,
    subject: Option<String>,
    purpose: Option<String>,
) -> Result<String, FfiError> {
    let payload = challenge::Payload {
        subject: subject
            .map(challenge::PayloadSubject::try_from)
            .transpose()
            .map_err(conv)?,
        purpose: purpose
            .map(challenge::PayloadPurpose::try_from)
            .transpose()
            .map_err(conv)?,
        ext: None,
    };
    serialize(&envelope_doc(&env, payload)?)
}

/// Parse an `auth/challenge/0.1#response`.
#[uniffi::export]
pub fn parse_auth_challenge_response(json: String) -> Result<AuthChallenge, FfiError> {
    let doc: TrustTask<challenge::Response> = serde_json::from_str(&json).map_err(decode)?;
    Ok(AuthChallenge {
        challenge: doc.payload.challenge.to_string(),
        session_id: doc.payload.session_id.to_string(),
        expires_at: doc.payload.expires_at.to_rfc3339(),
    })
}

/// Build a signed `auth/authenticate/0.1`. The framework Data Integrity proof —
/// signed by the holder via `signer` — IS the authentication; `challenge` and
/// `session_id` are echoed from the challenge response.
#[uniffi::export]
pub fn build_authenticate(
    env: AuthEnvelope,
    challenge: String,
    session_id: String,
    scope: Vec<String>,
    signer: Box<dyn Signer>,
) -> Result<String, FfiError> {
    let payload = authenticate::Payload {
        challenge: authenticate::PayloadChallenge::try_from(challenge).map_err(conv)?,
        session_id: authenticate::PayloadSessionId::try_from(session_id).map_err(conv)?,
        scope: scope
            .into_iter()
            .map(authenticate::PayloadScopeItem::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(conv)?,
        ext: None,
    };
    let mut doc = envelope_doc(&env, payload)?;
    attach_did_signed_proof(&mut doc, &*signer, &env.issued_at)?;
    serialize(&doc)
}

/// Parse an `auth/authenticate/0.1#response` — the issued tokens + session.
#[uniffi::export]
pub fn parse_authenticate_response(json: String) -> Result<AuthTokens, FfiError> {
    let doc: TrustTask<authenticate::Response> = serde_json::from_str(&json).map_err(decode)?;
    let tokens = doc.payload.tokens;
    let session = doc.payload.session;
    Ok(AuthTokens {
        access_token: tokens.access_token.to_string(),
        token_type: tokens.token_type.to_string(),
        expires_in: tokens.expires_in.get(),
        refresh_token: tokens.refresh_token.map(|t| t.to_string()),
        refresh_expires_in: tokens.refresh_expires_in.map(|n| n.get()),
        acr: session.acr,
        amr: session.amr.iter().map(|a| a.to_string()).collect(),
    })
}

/// Build an `auth/refresh/0.1` request: exchange a previously-issued refresh
/// token for a new access token. **No proof** — `auth/refresh` is
/// `IS_PROOF_REQUIRED == false`; the opaque refresh token is the credential and
/// is verified server-side. `scope` MAY narrow (never widen) the issued scope;
/// pass empty to keep the session's current scope.
#[uniffi::export]
pub fn build_refresh(
    env: AuthEnvelope,
    refresh_token: String,
    scope: Vec<String>,
) -> Result<String, FfiError> {
    let payload = refresh::Payload {
        refresh_token: refresh::PayloadRefreshToken::try_from(refresh_token).map_err(conv)?,
        scope: scope
            .into_iter()
            .map(refresh::PayloadScopeItem::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(conv)?,
        ext: None,
    };
    serialize(&envelope_doc(&env, payload)?)
}

/// Parse an `auth/refresh/0.1#response` — the rotated tokens. Unlike
/// authenticate, the session snapshot is **optional**: when the response omits
/// it, `acr` is `None` and `amr` is empty (the caller keeps its prior session
/// state). A consumer that doesn't rotate refresh tokens may also omit
/// `refreshToken`, in which case the caller keeps reusing the current one.
#[uniffi::export]
pub fn parse_refresh_response(json: String) -> Result<AuthTokens, FfiError> {
    let doc: TrustTask<refresh::Response> = serde_json::from_str(&json).map_err(decode)?;
    let tokens = doc.payload.tokens;
    let session = doc.payload.session;
    Ok(AuthTokens {
        access_token: tokens.access_token.to_string(),
        token_type: tokens.token_type.to_string(),
        expires_in: tokens.expires_in.get(),
        refresh_token: tokens.refresh_token.map(|t| t.to_string()),
        refresh_expires_in: tokens.refresh_expires_in.map(|n| n.get()),
        acr: session.as_ref().and_then(|s| s.acr.clone()),
        amr: session
            .map(|s| s.amr.iter().map(|a| a.to_string()).collect())
            .unwrap_or_default(),
    })
}

/// Build a signed `auth/whoami/0.1` introspection request. The payload is empty;
/// like authenticate, `auth/whoami` is `IS_PROOF_REQUIRED == true`, so the
/// holder-signed framework proof (via `signer`, reusing [`crate::proof`]) is
/// what authenticates the request.
#[uniffi::export]
pub fn build_whoami(env: AuthEnvelope, signer: Box<dyn Signer>) -> Result<String, FfiError> {
    let mut doc = envelope_doc(&env, whoami::Payload::default())?;
    attach_did_signed_proof(&mut doc, &*signer, &env.issued_at)?;
    serialize(&doc)
}

/// Parse an `auth/whoami/0.1#response` — the auth service's view of the holder:
/// the current session plus the roles/scopes it holds.
#[uniffi::export]
pub fn parse_whoami_response(json: String) -> Result<SessionInfo, FfiError> {
    let doc: TrustTask<whoami::Response> = serde_json::from_str(&json).map_err(decode)?;
    let r = doc.payload;
    let session = r.session;
    Ok(SessionInfo {
        session_id: session.id.to_string(),
        subject: session.subject.to_string(),
        issued_at: session.issued_at.to_rfc3339(),
        expires_at: session.expires_at.to_rfc3339(),
        acr: session.acr,
        amr: session.amr.iter().map(|a| a.to_string()).collect(),
        roles: r.roles.iter().map(|x| x.to_string()).collect(),
        scopes: r.scopes.iter().map(|x| x.to_string()).collect(),
    })
}

/// Build the request envelope (issuer/recipient/issuedAt) for an auth payload.
fn envelope_doc<P: Payload>(env: &AuthEnvelope, payload: P) -> Result<TrustTask<P>, FfiError> {
    let issued_at = DateTime::parse_from_rfc3339(&env.issued_at)
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("issued_at is not an RFC 3339 timestamp: {e}"),
        })?
        .with_timezone(&chrono::Utc);
    let mut doc = TrustTask::for_payload(env.id.clone(), payload);
    doc.issuer = Some(env.holder_did.clone());
    doc.recipient = Some(env.vta_did.clone());
    doc.issued_at = Some(issued_at);
    Ok(doc)
}

fn serialize<P: serde::Serialize>(doc: &TrustTask<P>) -> Result<String, FfiError> {
    serde_json::to_string(doc).map_err(|e| FfiError::InvalidInput {
        reason: format!("failed to serialize auth document: {e}"),
    })
}

fn conv<E: ::std::fmt::Display>(e: E) -> FfiError {
    FfiError::InvalidInput {
        reason: e.to_string(),
    }
}

fn decode<E: ::std::fmt::Display>(e: E) -> FfiError {
    FfiError::Decode {
        reason: format!("not a valid auth document: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> AuthEnvelope {
        AuthEnvelope {
            id: "auth-1".to_string(),
            holder_did: "did:key:zHolder".to_string(),
            vta_did: "did:web:vta.example".to_string(),
            issued_at: "2026-05-30T10:00:00Z".to_string(),
        }
    }

    #[test]
    fn challenge_request_has_no_proof_and_right_type() {
        let json = build_auth_challenge(env(), Some("did:key:zHolder".into()), None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "https://trusttasks.org/spec/auth/challenge/0.1");
        assert_eq!(v["issuer"], "did:key:zHolder");
        assert_eq!(v["recipient"], "did:web:vta.example");
        assert!(v.get("proof").is_none());
    }

    #[test]
    fn authenticate_is_signed_and_verifies_against_the_holder_key() {
        use ed25519_dalek::{Signer as _, SigningKey};
        use multibase::Base;

        let sk = SigningKey::from_bytes(&[42u8; 32]);
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

        let e = AuthEnvelope {
            id: "auth-2".to_string(),
            holder_did: did.clone(),
            vta_did: "did:web:vta.example".to_string(),
            issued_at: "2026-05-30T10:00:00Z".to_string(),
        };
        let json = build_authenticate(
            e,
            "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ".to_string(),
            "sess-1".to_string(),
            vec!["vault-read".to_string()],
            Box::new(EnclaveStub {
                sk,
                did: did.clone(),
            }),
        )
        .unwrap();

        let doc: TrustTask<authenticate::Payload> = serde_json::from_str(&json).unwrap();
        let proof = doc.proof.clone().expect("authenticate must be signed");
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
        .expect("the authenticate proof must verify against the holder key");
    }

    #[test]
    fn parses_authenticate_response_tokens() {
        let json = r#"{
          "id": "r-1",
          "type": "https://trusttasks.org/spec/auth/authenticate/0.1#response",
          "issuer": "did:web:vta.example",
          "recipient": "did:key:zHolder",
          "payload": {
            "session": {
              "id": "sess-1",
              "subject": "did:key:zHolder",
              "issuedAt": "2026-05-30T10:00:01Z",
              "expiresAt": "2026-05-30T10:30:01Z",
              "amr": ["did"],
              "acr": "aal1"
            },
            "tokens": {
              "accessToken": "eyJhbGciOi.access",
              "tokenType": "Bearer",
              "expiresIn": 900,
              "refreshToken": "rt_abc",
              "refreshExpiresIn": 86400
            }
          }
        }"#;
        let t = parse_authenticate_response(json.to_string()).unwrap();
        assert_eq!(t.access_token, "eyJhbGciOi.access");
        assert_eq!(t.token_type, "Bearer");
        assert_eq!(t.expires_in, 900);
        assert_eq!(t.refresh_token.as_deref(), Some("rt_abc"));
        assert_eq!(t.refresh_expires_in, Some(86400));
        assert_eq!(t.acr.as_deref(), Some("aal1"));
        assert_eq!(t.amr, vec!["did".to_string()]);
    }

    #[test]
    fn refresh_request_has_no_proof_and_carries_the_token() {
        let json =
            build_refresh(env(), "rt_abc".to_string(), vec!["acl:read".to_string()]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "https://trusttasks.org/spec/auth/refresh/0.1");
        assert_eq!(v["issuer"], "did:key:zHolder");
        assert_eq!(v["recipient"], "did:web:vta.example");
        assert_eq!(v["payload"]["refreshToken"], "rt_abc");
        assert_eq!(v["payload"]["scope"][0], "acl:read");
        // auth/refresh is IS_PROOF_REQUIRED == false — the token is the credential.
        assert!(v.get("proof").is_none());
    }

    #[test]
    fn empty_scope_is_omitted_from_the_refresh_request() {
        let json = build_refresh(env(), "rt_abc".to_string(), vec![]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // `scope` skips serialization when empty — keep the session's scope.
        assert!(v["payload"].get("scope").is_none());
    }

    #[test]
    fn parses_refresh_response_with_rotated_token_and_session_bump() {
        let json = r#"{
          "id": "r-2",
          "type": "https://trusttasks.org/spec/auth/refresh/0.1#response",
          "issuer": "did:web:vta.example",
          "recipient": "did:key:zHolder",
          "payload": {
            "session": {
              "id": "sess-1",
              "subject": "did:key:zHolder",
              "issuedAt": "2026-05-30T10:00:01Z",
              "expiresAt": "2026-05-30T10:30:01Z",
              "amr": ["did", "passkey"],
              "acr": "aal2"
            },
            "tokens": {
              "accessToken": "eyJhbGciOi.access2",
              "tokenType": "Bearer",
              "expiresIn": 900,
              "refreshToken": "rt_rotated",
              "refreshExpiresIn": 86400
            }
          }
        }"#;
        let t = parse_refresh_response(json.to_string()).unwrap();
        assert_eq!(t.access_token, "eyJhbGciOi.access2");
        assert_eq!(t.refresh_token.as_deref(), Some("rt_rotated"));
        // Session snapshot present → the step-up acr/amr bump is surfaced.
        assert_eq!(t.acr.as_deref(), Some("aal2"));
        assert_eq!(t.amr, vec!["did".to_string(), "passkey".to_string()]);
    }

    #[test]
    fn parses_refresh_response_without_session_or_rotated_token() {
        // Non-rotating consumer: no session snapshot, no new refresh token.
        let json = r#"{
          "id": "r-3",
          "type": "https://trusttasks.org/spec/auth/refresh/0.1#response",
          "issuer": "did:web:vta.example",
          "recipient": "did:key:zHolder",
          "payload": {
            "tokens": {
              "accessToken": "eyJhbGciOi.access3",
              "tokenType": "Bearer",
              "expiresIn": 900
            }
          }
        }"#;
        let t = parse_refresh_response(json.to_string()).unwrap();
        assert_eq!(t.access_token, "eyJhbGciOi.access3");
        assert_eq!(t.expires_in, 900);
        // No rotation, no session → caller keeps its prior refresh token + acr.
        assert_eq!(t.refresh_token, None);
        assert_eq!(t.refresh_expires_in, None);
        assert_eq!(t.acr, None);
        assert!(t.amr.is_empty());
    }

    #[test]
    fn whoami_request_is_signed_and_verifies_against_the_holder_key() {
        use ed25519_dalek::{Signer as _, SigningKey};
        use multibase::Base;

        let sk = SigningKey::from_bytes(&[99u8; 32]);
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

        let e = AuthEnvelope {
            id: "whoami-1".to_string(),
            holder_did: did.clone(),
            vta_did: "did:web:vta.example".to_string(),
            issued_at: "2026-05-30T10:00:00Z".to_string(),
        };
        let json = build_whoami(
            e,
            Box::new(EnclaveStub {
                sk,
                did: did.clone(),
            }),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "https://trusttasks.org/spec/auth/whoami/0.1");

        let doc: TrustTask<whoami::Payload> = serde_json::from_str(&json).unwrap();
        let proof = doc.proof.clone().expect("whoami must be signed");
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
        .expect("the whoami proof must verify against the holder key");
    }

    #[test]
    fn parses_whoami_response_with_session_roles_and_scopes() {
        let json = r#"{
          "id": "w-1",
          "type": "https://trusttasks.org/spec/auth/whoami/0.1#response",
          "issuer": "did:web:vta.example",
          "recipient": "did:key:zHolder",
          "payload": {
            "session": {
              "id": "sess-1",
              "subject": "did:key:zHolder",
              "issuedAt": "2026-05-30T10:00:01Z",
              "expiresAt": "2026-05-30T10:30:01Z",
              "amr": ["did", "passkey"],
              "acr": "aal2"
            },
            "roles": ["admin", "operator"],
            "scopes": ["acl:read", "acl:write"]
          }
        }"#;
        let s = parse_whoami_response(json.to_string()).unwrap();
        assert_eq!(s.session_id, "sess-1");
        assert_eq!(s.subject, "did:key:zHolder");
        assert_eq!(s.acr.as_deref(), Some("aal2"));
        assert_eq!(s.amr, vec!["did".to_string(), "passkey".to_string()]);
        assert_eq!(s.roles, vec!["admin".to_string(), "operator".to_string()]);
        assert_eq!(
            s.scopes,
            vec!["acl:read".to_string(), "acl:write".to_string()]
        );
    }

    #[test]
    fn parses_whoami_response_with_omitted_roles_and_scopes() {
        // roles/scopes skip-serialize when empty; acr may be absent too.
        let json = r#"{
          "id": "w-2",
          "type": "https://trusttasks.org/spec/auth/whoami/0.1#response",
          "issuer": "did:web:vta.example",
          "recipient": "did:key:zHolder",
          "payload": {
            "session": {
              "id": "sess-2",
              "subject": "did:key:zHolder",
              "issuedAt": "2026-05-30T10:00:01Z",
              "expiresAt": "2026-05-30T10:30:01Z"
            }
          }
        }"#;
        let s = parse_whoami_response(json.to_string()).unwrap();
        assert_eq!(s.session_id, "sess-2");
        assert_eq!(s.acr, None);
        assert!(s.amr.is_empty());
        assert!(s.roles.is_empty());
        assert!(s.scopes.is_empty());
    }
}
