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
//! Transport is the [`crate::didcomm::DidcommSession`]; these functions only
//! build/parse the JSON.

use chrono::DateTime;
use trust_tasks_rs::specs::auth::{
    authenticate::v0_1 as authenticate, challenge::v0_1 as challenge,
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
}
