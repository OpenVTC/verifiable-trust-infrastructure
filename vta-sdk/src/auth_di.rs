//! Shared building blocks for the **canonical REST auth transport**: a
//! `auth/authenticate/0.1` Trust Task whose holder `eddsa-jcs-2022`
//! Data-Integrity proof *is* the authentication, and its unsigned
//! `auth/refresh/0.1` counterpart.
//!
//! Why this exists rather than a DIDComm envelope: the VTA's `/auth/` and
//! `/auth/refresh` routes try the Trust-Task document **before** the
//! DIDComm-envelope path (`vta-service/src/routes/auth.rs::
//! try_authenticate_trust_task`), so this transport works against a REST-only
//! VTA (no mediator / ATM) as well as a DIDComm-enabled one — and it *signs*,
//! which the envelope path now requires of everyone.
//!
//! The historical alternative — `didcomm_light`'s **anoncrypt** envelope —
//! carried an unauthenticated plaintext `from`. The VTA hardened `/auth/*` to
//! require authcrypt (`vti_common::auth::bind_authcrypt_sender`, VTI #771), so
//! an anoncrypt envelope is now rejected outright with "authenticate message
//! must be an authenticated (authcrypt) DIDComm envelope". Signing with the
//! holder key is the fix — the key the caller already holds proves the sender
//! instead of a header asserting it.
//!
//! Server-side the proof is verified with a **`did:key` resolver**
//! (`vti-common/src/auth/di_proof.rs`, shared by the VTA and the VTC), so
//! [`sign_authenticate_doc`] refuses
//! any other DID method up front rather than letting the VTA reject it after a
//! round trip.
//!
//! Both [`crate::auth_light`] (the REST client tier) and
//! [`crate::provision_client::auth_rest`] build their documents here so the two
//! can't drift.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::auth::authenticate::v0_1 as authenticate;
use trust_tasks_rs::specs::auth::refresh::v0_1 as refresh;

use crate::protocols::auth::AuthenticateResponse;
use crate::trust_task_sign::{self, TrustTaskSignError};
use crate::trust_tasks::{TASK_AUTH_AUTHENTICATE_0_1, TASK_AUTH_REFRESH_0_1};

/// Why building or reading a DI-signed auth document failed.
///
/// Deliberately narrow: transport errors belong to the caller, which owns the
/// HTTP client and its error type.
#[derive(Debug)]
pub enum AuthDiError {
    /// A payload field failed the spec type's own validation (e.g. an empty
    /// challenge or refresh token) — caught here rather than by the server.
    Payload(String),
    /// Building or signing the document failed — see
    /// [`TrustTaskSignError`] (non-`did:key` holder, bad key, bad type URI).
    Sign(TrustTaskSignError),
    /// The VTA's response was neither a flat `AuthenticateResponse` nor a
    /// Trust-Task `#response` document wrapping one.
    Response(String),
}

impl From<TrustTaskSignError> for AuthDiError {
    fn from(e: TrustTaskSignError) -> Self {
        Self::Sign(e)
    }
}

impl std::fmt::Display for AuthDiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Payload(e) => write!(f, "invalid auth payload: {e}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::Response(e) => write!(f, "unexpected auth response from VTA: {e}"),
        }
    }
}

impl std::error::Error for AuthDiError {}

/// Build and sign an `auth/authenticate/0.1` Trust Task, returning the JSON
/// body to POST to `/auth/`.
///
/// `challenge` / `session_id` come from `/auth/challenge`. The payload is built
/// from the **generated spec type** (`authenticate::Payload`) rather than
/// hand-written JSON, so its wire casing (`sessionId`) is whatever the spec says
/// and cannot drift: the server deserializes into that same type with
/// `deny_unknown_fields`, and R3.1 casing drift is the recurring class that
/// silently breaks these bodies. It is also the shape `vta-mobile-core` emits.
///
/// The proof is attached over the **proof-less** document: `eddsa-jcs-2022`
/// canonicalises with JCS, which is presence-sensitive, and the server verifies
/// against the same shape with `proof` stripped.
pub async fn sign_authenticate_doc(
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
    challenge: &str,
    session_id: &str,
) -> Result<String, AuthDiError> {
    let payload: authenticate::Payload = authenticate::Payload::builder()
        .challenge(
            authenticate::PayloadChallenge::try_from(challenge.to_string())
                .map_err(|e| AuthDiError::Payload(format!("challenge: {e}")))?,
        )
        .session_id(
            authenticate::PayloadSessionId::try_from(session_id.to_string())
                .map_err(|e| AuthDiError::Payload(format!("sessionId: {e}")))?,
        )
        .scope(Vec::new())
        .try_into()
        .map_err(|e| AuthDiError::Payload(format!("authenticate payload: {e}")))?;
    Ok(trust_task_sign::build_signed(
        TASK_AUTH_AUTHENTICATE_0_1,
        serde_json::to_value(&payload).map_err(|e| AuthDiError::Payload(e.to_string()))?,
        client_did,
        private_key_multibase,
        vta_did,
    )
    .await?)
}

/// Build an `auth/refresh/0.1` Trust Task, returning the JSON body to POST to
/// `/auth/refresh`.
///
/// **Unsigned by design.** The opaque refresh token in the payload *is* the
/// bearer credential (RFC 6749 §10.4 rotation), so the server's Trust-Task
/// refresh path passes `signer_did: None` and verifies no proof. That also
/// means refresh works for a holder of any DID method, unlike
/// [`sign_authenticate_doc`].
///
/// Payload built from the generated `refresh::Payload` for the same
/// casing-can't-drift reason as [`sign_authenticate_doc`].
pub fn build_refresh_doc(
    client_did: &str,
    vta_did: &str,
    refresh_token: &str,
) -> Result<String, AuthDiError> {
    let payload: refresh::Payload = refresh::Payload::builder()
        .refresh_token(
            refresh::PayloadRefreshToken::try_from(refresh_token.to_string())
                .map_err(|e| AuthDiError::Payload(format!("refreshToken: {e}")))?,
        )
        .scope(Vec::new())
        .try_into()
        .map_err(|e| AuthDiError::Payload(format!("refresh payload: {e}")))?;
    let doc = trust_task_sign::build_unsigned(
        TASK_AUTH_REFRESH_0_1,
        serde_json::to_value(&payload).map_err(|e| AuthDiError::Payload(e.to_string()))?,
        client_did,
        vta_did,
    )?;
    serde_json::to_string(&doc).map_err(|e| AuthDiError::Payload(e.to_string()))
}

/// Parse an `/auth/` or `/auth/refresh` response body.
///
/// A Trust-Task request yields a Trust-Task `#response` document whose payload
/// is the `{ session, tokens }` body; flat JSON is still what the older
/// DIDComm-envelope path returns, and some mocks emit it. Accept either.
pub fn parse_auth_response(body: &str) -> Result<AuthenticateResponse, AuthDiError> {
    if let Ok(flat) = serde_json::from_str::<AuthenticateResponse>(body) {
        return Ok(flat);
    }
    let doc: TrustTask<Value> = serde_json::from_str(body)
        .map_err(|e| AuthDiError::Response(format!("{e} (is this a VTA?)")))?;
    serde_json::from_value(doc.payload)
        .map_err(|e| AuthDiError::Response(format!("payload is not an AuthenticateResponse: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A challenge shaped like the real thing — the canonical handler issues
    /// hex-encoded 32 random bytes, and the spec type enforces `minLength: 16`,
    /// so a toy `"c"` is not a valid fixture.
    const CHALLENGE: &str = "a3f1c09b7e2d4856a3f1c09b7e2d4856";

    /// A deterministic `did:key` + its multibase private key.
    fn did_key_from_seed(seed_byte: u8) -> (String, String) {
        let seed = [seed_byte; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut buf = vec![0x80, 0x26];
        buf.extend_from_slice(&seed);
        (did, multibase::encode(multibase::Base::Base58Btc, &buf))
    }

    /// The signed document carries the camelCase payload the server's typed
    /// `authenticate::Payload` expects, and an `eddsa-jcs-2022` proof whose
    /// verification method is the holder's `did:key` VM id.
    #[tokio::test]
    async fn authenticate_doc_is_signed_and_camel_cased() {
        let (did, pk) = did_key_from_seed(0x11);
        let body = sign_authenticate_doc(&did, &pk, "did:key:z6MkVta", CHALLENGE, "sess-1")
            .await
            .expect("sign");
        let v: Value = serde_json::from_str(&body).unwrap();

        assert_eq!(v["type"], TASK_AUTH_AUTHENTICATE_0_1);
        assert_eq!(v["payload"]["challenge"], CHALLENGE);
        assert_eq!(v["payload"]["sessionId"], "sess-1");
        assert_eq!(v["issuer"], did);
        assert_eq!(v["recipient"], "did:key:z6MkVta");
        assert_eq!(v["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert_eq!(
            v["proof"]["verificationMethod"],
            format!("{did}#{}", did.strip_prefix("did:key:").unwrap())
        );
        assert!(
            v["proof"]["proofValue"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "proof carries no proofValue"
        );
    }

    /// A non-`did:key` holder is refused locally rather than after a round trip
    /// the VTA's `did:key`-only verifier would reject anyway. The refusal comes
    /// from the shared signer and must survive being wrapped by this layer —
    /// the auth entry point is where a caller actually meets it.
    #[tokio::test]
    async fn non_did_key_holder_is_refused() {
        let (_, pk) = did_key_from_seed(0x44);
        let err = sign_authenticate_doc(
            "did:web:example.com",
            &pk,
            "did:key:z6MkVta",
            CHALLENGE,
            "sess-1",
        )
        .await
        .expect_err("did:web holder must be refused");
        assert!(
            matches!(
                err,
                AuthDiError::Sign(crate::trust_task_sign::TrustTaskSignError::NotDidKey(_))
            ),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("did:web:example.com"),
            "the rendered error must name the offending DID: {err}"
        );
    }

    /// Refresh carries the token in a camelCase payload and no proof.
    #[test]
    fn refresh_doc_is_unsigned_and_camel_cased() {
        let body = build_refresh_doc("did:key:z6MkHolder", "did:key:z6MkVta", "tok-1").unwrap();
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["type"], TASK_AUTH_REFRESH_0_1);
        assert_eq!(v["payload"]["refreshToken"], "tok-1");
        assert!(
            v.get("proof").is_none_or(Value::is_null),
            "refresh must not be signed"
        );
    }

    /// Both response shapes parse: the Trust-Task `#response` envelope the
    /// server returns to a Trust-Task request, and flat JSON.
    #[test]
    fn parses_flat_and_trust_task_responses() {
        let tokens = json!({
            "session": {
                "id": "sess", "subject": "did:key:z6MkHolder",
                "issuedAt": "1970-01-01T00:00:00Z", "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"], "acr": "aal1"
            },
            "tokens": {
                "accessToken": "acc", "tokenType": "Bearer", "expiresIn": 900_u64
            }
        });

        let flat = parse_auth_response(&tokens.to_string()).expect("flat");
        assert_eq!(flat.tokens.access_token, "acc");

        let wrapped = json!({
            "id": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/auth/authenticate/0.1#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": tokens,
        });
        let unwrapped = parse_auth_response(&wrapped.to_string()).expect("trust-task");
        assert_eq!(unwrapped.tokens.access_token, "acc");
    }

    /// Anything else is a typed error, not a panic or a silent default.
    #[test]
    fn rejects_unrecognisable_response() {
        assert!(matches!(
            parse_auth_response("<html>not a VTA</html>"),
            Err(AuthDiError::Response(_))
        ));
    }
}
