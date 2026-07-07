use crate::error::AppError;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// JWT claims for VTA/VTC access tokens.
///
/// Aligns with the OIDC Core §2 / RFC 8176 vocabulary so the same
/// claim names other identity stacks emit work here unchanged:
///
/// - `amr` — *Authentication Methods References*. Per [RFC 8176]
///   the canonical short strings are `pwd`, `hwk`, `swk`, `iris`,
///   `face`, `sms`, etc.; the VTI vocabulary in current use is
///   `"did"` (challenge-response), `"passkey"` (WebAuthn), `"vta"`
///   (verifiable-trust-agent attestation). Multi-factor sessions
///   list every method that contributed.
/// - `acr` — *Authentication Context Class Reference*. The
///   recommended set is `"aal1"` (single-factor DID), `"aal2"`
///   (a second possession-or-biometric factor confirmed), `"aal3"`
///   (hardware-bound second factor).
///
/// `Default` derives so test fixtures and follow-up constructions can
/// use `Claims { aud: ..., ..Default::default() }` without listing
/// every field — production minters still set the values that
/// matter, but the boilerplate at non-load-bearing call sites
/// (default-empty in tests, mocks, examples) stays out of the way.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    pub sub: String,
    pub session_id: String,
    pub role: String,
    #[serde(default)]
    pub contexts: Vec<String>,
    pub exp: u64,
    /// Issued-at, Unix seconds. Mirrors OIDC Core §2 / RFC 7519
    /// §4.1.6. The extractor doesn't gate on it directly — `exp`
    /// is the only mandatory freshness check — but `iat` lets
    /// audit logs and downstream consumers distinguish a re-issued
    /// token from the original mint, and lets clock-skew analysis
    /// detect a stuck issuer.
    ///
    /// `#[serde(default)]` so tokens minted before `iat` landed
    /// deserialise as `iat=0` — never confused with a fresh mint
    /// because `iat==0` is older than any real session.
    #[serde(default)]
    pub iat: u64,
    /// Indicates the service is running inside a Trusted Execution Environment.
    /// Only present (and `true`) when TEE is active; omitted when false to
    /// reduce token size.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tee_attested: bool,
    /// Authentication Methods References per [RFC 8176]. Empty when
    /// the consumer's authentication path did not categorise the
    /// factor (e.g. legacy tokens minted before AAL plumbing landed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    /// Authentication Context Class Reference per OIDC Core §2.
    /// Empty when not categorised.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub acr: String,
    /// JWT ID (RFC 7519 §4.1.7) — a per-issue nonce that pins this access
    /// token to the session's current `token_id`. The extractor rejects a
    /// token whose `jti` does not match `Session.token_id` (when that field is
    /// set), so minting a fresh token immediately supersedes the prior one for
    /// the same session. Load-bearing once a session_id stops rotating on
    /// refresh; harmless before then (each session already has exactly one live
    /// token). `#[serde(default)]` so pre-`jti` tokens deserialise with an empty
    /// string and are treated as "no pin" by sessions that predate the field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jti: String,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// Holds the JWT encoding and decoding keys derived from an Ed25519 seed.
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    /// Audience string used for encoding and validation (e.g., "VTA" or "VTC").
    audience: String,
}

impl JwtKeys {
    /// Create JWT keys from raw 32-byte Ed25519 private key bytes.
    ///
    /// `audience` is the expected JWT audience claim (e.g., "VTA" or "VTC").
    ///
    /// Computes the public key and wraps both in DER format as required
    /// by `jsonwebtoken`'s `from_ed_der()` methods.
    pub fn from_ed25519_bytes(private_bytes: &[u8; 32], audience: &str) -> Result<Self, AppError> {
        // Compute the Ed25519 public key from the private key seed
        let signing_key = ed25519_dalek::SigningKey::from_bytes(private_bytes);
        let public_bytes = signing_key.verifying_key().to_bytes();

        // Build PKCS8 v1 DER for the private key (used by EncodingKey)
        //
        // SEQUENCE {                                  -- 0x30, 0x2e (46 bytes)
        //   INTEGER 0                                 -- 0x02, 0x01, 0x00
        //   SEQUENCE { OID 1.3.101.112 }              -- 0x30, 0x05, ...
        //   OCTET STRING { OCTET STRING <32 bytes> }  -- 0x04, 0x22, 0x04, 0x20, ...
        // }
        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&[
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER 0 (version v1)
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier (Ed25519)
            0x04, 0x22, 0x04, 0x20, // OCTET STRING { OCTET STRING, 32 bytes }
        ]);
        pkcs8.extend_from_slice(private_bytes);

        let encoding = EncodingKey::from_ed_der(&pkcs8);
        // rust_crypto backend expects raw 32-byte public key, not SPKI DER
        let decoding = DecodingKey::from_ed_der(&public_bytes);

        Ok(Self {
            encoding,
            decoding,
            audience: audience.to_string(),
        })
    }

    /// Encode claims into a signed JWT access token.
    pub fn encode(&self, claims: &Claims) -> Result<String, AppError> {
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|e| AppError::Internal(format!("JWT encode failed: {e}")))
    }

    /// Decode and validate a JWT access token, returning the claims.
    pub fn decode(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "session_id", "role"]);

        jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                debug!(error = %e, "JWT decode failed");
                AppError::Unauthorized(format!("invalid token: {e}"))
            })
    }

    /// Create claims for a new access token.
    pub fn new_claims(
        &self,
        sub: String,
        session_id: String,
        role: String,
        contexts: Vec<String>,
        expiry_secs: u64,
        tee_attested: bool,
    ) -> Claims {
        // Fall back to 0 if the clock is before UNIX_EPOCH — happens on
        // recovery boots before NTP sync. Token would expire immediately
        // in that (very unusual) state, which is safer than panicking in
        // a hot auth path.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let exp = now_secs + expiry_secs;

        Claims {
            aud: self.audience.clone(),
            sub,
            session_id,
            role,
            contexts,
            exp,
            iat: now_secs,
            tee_attested,
            amr: Vec::new(),
            acr: String::new(),
            jti: String::new(),
        }
    }
}

impl Claims {
    /// Builder-style setter for the `amr` + `acr` claims. Production
    /// minters that know how the session was authenticated call this
    /// after [`JwtKeys::new_claims`] to attach the AAL signal:
    ///
    /// ```ignore
    /// let claims = jwt_keys.new_claims(/* ... */)
    ///     .with_aal(vec!["did".into()], "aal1");
    /// ```
    ///
    /// Step-up flows append a factor and raise the acr:
    ///
    /// ```ignore
    /// claims = claims.with_aal(vec!["did".into(), "passkey".into()], "aal2");
    /// ```
    /// Builder-style setter for the `jti` pin. Minters call this after
    /// [`JwtKeys::new_claims`] with the same value they persist as the
    /// session's `token_id`, so the extractor's pin check matches. Defaults to
    /// empty (no pin) when not called.
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = jti.into();
        self
    }

    pub fn with_aal(mut self, amr: Vec<String>, acr: impl Into<String>) -> Self {
        self.amr = amr;
        self.acr = acr.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Pin jsonwebtoken's default `CryptoProvider` to `aws_lc_rs`
    /// once per process. Required because jsonwebtoken's auto-select
    /// panics when more than one provider is in the feature graph;
    /// `cargo test --workspace` unifies features across crates and
    /// can produce that situation. We compile `jsonwebtoken` with
    /// only the `aws_lc_rs` backend (the `rust_crypto` bundle pulls
    /// in `rsa` which is exposed to RUSTSEC-2023-0071), so this is
    /// also the only backend available at runtime.
    fn init_jwt_provider() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
        });
    }

    fn test_keys() -> JwtKeys {
        init_jwt_provider();
        JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "VTA").unwrap()
    }

    #[test]
    fn test_jwt_roundtrip() {
        let keys = test_keys();
        let claims = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-1".into(),
            "admin".into(),
            vec!["vta".into()],
            900,
            false,
        );
        let token = keys.encode(&claims).unwrap();
        let decoded = keys.decode(&token).unwrap();
        assert_eq!(decoded.sub, "did:key:z6Mk");
        assert_eq!(decoded.role, "admin");
        assert!(!decoded.tee_attested);
    }

    #[test]
    fn jti_defaults_empty_and_round_trips_when_set() {
        let keys = test_keys();
        // Default: no pin.
        let plain = keys.new_claims(
            "did:key:z6Mk".into(),
            "s".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        assert_eq!(plain.jti, "", "jti defaults empty (unpinned)");
        assert!(!keys.encode(&plain).unwrap().is_empty());

        // Pinned via the builder: survives encode → decode.
        let pinned = keys
            .new_claims(
                "did:key:z6Mk".into(),
                "s".into(),
                "admin".into(),
                vec![],
                900,
                false,
            )
            .with_jti("tok-abc123");
        assert_eq!(pinned.jti, "tok-abc123");
        let decoded = keys.decode(&keys.encode(&pinned).unwrap()).unwrap();
        assert_eq!(
            decoded.jti, "tok-abc123",
            "jti must round-trip so the extractor pin can match"
        );
    }

    #[test]
    fn test_jwt_tee_attested_true() {
        let keys = test_keys();
        let claims = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-2".into(),
            "admin".into(),
            vec![],
            900,
            true,
        );
        let token = keys.encode(&claims).unwrap();

        // Verify the raw JSON contains tee_attested
        let parts: Vec<&str> = token.split('.').collect();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(json["tee_attested"], true);

        let decoded = keys.decode(&token).unwrap();
        assert!(decoded.tee_attested);
    }

    #[test]
    fn test_jwt_tee_attested_false_omitted() {
        let keys = test_keys();
        let claims = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-3".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        let token = keys.encode(&claims).unwrap();

        // Verify tee_attested is NOT in the JSON (skip_serializing_if)
        let parts: Vec<&str> = token.split('.').collect();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(json.get("tee_attested").is_none());
    }

    #[test]
    fn test_jwt_audience_parameterized() {
        let vta_keys = JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "VTA").unwrap();
        let vtc_keys = JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "VTC").unwrap();

        // VTA token should decode with VTA keys
        let claims = vta_keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-1".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        let token = vta_keys.encode(&claims).unwrap();
        assert!(vta_keys.decode(&token).is_ok());
        // VTA token should NOT decode with VTC audience
        assert!(vtc_keys.decode(&token).is_err());

        // VTC token should decode with VTC keys
        let claims = vtc_keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-2".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        let token = vtc_keys.encode(&claims).unwrap();
        assert!(vtc_keys.decode(&token).is_ok());
        assert!(vta_keys.decode(&token).is_err());
    }

    // ── Rejection tests ─────────────────────────────────────────────
    //
    // The textbook JWT bypasses: expired tokens, `alg: none` attacks,
    // tampered signatures, wrong signer, missing required claims.
    // These assert the jsonwebtoken crate's defaults are actually on
    // in our wrapper — a misconfigured Validation would silently
    // accept any of them.

    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    /// Rewrite a JWT's payload with extra mutations applied, re-signing
    /// with the provided keys so the signature stays valid. Used to
    /// test that decode rejects claim-level issues (expiry, missing
    /// fields) rather than accidentally asserting signature failure.
    fn reencode_with<F: FnOnce(&mut serde_json::Value)>(
        keys: &JwtKeys,
        claims: &Claims,
        mutate: F,
    ) -> String {
        let mut payload = serde_json::to_value(claims).unwrap();
        mutate(&mut payload);
        let header = Header::new(Algorithm::EdDSA);
        let header_json = serde_json::to_vec(&header).unwrap();
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let signing_input = format!(
            "{}.{}",
            B64URL.encode(&header_json),
            B64URL.encode(&payload_json)
        );
        // Re-sign via the wrapper's own encode path by reconstructing
        // via jsonwebtoken. Simplest: just encode a fresh Claims whose
        // serde repr matches our mutated payload.
        let mutated: Claims = serde_json::from_value(payload).unwrap();
        let _ = signing_input;
        keys.encode(&mutated).unwrap()
    }

    #[test]
    fn decode_rejects_expired_token() {
        let keys = test_keys();
        let expired = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-expired".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        // Drop exp into the past before signing.
        let past_token = reencode_with(&keys, &expired, |payload| {
            payload["exp"] = serde_json::json!(1);
        });

        let err = keys
            .decode(&past_token)
            .expect_err("expired token must be rejected");
        assert!(matches!(err, AppError::Unauthorized(_)), "got {err:?}");
    }

    #[test]
    fn decode_rejects_tampered_signature() {
        let keys = test_keys();
        let claims = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-tamper".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        let token = keys.encode(&claims).unwrap();

        // Flip one byte in the signature segment.
        let mut parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut sig_bytes = B64URL.decode(parts[2]).unwrap();
        sig_bytes[0] ^= 0x01;
        let tampered_sig = B64URL.encode(&sig_bytes);
        parts[2] = &tampered_sig;
        let tampered = parts.join(".");

        let err = keys
            .decode(&tampered)
            .expect_err("tampered signature must be rejected");
        assert!(matches!(err, AppError::Unauthorized(_)), "got {err:?}");
    }

    #[test]
    fn decode_rejects_alg_none_header() {
        // Classic JWT bypass: forge a header claiming alg=none and
        // omit the signature. The decoder must reject it — only EdDSA
        // is accepted. A naive `Validation::default()` would allow
        // alg=none in some jsonwebtoken versions; our wrapper pins
        // Algorithm::EdDSA which prevents that.
        let keys = test_keys();
        let claims = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-none".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        let payload = serde_json::to_vec(&claims).unwrap();
        let none_header = r#"{"typ":"JWT","alg":"none"}"#;
        let header_b64 = B64URL.encode(none_header.as_bytes());
        let payload_b64 = B64URL.encode(&payload);
        // No signature — some none-accepting parsers still want the
        // trailing dot. Try both shapes.
        for forged in [
            format!("{header_b64}.{payload_b64}."),
            format!("{header_b64}.{payload_b64}"),
        ] {
            let err = keys.decode(&forged).expect_err("alg=none must be rejected");
            assert!(
                matches!(err, AppError::Unauthorized(_)),
                "got {err:?} for shape {forged:?}"
            );
        }
    }

    #[test]
    fn decode_rejects_foreign_signer() {
        // A token signed by a different JWT key must not decode,
        // regardless of audience match.
        let genuine = test_keys();
        let attacker = JwtKeys::from_ed25519_bytes(&[0xAAu8; 32], "VTA").unwrap();

        let claims = attacker.new_claims(
            "did:key:zForged".into(),
            "sess-forged".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        let forged = attacker.encode(&claims).unwrap();

        let err = genuine
            .decode(&forged)
            .expect_err("token signed by foreign key must be rejected");
        assert!(matches!(err, AppError::Unauthorized(_)), "got {err:?}");
    }

    #[test]
    fn decode_rejects_missing_required_claims() {
        // set_required_spec_claims(["exp","sub","aud","session_id","role"])
        // is load-bearing — a caller that drops any of these shouldn't
        // slip through. Build a JWT manually with no `exp` and confirm
        // decode rejects it.
        let keys = test_keys();
        let claims = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-missing".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        // Encode normally, then rewrite the payload without `exp`.
        let mut payload = serde_json::to_value(&claims).unwrap();
        payload.as_object_mut().unwrap().remove("exp");
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let header = Header::new(Algorithm::EdDSA);
        let header_bytes = serde_json::to_vec(&header).unwrap();

        // Naively build + sign with the SAME keypair so only the
        // missing-claim check can reject this.
        let signing_input = format!(
            "{}.{}",
            B64URL.encode(&header_bytes),
            B64URL.encode(&payload_bytes)
        );
        // Compute the raw Ed25519 signature over the signing input.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(signing_input.as_bytes());
        let forged = format!("{signing_input}.{}", B64URL.encode(sig.to_bytes()));

        let err = keys
            .decode(&forged)
            .expect_err("token missing `exp` must be rejected");
        assert!(matches!(err, AppError::Unauthorized(_)), "got {err:?}");
    }

    #[test]
    fn decode_rejects_empty_token() {
        let keys = test_keys();
        assert!(matches!(keys.decode(""), Err(AppError::Unauthorized(_))));
    }

    #[test]
    fn decode_rejects_malformed_structure() {
        let keys = test_keys();
        for bad in ["not-a-jwt", "only.two", "four.dot.separated.parts"] {
            let err = keys
                .decode(bad)
                .expect_err(&format!("{bad:?} must be rejected"));
            assert!(matches!(err, AppError::Unauthorized(_)), "got {err:?}");
        }
    }
}
