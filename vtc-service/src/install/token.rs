//! [`InstallTokenClaims`] + [`InstallTokenSigner`] — the JWT bearer
//! credential `vtc setup` prints to the operator after provisioning.
//!
//! ## Design (plan D2)
//!
//! - **Signature**: EdDSA over an Ed25519 key derived via
//!   `HKDF-SHA256(IKM = bundle.ed25519_priv, info = b"vtc-install-jwt-key/v2")`.
//!   The IKM is the 32-byte Ed25519 private the VTA handed back in
//!   the `vtc-host` template bundle — see
//!   `tasks/vtc-mvp/vta-driven-keys.md` §5.2 for why the version
//!   bumped (pre-rework deployments fed 64-byte BIP-39 seeds, so a
//!   `/v1` derivation would silently mint tokens that the `/v2`
//!   verifier rejects). Same trust boundary signs + verifies, so a
//!   symmetric MAC would also work — EdDSA is chosen to match the
//!   workspace JWT convention so the wire shape is identical to
//!   the session JWTs that follow.
//! - **Audience**: `"vtc-install"` (pinned). A session-token decoder
//!   configured for `"VTC"` will reject this token, and vice versa.
//! - **Subject**: `"install"`. Distinguishes the install bearer
//!   from any future operator/admin tokens minted under the same
//!   audience family.
//! - **TTL**: 15 minutes (`INSTALL_TOKEN_DEFAULT_TTL_SECS`).
//! - **Per-token state**: each token carries a random `jti` (Uuid),
//!   the WebAuthn ceremony nonce (`cnonce`, 32 random bytes
//!   base64url-encoded), and the **public** half of an ephemeral
//!   Ed25519 keypair (`epubkey`, base64url-encoded). The matching
//!   private half lives in the `install` keyspace under the `jti`,
//!   never touches the wire.
//!
//! ## Why both wire and server hold the cnonce
//!
//! The browser reads `cnonce` from the parsed token (no server
//! round-trip needed to start a WebAuthn ceremony). The server
//! stores its own copy so it can validate the WebAuthn assertion's
//! `clientDataJSON.challenge` field against the **authoritative**
//! value indexed by `jti`. A stolen token alone is insufficient —
//! the WebAuthn ceremony binds to the cnonce the server holds, and
//! a manipulated wire `cnonce` would mismatch the stored one.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::AppError;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Audience claim every install token carries. Pinned in code; a
/// session-token decoder configured for the `"VTC"` audience will
/// reject install tokens by design.
pub const INSTALL_AUDIENCE: &str = "vtc-install";

/// Subject claim every install token carries. Distinguishes the
/// install bearer from any future operator/admin token shaped under
/// the same audience family.
pub const INSTALL_SUBJECT: &str = "install";

/// Default install-token lifetime in seconds. Spec §4.1 — long
/// enough that an operator who clicked the URL has time to complete
/// the WebAuthn ceremony, short enough that an unobserved leaked
/// URL doesn't sit redeemable for hours.
pub const INSTALL_TOKEN_DEFAULT_TTL_SECS: u64 = 15 * 60;

/// Audience claim for the setup-session token minted by
/// `/v1/install/claim/finish`. The token bridges the install
/// ceremony to M0.6's `/v1/admin/bootstrap`; `"VTC"` and
/// `"vtc-install"` audience decoders both reject it by design.
pub const INSTALL_SESSION_AUDIENCE: &str = "vtc-install-session";

/// Default setup-session token lifetime in seconds. The operator
/// has just completed the WebAuthn ceremony; they need a few
/// minutes to round-trip to the bootstrap endpoint before the
/// receipt expires.
pub const INSTALL_SESSION_DEFAULT_TTL_SECS: u64 = 5 * 60;

/// HKDF info string for install-token signing key derivation.
/// Bumped from `/v1` to `/v2` as part of the VTA-driven-keys
/// rework (`tasks/vtc-mvp/vta-driven-keys.md` §5.2): the IKM is
/// no longer a 64-byte BIP-39 seed but a 32-byte Ed25519 private
/// scalar handed back by the VTA's `provision-integration`. Any
/// pre-rework deployment that still feeds a 64-byte buffer will
/// derive a different signing key and fail token verification
/// loudly instead of silently accepting tokens minted under the
/// old derivation.
const HKDF_INFO: &[u8] = b"vtc-install-jwt-key/v2";

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// JWT claims for an install token. Field names match RFC 7519
/// where applicable; custom fields keep `snake_case` for
/// readability (this token isn't consumed by external SIEM
/// tooling).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallTokenClaims {
    /// Issuer — the VTC DID (or `did:key:vtc-install-uninitialised`
    /// when minted before the VTC DID is known, e.g. during the
    /// very first `vtc setup` run before the DID is provisioned).
    pub iss: String,
    /// Always [`INSTALL_SUBJECT`].
    pub sub: String,
    /// Always [`INSTALL_AUDIENCE`].
    pub aud: String,
    /// Unix-second expiry timestamp.
    pub exp: u64,
    /// Unix-second issued-at timestamp.
    pub iat: u64,
    /// Stable identifier — used as the key in the `install`
    /// keyspace state machine (M0.4.2).
    pub jti: String,
    /// Base64url-encoded 32-byte WebAuthn ceremony nonce. The
    /// browser reads this directly from the parsed JWT to start the
    /// ceremony; the server stores its own authoritative copy and
    /// validates the WebAuthn assertion against it.
    pub cnonce: String,
    /// Base64url-encoded **public** half of the ephemeral Ed25519
    /// keypair. Used by `/install/claim/finish` to verify the
    /// candidate `did:key` signature without trusting the wire
    /// shape of the ceremony alone.
    pub epubkey: String,
    /// Admin DID this invite materialises an ACL entry + passkey for.
    /// Carried in the JWT so `claim_finish` doesn't have to derive
    /// the DID from the passkey — the passkey can be any algorithm
    /// (ES256, RS256, EdDSA), matching what platform authenticators
    /// produce. Modelled on `affinidi-webvh-service::Enrollment::did`.
    pub admin_did: String,
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

/// Holds the EdDSA encode/decode keys derived from the master seed.
/// Cheap to clone (jsonwebtoken's keys are small).
pub struct InstallTokenSigner {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl InstallTokenSigner {
    /// Derive the install-token signing key from `master_seed` via
    /// HKDF. Idempotent — same seed yields the same encode/decode
    /// keys, so a restart doesn't invalidate outstanding tokens.
    pub fn from_master_seed(master_seed: &[u8]) -> Result<Self, AppError> {
        let mut signing_key_bytes = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, master_seed)
            .expand(HKDF_INFO, signing_key_bytes.as_mut())
            .map_err(|e| AppError::Internal(format!("HKDF expand failed: {e}")))?;

        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let public_bytes = signing_key.verifying_key().to_bytes();

        // PKCS8 v1 DER wrap for the private key (mirror of
        // vti_common::auth::jwt::JwtKeys — the DER bytes are stable
        // and well-known so we duplicate them here rather than
        // extracting a helper).
        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        pkcs8.extend_from_slice(signing_key_bytes.as_ref());

        let encoding = EncodingKey::from_ed_der(&pkcs8);
        let decoding = DecodingKey::from_ed_der(&public_bytes);
        Ok(Self { encoding, decoding })
    }

    /// Sign a `InstallTokenClaims` into an EdDSA-signed JWT.
    pub fn encode(&self, claims: &InstallTokenClaims) -> Result<String, AppError> {
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|e| AppError::Internal(format!("install JWT encode failed: {e}")))
    }

    /// Verify + decode an install token. Validates the signature,
    /// audience, subject, and required claims; returns
    /// `AppError::Unauthorized` on every failure (the caller's
    /// 401/403 response carries no detail to avoid revealing which
    /// check rejected).
    pub fn decode(&self, token: &str) -> Result<InstallTokenClaims, AppError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[INSTALL_AUDIENCE]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "iat", "iss"]);

        let claims = jsonwebtoken::decode::<InstallTokenClaims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|_| AppError::Unauthorized("invalid install token".into()))?;

        if claims.sub != INSTALL_SUBJECT {
            return Err(AppError::Unauthorized("invalid install token".into()));
        }
        Ok(claims)
    }

    /// Sign an [`InstallSessionClaims`] into an EdDSA JWT. Shares the
    /// underlying signing key with [`Self::encode`]; the
    /// `"vtc-install-session"` audience separates the two token
    /// families at every decoder.
    pub fn encode_session(&self, claims: &InstallSessionClaims) -> Result<String, AppError> {
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|e| AppError::Internal(format!("install session JWT encode failed: {e}")))
    }

    /// Verify + decode an install-session token. Returns
    /// `AppError::Unauthorized` on every failure for the same
    /// defence-in-depth reason [`Self::decode`] does.
    pub fn decode_session(&self, token: &str) -> Result<InstallSessionClaims, AppError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[INSTALL_SESSION_AUDIENCE]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "iat", "iss"]);

        jsonwebtoken::decode::<InstallSessionClaims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|_| AppError::Unauthorized("invalid install session token".into()))
    }
}

// ---------------------------------------------------------------------------
// Install-session claims
// ---------------------------------------------------------------------------

/// JWT claims for the setup-session token minted at the end of the
/// install claim ceremony. `sub` is the candidate admin DID; M0.6's
/// `/v1/admin/bootstrap` will accept this token exactly once,
/// matching `sub` against the ACL entry it writes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSessionClaims {
    /// Issuer — the VTC DID.
    pub iss: String,
    /// Subject — the candidate admin `did:key` derived from the
    /// passkey's COSE public key.
    pub sub: String,
    /// Always [`INSTALL_SESSION_AUDIENCE`].
    pub aud: String,
    /// Unix-second expiry.
    pub exp: u64,
    /// Unix-second issued-at.
    pub iat: u64,
    /// Random identifier — M0.6's bootstrap endpoint can drop a
    /// once-only marker keyed by `jti` to prevent replay.
    pub jti: String,
    /// The originating install token's `jti`. Lets the bootstrap
    /// audit event (`CommunityInstalled.install_token_jti`)
    /// correlate the carve-out close with the install URL the
    /// operator clicked.
    pub install_jti: String,
}

// ---------------------------------------------------------------------------
// Mint / parse helpers
// ---------------------------------------------------------------------------

/// Outcome of [`mint_install_token`]: the signed JWT, the random
/// `jti`, the ephemeral signing key the caller must persist into
/// the `install` keyspace state alongside `(jti, cnonce_bytes)`,
/// and the wall-clock expiry.
pub struct MintedInstallToken {
    pub jwt: String,
    pub jti: Uuid,
    pub claims: InstallTokenClaims,
    /// Raw 32-byte cnonce (the JWT carries the base64url-encoded
    /// form; the keyspace state machine wants the raw bytes for
    /// constant-time comparison against the WebAuthn assertion).
    pub cnonce_bytes: [u8; 32],
    /// Ephemeral private key the keyspace state machine must hold;
    /// the browser only sees the matching public half via
    /// [`InstallTokenClaims::epubkey`].
    pub ephemeral_signing_key: Zeroizing<[u8; 32]>,
    pub expires_at_unix: u64,
}

/// Written by hand so the ephemeral signing key never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for MintedInstallToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedInstallToken")
            .field("jwt", &"<redacted>")
            .field("jti", &self.jti)
            .field("claims", &self.claims)
            .field("cnonce_bytes", &self.cnonce_bytes)
            .field("ephemeral_signing_key", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// Mint a fresh install token. Generates the `jti`, the WebAuthn
/// ceremony nonce, and the ephemeral keypair internally — the caller
/// only supplies the issuer DID and TTL.
pub fn mint_install_token(
    signer: &InstallTokenSigner,
    issuer_did: &str,
    admin_did: &str,
    ttl_seconds: u64,
) -> Result<MintedInstallToken, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exp = now + ttl_seconds;
    let jti = Uuid::new_v4();

    let mut cnonce_bytes = [0u8; 32];
    rand::fill(&mut cnonce_bytes);
    let cnonce = B64.encode(cnonce_bytes);

    let mut ephemeral_bytes = Zeroizing::new([0u8; 32]);
    rand::fill(&mut *ephemeral_bytes);
    let ephemeral_signing_key = SigningKey::from_bytes(&ephemeral_bytes);
    let epubkey = B64.encode(ephemeral_signing_key.verifying_key().to_bytes());

    let claims = InstallTokenClaims {
        iss: issuer_did.to_string(),
        sub: INSTALL_SUBJECT.to_string(),
        aud: INSTALL_AUDIENCE.to_string(),
        exp,
        iat: now,
        jti: jti.to_string(),
        cnonce,
        epubkey,
        admin_did: admin_did.to_string(),
    };
    let jwt = signer.encode(&claims)?;

    Ok(MintedInstallToken {
        jwt,
        jti,
        claims,
        cnonce_bytes,
        ephemeral_signing_key: ephemeral_bytes,
        expires_at_unix: exp,
    })
}

/// Verify + decode an install token. Thin wrapper over
/// [`InstallTokenSigner::decode`] for ergonomic call sites.
pub fn parse_install_token(
    signer: &InstallTokenSigner,
    token: &str,
) -> Result<InstallTokenClaims, AppError> {
    signer.decode(token)
}

/// Mint a setup-session token for `admin_did`. Called from
/// `POST /v1/install/claim/finish` after the WebAuthn ceremony and
/// DID-binding signature both verify. `install_jti` is the
/// originating install token's `jti` — propagated forward so the
/// bootstrap audit event can record it.
pub fn mint_install_session_token(
    signer: &InstallTokenSigner,
    issuer_did: &str,
    admin_did: &str,
    install_jti: &str,
    ttl_seconds: u64,
) -> Result<String, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exp = now + ttl_seconds;
    let jti = Uuid::new_v4().to_string();

    let claims = InstallSessionClaims {
        iss: issuer_did.to_string(),
        sub: admin_did.to_string(),
        aud: INSTALL_SESSION_AUDIENCE.to_string(),
        exp,
        iat: now,
        jti,
        install_jti: install_jti.to_string(),
    };
    signer.encode_session(&claims)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    /// Pin jsonwebtoken's default `CryptoProvider` to `aws_lc_rs`
    /// once per process (matches the workspace pattern from
    /// `vti_common::auth::jwt::tests::init_jwt_provider`).
    fn init_jwt_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
        });
    }

    const SEED: [u8; 32] = [0xAB; 32];

    fn signer() -> InstallTokenSigner {
        init_jwt_provider();
        InstallTokenSigner::from_master_seed(&SEED).unwrap()
    }

    #[test]
    fn round_trip_returns_same_claims() {
        let signer = signer();
        let minted = mint_install_token(
            &signer,
            "did:webvh:vtc.example.com:abc",
            "did:key:zAdmin",
            600,
        )
        .unwrap();
        let back = parse_install_token(&signer, &minted.jwt).unwrap();
        assert_eq!(back.iss, "did:webvh:vtc.example.com:abc");
        assert_eq!(back.aud, INSTALL_AUDIENCE);
        assert_eq!(back.sub, INSTALL_SUBJECT);
        assert_eq!(back.jti, minted.jti.to_string());
        assert_eq!(back.cnonce, minted.claims.cnonce);
        assert_eq!(back.epubkey, minted.claims.epubkey);
    }

    #[test]
    fn different_seeds_produce_disjoint_keys() {
        init_jwt_provider();
        let a = InstallTokenSigner::from_master_seed(&[0x01; 32]).unwrap();
        let b = InstallTokenSigner::from_master_seed(&[0x02; 32]).unwrap();
        let minted = mint_install_token(&a, "did:webvh:x", "did:key:zAdmin", 60).unwrap();
        let err = parse_install_token(&b, &minted.jwt).expect_err("must reject");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn expired_token_is_rejected() {
        let signer = signer();
        // TTL = 0 means `exp == iat`; jsonwebtoken treats `exp <= now`
        // as expired.
        let minted = mint_install_token(&signer, "did:webvh:x", "did:key:zAdmin", 0).unwrap();
        // Allow the second to tick — jsonwebtoken's clock-skew
        // tolerance is 60s by default, but `validate_exp = true` with
        // `leeway = 0` (Validation::new default sets leeway=60) means
        // we need to sleep past leeway. Use a deliberately stale
        // token instead: re-mint with a backdated exp.
        let claims = InstallTokenClaims {
            exp: 1, // 1970-01-01
            iat: 0,
            ..minted.claims.clone()
        };
        let stale = signer.encode(&claims).unwrap();
        let err = parse_install_token(&signer, &stale).expect_err("expired");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let signer = signer();
        let minted = mint_install_token(&signer, "did:webvh:x", "did:key:zAdmin", 600).unwrap();
        // Re-sign with a different aud claim.
        let mut claims = minted.claims.clone();
        claims.aud = "VTC".to_string();
        let stale = signer.encode(&claims).unwrap();
        let err = parse_install_token(&signer, &stale).expect_err("wrong aud");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn wrong_subject_is_rejected() {
        let signer = signer();
        let minted = mint_install_token(&signer, "did:webvh:x", "did:key:zAdmin", 600).unwrap();
        let mut claims = minted.claims.clone();
        claims.sub = "session".to_string();
        let stale = signer.encode(&claims).unwrap();
        let err = parse_install_token(&signer, &stale).expect_err("wrong sub");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let signer = signer();
        let minted = mint_install_token(&signer, "did:webvh:x", "did:key:zAdmin", 600).unwrap();
        // Flip the very last byte of the base64-encoded signature.
        let mut bytes = minted.jwt.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        let err = parse_install_token(&signer, &tampered).expect_err("tampered");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn cnonce_is_32_bytes_base64url() {
        let signer = signer();
        let minted = mint_install_token(&signer, "did:webvh:x", "did:key:zAdmin", 600).unwrap();
        let decoded = B64.decode(&minted.claims.cnonce).unwrap();
        assert_eq!(decoded.len(), 32);
        // And the round-tripped raw bytes match.
        assert_eq!(decoded.as_slice(), &minted.cnonce_bytes[..]);
    }

    #[test]
    fn epubkey_is_32_bytes_base64url() {
        let signer = signer();
        let minted = mint_install_token(&signer, "did:webvh:x", "did:key:zAdmin", 600).unwrap();
        let decoded = B64.decode(&minted.claims.epubkey).unwrap();
        assert_eq!(decoded.len(), 32);
    }
}
