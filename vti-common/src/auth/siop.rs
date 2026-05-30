//! SIOPv2 self-issued `id_token` verification.
//!
//! A browser wallet (the VTA wallet extension) self-issues a SIOPv2
//! `id_token` — a compact EdDSA JWS with claims
//! `{iss, sub, aud, nonce, iat, exp}` where `iss == sub` (the holder
//! signs for itself) — and POSTs it to a relying party's `/auth/`
//! endpoint. This module performs the **cryptographic** verification:
//! parse the JWS, confirm self-issuance, resolve the issuer DID to its
//! Ed25519 key, and verify the signature.
//!
//! The **policy** checks — `aud` matches this service, `nonce` matches
//! the issued challenge, and `iat`/`exp` freshness — are deliberately
//! the caller's job, because they need session and config state this
//! module doesn't own. [`verify_siop_id_token`] returns the
//! eagerly-parsed claims so the caller can apply them; the
//! [`VerifiedSiopIdToken`] type can only be constructed here, so a call
//! site can't read verified claims without having verified the
//! signature first.
//!
//! Ported from `did-hosting-control`'s SIOP path so the VTA, VTC, and
//! did-hosting services all verify wallet logins identically.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::did_common::DocumentExt;
use affinidi_tdk::didcomm::jws::envelope::JwsProtectedHeader;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

/// A SIOPv2 `id_token` whose signature has been verified against the
/// `iss` DID's resolved Ed25519 key. Constructable only via
/// [`verify_siop_id_token`]. The caller still must bind `audience` to
/// this service, `nonce` to the issued challenge, and check the
/// `issued_at`/`expires_at` freshness window before trusting it.
#[derive(Debug, Clone)]
pub struct VerifiedSiopIdToken {
    /// `iss` (== `sub`) — the holder DID that signed the token.
    pub issuer: String,
    /// `aud` — the relying-party DID the token is addressed to.
    pub audience: String,
    /// `nonce` — the challenge the relying party issued.
    pub nonce: String,
    /// `iat` — issued-at, unix seconds.
    pub issued_at: u64,
    /// `exp` — expiry, unix seconds.
    pub expires_at: u64,
}

/// Failure modes of [`verify_siop_id_token`]. Every variant maps to a
/// 401-class authentication failure at the route layer; the messages
/// are intentionally specific for operator logs but carry no secret
/// material.
#[derive(Debug, thiserror::Error)]
pub enum SiopError {
    #[error("id_token is not a compact JWS (header.payload.signature)")]
    MalformedJws,
    #[error("id_token {0} is not valid base64url")]
    Base64(&'static str),
    #[error("id_token {0} is not valid JSON")]
    Json(&'static str),
    #[error("id_token missing `{0}`")]
    MissingClaim(&'static str),
    #[error("id_token `iss` does not equal `sub`")]
    NotSelfIssued,
    #[error("id_token header missing `kid`")]
    MissingKid,
    #[error("id_token header `alg` is `{0}`; only EdDSA is accepted")]
    UnsupportedAlg(String),
    #[error("id_token header `kid` DID does not match `iss`")]
    KidMismatch,
    #[error("verification method {0} is not in the DID's `authentication` relationship")]
    VmNotAuthentication(String),
    #[error("failed to resolve DID {0}")]
    Resolve(String),
    #[error("verification method {0} not found in DID document")]
    VmNotFound(String),
    #[error(
        "verification method {0} is an X25519 key-agreement key; expected an Ed25519 signing key"
    )]
    NotSigningKey(String),
    #[error("id_token `iss` did:key does not match its resolved authentication key")]
    DidKeyMismatch,
    #[error("id_token `iss` is not an Ed25519 did:key")]
    NotEd25519DidKey,
    #[error("id_token public key is invalid: {0}")]
    BadPublicKey(String),
    #[error("id_token signature verification failed")]
    BadSignature,
}

/// Claims read out of the JWS payload before verification. All fields
/// are `Option` so a missing claim becomes a clean error rather than a
/// deserialization failure.
#[derive(Deserialize)]
struct SiopClaims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    nonce: Option<String>,
    iat: Option<u64>,
    exp: Option<u64>,
}

/// Verify a SIOPv2 self-issued `id_token` (compact EdDSA JWS).
///
/// Steps (cryptographic only — see module docs for what the caller
/// must still check):
/// 1. Split the compact JWS into `header.payload.signature`.
/// 2. Parse the payload and require `iss` present and `iss == sub`.
/// 3. Resolve the authentication key for `iss`. The header `kid` drives
///    the verification-method lookup and its base DID must equal `iss`.
///    For a self-certifying `did:key`, the resolved key is additionally
///    pinned against the key encoded in the DID string so a `kid`
///    pointing at a foreign DID's key can't impersonate `iss`. For
///    document-based methods (`did:webvh`, `did:peer`) the resolved DID
///    document is the authority.
/// 4. EdDSA-verify the signature over the ASCII `header.payload`.
pub async fn verify_siop_id_token(
    id_token: &str,
    did_resolver: &DIDCacheClient,
) -> Result<VerifiedSiopIdToken, SiopError> {
    // 1. Split the compact JWS. Exactly three dot-separated parts.
    let mut parts = id_token.split('.');
    let (header_b64, payload_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err(SiopError::MalformedJws),
        };

    // 2. Parse the payload (pre-verify) and enforce self-issuance.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| SiopError::Base64("payload"))?;
    let claims: SiopClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| SiopError::Json("payload"))?;
    let iss = claims.iss.ok_or(SiopError::MissingClaim("iss"))?;
    let sub = claims.sub.ok_or(SiopError::MissingClaim("sub"))?;
    if iss != sub {
        return Err(SiopError::NotSelfIssued);
    }

    // 3. Resolve the Ed25519 key. `kid`'s base DID must equal `iss`;
    //    `did:key` is additionally pinned to the in-string key.
    let kid = extract_signer_kid_compact(header_b64)?;
    let kid_base = kid.split('#').next().unwrap_or(&kid);
    if kid_base != iss {
        return Err(SiopError::KidMismatch);
    }
    let resolved_key = resolve_verifying_key(did_resolver, &kid).await?;
    if iss.starts_with("did:key:") {
        let did_key_pub = ed25519_pubkey_from_did_key(&iss)?;
        if resolved_key != did_key_pub {
            return Err(SiopError::DidKeyMismatch);
        }
    }

    // 4. EdDSA-verify over the ASCII `header.payload`.
    let verifying_key = VerifyingKey::from_bytes(&resolved_key)
        .map_err(|e| SiopError::BadPublicKey(e.to_string()))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| SiopError::Base64("signature"))?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| SiopError::BadSignature)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| SiopError::BadSignature)?;

    Ok(VerifiedSiopIdToken {
        issuer: iss,
        audience: claims.aud.ok_or(SiopError::MissingClaim("aud"))?,
        nonce: claims.nonce.ok_or(SiopError::MissingClaim("nonce"))?,
        issued_at: claims.iat.ok_or(SiopError::MissingClaim("iat"))?,
        expires_at: claims.exp.ok_or(SiopError::MissingClaim("exp"))?,
    })
}

/// Parse the `iss` claim from an `id_token` **without** verifying its
/// signature or resolving any DID. Enforces `iss == sub` (self-issued).
///
/// This is a cheap pre-check so a caller can bind the issuer to an existing
/// session *before* calling [`verify_siop_id_token`] — which performs a
/// network DID resolution of `iss`. Gating that resolution behind a
/// session/ACL check stops an unauthenticated caller from steering the
/// daemon into resolving (HTTP-fetching) an arbitrary attacker-chosen DID.
///
/// The returned DID is **not** authenticated — only [`verify_siop_id_token`]
/// proves the holder controls it. Never trust this value for anything but a
/// pre-resolution gate.
pub fn parse_unverified_iss(id_token: &str) -> Result<String, SiopError> {
    let payload_b64 = id_token.split('.').nth(1).ok_or(SiopError::MalformedJws)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| SiopError::Base64("payload"))?;
    let claims: SiopClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| SiopError::Json("payload"))?;
    let iss = claims.iss.ok_or(SiopError::MissingClaim("iss"))?;
    let sub = claims.sub.ok_or(SiopError::MissingClaim("sub"))?;
    if iss != sub {
        return Err(SiopError::NotSelfIssued);
    }
    Ok(iss)
}

/// Resolve `kid`'s base DID and return its Ed25519 public key bytes.
/// Mirrors the DID-resolve + key-extraction primitive the DIDComm
/// `unpack_signed` path uses. Rejects obvious X25519 key-agreement
/// methods; any Ed25519 verification-method type the resolver yields a
/// 32-byte key for is accepted.
async fn resolve_verifying_key(
    did_resolver: &DIDCacheClient,
    kid: &str,
) -> Result<[u8; 32], SiopError> {
    let base_did = kid.split('#').next().unwrap_or(kid);
    let resolved = did_resolver
        .resolve(base_did)
        .await
        .map_err(|e| SiopError::Resolve(format!("{base_did}: {e}")))?;

    // The key must be published for *authentication* — a SIOP login is an
    // authentication, so a key the DID controller listed only for
    // `assertionMethod` / `keyAgreement` / `capabilityInvocation` must not
    // mint a login token. `did:key` lists its key under every relationship
    // (incl. authentication), so this doesn't affect the did:key path.
    if !resolved.doc.contains_authentication(kid) {
        return Err(SiopError::VmNotAuthentication(kid.to_string()));
    }

    let vm = resolved
        .doc
        .get_verification_method(kid)
        .ok_or_else(|| SiopError::VmNotFound(kid.to_string()))?;

    // X25519 key-agreement keys have narrow, unambiguous *type* names —
    // refuse them early for a clear error.
    if matches!(
        vm.type_.as_str(),
        "X25519KeyAgreementKey2020" | "X25519KeyAgreementKey2019"
    ) {
        return Err(SiopError::NotSigningKey(kid.to_string()));
    }

    // Extract the key and **validate the multicodec**. The resolver
    // normalises signing keys to `Multikey` (a `publicKeyMultibase`). Decode
    // it ourselves and require the Ed25519 multicodec (`0xed01`): an X25519
    // key published as a `Multikey` (codec `0xec01`, `z6LS…`) would otherwise
    // decode to 32 bytes and be loaded as an "Ed25519" key, caught only later
    // at signature verification. Checking the codec here rejects it up front
    // and refuses any non-Ed25519 curve for the signing key.
    let multibase = vm
        .property_set
        .get("publicKeyMultibase")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SiopError::BadPublicKey(format!(
                "verification method {kid} has no publicKeyMultibase"
            ))
        })?;
    let (_base, bytes) = multibase::decode(multibase)
        .map_err(|e| SiopError::BadPublicKey(format!("publicKeyMultibase: {e}")))?;
    let key = bytes
        .strip_prefix(&[0xed, 0x01])
        .ok_or_else(|| SiopError::NotSigningKey(kid.to_string()))?;
    key.try_into()
        .map_err(|_| SiopError::BadPublicKey("public key must be 32 bytes".into()))
}

/// Extract the `kid` from a base64url-encoded compact-JWS protected
/// header.
fn extract_signer_kid_compact(header_b64: &str) -> Result<String, SiopError> {
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| SiopError::Base64("header"))?;
    let header: JwsProtectedHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| SiopError::Json("header"))?;
    // Verification is hard-wired to Ed25519; reject any other `alg` up
    // front so a future refactor can't reintroduce alg-confusion, and so
    // `alg:none` / HS256 tokens fail with a precise error.
    if !header.alg.eq_ignore_ascii_case("EdDSA") {
        return Err(SiopError::UnsupportedAlg(header.alg));
    }
    header.kid.ok_or(SiopError::MissingKid)
}

/// Decode the multibase tail of an Ed25519 `did:key` to its raw 32-byte
/// public key. Rejects anything that isn't `did:key:z…` with the
/// multicodec `0xed01` (Ed25519) prefix followed by exactly 32 bytes.
fn ed25519_pubkey_from_did_key(did: &str) -> Result<[u8; 32], SiopError> {
    let multibase = did
        .strip_prefix("did:key:")
        .ok_or(SiopError::NotEd25519DidKey)?;
    let (_base, bytes) = multibase::decode(multibase).map_err(|_| SiopError::NotEd25519DidKey)?;
    let key = bytes
        .strip_prefix(&[0xed, 0x01])
        .ok_or(SiopError::NotEd25519DidKey)?;
    key.try_into().map_err(|_| SiopError::NotEd25519DidKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use ed25519_dalek::{Signer, SigningKey};

    /// A local (network-free) resolver for the failure-path tests,
    /// which all short-circuit before any DID resolution happens.
    async fn test_resolver() -> DIDCacheClient {
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("build DID resolver")
    }

    /// Build a signed compact-JWS id_token for `did:key` issuers, plus
    /// helpers to tamper with it. Returns `(id_token, did)`.
    fn make_did_key_id_token(
        signing_key: &SigningKey,
        iss: &str,
        sub: &str,
        aud: &str,
        nonce: &str,
        iat: u64,
        exp: u64,
        kid: &str,
    ) -> String {
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
        let payload = serde_json::json!({
            "iss": iss, "sub": sub, "aud": aud, "nonce": nonce, "iat": iat, "exp": exp,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    fn did_key_for(signing_key: &SigningKey) -> String {
        let pubkey = signing_key.verifying_key().to_bytes();
        let mut buf = Vec::with_capacity(34);
        buf.extend_from_slice(&[0xed, 0x01]);
        buf.extend_from_slice(&pubkey);
        format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &buf)
        )
    }

    // NB: full happy-path verification needs a live DIDCacheClient to
    // resolve the issuer DID, so the round-trip is exercised in
    // vtc-service's integration tests (which build a resolver). These
    // unit tests cover the pure, resolver-independent failure paths
    // that short-circuit before resolution.

    #[tokio::test]
    async fn rejects_non_compact_jws() {
        let resolver = test_resolver().await;
        let err = verify_siop_id_token("not.a", &resolver).await.unwrap_err();
        assert!(matches!(err, SiopError::MalformedJws));
    }

    #[tokio::test]
    async fn rejects_when_iss_ne_sub() {
        let resolver = test_resolver().await;
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let did = did_key_for(&sk);
        let token = make_did_key_id_token(
            &sk,
            &did,
            "did:key:zSomeoneElse",
            "did:webvh:scid:rp.example",
            "nonce-1",
            1000,
            2000,
            &format!("{did}#key-0"),
        );
        let err = verify_siop_id_token(&token, &resolver).await.unwrap_err();
        assert!(matches!(err, SiopError::NotSelfIssued));
    }

    #[tokio::test]
    async fn rejects_when_kid_base_ne_iss() {
        let resolver = test_resolver().await;
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let did = did_key_for(&sk);
        // kid points at a different DID than iss/sub.
        let token = make_did_key_id_token(
            &sk,
            &did,
            &did,
            "did:webvh:scid:rp.example",
            "nonce-1",
            1000,
            2000,
            "did:key:zForeign#key-0",
        );
        let err = verify_siop_id_token(&token, &resolver).await.unwrap_err();
        assert!(matches!(err, SiopError::KidMismatch));
    }

    #[tokio::test]
    async fn rejects_missing_iss() {
        let resolver = test_resolver().await;
        // Hand-build a token with no `iss`.
        let header = serde_json::json!({ "alg": "EdDSA", "kid": "did:key:z#k" });
        let payload = serde_json::json!({ "sub": "did:key:z", "aud": "rp" });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("{h}.{p}.AAAA");
        let err = verify_siop_id_token(&token, &resolver).await.unwrap_err();
        assert!(matches!(err, SiopError::MissingClaim("iss")));
    }

    #[tokio::test]
    async fn rejects_unsupported_alg() {
        let resolver = test_resolver().await;
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let did = did_key_for(&sk);
        // Valid `iss == sub` so we reach the header check, but `alg` is not
        // EdDSA — must be rejected before any signature work.
        let header = serde_json::json!({ "alg": "HS256", "kid": format!("{did}#k") });
        let payload = serde_json::json!({
            "iss": did, "sub": did, "aud": "rp", "nonce": "n", "iat": 1, "exp": 2,
        });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("{h}.{p}.AAAA");
        let err = verify_siop_id_token(&token, &resolver).await.unwrap_err();
        assert!(matches!(err, SiopError::UnsupportedAlg(_)));
    }

    #[test]
    fn parse_unverified_iss_returns_self_issued_did() {
        let sk = SigningKey::from_bytes(&[15u8; 32]);
        let did = did_key_for(&sk);
        let kid = format!("{did}#k");
        let token = make_did_key_id_token(&sk, &did, &did, "rp", "n", 1, 2, &kid);
        assert_eq!(parse_unverified_iss(&token).unwrap(), did);
    }

    #[test]
    fn parse_unverified_iss_rejects_non_self_issued() {
        let sk = SigningKey::from_bytes(&[16u8; 32]);
        let did = did_key_for(&sk);
        let token = make_did_key_id_token(
            &sk,
            &did,
            "did:key:zOther",
            "rp",
            "n",
            1,
            2,
            &format!("{did}#k"),
        );
        assert!(matches!(
            parse_unverified_iss(&token),
            Err(SiopError::NotSelfIssued)
        ));
    }

    #[test]
    fn did_key_decode_round_trips() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let did = did_key_for(&sk);
        let decoded = ed25519_pubkey_from_did_key(&did).unwrap();
        assert_eq!(decoded, sk.verifying_key().to_bytes());
    }

    #[test]
    fn did_key_decode_rejects_non_ed25519() {
        assert!(matches!(
            ed25519_pubkey_from_did_key("did:key:zNotMultibaseEd25519!!"),
            Err(SiopError::NotEd25519DidKey)
        ));
        assert!(matches!(
            ed25519_pubkey_from_did_key("did:web:example.com"),
            Err(SiopError::NotEd25519DidKey)
        ));
    }
}
