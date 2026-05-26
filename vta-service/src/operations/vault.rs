//! Vault operations layer — primitives the vault trust-task handlers
//! reach for when they need elevated authority (e.g. resolving the
//! signing key referenced by a `did-self-issued` vault entry without
//! re-running the caller-facing ACL gate). Mirrors the shape of
//! [`crate::operations::step_up_approval`], which holds the same kind
//! of internal-authority helpers for the step-up flow.
//!
//! M2B.2b ships the SIOP id-token issuance path used by
//! `vault/proxy-login/0.1` when the entry's secret is a
//! `did-self-issued` reference. Password POST + OAuth refresh drivers
//! land in M2B.5 — they'll grow this module rather than the handler's
//! file so the auth-elevated paths stay scoped here.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::operations::internal_authority::InternalAuthority;
use crate::store::KeyspaceHandle;
use vta_sdk::did_key::decode_private_key_multibase;

/// Audit channel tag for the internal authority used by
/// proxy-login key resolution.
const PROXY_LOGIN_CHANNEL: &str = "vault-proxy-login-internal";

/// Default SIOP id_token lifetime (seconds). The vault/proxy-login spec
/// recommends a short window; 300 s matches the step-up token's TTL and
/// is a sensible ceiling for a one-shot login token.
pub const PROXY_LOGIN_ID_TOKEN_TTL_SECS: u64 = 300;

/// Load an Ed25519 signing key by its key-record id from the vault's
/// keystore. Generalises [`crate::operations::step_up_approval::load_vta_key0_signing_key`]
/// — that helper is hardcoded to `{vta_did}#key-0`; this one accepts any
/// key id (which is exactly what a `did-self-issued` vault entry's
/// `signing_key_id` field references).
///
/// Auth: gated by `InternalAuthority` per the operations-layer convention.
/// The caller (vault proxy-login handler) has already validated the
/// `ProxyLogin` capability + the entry's context scope; this helper
/// trusts those gates.
pub async fn load_signing_key_by_id(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit_ks: &KeyspaceHandle,
    key_id: &str,
) -> Result<SigningKey, AppError> {
    let authority = InternalAuthority::new("vault-proxy-login");
    let resp = crate::operations::keys::get_key_secret_internal(
        keys_ks,
        imported_ks,
        seed_store,
        audit_ks,
        authority,
        key_id,
        PROXY_LOGIN_CHANNEL,
    )
    .await?;
    let seed: [u8; 32] = decode_private_key_multibase(&resp.private_key_multibase)
        .map_err(|e| AppError::Internal(format!("decode signing-key seed for {key_id}: {e}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Build a SIOPv2 id_token (compact Ed25519 JWS) on behalf of a
/// `did-self-issued` vault entry. Header carries the entry's
/// `signing_key_id` as `kid`; payload follows SIOP shape with
/// `iss == sub` (the self-issued DID), `aud` (the relying-party DID or
/// origin), random `nonce`, server-issued `iat`/`exp`.
///
/// Unlike `step_up_approval::build_vta_approval_token` which has
/// `iss = vta_did, sub = holder_did` (VTA vouches for someone), SIOP
/// has `iss == sub` (the holder self-asserts). The actual signing
/// authority is the VTA — it holds the key — but the wire shape
/// presents the DID as both issuer and subject because the relying
/// party only knows the DID, not who custodies its keys.
///
/// `nonce` is generated server-side (UUIDv4) — the spec accepts a
/// client `nonce` claim in `ttlSecondsHint` siblings but for M2B.2b
/// the wallet doesn't supply one and the maintainer is the authority
/// on nonce freshness anyway.
pub fn build_siop_id_token(
    siop_did: &str,
    signing_key_id: &str,
    audience: &str,
    iat: u64,
    ttl_secs: u64,
    signing_key: &SigningKey,
) -> Result<String, AppError> {
    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": signing_key_id,
    });
    let payload = json!({
        "iss": siop_did,
        "sub": siop_did,
        "aud": audience,
        "nonce": uuid::Uuid::new_v4().to_string(),
        "iat": iat,
        "exp": iat.saturating_add(ttl_secs),
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|e| AppError::Internal(format!("serialize SIOP header: {e}")))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&payload)
            .map_err(|e| AppError::Internal(format!("serialize SIOP payload: {e}")))?,
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn siop_id_token_round_trip_verifies_against_signing_key() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key: VerifyingKey = (&signing_key).into();

        let siop_did = "did:webvh:Q1:proxy.example:persona-work";
        let kid = format!("{siop_did}#key-0");
        let audience = "did:web:rp.example";
        let iat = 1_700_000_000u64;
        let ttl = 300;

        let jws = build_siop_id_token(siop_did, &kid, audience, iat, ttl, &signing_key)
            .expect("build SIOP id_token");

        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS = 3 parts");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig decode");
        let signature = Signature::from_slice(&sig_bytes).expect("sig parse");
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature verifies against the signing key's public half");

        // Header carries the right kid + alg.
        let header_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("header decode"))
                .expect("header parse");
        assert_eq!(header_json["alg"], "EdDSA");
        assert_eq!(header_json["typ"], "JWT");
        assert_eq!(header_json["kid"], kid);

        // Payload: iss == sub == siop_did; aud, iat, exp as specified;
        // nonce is a non-empty server-generated string.
        let payload_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("payload decode"))
                .expect("payload parse");
        assert_eq!(payload_json["iss"], siop_did);
        assert_eq!(payload_json["sub"], siop_did);
        assert_eq!(payload_json["aud"], audience);
        assert_eq!(payload_json["iat"], iat);
        assert_eq!(payload_json["exp"], iat + ttl);
        assert!(
            payload_json["nonce"]
                .as_str()
                .map(|n| !n.is_empty())
                .unwrap_or(false),
            "nonce is server-generated and non-empty"
        );
    }

    #[test]
    fn siop_id_token_different_signing_key_fails_verification() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let wrong_key: VerifyingKey = (&SigningKey::from_bytes(&[99u8; 32])).into();

        let jws = build_siop_id_token(
            "did:webvh:foo",
            "did:webvh:foo#key-0",
            "did:web:rp.example",
            1_700_000_000,
            300,
            &signing_key,
        )
        .unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        assert!(
            wrong_key.verify(signing_input.as_bytes(), &sig).is_err(),
            "verification must fail against an unrelated public key"
        );
    }
}
