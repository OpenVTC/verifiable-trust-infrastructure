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

use affinidi_messaging_didcomm::Message;
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::messaging::ATM;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use uuid::Uuid;

use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::operations::internal_authority::InternalAuthority;
use crate::store::KeyspaceHandle;
use vta_sdk::did_key::decode_private_key_multibase;

/// `vault/release/0.1` sealing logic.
pub mod release;

/// DIDComm `Message.typ` for the release envelope's cleartext. Workspace-
/// namespaced (not a Trust Task URI) — purely transport metadata inside the
/// JWE; the consumer parses the JWE body as `VaultSecret` directly per the
/// `vault/release/0.1` spec.
pub const RELEASE_INNER_MSG_TYPE: &str = "https://openvtc.org/vault/release/secret-envelope/1.0";

/// Authcrypt `body` from the VTA (`vta_did`) to `holder_did`, returning the
/// JWE. Shared by the release + proxy-login flows — both seal a cleartext body
/// (a `VaultSecret` / a `SessionBlob`) to the calling holder, signed and
/// encrypted as the VTA. `inner_type` is the inner DIDComm `Message.typ`.
pub async fn authcrypt_to_holder(
    atm: &ATM,
    vta_did: &str,
    holder_did: &str,
    inner_type: &str,
    body: serde_json::Value,
) -> Result<String, AppError> {
    let msg = Message::build(Uuid::new_v4().to_string(), inner_type.to_string(), body)
        .from(vta_did.to_string())
        .to(holder_did.to_string())
        .finalize();
    let (jwe, _metadata) = atm
        .pack_encrypted(&msg, holder_did, Some(vta_did), Some(vta_did))
        .await
        .map_err(|e| AppError::Internal(format!("pack_encrypted failed: {e}")))?;
    Ok(jwe)
}

/// HTTP-POST driver for vault/proxy-login/0.1 against
/// `VaultSecret::Password` entries with a populated `loginConfig`.
/// Pulls in `reqwest` + `url`, so it's gated behind `webvh` — every
/// real consumer of vta-service (local binary + enclave) enables that
/// feature already, but the gating keeps `cargo check
/// --no-default-features` honest.
#[cfg(feature = "webvh")]
pub mod password_post;

/// Audit channel tag for the internal authority used by
/// proxy-login key resolution.
const PROXY_LOGIN_CHANNEL: &str = "vault-proxy-login-internal";

/// Audit channel tag for the internal authority used by
/// sign-trust-task key resolution.
const SIGN_TRUST_TASK_CHANNEL: &str = "vault-sign-trust-task-internal";

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

/// Load an Ed25519 signing key by id as an affinidi
/// [`Secret`](affinidi_secrets_resolver::secrets::Secret) — the form
/// `affinidi_data_integrity::DataIntegrityProof::sign` consumes.
/// Companion to [`load_signing_key_by_id`] which returns the raw
/// `ed25519_dalek::SigningKey` used by the SIOP id_token JWS path.
///
/// Auth: gated by `InternalAuthority`. The caller (sign-trust-task
/// handler) has already validated the `SignTrustTask` capability and
/// the entry's context scope.
pub async fn load_signing_secret_by_id(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit_ks: &KeyspaceHandle,
    key_id: &str,
) -> Result<Secret, AppError> {
    let authority = InternalAuthority::new("vault-sign-trust-task");
    let resp = crate::operations::keys::get_key_secret_internal(
        keys_ks,
        imported_ks,
        seed_store,
        audit_ks,
        authority,
        key_id,
        SIGN_TRUST_TASK_CHANNEL,
    )
    .await?;
    let mut secret = Secret::from_multibase(&resp.private_key_multibase, None)
        .map_err(|e| AppError::Internal(format!("construct Secret for {key_id}: {e}")))?;
    secret.id = key_id.to_string();
    Ok(secret)
}

/// Build a SIOPv2 id_token (compact Ed25519 JWS) on behalf of a
/// `did-self-issued` vault entry. Header carries the entry's
/// `signing_key_id` as `kid`; payload follows SIOP shape with
/// `iss == sub` (the self-issued DID), `aud` (the relying-party DID or
/// origin), `nonce` (caller-supplied verbatim if `Some`, else a fresh
/// UUIDv4), server-issued `iat`/`exp`.
///
/// Unlike `step_up_approval::build_vta_approval_token` which has
/// `iss = vta_did, sub = holder_did` (VTA vouches for someone), SIOP
/// has `iss == sub` (the holder self-asserts). The actual signing
/// authority is the VTA — it holds the key — but the wire shape
/// presents the DID as both issuer and subject because the relying
/// party only knows the DID, not who custodies its keys.
///
/// **Nonce handling.** Per `vault/proxy-login/0.1` conformance bullet
/// #5, when the consumer supplies `nonce` the maintainer MUST embed
/// it verbatim. The canonical use is SIOPv2: the RP's authorization-
/// request `nonce` MUST appear as the `nonce` claim in the id_token
/// or the RP's exact-match check fails. We treat the supplied nonce
/// as opaque — no trimming, canonicalisation, or re-encoding. When
/// `None`, the maintainer generates a fresh UUIDv4; that path is
/// appropriate for push-mode flows where the consumer doesn't
/// pre-fetch a challenge.
pub fn build_siop_id_token(
    siop_did: &str,
    signing_key_id: &str,
    audience: &str,
    nonce: Option<&str>,
    iat: u64,
    ttl_secs: u64,
    signing_key: &SigningKey,
) -> Result<String, AppError> {
    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": signing_key_id,
    });
    let nonce_claim = match nonce {
        Some(n) => n.to_string(),
        None => uuid::Uuid::new_v4().to_string(),
    };
    let payload = json!({
        "iss": siop_did,
        "sub": siop_did,
        "aud": audience,
        "nonce": nonce_claim,
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

        let jws = build_siop_id_token(siop_did, &kid, audience, None, iat, ttl, &signing_key)
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
            None,
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

    #[test]
    fn siop_id_token_embeds_caller_nonce_verbatim() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        // Pick a nonce that's NOT a UUID and contains characters the
        // server might be tempted to canonicalise — verifies we treat
        // it as opaque per the spec.
        let nonce = "rp-challenge_5e3f-AB cd~!@#$%^&*()";
        let jws = build_siop_id_token(
            "did:webvh:foo",
            "did:webvh:foo#key-0",
            "did:web:rp.example",
            Some(nonce),
            1_700_000_000,
            300,
            &signing_key,
        )
        .expect("build SIOP id_token with caller nonce");
        let parts: Vec<&str> = jws.split('.').collect();
        let payload_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            payload_json["nonce"], nonce,
            "caller-supplied nonce must appear verbatim in the id_token's nonce claim"
        );
    }

    #[test]
    fn siop_id_token_generates_uuid_nonce_when_none_supplied() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let jws = build_siop_id_token(
            "did:webvh:foo",
            "did:webvh:foo#key-0",
            "did:web:rp.example",
            None,
            1_700_000_000,
            300,
            &signing_key,
        )
        .unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        let payload_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let n = payload_json["nonce"].as_str().expect("nonce is a string");
        // UUIDv4: 8-4-4-4-12 hex with dashes = 36 chars total.
        assert_eq!(n.len(), 36, "fallback nonce is a UUIDv4 (36 chars)");
        assert!(
            uuid::Uuid::parse_str(n).is_ok(),
            "fallback nonce parses as a UUID"
        );
    }
}
