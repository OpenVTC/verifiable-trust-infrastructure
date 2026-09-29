//! Step-up approval token: a compact EdDSA JWS the VTA signs *as itself*
//! to vouch that a holder may step up their session at a relying party
//! (RP).
//!
//! The token shape is fixed and verified by a separate RP service
//! (`did_hosting_common::server::didcomm_unpack::verify_vta_approval_token`).
//! It MUST match byte-for-byte:
//!
//! - **header** `{"alg":"EdDSA","typ":"JWT","kid":"<vta_did>#key-0"}`
//! - **payload** `{"iss":<vta_did>,"sub":<holder_did>,"aud":<rp_did>,
//!   "nonce":<nonce>,"iat":<unix>,"exp":<iat+300>}`
//! - **signature** Ed25519 over the UTF-8 bytes of
//!   `"<header_b64>.<payload_b64>"` using the VTA's `{vta_did}#key-0`
//!   key.
//!
//! Unlike the holder-self-issued SIOPv2 `id_token` (where `iss == sub`),
//! here `iss != sub`: the VTA vouches for the holder. The RP verifier
//! resolves `iss`'s key and requires the header `kid` base to equal
//! `iss` — so the `kid` is `"<vta_did>#key-0"` with base `<vta_did>`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::operations::internal_authority::InternalAuthority;
use crate::store::KeyspaceHandle;
use vta_sdk::did_key::decode_private_key_multibase;

/// Step-up approval token lifetime, in seconds. The RP verifier enforces
/// `iat <= now <= exp`; we stamp `exp = iat + 300` (5 minutes) — long
/// enough for the round-trip, short enough to bound replay.
const APPROVAL_TTL_SECS: u64 = 300;

/// Authorization gate: the holder must be a principal of this VTA (a live ACL
/// entry). Refusals are audited (VTI-AUD-003) as `step_up.approve` `denied`.
///
/// The approval is signed with the VTA's own `#key-0`, and what an RP reads
/// from it is "this VTA approved a step-up for `sub`". Without this gate any
/// DID anywhere could get that statement signed. The approval then proved
/// nothing beyond the sender holding its own key, which the RP's aal1 session
/// already proves. The VTA vouches only for subjects it serves, the rule
/// VTI-SES-006 applies to issuing an auth challenge.
pub async fn authorize_holder(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    holder_did: &str,
    channel: &str,
) -> Result<(), AppError> {
    if let Err(e) = crate::acl::check_acl(acl_ks, holder_did).await {
        tracing::warn!(
            audit = true,
            security_alert = true,
            holder = %holder_did,
            "step-up approval refused: sender is not a principal of this VTA"
        );
        vta_audit::record_with_detail_best_effort(
            audit,
            "step_up.approve",
            holder_did,
            None,
            "denied",
            Some(channel),
            None,
            Some(&e.to_string()),
        )
        .await;
        return Err(AppError::Forbidden(
            "step-up approval is available only to principals of this VTA".into(),
        ));
    }
    Ok(())
}

/// User-verification gate. Decides whether `holder_did` may step up at
/// `rp_did` *after* [`authorize_holder`] has established it is a principal.
///
/// Currently always approves. Real user verification plugs in here. It is not
/// the authorization control; [`authorize_holder`] is.
pub fn step_up_policy_approve(_holder_did: &str, _rp_did: &str) -> bool {
    // TODO: real user-verification (CLI confirm / passkey-at-VTA / push) plugs in here
    true
}

/// Build + sign the compact EdDSA approval-token JWS.
///
/// Byte-for-byte mirror of what the RP verifier
/// (`verify_vta_approval_token`) expects: header
/// `{"alg":"EdDSA","typ":"JWT","kid":"<vta_did>#key-0"}`, payload
/// `{iss,sub,aud,nonce,iat,exp}` with `iss = vta_did`, `sub = holder_did`,
/// `aud = rp_did`, `exp = iat + 300`, and an Ed25519 signature over the
/// ASCII `"<header_b64>.<payload_b64>"`.
///
/// `signing_key` MUST be the VTA's `{vta_did}#key-0` Ed25519 key so the
/// RP can resolve `iss`'s key and verify.
pub fn build_vta_approval_token(
    vta_did: &str,
    holder_did: &str,
    rp_did: &str,
    nonce: &str,
    iat: u64,
    signing_key: &SigningKey,
) -> Result<String, AppError> {
    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": format!("{vta_did}#key-0"),
    });
    let payload = json!({
        "iss": vta_did,
        "sub": holder_did,
        "aud": rp_did,
        "nonce": nonce,
        "iat": iat,
        "exp": iat + APPROVAL_TTL_SECS,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|e| AppError::Internal(format!("serialize approval header: {e}")))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&payload)
            .map_err(|e| AppError::Internal(format!("serialize approval payload: {e}")))?,
    );

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Load the VTA's `{vta_did}#key-0` Ed25519 signing key as an
/// `ed25519_dalek::SigningKey`.
///
/// This is the VTA's VC-issuance / assertion key — the same `#key-0` the
/// provision-integration flow uses for Data-Integrity proofs. We fetch it
/// via the internal-authority key-secret path (no caller-facing auth gate;
/// possessing an [`InternalAuthority`] *is* the gate) and decode the
/// 32-byte Ed25519 seed from the returned private-key multibase, mirroring
/// `provision_integration::vta_keys::build_did_signed_assertion`.
pub async fn load_vta_key0_signing_key(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit: &vta_audit::SharedAuditSink,
    vta_did: &str,
) -> Result<SigningKey, AppError> {
    let key_id = format!("{vta_did}#key-0");
    let authority = InternalAuthority::new("step-up-approval");
    let resp = crate::operations::keys::get_key_secret_internal(
        keys_ks,
        imported_ks,
        contexts_ks,
        seed_store,
        audit,
        authority,
        &key_id,
        "step-up-approval-internal",
    )
    .await?;
    let seed: [u8; 32] = decode_private_key_multibase(&resp.private_key_multibase)
        .map_err(|e| AppError::Internal(format!("decode VTA key-0 seed for {key_id}: {e}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// The VTA signs a step-up approval only for its own principals: a stranger
    /// is refused and the refusal is audited; an ACL member is authorized.
    #[tokio::test]
    async fn only_a_principal_of_this_vta_is_authorized_for_approval() {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        let audit_ks = store.keyspace(crate::keyspaces::AUDIT).unwrap();
        let audit = vta_audit::shared_keyspace_sink(audit_ks.clone());
        crate::acl::store_acl_entry(
            &acl_ks,
            &crate::acl::AclEntry::new("did:key:zMember", crate::acl::Role::Reader, "t")
                .with_contexts(vec!["ctx".into()]),
        )
        .await
        .unwrap();

        assert!(
            authorize_holder(&acl_ks, &audit, "did:key:zMember", "t")
                .await
                .is_ok()
        );
        let err = authorize_holder(&acl_ks, &audit, "did:key:zStranger", "t")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");

        let denied = audit_ks
            .prefix_iter_raw("log:")
            .await
            .unwrap()
            .iter()
            .filter_map(|(_, v)| {
                serde_json::from_slice::<vta_sdk::protocols::audit_management::list::AuditLogEntry>(
                    v,
                )
                .ok()
            })
            .filter(|r| r.action == "step_up.approve" && r.outcome == "denied")
            .count();
        assert_eq!(denied, 1);
    }

    /// A built token is a 3-part compact JWS whose header carries the
    /// expected `kid`, whose payload binds `iss`/`sub`/`aud`/`nonce` with
    /// `exp == iat + 300`, and whose signature verifies against the
    /// signing key's public half over the ASCII `header.payload`.
    #[test]
    fn approval_token_matches_contract_and_verifies() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let vta_did = "did:webvh:Q1:vta.example.com:agent";
        let holder = "did:key:z6MkHolder";
        let rp = "did:key:z6MkRelyingParty";
        let nonce = "deadbeefcafe";
        let iat = 1_700_000_000u64;

        let token = build_vta_approval_token(vta_did, holder, rp, nonce, iat, &signing_key)
            .expect("token builds");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS has three parts");

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], format!("{vta_did}#key-0"));

        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["iss"], vta_did);
        assert_eq!(payload["sub"], holder);
        assert_eq!(payload["aud"], rp);
        assert_eq!(payload["nonce"], nonce);
        assert_eq!(payload["iat"], iat);
        assert_eq!(payload["exp"], iat + 300);

        // The RP verifier requires the `kid` base to equal `iss`.
        let kid = header["kid"].as_str().unwrap();
        let kid_base = kid.split('#').next().unwrap();
        assert_eq!(kid_base, payload["iss"].as_str().unwrap());

        // Signature must verify over the ASCII `header.payload` against
        // the signing key's public half — the exact check the RP runs.
        let vk: VerifyingKey = signing_key.verifying_key();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        vk.verify(signing_input.as_bytes(), &sig)
            .expect("signature must verify");
    }

    /// Policy gate currently approves everything (stub).
    #[test]
    fn policy_approves_by_default() {
        assert!(step_up_policy_approve("did:key:zHolder", "did:key:zRp"));
    }
}
