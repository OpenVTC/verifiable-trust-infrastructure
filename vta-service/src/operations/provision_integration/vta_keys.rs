//! Helpers for loading the VTA's own signing material and building
//! the sealed-transfer producer assertion.
//!
//! The provision-integration flow needs two of the VTA's Ed25519 keys:
//!   - `{vta_did}#key-0` — for the VC's Data-Integrity proof
//!   - `{vta_did}#sealed-transfer-0` — for the sealed-bundle producer
//!     assertion (distinct from `#key-0` so VC issuance and producer
//!     assertion can rotate independently)
//!
//! These are server-internal step, not actions attributable to the
//! user caller (who has already been authorised upstream). The
//! sealed-authority pattern in
//! [`crate::operations::internal_authority::InternalAuthority`] makes
//! the elevation explicit at the call site and unforgeable from outside
//! the operations layer.

use affinidi_secrets_resolver::secrets::Secret;
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};

use crate::error::AppError;
use crate::operations::internal_authority::InternalAuthority;
use vta_sdk::did_key::decode_private_key_multibase;
use vta_sdk::sealed_transfer::{
    AssertionProof, DidSignedAssertion, ProducerAssertion, template_bootstrap::VtaTrustBundle,
};

use super::ProvisionIntegrationDeps;

/// Load one of the VTA's Ed25519 keys as a `Secret` suitable for
/// signing. Used to fetch both the VC-issuance key (`#key-0`, see
/// [`load_vta_vc_issuance_secret`]) and the sealed-transfer
/// producer-assertion key (`#sealed-transfer-0`, see
/// [`load_vta_sealed_transfer_secret`]).
///
/// Constructs an [`InternalAuthority`] tagged `provision-integration`.
/// Route handlers cannot construct one (its constructor is `pub(super)`
/// to `operations`), so this elevation is reachable only from the
/// operations layer.
async fn load_vta_key_as_secret(
    state: &ProvisionIntegrationDeps,
    key_id: String,
) -> Result<Secret, AppError> {
    let authority = InternalAuthority::new("provision-integration");
    let resp = crate::operations::keys::get_key_secret_internal(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &*state.seed_store,
        &state.audit,
        authority,
        &key_id,
        "provision-integration-internal",
    )
    .await?;
    let _seed: [u8; 32] = decode_private_key_multibase(&resp.private_key_multibase)
        .map_err(|e| AppError::Internal(format!("decode VTA key secret for {key_id}: {e}")))?;
    let mut secret = Secret::from_multibase(&resp.private_key_multibase, None)
        .map_err(|e| AppError::Internal(format!("construct Secret for {key_id}: {e}")))?;
    secret.id = key_id;
    Ok(secret)
}

/// This VTA's keys by role, from its own `did:webvh` log or `did:webs` key
/// event log.
async fn provision_self_keys(
    state: &ProvisionIntegrationDeps,
    vta_did: &str,
) -> crate::self_keys::SelfKeys {
    crate::self_keys::self_keys(vta_did, Some(&state.webvh_ks), Some(&state.webs_ks)).await
}

/// Load the VTA's signing key (`{vta_did}#key-0` on a did:webvh) for issuing the VtaAuthorization VC's
/// Data-Integrity proof.
pub(super) async fn load_vta_vc_issuance_secret(
    state: &ProvisionIntegrationDeps,
    vta_did: &str,
) -> Result<Secret, AppError> {
    // The key this VTA's own document lists for signing, stored under its
    // record id; the proof names the method the document gives it (VTI-KEY-150).
    let keys = provision_self_keys(state, vta_did).await;
    let mut secret = load_vta_key_as_secret(state, keys.signing.record_id.clone()).await?;
    secret.id = keys.signing.vm_id;
    Ok(secret)
}

/// Load `{vta_did}#sealed-transfer-0` for signing the sealed-transfer
/// producer assertion. The key is minted at VTA DID creation
/// (see `operations::did_webvh::create_did_webvh` + `is_vta_identity`).
/// A VTA missing this key is mis-provisioned — surface the error rather
/// than silently falling back to `#key-0`, which would hide the defect
/// and re-introduce the key-reuse we split out.
pub(super) async fn load_vta_sealed_transfer_secret(
    state: &ProvisionIntegrationDeps,
    vta_did: &str,
) -> Result<Secret, AppError> {
    let keys = provision_self_keys(state, vta_did).await;
    let record_id = keys.sealed_transfer.map(|k| k.record_id).ok_or_else(|| {
        AppError::Internal(format!(
            "VTA '{vta_did}' lists no sealed-transfer key — re-bootstrap required"
        ))
    })?;
    load_vta_key_as_secret(state, record_id)
        .await
        .map_err(|e| match e {
            AppError::NotFound(_) => AppError::Internal(format!(
                "VTA missing '{vta_did}#sealed-transfer-0' — re-bootstrap required (this VTA was \
                 provisioned before key-use split, see review item 12)"
            )),
            other => other,
        })
}

/// Assemble the trust bundle shipped alongside every provisioning
/// payload: VTA DID, rendered DID document, and webvh log if we have
/// one on disk.
///
/// For `did:webvh:` VTAs the document is rendered from the locally-stored
/// `did.jsonl` — going to the network would fail any time the public
/// endpoint isn't reachable (offline bootstrap, pre-publication, or a
/// transient 5xx from the hosting webvh server) even though the VTA
/// already holds the authoritative log on disk. The public endpoint only
/// serves what the VTA itself produced; resolving locally keeps
/// provisioning self-contained.
///
/// For other methods (e.g. `did:key:` in dev mode) there is no log to
/// replay, so we fall back to the cache resolver — `did:key` is purely
/// local anyway, so this stays offline-safe.
pub(super) async fn load_vta_trust_bundle(
    state: &ProvisionIntegrationDeps,
    vta_did: &str,
) -> Result<VtaTrustBundle, AppError> {
    #[cfg(feature = "webvh")]
    let vta_did_log = crate::webvh_store::get_did_log(&state.webvh_ks, vta_did).await?;
    #[cfg(not(feature = "webvh"))]
    let vta_did_log: Option<String> = None;

    // A did:webs VTA's document is derived from the key event log it holds,
    // as its host serves it: offline-safe, and right before its first-boot
    // publication too.
    let own_webs = if vta_did.starts_with("did:webs:") {
        crate::self_keys::own_document(vta_did, None, Some(&state.webs_ks)).await
    } else {
        None
    };
    let vta_did_document = match (&vta_did_log, own_webs) {
        (_, Some(document)) => document,
        #[cfg(feature = "webvh")]
        (Some(log), None) => {
            let mut webvh_state = didwebvh_rs::DIDWebVHState::default();
            let (log_entry, _meta) =
                webvh_state
                    .resolve_log(vta_did, log, None)
                    .await
                    .map_err(|e| {
                        AppError::Internal(format!(
                            "resolve VTA DID '{vta_did}' from local webvh log: {e}"
                        ))
                    })?;
            use didwebvh_rs::log_entry::LogEntryMethods;
            log_entry.get_did_document().map_err(|e| {
                AppError::Internal(format!(
                    "render VTA DID doc from local webvh log for '{vta_did}': {e}"
                ))
            })?
        }
        _ => {
            let resolver = state
                .did_resolver
                .as_ref()
                .ok_or_else(|| AppError::Internal("DID resolver not initialized".into()))?;
            let resolved = resolver
                .resolve(vta_did)
                .await
                .map_err(|e| AppError::Internal(format!("resolve VTA DID '{vta_did}': {e}")))?;
            serde_json::to_value(&resolved.doc)
                .map_err(|e| AppError::Internal(format!("serialize VTA DID doc: {e}")))?
        }
    };

    Ok(VtaTrustBundle {
        vta_did: vta_did.to_string(),
        vta_did_document,
        vta_did_log,
    })
}

/// Sign the sealed-transfer producer assertion with the VTA's
/// purpose-specific Ed25519 key (`{vta_did}#sealed-transfer-0`).
///
/// Signed target: domain-tagged `client_x25519_pub || bundle_id`. The
/// domain tag (`"vta-sealed-transfer/v1\0"`) alone already prevents
/// signature replay into other signing contexts; separating this key
/// from `#key-0` adds defence-in-depth:
///   - a leak of one key doesn't void the other (VC issuance vs
///     producer assertion), and
///   - each can rotate independently (e.g. VC issuance eventually
///     moves to an HSM while sealed-transfer stays local for
///     throughput).
pub(super) fn build_did_signed_assertion(
    vta_signing_secret: &Secret,
    client_x25519_pub: &[u8; 32],
    bundle_id: [u8; 16],
) -> Result<ProducerAssertion, AppError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    let (vta_did_frag, _) = vta_signing_secret
        .id
        .split_once('#')
        .ok_or_else(|| AppError::Internal("VTA signing secret id missing fragment".into()))?;
    let vta_did = vta_did_frag.to_string();

    // Decode the multibase-encoded private seed so we can use
    // ed25519-dalek directly. The `Secret` API is optimised for
    // Data-Integrity flows; for a raw sign-these-bytes we drop down.
    let priv_mb = vta_signing_secret
        .get_private_keymultibase()
        .map_err(|e| AppError::Internal(format!("get VTA private key multibase: {e}")))?;
    let seed: [u8; 32] = decode_private_key_multibase(&priv_mb)
        .map_err(|e| AppError::Internal(format!("decode VTA signing seed: {e}")))?;
    let signing_key = SigningKey::from_bytes(&seed);

    let mut to_sign = Vec::with_capacity(64);
    to_sign.extend_from_slice(b"vta-sealed-transfer/v1\0");
    to_sign.extend_from_slice(client_x25519_pub);
    to_sign.extend_from_slice(&bundle_id);

    let signature = signing_key.sign(&to_sign);
    let signature_b64 = B64URL.encode(signature.to_bytes());

    Ok(ProducerAssertion {
        producer_did: vta_did.clone(),
        proof: AssertionProof::DidSigned(DidSignedAssertion {
            did: vta_did,
            signature_b64,
            verification_method: vta_signing_secret.id.clone(),
        }),
    })
}

#[cfg(all(test, feature = "webs"))]
mod tests {
    use super::*;

    /// S6: a did:webs VTA provisions from its own key event log — its trust
    /// bundle is the document its log derives (offline, and before its
    /// first-boot publication), and the VC and sealed transfer are signed by
    /// its attestation key, by role, not by a webvh `#key-0` it does not have.
    #[tokio::test]
    async fn a_did_webs_vta_provisions_from_its_own_key_event_log() {
        let ts = crate::test_support::open_test_store().await;
        let (_, mut deps) = crate::test_support::bootstrap_test_vta(&ts).await;
        let (did, record) = crate::self_keys::tests::key_role_webs_record();
        crate::webs_store::put(&ts.webs_ks, &record).await.unwrap();
        deps.config.write().await.vta_did = Some(did.clone());
        // No network: the resolver must not be what answers.
        deps.did_resolver = None;

        let bundle = load_vta_trust_bundle(&deps, &did).await.expect("bundle");
        assert_eq!(bundle.vta_did, did);
        assert!(bundle.vta_did_log.is_none());
        assert!(
            bundle.vta_did_document.get("keyRoles").is_some(),
            "{}",
            bundle.vta_did_document
        );

        let keys = provision_self_keys(&deps, &did).await;
        let ids =
            vta_sdk::node_keys::NodeKeyIds::from_document(&did, &bundle.vta_did_document).unwrap();
        assert_eq!(keys.signing.record_id, ids.signing);
        assert_eq!(
            keys.sealed_transfer.map(|k| k.record_id),
            Some(ids.signing),
            "a key-role identity's sealed transfer is its attestation key"
        );
    }
}
