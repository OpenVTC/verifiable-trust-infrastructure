//! Shared sealing primitive for provision-integration payloads.
//!
//! `provision_integration` mints two distinct payload shapes —
//! [`TemplateBootstrap`](vta_sdk::sealed_transfer::TemplateBootstrapPayload)
//! for the integration-bootstrap case and
//! [`AdminRotation`](vta_sdk::sealed_transfer::AdminRotationPayload)
//! for the standalone admin-rotation case. Both go through the exact
//! same end-of-flow steps: pick a producer assertion, seal the payload,
//! armor, compute the digest. The two call sites used to copy-paste
//! that block; this module collapses them so any future change to the
//! sealing contract lands in one place.
//!
//! Public surface is `pub(super)` only — both callers live inside
//! `crate::operations::provision_integration`.
//!
//! Tested indirectly via the `provision_integration_*` integration
//! tests in `vta-service/tests/api_integration.rs`, which exercise the
//! full `TemplateBootstrap` → seal → armor → open round-trip end-to-end.

use crate::error::AppError;
use crate::sealed_nonce_store::PersistentNonceStore;
use vta_sdk::sealed_transfer::{
    AssertionProof, ProducerAssertion, SealedPayloadV1, armor, bundle_digest, seal_payload,
};

use super::{AssertionMode, ProvisionIntegrationDeps, vta_keys};

/// Result of sealing a provision-integration payload.
pub(super) struct SealedProvisionBundle {
    /// ASCII-armored sealed bytes ready to return to the consumer.
    pub armored: String,
    /// Lowercase-hex SHA-256 of the bundle, communicated out-of-band so
    /// the consumer can pin integrity before opening.
    ///
    /// Kept in hex for the operator-facing surfaces (`pnm bootstrap open
    /// --expect-digest`, the CLI printouts). The *wire* form is
    /// [`digest_multibase`](Self::digest_multibase).
    pub digest: String,
    /// The same digest as a multibase multihash — the form
    /// `provision/integration/0.3` puts on the wire, where it replaced the
    /// bare-hex `digest` so the algorithm travels with the value.
    pub digest_multibase: String,
}

/// Seal a `SealedPayloadV1` for the consumer's HPKE pubkey, choosing
/// the producer assertion mode according to `assertion_mode`.
///
/// Centralises the pattern previously duplicated between
/// `provision_integration` (TemplateBootstrap) and
/// `provision_admin_rotation` (AdminRotation). New payload variants
/// added to `SealedPayloadV1` automatically get the same sealing
/// contract by routing through here.
pub(super) async fn seal_provision_payload(
    state: &ProvisionIntegrationDeps,
    vta_did: &str,
    assertion_mode: AssertionMode,
    bundle_id: [u8; 16],
    client_x25519_pub: &[u8; 32],
    payload: SealedPayloadV1,
) -> Result<SealedProvisionBundle, AppError> {
    let producer_assertion = match assertion_mode {
        AssertionMode::DidSigned => {
            let sealed_transfer_secret =
                vta_keys::load_vta_sealed_transfer_secret(state, vta_did).await?;
            vta_keys::build_did_signed_assertion(
                &sealed_transfer_secret,
                client_x25519_pub,
                bundle_id,
            )?
        }
        AssertionMode::PinnedOnly => ProducerAssertion {
            producer_did: vta_did.to_string(),
            proof: AssertionProof::PinnedOnly,
        },
    };

    let nonce_store = PersistentNonceStore::new(state.sealed_nonces_ks.clone());
    let bundle = seal_payload(
        client_x25519_pub,
        bundle_id,
        producer_assertion,
        &payload,
        &nonce_store,
    )
    .await
    .map_err(|e| AppError::Internal(format!("sealed-transfer seal failed: {e}")))?;

    Ok(SealedProvisionBundle {
        armored: armor::encode(&bundle),
        digest: bundle_digest(&bundle),
        digest_multibase: vta_sdk::sealed_transfer::bundle_digest_multibase(&bundle),
    })
}
