//! Generate valid seed-corpus fixtures for the downstream `fuzz/` workspace.
//!
//! Coverage-guided fuzzers mutate *from* valid inputs — feeding libFuzzer a
//! handful of well-formed artifacts massively improves yield over starting
//! from noise (issue #439, item 6). This emits the two artifact kinds the SDK
//! can produce end-to-end through its public API:
//!
//! - `sealed-transfer-armor/*.vta` — ASCII-armored [`SealedBundle`]s (the
//!   `armor::decode` / sealed-bundle-open fuzz targets).
//! - `bootstrap-request/*.json` — VP-framed [`BootstrapRequest`]s (the
//!   `BootstrapRequest::verify` fuzz target).
//!
//! VP-token / SD-JWT-VC / OID4VCI-proof seeds are emitted by the sibling
//! generator in `vtc-service` (an `#[ignore]`d test), where the issuer/holder
//! signing helpers live.
//!
//! Run with:
//! ```bash
//! cargo run --example gen_fuzz_seeds \
//!     --features sealed-transfer,provision-integration
//! ```
//! Writes under `<workspace-root>/fuzz/seeds/` by default, or to the directory
//! given as the first argument. The keys are freshly generated each run, so the
//! exact bytes differ run-to-run — that is fine, a seed need only be *valid*.

use std::path::PathBuf;

use chrono::Duration;
use vta_sdk::provision_integration::{
    BootstrapAsk, BootstrapRequest, DidTemplateRef, TemplateBootstrapAsk,
};
use vta_sdk::sealed_transfer::{
    AssertionProof, DidSignedAssertion, InMemoryNonceStore, LabeledKey, ProducerAssertion,
    SealedPayloadV1, armor, generate_ed25519_keypair, seal_payload,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seeds_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_seeds_dir);

    let armor_dir = seeds_dir.join("sealed-transfer-armor");
    let bootstrap_dir = seeds_dir.join("bootstrap-request");
    std::fs::create_dir_all(&armor_dir)?;
    std::fs::create_dir_all(&bootstrap_dir)?;

    let armored = make_sealed_armor().await?;
    let armor_path = armor_dir.join("admin-key-set.vta");
    std::fs::write(&armor_path, &armored)?;
    println!("wrote {} ({} bytes)", armor_path.display(), armored.len());

    let request = make_bootstrap_request().await?;
    let bootstrap_path = bootstrap_dir.join("template-bootstrap.json");
    std::fs::write(&bootstrap_path, &request)?;
    println!(
        "wrote {} ({} bytes)",
        bootstrap_path.display(),
        request.len()
    );

    Ok(())
}

/// `<workspace-root>/fuzz/seeds` — the manifest dir is `vta-sdk/`, the
/// workspace root is its parent.
fn default_seeds_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vta-sdk has a parent (the workspace root)")
        .join("fuzz")
        .join("seeds")
}

/// A valid armored `SealedBundle` carrying a `DidSigned` producer assertion —
/// the same shape `examples/sealed_transfer_round_trip.rs` round-trips.
async fn make_sealed_armor() -> Result<String, Box<dyn std::error::Error>> {
    use base64::Engine;
    use ed25519_dalek::Signer;

    let (producer_seed, producer_ed_pub) = generate_ed25519_keypair();
    let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed_pub);

    let (_consumer_seed, consumer_ed_pub) = generate_ed25519_keypair();
    let recipient_x25519 = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&consumer_ed_pub)?;

    let mut bundle_id = [0u8; 16];
    getrandom::fill(&mut bundle_id)?;

    let payload = SealedPayloadV1::AdminKeySet(vec![LabeledKey {
        label: "example-key".into(),
        key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        key_type: Some("ed25519".into()),
    }]);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&producer_seed);
    let mut to_sign = Vec::with_capacity(64);
    to_sign.extend_from_slice(b"vta-sealed-transfer/v1\0");
    to_sign.extend_from_slice(&recipient_x25519);
    to_sign.extend_from_slice(&bundle_id);
    let signature = signing_key.sign(&to_sign);

    let strip = producer_did
        .strip_prefix("did:key:")
        .unwrap_or(&producer_did);
    let assertion = ProducerAssertion {
        producer_did: producer_did.clone(),
        proof: AssertionProof::DidSigned(DidSignedAssertion {
            did: producer_did.clone(),
            signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_bytes()),
            verification_method: format!("{producer_did}#{strip}"),
        }),
    };

    let nonce_store = InMemoryNonceStore::new();
    let bundle = seal_payload(
        &recipient_x25519,
        bundle_id,
        assertion,
        &payload,
        &nonce_store,
    )
    .await?;
    Ok(armor::encode(&bundle))
}

/// A valid VP-framed `BootstrapRequest` — the same shape
/// `examples/bootstrap_request.rs` signs and verifies.
async fn make_bootstrap_request() -> Result<String, Box<dyn std::error::Error>> {
    let (holder_seed, holder_ed_pub) = generate_ed25519_keypair();
    let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&holder_ed_pub);

    let mut bundle_id = [0u8; 16];
    getrandom::fill(&mut bundle_id)?;

    let ask = BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
        context_hint: Some("prod-mediator".to_string()),
        template: DidTemplateRef {
            name: "didcomm-mediator".to_string(),
            vars: Default::default(),
        },
        admin_template: None,
        note: Some("fuzz seed from vta-sdk/examples/gen_fuzz_seeds.rs".to_string()),
    });

    let request = BootstrapRequest::sign(
        &holder_seed,
        &holder_did,
        bundle_id,
        Duration::hours(1),
        Some("fuzz-seed-mediator".to_string()),
        ask,
    )
    .await?;

    Ok(serde_json::to_string_pretty(&request)?)
}
