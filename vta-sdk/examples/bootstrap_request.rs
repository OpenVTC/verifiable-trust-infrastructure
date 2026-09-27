//! Build + sign a `BootstrapRequest` for the provision-integration flow.
//!
//! Demonstrates the consumer side of the wire shape: mint an ephemeral
//! Ed25519 keypair, construct + sign a `BootstrapRequest` over a
//! `TemplateBootstrapAsk`, serialize to JSON, and round-trip via
//! `.verify()` (which the **producer** runs — included here so the
//! demo is self-contained).
//!
//! The producer side (a VTA running `operations::provision_integration`)
//! takes the verified request, mints integration keys + an admin VC,
//! and returns a sealed `TemplateBootstrapPayload` keyed to the
//! consumer's X25519 pubkey (derived from the same Ed25519 seed).
//!
//! Run with:
//! ```bash
//! cargo run --example bootstrap_request \
//!     --features sealed-transfer,provision-integration
//! ```
//!
//! The printed JSON is exactly what the consumer would hand to
//! `pnm bootstrap provision-request` (offline file path) or what the
//! SDK would send as the `provision/integration/0.3` Trust Task.

use chrono::Duration;
use vta_sdk::provision_integration::{
    BootstrapAsk, BootstrapRequest, DidTemplateRef, TemplateBootstrapAsk,
};
use vta_sdk::sealed_transfer::generate_ed25519_keypair;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Holder identity. The seed stays on disk in a real flow (operators
    // persist it under `~/.config/{pnm,cnm}/bootstrap-secrets/`); here
    // we generate one fresh for the demo.
    let (holder_seed, holder_ed_pub) = generate_ed25519_keypair();
    let holder_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&holder_ed_pub);

    // Per-bundle nonce. In production this is the same nonce the
    // producer's `seal_payload` will key into its `NonceStore` for
    // single-use enforcement; the consumer chooses it.
    let mut bundle_id = [0u8; 16];
    getrandom::fill(&mut bundle_id)?;

    // Describe what we want the VTA to provision. Most common shape:
    // a TemplateBootstrap that asks the VTA to render its bundled
    // `didcomm-mediator` template.
    let ask = BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
        context_hint: Some("prod-mediator".to_string()),
        template: DidTemplateRef {
            name: "didcomm-mediator".to_string(),
            vars: Default::default(),
        },
        admin_template: None,
        note: Some("Demo run from vta-sdk/examples/bootstrap_request.rs".to_string()),
    });

    // Sign + assemble. Returns the wire shape; callers persist the
    // holder seed alongside the bundle_id so the eventual sealed
    // bundle can be opened.
    let request = BootstrapRequest::sign(
        &holder_seed,
        &holder_did,
        bundle_id,
        Duration::hours(1),
        Some("demo-mediator".to_string()),
        ask,
    )
    .await?;

    let wire = serde_json::to_string_pretty(&request)?;
    println!("BootstrapRequest wire form:\n{wire}");

    // Round-trip through `.verify()` — proves the request is
    // self-consistent (signature checks out, nonce decodes, holder DID
    // matches the embedded pubkey). Real callers do this on the
    // producer side; the consumer never verifies its own signature,
    // but the demo shows the typestate gating: only a
    // `VerifiedBootstrapRequest` can be passed to the operations layer.
    let verified = request.verify()?;
    println!("\nVerified holder: {}", verified.holder());
    let nonce = verified.decode_nonce()?;
    println!("Verified nonce: {}", hex_lower(&nonce));

    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(TABLE[(b >> 4) as usize] as char);
        s.push(TABLE[(b & 0xf) as usize] as char);
    }
    s
}
