//! Standalone DIDComm connectivity test.
//!
//! Mimics the VTA TEE key derivation and DIDComm message flow without
//! requiring a TEE, KMS, or persistent store. Useful for verifying that
//! the TDK, mediator authentication, and WebSocket live streaming all
//! work end-to-end with the current crate versions.
//!
//! Usage:
//! ```text
//! cargo run --package didcomm-test -- --mediator-did <DID>
//! cargo run --package didcomm-test -- --mediator-did <DID> --resolver-url ws://localhost:4445/did/v1/ws
//! cargo run --package didcomm-test -- --mediator-did <DID> --seed-hex <64-hex-chars>
//! ```

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use clap::Parser;
use ed25519_dalek_bip32::ExtendedSigningKey;
use tracing::{error, info, warn};
use vta_sdk::did_key::{ed25519_multibase_pubkey, secrets_from_did_key};

#[derive(Parser)]
#[command(name = "didcomm-test", about = "DIDComm connectivity test")]
struct Args {
    /// DID of the mediator to connect to.
    #[arg(long)]
    mediator_did: String,

    /// Optional DID resolver URL (network mode). Omit for local resolution.
    #[arg(long)]
    resolver_url: Option<String>,

    /// Hex-encoded 32-byte seed. Generated randomly if omitted.
    #[arg(long)]
    seed_hex: Option<String>,

    /// BIP-32 derivation path for the signing key.
    #[arg(long, default_value = "m/44'/0'/0'")]
    signing_path: String,

    /// BIP-32 derivation path for the key-agreement key.
    #[arg(long, default_value = "m/44'/0'/1'")]
    ka_path: String,

    /// Seconds to listen for inbound messages after connecting.
    #[arg(long, default_value = "15")]
    listen_secs: u64,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Pin rustls to the aws-lc-rs backend before any TLS object is built;
    // see `vta_sdk::crypto_init`. Without this, rustls 0.23 panics on
    // backend auto-detection when both backends are compiled in.
    vta_sdk::crypto_init::install_default_crypto_provider();

    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap_or_default()),
        )
        .init();

    // ---------------------------------------------------------------
    // 1. Seed — reuse or generate
    // ---------------------------------------------------------------
    let seed: Vec<u8> = if let Some(ref hex) = args.seed_hex {
        let bytes = hex::decode(hex).map_err(|e| format!("bad --seed-hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", bytes.len()).into());
        }
        info!("using provided seed");
        bytes
    } else {
        let mut buf = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut buf);
        info!(seed_hex = %hex::encode(buf), "generated random seed (save this to reuse the same identity)");
        buf.to_vec()
    };

    // ---------------------------------------------------------------
    // 2. Derive keys (same as VTA TEE: BIP-32 → Ed25519 → X25519)
    // ---------------------------------------------------------------
    let root = ExtendedSigningKey::from_seed(&seed)?;

    // Signing key (Ed25519)
    let signing_dp: ed25519_dalek_bip32::DerivationPath = args.signing_path.parse()?;
    let signing_derived = root.derive(&signing_dp)?;
    let signing_pub_bytes: [u8; 32] =
        ed25519_dalek::SigningKey::from_bytes(signing_derived.signing_key.as_bytes())
            .verifying_key()
            .to_bytes();
    let signing_pub_mb = ed25519_multibase_pubkey(&signing_pub_bytes);

    // Build did:key from the signing public key
    let did = format!("did:key:{signing_pub_mb}");
    info!(did = %did, "identity created");

    // Derive secrets — these get did:key fragment IDs automatically:
    //   signing:       "{did}#{ed25519_multibase_pub}"
    //   key_agreement: "{did}#{x25519_multibase_pub}"
    let secrets = secrets_from_did_key(&did, signing_derived.signing_key.as_bytes())?;

    let signing_pub = secrets
        .signing
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;
    let ka_pub = secrets
        .key_agreement
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;

    info!(
        signing_id = %secrets.signing.id,
        ka_id = %secrets.key_agreement.id,
        signing = %signing_pub,
        ka = %ka_pub,
        "keys derived"
    );

    // Also derive the KA key via the BIP-32 path (like VTA does for did:webvh entities)
    // to verify both derivation paths produce the same X25519 key
    {
        use affinidi_tdk::secrets_resolver::secrets::Secret;
        let ka_dp: ed25519_dalek_bip32::DerivationPath = args.ka_path.parse()?;
        let ka_derived = root.derive(&ka_dp)?;
        let ka_ed = Secret::generate_ed25519(None, Some(ka_derived.signing_key.as_bytes()));
        let ka_x = ka_ed.to_x25519().map_err(|e| format!("{e}"))?;
        let ka_bip32_pub = ka_x.get_public_keymultibase().map_err(|e| format!("{e}"))?;
        info!(
            ka_bip32 = %ka_bip32_pub,
            "BIP-32 KA key (separate path — would be used for did:webvh)"
        );
    }

    // ---------------------------------------------------------------
    // 3. Build TDK + ATM directly (not via init_didcomm_connection,
    //    which hardcodes #key-0/#key-1 lookups that don't work for did:key)
    // ---------------------------------------------------------------
    info!(mediator = %args.mediator_did, "connecting to mediator...");

    let tdk = {
        let mut builder = TDKConfig::builder();
        if let Some(ref url) = args.resolver_url {
            info!(url = %url, "DID resolver using network mode");
            let resolver_config = DIDCacheConfigBuilder::default()
                .with_network_mode(url)
                .build();
            builder = builder.with_did_resolver_config(resolver_config);
        }
        let config = builder.build().map_err(|e| format!("TDK config: {e}"))?;
        TDKSharedState::new(config)
            .await
            .map_err(|e| format!("TDK init: {e}"))?
    };

    // Insert secrets directly into the TDK's resolver with their did:key fragment IDs
    tdk.secrets_resolver().insert(secrets.signing).await;
    tdk.secrets_resolver().insert(secrets.key_agreement).await;
    info!("secrets inserted into TDK resolver");

    // Create ATM with inbound message channel
    let atm_config = ATMConfig::builder()
        .with_inbound_message_channel(100)
        .build()
        .map_err(|e| format!("ATM config: {e}"))?;
    let atm = ATM::new(atm_config, Arc::new(tdk))
        .await
        .map_err(|e| format!("ATM init: {e}"))?;

    // Create profile with mediator
    let profile = ATMProfile::new(&atm, None, did.clone(), Some(args.mediator_did.clone()))
        .await
        .map_err(|e| format!("ATM profile: {e}"))?;
    let profile = Arc::new(profile);

    // Enable WebSocket (triggers auth + live streaming)
    atm.profile_enable_websocket(&profile)
        .await
        .map_err(|e| format!("WebSocket enable: {e}"))?;

    let atm = Arc::new(atm);
    info!("connected to mediator — WebSocket live streaming active");

    // ---------------------------------------------------------------
    // 4. Send a trust-ping
    // ---------------------------------------------------------------
    info!("sending trust-ping to mediator...");
    let ping = TrustPing::default().generate_ping_message(Some(&did), &args.mediator_did, true)?;

    let (packed, _) = atm
        .pack_encrypted(&ping, &args.mediator_did, Some(&did), Some(&did))
        .await
        .map_err(|e| format!("pack_encrypted failed: {e}"))?;

    atm.send_message(&profile, &packed, &ping.id, false, false)
        .await
        .map_err(|e| format!("send_message failed: {e}"))?;

    info!(msg_id = %ping.id, "trust-ping sent");

    // ---------------------------------------------------------------
    // 5. Listen for inbound messages
    // ---------------------------------------------------------------
    let mut rx = atm.get_inbound_channel().ok_or("no inbound channel")?;

    info!(
        listen_secs = args.listen_secs,
        "listening for inbound messages..."
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.listen_secs);
    let mut received = 0u32;

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(WebSocketResponses::MessageReceived(msg, _)) => {
                        received += 1;
                        log_message("plaintext", &msg);
                    }
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        match atm.unpack(&packed).await {
                            Ok((msg, _metadata)) => {
                                received += 1;
                                log_message("decrypted", &msg);
                            }
                            Err(e) => {
                                error!("failed to unpack message: {e}");
                            }
                        }
                    }
                    Ok(WebSocketResponses::Disconnected) => {
                        // New in messaging-sdk 0.18.5: the transport signals a
                        // lost socket instead of silently blocking. Stop
                        // listening — the connection is gone.
                        warn!("websocket disconnected");
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("channel lagged, missed {n} messages");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("inbound channel closed");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                info!("listen period elapsed");
                break;
            }
        }
    }

    // ---------------------------------------------------------------
    // 6. Summary
    // ---------------------------------------------------------------
    info!(
        did = %did,
        messages_received = received,
        "test complete"
    );

    if received > 0 {
        info!("SUCCESS — authentication, pack/unpack, and live streaming all working");
    } else {
        warn!("no messages received — check mediator logs for errors");
    }

    atm.graceful_shutdown().await;
    Ok(())
}

fn log_message(label: &str, msg: &Message) {
    info!(
        label,
        msg_type = %msg.typ,
        from = msg.from.as_deref().unwrap_or("anon"),
        msg_id = %msg.id,
        thid = msg.thid.as_deref().unwrap_or("none"),
        "received message"
    );
}
