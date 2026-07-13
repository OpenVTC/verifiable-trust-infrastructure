use ed25519_dalek::{Signer, SigningKey};
use vta_sdk::session::{SessionStore, TokenStatus};

pub use vta_sdk::session::SessionInfo;

const SERVICE_NAME: &str = "pnm-cli";

fn store() -> SessionStore {
    SessionStore::new(
        SERVICE_NAME,
        crate::config::config_dir().expect("could not determine config directory"),
    )
}

/// Store a session directly in the keyring without performing auth.
///
/// Used by the TEE setup flow where the admin identity is a stable key baked
/// into the enclave config and must not be rotated.
///
/// The VTA's REST URL is not stored — it's resolved from the VTA DID
/// document at runtime on every command.
pub fn store_session(
    keyring_key: &str,
    did: &str,
    private_key: &str,
    vta_did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    store().store_direct(keyring_key, did, private_key, vta_did)
}

/// Park a phase-1 ephemeral identity with no VTA DID bound yet.
///
/// Used by the deferred-VTA-DID `pnm setup` flow. Phase 2
/// (`pnm setup continue <slug>`) lifts the entry into a
/// `PendingRotation` session via [`bind_vta_did`].
pub fn store_pending_vta_binding(
    keyring_key: &str,
    did: &str,
    private_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    store().store_pending_vta_binding(keyring_key, did, private_key)
}

/// Lift a `PendingVtaBinding` entry into a `PendingRotation` session.
pub fn bind_vta_did(keyring_key: &str, vta_did: &str) -> Result<(), Box<dyn std::error::Error>> {
    store().bind_vta_did(keyring_key, vta_did)
}

/// Report whether `keyring_key` identifies a `PendingVtaBinding` session.
pub fn has_pending_vta_binding(keyring_key: &str) -> bool {
    store().has_pending_vta_binding(keyring_key)
}

/// Clear stored credentials and cached tokens.
pub fn logout(keyring_key: &str) {
    store().logout(keyring_key);
    println!("Logged out. Credentials and tokens removed.");
}

/// `pnm auth sign-challenge <hex>` — sign a 32-byte challenge from
/// `vta unseal` using this PNM's stored admin key.
///
/// The cold-start companion is `vta auth sign-challenge --did <did>
/// --challenge <hex>`, which signs from the VTA's local fjall keystore
/// (daemon must be stopped). This online form is friendlier for
/// operators whose admin key already lives in PNM — no DID flag, no
/// daemon stop, no fjall lock juggling.
pub fn sign_unseal_challenge(
    keyring_key: &str,
    challenge_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = loaded_session(keyring_key).ok_or_else(|| -> Box<dyn std::error::Error> {
        "no PNM session — run `pnm setup` first, or use `vta auth sign-challenge` \
         (the offline cold-start path)"
            .into()
    })?;

    let challenge_bytes: [u8; 32] = hex::decode(challenge_hex.trim())
        .map_err(|e| format!("challenge is not valid hex: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("challenge must be 32 bytes (got {} bytes)", v.len()))?;

    // The session stores the Ed25519 secret as a multibase-encoded
    // 32-byte seed (matches `derive_and_store_did_key`'s
    // `encode_private_multibase` for KeyType::Ed25519). Decode and
    // construct the SigningKey directly.
    let (_, decoded) = multibase::decode(&session.private_key_multibase)
        .map_err(|e| format!("stored private key is not valid multibase: {e}"))?;
    // Strip the multicodec prefix `[0x80, 0x26]` (ed25519-priv,
    // varint 0x1300). Defensive: some flows store raw 32-byte seeds
    // without the codec prefix — accept either shape.
    let seed_bytes: [u8; 32] = if decoded.len() == 34 && decoded[0] == 0x80 && decoded[1] == 0x26 {
        decoded[2..]
            .try_into()
            .map_err(|_| "decoded private key not 32 bytes after stripping codec")?
    } else if decoded.len() == 32 {
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| "decoded private key not 32 bytes")?
    } else {
        return Err(format!(
            "stored private key is {} bytes (expected 32 raw or 34 with multicodec prefix)",
            decoded.len()
        )
        .into());
    };

    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let signature = signing_key.sign(&challenge_bytes);

    eprintln!();
    eprintln!("  Admin DID: {}", session.client_did);
    eprintln!("  Signature (hex):");
    println!("{}", hex::encode(signature.to_bytes()));
    eprintln!();
    eprintln!("  Paste the DID and signature above into the `vta unseal` prompt.");
    eprintln!();
    Ok(())
}

/// Load the stored session for diagnostics.
pub fn loaded_session(keyring_key: &str) -> Option<SessionInfo> {
    store().loaded_session(keyring_key)
}

/// Return current session status (for health diagnostics).
pub fn session_status(keyring_key: &str) -> Option<vta_sdk::session::SessionStatus> {
    store().session_status(keyring_key)
}

/// Show current authentication status.
///
/// The VTA's REST URL isn't shown here — it's derived from the VTA DID
/// at runtime, not stored by PNM. Use `pnm health` or `pnm vta info` to
/// see the resolved URL.
pub fn status(keyring_key: &str) {
    match store().session_status(keyring_key) {
        Some(status) => {
            println!("Client DID: {}", status.client_did);
            println!(
                "VTA DID:    {}",
                status.vta_did.as_deref().unwrap_or("(pending setup)")
            );
            match status.token_status {
                TokenStatus::Valid { expires_in_secs } => {
                    println!("Token:      valid (expires in {expires_in_secs}s)");
                }
                TokenStatus::Expired => {
                    println!("Token:      expired");
                }
                TokenStatus::None => {
                    println!("Token:      none (will authenticate on next request)");
                }
            }
        }
        None => {
            println!("Not authenticated.");
            println!("\nRun `pnm setup` to provision an admin identity for a VTA.");
        }
    }
}

/// Ensure we have a valid access token. Returns the token string.
pub async fn ensure_authenticated(
    base_url: &str,
    keyring_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    store().ensure_authenticated(base_url, keyring_key).await
}

/// Print the current access token (JWT) to stdout. Performs a fresh
/// authentication if the cached token is missing or expired. Used by
/// operator tooling that needs to paste the bearer credential into a
/// browser (e.g. `examples/vta-auth-demo/`).
///
/// Resolves the VTA URL the same way every other PNM command does —
/// from the session's stored VTA DID + DID resolver. Errors if PNM
/// hasn't been set up.
pub async fn show_token(keyring_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let session = loaded_session(keyring_key).ok_or_else(|| -> Box<dyn std::error::Error> {
        "no session — run `pnm setup` to provision an admin identity first".into()
    })?;
    let vta_did = session
        .vta_did
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "session has no VTA DID bound — run `pnm setup continue` to finish setup".into()
        })?;
    let url = vta_sdk::session::resolve_vta_url(&vta_did).await?;
    let token = ensure_authenticated(&url, keyring_key).await?;
    println!("{token}");
    Ok(())
}

/// Connect to the VTA using the preferred transport (DIDComm or REST).
///
/// Transport selection priority:
/// 1. `mediator_did_hint` from config → DIDComm (pinned).
/// 2. VTA DID doc DIDCommMessaging service → DIDComm (resolved).
/// 3. `url_override` + REST discovery → DIDComm if available.
/// 4. `url_override` → REST-only fallback.
///
/// `transport` overrides the above: `TransportChoice::Rest` forces REST and
/// skips priorities 1 & 2 (the recovery path for an unreachable mediator).
pub async fn connect(
    url_override: Option<&str>,
    mediator_did_hint: Option<&str>,
    transport: vta_sdk::session::TransportChoice,
    keyring_key: &str,
) -> Result<vta_sdk::client::VtaClient, Box<dyn std::error::Error>> {
    store()
        .connect_with_transport(keyring_key, url_override, mediator_did_hint, transport)
        .await
}

#[cfg(test)]
mod sign_challenge_tests {
    use super::*;
    use ed25519_dalek::Verifier;

    /// Verifier mirror of the `vta unseal` chain in
    /// `vta-service::seal::verify_challenge_signature`. Pin the
    /// signature shape so a refactor of either side surfaces here.
    fn verify(seed: &[u8; 32], challenge: &[u8; 32], sig_hex: &str) -> bool {
        let sig_bytes = hex::decode(sig_hex).unwrap();
        let signing = SigningKey::from_bytes(seed);
        let verifying = signing.verifying_key();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        verifying.verify(challenge, &sig).is_ok()
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let seed = [0x42u8; 32];
        let challenge = [0x55u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let sig = signing.sign(&challenge);
        let sig_hex = hex::encode(sig.to_bytes());
        assert!(verify(&seed, &challenge, &sig_hex));
    }

    #[test]
    fn signature_is_64_bytes_hex() {
        let seed = [0x01u8; 32];
        let challenge = [0x02u8; 32];
        let sig = SigningKey::from_bytes(&seed).sign(&challenge);
        let sig_hex = hex::encode(sig.to_bytes());
        // 64-byte Ed25519 signature → 128 hex chars.
        assert_eq!(sig_hex.len(), 128);
    }

    #[test]
    fn wrong_seed_fails_verify() {
        let seed_a = [0xAAu8; 32];
        let seed_b = [0xBBu8; 32];
        let challenge = [0x33u8; 32];
        let sig = SigningKey::from_bytes(&seed_a).sign(&challenge);
        let sig_hex = hex::encode(sig.to_bytes());
        assert!(!verify(&seed_b, &challenge, &sig_hex));
    }
}
