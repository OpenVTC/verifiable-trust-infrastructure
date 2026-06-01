//! Lightweight DIDComm v2 anonymous encryption (anoncrypt) packer.
//!
//! Produces a JWE (General JSON Serialization) that can be unpacked by
//! `affinidi-messaging-didcomm`'s `decrypt` (the same decrypt used by
//! `affinidi-tdk`'s `ATM::unpack`).
//!
//! This module avoids the heavyweight ATM/TDK runtime initialization. It
//! only needs the recipient's X25519 public key (derived from their
//! `did:key`).
//!
//! Algorithm: ECDH-ES+A256KW (key agreement) + A256CBC-HS512 (content
//! encryption) — the algorithm pair the workspace's pinned
//! `affinidi-messaging-didcomm-0.15` actually decrypts. An earlier
//! revision emitted A256GCM instead, which the crate doesn't support;
//! every call fell through to the slower `session::challenge_response`
//! tier-3 fallback in `integration::auth::try_rest`. Delegating to the
//! crate's `jwe::encrypt::anoncrypt` keeps the algorithms aligned by
//! construction.

// ── DIDComm message builder ─────────────────────────────────────────

/// Build a DIDComm v2 plaintext message JSON.
pub fn build_message(msg_type: &str, body: serde_json::Value, from: &str, to: &str) -> String {
    serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "typ": "application/didcomm-plain+json",
        "type": msg_type,
        "body": body,
        "from": from,
        "to": [to],
    })
    .to_string()
}

// ── JWE anoncrypt packer ────────────────────────────────────────────

/// Pack a plaintext message as a DIDComm v2 anoncrypt JWE (General JSON).
///
/// Returns the JWE as a JSON string suitable for sending to `POST /auth/`.
///
/// Delegates to `affinidi_messaging_didcomm::jwe::encrypt::anoncrypt`,
/// which produces a JWE the workspace's pinned didcomm crate can also
/// decrypt — by construction. The wire shape:
///
///   - `alg`: `ECDH-ES+A256KW`
///   - `enc`: `A256CBC-HS512`
///   - 16-byte IV, 32-byte tag, 64-byte CEK split mac||enc.
pub fn pack_anoncrypt(
    plaintext: &[u8],
    recipient_x25519_pub: &[u8; 32],
    recipient_kid: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // didcomm 0.15 moved the key-agreement types out of its own
    // `crypto` module into `affinidi-crypto`; `anoncrypt` now takes the
    // `affinidi_crypto::jose` shape. Same enum, same X25519 variant.
    use affinidi_crypto::jose::key_agreement::PublicKeyAgreement;
    use affinidi_messaging_didcomm::jwe::encrypt::anoncrypt;

    let recipient_pub = PublicKeyAgreement::X25519(*recipient_x25519_pub);
    anoncrypt(plaintext, &[(recipient_kid, &recipient_pub)])
        .map_err(|e| -> Box<dyn std::error::Error> { format!("anoncrypt: {e}").into() })
}

// ── did:key → X25519 public key conversion ──────────────────────────

/// Extract the Ed25519 public key bytes from a `did:key:z6Mk...` identifier.
pub fn parse_did_key_ed25519(did: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let multibase_part = did.strip_prefix("did:key:").ok_or("not a did:key")?;
    let (_, decoded) = multibase::decode(multibase_part)?;
    // Expect 34 bytes: 2-byte multicodec (0xed 0x01) + 32-byte key
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err("invalid did:key: expected Ed25519 multicodec prefix 0xed01".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..]);
    Ok(key)
}

/// Convert an Ed25519 public key to an X25519 public key (Edwards → Montgomery).
pub fn ed25519_pub_to_x25519_pub(
    ed_pub: &[u8; 32],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let compressed = curve25519_dalek::edwards::CompressedEdwardsY(*ed_pub);
    let edwards = compressed
        .decompress()
        .ok_or("invalid Ed25519 public key: decompression failed")?;
    Ok(edwards.to_montgomery().to_bytes())
}

/// Derive the X25519 key-agreement key ID for a `did:key`.
///
/// Given `did:key:z6Mk...`, returns `did:key:z6Mk...#z6LS...` where the
/// fragment is the X25519 public key encoded with multicodec `0xec01`.
pub fn did_key_agreement_kid(did: &str) -> Result<String, Box<dyn std::error::Error>> {
    let ed_pub = parse_did_key_ed25519(did)?;
    let x_pub = ed25519_pub_to_x25519_pub(&ed_pub)?;
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&[0xec, 0x01]); // x25519-pub multicodec
    buf.extend_from_slice(&x_pub);
    let x_multibase = multibase::encode(multibase::Base::Base58Btc, &buf);
    Ok(format!("{did}#{x_multibase}"))
}

/// Convert an Ed25519 seed (private key) to X25519 static secret bytes.
pub fn ed25519_seed_to_x25519_secret(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    // Standard Ed25519→X25519 conversion: SHA-512(seed)[0..32] with clamping
    let hash = sha2::Sha512::digest(seed);
    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&hash[..32]);
    // Clamping (applied by StaticSecret::from, but be explicit)
    x25519_bytes[0] &= 248;
    x25519_bytes[31] &= 127;
    x25519_bytes[31] |= 64;
    x25519_bytes
}

// ── VTA keyAgreement resolution ─────────────────────────────────────

/// Resolve a VTA's first `keyAgreement` X25519 key.
///
/// Returns `(kid, x25519_public_bytes)`:
///   - `kid` is the verification-method id the JWE's `recipients[].header.kid`
///     and AAD/APV need (the VTA's secrets resolver looks up secrets by it).
///   - `x25519_public_bytes` is the raw 32-byte public key for ECDH.
///
/// Supported DID methods:
///   - `did:key:` — inlined, no I/O. Only the Ed25519 form; the X25519
///     keyAgreement key is derived via the Edwards-to-Montgomery map and
///     the kid is `{did}#{x25519_multikey}`.
///   - `did:webvh:` — fetches and verifies the log via `didwebvh-rs`,
///     then walks the DID document to find the first `keyAgreement` with
///     an X25519 `publicKeyMultibase`.
///
/// Other DID methods fall through to `Unsupported` — callers (currently
/// `integration::auth::try_rest`) handle that by falling back to the
/// heavyweight `session::challenge_response` path.
pub async fn resolve_vta_keyagreement(
    vta_did: &str,
) -> Result<(String, [u8; 32]), Box<dyn std::error::Error>> {
    if vta_did.starts_with("did:key:") {
        let ed_pub = parse_did_key_ed25519(vta_did)?;
        let x_pub = ed25519_pub_to_x25519_pub(&ed_pub)?;
        let kid = did_key_agreement_kid(vta_did)?;
        Ok((kid, x_pub))
    } else if vta_did.starts_with("did:webvh:") {
        resolve_webvh_keyagreement(vta_did).await
    } else {
        Err(format!(
            "unsupported VTA DID method (lightweight path supports did:key and did:webvh only): {vta_did}"
        )
        .into())
    }
}

/// Fetch + verify a `did:webvh:` log and extract its first X25519 keyAgreement.
async fn resolve_webvh_keyagreement(
    vta_did: &str,
) -> Result<(String, [u8; 32]), Box<dyn std::error::Error>> {
    use didwebvh_rs::DIDWebVHState;
    use didwebvh_rs::log_entry::LogEntryMethods;
    use didwebvh_rs::resolve::ResolveOptions;

    let mut state = DIDWebVHState::default();
    let (log_entry, _meta) = state
        .resolve(vta_did, ResolveOptions::default())
        .await
        .map_err(|e| format!("resolve did:webvh {vta_did}: {e}"))?;
    let did_doc = log_entry
        .get_did_document()
        .map_err(|e| format!("render did:webvh document for {vta_did}: {e}"))?;
    extract_x25519_keyagreement(&did_doc)
}

/// Walk a serde DID document JSON value and find the first keyAgreement
/// entry that exposes an X25519 `publicKeyMultibase`. Resolves a `#fragment`
/// reference into the matching `verificationMethod[]` entry per DID Core
/// §5.4.1.
fn extract_x25519_keyagreement(
    did_doc: &serde_json::Value,
) -> Result<(String, [u8; 32]), Box<dyn std::error::Error>> {
    let did_id = did_doc
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or("DID document has no `id`")?;

    let key_agreement = did_doc
        .get("keyAgreement")
        .and_then(|v| v.as_array())
        .ok_or("DID document has no `keyAgreement` array")?;

    for ka in key_agreement {
        let vm = match ka {
            serde_json::Value::String(reference) => {
                resolve_vm_reference(did_doc, did_id, reference)?
            }
            serde_json::Value::Object(_) => ka.clone(),
            _ => continue,
        };
        let kid = vm
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("verificationMethod has no `id`")?
            .to_string();
        let Some(pk_mb) = vm.get("publicKeyMultibase").and_then(|v| v.as_str()) else {
            continue;
        };
        let (_, bytes) =
            multibase::decode(pk_mb).map_err(|e| format!("decode publicKeyMultibase: {e}"))?;
        // X25519 multikey: multicodec varint 0xec 0x01, then 32 bytes.
        if bytes.len() == 34 && bytes[0] == 0xec && bytes[1] == 0x01 {
            let mut x_pub = [0u8; 32];
            x_pub.copy_from_slice(&bytes[2..]);
            return Ok((kid, x_pub));
        }
    }

    Err("no X25519 keyAgreement Multikey found on this DID".into())
}

/// Resolve a `#fragment` (or absolute DID URL) reference into the matching
/// `verificationMethod[]` entry. Returns the inline `Value`.
fn resolve_vm_reference(
    did_doc: &serde_json::Value,
    did_id: &str,
    reference: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // Accept both bare-fragment and absolute forms.
    let target_id = if reference.starts_with('#') {
        format!("{did_id}{reference}")
    } else {
        reference.to_string()
    };
    let vms = did_doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or("DID document missing `verificationMethod` while resolving reference")?;
    vms.iter()
        .find(|vm| {
            vm.get("id").and_then(|i| i.as_str()) == Some(target_id.as_str())
                || vm.get("id").and_then(|i| i.as_str()) == Some(reference)
        })
        .cloned()
        .ok_or_else(|| {
            format!("keyAgreement reference {reference} not in verificationMethod[]").into()
        })
}

// ── High-level: pack auth message ───────────────────────────────────

/// Pack a DIDComm v2 authenticate message for VTA challenge-response.
///
/// This is the lightweight equivalent of `atm.pack_encrypted()` — it
/// produces a JWE that the server's ATM can unpack, without needing
/// ATM initialization. Supports both `did:key:` (no I/O) and
/// `did:webvh:` (fetches + verifies the log) VTAs; for other DID
/// methods, errors out so the caller can fall back to the heavyweight
/// `session::challenge_response` path.
pub async fn pack_auth_message(
    msg_type: &str,
    body: serde_json::Value,
    client_did: &str,
    vta_did: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let plaintext = build_message(msg_type, body, client_did, vta_did);
    let (kid, x_pub) = resolve_vta_keyagreement(vta_did).await?;
    pack_anoncrypt(plaintext.as_bytes(), &x_pub, &kid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an X25519 `publicKeyMultibase` (multicodec 0xec01) from raw bytes.
    fn x25519_multikey(bytes: &[u8; 32]) -> String {
        let mut buf = Vec::with_capacity(34);
        buf.extend_from_slice(&[0xec, 0x01]);
        buf.extend_from_slice(bytes);
        multibase::encode(multibase::Base::Base58Btc, &buf)
    }

    #[test]
    fn extract_keyagreement_embedded_vm() {
        let x = [7u8; 32];
        let doc = serde_json::json!({
            "id": "did:webvh:scid:example.com",
            "keyAgreement": [{
                "id": "did:webvh:scid:example.com#key-agreement-0",
                "type": "Multikey",
                "publicKeyMultibase": x25519_multikey(&x),
            }],
        });
        let (kid, pub_bytes) = extract_x25519_keyagreement(&doc).unwrap();
        assert_eq!(kid, "did:webvh:scid:example.com#key-agreement-0");
        assert_eq!(pub_bytes, x);
    }

    #[test]
    fn extract_keyagreement_by_reference() {
        let x = [9u8; 32];
        let doc = serde_json::json!({
            "id": "did:webvh:scid:example.com",
            "keyAgreement": ["#key-agreement-0"],
            "verificationMethod": [{
                "id": "did:webvh:scid:example.com#key-agreement-0",
                "type": "Multikey",
                "publicKeyMultibase": x25519_multikey(&x),
            }],
        });
        let (kid, pub_bytes) = extract_x25519_keyagreement(&doc).unwrap();
        assert_eq!(kid, "did:webvh:scid:example.com#key-agreement-0");
        assert_eq!(pub_bytes, x);
    }

    #[test]
    fn extract_keyagreement_skips_non_x25519_and_errors() {
        // An Ed25519 (0xed01) entry in keyAgreement is not a valid X25519
        // recipient — extraction must skip it and report "none found".
        let mut buf = vec![0xed, 0x01];
        buf.extend_from_slice(&[1u8; 32]);
        let doc = serde_json::json!({
            "id": "did:webvh:scid:example.com",
            "keyAgreement": [{
                "id": "did:webvh:scid:example.com#wrong",
                "type": "Multikey",
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, &buf),
            }],
        });
        let err = extract_x25519_keyagreement(&doc).unwrap_err();
        assert!(err.to_string().contains("no X25519 keyAgreement"), "{err}");
    }

    #[test]
    fn extract_keyagreement_no_keyagreement_errors() {
        let doc = serde_json::json!({ "id": "did:webvh:scid:example.com" });
        let err = extract_x25519_keyagreement(&doc).unwrap_err();
        assert!(err.to_string().contains("no `keyAgreement`"), "{err}");
    }

    #[tokio::test]
    async fn resolve_keyagreement_did_key_no_io() {
        // did:key resolution is inlined — no network. The kid fragment is
        // the derived X25519 multikey and the returned bytes must match.
        let ed_pub = [42u8; 32];
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&ed_pub)
        );
        let (kid, x_pub) = resolve_vta_keyagreement(&did).await.unwrap();
        assert!(kid.starts_with(&did));
        assert_eq!(x_pub, ed25519_pub_to_x25519_pub(&ed_pub).unwrap());
    }

    #[tokio::test]
    async fn resolve_keyagreement_rejects_unsupported_method() {
        let err = resolve_vta_keyagreement("did:web:example.com")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unsupported VTA DID method"),
            "{err}"
        );
    }

    #[test]
    fn test_parse_did_key_ed25519() {
        // Create a known did:key from a known public key
        let pub_bytes = [42u8; 32];
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&pub_bytes)
        );
        let parsed = parse_did_key_ed25519(&did).unwrap();
        assert_eq!(parsed, pub_bytes);
    }

    #[test]
    fn test_ed25519_to_x25519_conversion() {
        // Generate an Ed25519 key pair and verify conversion produces valid X25519
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let ed_pub = verifying_key.to_bytes();

        let x_pub = ed25519_pub_to_x25519_pub(&ed_pub).unwrap();
        assert_ne!(x_pub, [0u8; 32]); // Should not be all zeros
    }

    #[test]
    fn test_did_key_agreement_kid() {
        let pub_bytes = [42u8; 32];
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&pub_bytes)
        );
        let kid = did_key_agreement_kid(&did).unwrap();
        assert!(kid.starts_with(&did));
        assert!(kid.contains('#'));
        // The fragment should be an X25519 multibase (starts with z after #)
        let fragment = kid.split('#').nth(1).unwrap();
        assert!(fragment.starts_with('z'));
    }

    #[test]
    fn test_pack_anoncrypt_produces_valid_jwe() {
        use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement};
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};

        // Generate a recipient X25519 keypair via the same crate the
        // server uses — keeps the test honest about wire compatibility.
        let recipient_private = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient_pub_bytes = match recipient_private.public_key() {
            affinidi_crypto::jose::key_agreement::PublicKeyAgreement::X25519(b) => b,
            _ => unreachable!("we asked for X25519"),
        };

        let jwe_str =
            pack_anoncrypt(b"hello world", &recipient_pub_bytes, "did:key:test#key-1").unwrap();

        let jwe: serde_json::Value = serde_json::from_str(&jwe_str).unwrap();
        assert!(jwe["protected"].is_string());
        assert!(jwe["recipients"].is_array());
        assert_eq!(jwe["recipients"].as_array().unwrap().len(), 1);
        assert!(jwe["iv"].is_string());
        assert!(jwe["ciphertext"].is_string());
        assert!(jwe["tag"].is_string());

        // The protected header MUST advertise the algorithm pair the
        // workspace's pinned `affinidi-messaging-didcomm-0.13` accepts
        // on decrypt. Regressing this to A256GCM means every consumer
        // silently falls through to the slower tier-3 fallback.
        let protected_json: serde_json::Value =
            serde_json::from_slice(&B64.decode(jwe["protected"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(protected_json["alg"], "ECDH-ES+A256KW");
        assert_eq!(protected_json["enc"], "A256CBC-HS512");
        assert_eq!(protected_json["typ"], "application/didcomm-encrypted+json");

        // Decrypt round-trip via the same crate the server uses.
        let decrypted = affinidi_messaging_didcomm::jwe::decrypt::decrypt(
            &jwe_str,
            "did:key:test#key-1",
            &recipient_private,
            None, // anoncrypt — no sender public key needed
        )
        .expect("decrypt round-trip");
        assert_eq!(decrypted.plaintext, b"hello world");
        assert!(!decrypted.authenticated, "anoncrypt is not authenticated");
    }

    #[test]
    fn test_build_message_structure() {
        let msg = build_message(
            "https://example.com/test",
            serde_json::json!({"foo": "bar"}),
            "did:key:sender",
            "did:key:recipient",
        );
        let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(parsed["type"], "https://example.com/test");
        assert_eq!(parsed["from"], "did:key:sender");
        assert_eq!(parsed["to"][0], "did:key:recipient");
        assert_eq!(parsed["body"]["foo"], "bar");
        assert!(parsed["id"].is_string());
    }
}
