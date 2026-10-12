//! CLI-side producer helper for `vta_sdk::sealed_transfer`.
//!
//! Used by commands that emit sensitive bundles (context provisioning, key
//! bundle export). The CLI sits on the admin's workstation, not inside the
//! VTA, so it has no persistent nonce store and no long-lived producer
//! identity to sign with. We mint a fresh ephemeral keypair per seal and
//! attach a `PinnedOnly` assertion — the operator communicates the producer
//! pubkey + digest out-of-band to the recipient, who verifies by pinning.
//!
//! This mirrors the `vta bootstrap seal` (offline Mode C) pattern from
//! `vta-service/src/bootstrap_cli.rs`; the difference is that context
//! provisioning composes seal + VTA REST calls into a single operator action,
//! whereas Mode C takes a pre-constructed payload file.
//!
//! Call pattern:
//!
//! ```ignore
//! use vta_cli_common::sealed_producer::{SealedRecipient, seal_for_recipient};
//!
//! let recipient = SealedRecipient::from_file(&path)?;  // or ::from_inline(...)
//! let sealed = seal_for_recipient(&recipient, &payload).await?;
//! print!("{}", sealed.armored);
//! eprintln!("SHA-256 digest: {}", sealed.digest);
//! ```

use std::path::Path;

use vta_sdk::sealed_transfer::{
    AssertionProof, BootstrapRequest, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1,
    armor, bundle_digest, generate_ed25519_keypair, seal_payload,
};

/// Recipient of a sealed bundle — the X25519 pubkey the AEAD encrypts to
/// (derived from the consumer's `did:key`), plus the bundle id (the
/// recipient's nonce) that anchors anti-replay.
///
/// Construct via [`Self::from_file`] (standard path: consumer ran
/// `pnm bootstrap request --out <file>`) or [`Self::from_inline`] (fallback:
/// consumer pasted did:key / nonce over chat, no file transfer available).
#[derive(Debug)]
pub struct SealedRecipient {
    pub pubkey: [u8; 32],
    pub bundle_id: [u8; 16],
    pub label: Option<String>,
}

impl SealedRecipient {
    /// Load from a `BootstrapRequest` JSON file (produced by
    /// `pnm bootstrap request --out <file>`).
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let json =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::from_json_str(&json)
            .map_err(|e| format!("parse BootstrapRequest at {}: {e}", path.display()).into())
    }

    /// Parse directly from a JSON string. Useful for tests and non-file
    /// transports (e.g. stdin).
    pub fn from_json_str(json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let request: BootstrapRequest =
            serde_json::from_str(json).map_err(|e| format!("parse BootstrapRequest: {e}"))?;
        if request.version != 1 {
            return Err(
                format!("unsupported BootstrapRequest version: {}", request.version).into(),
            );
        }
        Ok(Self {
            pubkey: request.decode_client_x25519_pub()?,
            bundle_id: request.decode_nonce()?,
            label: request.label,
        })
    }

    /// Construct from an inline `did:key` (Ed25519) and hex nonce.
    ///
    /// `nonce_hex` must be 32 hex characters (16 bytes). Accepts either case.
    /// The `did:key` is decoded to an Ed25519 pubkey and converted to the
    /// X25519 pubkey HPKE uses.
    pub fn from_inline(
        client_did: &str,
        nonce_hex: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let ed_pub = affinidi_crypto::did_key::did_key_to_ed25519_pub(client_did.trim())
            .map_err(|e| format!("invalid recipient did:key: {e}"))?;
        let pubkey = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&ed_pub)
            .map_err(|e| format!("recipient did:key X25519 derivation: {e}"))?;
        let nonce_bytes = decode_hex(nonce_hex.trim())?;
        let bundle_id: [u8; 16] = nonce_bytes
            .try_into()
            .map_err(|_| "recipient nonce must be 16 bytes (32 hex chars)".to_string())?;
        Ok(Self {
            pubkey,
            bundle_id,
            label: None,
        })
    }
}

/// Resolve CLI `--recipient` / `--recipient-did` / `--recipient-nonce`
/// arguments into a [`SealedRecipient`].
///
/// Clap's `conflicts_with` + `requires` already enforce at most one mode
/// is populated; this helper enforces that at least one is and produces
/// a consistent error message. Shared between `pnm` (admin workstation)
/// and `vta` (on-host offline admin) CLIs — both accept the same
/// recipient-specification shape.
pub fn resolve_recipient(
    recipient: Option<&std::path::Path>,
    recipient_did: Option<&str>,
    recipient_nonce: Option<&str>,
) -> Result<SealedRecipient, Box<dyn std::error::Error>> {
    if let Some(path) = recipient {
        SealedRecipient::from_file(path)
    } else if let (Some(did), Some(nonce)) = (recipient_did, recipient_nonce) {
        SealedRecipient::from_inline(did, nonce)
    } else {
        Err(
            "a recipient is required: pass --recipient <file> or both --recipient-did and --recipient-nonce"
                .into(),
        )
    }
}

/// Output of a successful [`seal_for_recipient`] call.
pub struct SealedOutput {
    /// The armored sealed bundle (caller writes to stdout or file).
    pub armored: String,
    /// SHA-256 digest of the sealed ciphertext (lowercase hex).
    ///
    /// The recipient verifies this out-of-band to defeat producer
    /// impersonation — without it, `PinnedOnly` reduces to trust-on-first-use.
    pub digest: String,
    /// Ephemeral producer `did:key` (Ed25519). Communicated out-of-band
    /// alongside the digest so the recipient can confirm the assertion.
    pub producer_did: String,
    pub bundle_id: [u8; 16],
}

/// Seal a payload for the given recipient with a fresh ephemeral producer
/// keypair and a `PinnedOnly` assertion.
///
/// Uses an [`InMemoryNonceStore`] — the CLI is single-shot, so there is no
/// cross-run replay to defend against on the producer side.
pub async fn seal_for_recipient(
    recipient: &SealedRecipient,
    payload: &SealedPayloadV1,
) -> Result<SealedOutput, Box<dyn std::error::Error>> {
    let (_producer_seed, producer_pk) = generate_ed25519_keypair();
    let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_pk);
    let producer = ProducerAssertion {
        producer_did: producer_did.clone(),
        proof: AssertionProof::PinnedOnly,
    };
    let nonce_store = InMemoryNonceStore::new();
    let bundle = seal_payload(
        &recipient.pubkey,
        recipient.bundle_id,
        producer,
        payload,
        &nonce_store,
    )
    .await?;
    let armored = armor::encode(&bundle);
    let digest = bundle_digest(&bundle);
    Ok(SealedOutput {
        armored,
        digest,
        producer_did,
        bundle_id: recipient.bundle_id,
    })
}

/// Seal a [`vta_sdk::did_secrets::DidSecretsBundle`] to the given recipient
/// and emit the armored output + stderr banner. Shared between
/// `pnm keys bundle` (online admin, reads state over REST) and
/// `vta keys bundle` (offline admin, reads state from the local store) —
/// both produce the same bundle shape, this helper handles seal + print.
///
/// When `out` is `Some(path)`, the armor is written to that file; when
/// `None`, it is printed to stdout. Either way the banner + digest +
/// producer DID go to stderr.
pub async fn emit_did_secrets_bundle(
    bundle: vta_sdk::did_secrets::DidSecretsBundle,
    recipient: &SealedRecipient,
    context_id: &str,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let did = bundle.did.clone();
    let secret_count = bundle.secrets.len();
    let payload = SealedPayloadV1::DidSecrets(Box::new(bundle));
    let sealed = seal_for_recipient(recipient, &payload).await?;

    eprintln!();
    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  DID secrets bundle (sealed — armored to the recipient)  ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
    eprintln!("  Context: {context_id}");
    eprintln!("  DID:     {did}");
    eprintln!("  Secrets: {secret_count}");
    if let Some(ref label) = recipient.label {
        eprintln!("  Recipient: {label}");
    }
    eprintln!();

    emit_sealed_output(&sealed, out)
}

/// Seal one raw private key ([`SealedPayloadV1::RawPrivateKey`]) to the given
/// recipient and emit the armored output + stderr banner. Used by
/// `pnm keys bundle-key` for a key no DID publishes.
pub async fn emit_raw_private_key_bundle(
    key_type: vta_sdk::keys::KeyType,
    key_bytes: &[u8],
    key_id: &str,
    recipient: &SealedRecipient,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine as _;
    let payload = SealedPayloadV1::RawPrivateKey(vta_sdk::sealed_transfer::RawPrivateKey {
        key_type: key_type.to_string(),
        key_bytes_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes),
    });
    let sealed = seal_for_recipient(recipient, &payload).await?;

    eprintln!();
    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  Private key (sealed — armored to the recipient)         ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
    eprintln!("  Key:  {key_id}");
    eprintln!("  Type: {key_type}");
    if let Some(ref label) = recipient.label {
        eprintln!("  Recipient: {label}");
    }
    eprintln!();

    emit_sealed_output(&sealed, out)
}

/// Seal a [`vta_sdk::context_provision::ContextProvisionBundle`] to the
/// given recipient and emit the armored output + stderr banner. Shared
/// between `pnm context reprovision` and `vta context reprovision` —
/// both produce the same bundle shape from different transports.
///
/// When `out` is `Some(path)`, the armor is written to that file; when
/// `None`, it is printed to stdout. Either way the banner + digest +
/// producer DID go to stderr.
pub async fn emit_context_provision_bundle(
    bundle: vta_sdk::context_provision::ContextProvisionBundle,
    recipient: &SealedRecipient,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let context_id = bundle.context_id.clone();
    let context_name = bundle.context_name.clone();
    let admin_did = bundle.admin_did.clone();
    let did = bundle.did.as_ref().map(|d| d.id.clone());
    let payload = SealedPayloadV1::ContextProvision(Box::new(bundle));
    let sealed = seal_for_recipient(recipient, &payload).await?;

    eprintln!();
    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  Context provision bundle (sealed — hand off armored output) ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
    eprintln!("  Context:   {context_id} ({context_name})");
    eprintln!("  Admin DID: {admin_did}");
    if let Some(ref d) = did {
        eprintln!("  DID:       {d}");
    }
    if let Some(ref label) = recipient.label {
        eprintln!("  Recipient: {label}");
    }
    eprintln!();

    emit_sealed_output(&sealed, out)
}

/// Emit a sealed bundle. When `out` is `Some`, the armor is written to
/// that path; when `None`, it goes to stdout. The banner + digest +
/// producer DID always go to stderr so they don't contaminate a
/// redirected armor file.
pub fn emit_sealed_output(
    sealed: &SealedOutput,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle_id_hex = hex_lower(&sealed.bundle_id);

    match out {
        Some(path) => {
            std::fs::write(path, sealed.armored.as_bytes())
                .map_err(|e| format!("write {}: {e}", path.display()))?;
            eprintln!("Armored bundle written to {}", path.display());
        }
        None => {
            println!("{}", sealed.armored);
        }
    }

    eprintln!();
    eprintln!("  Bundle-Id:       {bundle_id_hex}");
    eprintln!("  Producer DID:    {}", sealed.producer_did);
    eprintln!("  SHA-256 digest:  {}", sealed.digest);
    eprintln!();
    eprintln!(
        "Communicate the digest to the recipient out-of-band so they can run:\n  \
         pnm bootstrap open --bundle <file> --expect-digest {}",
        sealed.digest
    );
    Ok(())
}

use vta_sdk::hex::lower as hex_lower;

fn decode_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex string must have even length (got {})", s.len()).into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = std::str::from_utf8(&bytes[i..i + 2])
            .map_err(|e| format!("hex not UTF-8 at offset {i}: {e}"))?;
        let b = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("invalid hex at offset {i} ('{pair}'): {e}"))?;
        out.push(b);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::credentials::CredentialBundle;
    use vta_sdk::sealed_transfer::open_bundle;

    fn sample_payload() -> SealedPayloadV1 {
        SealedPayloadV1::AdminCredential(Box::new(CredentialBundle::new(
            "did:key:z6Mk123",
            "z1234567890",
            "did:key:z6MkVTA",
        )))
    }

    #[test]
    fn hex_roundtrip_16_bytes() {
        let bytes: Vec<u8> = (0..16u8).collect();
        let hex = hex_lower(&bytes);
        assert_eq!(hex.len(), 32);
        let back = decode_hex(&hex).unwrap();
        assert_eq!(back, bytes);
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn decode_hex_rejects_non_hex() {
        assert!(decode_hex("gg").is_err());
    }

    #[test]
    fn recipient_from_inline_validates_sizes() {
        use vta_sdk::sealed_transfer::generate_ed25519_keypair;

        let (_seed, ed_pub) = generate_ed25519_keypair();
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&ed_pub);
        let nonce_hex = "00112233445566778899aabbccddeeff";
        let r = SealedRecipient::from_inline(&did, nonce_hex).unwrap();
        // Recipient-side pubkey is the derived X25519, not the raw Ed25519.
        let expected_x = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&ed_pub).unwrap();
        assert_eq!(r.pubkey, expected_x);
        assert_eq!(
            r.bundle_id,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );

        // Wrong did:key prefix.
        assert!(SealedRecipient::from_inline("did:example:123", nonce_hex).is_err());

        // Wrong nonce size.
        assert!(SealedRecipient::from_inline(&did, "deadbeef").is_err());
    }

    #[tokio::test]
    async fn seal_round_trips_via_armor() {
        use vta_sdk::sealed_transfer::{ed25519_seed_to_x25519_secret, generate_ed25519_keypair};

        // Recipient generates Ed25519 keypair + nonce (simulating
        // `pnm bootstrap request`). The HPKE target is the derived X25519.
        let (recip_seed, recip_ed_pub) = generate_ed25519_keypair();
        let recip_pk =
            affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&recip_ed_pub).unwrap();
        let recip_sk = ed25519_seed_to_x25519_secret(&recip_seed);
        let bundle_id: [u8; 16] = rand::random();
        let recipient = SealedRecipient {
            pubkey: recip_pk,
            bundle_id,
            label: Some("test".into()),
        };

        // Producer seals.
        let sealed = seal_for_recipient(&recipient, &sample_payload())
            .await
            .unwrap();
        assert!(sealed.armored.contains("BEGIN VTA SEALED BUNDLE"));

        // Recipient opens.
        let parsed = armor::decode(&sealed.armored).unwrap();
        assert_eq!(parsed.len(), 1);
        let opened = open_bundle(&recip_sk, &parsed[0], Some(&sealed.digest)).unwrap();
        assert_eq!(opened.bundle_id, bundle_id);
        match opened.payload {
            SealedPayloadV1::AdminCredential(c) => {
                assert_eq!(c.did, "did:key:z6Mk123");
            }
            _ => panic!("wrong payload variant"),
        }

        // Producer assertion is PinnedOnly and the did:key matches what we
        // surfaced in the output.
        assert!(matches!(opened.producer.proof, AssertionProof::PinnedOnly));
        assert_eq!(opened.producer.producer_did, sealed.producer_did);
    }

    #[tokio::test]
    async fn seal_recipient_from_json_round_trip() {
        use vta_sdk::sealed_transfer::{ed25519_seed_to_x25519_secret, generate_ed25519_keypair};

        let (ed_seed, ed_pub) = generate_ed25519_keypair();
        let bundle_id: [u8; 16] = rand::random();
        let request = BootstrapRequest::new(ed_pub, bundle_id, Some("json-test".into()));
        let json = serde_json::to_string(&request).unwrap();

        let recipient = SealedRecipient::from_json_str(&json).unwrap();
        // Recipient carries the X25519 pubkey derived from the did:key; the
        // opener uses the X25519 secret derived from the same Ed25519 seed.
        let recip_x_sk = ed25519_seed_to_x25519_secret(&ed_seed);
        assert_eq!(recipient.bundle_id, bundle_id);
        assert_eq!(recipient.label.as_deref(), Some("json-test"));

        let sealed = seal_for_recipient(&recipient, &sample_payload())
            .await
            .unwrap();
        let parsed = armor::decode(&sealed.armored).unwrap();
        let opened = open_bundle(&recip_x_sk, &parsed[0], Some(&sealed.digest)).unwrap();
        assert_eq!(opened.bundle_id, bundle_id);
    }

    #[test]
    fn recipient_from_json_rejects_unknown_version() {
        // Manually craft an unsupported version — BootstrapRequest::new always
        // sets version=1, so there's no constructor for this.
        let json = r#"{"version": 99, "client_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "nonce": "AAAAAAAAAAAAAAAAAAAAAA"}"#;
        let err = SealedRecipient::from_json_str(json)
            .unwrap_err()
            .to_string();
        assert!(err.contains("version"), "unexpected error: {err}");
    }
}
