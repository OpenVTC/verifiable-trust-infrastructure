//! `VtcKeyBundle` — the secret-store payload that holds the VTC's
//! VTA-provisioned DID + key material.
//!
//! The VTC's identity is **always** provisioned by a VTA via the
//! `vtc-host` template. The resulting [`TemplateBootstrapPayload`]
//! carries:
//!
//! - The integration's DID (becomes [`AppConfig::vtc_did`]).
//! - One [`DidKeyMaterial`] entry with two keys: Ed25519 signing
//!   (serves both `assertionMethod` and `authentication`) and X25519
//!   key-agreement (`keyAgreement`).
//!
//! We persist exactly that subset as a `VtcKeyBundle` inside the
//! secret store. The on-disk format is JSON (Q2 of the
//! VTA-driven-keys design doc): forward-compat over wire-size
//! savings, and trivially inspectable for debugging.
//!
//! ## Key derivations downstream
//!
//! `init_auth` extracts the raw Ed25519 + X25519 private bytes
//! and feeds them to:
//!
//! - The DIDComm `Secret::generate_ed25519` / `generate_x25519`
//!   constructors — they become the VTC DID's `#key-0` and
//!   `#key-1` resolver entries.
//! - HKDF derivations for the install-token signer and the audit
//!   key. The Ed25519 private bytes (32) are the master IKM;
//!   `info` strings (`vtc-install-jwt-key/v2`, `vtc-audit-key/v2`)
//!   domain-separate them. Bumping from `/v1` is intentional —
//!   any pre-rework keyring entry derived from a 64-byte BIP-39
//!   seed produces different HKDF output under `/v2`, so a stale
//!   deployment fails loud at the verification step rather than
//!   silently accepting tokens minted under the old derivation.

use multibase::Base;
use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use zeroize::Zeroizing;

/// The persisted shape of the VTC's VTA-provisioned identity.
///
/// All public material is multibase-encoded (matching the
/// `DidKeyMaterial` wire shape from `vta-sdk`); private halves are
/// multibase-encoded strings at rest. Use the accessor methods
/// instead of touching the raw fields if you need a `Zeroizing`
/// buffer for the live key.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VtcKeyBundle {
    /// The VTC's `did:webvh`. Matches [`crate::config::AppConfig::vtc_did`]
    /// after a successful setup.
    pub integration_did: String,
    /// DID URL for the Ed25519 signing key (e.g. `did:webvh:…#key-0`).
    pub ed25519_key_id: String,
    /// Multibase-encoded Ed25519 public key.
    pub ed25519_public_multibase: String,
    /// Multibase-encoded Ed25519 private key. Kept as `String` so the
    /// derived `Serialize`/`Deserialize` stays simple; access via
    /// [`Self::ed25519_private_zeroizing`] when feeding a signer.
    pub ed25519_private_multibase: String,
    /// DID URL for the X25519 key-agreement key (e.g. `did:webvh:…#key-1`).
    pub x25519_key_id: String,
    /// Multibase-encoded X25519 public key.
    pub x25519_public_multibase: String,
    /// Multibase-encoded X25519 private key. Access via
    /// [`Self::x25519_private_zeroizing`].
    pub x25519_private_multibase: String,
}

// Manual Debug — the two `*_private_multibase` fields are live key
// material; a derived `Debug` would print them on any `{:?}`. Redact the
// private halves; DIDs + public keys are not secret.
impl std::fmt::Debug for VtcKeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VtcKeyBundle")
            .field("integration_did", &self.integration_did)
            .field("ed25519_key_id", &self.ed25519_key_id)
            .field("ed25519_public_multibase", &self.ed25519_public_multibase)
            .field("ed25519_private_multibase", &"<redacted>")
            .field("x25519_key_id", &self.x25519_key_id)
            .field("x25519_public_multibase", &self.x25519_public_multibase)
            .field("x25519_private_multibase", &"<redacted>")
            .finish()
    }
}

impl VtcKeyBundle {
    /// Take the Ed25519 private key out into a [`Zeroizing`] buffer.
    pub fn ed25519_private_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.ed25519_private_multibase.clone())
    }

    /// Take the X25519 private key out into a [`Zeroizing`] buffer.
    pub fn x25519_private_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.x25519_private_multibase.clone())
    }

    /// Decode the 32-byte Ed25519 private scalar.
    ///
    /// Multibase keys carry a 2-byte multicodec prefix (`0xed01`
    /// for Ed25519 private). The Rust SDK uses
    /// `affinidi_crypto::ed25519::decode_private_key_multibase` for
    /// this; we duplicate the strip-and-decode inline to avoid
    /// pulling the dep into vtc-service just for one call.
    pub fn ed25519_private_bytes(&self) -> Result<Zeroizing<[u8; 32]>, AppError> {
        decode_private_multibase(&self.ed25519_private_multibase, ED25519_PRIV_CODEC)
    }

    /// Decode the 32-byte X25519 private scalar.
    pub fn x25519_private_bytes(&self) -> Result<Zeroizing<[u8; 32]>, AppError> {
        decode_private_multibase(&self.x25519_private_multibase, X25519_PRIV_CODEC)
    }

    /// Serialize the bundle as the bytes that should land in the
    /// secret store. JSON for forward-compat.
    pub fn to_secret_store_bytes(&self) -> Result<Vec<u8>, AppError> {
        serde_json::to_vec(self).map_err(|e| AppError::Internal(format!("bundle serialize: {e}")))
    }

    /// Decode the bytes that came out of the secret store.
    pub fn from_secret_store_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        serde_json::from_slice(bytes).map_err(|e| {
            AppError::Internal(format!(
                "secret store does not contain a VtcKeyBundle: {e}. Has this VTC been set up \
                 against a VTA? Run `vtc setup` to provision."
            ))
        })
    }
    /// Construct a bundle directly from a VTA-returned
    /// `DidKeyMaterial`. `integration_did` is supplied separately
    /// because `DidKeyMaterial` only carries it as part of the
    /// inner `KeyPair.key_id` (`did:webvh:…#key-0`) — promoting it
    /// to the top-level field keeps the bundle self-contained.
    pub fn from_did_key_material(
        integration_did: String,
        material: &vta_sdk::sealed_transfer::template_bootstrap::DidKeyMaterial,
    ) -> Self {
        Self {
            integration_did,
            ed25519_key_id: material.signing_key.key_id.clone(),
            ed25519_public_multibase: material.signing_key.public_key_multibase.clone(),
            ed25519_private_multibase: material.signing_key.private_key_multibase.clone(),
            x25519_key_id: material.ka_key.key_id.clone(),
            x25519_public_multibase: material.ka_key.public_key_multibase.clone(),
            x25519_private_multibase: material.ka_key.private_key_multibase.clone(),
        }
    }
}

const ED25519_PRIV_CODEC: [u8; 2] = [0x80, 0x26];
const X25519_PRIV_CODEC: [u8; 2] = [0x82, 0x26];

fn decode_private_multibase(
    mb: &str,
    expected_codec: [u8; 2],
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let (base, decoded) =
        multibase::decode(mb).map_err(|e| AppError::Internal(format!("multibase decode: {e}")))?;
    if base != Base::Base58Btc {
        return Err(AppError::Internal(format!(
            "expected base58btc multibase, got {base:?}"
        )));
    }
    if decoded.len() != 2 + 32 {
        return Err(AppError::Internal(format!(
            "expected 34-byte multicodec-prefixed key, got {}",
            decoded.len()
        )));
    }
    if decoded[..2] != expected_codec {
        return Err(AppError::Internal(format!(
            "wrong multicodec prefix: expected {:02x}{:02x}, got {:02x}{:02x}",
            expected_codec[0], expected_codec[1], decoded[0], decoded[1]
        )));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&decoded[2..]);
    Ok(out)
}

/// Encode a 32-byte private scalar back into the multibase form
/// the bundle stores. Only used by tests + the wizard's
/// `from_bundle_bytes` fixture path; production bundles are built
/// from a `DidKeyMaterial` whose multibase fields are already
/// VTA-issued.
#[doc(hidden)]
pub fn encode_private_multibase(bytes: &[u8; 32], codec: [u8; 2]) -> String {
    let mut buf = Vec::with_capacity(2 + 32);
    buf.extend_from_slice(&codec);
    buf.extend_from_slice(bytes);
    multibase::encode(Base::Base58Btc, &buf)
}

#[doc(hidden)]
pub fn ed25519_priv_codec() -> [u8; 2] {
    ED25519_PRIV_CODEC
}

#[doc(hidden)]
pub fn x25519_priv_codec() -> [u8; 2] {
    X25519_PRIV_CODEC
}

/// Test-only fixture builder: produce a bundle from two raw 32-byte
/// scalars. Production code never calls this — bundles come from
/// the VTA via [`VtcKeyBundle::from_did_key_material`].
///
/// Exposed outside `#[cfg(test)]` so integration tests under
/// `vtc-service/tests/` can stage a bundle without needing a live
/// VTA. The function is otherwise harmless — given any two 32-byte
/// scalars it produces a syntactically-valid bundle.
#[doc(hidden)]
pub fn bundle_from_raw(
    integration_did: &str,
    ed25519_priv: &[u8; 32],
    x25519_priv: &[u8; 32],
) -> VtcKeyBundle {
    use ed25519_dalek::SigningKey;

    let signing = SigningKey::from_bytes(ed25519_priv);
    let ed25519_public = signing.verifying_key().to_bytes();
    let x25519_public_priv = x25519_dalek::StaticSecret::from(*x25519_priv);
    let x25519_public = x25519_dalek::PublicKey::from(&x25519_public_priv).to_bytes();

    VtcKeyBundle {
        integration_did: integration_did.to_string(),
        ed25519_key_id: format!("{integration_did}#key-0"),
        ed25519_public_multibase: encode_public_multibase(&ed25519_public, [0xed, 0x01]),
        ed25519_private_multibase: encode_private_multibase(ed25519_priv, ED25519_PRIV_CODEC),
        x25519_key_id: format!("{integration_did}#key-1"),
        x25519_public_multibase: encode_public_multibase(&x25519_public, [0xec, 0x01]),
        x25519_private_multibase: encode_private_multibase(x25519_priv, X25519_PRIV_CODEC),
    }
}

fn encode_public_multibase(bytes: &[u8; 32], codec: [u8; 2]) -> String {
    let mut buf = Vec::with_capacity(2 + 32);
    buf.extend_from_slice(&codec);
    buf.extend_from_slice(bytes);
    multibase::encode(Base::Base58Btc, &buf)
}

/// Decode whatever the secret store handed back into the VTC's
/// `(ed25519, x25519)` private-scalar pair.
///
/// Accepts both on-disk shapes, so every consumer (auth bootstrap in
/// `server.rs`, the `vtc status` trust-ping) reads keys the same way:
///
/// - **JSON `VtcKeyBundle`** — what `vtc setup` has written since the
///   VTA-driven-keys rework, i.e. every real deployment. The bundle's
///   `integration_did` is checked against `vtc_did` so a mismatched bundle
///   can't silently sign for the wrong DID.
/// - **Legacy 64 raw bytes** (`ed‖x`) — used by the integration-test
///   fixtures; split directly.
///
/// Returning the pair in [`Zeroizing`] buffers keeps the live scalars off
/// the heap-without-wipe path. The error is a display `String` because both
/// call sites only surface it (a warning log / a `Box<dyn Error>` bubble),
/// never match on it.
pub fn decode_secret_store_value(
    vtc_did: &str,
    stored: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    if stored.len() == 64 {
        // Legacy raw-bytes shape — used by every integration-test
        // fixture today. Promote into a bundle-shaped pair via a
        // direct copy.
        let mut ed = Zeroizing::new([0u8; 32]);
        let mut x = Zeroizing::new([0u8; 32]);
        ed.copy_from_slice(&stored[..32]);
        x.copy_from_slice(&stored[32..]);
        return Ok((ed, x));
    }
    let bundle = VtcKeyBundle::from_secret_store_bytes(stored)
        .map_err(|e| format!("secret store payload not a VtcKeyBundle: {e}"))?;
    if bundle.integration_did != vtc_did {
        return Err(format!(
            "VtcKeyBundle DID '{}' does not match config.vtc_did '{}' — refusing to init auth",
            bundle.integration_did, vtc_did
        ));
    }
    let ed = bundle
        .ed25519_private_bytes()
        .map_err(|e| format!("bundle Ed25519 decode: {e}"))?;
    let x = bundle
        .x25519_private_bytes()
        .map_err(|e| format!("bundle X25519 decode: {e}"))?;
    Ok((ed, x))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> VtcKeyBundle {
        bundle_from_raw("did:webvh:vtc.example.com:abc", &[0x11; 32], &[0x22; 32])
    }

    #[test]
    fn round_trip_secret_store_bytes() {
        let b = fixture();
        let bytes = b.to_secret_store_bytes().unwrap();
        let parsed = VtcKeyBundle::from_secret_store_bytes(&bytes).unwrap();
        assert_eq!(b, parsed);
    }

    #[test]
    fn debug_redacts_private_keys() {
        let b = fixture();
        let dbg = format!("{b:?}");
        assert!(dbg.contains("<redacted>"), "got {dbg}");
        // The actual private multibase strings must not appear.
        assert!(
            !dbg.contains(&b.ed25519_private_multibase),
            "ed25519 private leaked: {dbg}"
        );
        assert!(
            !dbg.contains(&b.x25519_private_multibase),
            "x25519 private leaked: {dbg}"
        );
        // Public material stays visible for diagnostics.
        assert!(dbg.contains(&b.integration_did));
    }

    #[test]
    fn ed25519_private_bytes_decodes() {
        let b = fixture();
        let raw = b.ed25519_private_bytes().unwrap();
        assert_eq!(&*raw, &[0x11; 32]);
    }

    #[test]
    fn x25519_private_bytes_decodes() {
        let b = fixture();
        let raw = b.x25519_private_bytes().unwrap();
        assert_eq!(&*raw, &[0x22; 32]);
    }

    #[test]
    fn from_secret_store_bytes_clear_error_on_garbage() {
        let err = VtcKeyBundle::from_secret_store_bytes(b"not a bundle").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Run `vtc setup`"),
            "expected operator hint in error, got: {msg}"
        );
    }

    #[test]
    fn from_secret_store_bytes_rejects_unknown_fields() {
        let bogus = br#"{"integration_did":"did:webvh:x","extra":"sneaky","ed25519_key_id":"x#0","ed25519_public_multibase":"z","ed25519_private_multibase":"z","x25519_key_id":"x#1","x25519_public_multibase":"z","x25519_private_multibase":"z"}"#;
        assert!(VtcKeyBundle::from_secret_store_bytes(bogus).is_err());
    }

    #[test]
    fn rejects_wrong_multicodec_prefix() {
        let mut b = fixture();
        // Swap the Ed25519 private's multicodec for the X25519 one.
        let raw = [0x11; 32];
        b.ed25519_private_multibase = encode_private_multibase(&raw, X25519_PRIV_CODEC);
        let err = b.ed25519_private_bytes().unwrap_err();
        assert!(format!("{err}").contains("wrong multicodec prefix"));
    }

    /// P0.19: the JSON `VtcKeyBundle` shape every real deployment writes
    /// decodes into the right scalar pair. This is the shape the `vtc
    /// status` trust-ping used to reject with a "not 64 bytes" error.
    #[test]
    fn decode_secret_store_value_accepts_json_bundle() {
        let b = fixture(); // did:webvh:vtc.example.com:abc, ed=0x11.., x=0x22..
        let bytes = b.to_secret_store_bytes().unwrap();
        let (ed, x) =
            decode_secret_store_value("did:webvh:vtc.example.com:abc", &bytes).expect("decodes");
        assert_eq!(&*ed, &[0x11; 32]);
        assert_eq!(&*x, &[0x22; 32]);
    }

    /// The legacy 64-raw-byte shape (test/CI fixtures) still splits
    /// cleanly — the DID is irrelevant for this path.
    #[test]
    fn decode_secret_store_value_accepts_legacy_64_bytes() {
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(&[0xAA; 32]);
        raw.extend_from_slice(&[0xBB; 32]);
        let (ed, x) = decode_secret_store_value("did:any", &raw).expect("64-byte split");
        assert_eq!(&*ed, &[0xAA; 32]);
        assert_eq!(&*x, &[0xBB; 32]);
    }

    /// A bundle whose DID doesn't match the configured `vtc_did` is
    /// refused — it must not silently sign for the wrong identity.
    #[test]
    fn decode_secret_store_value_rejects_did_mismatch() {
        let b = fixture();
        let bytes = b.to_secret_store_bytes().unwrap();
        let err = decode_secret_store_value("did:webvh:someone.else", &bytes).unwrap_err();
        assert!(
            err.contains("does not match"),
            "expected DID-mismatch error, got: {err}"
        );
    }
}
