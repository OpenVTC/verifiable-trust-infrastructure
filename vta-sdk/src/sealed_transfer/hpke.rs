//! HPKE (RFC 9180) wiring.
//!
//! Suite: `0x0020, 0x0001, 0x0003`
//!   - KEM: DHKEM(X25519, HKDF-SHA256)
//!   - KDF: HKDF-SHA256
//!   - AEAD: ChaCha20-Poly1305
//!
//! Single-shot, base mode (no PSK, no auth-mode KEM). The chunk header is
//! bound as AEAD AAD by the caller.

use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open, single_shot_seal,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::error::SealedTransferError;

/// HPKE `info` string. Binds the suite to its purpose so a ciphertext for one
/// purpose cannot be replayed against another.
const HPKE_INFO: &[u8] = b"vta-sealed-transfer/v1";

// Randomness note: the `single_shot_seal` / `gen_keypair` calls below are
// `hpke`'s OS-CSPRNG variants — internally `UnwrapErr(getrandom::SysRng)`.
//
// **On CSPRNG failure they panic**, which is the behaviour we want and the
// same posture the hand-rolled `OsCsprng` adapter had before hpke 0.14. The
// only alternatives on a `getrandom` error are (a) return zeros
// (catastrophic: attacker-predictable HPKE keys) or (b) silently degrade to
// a weaker source (worse). A panic propagates to the handler and bubbles up
// as a 500. In practice the OS CSPRNG only fails pre-init on broken
// platforms; in a TEE with proper boot it cannot fail after startup.
//
// hpke 0.14 moved to rand_core 0.10, so the adapter that used to bridge
// `getrandom` to hpke's rand_core 0.9 traits is no longer needed.

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;

/// Wire layout for one HPKE-sealed chunk. CBOR-encoded into the
/// `ArmoredChunk.sealed_bytes` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeSealed {
    /// X25519 ephemeral public key from the KEM encapsulation (32 bytes).
    pub kem_encap: [u8; 32],
    /// AEAD-sealed bytes (ciphertext || tag).
    pub aead_ciphertext: Vec<u8>,
}

/// Seal a plaintext to `recipient_pubkey` (32-byte X25519 public key), binding
/// `aad` as additional authenticated data.
pub fn seal(
    recipient_pubkey: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<HpkeSealed, SealedTransferError> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pubkey)
        .map_err(SealedTransferError::hpke)?;
    let (encap, ciphertext) =
        single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &pk, HPKE_INFO, plaintext, aad)
            .map_err(SealedTransferError::hpke)?;
    let encap_bytes = encap.to_bytes();
    let kem_encap: [u8; 32] = encap_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SealedTransferError::Hpke("KEM encap not 32 bytes".into()))?;
    Ok(HpkeSealed {
        kem_encap,
        aead_ciphertext: ciphertext,
    })
}

/// Open an [`HpkeSealed`] using the recipient's 32-byte X25519 secret key.
pub fn open(
    recipient_secret: &[u8; 32],
    sealed: &HpkeSealed,
    aad: &[u8],
) -> Result<Vec<u8>, SealedTransferError> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_secret)
        .map_err(SealedTransferError::hpke)?;
    let encap = <Kem as KemTrait>::EncappedKey::from_bytes(&sealed.kem_encap)
        .map_err(SealedTransferError::hpke)?;
    single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encap,
        HPKE_INFO,
        &sealed.aead_ciphertext,
        aad,
    )
    .map_err(SealedTransferError::hpke)
}

/// Generate a fresh X25519 keypair (secret, public). The secret is the
/// recipient's input to [`open`]; the public is what they advertise via a
/// [`crate::sealed_transfer::request::BootstrapRequest`].
///
/// The secret is returned in a [`Zeroizing`] wrapper so the bytes are
/// scrubbed from memory when the value is dropped. `Deref<Target = [u8; 32]>`
/// so call sites that pass `&[u8; 32]` (e.g. to [`open`] / [`crate::sealed_transfer::open_bundle`])
/// keep working unchanged via auto-deref.
pub fn generate_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let (sk, pk) = <Kem as KemTrait>::gen_keypair();
    let sk_bytes: [u8; 32] = sk
        .to_bytes()
        .as_slice()
        .try_into()
        .expect("X25519 secret is 32 bytes");
    let pk_bytes: [u8; 32] = pk
        .to_bytes()
        .as_slice()
        .try_into()
        .expect("X25519 public is 32 bytes");
    (Zeroizing::new(sk_bytes), pk_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: seal to a recipient, open with that recipient's
    /// secret. Confirms the HPKE pipeline is wired correctly before
    /// the negative-path tests below try to break it.
    #[test]
    fn seal_open_round_trip() {
        let (sk, pk) = generate_keypair();
        let plaintext = b"the quick brown fox";
        let aad = b"binding context";
        let sealed = seal(&pk, plaintext, aad).expect("seal");
        let opened = open(&sk, &sealed, aad).expect("open");
        assert_eq!(opened, plaintext);
    }

    /// Opening a bundle sealed to recipient A with a *different*
    /// recipient's X25519 secret must fail. This is the load-bearing
    /// confidentiality property of `sealed_transfer` — without it, any
    /// stray X25519 secret could decrypt any bundle. The reviewer
    /// flagged this case as missing from the test suite even though
    /// the AEAD-tamper paths were thorough.
    #[test]
    fn open_with_wrong_recipient_secret_rejected() {
        let (_sk_intended, pk_intended) = generate_keypair();
        let (sk_attacker, _pk_attacker) = generate_keypair();
        let sealed = seal(&pk_intended, b"secret content", b"aad").expect("seal");
        let err = open(&sk_attacker, &sealed, b"aad")
            .expect_err("opening with the wrong X25519 secret must fail");
        assert!(
            matches!(err, SealedTransferError::Hpke(_)),
            "expected Hpke variant, got {err:?}"
        );
    }

    /// AAD binding test: open with the wrong AAD must fail even when
    /// the recipient secret is correct. Confirms the AEAD's
    /// authenticated-data binding is wired through (the chunk header
    /// fields the workspace AADs into HPKE — see `bundle.rs`).
    #[test]
    fn open_with_wrong_aad_rejected() {
        let (sk, pk) = generate_keypair();
        let sealed = seal(&pk, b"payload", b"correct aad").expect("seal");
        let err = open(&sk, &sealed, b"different aad")
            .expect_err("AAD mismatch must fail authentication");
        assert!(matches!(err, SealedTransferError::Hpke(_)), "got {err:?}");
    }

    /// Tampering with the KEM encapsulation (i.e. swapping in a
    /// different sender's ephemeral pubkey) must fail to open. Pins
    /// that an attacker can't substitute their own KEM output and
    /// have the recipient still decrypt the original ciphertext.
    #[test]
    fn open_with_tampered_kem_encap_rejected() {
        let (sk, pk) = generate_keypair();
        let mut sealed = seal(&pk, b"payload", b"aad").expect("seal");
        // Flip a single byte of the encap. Almost certainly produces
        // either a malformed encap or a successful decap to wrong
        // shared secret → AEAD failure either way.
        sealed.kem_encap[0] ^= 0x01;
        let err = open(&sk, &sealed, b"aad").expect_err("KEM-encap tampering must fail to open");
        assert!(matches!(err, SealedTransferError::Hpke(_)), "got {err:?}");
    }
}
