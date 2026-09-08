//! A bare 32-byte key must survive decoding even when its first two bytes
//! happen to spell a multicodec prefix.
//!
//! Both decoders accept two encodings — a 2-byte multicodec prefix plus 32 key
//! bytes, or 32 bare key bytes — and originally told them apart by looking at
//! the leading bytes. A bare key is free to begin with any two bytes at all,
//! including a prefix's, so such a key had its first two stripped and arrived as
//! 30 bytes: `InvalidSeedLength`, for a key that was perfectly valid.
//!
//! For randomly generated keys that is 3 chances in 65536 (`0x8026`, `0x8226`,
//! `0x8626`) — rare enough to read as noise, frequent enough to fail CI, which
//! it did on `room-host`'s `a_member_without_a_nomination_cannot_claim`.
//!
//! Length is the only sound disambiguator, and these tests pin both directions
//! of it: a colliding bare key still decodes whole, and a genuinely prefixed key
//! still has its prefix removed.

use vta_sdk::did_key::{decode_ed25519_public_key_multibase, decode_private_key_multibase};

const ED25519_PRIV: [u8; 2] = [0x80, 0x26];
const X25519_PRIV: [u8; 2] = [0x82, 0x26];
const P256_PRIV: [u8; 2] = [0x86, 0x26];
const ED25519_PUB: [u8; 2] = [0xed, 0x01];

fn mb(bytes: &[u8]) -> String {
    multibase::encode(multibase::Base::Base58Btc, bytes)
}

/// A bare 32-byte key whose first two bytes collide with a private-key prefix.
#[test]
fn a_colliding_bare_private_key_decodes_whole() {
    for (name, prefix) in [
        ("ed25519", ED25519_PRIV),
        ("x25519", X25519_PRIV),
        ("p256", P256_PRIV),
    ] {
        let mut seed = [7u8; 32];
        seed[0] = prefix[0];
        seed[1] = prefix[1];

        let got = decode_private_key_multibase(&mb(&seed))
            .unwrap_or_else(|e| panic!("{name}: a valid 32-byte seed must decode, got {e}"));
        assert_eq!(got, seed, "{name}: the key came back altered");
    }
}

/// The same, for the public-key decoder.
#[test]
fn a_colliding_bare_public_key_decodes_whole() {
    let mut key = [9u8; 32];
    key[0] = ED25519_PUB[0];
    key[1] = ED25519_PUB[1];

    let got = decode_ed25519_public_key_multibase(&mb(&key)).expect("a valid 32-byte key decodes");
    assert_eq!(got, key);
}

/// The other direction: a genuinely prefixed key still loses its prefix. Without
/// this, "stop stripping" would pass the tests above and break every real caller.
#[test]
fn a_prefixed_key_still_has_its_prefix_removed() {
    let key = [3u8; 32];

    for prefix in [ED25519_PRIV, X25519_PRIV, P256_PRIV] {
        let mut prefixed = Vec::with_capacity(34);
        prefixed.extend_from_slice(&prefix);
        prefixed.extend_from_slice(&key);

        assert_eq!(
            decode_private_key_multibase(&mb(&prefixed)).expect("prefixed key decodes"),
            key,
            "a 34-byte prefixed key must yield the 32 bytes after the prefix"
        );
    }

    let mut prefixed = Vec::with_capacity(34);
    prefixed.extend_from_slice(&ED25519_PUB);
    prefixed.extend_from_slice(&key);
    assert_eq!(
        decode_ed25519_public_key_multibase(&mb(&prefixed)).expect("prefixed pubkey decodes"),
        key
    );
}

/// Anything that is neither 32 nor 34 bytes is still refused rather than coerced.
#[test]
fn a_wrong_length_key_is_still_refused() {
    for len in [0usize, 2, 31, 33, 35, 64] {
        let bytes = vec![1u8; len];
        assert!(
            decode_private_key_multibase(&mb(&bytes)).is_err(),
            "{len} bytes must not decode as a key"
        );
    }
}
