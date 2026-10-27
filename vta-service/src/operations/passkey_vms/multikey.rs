//! COSE_Key → W3C Multikey conversion.
//!
//! Parses the `authData` field of a WebAuthn attestationObject to
//! locate the attested COSE public key, validates the algorithm, and
//! re-encodes the key as a multibase-base58btc multicodec-prefixed
//! Multikey. The result is byte-identical to what the wallet
//! computed client-side; mismatches are how the VTA detects a
//! browser that lied about the public key.
//!
//! Algorithm support:
//!
//! | COSE alg | Curve | Multicodec | Multikey key bytes |
//! |---|---|---|---|
//! | `-7` ES256  | P-256 | `p256-pub` (`0x1200`) | 33 (compressed) |
//! | `-8` EdDSA  | Ed25519 | `ed25519-pub` (`0xed`) | 32 |
//!
//! ES384 / RS256 are rejected — neither maps to a standardised
//! multicodec slot we want to ship.

use thiserror::Error;

pub const COSE_ALG_ES256: i64 = -7;
pub const COSE_ALG_EDDSA: i64 = -8;

const MULTICODEC_P256_PUB: u64 = 0x1200;
const MULTICODEC_ED25519_PUB: u64 = 0xed;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MultikeyError {
    #[error("invalid CBOR in COSE_Key: {0}")]
    Cbor(String),
    #[error("unsupported COSE algorithm: {0}")]
    UnsupportedAlg(i64),
    #[error("malformed COSE_Key or authData: {0}")]
    Malformed(String),
}

/// Successful parse result.
#[derive(Debug, Clone)]
pub struct ParsedAuthData {
    pub cose_algorithm: i64,
    pub multikey: String,
    pub credential_id: Vec<u8>,
    pub rp_id_hash: [u8; 32],
}

/// Parse a WebAuthn `authenticatorData` byte slice and produce the
/// canonical Multikey string for the attested credential's public
/// key, plus the cleartext credential id and RP-ID hash.
///
/// Layout per WebAuthn-2 §6.1:
///   0..32   rpIdHash
///   32      flags
///   33..37  signCount (big-endian u32)
///   if AT flag set (bit 6):
///     37..53  AAGUID
///     53..55  credIdLen (big-endian u16)
///     55..55+L  credId
///     55+L..    COSE_Key (CBOR)
///   if ED flag set (bit 7):
///     trailing CBOR map of extensions
pub fn parse_auth_data_to_multikey(auth_data: &[u8]) -> Result<ParsedAuthData, MultikeyError> {
    if auth_data.len() < 37 {
        return Err(MultikeyError::Malformed("authData too short".into()));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[0..32]);
    let flags = auth_data[32];
    let at_present = (flags & 0x40) != 0;
    if !at_present {
        return Err(MultikeyError::Malformed(
            "authData missing AT flag — no attested credential data".into(),
        ));
    }
    if auth_data.len() < 55 {
        return Err(MultikeyError::Malformed(
            "authData too short for attested credential data".into(),
        ));
    }
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let key_start = 55 + cred_len;
    if auth_data.len() < key_start {
        return Err(MultikeyError::Malformed(
            "authData credential ID truncated".into(),
        ));
    }
    let credential_id = auth_data[55..55 + cred_len].to_vec();
    let cose_bytes = &auth_data[key_start..];
    let (cose_algorithm, multikey) = cose_key_to_multikey(cose_bytes)?;
    Ok(ParsedAuthData {
        cose_algorithm,
        multikey,
        credential_id,
        rp_id_hash,
    })
}

/// Decode a COSE_Key (CBOR-encoded) and return `(alg, multikey)`.
pub fn cose_key_to_multikey(cose_bytes: &[u8]) -> Result<(i64, String), MultikeyError> {
    let value: ciborium::value::Value = ciborium::de::from_reader(cose_bytes)
        .map_err(|e| MultikeyError::Cbor(format!("decode: {e}")))?;

    let map = match value {
        ciborium::value::Value::Map(m) => m,
        _ => {
            return Err(MultikeyError::Malformed(
                "COSE_Key is not a CBOR map".into(),
            ));
        }
    };

    let mut alg: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;

    for (k, v) in map {
        let label = match k {
            ciborium::value::Value::Integer(i) => i128::from(i) as i64,
            _ => continue,
        };
        match label {
            3 => {
                if let ciborium::value::Value::Integer(i) = v {
                    alg = Some(i128::from(i) as i64);
                }
            }
            -2 => {
                if let ciborium::value::Value::Bytes(b) = v {
                    x = Some(b);
                }
            }
            -3 => {
                if let ciborium::value::Value::Bytes(b) = v {
                    y = Some(b);
                }
            }
            _ => {}
        }
    }

    let alg =
        alg.ok_or_else(|| MultikeyError::Malformed("COSE_Key missing alg (label 3)".into()))?;

    match alg {
        COSE_ALG_ES256 => {
            let x = x.ok_or_else(|| MultikeyError::Malformed("ES256 missing x".into()))?;
            let y = y.ok_or_else(|| MultikeyError::Malformed("ES256 missing y".into()))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(MultikeyError::Malformed(format!(
                    "ES256 coords wrong length: x={}, y={}",
                    x.len(),
                    y.len()
                )));
            }
            let mut compressed = Vec::with_capacity(33);
            let parity_prefix = if (y[31] & 1) == 0 { 0x02 } else { 0x03 };
            compressed.push(parity_prefix);
            compressed.extend_from_slice(&x);
            Ok((alg, encode_multikey(MULTICODEC_P256_PUB, &compressed)))
        }
        COSE_ALG_EDDSA => {
            let x = x.ok_or_else(|| MultikeyError::Malformed("EdDSA missing x".into()))?;
            if x.len() != 32 {
                return Err(MultikeyError::Malformed(format!(
                    "Ed25519 x wrong length: {}",
                    x.len()
                )));
            }
            Ok((alg, encode_multikey(MULTICODEC_ED25519_PUB, &x)))
        }
        other => Err(MultikeyError::UnsupportedAlg(other)),
    }
}

/// `multibase(base58btc, varint(multicodec) || key_bytes)`.
fn encode_multikey(multicodec: u64, key_bytes: &[u8]) -> String {
    let mut buf = encode_varint(multicodec);
    buf.extend_from_slice(key_bytes);
    multibase::encode(multibase::Base::Base58Btc, &buf)
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while value >= 0x80 {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-rolled COSE_Key for an Ed25519 public key with all-zero x.
    /// Tests that we read alg/x correctly and emit the right multicodec.
    #[test]
    fn ed25519_cose_to_multikey() {
        let cose = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1i64.into()),
                ciborium::value::Value::Integer(1i64.into()),
            ), // kty: OKP
            (
                ciborium::value::Value::Integer(3i64.into()),
                ciborium::value::Value::Integer((-8i64).into()),
            ), // alg: EdDSA
            (
                ciborium::value::Value::Integer((-1i64).into()),
                ciborium::value::Value::Integer(6i64.into()),
            ), // crv: Ed25519
            (
                ciborium::value::Value::Integer((-2i64).into()),
                ciborium::value::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cose, &mut bytes).unwrap();

        let (alg, mk) = cose_key_to_multikey(&bytes).unwrap();
        assert_eq!(alg, -8);
        // Expected: multibase("z") + base58btc(0xed 0x01 || 32 zero bytes)
        assert!(mk.starts_with('z'));
        // Decode and verify the multicodec prefix bytes are [0xed, 0x01].
        let (_base, decoded) = multibase::decode(&mk).unwrap();
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);
        assert_eq!(&decoded[2..], &[0u8; 32]);
    }

    #[test]
    fn p256_cose_to_multikey_even_y() {
        let cose = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1i64.into()),
                ciborium::value::Value::Integer(2i64.into()),
            ), // kty: EC2
            (
                ciborium::value::Value::Integer(3i64.into()),
                ciborium::value::Value::Integer((-7i64).into()),
            ), // alg: ES256
            (
                ciborium::value::Value::Integer((-1i64).into()),
                ciborium::value::Value::Integer(1i64.into()),
            ), // crv: P-256
            (
                ciborium::value::Value::Integer((-2i64).into()),
                ciborium::value::Value::Bytes(vec![0xAAu8; 32]),
            ),
            (
                ciborium::value::Value::Integer((-3i64).into()),
                ciborium::value::Value::Bytes({
                    let mut y = vec![0xBBu8; 32];
                    y[31] = 0x42; // even
                    y
                }),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cose, &mut bytes).unwrap();

        let (alg, mk) = cose_key_to_multikey(&bytes).unwrap();
        assert_eq!(alg, -7);
        let (_base, decoded) = multibase::decode(&mk).unwrap();
        // Expected varint of 0x1200 is [0x80, 0x24].
        assert_eq!(decoded[0], 0x80);
        assert_eq!(decoded[1], 0x24);
        // Even-y parity prefix.
        assert_eq!(decoded[2], 0x02);
        // X bytes follow.
        assert_eq!(&decoded[3..], &[0xAAu8; 32]);
    }

    #[test]
    fn p256_cose_to_multikey_odd_y() {
        let cose = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(3i64.into()),
                ciborium::value::Value::Integer((-7i64).into()),
            ),
            (
                ciborium::value::Value::Integer((-2i64).into()),
                ciborium::value::Value::Bytes(vec![0x11u8; 32]),
            ),
            (
                ciborium::value::Value::Integer((-3i64).into()),
                ciborium::value::Value::Bytes({
                    let mut y = vec![0x22u8; 32];
                    y[31] = 0x43; // odd
                    y
                }),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cose, &mut bytes).unwrap();

        let (_alg, mk) = cose_key_to_multikey(&bytes).unwrap();
        let (_base, decoded) = multibase::decode(&mk).unwrap();
        assert_eq!(decoded[2], 0x03, "odd y should produce 0x03 prefix");
    }

    #[test]
    fn rs256_rejected() {
        let cose = ciborium::value::Value::Map(vec![(
            ciborium::value::Value::Integer(3i64.into()),
            ciborium::value::Value::Integer((-257i64).into()),
        )]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cose, &mut bytes).unwrap();

        let err = cose_key_to_multikey(&bytes).unwrap_err();
        assert!(
            matches!(err, MultikeyError::UnsupportedAlg(-257)),
            "RS256 must be rejected (no multicodec): {err:?}"
        );
    }

    #[test]
    fn parse_auth_data_round_trip() {
        // Minimal authData with AT flag set, an Ed25519 COSE key.
        let cose = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1i64.into()),
                ciborium::value::Value::Integer(1i64.into()),
            ),
            (
                ciborium::value::Value::Integer(3i64.into()),
                ciborium::value::Value::Integer((-8i64).into()),
            ),
            (
                ciborium::value::Value::Integer((-1i64).into()),
                ciborium::value::Value::Integer(6i64.into()),
            ),
            (
                ciborium::value::Value::Integer((-2i64).into()),
                ciborium::value::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        let mut cose_bytes = Vec::new();
        ciborium::ser::into_writer(&cose, &mut cose_bytes).unwrap();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0x11u8; 32]); // rpIdHash
        auth_data.push(0x40); // flags: AT only
        auth_data.extend_from_slice(&[0u8; 4]); // signCount
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(&4u16.to_be_bytes()); // credIdLen=4
        auth_data.extend_from_slice(b"abcd"); // credId
        auth_data.extend_from_slice(&cose_bytes);

        let parsed = parse_auth_data_to_multikey(&auth_data).unwrap();
        assert_eq!(parsed.cose_algorithm, -8);
        assert_eq!(parsed.credential_id, b"abcd");
        assert_eq!(parsed.rp_id_hash, [0x11u8; 32]);
        assert!(parsed.multikey.starts_with('z'));
    }
}
