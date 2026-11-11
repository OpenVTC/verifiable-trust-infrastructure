//! W3C Bitstring Status List v1.0: one list per purpose (`revocation`, `suspension`).
//!
//! Every credential the network issues gets one index, used in both lists. Removal sets
//! the revocation bit of every credential that evidenced the entry (VTI-VTN-053);
//! suspension sets the suspension bit of the grant.

use std::io::{Read, Write};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{Result, VtnError};
use crate::model::StatusIndex;

/// 16 KiB: the specification's minimum list size, for herd privacy.
pub const LIST_BITS: usize = 131_072;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    Revocation,
    Suspension,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Revocation => "revocation",
            Purpose::Suspension => "suspension",
        }
    }
}

/// A bitstring; bit 0 is the most significant bit of byte 0, as the spec defines.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Bitstring {
    bytes: Vec<u8>,
}

impl Default for Bitstring {
    fn default() -> Self {
        Self {
            bytes: vec![0; LIST_BITS / 8],
        }
    }
}

impl Bitstring {
    /// How many entries the bitstring holds.
    pub fn len_bits(&self) -> usize {
        self.bytes.len().saturating_mul(8)
    }

    /// The bit at `index`; an index past the end reads as clear. A reader of
    /// someone else's list uses [`Bitstring::len_bits`] first, since W3C
    /// Bitstring Status List v1.0 §3.2 step 10 makes such an index a
    /// RANGE_ERROR, not a clear bit.
    pub fn get(&self, index: StatusIndex) -> bool {
        let i = index as usize;
        self.bytes
            .get(i / 8)
            .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
    }

    pub fn set(&mut self, index: StatusIndex, value: bool) -> Result<()> {
        let i = index as usize;
        let byte = self.bytes.get_mut(i / 8).ok_or(VtnError::StatusListFull)?;
        if value {
            *byte |= 0x80 >> (i % 8);
        } else {
            *byte &= !(0x80 >> (i % 8));
        }
        Ok(())
    }

    /// `encodedList`: multibase base64url (`u`) of the GZIP-compressed bitstring.
    pub fn encode(&self) -> Result<String> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&self.bytes)
            .map_err(|e| VtnError::Internal(e.to_string()))?;
        let compressed = gz.finish().map_err(|e| VtnError::Internal(e.to_string()))?;
        Ok(format!("u{}", URL_SAFE_NO_PAD.encode(compressed)))
    }

    pub fn decode(encoded: &str) -> Result<Self> {
        let body = encoded
            .strip_prefix('u')
            .ok_or_else(|| VtnError::Rejected("encodedList is not multibase base64url".into()))?;
        let compressed = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|e| VtnError::Rejected(e.to_string()))?;
        let mut bytes = Vec::new();
        GzDecoder::new(&compressed[..])
            .take((LIST_BITS / 8 + 1) as u64 * 8)
            .read_to_end(&mut bytes)
            .map_err(|e| VtnError::Rejected(e.to_string()))?;
        // W3C Bitstring Status List v1.0 §3.2 step 9: "If the length of the
        // revocation bitstring divided by statusSize is less than
        // minimumNumberOfEntries, raise a STATUS_LIST_LENGTH_ERROR." Step 2 sets
        // minimumNumberOfEntries to 131,072.
        if bytes.len() < LIST_BITS / 8 {
            return Err(VtnError::Rejected(format!(
                "encodedList holds {} entries, fewer than the minimum of {LIST_BITS}",
                bytes.len() * 8
            )));
        }
        Ok(Self { bytes })
    }
}

/// URL of the status list credential for `purpose`, under the service's public base URL.
pub fn list_url(base_url: &str, purpose: Purpose) -> String {
    format!(
        "{}/v1/status/{}",
        base_url.trim_end_matches('/'),
        purpose.as_str()
    )
}

/// The `credentialStatus` value for a credential at `index`: one entry per purpose.
pub fn credential_status(base_url: &str, index: StatusIndex) -> Value {
    let entry = |purpose: Purpose| {
        let list = list_url(base_url, purpose);
        json!({
            "id": format!("{list}#{index}"),
            "type": "BitstringStatusListEntry",
            "statusPurpose": purpose.as_str(),
            "statusListIndex": index.to_string(),
            "statusListCredential": list,
        })
    };
    json!([entry(Purpose::Revocation), entry(Purpose::Suspension)])
}

/// The unsigned `BitstringStatusListCredential` for a list.
pub fn status_list_credential(
    issuer: &str,
    base_url: &str,
    purpose: Purpose,
    bits: &Bitstring,
    valid_from: DateTime<Utc>,
) -> Result<Value> {
    let url = list_url(base_url, purpose);
    Ok(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": url,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer,
        "validFrom": valid_from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "credentialSubject": {
            "id": format!("{url}#list"),
            "type": "BitstringStatusList",
            "statusPurpose": purpose.as_str(),
            "encodedList": bits.encode()?,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_and_round_trip() {
        let mut bits = Bitstring::default();
        bits.set(0, true).unwrap();
        bits.set(9, true).unwrap();
        bits.set(LIST_BITS as u32 - 1, true).unwrap();
        assert!(bits.set(LIST_BITS as u32, true).is_err());
        let decoded = Bitstring::decode(&bits.encode().unwrap()).unwrap();
        assert!(decoded.get(0) && decoded.get(9) && decoded.get(LIST_BITS as u32 - 1));
        assert!(!decoded.get(1));
        bits.set(9, false).unwrap();
        assert!(!bits.get(9));
    }

    #[test]
    fn decoding_reads_only_a_bounded_prefix_of_a_long_list() {
        // 4 MiB of zeros compresses to a few KiB; decoding stops at the cap.
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&vec![0u8; 4 << 20]).unwrap();
        let encoded = format!("u{}", URL_SAFE_NO_PAD.encode(gz.finish().unwrap()));
        let decoded = Bitstring::decode(&encoded).unwrap();
        assert_eq!(decoded.len_bits(), (LIST_BITS / 8 + 1) * 8 * 8);
        assert_eq!(Bitstring::default().len_bits(), LIST_BITS);
    }

    #[test]
    fn a_list_shorter_than_the_minimum_is_refused() {
        let encode = |len: usize| {
            let mut gz = GzEncoder::new(Vec::new(), Compression::default());
            gz.write_all(&vec![0u8; len]).unwrap();
            format!("u{}", URL_SAFE_NO_PAD.encode(gz.finish().unwrap()))
        };
        assert!(Bitstring::decode(&encode(LIST_BITS / 8 - 1)).is_err());
        assert!(Bitstring::decode(&encode(0)).is_err());
        assert_eq!(
            Bitstring::decode(&encode(LIST_BITS / 8))
                .unwrap()
                .len_bits(),
            LIST_BITS
        );
    }

    #[test]
    fn bit_order_is_msb_first() {
        let mut bits = Bitstring::default();
        bits.set(0, true).unwrap();
        assert_eq!(bits.bytes[0], 0x80);
    }
}
