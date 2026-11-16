//! libFuzzer target for
//! [`vtc_service::credentials::exchange::verify_oid4vci_proof`]: the OID4VCI
//! key-binding proof JWT a wallet sends to receive a credential. The compact
//! JWT split, header and claim decode, `typ`, the `did:key` in `kid` (Ed25519,
//! P-256 or secp256k1), the signature in that key's algorithm, `aud` and the
//! `iat` window all run on bytes from the requester.
//!
//! A fixed audience and clock keep the run deterministic. The invariant is
//! totality: every input verifies or is refused with a typed error, never a
//! panic.
//!
//! Seed corpus: `seeds/oid4vci-proof/`.
#![no_main]

use chrono::{DateTime, Utc};
use libfuzzer_sys::fuzz_target;
use vtc_service::credentials::exchange::verify_oid4vci_proof;

fuzz_target!(|data: &[u8]| {
    let Ok(proof) = std::str::from_utf8(data) else {
        return;
    };
    // 2026-01-01T00:00:00Z.
    let now: DateTime<Utc> = DateTime::from_timestamp(1_767_225_600, 0).expect("valid timestamp");
    let _ = verify_oid4vci_proof(proof, "did:web:vtc.example", now);
});
