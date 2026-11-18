//! libFuzzer target for
//! [`vtc_service::credentials::exchange::parse_sd_jwt_presentation`]: the
//! structural parse of an SD-JWT-VC presentation (issuer JWS, disclosures,
//! holder `kb-jwt`, `iss`, `kid`, the `cnf.jwk` holder key on any of the three
//! curves) that runs before any signature is checked or any DID resolved.
//! A presentation reaches it from whoever is applying to join.
//!
//! The invariant is totality: every input parses or is refused with a typed
//! error, never a panic.
//!
//! Seed corpus: `seeds/sd-jwt-presentation/`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vtc_service::credentials::exchange::parse_sd_jwt_presentation;

fuzz_target!(|data: &[u8]| {
    if let Ok(compact) = std::str::from_utf8(data) {
        let _ = parse_sd_jwt_presentation(compact);
    }
});
