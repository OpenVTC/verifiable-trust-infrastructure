//! libFuzzer target for the OID4VP `vp_token` envelope
//! ([`vtc_service::credentials::exchange::flatten_vp_token`]): a DCQL map of
//! query id to presentation (or array of them), or a bare compact string. Each
//! string entry is then taken through
//! [`vtc_service::credentials::exchange::parse_sd_jwt_presentation`], as the
//! verifier does before it checks signatures, so the fuzzer reaches the SD-JWT
//! parser through the shape a wallet actually sends.
//!
//! The invariant is totality: every input is flattened and parsed, or refused
//! with a typed error, never a panic.
//!
//! Seed corpus: `seeds/vp-token/`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vtc_service::credentials::exchange::{flatten_vp_token, parse_sd_jwt_presentation};

fuzz_target!(|data: &[u8]| {
    let Ok(vp_token) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let Ok(entries) = flatten_vp_token(&vp_token) else {
        return;
    };
    for entry in entries {
        if let Some(compact) = entry.as_str() {
            let _ = parse_sd_jwt_presentation(compact);
        }
    }
});
