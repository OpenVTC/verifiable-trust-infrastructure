//! libFuzzer target for [`vta_sdk::provision_integration::BootstrapRequest::verify_value`]:
//! the VP-framed bootstrap request a would-be integration sends a VTA before it
//! holds any authority. The typed parse (`deny_unknown_fields`, the 0.1/0.2
//! `ask` casings), the structure checks, the holder `did:key` decode and the
//! Data Integrity proof over the JCS form all run on unauthenticated bytes.
//!
//! The invariant is totality: every input verifies or is refused with a typed
//! error, never a panic.
//!
//! Seed corpus: `seeds/bootstrap-request/`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vta_sdk::provision_integration::BootstrapRequest;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let _ = BootstrapRequest::verify_value(value);
});
