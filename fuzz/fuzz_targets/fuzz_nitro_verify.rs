//! libFuzzer target for the full local Nitro verifier
//! ([`vta_sdk::attestation::NitroVerifier`], issue #449): the certificate-chain
//! walk + COSE_Sign1 signature check on top of the parse step. Driven with a
//! fixed trust anchor + clock so the run is deterministic. Garbage input is
//! expected to be *rejected*; the invariant is that it is rejected as a typed
//! error and never panics (no slice/index/unwrap blow-ups in the chain walk).
//!
//! Seed corpus: `seeds/nitro-quote/`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;
use vta_sdk::attestation::{NitroVerifier, TrustAnchor};

fuzz_target!(|data: &[u8]| {
    // Fixed instant (2023-11-14T22:13:20Z) so validity-window checks are
    // deterministic across runs.
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid timestamp");
    let verifier = NitroVerifier {
        anchor: TrustAnchor::AwsProduction,
        now,
    };
    let _ = verifier.verify(data);
});
