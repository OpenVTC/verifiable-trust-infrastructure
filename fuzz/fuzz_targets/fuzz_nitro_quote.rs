//! libFuzzer target for [`vta_sdk::attestation::parse_nitro_quote`] (issue
//! #449): the parse-only COSE_Sign1 + CBOR decode of an AWS Nitro attestation
//! quote, with no signature/chain/PCR/time checks. The invariant under test is
//! totality — no `&[u8]` may panic the decoder; every input either decodes to a
//! `ParsedNitroQuote` or returns a typed `NitroParseError`.
//!
//! Seed corpus: `seeds/nitro-quote/`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vta_sdk::attestation::parse_nitro_quote(data);
});
