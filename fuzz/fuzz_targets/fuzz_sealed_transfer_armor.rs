//! libFuzzer target for the sealed-transfer armor decoder and bundle opener
//! ([`vta_sdk::sealed_transfer::armor::decode`],
//! [`vta_sdk::sealed_transfer::open_bundle_with_policy`]). An armored bundle is
//! pasted in by an operator from wherever it travelled, so it is decoded before
//! anything about it is authenticated: block framing, headers, base64, chunk
//! grouping by `Bundle-Id`, then the HPKE open of each chunk.
//!
//! The opener runs with a fixed recipient key the fuzzer cannot know, so the
//! AEAD rejects every mutated ciphertext; what it exercises is everything in
//! front of that (chunk ordering, sizes, digest comparison, header parse). The
//! invariant is totality: any input decodes or is refused with a typed error.
//!
//! Seed corpus: `seeds/sealed-transfer-armor/`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vta_sdk::sealed_transfer::{PinnedOnlyPolicy, armor, open_bundle_with_policy};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(bundles) = armor::decode(text) else {
        return;
    };
    let recipient = [7u8; 32];
    for bundle in &bundles {
        let _ = open_bundle_with_policy(
            &recipient,
            bundle,
            None,
            PinnedOnlyPolicy::CallerHasIndependentTrustAnchor,
        );
        let _ = open_bundle_with_policy(
            &recipient,
            bundle,
            Some("sha256:00"),
            PinnedOnlyPolicy::RequireOobDigest,
        );
    }
});
