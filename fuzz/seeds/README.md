# Fuzzing seed corpora

Valid, well-formed artifacts that seed the coverage-guided fuzzers (issue #439,
item 6). Coverage-guided fuzzers mutate *from* valid inputs — handing libFuzzer
a handful of real artifacts massively improves yield over starting from noise.

These are inputs, not expected outputs: each file is *a* valid example of its
kind. The `fuzz/` cargo-fuzz workspace now lands alongside these seeds; point a
target at its matching folder with `cargo +nightly fuzz run <target> seeds/<dir>`
(or copy the files into `fuzz/corpus/<target>/`).

## Layout

| Directory | Artifact | Suggested target(s) |
|---|---|---|
| `sealed-transfer-armor/` | ASCII-armored `SealedBundle` (`.vta`) | `armor::decode`, sealed-bundle open/verify |
| `bootstrap-request/` | VP-framed `BootstrapRequest` JSON | `BootstrapRequest::verify` |
| `sd-jwt-presentation/` | Compact SD-JWT-VC presentation | `parse_sd_jwt_presentation` |
| `vp-token/` | OID4VP `vp_token` (bare string + DCQL map) | `flatten_vp_token` / `verify_vp_token` |
| `oid4vci-proof/` | OID4VCI key-binding proof JWT | `verify_oid4vci_proof` |
| `nitro-quote/` | COSE_Sign1 AWS Nitro attestation quote (`.cose`) | `fuzz_nitro_quote`, `fuzz_nitro_verify` |

The verify-path parser entry points are the sync, IO-free cores in
`vtc-service/src/credentials/exchange.rs` (`parse_sd_jwt_presentation`,
`flatten_vp_token`, `verify_oid4vci_proof`) and
`vta-sdk/src/provision_integration/request.rs`
(`BootstrapRequest::verify`) — all reachable without a tokio runtime or a DID
resolver, so a libFuzzer harness drives them directly. The Nitro targets drive
`vta_sdk::attestation::{parse_nitro_quote, NitroVerifier::verify}` (issue #449),
likewise IO-free and runtime-free.

## Regenerating

The keys are freshly generated each run, so the exact bytes differ run-to-run —
that is fine; a seed need only be valid.

```bash
# sealed-transfer armor + bootstrap request
cargo run --example gen_fuzz_seeds \
    --features sealed-transfer,provision-integration

# SD-JWT-VC presentation + vp_token shapes + OID4VCI proof
VTC_SKIP_ADMIN_UI_BUILD=1 cargo test -p vtc-service \
    --lib credentials::exchange::tests::gen_fuzz_seed_corpus -- --ignored

# Nitro attestation quote (synthetic, freshly signed each run)
cargo test -p vta-sdk --features attest-verify \
    attestation::test_quote::tests::gen_nitro_fuzz_seed -- --ignored
```

Both generators write here (`<workspace-root>/fuzz/seeds/`). The vta-sdk
generator accepts an alternate output directory as its first argument.
