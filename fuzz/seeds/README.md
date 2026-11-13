# Fuzzing seed corpora

Valid, well-formed artifacts that seed the coverage-guided fuzzers (issue #439,
item 6). Coverage-guided fuzzers mutate *from* valid inputs — handing libFuzzer
a handful of real artifacts massively improves yield over starting from noise.

These are inputs, not expected outputs: each file is *a* valid example of its
kind. Point a target at its folder, after a scratch corpus so libFuzzer does not
write into the committed one:
`cargo +nightly fuzz run <target> corpus/<target> seeds/<dir>`.

## Layout

| Directory | Artifact | Target(s) |
|---|---|---|
| `sealed-transfer-armor/` | ASCII-armored `SealedBundle` (`.vta`) | `fuzz_sealed_transfer_armor` (`armor::decode`, `open_bundle_with_policy`) |
| `bootstrap-request/` | VP-framed `BootstrapRequest` JSON | `fuzz_bootstrap_request` (`BootstrapRequest::verify_value`) |
| `sd-jwt-presentation/` | Compact SD-JWT-VC presentation | `fuzz_sd_jwt_presentation` (`parse_sd_jwt_presentation`) |
| `vp-token/` | OID4VP `vp_token` (bare string + DCQL map) | `fuzz_vp_token` (`flatten_vp_token`, then `parse_sd_jwt_presentation` per entry) |
| `oid4vci-proof/` | OID4VCI key-binding proof JWT | `fuzz_oid4vci_proof` (`verify_oid4vci_proof`) |
| `nitro-quote/` | COSE_Sign1 AWS Nitro attestation quote (`.cose`) | `fuzz_nitro_quote`, `fuzz_nitro_verify` |

The credential-exchange entry points are the sync, IO-free cores in
`vtc-service/src/credentials/exchange/` (`verify.rs`: `parse_sd_jwt_presentation`,
`flatten_vp_token`; `issue.rs`: `verify_oid4vci_proof`), re-exported as
`vtc_service::credentials::exchange::*`; the bootstrap VP is
`vta-sdk/src/provision_integration/request.rs` (`BootstrapRequest::verify_value`);
sealed transfer is `vta_sdk::sealed_transfer`. All are reachable without a tokio
runtime or a DID resolver, so a libFuzzer harness drives them directly. The Nitro
targets drive `vta_sdk::attestation::{parse_nitro_quote, NitroVerifier::verify}`
(issue #449), likewise IO-free and runtime-free.

## Regenerating

The keys are freshly generated each run, so the exact bytes differ run-to-run —
that is fine; a seed need only be valid.

```bash
# sealed-transfer armor + bootstrap request
cargo run -p vta-sdk --example gen_fuzz_seeds \
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
