# vti-fuzz

Fuzz targets for the parsers that read bytes someone else wrote.

Not published, and not part of the workspace build — `cargo-fuzz` needs its own
manifest and a nightly toolchain, which is why this sits in a detached crate
rather than as a feature of the crates it exercises.

## What is worth fuzzing here

Every target aims at the same class of surface: **bytes parsed before anything
has authenticated them.** A panic there is reachable by anyone who can reach
the endpoint, a different kind of bug from one sitting behind an authorization
check.

| Target | Drives | Seeds |
|---|---|---|
| `fuzz_nitro_quote` | `vta_sdk::attestation::parse_nitro_quote` | `seeds/nitro-quote/` |
| `fuzz_nitro_verify` | `vta_sdk::attestation::NitroVerifier::verify` (fixed anchor + clock) | `seeds/nitro-quote/` |
| `fuzz_sealed_transfer_armor` | `vta_sdk::sealed_transfer::armor::decode`, then `open_bundle_with_policy` | `seeds/sealed-transfer-armor/` |
| `fuzz_bootstrap_request` | `vta_sdk::provision_integration::BootstrapRequest::verify_value` | `seeds/bootstrap-request/` |
| `fuzz_sd_jwt_presentation` | `vtc_service::credentials::exchange::parse_sd_jwt_presentation` | `seeds/sd-jwt-presentation/` |
| `fuzz_vp_token` | `flatten_vp_token`, then `parse_sd_jwt_presentation` per entry | `seeds/vp-token/` |
| `fuzz_oid4vci_proof` | `vtc_service::credentials::exchange::verify_oid4vci_proof` (fixed audience + clock) | `seeds/oid4vci-proof/` |

Each asserts totality: every input is accepted or refused with a typed error,
never a panic.

## Running

```sh
cp ../Cargo.lock Cargo.lock    # resolve from the workspace's lockfile, as CI does
cargo +nightly fuzz list
cargo +nightly fuzz build --release
# A scratch corpus first: libFuzzer writes new inputs into the FIRST directory.
cargo +nightly fuzz run --release <target> corpus/<target> seeds/<dir> -- -max_total_time=300
```

There is no committed lockfile (`.gitignore`): one would record this
workspace's own crate versions, which every release moves.

Crashes land in `artifacts/`. A reproducer is worth turning into an ordinary
unit test in the crate that owns the parser, so the case stays covered without
needing nightly.

## In CI

`.github/workflows/fuzz.yml` builds every target on a pull request that touches
`fuzz/`, `vta-sdk/` or `vtc-service/src/credentials/exchange/`, and every night
runs each one for five minutes over its seeds, uploading `artifacts/` when one
crashes. The nightly toolchain there is pinned to a date.

## Licence

Apache-2.0
