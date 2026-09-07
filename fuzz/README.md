# vti-fuzz

Fuzz targets for the parsers that read bytes someone else wrote.

Not published, and not part of the workspace build — `cargo-fuzz` needs its own
manifest and a nightly toolchain, which is why this sits in a detached crate
rather than as a feature of the crates it exercises.

## What is worth fuzzing here

Both current targets — `fuzz_nitro_quote` and `fuzz_nitro_verify` — aim at the
same class of surface: **attestation bytes, parsed before anything has
authenticated them.**

That is the shape worth the effort. A Nitro quote arrives from whoever is
claiming to be an enclave, and it has to be decoded before it can be checked,
so a panic in the decoder is reachable by anyone who can reach the endpoint —
a different kind of bug from one sitting behind an authorization check.

## Running

```sh
cargo +nightly fuzz run <target>
cargo +nightly fuzz list      # what exists
```

Crashes land in `artifacts/`. A reproducer is worth turning into an ordinary
unit test in the crate that owns the parser, so the case stays covered without
needing nightly.

## Licence

Apache-2.0
