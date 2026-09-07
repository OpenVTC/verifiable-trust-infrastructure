# vti-rooms-dtg

The DTG-credential chain verifier for data rooms — the cryptographic half of
room authorization.

[`vti-rooms`](https://crates.io/crates/vti-rooms) decides whether a presentation
is *shaped* right, then asks a `ChainVerifier` whether it is *true*. This crate
is that verifier, over the DTG credentials the rooms design uses: a **VMC** for
membership and a chain of **VACs** for authority.

## Why it is a separate crate

`vti-rooms` depends on `vti-common` and nothing else, so a room host can reuse
its storage without dragging in a credential library and a DID resolver.
Verifying needs both.

Keeping them apart is what lets `vti-rooms` stay honest about the limit of what
it can answer on its own — a crate that could reach a verifier would eventually
be asked to, and the boundary between "well-formed" and "valid" would blur at
exactly the point where it matters.

## Status

Early. The API will change.

## Licence

Apache-2.0
