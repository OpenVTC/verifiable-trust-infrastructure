# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-vtn-v0.1.0) — 2026-11-03


### Added

- **vti-vtn**: Listings and repudiations use the registered DTG predicates ([#2403](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2403))
- **vti-vtn**: The Verifiable Trust Network protocol as a workspace crate ([#2398](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2398))

* feat(vti-vtn): the Verifiable Trust Network protocol as a workspace crate

  The VTN protocol — listings, membership offers and acknowledgements,
  repudiation, the entry lifecycle, Bitstring Status Lists, the signed
  network index and DTG graph, directory search, role/group registration
  (servesRole / groupRegistered), signed broadcast envelopes and hop
  chains, and network room passes (VTI-VTN-001..063) — as a crate both
  sides use. vtc-service will act as a network member with it; the VTN
  service (OpenVTC/verifiable-trust-network) depends on it from crates.io,
  so dependencies run one way: the VTN repository on VTI, never the
  reverse.

  Moved from that repository's vtn-core and vtn-client, with one change:
  verification accepts a proof set, as a VTC holding an ML-DSA key
  alongside its Ed25519 one signs. Every proof must come from a key of the
  expected signer, for the expected purpose, and verify; at least one is
  required. dtg-credentials' DTGCredential carries a single proof, so the
  claims are parsed with the proof set split off.

  Feature `client` adds VtnClient (DID sign-in bound to the expected
  network DID), vtn-signin: links and a status-list StatusChecker.


