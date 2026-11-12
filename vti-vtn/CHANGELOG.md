# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.10.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.10.0...vti-vtn-v0.10.1) — 2026-11-12


### Fixed

- **status-list**: Bound every size read from a fetched Bitstring Status List ([#2674](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2674))

* fix(status-list): bound every size read from a fetched Bitstring Status List

  A fetched BitstringStatusListCredential is someone else's document, and
  the VTC sized its decode from it: `credentialSubject.statusSize` was taken
  as the list length, unbounded, and handed to the decoder, which allocates
  in proportion. In W3C Bitstring Status List v1.0 `statusSize` is the bits
  per entry, on the BitstringStatusListEntry (§2.1), not a list length — so
  a list carrying the conformant `"statusSize": 1` was also read as a
  one-entry list and refused for any index past 0.

  vtc-service (`recognition::verify`, used by recognise, join presentation
  and invitation checks):
  - The bit is read by `read_status_bit`, which bounds everything before
    decoding: the index (at most 4,194,304 entries, checked before the fetch
    too), the `encodedList` length, and the decoded length, which is the
    larger of `index + 1` and the spec minimum of 131,072 entries. Nothing
    the list declares sizes a buffer.
  - A list shorter than 131,072 entries, or than the index, is refused
    (§3.2 steps 9 and 10).
  - `statusSize` on an entry, or on a list, must be 1: the reader supports
    only 1-bit entries, which §1.3 allows. Anything else is refused rather
    than read as one bit.
  - A multibase `u`-prefixed `encodedList` (§2.2) is now read.

  The same reads elsewhere:
  - vta-sdk `vetting::status`: `MAX_STATUS_LIST_BITS` is now 1 << 22 (was
    1 << 26), since the decoder allocates about a byte per entry read; an
    entry whose `statusSize` is not 1 reads as Unknown.
  - vta-vault `status`: the resolver-supplied list size and `encodedList`
    length are bounded before decoding, the index is checked against the
    size first, and an entry whose `statusSize` is not 1 is refused.
  - vti-vtn: `VtnClient::get_url` reads the body under a 2 MiB cap
    (`MAX_FETCHED_BODY`) instead of buffering it whole; `StatusChecker`
    refuses an index past the end of the list (it read as clear) and an
    entry whose `statusSize` is not 1. `Bitstring::len_bits` is new.

  Behaviour changes: entries declaring `statusSize` other than 1 are
  refused (status Unknown / error) everywhere; in vtc-service a list
  carrying `statusSize: 1` is now read in full, one carrying any other
  value is refused, and a list longer than 131,072 entries is read past
  that point (it used to be read only to the first 131,072); indexes past
  4,194,304 are refused in vtc-service and vta-sdk; vti-vtn's checker
  errors on an out-of-range index instead of reporting Valid.



## [0.10.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.9.0...vti-vtn-v0.10.0) — 2026-11-10


## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.8.0...vti-vtn-v0.9.0) — 2026-11-09


## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.7.0...vti-vtn-v0.8.0) — 2026-11-05


## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.6.0...vti-vtn-v0.7.0) — 2026-11-05


## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.5.0...vti-vtn-v0.6.0) — 2026-11-05


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.4.0...vti-vtn-v0.5.0) — 2026-11-04


## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.3.0...vti-vtn-v0.4.0) — 2026-11-04


### Added

- **vti-vtn**: Verify the network's proof on every Trust Task answer ([#2439](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2439))

A client accepts a #response only with the network DID's valid
  authentication proof (ClientError::Unverified otherwise), and sends no
  task without a resolver (VtnClient::verifying). New `resolve` feature:
  VmKeyResolver, the purpose-checking DID resolver the VTC, the VTN and
  the NNM share. The VTC verifies every network answer; an unverified one
  is a mismatch.



## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.2.0...vti-vtn-v0.3.0) — 2026-11-04


### Added

- **vtc-service**: Talk to networks over vtn/* Trust Tasks ([#2422](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2422))

The community's VTN client signs each request as the community (vtn/entries/show,
  vtn/membership/{offer,acknowledge,repudiate}, the signed vtn/groups/register
  request) instead of signing in and calling the REST routes the VTN removed.
  Answers are read as their generated #response types.



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vtn-v0.1.0...vti-vtn-v0.2.0) — 2026-11-03


### Added

- **vti-vtn**: Group registration is the signed vtn/groups/register request; A20 lifetimes ([#2416](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2416))

- groups::register_as signs a vtn/groups/register/0.1 request; verify_registration checks
    its type, issuer, recipient and authentication proof. servesRole/1 is retired.
  - groupRegistered binds registration_digest: JCS over the request including its proof.
  - Registered endpoints are https.
  - room_pass refuses a lifetime over 24h; relay::new_message and relay::verify refuse a
    broadcast lasting more than 7 days after sentAt.
  - request::{request_document, sign_request} move out of the client feature;
    vti_vtn::specs re-exports the vtn/* types.

- **vti-vtn**: The vtn/* Trust Task client ([#2413](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2413))


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


