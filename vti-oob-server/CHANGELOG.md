# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-oob-server-v0.1.0...vti-oob-server-v0.2.0) — 2026-11-04


## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-oob-server-v0.1.0) — 2026-11-04


### Changed

- **vtc-service**: Wallet sign-in (auth/oob/*) as the vti-oob-server crate ([#2425](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2425))

* refactor(vtc-service): wallet sign-in (auth/oob/*) as the vti-oob-server crate

  The auth/oob key-grant flow (a wallet approving a browser's key K_b)
  moves out of vtc-service into a new workspace crate, so the VTN service
  can serve the same flow instead of a copy.

  The crate owns the request store and compare-and-set, the claim and
  decision clocks, the redeem long poll and its caps, the did:key precheck
  (T21), the carried-document checks (T7, T15) and the check order of
  request, claim, prove, respond, redeem and cancel. A host implements
  OobHost: records keyspace, DID, origin and name, step signer,
  carried-proof verifiers, accepted-id record, a per-audience gate at three
  fixed points, signingScope, audit, and redeem's completion. Audiences
  are the host's associated type, and the default is never stored or
  signed, so VTC rows and signatures are byte for byte unchanged. The
  generic half of delegated signing (scope match, exclusions, record,
  armed over the host's row and liveness) moves too.

  vtc-service keeps SessionAudience, the member and admin gates,
  PORTAL_SIGNING_SCOPE, the audit events, session and cookie minting, its
  delegation row, the session liveness check, and the DID-document checks.
  Behaviour is unchanged. Every existing test passes unmodified.


