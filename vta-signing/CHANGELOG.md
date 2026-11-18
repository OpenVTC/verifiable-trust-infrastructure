# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vta-signing-v0.1.0) — 2026-11-18


### Added

- **vta-signing**: A small signing library the VTA and its callers share ([#2745](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2745))

* feat(keys): keys/sign-jws/0.1 — a VTA-built compact JWS walled off to JWT types

  Add a `keys/sign-jws/0.1` Trust Task that produces a compact JWS (a JWT) over
  a caller-supplied JOSE header and claims set, signed by a stored key. Unlike
  `keys/sign/0.1` it is not a general signing oracle: the VTA assembles the
  `b64url(header).b64url(payload)` signing input itself and signs it under
  `SigningDomain::ProtocolDefined`, so the result verifies as a JWS rather than
  as a VTA opaque-signing payload.

  The task is walled off so it can never be pointed at producing a credential or
  issuer artifact:

  - the finalized protected header's `typ` must be on a small allow-list of JWT
    profiles (`JWT`, `at+jwt`, `oauth-id-jag+jwt`, `dpop+jwt`, `logout+jwt`);
    anything else — e.g. a Verifiable Credential media type — is refused before
    the key is touched;
  - the VTA, not the caller, sets `alg` from the key, so a caller cannot request
    a signature under an algorithm the key does not implement or mislabel one;
  - the payload must be a JSON object (a JWT claims set); raw bytes still go
    through the opaque oracle, not here.

  Authorized exactly as `keys/sign` is — per the key's context — so the same
  context separation that walls off a signer's identities applies. Added to the
  dispatch table with the spec's (none / none / actsAsSubject) class, and
  acknowledged in `UNSPECCED_DISPATCHED_URIS` pending an upstream spec in
  trustoverip/dtgwg-trust-tasks-tf (dispatched unvalidated like any
  unknown-schema task until then).

  Enables the Agent Gateway to delegate JWT signing (STS access tokens, ID-JAG)
  to the VTA while keeping the JWT-signing path structurally separate from
  credential signing.


