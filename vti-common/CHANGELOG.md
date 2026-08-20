# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.12.2...vti-common-v0.13.0) — 2026-08-20


### Added

- **vta**: Dedup keyed Trust Tasks on an idempotency key ([#1011](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1011))

A client that retries a timed-out request is doing the right thing. The
  dangerous case is the one where the VTA processed it and only the reply
  was lost, because the retry then produces a second durable effect —
  `webvh/dids/create` being the sharp example, where auto-assigned paths
  mean the retry mints a *different* DID and the first stays published
  with nobody holding a reference to it.

  The existing `trust_tasks::replay` layer cannot catch that. It keys on
  `(actor, envelope-id)` and every SDK path mints a fresh `urn:uuid:` per
  attempt, so a genuine retry sails past it. Its own module docs name this
  work as the deliberate follow-up.

  ## Built on the store that was already here



### Fixed

- **tee**: Bootstrap 410 and vsock enotconn ([#1003](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1003))

* fix(tee): retry transient ENOTCONN on first vsock config-overlay read

  tokio-vsock can report a stream connected just before Nitro finishes the
  nonblocking handshake, so the very first read on a fresh vsock:5800
  connection to the parent config server can return ENOTCONN even though
  the parent is listening and ready. Retry only that specific transient
  error kind with a short delay; any other I/O error still fails closed
  immediately, and the existing overall READ_TIMEOUT deadline still
  bounds the whole fetch.

  Adds positive (retries ENOTCONN then succeeds) and negative (does not
  retry PermissionDenied) unit tests against the inner read loop.



## [0.12.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.12.1...vti-common-v0.12.2) — 2026-08-18


## [0.12.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.12.0...vti-common-v0.12.1) — 2026-08-17


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.41...vti-common-v0.12.0) — 2026-08-16


### Added

- **vta-vault**: Resolve mdoc issuers against configured IACA trust anchors ([#987](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/987))

Answers the one question mdoc asks differently from every other credential
  format here: which key do I trust to have issued this?

  Every other format names its issuer as a DID, so receiving resolves that DID
  and verifies against whatever comes back — the VTA holds no list and there is
  no operator step. An mdoc has no issuer DID. It carries an X.509 chain in the
  issuerAuth COSE unprotected header (x5chain, label 33): a Document Signer
  certificate issued by an IACA. Verifying it means the VTA must already hold the
  roots it accepts, which is a trust store, not a lookup.

  The decision taken is a configured set of IACA root certificates — how
  production EUDI verifiers work, and what Member State trusted lists (ETSI TS
  119 612) distribute. It keeps X.509 at the boundary: nothing below this module
  learns certificates exist, and receive_mdoc still takes a plain resolved key.

  Validation is scoped to what ISO 18013-5 Annex B actually specifies — a
  two-level IACA to Document Signer hierarchy, so no general RFC 5280 path
  building. Checks the leaf issuer DN against a configured anchor subject, the
  leaf signature against that anchor key, the leaf validity window, that the
  anchor is a CA (a DS certificate configured by mistake cannot become a root),
  and keyUsage.digitalSignature where present.

  Deliberately not checked, both documented in the module: revocation (CRL/OCSP
  needs egress and an unavailability policy — its own decision), and the ISO mDL
  EKU 1.0.18013.5.1.2, which the EUDI PID profile does not share, so enforcing it
  would reject valid PID credentials as what looks exactly like a trust failure.

  Fails closed. An empty anchor set is an error, not permissive — mdoc is the one
  format whose issuer is not a resolvable DID, so there is no safe default. The
  config field defaults to empty, so an existing config still loads and an upgrade
  neither breaks a deployment nor silently starts trusting mdocs.

  Anchors are inline PEM in [vault] rather than file paths: an enclave has no
  convenient filesystem, and inline values are covered by the effective-config
  digest boot attestation commits to, so a verifier can see which issuers a TEE
  VTA was trusting when it was attested.

  x509-parser takes the verify-aws feature rather than the default verify, which
  pulls ring — ring currently only reaches this workspace through a
  dev-dependency, while aws-lc-rs is already a real dependency. Same crypto, no
  new production tree.



## [0.11.41](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.40...vti-common-v0.11.41) — 2026-08-16


## [0.11.40](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.39...vti-common-v0.11.40) — 2026-08-14


## [0.11.39](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.38...vti-common-v0.11.39) — 2026-08-12


## [0.11.38](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.37...vti-common-v0.11.38) — 2026-08-12

