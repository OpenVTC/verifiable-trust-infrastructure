# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-trust-task-server-v0.1.0) — 2026-11-03


### Changed

- **vtc-service**: The Trust Task receive pipeline as the vti-trust-task-server crate ([#2410](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2410))

The spine a received Trust Task goes through (size, parse, freshness,
  expiry and recipient, the spec's own policy, proof bound to issuer, the
  DIDComm/TSP sender binding, admission, the duplicate-id record, dispatch,
  signed replies) moves out of vtc-service into a new workspace crate, so the
  VTN service can speak Trust Tasks with the same pipeline instead of a copy.

  Service concerns are injected as traits: SpecPolicySource, SizeGate,
  ProofVerifier (ResolverProofVerifier over a TrustTaskVmResolver),
  SpineHooks (recipient, before/after-proof gates), VerifiedAdmission,
  AcceptedIdStore (InMemoryAcceptedIds for tests), Dispatcher and
  ResponseSigner. The crate also owns TrustTaskOutcome, ArrivalCtx/Transport,
  the reject and response helpers, typed payload/response validation, and an
  axum POST /v1/trust-tasks handler. It depends on no service and no
  vti-specs-* crate.

  vtc-service keeps its fjall-backed accepted-id record, its known-issuer
  size gate and large-document budget, the oob/install/delegation/did:scid
  hooks, the parked-operation submission scope, ACL and step-up, and its own
  HTTPS route (admission, cookies, event streams). JoinAuthCtx and
  JoinTransport are now the crate's ArrivalCtx and Transport. Behaviour is
  unchanged: four generic helper tests moved into the new crate.


