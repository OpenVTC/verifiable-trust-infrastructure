# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.7.0...vti-trust-task-server-v0.8.0) — 2026-11-09


## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.6.0...vti-trust-task-server-v0.7.0) — 2026-11-05


## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.5.0...vti-trust-task-server-v0.6.0) — 2026-11-05


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.4.0...vti-trust-task-server-v0.5.0) — 2026-11-05


## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.3.0...vti-trust-task-server-v0.4.0) — 2026-11-04


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.2.0...vti-trust-task-server-v0.3.0) — 2026-11-04


## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.1.1...vti-trust-task-server-v0.2.0) — 2026-11-04


### Added

- **trust-tasks**: Honour a stated expiresAt up to 30 days, and keep the replay record to the acceptance end (VTI-OPS-024, VTI-OPS-028, VTI-OPS-029) ([#2423](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2423))

trust-tasks-rs 0.37 (trustoverip/dtgwg-trust-tasks-tf #1021), with
  affinidi-tdk 0.37, affinidi-messaging-sdk 0.45 (affinidi-tdk-rs #983) and
  mediator 0.50 (affinidi-messaging-mediator #55), which move with it.

  Acceptance. A document that states an expiresAt is accepted until then, up to
  thirty days after its issuedAt, whatever the ten-minute maximum age
  (VTI-OPS-024, VTI-OPS-028). An expiry beyond the horizon is clamped, not
  refused. A document without one keeps the ten-minute window. The horizon is
  `vti_common::trust_task::acceptance::EXPIRY_HORIZON`, applied by
  `AcceptanceWindow::freshness_policy`, so every VTI consumer takes it.

  Retention. Every record of an accepted document was capped at
  issuedAt + max_age + skew, relying on the freshness check to refuse anything
  older. Under 0.37 that check accepts a document with a later expiresAt, so
  the record would be dropped while its document was still acceptable and a
  replay would execute twice. One rule now decides retention for every consumer,
  `vti_common::trust_task::acceptance::retain_until`: the acceptance end plus the
  skew (VTI-OPS-029), bounded by the horizon. It is used by the shared receive
  pipeline (VTA and VTC accepted-id records), the VTC's spent step-up approver
  statements, vti-witness and room-host.

  Behaviour change for producers: a document stating a long expiresAt is no
  longer refused as stale after ten minutes. Step-up approver statements are
  included, as VTI-OPS-028 requires of any document that states an expiry.

  Not here: idempotency records still live 24 hours although a keyed document
  can now be acceptable for 30 days (VTI-OPS-066, next step); room-host's replay
  record is still in memory and lost on restart (VTI-OPS-029).



## [0.1.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.1.0...vti-trust-task-server-v0.1.1) — 2026-11-03


### Added

- **vta-service**: The accepted-document-id record in the store, shared with the VTC (VTI-OPS-026, VTI-OPS-027) ([#2417](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2417))

The VTA kept its record of accepted document ids (SPEC §7.2 item 11) in a
  process-local InMemoryReplayGuard, so a document accepted before a restart
  executed again when replayed after it, still inside its acceptance window
  (VTI-OPS-026).

  The VTC's store-backed record moves into vti-trust-task-server as
  StoreAcceptedIds (with its sweep and tests) and the VTA adopts it over a new
  `accepted_ids` keyspace: encrypted, excluded from backup, Unrelated to DID
  deletion, swept on the storage thread's timer. Rows keep the `accepted:<id>`
  shape, so the VTC needs no migration. admit_carried_document now returns the
  claim it took, and the deposit handler settles it.

  Also fixes a document refused after its claim (schema, spec policy, proof,
  idempotency) keeping its id spent as in-flight: the corrected resend under
  the same id was answered 202 and never ran. The post-claim work is now
  dispatch_claimed, and the caller settles the claim on every outcome.

  Retention is unchanged (issuedAt + max_age + skew); it moves to expiresAt when
  the nodes adopt trust-tasks-rs 0.37.



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


