# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.10.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.9.0...vti-trust-task-server-v0.10.0) — 2026-11-12


### Added

- **vta-sdk**: ResolvedMethods declarations and the VTI-KEY-009 refusals ([#2672](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2672))

* feat(vta-sdk): resolvedMethods declarations and the VTI-KEY-009 refusals

  The VTI specification now admits did:webs as an optional, alpha method
  for a node's durable identity (dtgwg-vti-spec#121). A node acts as an
  identity of an optional method only toward a peer whose verified current
  DID document declares it resolves that method, in a top-level
  resolvedMethods member (VTI-KEY-008); otherwise it sends nothing and
  fails with methodNotDeclared. A party that cannot rely on material
  without resolving a method it does not resolve refuses it with
  unsupportedDidMethod (VTI-KEY-009).

  - vta_sdk::resolved_methods: the required methods, what this build
    resolves and declares, the lenient reader of a peer's declaration,
    require_declared (the sending-side rule) and declare (with the JSON-LD
    term VTI-KEY-008 fixes).
  - The VTA declares did:webs in every document it mints, and so do the
    built-in templates for the nodes this workspace runs (vtc-host,
    room-host, dtg-witness, ballot-box). Templates for software outside it
    declare nothing.
  - Receive side: a proof by a DID of a method this party does not resolve
    is refused as DiProofError::UnsupportedDidMethod before any resolver is
    asked, and answered proofInvalid with details.reason
    unsupportedDidMethod and the method (the VTA, the shared Trust Task
    spine, the VTC).
  - Typed errors end to end: AppError::{MethodNotDeclared,
    UnsupportedDidMethod}, VtaError::{MethodNotDeclared,
    UnsupportedDidMethod}, read back from a Trust Task rejection and a REST
    body. The spine's app_error_to_reject also gains the NoMatchingProtocol
    arm it lacked (it answered internalError).

  Not breaking: DiProofError, AppError and VtaError are non_exhaustive.
  The documents the VTA mints and the four templates gain resolvedMethods
  and a further @context entry, which a DID-document consumer ignores.

  The sending-side check at the outbound seams follows separately; no
  node's own identity can be did:webs yet.



### Fixed

- **vta**: A did:webs node acts toward any peer; withdraw the resolvedMethods gate (VTI-KEY-003, VTI-KEY-008) ([#2697](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2697))

* fix(vta,vtc)!: a did:webs node acts toward any peer; withdraw the resolvedMethods gate (VTI-KEY-003, VTI-KEY-008)

  Each party chooses its own identity method and still works with every
  other: a did:webs client talks to a did:webvh service, and a did:webs
  node reaches any peer. dtgwg-vti-spec#123 makes did:webs a required
  method every node resolves, with the key-role designation extension
  (VTI-KEY-003); a node never requires a peer to use a particular durable
  method (VTI-KEY-001); VTI-KEY-008, the resolvedMethods declaration gate,
  is withdrawn with its methodNotDeclared refusal; VTI-KEY-009 keeps only
  the receiving side.

- **vtc-service**: Keep no copy of a token-bearing response for redelivery ([#2677](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2677))

The Trust Task spine records each successful response so that a redelivery
  of the same document `id` gets the first result back. Responses carrying a
  bearer secret are left out of that record. That list had invite claim codes,
  invitations and the event-stream grant, but not session tokens. So a
  redelivered `auth/authenticate/0.3` or `auth/refresh/0.2` got the recorded
  tokens back without the handler running: no single-use challenge check, no
  refresh rotation or reuse detection, no audit row. The tokens also stayed in
  the record for the acceptance window.

  Now also unrecorded (a redelivery is answered `204`):
  - `auth/authenticate/0.3`, `auth/refresh/0.2` (access and refresh tokens)
  - `vtc/install/claim/finish/0.3`, `vtc/install/claim/passkey/finish/0.1`
    (setup session token)
  - `vtc/auth/recognise/0.3` (cross-community access token)
  - `backup/initiate-export/0.1`, `backup/initiate-import/0.1` (transport token)



## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-trust-task-server-v0.8.0...vti-trust-task-server-v0.9.0) — 2026-11-10


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


