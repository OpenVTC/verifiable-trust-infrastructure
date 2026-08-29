# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.32.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.32.1...vta-sdk-v0.32.2) — 2026-08-29


### Fixed

- **vta**: Answer provision/integration under the version the body was rendered in ([#1202](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1202))

#1147 made 0.3 the only provision-integration version the DIDComm router
  accepts, and #1200 moved the client dispatch sites onto it. The reply's
  *type URI* stayed behind. `result_uri_for` tested for one version and fell
  through:

      if request_uri == CANONICAL_PROVISION_INTEGRATION_0_2 {
          CANONICAL_PROVISION_INTEGRATION_0_2_RESULT
      } else {
          CANONICAL_PROVISION_INTEGRATION_RESULT   // 0.1, for everything else
      }

  so 0.3 — the only URI that can now reach the handler — took the `else` arm.
  `CANONICAL_PROVISION_INTEGRATION_0_3_RESULT` was declared and never read.

  Two lines apart in `handle_provision_integration`, the result URI comes from
  `result_uri_for` and the body from `response_body_for_version`. The body was
  rendered 0.3; the URI said 0.1. Every DIDComm provisioning reply went out as
  a `digestMultibase` body labelled `provision/integration/0.1#response` — a
  message that cannot satisfy the schema it names, because 0.1's response
  requires a bare-hex `digest` and closes with `additionalProperties: false`.
  `ProvisionIntegrationResponse` has carried `digest_multibase` and no `digest`
  since #1147, so under that label the reply was unserveable by construction.

  Nothing in this workspace noticed, because both halves were wrong the same
  way: `provision_integration/didcomm.rs` computes the reply type it waits for
  with the same `result_uri_for`, so the Rust client asked for `0.1#response`
  and the server sent `0.1#response` and they agreed. It takes an independent
  client to see it — the browser wallet reads the URI from the trust-tasks
  registry bindings, expects `0.3#response`, and rejects the reply. What the
  operator sees is a provisioning run that has fully succeeded — bundle sealed,
  admin rolled over, secret written — reported as a failure, with the whole
  successful response body quoted back inside the error. The holder discards a
  bundle the VTA has already committed to.

  `result_uri_for` now resolves through `ProvisionSpecVersion`, which grows the
  two halves a reverse map needs: `ALL`, and `from_request_uri` as a search over
  it rather than a hand-written second table. This is the same correction
  `is_v0_1` already carries — a predicate about one version has to name that
  version, because a fall-through arm silently claims every version nobody has
  written yet. An unrecognised URI resolves to `CURRENT`, which is what
  `response_body_for_version` renders it as, so the label and the body agree
  even on the branch the router cannot reach.

  The router now dispatches on `CURRENT.request_uri()` instead of the 0.3
  constant, so the URI it accepts, the URI the handler answers under, and the
  URI the clients send are one knob rather than three that have now twice been
  moved separately.

  Guards, at the level that can actually catch this: asserting
  `result_uri_for(0.3) == 0.3#response` alone would pin the symptom, so the new
  tests assert the rule over `ALL` — every version's result URI is its request
  URI plus `#response` (SPEC.md §4.4.1), and `result_uri_for` agrees with the
  version the request URI names. Both fail on the old implementation, naming
  V0_3. The test they replace asserted the fallback *was* 0.1 and called the
  branch "unreachable in production, the router only advertises 0.1 and 0.2" —
  true when written, false since #1147, and it pinned the defect in place.

  Also corrects three comments that outlived their subject: the enum doc stopped
  at 0.2, `response_body_for_version` still named the removed `digest`, and the
  handler still described a "legacy FPN URI" retired several releases ago.



## [0.32.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.32.0...vta-sdk-v0.32.1) — 2026-08-29


### Fixed

- **sdk**: Dispatch provision/integration 0.3 on every transport, not just REST ([#1200](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1200))

#1147 cut provision-integration over to 0.3 and removed 0.2 outright — 0.2
  requires a bare-hex `digest` and forbids the `digestMultibase` 0.3 requires, and
  both close their response with `additionalProperties: false`, so no single
  response satisfies the two. The server moved, the REST runner moved, and the
  response-parsing side moved. The other three dispatch sites did not:

  | site | asked for |
  |---|---|
  | `provision_client/runner_tsp` | `0.2` (trust-task spine) |
  | `provision_client/runner_didcomm` ×2 | `0.1` (DIDComm protocol message) |
  | `client/bootstrap` DIDComm arm | `0.1` |

  Each held its own literal, and each was correct on the day it was written — TSP
  and DIDComm genuinely addressed different versions of this operation before the
  cut-over collapsed them onto one URI. So nothing looked wrong, and nothing
  failed in CI: both halves were internally consistent. What shipped is a VTA that
  can only be provisioned over REST. Every TSP and DIDComm attempt returns

      trust task failed [unsupportedType]: unsupported type:
      https://trusttasks.org/spec/provision/integration/0.2

  against a VTA that is otherwise healthy — and it surfaces as a `PostAuthFailure`
  *after* auth succeeds, so the runner reports it as terminal and never falls back
  to the REST leg that would have worked. OpenVTC's setup wizard prefers TSP, so
  this is every fresh OpenVTC install.



## [0.32.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.31.1...vta-sdk-v0.32.0) — 2026-08-29


### Added

- **sdk**: Any DID that names a key may sign a Trust Task ([#1193](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1193))

A Trust Task proof could only be made by a `did:key`. That was never a policy
  anyone chose — it was the shape of two helpers, and it meant a provisioned
  integration could not dispatch any of the 210 proof-requiring Trust Tasks, over
  any transport, because every DID this workspace provisions is a `did:webvh`.

  The rule is now the obvious one: **any DID that can name a key may sign**. The
  DID method is not the authorization; resolving the verification method and
  checking the signature is. `did:key:z6Mk…#z6Mk…`,
  `did:webvh:<scid>:example.com:glenn#key-0` and `did:web:example.com#key-1` are
  all ordinary holders.

  What actually stood in the way:

  The signer took `(holder_did, private_key)` and *derived* the verification
  method as `<did>#<multibase>`. That derivation exists only for `did:key`, whose
  key is its identifier — a `did:webvh` document decides what its keys are
  called, so nothing can guess `#key-0`. A signer that takes only a DID
  structurally cannot serve any other method. `HolderKey` now carries the
  verification method; `HolderKey::from_did_key` keeps the derivation for the one
  method that has one, and refuses to invent one for the others.

  The verifier used `DidKeyResolver`, which refuses everything else.
  `TrustTaskVmResolver` resolves `did:key` locally and any other method through
  the configured DID cache, matching a proof's absolute `verificationMethod`
  against a document that may name it relatively. It is hoisted from the
  equivalent the VTC already had for credential verification.

  `ClientIdentity` gains `verification_method`, and `connect_didcomm_bundle{,_on}`
  build an identity from the bundle's own Ed25519 `SecretEntry` — whose `key_id`
  *is* the verification method the DID document publishes, so nothing is guessed.
  Those constructors passed `identity: None` deliberately; that reason is gone.

  Every verifying call site now takes a resolver: the VTA's dispatch spine, REST
  login, step-up and consent; the VTC's dispatch, REST login and relationships.
  Threading it is the half that makes the signer change real.

- **device**: Let a device correct its display name on the heartbeat ([#1191](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1191))

`displayName` was written exactly once, at registration, and nothing in the
  device family could change it. `device/register` is intentionally not
  idempotent — a binding hangs off the caller's ACL entry, one per DID, and a
  second claim is refused with `device/register:alreadyRegistered` — so a
  renamed machine, or an install moved to another profile, kept announcing a
  name that no longer identified it. The spec is explicit that `displayName`
  exists "to help a human pick their own laptop out of a list", which is the
  thing that degrades.

  Heartbeat is where the spec already puts metadata drift: `platform` is
  defined there as "updated platform descriptor if it changed since
  registration". `ext` is the slot it provides for the rest, so a device now
  sends `org.openvtc.device-name: { displayName }` and the VTA applies it.

  Nothing about the register refusal moves. The binding, its `deviceId` and
  its `registeredAt` are untouched, no new binding can be claimed this way,
  and the entry `version` does not bump: a rename is metadata, and the spec
  forbids `displayName` being used as a security input by anything that
  renders it, so no policy decision can turn on it. The entry is fetched by
  `auth.did`, so a device can only correct the binding it authenticated as.

  A malformed extension is **ignored, not rejected**. A heartbeat's real job
  is refreshing `lastSeenAt`, and failing the call over a bad name would make
  a device with a client-side bug look offline — the more expensive error,
  because it is the one that sends an operator after a machine that is running
  fine. The 1..=128 bound the untyped `ext` slot cannot inherit from the
  register schema is enforced here instead.

  The extension key is defined once, in the SDK that produces it, and imported
  by the service that honours it — the two sides otherwise agree by string,
  and a typo on either would be a rename that silently never happens.

  `device_heartbeat_named` is a new method rather than a wider
  `device_heartbeat`: this crate is consumed across repositories, and
  widening a public signature would spend a breaking release on a diagnostic
  field. The new `ext` member on `DeviceHeartbeatBody` is still a public-field
  addition, so this is a **minor** for `vta-sdk`, not a patch — nothing in the
  workspace or in OpenVTC constructs that struct, but the semver report will
  name it and the release should follow it.

  A VTA that does not understand the extension ignores it (SPEC §4.5.1): the
  heartbeat still refreshes liveness and the name stays as it was.



### Fixed

- **sdk**: Stop rewriting the envelope a Trust Task proof covers ([#1192](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1192))

An operator running `pnm contexts create` against a production VTA got:

      Protocol error: trust task failed [proofRequired]: proof required but
      not present

  That is `SpecPolicy::enforce` on the VTA's dispatch spine refusing a document
  whose specification declares `proof` REQUIRED (SPEC §7.2 item 7a).

  The cause is the one #1184 fixed: `didcomm_transport` and `tsp_transport` built
  every client with `identity: None`, so `build_task_document` set no `issuer` or
  `recipient` and `signed_task_document` attached no proof. What is new here is
  why it reported itself as `proofRequired` rather than the `malformedRequest:
  … no in-band recipient` #1184's changelog describes. `address_trust_task`
  back-fills both members on the TSP paths, which satisfies item 5b — so a TSP
  document sails past the recipient check and lands on the proof check instead.
  Same defect, two names, depending on transport.

  It is released in vta-sdk 0.31.1; pnm-cli 0.14.0 was cut against 0.31.0 and has
  not been re-released, so an installed binary still carries it. Rebuilding, or
  `--transport rest`, is the operator's way out.

  Three things this changes.

  `address_trust_task` no longer assigns `issuer` and `recipient`
  unconditionally. A Data-Integrity proof covers every member but `proof`, so
  writing either one *after* signing turns a valid signature into `proofInvalid`
  at the far end — a failure that names the proof and says nothing about the
  rewrite that caused it. The values come from the same triple the identity was
  built from, so the assignment was a no-op; "it happens to be equal" is not
  something the next constructor has to keep true, and nothing was checking. It
  now fills only an absent member and refuses a disagreement, since neither
  answer is safe: honouring the transport breaks the proof, honouring the
  document sends it somewhere the caller did not ask for.

  A new test builds the document the SDK actually sends and runs it through
  `schema_index::spec_policy_for(uri).enforce(..)` — the same call the VTA makes.
  The existing tests checked `issuer`, `recipient` and `proof` by name and
  passed, because they were written from the same understanding as the code.
  Asserting against the registry means a new flag starts being checked without
  the test being edited. It covers a mutation and a read deliberately: the proof
  flag falls almost exactly along that line, so a client that only ever listed
  saw nothing wrong.

  The rationale on `signed_task_document` said "72 of the 109" specs require a
  proof. It is 210 of 344 in trust-tasks-rs 0.17 — and the number that actually
  justifies the hard error is `recipient`, which 343 of 344 require.

  `docs/05-design-notes/trust-task-envelope-conformance.md` records the
  diagnosis and the two instances of the same root cause still live on main: a
  `did:webvh` bundle holder cannot sign at all, because `trust_task_sign` refuses
  a non-`did:key` holder — so a provisioned integration cannot dispatch any of
  the 210 proof-requiring tasks; and `VtaClient::new` + `set_token_async` carries
  no identity, which is the documented `url + token` rung of the `AgentConnect`
  ladder. Neither is fixed here: the first needs a decision about how a
  `did:webvh` integration signs.

  Verified with `cargo fmt --all --check`, `cargo check --workspace
  --all-targets`, `cargo clippy --workspace --all-targets -- -D warnings`, and
  `cargo test -p vta-sdk` (298 passing).



## [0.31.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.31.0...vta-sdk-v0.31.1) — 2026-08-28


### Fixed

- **sdk**: Carry the client identity on DIDComm and TSP clients ([#1184](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1184))

`didcomm_transport` and `tsp_transport` built every client with
  `identity: None`, so `build_task_document` set neither `issuer` nor
  `recipient` and `signed_task_document` attached no proof. A conforming
  VTA rejects that with `malformedRequest`:

      specification declares recipient REQUIRED but the document carries
      no in-band recipient

  which is what `integration::startup` hits on its first call after
  connecting over the DIDComm tier. The failure surfaces from
  `fetch_did_secrets_bundle`, past the transport fallback, so
  `TransportPreference::Auto` never downgrades to the REST tier — whose
  `from_credential` constructor is the only one that already set an
  identity.

  Both transport constructors now take the identity as a required
  argument, fed from the `did:key` triple their public `connect_*` callers
  already hold, so the next variant cannot forget it. The bundle
  constructors pass `None` deliberately: their holder is a `did:webvh` and
  `trust_task_sign` signs for `did:key` holders only.

  The guard meant to catch exactly this was gated on `has_token()`, which
  is false by construction for DIDComm and TSP — it covered the one
  transport whose constructor was already correct. It now fires for any
  identity-less client, so the fault is reported locally, and named, in
  place of a wire-level `malformedRequest` that reads like a payload bug.



## [0.31.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.30.0...vta-sdk-v0.31.0) — 2026-08-28


### Added

- **credentials**: Move vta/credentials/issue to 0.2 ([#1159](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1159))

The last family behind its latest published spec. Checked against
  `website/registry.json` rather than the schema files on disk: every other
  implemented family is already on the newest published version.

  0.1 and 0.2 have identical payloads. The response differs only in how it is
  written — 0.2 composes it from `credentials/_shared/0.2`'s
  `IssuedCredentialBase` instead of restating the members inline, which is
  what stops the two drifting. The composition brings one new member,
  `issuedAt`.

  That member costs nothing to fill: `IssuedCredentialRecord` has carried
  `issued_at` since the family existed, and 0.1 simply had nowhere to put it,
  so the value was being computed, stored, and then dropped on the way out.
  It stays `Option` on our side because the shared definition declares it
  optional — a response without it is schema-valid and must still
  deserialize — but the VTA always sends it.

  The conformance sweep caught something on the way through, which is what it
  is for. Its drifted-witness check asserts the generated type rejects an
  unknown member, and 0.2's response type does not: closing a composed object
  requires `unevaluatedProperties` (`additionalProperties` is evaluated
  per-subschema and would reject the `allOf`-supplied members), and
  trust-tasks-codegen maps only `additionalProperties: false` onto
  `deny_unknown_fields`. So the generated struct is permissive where 0.1's
  was strict.

  The wire is unaffected — the schema itself is strict, so `validate_payload`
  still rejects the member. What is lost is the type-level guard, which makes
  the drifted-witness check pass vacuously. Recorded in
  `PERMISSIVE_GENERATED_TYPE` with its reason and skipped rather than left to
  give false assurance. The fix belongs in the codegen; deleting the entry
  re-arms the check.



## [0.29.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.28.0...vta-sdk-v0.29.0) — 2026-08-26


### Added

- **sdk**: Extract the agent-side connect ladder into vta_sdk::agent_connect ([#1081](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1081))

* feat(sdk): extract the agent-side connect ladder into vta_sdk::agent_connect

  Every tool that runs beside a user and talks to their VTA on their behalf
  needs the same four ways in — did:webvh bundle, scoped did:key, bearer
  token, existing pnm session — in the same order, with the same fail-fast
  rules. That ladder existed only inside vta-mcp's main.rs, so the next
  bridge had to copy 110 lines or invent a fifth way in.

  `AgentConnect` is that ladder as SDK surface. `mode()` resolves the rung
  with no I/O, so a bridge can log it (and refuse a rung it does not
  support) before connecting; `connect()` returns the authenticated
  VtaClient. Session mode keeps TransportChoice::Auto, so it inherits the
  workspace preference order (TSP > DIDComm > REST) from what both DID
  documents advertise.

  Two rules are enforced rather than documented, both carried over from the
  vta-mcp original: the two DIDComm identity modes are mutually exclusive,
  and a half-configured rung errors naming the missing fields instead of
  falling through to session mode — a bridge silently authenticating as the
  operator rather than as its scoped agent identity is the failure that
  matters here. ConnectMode::is_dedicated_agent() makes the same
  distinction available to callers deciding whether to enroll as a device.

  vta-mcp is refactored onto it, which is what proves the extraction: its
  build_client is now a pure args -> AgentConnect mapping plus a connect,
  and its tests assert which rung a set of flags selects.

- **vtc**: Tell a member when the community removes them ([#1060](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1060))

Removal was the most consequential thing a community does to a member and the
  one it delivered with the least information — none. There was no outbound
  message on any removal path. The only signal a removed member could observe was
  a side effect: the revocation bit on their membership credential flipping. They
  inferred their own removal from a status list and learned nothing about why.

  `vtc/members/removal-notice/0.1` (published upstream as
  trustoverip/dtgwg-trust-tasks-tf#256) now goes out from both admin paths,
  carrying the deciding administrator, the moment the decision took effect, the
  resolved disposition, and the operator's reason.

  **Signed, because the recipient is not the audience.** Authcrypt already proves
  the sender to the member. But this is the one member-facing message whose value
  lies in showing it to somebody else — an appeal, a dispute, another community
  weighing a rejected applicant. Forwarded, an unsigned notice is an assertion
  anyone could have written. So it is a Trust Task document with a Data Integrity
  proof, packed in the trust-task envelope — note `TRUST_TASK_ENVELOPE_TYPE`, not
  the task URI, which is a mistake this workspace has made before and which a
  conformant peer rejects silently.

  **Thirty days, because there is no second route.** `resolve_auth_role` refuses
  any DID without an ACL row and removal hard-deletes it, so a removed member
  cannot authenticate at all: every authenticated route, including any poll that
  might have served the notice, closes at the moment the removal lands. The act
  this reports is the act that ends their ability to ask about it. `send_to_member`
  already had a durable outbox, so this needed a deadline parameter rather than
  new machinery — `send_to_member_by`, with the six existing callers keeping the
  24h default.

  A member offline beyond the window still never learns. No window fixes that; the
  honest fix is a retrieval path not gated on an ACL row, which is a larger design
  than this. Stated in the spec and in the constant's doc comment rather than left
  for someone to discover.

  **Never for a self-leave.** `remove_inner` serves both the admin path and the
  DIDComm self-leave. A member who chose to leave already has their receipt, and
  telling them they were "removed" is a different and worse thing to be told.

  **Best-effort.** The notice never fails the removal. That has already happened
  and is durable; refusing the operator's request because the notice could not be
  *queued* would leave the member removed and the operator believing they were
  not. Failures log loudly — and log "queued", not "sent", because a DIDComm `Ok`
  means the mediator accepted the frame and nothing more (R1.1).

  Seven tests. Four unit: payload shape, a blank reason omitted rather than sent
  as an empty string, the two codes distinguishable, and the payload validated
  against the *published* schema — the check that catches the implementation
  drifting from the spec it claims to implement.

  Three end-to-end over a real mediator, because only a peer holding the document
  demonstrates the feature: an admin removal arrives signed with its reason and
  deciding admin, a purge says it was a purge, and a self-leave sends nothing. Two
  of them first failed on `no active removal policy`, which was the paths
  differing exactly as specified — a purge deliberately skips the removal policy,
  which is why that one passed before the fixture seeded any.

- **app-state**: A third store for versioned, namespaced application state ([#1051](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1051))

Applications built on a VTA have had nowhere to keep versioned metadata.
  Adds `vta/app-state/{get,put,list,delete,get-many,put-many}/1.0` — a store
  beside the secrets vault and the credential vault, for JSON an application
  owns and the VTA does not interpret.

  Records are addressed `(contextId, namespace, key)`. The namespace scopes one
  application so several tools can share a context without colliding, and is the
  seam a per-namespace grant would later use — which is why it is part of the
  address rather than a prefix convention on the key. In 1.0 a namespace is
  collision avoidance and NOT a trust boundary: an application with write access
  to a context reaches every namespace in it, and the `put` and `delete` specs
  say so normatively. Isolation means separate contexts.

  Deliberately not built on `vta/memory/*`. `MemoryItem` is `{key, value}` with
  nothing to hang a precondition on, and its `list` returns the whole context —
  but the argument that settles it is that "forget everything" has to stay a safe
  thing to ask an agent, which it cannot be if account state lives there.

  Three properties are why this is a store rather than a field on an existing one.

  **One counter per `(contextId, namespace)`, not per record.** A record's
  `version` is the counter value its most recent write took, so one number is
  simultaneously the optimistic-concurrency token `expectedVersion` compares
  against and the watermark `sinceVersion` compares against. A per-record counter
  serves the first but cannot serve the second — two records' counters are not
  comparable, so no single number means "everything after this point" — and would
  have forced a second sequence kept consistent by hand. The cost is that a
  record's version jumps by whatever its neighbours consumed, which the wire
  contract states: versions are opaque and monotonic, never an edit count.

  **A failed precondition returns the current version AND value.** A bare
  rejection obliges a re-read, and the re-read races the next write; the pattern
  has no fixed point under contention. Returning the winner's view removes the
  race rather than narrowing it, and the spec makes it normative.

  **Delete leaves a versioned tombstone, and the tombstones are reaped.** Without
  one, a consumer pulling from a watermark learns of every create and update and
  never of a deletion, so deleted records resurrect on its next rebuild.
  Retention is `app_state.tombstone_retention_days` (default 30, matching the
  vault's `grace_days`) — a destructive window is an operator's choice, not a
  constant — and `list` advertises the configured value, since a consumer
  schedules against that number. The sweeper runs from the storage thread beside
  the ACL/consent/vault sweepers.

  The sweeper reaps a *prefix*, not a set: each namespace walks its tombstones in
  version order and stops at the first still inside the window. Reaping a later
  tombstone while leaving an earlier one would make the reap watermark
  unstateable — no single number would describe what survives, which is precisely
  what `watermarkTooOld` has to be able to say. `0` days disables reaping, and
  that is enforced at the call site rather than as a zero cutoff, which would mean
  the opposite.

  Version reservation is fsynced and re-seals the TEE integrity manifest, for the
  reason `vti_common::store::counter` gives for BIP-32 counters: a counter
  surviving only in the journal buffer can be re-derived after a crash and reissue
  a used value. Here a reused version means two records collide on one `appv:`
  index key, so one disappears from the change feed and every incremental consumer
  misses that change permanently, silently. A batch reserves a block and pays one
  fsync rather than N; writes that then fail leave gaps, which are safe and
  tested.

  Retry safety: reads are `ReadOnly`, `delete` is `RetrySafe` (a second delete
  finds a tombstone and deliberately takes no new version, so a watcher sees
  nothing), and `put`/`put-many` are `Keyed` — a `put` without `expectedVersion`
  does not converge, and the class is per URI, not per payload.

  Blobs are deliberately out of scope in 1.0; adding a `blobRef` is additive.

  Concurrency is a process-local lock per namespace, not a store-layer
  compare-and-swap. fjall takes an exclusive database lock so two processes cannot
  share a store, and the vsock protocol has no atomic opcode — its
  `insert_if_absent`/`swap` are already non-atomic fallbacks. A CAS today would be
  atomic exactly where the lock suffices and a warn-and-fallback exactly where it
  would need to be real. Recorded in the design note with what would change that.

  Schemas published upstream as trustoverip/dtgwg-trust-tasks-tf#252 and #253;
  this depends on the released trust-tasks-rs 0.11.2, pinned to a minimum patch so
  an older resolve fails as a stale dependency rather than as unspecced URIs.
  Conformance witnesses cover all six URIs, so nothing enters
  `UNSPECCED_DISPATCHED_URIS`.



### Changed

- Delete the Verifiable-prefixed credential tags that were never DTG types ([#1071](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1071))

`VerifiableMembershipCredential` and `VerifiableEndorsementCredential` are not
  DTG credential types and never were. The specification defines seven concrete
  subtypes; neither is among them, and nothing in this stack has ever issued
  either. They survived as a name, a pair of literals and a compatibility shim,
  and between them they broke cross-community recognition for every real
  presentation ([#1062](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1062)).

  Four places, one cause.

  **The SDK constant.** `VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE` held the value
  `"MembershipCredential"`, with a doc comment explaining that the prefix in the
  name was historical and the tag did not have it. A constant whose name
  disagrees with its value is an invitation, and it was taken: someone reading
  the name hand-rolled `"VerifiableEndorsementCredential"` into the recognition
  path, where it matched nothing. Renamed to `MEMBERSHIP_CREDENTIAL_TYPE`, and
  `ENDORSEMENT_CREDENTIAL_TYPE` added beside it so the VEC tag has a home rather
  than being a literal at the point of use.

  **The compatibility shim.** #1063 added `LEGACY_TYPE_TAGS`, accepting both
  prefixed tags from peers predating the catalog adoption. Nothing is published,
  so no such peer exists — and a reference implementation that accepts a type the
  specification does not define reintroduces exactly the drift the function it
  sits in was written to prevent. Removed; the test that pinned the behaviour now
  pins its refusal.

  **The audit trail.** Emitted envelopes recorded `credential_type:
  "VerifiableMembershipCredential"` / `"VerifiableEndorsementCredential"` — tags
  no credential ever carried, in the one record meant to be authoritative after
  the fact. They now record what was issued.

  **The policy input.** `issuer_member` / `subject_member` were carried alongside
  `issuer` / `subject` for operator policies written against the pre-#1061 shape.
  There are no deployed operator policies to preserve, and two spellings of one
  concept is how the concept drifts. The duplicates are gone and the surviving
  fields carry `is_current`.



### Fixed

- **vta**: Three of the four responses the conformance layer found ([#1114](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1114))

Closes three of the four violations #1113 reported. The fourth is the vault
  pair, blocked on trust-tasks-rs 0.11.16 (dtgwg-trust-tasks-tf#268).

  `vta/webvh/dids/get/1.0` carried its record under `#[serde(flatten)]` since
  #849, to make the folded task a strict superset of the two shapes it replaced.
  That superset was readable by no conforming client: the response is
  `additionalProperties: false`, so a flattened record fails on all eleven
  members and the `ext` slot is unreachable. Its sibling settles which side
  moves — `dids/list` carries the same component nested under `dids` and has
  always conformed, so flattening made `get` the outlier in its own family.

  Both SDK client methods decoded the flat shape straight into
  `WebvhDidRecord`, so the workspace compiled clean while the wire broke. They
  now project the envelope. `webvh_get_did_round_trips_after_the_get_log_fold`
  predicted exactly this in its doc comment and caught it.

  `provision/integration/0.2` sent `null` for `adminTemplateName` and
  `webvhServerId`, the only two of five `Option<String>` members without
  `skip_serializing_if`.

- **vtc**: A null the schema forbids, and three fixtures that lied ([#1099](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1099))

Four entries close, and three of the four closed because the **ledger was
  wrong**, not because anything about the service changed. Drift **15 → 12**,
  with `join-requests/submit` narrowed from both sides to response-only.

  Found by making the conformance probe print the *actual* parse error for
  every drift entry rather than re-reading the notes — the same technique that
  surfaced the #1098 defect. The notes are prose and can be wrong in either
  direction; the schemas cannot.

  ## One real bug: a `null` where the schema says `object`

  `JoinRequest.policyDecision` is `Option<JsonValue>` with `#[serde(default)]`
  and no `skip_serializing_if`, so it went out as `"policyDecision": null` on
  every row that had no policy decision — which is every row in Phase 1.

  The component types it **`object`**, not `["object", "null"]` as it types the
  neighbouring `vpClaims` and `decision`. It is not required, so *absent* is
  how you say "no policy decision"; `null` is a type error. Now omitted.

  `JoinRequestSubmitBody.extensions` in `vta-sdk` had the identical shape — a
  bare `#[serde(default)]` `JsonValue` serialising `Value::Null` against a
  schema that types it `object`, so a minimal client's submit was
  non-conformant. The existing note had diagnosed this exactly and called it "a
  one-line fix in vta-sdk"; this is that line.

  Both are the null-into-`Option` class that shipped `keys/create/0.1` broken.

  ## Three fixtures that lied

  **`totalEstimate` was invented.** The `paginated()` helper hand-wrote
  `"totalEstimate": 12`. Nothing in the workspace ever sets `total_estimate` to
  `Some` — it is `skip_serializing_if = "Option::is_none"` and every producer
  passes `None`, so it has never reached the wire. The fixture made
  `endorsement-types/list` look non-conformant against a schema that simply
  does not define the member.

  **`endorsement-types/list`'s note blamed `createdByDid`**, which has been
  defined upstream since 0.11.8. The real error was the invented
  `totalEstimate`. Entry now `checked!`.

  **`community/profile/*`'s notes over-claimed.** `show` listed
  `relationshipIdentifierDefault` among its unspecced members — defined as of
  0.11.8. `update` claimed `fieldsChanged` was a divergence; the response
  schema defines it. That one is worth naming precisely, because it is a trap
  in how the probe reads: **a serde parse stops at the first unknown member and
  never reaches the rest**, so everything a note lists after the first is
  inference, not evidence. Both notes now say only what the schema actually
  refuses.

  ## What the remaining twelve are

  With the notes corrected, the residue is short and honest:

  - `communityDid` / `createdAt` on `CommunityProfile` — 2 entries, one change
  - `credential` / `expiresAt` not on the stored endorsement row — 2 entries,
    a storage decision (see #1098)
  - `factsTemplate`, `etag`, `deployedAt`/`sizeBytes`, the diagnostics
    transport half — 4 entries, service ahead of spec
  - `auth/recognise`, `install/claim/start`, `install/claim/finish`,
    `join-requests/submit` — 4 entries, genuine design questions

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace --no-fail-fast` — the whole workspace, since this
    touches `vta-sdk`
  - `cargo fmt --all --check`

- **sdk**: Look for pnm sessions where pnm actually writes them ([#1087](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1087))
- **mcp**: Look the pnm session up under the key pnm actually writes ([#1083](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1083))

`vta-mcp --vta <slug>` — the invocation its own README documents — could
  never find a session. `pnm` stores every login under the keyring key
  `vta:<slug>` (`vta_keyring_key`, pnm-cli/src/config.rs), `cnm` uses
  `community:<slug>` for the same reason, and neither session backend adds
  a prefix on the way in or out. vta-mcp passed the bare slug, so the
  lookup missed and the operator was told they were not authenticated.

  That failure mode is worth naming: from the operator's side it is
  indistinguishable from an expired login. They run `pnm auth status`, are
  told they are fine, and are none the wiser.

  The rule now has one definition, `agent_connect::pnm_session_key`, next
  to the connect ladder both agent-side bridges share — a second consumer
  (the agent-memory service) hit exactly this. It is idempotent, so an
  operator who worked the bug out and passes `vta:mine` keeps working.

- **vtc**: Tell a rejected applicant why, on the one path built to recover it ([#1058](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1058))

`project_status` projected `needs` / `presentationDefinition` for a
  `Deferred` request and bare `{requestId, status}` for a `Rejected` one.
  The evidence existed on both rejection paths and neither reached the
  applicant through the poll.

  The correlated `VerdictResponse` was the only place a `{code, reason}`
  ever reached an applicant, which makes it a one-shot delivery: a socket
  that was down, a reply that was lost, or a rejection an admin took hours
  later, and the reason was unrecoverable. The poll is the natural recovery
  path and it was the one path that deliberately stripped it. An
  admin-rejected applicant could never learn why at all — `reject_pending`
  emits no message to them, and the operator's reason reached only the
  audit log, which no applicant can read.

  Both paths now write one `JoinRequest::decision` field — code, optional
  reason, and the decision's own timestamp — and the poll projects it. One
  field rather than two, because the whole failure was two producers of the
  same fact drifting apart. It is deliberately *not* `policy_decision`: an
  operator's decision is not a policy verdict, and recording it as one
  would make the audit trail lie about where the refusal came from. The
  admin path carries `ADMIN_REJECT_CODE` ("admin-reject"), which is what
  lets a client tell "the rules refused you, satisfy them and re-apply"
  from "a human refused you, re-applying changes nothing".

  `decidedAt` is separate from the response document's `issuedAt` because
  `issuedAt` is when *this document* was produced. For an admin reject the
  two diverge by however long the applicant takes to poll. The test proves
  the distinction the only way it can be proved: poll twice, and `issuedAt`
  moves while `decidedAt` names the same moment.

  Rows rejected before this existed are not abandoned. An auto-deny always
  wrote the serialized `Deny` verdict, so `decision_for_applicant` falls
  back to it — recovering the code and reason, and reporting `decided_at:
  None` rather than back-filling a timestamp that would tell the applicant
  they were rejected the instant they polled. A legacy *admin* reject has
  nothing to recover and answers exactly as it did before.

  Also adds `VerdictResponse::deny`, which the issue asked for alongside:
  the deny shape had `allow` and `refer` constructors but was hand-assembled
  at its one call site, and this change gave it a second producer.



### Chore

- **vtc**: Recognise and submit 0.2 — drift reaches zero ([#1105](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1105))

Retargets `auth/recognise` and `join-requests/submit` to the `0.2` versions
  published by trustoverip/dtgwg-trust-tasks-tf#264.

  **Drift 2 → 0.** Every Trust Task this service binds now speaks the schema it
  publishes, on both sides. It was 33 when the sweep landed yesterday.

  ## Why these two moved the spec rather than the service

  Both were recorded as "the service's shape is arguably stronger". Reading them
  properly, one was not arguable at all.

  **`auth/recognise/0.1` took `{vec, vmc}` — a replayable impersonation token.**
  Both credentials are bearer artifacts, so anyone who obtained the pair from a
  relayed join, an audit log, a backup or a compromised device held everything
  the payload required, and the recognising community could not distinguish the
  subject from someone holding a copy. No proof of key possession, no freshness,
  no audience binding: one captured pair worked at every community that
  recognised the issuer, indefinitely. This service has required a holder-signed
  presentation — nonce, `domain`, holder-is-subject — since P0.2. `0.2` publishes
  that.

  **`join-requests/submit/0.1` returned `status: const "pending"`** where a
  submission has four outcomes. `0.2` returns a verdict.

  ## One real find in the retarget

  `VerdictEffect` serialised **`request_more`**, but I had specced `requestMore`
  in #264, and SPEC §4.10 rule 4 is explicit that specification-defined decision
  values are lowerCamelCase. So the wire was wrong.

  The fix is not to change either vocabulary wholesale, because there are two of
  them and both are correct in their own language:

  - **Rego authors verdicts.** Operator-written policy returns
    `{"effect": "request_more", …}`, and snake_case is that language's idiom —
    `vtc-service/policies/default/join.rego` and every deployed policy alongside
    it. Re-casing there would break operator policies to satisfy a wire rule
    that does not govern them.
  - **The wire publishes `requestMore`**, per §4.10 and the new
    `vtc/_shared/0.1/ceremony#VerdictEffect`.

  `VerdictEffect` is the boundary: it now serialises camelCase and keeps
  `#[serde(alias = "request_more")]` so anything producing the policy spelling
  still deserialises. That is the same storage-versus-wire split `EndorsementRow`
  ([#1096](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1096)) and `GenerationRow` ([#1095](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1095)) draw, applied to a policy vocabulary
  instead of a keyspace.

  The test that caught it now demonstrates the boundary instead of hiding it —
  its inline Rego authors `request_more`, and it asserts the wire says
  `requestMore`, with a comment saying why both are right.

  ## The table at zero

  `KNOWN_DRIFT_COUNT` stays asserted at `0`. It can no longer shrink, so the only
  thing it can do is catch a regression — which is what an asserted count is for.
  A new task that diverges must add a `drift!` entry and raise it deliberately.

  The `drift!` macro, `Side`, and `Conformance::KnownDrift` are now unconstructed
  and kept with `#[allow(dead_code)]` rather than deleted. They are the
  vocabulary for *recording* a divergence, and a table with no way to say "this
  diverges, on this side, for this reason" invites the next author to leave a
  real divergence unrecorded rather than write the machinery back. Deleting them
  would make the zero look permanent instead of current.

  ## The header, rewritten

  It described a 33-entry backlog. It now records how the 33 actually closed,
  because the distribution is not what the sweep predicted:

  | | |
  |---|---|
  | **10** | by correcting this service's wire shapes |
  | **19** | on dependency bumps alone — the specs had moved and the notes had not |
  | **4** | by correcting the **specification**, once the published shape turned out to be the weaker one |

  That last group is the one worth remembering. A conformance table makes
  divergence visible and says nothing about which side is wrong, and *"the schema
  requires X and the service omits X"* reads as an accusation against the
  implementation. Twice it was the schema. Once — `install/claim` — the
  requirement had been built, found impossible in a browser, and removed two
  months **before** the specification demanding it was written, and this table
  recorded that as the service being behind on a security control.

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace --no-fail-fast`
  - `cargo fmt --all --check`

- **deps**: Bring every dependency to latest, collapsing two duplicates ([#1055](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1055))

`cargo outdated` reported 13 direct dependencies behind and `cargo update`
  had 36 compatible updates waiting. Both are now clear: `cargo outdated`
  reports "All dependencies are up to date".

  Two of these were not cosmetic.

  **p256 was duplicated in the build.** Our crates declared `0.13` while
  `affinidi-crypto` — reached through `affinidi-data-integrity` and the TDK —
  already pulled `0.14`, so the graph carried two copies of a curve
  implementation. The lock now holds a single `p256 0.14.0`. The bump brings
  `elliptic-curve` 0.14 and `ecdsa` 0.17, which rename the SEC1 family:
  `EncodedPoint` -> `Sec1Point`, `From/ToEncodedPoint` -> `From/ToSec1Point`.
  Renamed across `vta-keys`, `vta-service` and `vti-webauthn`.

  **tokio-tungstenite was load-bearing, not incidental.** `vta-mobile-core`
  depends on it solely as a feature enabler: iOS has no native trust store, so
  `rustls-tls-webpki-roots` has to be on graph-wide or the mediator WebSocket
  fails with "no native root CA certificates found". Features unify per major
  version, so the declaration only works while it matches the version
  `affinidi-messaging-sdk` pulls — and the SDK moved to 0.30 in this refresh.
  Updating everything *except* this one would have stranded the enabler and
  broken iOS `wss://` silently.

  The rest:

  - `rcgen` 0.13 -> 0.14 (dev). `signed_by` takes an `Issuer` rather than a
    `(certificate, key)` pair, and `self_signed` borrows instead of consuming.
    The mdoc IACA test helper builds its issuer with `Issuer::from_params`,
    which is also a more direct statement of what it wanted.
  - `syn` 2 -> 3 (dev). No source change; syn 3 was already in the graph via
    `trust-tasks-rs`.
  - `rmcp` 1.7 -> 3.1.4. Two majors, one rename: `Content` -> `ContentBlock`.
    The `#[tool_router]` / `#[tool_handler]` macro surface the crate is built
    on is unchanged.
  - 36 lockfile updates, including `trust-tasks-rs` 0.11.3 (the corrected
    `vta/app-state` error taxonomy from dtgwg-trust-tasks-tf#253) and the AWS
    SDK set. `rustls-pemfile`, one of the unmaintained crates `cargo audit`
    flags, drops out of the graph entirely.

  Two deliberate choices where the shortest path was worse:

  `vti-webauthn` keeps parse-then-validate rather than collapsing to the
  one-shot `PublicKey::from_sec1_bytes`. That call merges "malformed SEC1
  encoding" and "valid encoding, point not on the curve" into one error, and
  those say different things to whoever reads the log — a broken client versus
  a point somebody chose.

  BIP-32 P-256 derivation replaces the now-deprecated `FieldBytes::from_slice`
  with `TryFrom` and a real error arm. The input is a fixed 32-byte window of a
  SHA-512 HMAC so it cannot fail, but the length check is now explicit rather
  than resting on a panic inside a deprecated helper.

  Unchanged and still suppressed: the four `cargo audit` advisories ignored in
  `deny.toml`, all transitive through the AWS SDK's hyper 0.14 / rustls 0.21
  path. `cargo deny check advisories` passes.



## [0.28.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.27.0...vta-sdk-v0.28.0) — 2026-08-22


### Added

- **discovery**: Serve canonical capability negotiation, drop the parallel REST route ([#1042](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1042))

* feat(discovery)!: serve canonical capability negotiation, drop the parallel REST route

  Clients had no way to ask a VTA which Trust Tasks it serves. Calling one it does
  not is a 30-second DIDComm timeout with no explanation — the failure mode
  `didhosting-083-retired-task-uris` describes.

  The answer already existed and we were not serving it. `trust-task-discovery/0.1`
  is a published family in the dtgwg-trust-tasks-tf registry, carried by the
  `trust-tasks-rs` we already depend on: a client sends slug-glob patterns (`*`,
  `acl/*`, or an exact slug) and gets back the Type URIs the responder serves plus
  the framework version it targets. Nothing needed inventing, and — unusually for a
  new family — nothing needed specifying upstream first.

  The VTA answers **from its own dispatch table**. `dispatched_uris()` was already
  generated by `dispatch_table!` from the same declarations that build the match
  arms; it is now available at runtime rather than only under `cfg(test)`. A
  hand-maintained list would be a second source of truth, and an overstated
  discovery response is worse than none: a client believes a task is available and
  finds out on a live call.

  **What this does not do.** It answers "do we both know this task, at this
  version". It does not answer "do we agree how its payload is spelled" — two peers
  can both serve `contexts/create/1.0` and still disagree about `basePath` vs
  `base_path`, which is what #1033 was. Said plainly on the SDK method, because the
  obvious misreading is that discovery makes wire skew detectable.

  ## GET /capabilities is gone

  Nothing consumed it: `VtaClient::capabilities` goes over `rpc_tt` like every
  other task, and no doc or downstream reads the route. A REST route running
  parallel to a Trust Task is precisely the shape #1020 removed everywhere else —
  the Trust-Task surface is already reachable over REST at
  `POST <base>/trust-tasks`.

  Removing it also dissolved the reason #1034 deferred folding
  `CapabilitiesResponse`: the hesitation was re-casing a public discovery endpoint
  whose readers nobody can enumerate. With the endpoint gone the only consumers
  left decode this very struct, so the fold is free and taken here.

  ## Both remaining inert aliases folded

  `UpdateRetentionBody` too, so `audit/update-retention` stops taking a snake_case
  request and returning a camelCase response — an asymmetry nobody chose, in one
  file, one screen apart. This is a request body, so the risk runs the other way: a
  client on this version sends `retentionDays` and an agent predating the change
  rejects it. That is the same trade #1000 made for every request body it folded;
  it is taken deliberately rather than inherited.

  `INERT_BY_DECISION` in the census is now **empty**, which is the intended end
  state rather than a coincidence.

  ## Notes for review

  - The `openapi_spec_describes_registered_routes` assertion was pinned on
    `/capabilities` as "the first route migrated to OpenAPI-aware registration".
    Re-pinned on `/auth/challenge` rather than deleted: what it actually asserts is
    that `routes!()` registration still lands operations in the served document,
    and that property did not leave with the route.
  - The two `capabilities_*` integration tests now drive the Trust-Task surface.
    The properties they assert — authenticated, reports features — are unchanged;
    only the door is.
  - A wrong assumption caught by its own test: ACL folded to the **top-level**
    canonical family, so the slug is `acl/grant/0.1`, not `vta/acl/grant/0.1`. The
    first draft of both the handler test and the conformance witness used the
    VTA-namespaced form. It fails silently — a wrong pattern returns an empty list,
    not an error — so the corrected test asserts the negative case too.



### Changed

- **discovery**: Retire vta/discovery/capabilities — every member had a better home ([#1044](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1044))

* refactor(discovery)!: retire vta/discovery/capabilities — every member had a better home

  #1042 reduced this task to `version` + `webvhServers` + `didCreationModes` and
  left a question: does what remains still earn a task? Audited each member. No.

  - **`version`** — `GET /health/details` already reports it, at the same auth
    level and from the same `env!("CARGO_PKG_VERSION")`. A duplicate, though a
    benign one: both read the same constant, so they cannot disagree.

  - **`webvhServers`** — a *lossy* duplicate of `webvh/servers/list/1.0`.
    `WebvhServerInfo {id, label}` against `WebvhServerRecord {id, did, label,
    createdAt, updatedAt}`, from the same `webvh_store::list_servers` call. The
    obvious objection is auth — a cheap summary for callers who cannot see the
    full list — and it does not hold: `list_webvh_servers` is commented "Any
    authenticated user can list servers", the same gate. No production code read
    it from here; `vtc-service`'s setup wizard already called the dedicated task.

  - **`didCreationModes`** — dead, and misleading. No consumer in this repo or
    OpenVTC. Derived entirely from `cfg!(feature = "webvh")`, which is the same
    species as the `features` booleans #1042 removed. Its vocabulary —
    `vta-built` / `template` / `final` / `user-specified-keys` — appears nowhere
    else in the codebase; it dates to #22 in April and predates `WebvhPathMode`,
    which is the axis DID creation actually turns on. The fixtures "covering" it
    asserted `["webvh"]`, a fourth vocabulary again, so its test coverage was
    fiction of the same kind #1033 was about.

  So the task is gone, along with the `discovery/1.0/*` DIDComm protocol beside
  it — which was routed unauthenticated, worth noting on the way out.
  `trust-task-discovery/0.1` ([#1042](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1042)) answers the one question this surface should
  have been answering.

  This also discharges the `UNSPECCED_DISPATCHED_URIS` entry by deletion rather
  than by a spec, which is the cheaper way to shrink that list when the answer is
  "this should not exist".

  ## Consumers

  `vta-mcp`'s `vta_capabilities` was the only one, and it becomes
  `vta_supported_tasks`. Not a rename: the old tool promised four answers, three
  better held elsewhere and one describing nothing. What an agent needs before
  calling an operation is whether the VTA serves it, and the tool description now
  says so — including that calling an unserved task fails as a transport timeout
  rather than a clear error, which is the reason to ask first.

  ## On retiring rather than deprecating

  `deprecation.rs` sets this repo's practice for removing a REST route: mark it,
  count usage, delete on an observed zero rather than a guessed date. There is no
  equivalent for Trust Task URIs, so that path was not available. The
  justification here is the audit — zero consumers across both repos, plus a
  vocabulary that corresponds to nothing — rather than a metric. Worth saying
  plainly, because it is a weaker instrument than the one the REST routes get.

  While there: the `GET /capabilities` row in that same table was left dangling by
  #1042, matching a route that no longer exists. Nothing catches that — no test
  ties the table to the live router — so it is removed by hand.

- **sdk**: One wire, one type — decode the agent's own bodies ([#1037](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1037))

#1033 fixed eleven Trust-Task call sites where the client's decode type had
  drifted from the agent's body, breaking every `pnm contexts` command, four `pnm
  keys` commands, seed rotate/list and the MCP surface. It fixed them with `serde`
  aliases, which restores compatibility without removing the hazard: the wire still
  had two structs, and either could move alone again.

  The audit behind it found the correlation was total. Of 61 call sites, the 50
  decoding a shared `protocols::**` type were all fine and all 11 with a private
  type in `client/types.rs` were broken. Not a coincidence to test around — the
  defect itself.

  Each of the eight duplicates is now a `pub use` of the body the agent
  serializes. The client-facing names are kept, so `get_context` still returns
  something called `ContextResponse`; what changed is that the name now refers to
  `CreateContextResultBody` rather than a copy of it. Two ends cannot disagree when
  there is one end.

  Two things fell out that a field-by-field mirror had been hiding:

  - **`vta contexts create --parent x` rendered no parent.** `bootstrap_cli.rs`
    carried an adapter whose comment said the two types were "identical on the
    wire". They were not: the client struct had no `parent`, so the adapter dropped
    it silently on every offline context render. Deleting the adapter fixes it, and
    the compiler found it — `missing field `parent`` was the first error after the
    re-export landed.

  - **`{:?}` on a key-secret response printed the raw private key.** The client's
    `GetKeySecretResponse` derived `Debug`; the agent's `GetKeySecretResultBody`
    hand-writes it to redact `private_key_multibase`, precisely so a caller cannot
    tracing-log it by accident. Sharing the type inherits the redaction.

  The ACL pair deliberately stays two types. `AclEntryResponse` renames `subject`
  to `did` and `scopes` to `allowed_contexts` and converts RFC 3339 to the epoch
  seconds the CLI speaks — it is an adapter with real logic, not a mirror, and it
  cannot be re-exported. It keeps its seam cases, which matters more now: an
  adapter that computes can be wrong in ways a copy cannot.

  Request builders also stay local. `CreateKeyRequest` and friends exist for
  ergonomics and *produce* the wire shape rather than describing it, so they cannot
  drift the same way.

  ## The tests shrink, on purpose

  Nine cases in `trust_task_decode.rs` are deleted. They serialized the agent's
  body and decoded it into the client's type; with one type on both sides that now
  asserts `serde` round-trips a type through itself — true of every type
  everywhere, and no longer a fact about this codebase. Keeping them as
  reassurance would be keeping exactly the kind of vacuous assertion that let
  `acl/update` ship broken through three PRs.

  What remains is the part that is still real: the ACL adapter, and the legacy
  snake_case direction. That second one is arguably stronger than before — it now
  exercises the intake aliases on the **agent's** types, which is where every
  consumer's backward compatibility comes from, not just this client's.

  `COVERED_BY_SEAM_TEST` in the census drops from nine names to one. That is the
  shape the census was built for: the list shrinks as duplicates are removed rather
  than growing as they are papered over. The census itself is unchanged and was
  re-verified against an injected duplicate after the collapse — it still refuses a
  new client-private decode type.



### Fixed

- **sdk**: Finish the seeds/list fold, and make an inert alias fail the build ([#1040](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1040))

* fix(sdk): finish the seeds/list fold, and make an inert alias fail the build

  `seeds/list` emitted a body that disagreed with itself:

      {"seeds":[{"id":1,"status":"active","created_at":"…"}],"activeSeedId":1}

  #1000 folded Trust Task payloads to lowerCamelCase and gave 126 members an
  alias for the retired spelling. `SeedInfo` got the aliases and not the
  `rename_all` that gives them meaning, so it kept emitting snake_case with
  `alias = "created_at"` sitting on a member already called `created_at` — while
  `ListSeedsResultBody` around it moved. Adding the `rename_all` finishes that and
  activates the aliases, so a producer still sending snake_case keeps decoding.

  Safe to finish precisely because the containing body already moved: the same
  REST route (`GET /keys/seeds`) has emitted `activeSeedId` since #1000, and the
  client type is the agent's own since #1035, so both ends move together.

  ## The class, not the instances

  An alias equal to its member's serialized name accepts what would be accepted
  anyway. That is not untidiness — it is how this shipped. The code compiled,
  every test passed, and the attribute reads as though the fold happened; a
  reviewer seeing `alias = "created_at"` reasonably assumes the member is now
  `createdAt`. Both known instances were found by hand, months later, while
  auditing something else.

  `tests/inert_alias_census.rs` decides it from the source instead, for every wire
  type under `protocols/` at once. Verified non-vacuous in all three directions
  rather than assumed:

  - reverting this fix reports `SeedInfo.created_at` and `.retired_at` — it would
    have caught #1000's miss;
  - an alias injected into an already-folded struct is reported;
  - an exception entry for a type that no longer needs one is reported, so the
    allow-list cannot rot into a blanket excuse;
  - and floors on files scanned and aliases parsed, so a `syn` upgrade or a moved
    directory leaves it red rather than green over nothing.

  ## It immediately found a third instance

  `UpdateRetentionBody.retention_days`, which nobody knew about. One screen down in
  the same file its sibling `RetentionResultBody` IS folded, and even the empty
  `GetRetentionBody` carries `rename_all` — so `audit/update-retention` takes a
  snake_case request and returns a camelCase response. Plainly a miss.

  Deferred anyway, with `CapabilitiesResponse`, both recorded in
  `INERT_BY_DECISION` with their reasons and tracked in #1039. The line is whether
  the fold *completes* a change already made or *starts* a new one:

  - `SeedInfo`'s containing body already moved — finishing it removes an
    inconsistency.
  - `CapabilitiesResponse` has not moved at all, and is served on `GET
    /capabilities` as well as the task surfaces, so folding it is a fresh REST wire
    change of exactly the kind #1000 deferred.
  - `UpdateRetentionBody` is a *request* body. Folding changes what clients SEND,
    and an agent predating the change rejects the new spelling — the opposite
    direction from `SeedInfo`, where a new agent's output is absorbed by aliases
    the client already holds.

  Deleting an inert alias is the wrong repair in every case, and the census says
  so where someone would try it: the alias is the only thing that lets an older
  producer keep working once the fold lands.

  The `client_rest.rs` seeds fixture is re-cut. It carried a comment explaining
  that `seeds[]` was snake_case inside a camelCase `activeSeedId` because that was
  what the agent really emitted; that asymmetry is gone, so describing it would now
  be the fiction.



## [0.27.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.26.0...vta-sdk-v0.27.0) — 2026-08-21


### Fixed

- **sdk**: Decode the Trust-Task responses the agent actually sends ([#1033](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1033))

`pnm contexts create` fails against any agent built since #1000:

      Protocol error: trust-task response decode: missing field `base_path`

  #1000 folded Trust Task payloads to lowerCamelCase per SPEC §4.10 and excluded
  `client/types.rs` as REST bodies whose casing "no published schema pins". The
  exclusion was drawn by file path, and the path was stale: `rpc_tt` carries the
  same Trust-Task document over REST, DIDComm and TSP alike, so `ContextResponse`
  is a Trust-Task decode target and a published schema does pin it. The agent moved
  to `basePath`; the client went on demanding `base_path`.

  Eleven call sites across eight types, every one a required field with no
  `default`, so they fail hard on every transport rather than degrading:

  - contexts create / get / update / update-did / list — all of `pnm contexts`
  - keys sign / rename / revoke / export-secret
  - seeds rotate / list (`activeSeedId` only)

  `vta-cli-common` and `vta-mcp` consume these, so `pnm`/`cnm` key management and
  the MCP tool surface are equally affected. The user who reported it hit contexts
  first and would have hit `keys sign` next.

  Aliases rather than `rename_all`: this is the same Postel fold #1000 used, it
  changes nothing about what the SDK emits, and it keeps working against an agent
  that has not taken the change. `SeedInfoResponse` gets aliases it does not yet
  need, because its counterpart `SeedInfo` is the one payload struct #1000 left
  unfolded — when that lands, this type should not be what breaks.

  The casing is the symptom. The defect is that one wire has two structs, so
  either end can move alone; the 50 Trust-Task call sites that did NOT break are
  exactly those where client and agent decode the same type. Collapsing each pair
  onto one type is the real repair and is not attempted here — it changes public
  type identity for two downstream crates. The module note records that.

  ## Why no test caught a total outage

  Three layers each stopped one step short of the join. The conformance harness
  checks the agent against the published schema — green, its witness correctly
  said `basePath`. The SDK's client tests check the client against a hand-written
  mock — also green, because the mock still said `base_path`. Nothing compared the
  two fixtures, so they disagreed for two days while both suites passed.

  `vta-sdk/tests/trust_task_decode.rs` is that missing seam: it constructs the
  agent's own body type, serializes it as the agent would, and requires the
  client's own decode type to accept the bytes. No JSON literal appears in the
  derived cases, so there is no third spelling to drift. Verified non-vacuous —
  with the aliases reverted, 9 of 9 derived cases fail, each naming the CLI surface
  that is broken and printing the exact wire.

  The stale fixtures are re-cut to what an agent really sends, including the
  asymmetry a uniform pass would have got wrong: `seeds[]` stays snake_case inside
  a camelCase `activeSeedId`, because that is what the half-folded type emits.
  Re-cutting them would have silently retired the only coverage of the snake_case
  intake aliases, so that direction is now asserted explicitly by name —
  `a_legacy_agent_snake_case_response_still_decodes` — rather than left implicit in
  a fixture someone would later tidy.

  Conformance witnesses stay hand-written: they anchor the types to the spec, and
  deriving them from the types they check would make them vacuous.

  Two adjacent findings, left alone as neither is a break: `CapabilitiesResponse`
  and `SeedInfo` both received `alias` attributes in #1000 without the
  `rename_all` that would give them meaning, so both still emit snake_case and
  their aliases are inert. Filed rather than folded in, since fixing them changes
  the wire.

- **sdk/cli**: A credential store that cannot be opened must not read as "never logged in" ([#1032](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1032))

All four binaries treated an unavailable OS credential store as a warning
  and carried on. What happened next was worse than a silent fallback:
  `KeyringBackend` stayed registered, every `Entry::new` returned
  `NoDefaultStore`, and `SessionBackend::load` swallowed it and returned
  `None` — so the tool behaved exactly as though the user had never logged
  in. A silent fallback at least stores something; this silently forgets.
  OpenVTC hit the user-facing end of it: a profile kept in the Linux kernel
  keyring did not survive a reboot, and the error told the user to check
  their network.

  The four call sites are byte-identical, but their consequences are not,
  so the fix is not:

  - `pnm` and `cnm` keep their session — the admin DID and its private key
    — in the credential store and nowhere else. They now exit at startup
    via `keyring_init::install_default_store_or_exit`, which is the whole
    point: there is nothing they can usefully do next.
  - `vta` and `vtc` never construct an SDK `SessionStore`; they use the
    fjall-backed `KeyspaceSessionStore`, and their keyring use is the seed
    store, one of eight `[secrets] backend` options. Which one is in play
    is not known until config loads, long after `main` starts, so hard
    failing there would break every deployment on aws/gcp/azure/vault/k8s
    running on a host with no credential store — the normal server shape.
    They get `warn_store_unavailable`, and `KeyringSeedStore` — which
    already failed closed — now says which subsystem broke rather than
    "failed to create keyring entry".

  The second half is `FileBackend`. `default_backend` ended in an
  `#[allow(unreachable_code)]` fallback into it whenever no backend feature
  was enabled, writing the admin private key to `sessions.json` as
  plaintext at the process umask, announced by a WARNING on every access —
  which is to say, invisible. `pnm`'s own bootstrap-secrets path has always
  used 0600; the inconsistency was inside one tool.

  That fallback is gone. A build with no session store gets `RefusingBackend`,
  which refuses to save rather than inventing somewhere to put a private
  key. `FileBackend` is now reachable only by explicit choice — the
  `config-session` feature, or `VTI_SECURE_STORE=file` at runtime — and
  creates its file at 0600 inside a 0700 directory *before* writing, since
  writing and then hardening leaves a window at the umask. An existing
  world-readable file from an older build is re-hardened on the next write.

  The runtime override exists because requiring a rebuild to run on a
  headless host creates pressure to disable the check rather than make a
  choice. It parses strictly: `os` or `file`, and anything else — including
  a near-miss like `plaintext` — resolves to neither and refuses. Asking
  for `os` on a build with no `keyring` feature refuses too, rather than
  quietly substituting a file.

  One explanation now serves every tool, in `vta_sdk::secure_store`, taking
  the error as `Display` so it is available without the `keyring` feature —
  OpenVTC renders the same text and honours the same override, which was
  the stated goal: identical secret handling across vta, pnm, openvtc and
  vtc, hard failure rather than a fallback to open text files.



## [0.26.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.25.1...vta-sdk-v0.26.0) — 2026-08-20


### Added

- **service**: Retire an orphaned webvh slot, on evidence rather than assertion ([#1022](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1022))

`vta/webvh/servers/reconcile` names two divergences and repairs
  neither, deliberately — they want opposite remedies. This implements the
  remedy for one: the orphan, a slot a hosting server serves for this VTA
  that the VTA has no record of.

  Nothing could repair that state, and the reason is structural. Every
  delete addresses a DID through its local record, which is what says
  which server to talk to and which keys to sign with; an orphan is
  defined by that record's absence, so the lookup fails before a request
  leaves the VTA. Nor can the caller go around it — the VTA holds the host
  credentials. A slot both parties can see, and neither can remove.

- **service**: The vta/services task family, and the twenty routes it supersedes ([#1017](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1017))

* feat(service): the vta/services task family, one verb per task

  Eight handlers covering what twenty `/services/*` REST routes did. The
  operations are untouched — `operations::protocol::*` already implements each
  transport — so this is the parameterised door onto them, not new logic.

  `service` names the transport and `config` carries its settings, so the fan-out
  happens here rather than on the wire. That is what keeps a fifth transport to a
  config variant instead of four new specs.

  **The drain guard is the part that matters.** Tearing down a mediator discards
  whatever is in flight through it, so `disable`/`update`/`rollback` on didcomm
  pass a `DisableTransport` that decides whether the 1-hour floor applies. The
  REST route hardcodes `Rest` and the DIDComm handler hardcodes `Didcomm`,
  because each IS that path; a trust task is not, so it reads the arrival
  transport from the dispatch spine.

  The spine records confidentiality, not binding: DIDComm and TSP are both
  `EndToEnd` and it cannot tell them apart. `EndToEnd` therefore maps to
  `Didcomm`, which OVER-applies the floor to a TSP-carried disable that does not
  strictly need it. Deliberate: under-applying tears down the mediator a request
  arrived through and discards the reply to the very task asking for it, while
  over-applying only delays a teardown the operator can repeat. The ambiguous
  case takes the cheaper mistake.

  Three shapes the generated types forced, each documented where it lands:

  - `ServiceMutationResult` and `RollbackKind` are duplicated per family —
    identical shapes, distinct types. Mutation results round-trip through the wire
    form rather than being hand-copied three times; rollback kinds go through a
    macro that names the variants, so a divergence is a compile error.
  - Rollback may write nothing. Its `noOp` arm has no `logEntryVersionId`, which
    is why it has its own result type, and the witness uses exactly that arm.
  - `handshake_timeout_secs` is `NonZeroU64` — the schema's `minimum: 1` — so the
    default is constructed, not unwrapped.

  **Operation futures are boxed, and that is load-bearing.** These handlers fan
  out to four sizeable futures, awaited inside a dispatch match that already
  carries every other task's state machine. Inlining them grew the frame past the
  default 8 MiB stack and aborted an unrelated mock_vta test with a stack
  overflow — which reads as infinite recursion and is not.

- **sdk**: Hold one idempotency key across every attempt of an operation ([#1012](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1012))

The VTA deduplicates keyed Trust Tasks on an `idempotencyKey` ([#1011](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1011)).
  That only helps if the retry carries the *same* key as the attempt it is
  retrying — and a hand-rolled retry loop structurally cannot do that,
  because it re-invokes a client method that builds a fresh document each
  time. Minting the key inside the method has the identical problem the
  envelope id already has: attempt two gets a new one, the VTA sees an
  unrelated request, and the second durable effect happens anyway.

  So the key has to be scoped *outside* the call. `VtaClient::idempotent`
  mints one, holds it in a task-local for the duration of a closure, and
  retries transient faults inside that scope:

      let key = client.idempotent(|| client.create_key(req.clone())).await?;

  Every dispatch the closure makes carries the same key. A task-local
  rather than a parameter because it has to reach all twenty-odd typed
  methods without changing twenty signatures, and because it is genuinely
  ambient — it belongs to the operation, not the call.

  The key is attached only when the task is one a second execution would
  actually harm (`retry_safety`); attaching it to a read would cost the
  VTA a dedup record and buy nothing. It goes top-level beside `id`, where
  the VTA reads it from `TrustTask::extra` and a Data-Integrity proof
  covers it — so a relayer cannot rewrite it to split one operation
  into two.

  ## One retry owner

  Retry layers compose badly. The messaging delivery layer already retries
  a durable outbox with backoff underneath this, so an application loop on
  top multiplies attempts against a server that dedups at neither. This is
  the application-layer owner: bounded at 3 attempts, backed off, and
  honouring the server's `retryAfter` up to a 30s cap — an unbounded wait
  on a server-chosen value is a stall the server can trigger at will.

  Callers should use it *instead of* their own loop, not around one.

  ## BREAKING CHANGE

  `VtaError` gains an `Unavailable { retry_after }` variant (exhaustive
  enum), reported by cargo-semver-checks so the release moves the
  compatibility field rather than shipping it as a patch.

  It is typed rather than folded into `Protocol(String)` because it is the
  one wire rejection meaning "ask again" rather than "this failed" — the
  idempotency layer returns it while a first attempt on the same key is
  still running. A retry loop reading it as terminal gives up on precisely
  the answer it was told to wait for. The REST leg parses the error
  document before the status (R3.7), so without this the `unavailable`
  code collapsed to a string and its 503 never surfaced.

- **sdk**: Classify what a lost reply costs every Trust Task ([#1010](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1010))

A client that retries a timed-out request is doing the right thing — the
  dominant transport fault is a request that never arrived. The dangerous
  case is the other one, where the VTA processed it and only the reply was
  lost, and whether that is harmful depends entirely on the operation.
  Deleting an already-deleted DID is free; creating a second auto-assigned
  `did:webvh` is not, because the first stays published in the log with
  nobody holding a reference to it.

  Callers currently cannot tell those apart, so they guess. This adds the
  property as data: `RetrySafety` over all 148 URIs in `ALL_URIS`, with a
  census test that fails if a task joins the catalog unclassified — the
  same discipline that pins `REST_ROUTED_URIS`.

  Four classes, drawn around the question a retry layer actually asks:

  - `ReadOnly` — no durable effect.
  - `RetrySafe` — mutating, but a repeat is harmless: it either converges
    on the same end state (revoke, disable, delete) or leaves an inert,
    self-expiring duplicate (a spare auth challenge). Deliberately not
    named "idempotent", because the second half is not.
  - `Keyed` — non-convergent: a repeat leaves a second durable artefact
    that persists and matters. Needs an idempotency key.
  - `KeyedSecret` — as `Keyed`, but the response carries secret material,
    so the response must never be cached. Deduping the effect without
    turning a dedup store into a second place mnemonics and sealed
    bundles live.

  That last class is the one worth arguing about. Result-caching
  idempotency wants to replay the stored response, and for
  `seeds/export-mnemonic`, `backup/complete-export` and
  `provision/integration` that would mean persisting the secret a second
  time, indefinitely, to serve a retry. The effect is still deduped; only
  the replay is refused.

  Where convergence is not obvious from an operation's contract it is
  classified `Keyed` rather than `RetrySafe`. The asymmetry is nearly
  free — an over-classified task costs one dedup record, while an
  under-classified one loses the protection in exactly the rare case the
  table exists for.

  Classification alone gates nothing: it changes how a *keyed* request is
  handled, and a request carrying no key behaves exactly as it does today
  on every task in the table. Nothing consumes this yet; the VTA-side
  dedup store and the client-side key are the follow-ups.

- **service**: Signal every superseded REST route, from one layer ([#1007](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1007))


### Fixed

- **sdk,service**: Serve and use the Trust-Task path the binding asks for ([#1020](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1020))

`trust-tasks-https` POSTs to `<serviceEndpoint>/trust-tasks`, where
  `serviceEndpoint` is what a VTA advertises on its service entry. Every
  deployment example advertises an ORIGIN — `https://trust.example.com`,
  `http://localhost:3000` — so a client built from the published binding asked
  for `/trust-tasks` and got a 404. Ours worked only because `vta-sdk` hardcoded
  `/api/trust-tasks` and this service happened to serve the same prefix.

  Two implementations agreeing by convention is not a contract; it hides the
  absence of one from the only people who would notice — which is why this
  survived until someone read the binding rather than the code.

  The underlying defect was never the path. Nothing defined what the advertised
  endpoint DENOTES, so the two clients composed it differently and both could not
  be right: the SDK appended `/api/trust-tasks`, the binding appended
  `/trust-tasks`. Settled, per Glenn: **serviceEndpoint is the Trust-Task base**,
  and the binding's suffix is the contract.

  - **The service serves both.** `/trust-tasks` alongside `/api/trust-tasks`, one
    dispatcher. This is what makes the change safe: for an origin-advertising VTA
    the Trust-Task base IS the origin, so every existing advertisement becomes
    conformant with no operator touching anything.
  - **The SDK moved to `<base>/trust-tasks`.** That is the half that makes the
    contract real rather than aspirational, and it is safe against any VTA that
    has taken the change above.
  - **`/api/trust-tasks` is marked superseded**, so the metric that governs every
    other retired route decides when it goes. Its successor is a PATH, not a task
    URI — the one row in that table where the successor is not a
    `trusttasks.org` URI, because what replaced it is a spelling rather than an
    operation.

  Moving the SDK surfaced a second hand-built call site: `backup_descriptors.rs`
  formatted `{base}/api/trust-tasks` itself instead of going through `rpc_tt`,
  which is exactly why it kept the legacy prefix after the shared path moved.

  Tests pin that both spellings reach the same dispatcher AND fail identically
  when unauthenticated — a divergence there would mean a conformant client and
  ours behave differently, which is the thing being fixed. 26 mocks across
  client_rest and auth_light_rest move with the client.

  Still to do, and deliberately not here: specifying what the Trust-Task service
  entry means, so this is a contract rather than a second convention. That is a
  spec-registry change.

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

- **sdk/service**: Take trust-tasks-rs 0.11, and fix the four defects it exposes ([#1015](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1015))

* build(deps): move to trust-tasks-rs 0.11 and affinidi-messaging-sdk 0.19.9

  trust-tasks-rs 0.11 carries the vta/services/* families this branch implements.
  The move needed affinidi-messaging-sdk to go first — acl_setup hands a
  MediatorAcl to TrustTasks::account_update, so two semver-incompatible copies of
  trust-tasks-rs made that a type error rather than a link. That landed as
  affinidi-tdk-rs#717 and published as 0.19.9.

  vta-sdk builds clean on this. The workspace does NOT yet: vtc-service still
  hits a duplicated TrustTask<Value> because the trust-tasks sibling crates
  (trust-tasks-didcomm, -https, -proof, -tsp, -capability-client, -didcomm-v1)
  changed their requirement to 0.11 without moving their own versions, so
  crates.io still serves tarballs built against 0.9. dtgwg-trust-tasks-tf's
  release/siblings-on-0.11 fixes that; this branch waits on it.

- **sdk**: Build these two task payloads from their typed bodies ([#1005](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1005))

`get_key_secret` and `list_dids_webvh` were the last two `rpc_tt` call sites
  constructing their payload as a hand-written `serde_json::json!` literal, so
  they emitted `key_id`, `context_id` and `server_id` — snake_case, against a
  SPEC §4.10 contract that says lowerCamelCase.

  The earlier casing fold could not reach them by construction: it rewrote
  structs via `rename_all`, and a literal has no struct to fold. Nothing was
  broken, because `GetKeySecretBody` and `ListDidsWebvhBody` both carry
  `#[serde(alias = "…")]` for the old spelling — but the SDK was emitting a
  non-canonical spelling of its own published contract, and a consumer generated
  from the schemas would not have recognised it.

  Building the typed body instead means the wire spelling now comes from the same
  struct the schema is generated from, so the two cannot drift again. This is
  what the earlier fold's "known gap" note pointed at.

  `list_dids_webvh` gains a second, smaller correctness win: the literal emitted
  `"context_id": null` for an absent filter, while `ListDidsWebvhBody` carries
  `skip_serializing_if = "Option::is_none"` and omits the key entirely.

  `list_dids_webvh_filters_by_context` asserted the old spelling and now asserts
  `contextId`/`serverId` — the test is the proof the emitted wire actually
  changed, not just the source.

- **wire**: Emit canonical lowerCamelCase on Trust Task payloads, accept snake_case ([#1000](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1000))

* fix(wire)!: emit canonical lowerCamelCase on Trust Task payloads, accept snake_case

  SPEC §4.10 makes lowerCamelCase the wire contract for Trust Task payload
  members. 53 wire structs emitted snake_case, so every consumer generated from
  the published schemas disagreed with what this agent actually sends — and the
  disagreement was invisible until someone wrote a client against the spec.

  The fold is Postel's. `rename_all = "camelCase"` changes what is emitted;
  a per-field `alias` keeps the previous spelling accepted on intake, so a
  producer written against the old wire keeps working while it migrates. 126
  fields carry an alias.

  **Scope is deliberately narrow, and three exclusions are not oversights:**

  - **Config (`setup/from_toml.rs`)** is TOML, where snake_case is idiomatic and
    is not a wire at all.
  - **Persisted stores and the backup file format** (`backup_management/types.rs`,
    `drain_store.rs`) are read back from disk. Re-casing those would fail to read
    data already written — a worse bug than the one being fixed. Note that
    `WebvhDidRecord` *is* both wire and persisted: it is folded, and reads of
    existing snake_case records keep working precisely because of the aliases.
  - **`protocols/credential_exchange.rs`** carries OID4VCI and OID4VP structures
    (`vp_token`, `credential_offer`, `dcql_query`). §4.10 requires externally
    owned names to be carried verbatim, never re-cased. The conformance harness
    caught this when a first pass re-cased `vp_token`, which is exactly what that
    test is for.

  REST request/response bodies (`routes/`, `client/types.rs`, `protocol/`) are a
  further 54 structs with the same problem. They are left for a separate change:
  unlike task payloads, no published schema pins their casing, and changing what
  they emit breaks readers that have no alias to fall back on.

  Thirteen integration assertions read the old spelling and now read the new one.
  Full suite green: 823 lib, 119 api_integration, 90 conformance, plus the rest.

  * style: wrap the serde attributes the casing fold widened

  Adding a per-field `alias` pushed several `#[serde(...)]` attributes past the
  line width, so rustfmt wants them broken across lines. No semantic change —
  `cargo fmt --all` output, nothing hand-edited.



## [0.25.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.25.0...vta-sdk-v0.25.1) — 2026-08-18


## [0.25.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.24.0...vta-sdk-v0.25.0) — 2026-08-17


### Added

- **vta-keys**: Add non-extractable internal signing keys ([#995](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/995))

An ordinary VTA key is BIP-32 derived, so anyone holding the 24-word mnemonic
  can reconstruct it offline. That is what makes the VTA recoverable, and equally
  what makes "the operator cannot obtain this key" false — the second limb of what
  eIDAS calls sole control.

  An internal key is generated from the system CSPRNG, has no derivation path, and
  is never returned by any surface. The VTA acts only as a signing oracle for it.

  Deliberately not a flag on the imported-key path. That path wraps its secrets
  under a KEK derived from the master seed (derive_kek(seed, salt)), so a
  non-extractable flag on it would be decorative: the boundary it claims to
  enforce has already been walked around. Internal keys get their own keyspace,
  INTERNAL_KEYS, with no seed involvement at any point, and that keyspace is in
  EXCLUDED_FROM_BACKUP by design — a backup carrying it would be an export of keys
  the VTA promises never to export, and restoring it elsewhere would clone a
  signer.

  Refused for did:webvh log entries, enforced in code rather than left to
  guidance. WebVH is append-only and each entry is authorised by the update key
  the previous entry named; an unrecoverable update key means that if storage is
  lost the DID can never be updated again by anyone, permanently, and every
  integration pinned to it is stranded. Credentials can be re-issued, an
  append-only identity log cannot. Internal keys remain fine as a signing
  verificationMethod inside a published document, where loss costs the ability to
  produce new signatures rather than control of the identity.

  The export refusal is not a permission check — admin is not a bypass, because
  the value of the origin is that no caller holds this power. There are two
  refusals (an early return and an in-match arm); removing either leaves the other,
  and removing both does not compile, since the match over KeyOrigin becomes
  non-exhaustive. An export path cannot silently reopen.

  Operator surfaces carry the cost prominently: `pnm keys create --internal`
  prints what is lost and requires the operator to type a confirmation phrase
  rather than mash y, the response repeats the warning, and docs/02-vta/
  internal-keys.md covers when to use one, what actually protects it (enclave
  measurement + KMS, not a mnemonic), and the two things that genuinely destroy
  it.

- **vta-service**: Present ISO mdoc credentials over OID4VP ([#993](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/993))

* feat(vta-service)!: present ISO mdoc credentials over OID4VP

  Completes mdoc support. A VTA could receive, verify and store an mdoc; it could
  not present one. This is the last piece, and it needed three things the other
  formats do not.

  An OID4VP session on the query wire. An mdoc's holder binding is a DeviceAuth
  signature over an ISO 18013-7 SessionTranscript, whose handover is
  [clientId, responseUri, nonce, mdocGeneratedNonce]. Two of those exist only in
  an OID4VP exchange, so a verifier that wants an mdoc supplies them; QueryBody
  gains an optional oid4vp_session carrying OID4VP's own field names, so a
  verifier can copy them out of its authorization request unrenamed.

  Absent, an mdoc is not offered at all rather than offered unbound. A DeviceAuth
  over invented handover values verifies nowhere and, worse, looks bound. The gate
  lives in match_held so matchable and presentable stay the same set: a
  matched-but-unpresentable credential bails the entire vp_token, not just itself,
  taking every other credential the verifier legitimately asked for with it. A
  mutation removing the gate fails the test that pins this.

  Holder identity that is key-shaped. ConsentGrant.holder_did becomes
  HolderIdentity::{Subject, DeviceKey}: every other format names a subject DID,
  while an mdoc names a device key discovered at receive. Both resolve to a
  did:key because ConsentRecord::verify_proof binds the proof's
  verificationMethod to the data subject — the variant records provenance that
  would otherwise be silently lost, not a different kind of value.

  A P-256 consent receipt. The device key signs its own receipt under
  ecdsa-jcs-2019 (affinidi-data-integrity 0.7.10), where every other format uses
  eddsa-jcs-2022. Signing the receipt with some other key would break the
  verificationMethod binding above; that is why the cryptosuite was added upstream
  rather than worked around here.

  Presentation itself is not a present_single arm: an mdoc vp_token entry is
  base64url CBOR of a DeviceResponse, not a W3C VP object, so present_mdoc sits
  beside it. Selective disclosure is by omission — only the [namespace, element]
  paths the query asked for are included.



## [0.24.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.23.3...vta-sdk-v0.24.0) — 2026-08-16


### Added

- **vtc**: Let an applicant poll a join without knowing its request id ([#985](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/985))

The status poll exists so an applicant can find out what became of a join
  the community never volunteered an answer for. It could not be used for
  that.

  The id it takes is the *community's*, minted here on submit and learned by
  the applicant from the first correlated reply. An applicant that never
  received that reply — the exact failure the poll is meant to recover from
  — holds only the id of the document it sent, which this VTC has never
  heard of, and gets `not found` for it. So the poll worked whenever it was
  not needed and failed whenever it was.

  Downstream the two recovery paths shared the blind spot and failed
  together: OpenVTC gates polling on having a confirmed id, and its other
  recovery (collecting stored mail) is empty once the mail has been acked
  and deleted. The record then sits Pending forever with no way back —
  OpenVTC/openvtc#221, where the only fix was hand-editing a config file.

  `requestId` is now optional. Omitted, it means "what is my open request?",
  and the community resolves it from the authenticated applicant. That is
  safe and unambiguous for the same reason the dedup on submit is: at most
  one request per applicant is open at a time, and the applicant is already
  proven by the authcrypt sender over DIDComm/TSP. No new auth surface, no
  new route, no new domain tag — the id simply stops being the only way to
  name a request.

  The response has always carried `requestId`, so one id-less poll also
  repairs the applicant's record and every later poll can quote it. That is
  what turns this from a query into a recovery.

  `find_open_request` is now `pub(crate)`: it was the dedup's private
  helper, and it is the same invariant both callers rely on.

  REST keeps requiring the id — it is a path segment there, and the stranded
  case is a messaging one. Worth revisiting if a REST applicant ever hits it.



## [0.23.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.23.2...vta-sdk-v0.23.3) — 2026-08-14


### Added

- **nitro**: Un-bake tenant config, deliver to the enclave over vsock ([#939](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/939))

* feat(nitro): un-bake tenant config, deliver to the enclave over vsock

  The Nitro enclave image no longer bakes tenant config.toml into the EIF, so one image (one PCR0) serves every tenant. The entrypoint fetches a versioned config envelope from the parent over vsock:5800 (bounded connect/read timeouts, 1 MB size cap, version check), fails closed unless VTA_ALLOW_DEFAULT_CONFIG=true, and writes /etc/vta/config.toml before start. Adds jq to the runtime; documents the KMS-policy isolation requirement and the tee-mode enforcement floor.



## [0.23.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.23.1...vta-sdk-v0.23.2) — 2026-08-14


## [0.23.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.23.0...vta-sdk-v0.23.1) — 2026-08-14


### Added

- **webvh**: Find DIDs a host serves that this VTA has no record of ([#976](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/976))

A DID can exist on a hosting server and nowhere in the VTA that owns it. The
  delete path says so out loud: `delete_did_webvh` calls the host first and, when
  that call fails, logs "continuing local cleanup but DID is now orphaned on the
  daemon" and removes the local record anyway. The host keeps serving a DID whose
  controller has discarded its keys, and nothing since then could tell you.

  Found the hard way: the hosting UI listed a DID, a delegated edit against it was
  refused with `did not found: SCID … not found`, and from the outside that reads
  as lost keys rather than an orphan.

      pnm did-mgmt dids reconcile --server primary

  Read-only, and repairs nothing on purpose — a host-only entry wants removing at
  the host, a local-only entry wants its publish retrying, and neither is safe to
  infer from a list. Naming them is the job.

  **Only the VTA can answer it.** The operator holds no credentials for the
  hosting server; the host has no view of the VTA's records. So the VTA
  authenticates with its own credentials, reads `GET /api/dids?owner=<its own
  DID>`, and compares against its local records.

  Three decisions worth the reviewer's attention:

  - **`owner` is always sent**, though the endpoint allows omitting it. A VTA that
    administers its own host *is* an admin caller, and the host answers an admin
    who names no owner with every DID on the server — reporting every other
    tenant's DID as missing locally.
  - **Matched on the host's slot id, not the DID.** A slot reserved but never
    published to has no DID at all and is exactly as orphaned as one that was.
    Pinned by a test.
  - **Super-admin, and DIDComm-only registrations are refused.** The host has no
    notion of VTA contexts, so its listing cannot be filtered by
    `has_context_access` the way `dids list` filters local records — and scoping
    the *result* instead would hide orphans from everyone, since an orphan has no
    local record to carry a context. The host's listing is REST-only, so against a
    DIDComm-only server this errors rather than returning an empty diff: "nothing
    to report" is the one wrong answer available, because it is the answer an
    operator stops looking after.

  ## The registry cost, stated plainly

  This adds one URI — `vta/webvh/servers/dids/0.1` — that the published registry
  has no spec for, so it lands on **both** drift registers: the per-family census
  in `vtc-service` (spec/vta 36 → 37) and the per-URI
  `UNSPECCED_DISPATCHED_URIS` in this crate, whose own rule reads "author the spec
  upstream — growing the allowlist is the wrong fix".

  It is added knowingly. The spec cannot come first from inside this repo: it
  needs a PR to trustoverip/dtgwg-trust-tasks-tf and a `trust-tasks-rs` release
  before the URI resolves, which is how every entry on that list arrived. The
  disposition is **spec under `vta/`**, recorded in `registry-drift-triage.md`
  beside `servers/{list,register,remove}` and for the same reason: the subject is
  the VTA's own view of a host it uses, and `did-management/did/list/0.1` is the
  host's listing rather than the comparison against local records. The nearest
  sibling shows the way out — `servers/domains/0.1` relays the same host's domain
  view, went upstream as dtgwg-trust-tasks-tf#171, and is on neither list as a
  result.

  The alternatives were weighed and are worse: a REST-only route is unreachable
  from a TSP-transport CLI, and folding this onto `webvh/dids/list/1.0` makes a
  local read do network I/O and grows a response shape most callers never want.

  The `did-hosting-ui` half — the warning beside the delegated-edit button, and
  the hint that names this command when the agent answers "not found" — is
  affinidi/affinidi-webvh-service#163.



## [0.23.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.22.0...vta-sdk-v0.23.0) — 2026-08-12


### Added

- **did-webvh**: Let a minted DID advertise TSP at the VTA's mediator ([#959](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/959))

A VTA-minted DID could never advertise TSP, whatever the VTA's own config
  said. `add_mediator_service` publishes the VTA's mediator as a
  `DIDCommMessaging` service and nothing else, so a caller wanting `#tsp`
  had to hand-build the service entry and pass it through
  `additional_services` — which means knowing the mediator DID, the one
  thing `add_mediator_service` exists so a caller does not have to know.
  Nobody did, so every persona-shaped identity is DIDComm-only by
  construction, and the both-ends transport rule can never resolve to TSP
  for one. TSP could be enabled end to end and the intersection would still
  be DIDComm.

  Surfaced by OpenVTC #211, where a join failed at the mediator and the
  applicant persona's document turned out to carry exactly one service
  entry.

  Adds `add_tsp_service` to the create-DID wire, honoured by
  `with_tsp_service` in `did_webvh/document.rs`. The entry points at the
  same mediator the DIDComm entry names — TSP advertises a mediator DID,
  not a transport URL (D8) — using the fragment and type the setup path and
  the runtime `services tsp enable` patcher already emit, so a document
  minted here, minted at setup, or patched later are the same shape.

  Two gates, neither redundant. The caller's flag is opt-in and
  deliberately not implied by `add_mediator_service`: a DID advertising a
  transport its holder cannot decode is unreachable over that transport,
  and only the caller knows whether the client behind the DID reads TSP
  frames. Ours is `[services] tsp` plus a configured mediator: a VTA whose
  own stack does not run TSP must not mint documents claiming it does,
  which is the failure this prevents rather than spreads. A caller-supplied
  `TSPTransport` entry wins over the injected one — matched on the service
  `type`, never the `#id` fragment.

  Additive on the wire in both directions: `skip_serializing_if` on the
  request and `Option` on the body, so an unset field serialises exactly as
  before and a VTA that predates it ignores the key.



## [0.22.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-sdk-v0.21.21...vta-sdk-v0.22.0) — 2026-08-12


### Fixed

- **vault**: Send entryId on vault release, from both the CLI and the MCP bridge ([#948](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/948))

* fix(vault): use entryId instead of id in vault release payload

  cmd_vault_release was constructing the vault/release/0.1 Trust Task
  payload with key `id`, which fails schema validation. The schema
  requires `entryId` (matching VaultReleaseBody's camelCase
  serialisation on the server side).

- **provisioning**: Relay the holder's bootstrap VP as raw JSON ([#949](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/949))

A relayer is usually not the holder — the air-gap onboarding flow exists
  precisely so it isn't — so `pnm bootstrap provision-integration` forwards
  a document some other process signed. It parsed that document into a
  typed `BootstrapRequest` and let serde re-render it on the way out, so
  the maintainer verified bytes the holder never signed. Both transports,
  every relayed request.

  Same defect as #946 one layer up, and with the same trigger: #917 moved
  `ask.type` to the 0.2 camelCase tag, so a holder on vta-sdk < 0.21.11
  (did-hosting `VTI-Cypress-RC-1` among them) has its own valid signature
  rewritten in transit and rejected as a forgery at the far end. #946 fixed
  the two maintainer-side surfaces that re-serialised; this is the client
  side of the same rule, and the two together close the flow.

  `ProvisionIntegrationRequest.request` and `provision_integration_didcomm`
  now take `serde_json::Value`. **Breaking** for anything constructing that
  struct. Callers that signed the VP themselves — every SDK runner — go
  through the new `BootstrapRequest::to_signed_wire_value`, where serde
  output and signed bytes are the same document by construction; pnm keeps
  a typed view purely to read `contextHint` and relays the raw JSON.

  `provision_integration_didcomm`'s doc comment already promised the VP was
  "left byte-identical either way". It now is.

  The existing relay tests could not have caught this: they assert the body
  carries `serde_json::to_value(&vp)`, which is the SDK's rendering
  compared against itself and true however badly the relayer mangles a
  foreign document. The new test starts from a VP this crate did not
  render, relays it under both spec versions, and requires it to arrive
  byte-for-byte and still verify. It also asserts the fixture actually
  diverges from this crate's serde output, so it fails loudly rather than
  going quietly vacuous if the casings ever converge.

- **provisioning**: Verify the bootstrap VP as received, not re-serialised ([#946](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/946))

`vta bootstrap provision-integration` and `POST /bootstrap/provision-integration`
  rejected a validly-signed request from any holder on vta-sdk < 0.21.11:

      Error: verify BootstrapRequest: proof verification failed:
      verify VP: signature invalid for cryptosuite EddsaJcs2022

  Both called `BootstrapRequest::verify()`, which re-serialises the typed
  struct and re-imposes this crate's casing on the bytes the holder signed.
  #917 flipped `ask.type` to the 0.2 camelCase tag (`templateBootstrap`),
  so a 0.1 holder's `TemplateBootstrap` — accepted on the way in by the
  serde alias, then re-emitted camelCase on the way to the verifier — no
  longer matched its own signature. The failure is indistinguishable from
  a forgery, which is what makes it expensive to diagnose in the field.
  did-hosting `VTI-Cypress-RC-1` pins vta-sdk 0.21.9 and hits this on
  every offline provision.

  #917 fixed exactly this defect at the Trust-Task handler and the DIDComm
  handler already did the right thing; the offline CLI and the REST route
  were the two surfaces left behind. Both now go through `verify_value`
  over the bytes as received, which is what its own docs require of any
  surface taking a request from elsewhere. The REST body consequently
  carries `request` as raw JSON — deserialising it into the typed struct
  at the extractor is what discarded the signed bytes. `deny_unknown_fields`
  still rejects smuggled fields, one layer in, inside `verify_value`.

  Tests cover the direction that was missing. #917's fixture signed the
  0.2 casing against a 0.2 maintainer; nothing exercised an *older* holder
  against a current one, which is the far commoner deployment shape. Added
  a PascalCase-signed fixture at both layers, plus a test pinning that
  `verify()` breaks such a request — so a call site reverting to it fails
  rather than shipping.

  Note for follow-up: the relayer has the same defect one layer up.
  `ProvisionIntegrationRequest.request` is a typed `BootstrapRequest`, so
  `pnm bootstrap provision-integration` re-serialises a request file before
  sending it (both transports), and the maintainer never sees the signed
  bytes. `provision_integration_didcomm`'s doc comment already claims the
  VP is "left byte-identical either way", which the code does not honour.
  Fixing it changes a published vta-sdk struct field, so it is deliberately
  not bundled here.


