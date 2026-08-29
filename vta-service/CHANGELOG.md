# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.23.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.22.0...vta-service-v0.23.0) — 2026-08-29


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



## [0.22.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.21.0...vta-service-v0.22.0) — 2026-08-28


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

- **compliance**: Enforce SPEC §7.2's flag-driven checks, and sign what we send ([#1146](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1146))

The VTA enforced none of the four checks a *Trust Task specification* declares
  for itself. It now enforces all of them, and the SDK produces documents that
  satisfy them.

    * item 5b — `recipient` REQUIRED: all 109 dispatched specs
    * item 7a — `proof` REQUIRED: 72 of them
    * item 8  — audience binding
    * §7.3 17 — `issuedAt` REQUIRED: 70 of them

  `spec_policy_for` (trust-tasks-rs 0.17.1, trustoverip/dtgwg-trust-tasks-tf#321,
  authored for this) keys those constants by Type URI. That is what makes the
  check reachable at all: `enforce_spec_policy` reads them off `P`, and the
  dispatch spine holds a `TrustTask<Value>`. The alternative was a 109-entry
  URI→type table in this repo, duplicating what the codegen already emits.

  The spine's own comment claimed "each slice's typed handler runs it after
  `parse_payload`". No handler did — that comment was the only occurrence of
  `enforce_audience_binding` in the repository.

  **This is an auth-model change, not a wire-format one.** A bearer token
  authenticates the connection; §7.2 item 7 admits no transport substitute, so
  every producer must now sign every document. `vta-sdk` gains `ClientIdentity`
  (client DID, its key, the VTA's DID) and signs in `dispatch_trust_task`.
  `SessionStore::connect` supplies it from the stored session — re-read *after*
  `ensure_authenticated`, because a session that needed rotation now holds a
  different DID and key, and signing with the pre-rotation pair produces a
  document whose issuer no longer matches the identity its token authenticates.

  `issuer` and `recipient` are set in `build_task_document` rather than at each
  call site, for the reason `issuedAt` already was: a member the framework
  requires of every document belongs to the one function that builds every
  document. Signing is unconditional rather than keyed on the flag — a proof on a
  task that merely RECOMMENDs one is legal and strictly more attributable — but
  it must never happen without an in-band recipient, and both come from the same
  `ClientIdentity` so they cannot come apart.

  Test identities are now derived from one-byte seeds. `did:key:zTestAdmin` was
  not a `did:key`: nothing resolves it and no document issued by it can carry a
  verifiable proof. That was fine while proofless documents were accepted. The
  seed gives a DID and the key behind it from one place, which is what item 6
  needs — it rejects a document whose in-band issuer disagrees with the
  transport-authenticated identity, so a test minting a token for one DID and
  signing with another is refused for that rather than for what it meant to check.

  One real bug surfaced in the fixtures: `delegated_consent_e2e`'s `sign_as` did
  not clear an existing proof before signing. `prepare_sign_input` hashes the
  document as given, so signing over one that already carries a proof yields a
  signature covering bytes no verifier reconstructs — it fails as `proofInvalid`,
  which reads like a key problem and is not one.

  Coverage holds at 88/109 with zero response-conformance violations.

- **tasks**: Catch up to the registry on vault 0.3, device/wipe 0.2 and credentials/issue 0.2 ([#1145](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1145))

Five of the six families vta-sdk lagged the registry on. The sixth,
  `provision/integration/0.3`, is not here: its response schema could never
  validate — `required` named a `digest` the 0.2→0.3 rename had already removed
  from `properties`, against `additionalProperties: false`. Fixed upstream in
  trustoverip/dtgwg-trust-tasks-tf#324; VTI adopts it once that publishes.

  **vault/{list,get,upsert} 0.3.** `AttachmentRef.sha256` — hex, with SHA-256
  pinned by an `^[0-9a-f]{64}$` pattern — becomes `digestMultibase`, a multibase
  multihash that names its own algorithm. Worth stating plainly: nothing in this
  service has ever constructed an `AttachmentRef`. Every site is `vec![]` and
  `vault/upsert` only carries forward whatever an entry already had, so the
  member has never reached the wire and this is a type-level rename today. The
  wire contract is what changes, and it changes so that moving off SHA-256 later
  is a value change rather than another schema revision.

  **device/wipe 0.2.** `cache-and-keys` → `cacheAndKeys`, the same recasing the
  rest of the device slice took. Its constant carried "No 0.2 spec exists
  upstream; this stays on 0.1" while `specs/device/wipe/0.2` had been published
  for some time. The replacement comment says so: a comment asserting an absence
  is a claim about the registry that nothing re-checks, and it is why nobody
  looked again.

  **vta/credentials/issue 0.2.** The request payload is unchanged. The response
  stops restating the shared `IssuedCredential` inline and composes it through
  `allOf` + `unevaluatedProperties` — same members, same required set, identical
  wire form. So the two versions share a dispatch arm rather than a transform.

  The edge-transform table goes from one wire URI per spec to a list.
  `vault/*` 0.3 differs from 0.2 only in `AttachmentRef`, which is not an enum
  value and not at any path the transform touches — so it down-converts to the
  same canonical handler by the same casing rules. Giving it its own row would
  have duplicated every path and left the two to be kept in step by hand.

  `upconvert_response` now answers as the version the caller *sent*. With several
  wire URIs per spec, retyping a response to a fixed one would be refused by a
  client validating against the version it asked for.

  Two guards needed widening, and both were right to fail first:

  * `superseded_tasks_are_dispatched` did not count an edge-transformed URI as
    served. Its premise is that a row whose counter can never move reads the same
    as "safe to retire" — but the counter *does* move for these, because
    `dispatch_trust_task_core` reads the superseded row from the URI as it
    arrived, before the down-convert. The successor half of the pair already
    accepted them.
  * the wire/deprecation parity test checked only the 0.1 hop. A spec accepting
    0.1, 0.2 and 0.3 needs a row per superseded version, or the middle one is
    retired on no evidence at all.

  `ALL_URIS` and `retry_safety` carry the four new URIs; the census caught their
  absence, which is what it is for.

- **vta**: Close the CI cache class, map the 0.5.0 lifecycle, cover more tasks ([#1134](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1134))

Three things belonging to the same release.

- **vta**: Mint the consent ceremony's correlator instead of deriving it ([#1133](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1133))

* feat(vta): mint the consent ceremony's correlator instead of deriving it

  Framework 0.5.0, *Identifier correlation and linkability*: `id`, `threadId` and
  `ceremony.enactment` MUST be freshly minted and unguessable, and MUST NOT be
  derived from subject data.

  The `task-consent/granted` notice threaded on `wire_digest` — a function of the
  task payload, and the same string the document carries as `payloadDigest`.

  The challenge is 256 bits of randomness, so the digest is not guessable from
  the payload; this is not the "UUIDv5 over a subject identifier" case. The
  mediator is the exposure. `threadId` is routing metadata, and the mediator also
  forwards documents carrying `payloadDigest`; with the same value in both it can
  tie the routing it performs to the digest it carries and link the refusal, the
  approval pushes and the notice into one ceremony with named counterparties.

  `PendingTaskConsent` gains a minted `correlator`, created alongside the
  challenge. The notice threads on it and the body still carries `payloadDigest`
  unchanged, so a requester matching on the digest is unaffected. The requester
  is told the correlator in the `auth:consent_required` refusal beside the digest
  it already receives.

  Smaller than it first looked: the request push to approvers already threaded on
  the request document's own id, so only the requester-facing notice was derived.
  The notice is produced but never consumed in this workspace and is explicitly
  non-load-bearing — the grant check at re-submit is the real gate.

- **vta**: Bound the error `details` member ([#1131](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1131))

Framework 0.5.0, *Bounding `details`*. `details` was the one error-payload
  member with no size bound, travelling in the direction no producer-side bound
  reaches: a producer caps what it sends, nothing caps what comes back.

  This service had a live instance. A policy denial puts the Rego module's
  `explanation` on the wire, and that string is authored by whoever wrote the
  policy with no length anybody checked.

  The bound is 4096 bytes of JCS or 16 immediate members — 0.5.0's default where
  a specification declares none — applied in `reject_with`, the single funnel
  every rejection passes through, rather than at the thirty `details: Some(...)`
  construction sites. A new site cannot be added that skips it.

  An oversized `details` is ignored and never grounds to discard the `code`: the
  code is what the receiving party needs, and dropping the rejection because its
  annex was too long would turn a verbose policy into an unexplained failure. An
  uncanonicalisable `details` is dropped too — it cannot be measured, so it does
  not go out.

- **vta**: Stop error messages from being a probing oracle ([#1130](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1130))

Framework 0.5.0 makes the message-sanitization rule normative for every code,
  not just `identityMismatch`: a `message` MUST NOT reveal consumer-internal
  state, the contested value of a mismatched party, or resolver, verifier, or
  key-status internals. Every rejection is emitted on the same path, to the same
  possibly-unauthenticated party, generally before any authorization decision has
  been reached.

  This service violated two of the three.

  `app_error_to_reject` passed `AppError::Internal`'s cause into the `message`
  verbatim, so a caller learned "ATM not configured — server cannot pack DIDComm
  envelopes" or "log entry has no update_keys" — the deployment's shape, its
  configuration, and which invariant just broke. The catch-all arm was the
  quieter half: it rendered whatever `Display` an error happened to have, so a
  variant added later would publish itself with nobody choosing to. Both now land
  on one fixed string and log the cause for the operator.

  `DiProofError`'s `Display` rendered the underlying verifier error, and that
  reaches the wire through `PermissionDenied`. A caller could read which
  cryptosuite ran and how verification failed. The detail moves to a `cause()`
  that is deliberately not reachable through `Display`, since the defect was that
  the wire rendering and the operator rendering were one function.

  `notFound`, `malformedRequest` and `permissionDenied` pass through unchanged:
  they describe the caller's own request back to it, which is not
  consumer-internal state.

  `an_internal_error_does_not_say_internal_error_twice` asserted the cause was on
  the wire. Its subject was a doubled prefix, which the fixed string also
  settles; it is now `an_internal_error_reveals_no_internal_state`, joined by
  `the_catch_all_arm_is_opaque_too`.

- **vta**: Bound the replay record by the acceptance window, not by capacity ([#1127](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1127))

The follow-up #1126 named. VTI now honours SPEC §7.2's same-bound rule: the
  acceptance window and the duplicate-execution record's retention are one
  instant, derived from one policy.

  #1126 shipped the ReplayGuard without a window, leaving the record bounded by
  InMemoryReplayGuard's capacity. That is not "no expiry so entries live
  forever" — it is LRU, which makes the window load-dependent: on a quiet service
  the protection is effectively unbounded, but under burst the eviction horizon
  can fall below any sensible acceptance window and a replay executes a second
  time. The defence was weakest exactly when the service was busiest.

  Ten minutes rather than the library's five: this service routes over a mediator
  that can hold a message while a recipient reconnects. It is the same 600s the
  retired replay::check_and_record used as its dedup TTL, now bounding acceptance
  as well as retention.

  Most of the diff is the fixture migration the window forced, and none of it was
  the policy being wrong. 65 envelopes carried no issuedAt at all — with a window
  set, a document with neither issuedAt nor expiresAt cannot be placed in time
  and is refused, which is what §7.2 requires. 12 more carried fixed literals
  already days stale.

  One subtlety: the first pass used to_rfc3339(), which renders the offset as
  +00:00 where TrustTask's typed DateTime<Utc> round-trip renders Z. That broke a
  signed fixture's proof — a document signed in one spelling and verified after
  the other is a different document, which is the §8.4 distinction #1126 added
  idConflict for, arriving as a signature failure instead. Every stamp now uses
  to_rfc3339_opts(SecondsFormat::Secs, true).

- **vta**: Adopt ReplayGuard and FreshnessPolicy, deleting the hand-rolled pair ([#1126](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1126))

The last of the three stopgaps #1121 unblocked. Deletes trust_tasks/replay.rs
  and the hand-rolled freshness bounds from #1117.

  They land together because ConsumeChecks bundles them in one argument: SPEC
  §7.2 makes the acceptance window and the replay record's retention the same
  bound, and splitting them is how a deployment ends up with a ten-minute record
  against an unbounded window believing it has a replay defence. This service had
  exactly that.

  The retired module keyed on (actor, id) and kept no digest, which cost two
  things. It never produced idConflict — item 11 requires a different document
  under an accepted id to be rejected, and with no digest that case was silently
  absorbed as a retry, the one outcome §7.2 and §8.4 both rule out. And the key
  was wrong: §7.2 fixes it as the document id alone, so actor-scoping let two
  callers each spend the same id. A duplicate is also no longer answered with
  taskFailed, which §7.2 forbids outright.

  A failed outcome releases the claim, mirroring the idempotency layer beside it;
  a successful one records its response so a retry is answered with the result.
  The Err arm fails closed with a retryable unavailable, and the non_exhaustive
  ReplayVerdict gets an arm that refuses rather than executes.

  No acceptance window yet, and that was measured rather than assumed:
  with_max_age(10 minutes) scoped to consequential tasks failed 41 assertions
  across 10 suites with expired, because the suite is full of documents stamped
  hours or days in the past. Fixing those alters what the service accepts and
  belongs in a change whose subject is the window.



### Fixed

- **consent**: Sign the approve-request prompt sent to an approver's device ([#1180](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1180))

`consent/approve-request/0.1` was constructed as a bare `id` / `type` /
  `issuedAt` / `payload` document and buffered to an approver's mediator for
  delivery to their phone, where a human is asked to approve something. It
  carried no proof, so nothing the device could check authenticated it.

  This is the odd one out rather than a deliberate exception. The sibling
  task-consent request in `consent_request.rs` already signs with this key and
  cryptosuite, and the step-up prompt's mobile parser refuses to render
  without a verified proof from an enrolled issuer
  (`vta-mobile-core::task::parse_step_up_request` — "no valid proof from an
  enrolled executor, no prompt"). Both end up in front of a person.

  `issuer` and `recipient` come with the proof, not as decoration: SPEC §7.2
  item 5b makes `recipient` REQUIRED and item 6 requires the in-band issuer to
  match the transport identity. A proof over a document naming neither party
  is replayable at a different approver, which is most of what the signature
  was supposed to buy.

  Fails closed. The wake path is best-effort and already warns on a failed
  buffer, leaving the approver to mediator pickup; an unsignable prompt takes
  the same route. "No prompt" is recoverable in a way "unverifiable prompt"
  is not.

  ## Sequencing

  This changes nothing about security on its own, because nothing verifies it
  yet, and that is the reason to land it now rather than later: the fleet has
  to be signing before devices can require a signature. Device-side
  enforcement in `vta-mobile-core` follows, and must not ship first or it
  breaks every VTA that has not deployed this.

  Publishing the spec with `proof` REQUIRED is the third step, so the
  requirement is normative rather than local convention. Tracked in #1177.

  The test runs the real verifier over the document as sent rather than
  asserting a `proof` member exists — a signature copied from another document
  would satisfy the weaker check — and pins `issuer` and `recipient`.
  Confirmed it has teeth by swapping the recipient DID and watching it fail.

- **services**: Let enable reconcile a config the document does not match ([#1150](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1150))

Coverage 93 to 97 of 109 — the `services/{enable,update,disable,rollback}`
  write paths — and a state they could not get out of.

  `enable` refused when the service was on in the live config **or** advertised
  in the published document. `update` requires it on in **both**. So config-on
  with a silent document was unmanageable: neither operation would touch it, and
  the operator's only route out was to edit the config by hand.

  That state is reachable, and not exotically. Re-point `vta_did` at a freshly
  minted DID and you have it — the new document advertises nothing while the
  config still says REST is on. Restoring a config without its log does the same.

  "Already enabled" now means enabled in both places, which is the only reading
  under which there is nothing to do. Where the two disagree there is work, and
  this is the operation that does it. Both disagreement directions become
  recoverable; the no-op case is still refused.

  The coverage is what found it. These four were the last block with a shared
  cause: they publish a new WebVH LogEntry for the VTA's *own* DID, so
  `load_vta_doc_state` needs a record and a log for it — and the ordinary fixture's
  `vta_did` is a self-resolving `did:key`, which has neither. No amount of
  test-writing reaches them from there. Minting one against the stub host and
  pointing `vta_did` at it is the unlock, which is why this is one test rather
  than four.

  The client is rebuilt after the flip. A document's `recipient` must name the
  consumer it is sent to, and the VTA's identity just changed — reusing the old
  client fails on `wrongRecipient` before reaching anything under test.

  The two unit tests that encoded the old rule now assert the new one, and assert
  it precisely: the fixture seeds no webvh record, so reaching
  `VtaDidRecordMissing` is what proves the config check no longer short-circuits
  ahead of the document. Asserting success would need a fixture modelling a fully
  published VTA, which is what the stub-host round-trip is for.

- **trust-tasks**: Verify the proofs we require, and cover the canonical device lifecycle ([#1149](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1149))

**SPEC §7.2 item 7 has two clauses. Only the second was implemented.**

    "If the document carries a `proof` member, verify it per §4.7 against the
     in-band `issuer` and reject the document with `proofInvalid` on verification
     failure. Independently, if the specification declares `proof` REQUIRED and
     no `proof` is present, reject with `proofRequired`."

  #1146 added the second. The first was never there, and that is the worse way
  round to have it: a caller attaches a proof *because* the task demands one, and
  until now any bytes in the member satisfied the demand. A document signed by a
  key its issuer does not control reached the handler — proven by the test added
  here, which sent one signed by an unrelated seed and watched it fail on
  `session not found` rather than on the proof.

  The verifier already existed. `vti_common::auth::di_proof::verify_trust_task_proof`
  returns the cryptographically-proven signer, and `step_up` and `task_consent`
  have called it for their own gates all along. The spine did not, so every other
  task took the issuer's word for who signed.

  Two checks, because a valid proof is not the same as a valid proof *by the
  issuer*: the proof must verify, and the DID it verifies as must be the
  document's `issuer`. Without the second, a signature would establish only that
  somebody signed something.

  `step_up` and `task_consent` keep their own calls. They bind the signer to a
  *specific* party — the approver — which is a stronger claim than "the issuer
  signed this" and not one this can make for them.

  **Coverage 88 → 93 of 109.** The device family's canonical 0.1 URIs, plus
  `disable` and `wipe`, which have no 0.2 form.

  Not a duplicate of the existing 0.2 walk. A 0.2 request is down-converted to
  the 0.1 handler and its response up-converted back, so driving 0.2 never
  produces a `…/0.1#response` and never exercises the branch that answers a
  caller who asked canonically. Two paths through the spine; one was tested.

  One fixture needed a real second identity. `idempotency_trust_task`'s
  "other caller" was a hand-written DID with no key: the document claimed that
  issuer and was signed by the *first* caller, and the VTA took its word for it.
  It cannot now, which is the point.

- **deps**: Declare the spec families this VTA validates against ([#1148](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1148))

The workspace asks `trust-tasks-rs` for `default-features = false, features =
  ["validate"]` and receives every spec family regardless, because
  `affinidi-messaging-sdk` -> `affinidi-tdk` enables the default feature and cargo
  unions them. The entire schema index — the thing `validate_payload` checks
  payloads against and `spec_policy_for` reads SPEC §7.2's constants from —
  arrives by luck rather than by request.

  Both of those fail **open**. `validate_payload` dispatches unvalidated when it
  knows no schema (unless `policy.require_payload_schema` is set), and
  `spec_policy_for` returning `None` skips the recipient/proof/issuedAt checks
  entirely. So the day any crate in that chain set `default-features = false`,
  this VTA would have stopped validating payloads and stopped enforcing §7.2,
  with a single `debug!` line between that and nobody noticing.

  `all-specs` is now declared. No behaviour change today — the features were
  already resolving on — which is the point: the resolved set is unchanged and
  the reason it resolves is no longer somebody else's business.

  The test asserts the index is populated, for three URIs across three families.
  Worth being exact about what it proves: it fails when the index is empty, which
  is the outcome that matters, and it *cannot* fail when the declaration is
  removed while the transitive path still supplies the families — cargo unions
  features, so from inside the build the two are indistinguishable. That is the
  right coverage anyway. An index populated by either route is a working VTA;
  this fires on the day neither route supplies it.

- **sdk**: Give every authenticated client its identity, and adopt provision/integration 0.3 ([#1147](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1147))

#1146 made every producer sign, and left seven production paths building
  clients that cannot. Each authenticates, takes the token, and drops the DID and
  key on the floor — so every task they dispatch is refused for a missing
  `recipient` and `proof`. `SessionStore::connect` was fixed; nothing else was,
  because no test drives those paths against an enforcing VTA.

- **auth**: Stop revoke-session telling a stranger the session exists ([#1141](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1141))

Coverage 87 to 88 of 109, and a disclosure the spec forbids in as many words.

  `auth/revoke-session/0.1` had three answers where it should have one. A session
  that is not there rejected with `TaskFailed "session not found: {id}"`; a
  session belonging to someone else rejected with `PermissionDenied`; only the
  caller's own succeeded. So anyone holding a bearer token could enumerate session
  ids and read existence straight off which refusal came back.

  The `notOwner` error code says, in its own definition: "The auth service MUST
  NOT reveal whether the session exists at all when the producer is not its
  owner."

  Meanwhile the response schema says "Zero is a valid outcome (e.g. the named
  sessionId was already revoked)", the prose adds that producers "SHOULD treat
  zero as 'the post-state is what you asked for', not as an error", and
  `vta-sdk`'s own `retry_safety` table has this task down as `RetrySafe` — which
  it was not, because retrying a completed revoke rejected.

  Both rules hold together only if "not yours" and "not there" answer
  identically, so both now return `revokedCount: 0`. The count is literally true
  either way: zero sessions were invalidated by this call. This handler therefore
  never emits `notOwner` — emitting it only when the session exists is precisely
  the disclosure the code's own definition forbids, and an error code is a
  registry entry, not an obligation.

  Non-disclosure is not a licence to act: a session the caller cannot touch is
  left alone, and the test asserts it is still there afterwards. The refusal is
  recorded in the audit trail (`outcome = "no-op"`) and a `warn!` line, neither of
  which is the caller's to read. The authorisation rule itself is unchanged —
  owner or admin — and an admin still reaches another subject's session.

- **consent**: Stop dropping the approver's label, and make revoke idempotent ([#1139](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1139))

Coverage 81 to 87 of 109 — the whole `consent/*` family — and three
  divergences from the published schemas that covering it turned up.

  **The approval prompt lost its label.** `consent/request` declares
  `displayHint`: the operator-facing name for the conversation, sent precisely
  because `conversationRef` is an opaque handle by design. The SDK sent it. The
  VTA's `RequestPayload` had no field for it, so serde dropped it, and the wake
  prompt built for the approver carried `{subject, scope, challenge}`. An
  approver was being asked to allow or deny `sig-1a2b3c4d`. Nothing failed —
  that is why it lasted.

  **`firstMessageDigest` existed only in the schema.** Declared on the same
  payload, absent from the SDK body and from the VTA's, so no part of the stack
  could send, store, or name it. It binds the prompt the approver answered to
  concrete content. The VTA never sees the message, so carrying it *is* the
  implementation: the bridge checks the digest, the VTA records what was shown.

  **`consent/revoke` could never emit a status its own schema promises.** The
  published response declares `"revoked" | "notFound"` — "`notFound` = no grant
  existed for the subject" — and the VTA rejected instead, so a conforming
  producer written to receive that value never could. It is also the answer the
  caller wants: revoke's post-condition is "no grant for this subject", and with
  none stored that already holds. An operator revoking twice, or racing another
  operator to the same grant, got an error for the outcome they asked for. The
  `consent/revoke:notFound` error code stays declared upstream for a consumer
  that cannot answer at all; it is not this case.

  `consent_request` now takes its body. The schema declares three optional
  members and two are hints, so the positional form was four `Option<&str>` in a
  row with `displayHint` and `contextHint` adjacent and interchangeable to the
  compiler — and it broke every time the schema grew a member, as it just did.

  Both conformance witnesses for the request now set every optional member. They
  left the hints `None`, which serializes them away, so the fixtures proved the
  required trio and nothing about the optional members' encoding —
  `firstMessageDigest` is a `DigestMultibase`, and an omitted member cannot fail
  its pattern.

  The coverage test drives the six as the ceremony they are rather than six
  shapes in isolation: `approver-set` is not setup for it, it is the step that
  makes `request` resolve an approver at all. The caller is minted with exactly
  one context, because the no-`contextHint` fallback goes through
  `default_context()`, which answers `Some` only then — an admin minted with
  `vec![]` has unrestricted access and no default, and would leave that path
  dead.

- **vta**: Say which fact refused a retire-orphan, and cover the slot paths ([#1138](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1138))

Coverage 79 to 81 of 109, and a misleading refusal message found by trying to
  make the task succeed.

  `servers/retire-orphan` routes two very different facts to the same
  `NotOrphaned` variant, and the message asserted one of them for both: "slot X
  has a record in this VTA, so it is not an orphan … use webvh/dids/delete for
  one it still controls."

  The variant already carries `did: Option<String>`, which distinguishes them.
  `Some` means the VTA still controls the slot, and the message was right.
  `None` means the slot is not in the host's listing at all — so the message told
  an operator the VTA held a record it had never heard of, and pointed them at
  `dids/delete` for a DID that does not exist. Both now say what happened and
  name different next actions. The `Option` was there the whole time; only the
  message ignored it.

  The stub host now answers `GET /api/dids` with one slot the VTA has no record
  of, rather than an empty list. That makes both reconcile arms non-empty in one
  call — host_only is the stub's slot, agent_only is the minted DID — where an
  empty list proved one arm and a list echoing the VTA's own records would prove
  neither. It is also what makes retire-orphan reachable: a slot is retireable
  precisely when it is host-only.

  Covers `vta/webvh/servers/{retire-orphan,remove}`. `remove` runs last, after
  `dids/delete`, because removing the server registration invalidates every path
  above it — the order an operator actually uses.

- **vta**: Refuse a swap-key without linkProof by name, not as malformed ([#1137](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1137))

Coverage 77 to 79 of 109, and a fifth request-side divergence.

- **vta**: Carry ecosystem-local capabilities under ext, not in the closed enum ([#1136](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1136))

Coverage 76 to 77 of 109, and a real conformance defect found by covering the
  device family.

  `device/register/0.2` put `credentialWrite` in the response's `capabilities`
  array. The published `Capability` enum does not define it, so the response
  failed its own schema. This was already known and half-fixed: a filter dropped
  `sign-trust-task` with a comment saying it is "absent from the wire schema's
  closed `Capability` enum". `CredentialWrite` was added later, the filter was not
  extended, and it went straight out.

  Fixed by carrying both under `ext["org.openvtc"].capabilities` rather than
  dropping them. Dropping is what the old filter did, and it is lossy in the
  direction that matters: omitting a capability from a listing is a safety claim,
  and it was not a true one — the device held `sign-trust-task` and the response
  said it did not. SPEC §4.5.1 provides the extension slot and `DeviceBinding`
  declares one, so no upstream change is needed; widening the framework's closed
  vocabulary with two ecosystem-specific concepts would be the wrong fix anyway.

  The filter is now positive: `PUBLISHED_CAPABILITIES` lists what the published
  enum defines and everything else is local, so a capability added tomorrow lands
  in `ext` by default rather than leaking one variant at a time.

  The local values are camel-cased at the source, because `wire_v0_2` re-cases
  kebab to camel only at declared enum field paths and an `ext` member is
  invisible to it — otherwise the response would answer `deviceAdmin` beside
  `sign-trust-task`, in two dialects at once.

  Two blockers recorded in earlier PRs turned out to be one line each.
  `passkey-vms/enroll-challenge` needs `public_url`, not a WebAuthn relying
  party — the RP is derived from the public origin. `device/*` needs one ACL
  row, not a provisioned integration — the entry is the enrolment the device is
  completing. Both notes were mine; a refusal that names a procedure reads as
  needing the whole procedure when it needs that procedure's residue.

- **vta**: Re-case the extended error codes the Trust Tasks registry moved ([#1122](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1122))

* fix(vta)!: emit the re-cased extended error codes the registry now declares

  trustoverip/dtgwg-trust-tasks-tf#279 re-cased 200 extended error-code local
  parts to lowerCamelCase per SPEC §4.10 rule 4 — only the part after the `:`
  moved, the namespace is unchanged. This service still produced the snake_case
  spellings for 32 of them, so every one of those rejects carried a code the
  registry no longer defines and no conforming consumer can branch on.

  Every site here is an **emitter**: this repo decides what to send, and the
  registry decides what is correct to send, so each moves to the new spelling
  with no compatibility arm. The matcher side — where this repo reads a code a
  peer produced and cannot control that peer's deploy order — is handled
  separately in the following commit.

  Three of the vault emitters build their namespace by interpolation
  (`vault/{verb}:not_found`, `vault/{verb}:version_conflict`,
  `vault/{op}:not_found` in `vault_not_found`, `check_expected_version` and
  `refuse_if_not_active`), so the codes they produce do not appear as literals
  anywhere. Those helpers cover `vault/delete:{notFound,versionConflict}` and the
  `notFound` conflation the three consumer-facing use paths rely on for
  enumeration resistance.

- **vta**: Take keyId from the wire instead of minting one ([#1123](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1123))

First of the three stopgaps #1121 unblocked. `keys/create/0.1` publishes
  `keyId` as of trust-tasks-rs 0.12.1 (dtgwg-trust-tasks-tf#275), so the caller
  names the key and the binding no longer has to invent one.

  #1118 minted `internal-<uuid>` at the binding for an internal key. That was a
  deliberate deviation from a SHOULD I wrote in #275 — a maintainer offering
  internal keys and receiving no `keyId` SHOULD reject — taken because the
  alternative was a security feature nobody could use: an internal key has no
  derivation path to be named after, the operation layer refuses one without an
  id, and the wire had no member to carry it. The comment at that site said to
  delete it when the bump landed.

- **vta**: --internal creates an internal key ([#1118](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1118))

`pnm keys create --internal` printed a non-recoverable-key warning, required
  the operator to type "i understand this key cannot be recovered", and then
  created an ordinary seed-derived key — recoverable from the mnemonic, included
  in backups, exportable. The operator was told the opposite of what happened.

  `CreateKeyRequest` carries `internal`, `key_id` and `derivation_path`; the CLI
  set them and `VtaClient::create_key` built its wire body with `internal: None`
  hardcoded, `key_id` never read, and `derivation_path` as `unwrap_or_default()`
  — `""` for absent, which worked only because the operation layer reads `""` as
  absent. The operation layer was always right: `derivation_path` is an `Option`
  there that auto-derives, and `internal` short-circuits to a CSPRNG key.

  It could not have worked even with the flag forwarded. The spine rejected the
  document, because `keys/create/0.1` was `additionalProperties: false` with no
  `internal` member (fixed upstream in dtgwg-trust-tasks-tf#269, which also added
  `internal` to `KeyOrigin` — the value that makes the outcome checkable); and an
  internal key needs an explicit `key_id`, which neither the wire type nor the
  specification had (dtgwg-trust-tasks-tf#275).

  Forwards `internal` and `derivation_path`, makes `CreateKeyBody`'s
  `derivation_path` optional to match the specification and the operation layer,
  and mints a `key_id` for an internal key at the trust-task binding, which has
  no `keyId` member to carry one yet.

  That minting is a deliberate, temporary deviation from a SHOULD in the
  specification, taken because `keyId` needs trust-tasks-rs 0.12.1 and this
  workspace cannot move to 0.12: `affinidi-messaging-sdk` 0.19.12 pins
  `trust-tasks-rs ^0.11` and `vta_sdk::acl_setup` hands it a generated
  `MediatorAcl`, so two nodes in one graph fail to compile. The id is returned on
  the record and `keys/rename/0.1` can change it; the site says to delete the
  branch when the bump lands.

  `an_internal_key_is_actually_internal` asserts `origin == "internal"` — the
  check the CLI already made and that always silently failed.



### Chore

- **deps**: Aes-gcm 0.11, and stop the nonce conversions panicking ([#1173](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1173))
- **sdk**: Release vta-sdk 0.30.0 for the added CreateKeyBody field ([#1156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1156))

`CreateKeyBody` gained a `key_id` field while the crate stayed at 0.29.0.
  The struct is exhaustively constructible through the public API, so an
  existing literal no longer compiles — a breaking change under 0.x rules,
  which the semver report has been flagging as its one real finding
  (195 pass, 1 fail) since the field landed.

  Bumps the crate and the nineteen intra-workspace requirements that pin it,
  so `cargo check --workspace` still resolves the path copy and a consumer
  resolving from the registry gets a version that admits the break.

- **deps**: Move VTI to trust-tasks-rs 0.17 ([#1144](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1144))

Every `trust-tasks-*` pin to 0.17, plus the TDK crates that had to publish
  first: `affinidi-tdk` 0.10, `affinidi-messaging-sdk` 0.21,
  `affinidi-messaging-test-mediator` 0.4 (affinidi/affinidi-tdk-rs#744). Two
  `trust-tasks-rs` versions in one graph fail to compile, so the messaging stack
  had to move before this could.

  Breaking for `vta-sdk` consumers, which is why the `!`. 0.17 marks the
  generated payload, response, component structs **and enums**
  `#[non_exhaustive]`, and those types sit in this crate's public API — a
  consumer that builds one with a struct literal, with or without
  `..Default::default()`, must move to the generated builder and to 0.17 in the
  same change.

  Struct literals become builders; matches gain a wildcard. That is what lets the
  registry add an optional member or an enum variant without breaking every
  consumer that spelled out the old list, and the cost is that "is every required
  member set?" moves from compile time to the builder's conversion. Every call
  site here sets its required members explicitly.

  The wildcard arms are decisions, and they went different ways:

  * `step_up`'s `evidence` match **refuses**. It chooses which cryptographic gate
    to verify, so falling through to the did-signed arm would check a gate the
    approver never presented and report the step-up satisfied on evidence this
    VTA did not understand.
  * `services/{enable,update,disable,rollback,get}` **refuse** an unknown service
    kind. Every arm mutates the DID document; picking one would write the wrong
    service. `get` additionally exists to tell "never configured" from
    "configured and disabled", which answering about another transport destroys.
  * `device/register`'s consumer kind, form factor and service kind **refuse**,
    and `wire_kind_to_internal` became fallible to say so. It writes an ACL entry
    and the kind is what policy keys off.
  * `push/wake`'s reply status **logs and continues** — the only one that does.
    Wake is best-effort with a mediator-queue fallback, and an unknown status is
    worth an operator's attention but not a failure. Named separately from `None`
    because the two say different things: "no status we could read" against "a
    status we read but do not know".

  `reason`, `deniedReason` and their siblings became bounded newtypes rather than
  `String`. Parsing them at the producer means an over-long value fails on the
  device that would otherwise sign a document the consumer must reject.

  **The response gate caught a live violation.** `passkey-vms/enroll-challenge`
  put the raw DID into WebAuthn's `userName`/`userDisplayName`, which 0.17 bounds
  at 64 characters — a `did:webvh` is ~85, so the response was unconformant.
  Worth stating that the schema is self-contradictory here: `userName`'s own
  description says "e.g. the DID" while its constraint makes any `did:webvh`
  unrepresentable. The constraint is the defensible half — WebAuthn L2 §5.4.3
  lets an authenticator truncate at 64 bytes, so the raw DID was already
  producing a picker entry cut mid-SCID, unreadable and identical between two
  DIDs on the same host. `userHandle` carries the DID-derived binding and is
  unbounded, so nothing is lost: `userName` now takes the operator's label, or
  the DID with its `did:<method>:<scid>:` prefix dropped, clamped on a char
  boundary.

  Coverage holds at 88/109 with zero response-conformance violations.

- **deps**: Trust-tasks-rs 0.12 and the TDK crates that carry it ([#1121](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1121))

Verified locally against a path-patched affinidi-tdk-rs before those crates
  published (affinidi/affinidi-tdk-rs#743); VTI's graph collapses to a single
  trust-tasks-rs 0.12.1 node and the workspace compiles.

  Bumps trust-tasks-rs 0.11.17 -> 0.12 with the four sibling crates that moved
  with it — capability-client 0.10 -> 0.11, https 0.10 -> 0.12, didcomm 0.10 ->
  0.12, proof 0.10 -> 0.11 — and the TDK crates whose public API carries
  trust-tasks-rs types: affinidi-tdk 0.8.5 -> 0.9, affinidi-messaging-sdk 0.19 ->
  0.20, affinidi-messaging-test-mediator 0.2 -> 0.3. They move together because
  two trust-tasks-rs nodes in one graph do not warn, they fail to compile:
  `expected MediatorAcl, found a different MediatorAcl`.

  One source change. `classify_git_trust_reply` gained a required
  `expected_thread_id` in capability-client 0.11, because acting on an
  uncorrelated reply lets whichever document arrives next decide the fate of a
  write it has nothing to do with. The `replies` registry already keys its waiter
  on `doc.id`, so this is defence in depth — and `correlation_thread` is the
  library's own SPEC §4.9 rule (`threadId` falling back to `id`) rather than this
  call site's guess at it.

  Three marked stopgaps become deletable once this lands, each of which names
  this bump at its site: the freshness stand-in from #1117 in favour of
  `FreshnessPolicy`/`validate_freshness`, the minted `key_id` branch from #1118
  in favour of the wire `keyId`, and `replay::check_and_record` in favour of
  `ReplayGuard`. They are left alone here so this change is a dependency move and
  nothing else.



### Test

- **vta**: Cover the did-templates and policy families ([#1128](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1128))

Coverage 48 -> 58 of 109 (44% -> 53%). Two families, one real defect.



## [0.21.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.20.0...vta-service-v0.21.0) — 2026-08-26


### Added

- **vta**: Framework 0.5.0 freshness bounds at the dispatch spine ([#1117](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1117))

Framework 0.5.0 Consumer Requirements item 13. A consumer MUST reject a
  document whose `issuedAt` is ahead of its own clock beyond its skew tolerance,
  and one whose `expiresAt` is at or before its `issuedAt`.

  Both are `malformedRequest`, never `expired`, and that distinction is the
  substance of the rule: `expired` names a document that was once acceptable and
  no longer is, so it tells the producer to wait when what it must do is reissue.
  Neither of these was acceptable at any instant.

  The rule makes the duplicate-execution record of item 11 implementable. That
  record is bounded only if every accepted document can be placed in a window,
  and both shapes escape every window while still looking acceptable: a future
  `issuedAt` sits in a window that has not opened and re-enters it as the clock
  advances, and an `expiresAt` at or before issuance describes an interval that
  never contained an instant.

  This is a stand-in and says so. `trust-tasks-rs` 0.12.0
  (dtgwg-trust-tasks-tf#274) ships `FreshnessPolicy` and
  `TrustTask::validate_freshness`, which implement these two rules identically —
  same 60s skew — and add the `max_age` window and the `ReplayGuard` item 11
  needs. The 0.12 bump is blocked on an external crate: `affinidi-messaging-sdk`
  0.19.12 pins `trust-tasks-rs ^0.11` and `vta_sdk::acl_setup` hands it a
  generated `MediatorAcl`, so two nodes in one graph fail to compile with
  `expected MediatorAcl, found a different MediatorAcl`. The four sibling
  trust-tasks crates have published 0.12-compatible releases; the messaging SDK
  has not.

  The module doc names the blocker and the replacement call, and the tests are
  written against behaviour rather than this implementation, so they survive the
  swap unchanged and are the check that it was faithful.

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

- **audit**: Make the audit destination a deployment choice, not a protocol one ([#1049](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1049))

`AuditLogEntry` is `{id, timestamp, action, actor, resource, outcome, channel,
  contextId, detail}` — no signature, no hash chain. The log corroborates what
  happened; it cannot prove it, and a compromised VTA can rewrite its own history.
  The canonical `AuditEnvelope` already names the members that would change that
  (`prevHash`, `entryHash`, `schemaVersion`) and records why this maintainer omits
  them: its log is flat and unchained.

  This does not add tamper-evidence, deliberately. It adds the seam, so an
  operator who needs a stronger guarantee implements one — an append-only file, a
  transparency log, a blockchain anchor, a hash chain filling in those three
  members — without the VTA committing to any scheme. Closes #1031.

  ## The shape

- **service**: Retire routes and Trust Tasks on evidence, not on a hand audit ([#1047](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1047))

Two gaps in how this workspace retires things, both surfaced while retiring
  `vta/discovery/capabilities/1.0` (#1043, #1044). Closes #1045.

  ## The superseded-route table had no guard

  `deprecation.rs` maps legacy REST routes to the Trust Task that supersedes them
  so that removal can be gated on observed usage dropping to zero. #1042 deleted
  `GET /capabilities` and left its row behind — a row matching a path that can
  never be hit again reads zero forever, which is exactly the signal the table
  exists to produce, emitted about something already deleted. It was noticed by
  accident and removed by hand in #1044, because nothing tied the table to the
  live router.

  `every_superseded_row_names_a_live_route` now walks the assembled router and
  asserts every row matches a live route. It asserts on `MatchedPath` rather than
  on a status code, because `MatchedPath` is what `mark_superseded` matches on: a
  row spelling a parameter differently — `/acl/{id}` where the router registered
  `/acl/{did}` — attaches no header and counts nothing while the route goes on
  answering, and a status-only probe reads green over that. The failure text says
  which way to fix it. The reverse direction is deliberately not asserted; a live
  route absent from the table is legitimate, and `deprecation.rs` already records
  which routes are excluded and why.

  ## Trust Task URIs had no deprecation path at all

  A task could be retired only by deleting it, and the only evidence available was
  a source audit — grep the repos we can see and reason about the rest. That was
  defensible for one task with zero consumers anywhere and does not generalise;
  the next retirement may be one somebody is calling.

  `SUPERSEDED_TASKS` gives them the route mechanism:
  `deprecated_trust_task_requests_total` labelled by URI, the successor named in
  the response so a client can act rather than guess, and removal on an observed
  zero. Seeded with the eleven dispatched URIs already carrying `#[deprecated]` in
  `vta_sdk::trust_tasks` — attributes that told a Rust caller to migrate, told a
  wire caller nothing, and left no instrument saying whether anyone was still
  sending them.

  Checked against the framework first. The *registry* has the concept
  (`status: retired` + `supersededBy`, how twelve `messaging/*` tasks were retired
  upstream), but `trust-tasks-rs` 0.11 exposes none of it: `schema_index` is
  URI → payload schema and nothing else, `Payload` carries no lifecycle constant,
  and `trust-task-discovery/0.1`'s expanded `supportedTypes` entry is closed over
  `{type, requiredExt}`. So this is invention rather than adoption; the vocabulary
  matches the registry's so that adopting a published signal later is a rename.

  The notice rides the response document's **top level**, not `payload.ext`. The
  framework envelope keeps unrecognized top-level members in `TrustTask::extra`
  and SPEC §7.1/§7.2 tells consumers to preserve rather than reject them, so a
  member there cannot break a client that has never heard of it. `payload` can
  make no such promise: every published payload schema is
  `additionalProperties: false`, the generated `Response` types are
  `deny_unknown_fields`, and the conformance sweep validates against both. This is
  the Trust-Task analogue of putting the REST signal in a header — beside the
  answer rather than inside it. A document carrying a `proof` is left untouched.

  ## Both tables are now pinned to what they describe

  `superseded_tasks_are_dispatched` refuses a row nothing routes (that reads zero
  forever, same defect as the dangling route row), `superseded_task_successors_are
  _served` refuses a successor this VTA does not serve (a notice that sends a
  migrating client onto an unsupported type), and
  `every_dual_accepted_spec_marks_its_0_1_form_superseded` pins
  `wire_v0_2::WIRE_SPECS_V0_2` against `SUPERSEDED_TASKS`, so a new dual-accept
  cannot land without an instrument on the form it replaces.

  Not covered, and said so in the source rather than papered over:
  `auth/passkey/login/{start,finish}/0.1` are deprecated but reach neither
  instrument. They are REST-routed on paths the route table excludes on purpose,
  and one path serves both versions with the delta inside the body, so separating
  them needs a counter in those two handlers.

  Two things the tests found rather than confirmed. The signal is attached in
  `dispatch_trust_task_inner` wrapping every exit out of the checks, not after
  them — the spine has a dozen early returns, and a URI going quiet because its
  callers are all being rejected before the hook would read as "nobody sends this
  any more"; the first version had exactly that hole and the rejection test caught
  it. And that split is `Box::pin`ed: the callee's state machine inlines every
  handler's future through `dispatch_typed`, and awaiting it by value overflowed
  the test-thread stack in `tests/mock_vta.rs` under `cargo test --workspace`,
  where feature unification builds more of vta-service than `-p vta-service` does.



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

- **vtc**: Follow the spec on every auth response, and close the conformance gate ([#1112](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1112))

* test(vtc)!: make response conformance fail the build

  Until now the layer reported and a green suite was not evidence of
  conformance — #1107's own memory note said to grep the run rather than trust
  the exit code, which is a signal nobody has to obey.

  A violation outside the allowlist now returns 500 with the schema error, so the
  test that provoked it fails on its own status assertion and prints the reason.
  Chosen over panicking in middleware, which surfaces at the call site as a
  transport error and says nothing about which task or why.

  The allowlist is eight `auth/*` tasks with ALLOWED_COUNT asserted beside them —
  the same discipline as KNOWN_DRIFT_COUNT, because the cheapest way to make a
  failing check pass is to add a line to a list nobody watches. An allowlisted
  violation is still reported, pinned by a test: a list that suppressed the
  evidence would mean rediscovering each entry before it could be closed.

  Two existing guards caught mistakes of mine on the first run. The allowlist
  named login/{start,finish}/0.1 where the service binds 0.2 — built from the
  violation output rather than the route mounts — and the manifest guard flagged a
  fake `trusttasks.org/spec/` URI in a new unit test, correctly, since binding
  such a URI asserts the registry serves it.

  Also retargets relationships/{list,graph} to the 0.2s from
  trustoverip/dtgwg-trust-tasks-tf#266, and fixes a seeder that wrote
  `seed-{uuid}` into `vrcDigestMultibase` — unique per row, and so a suite
  structurally blind to digest format.

  The VTC family is now clean; every remaining violation is `auth/*`.

- **service**: Make AppStateParts non-exhaustive so adding a field stops being a break ([#1057](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1057))

`AppState` was marked `#[non_exhaustive]` in #1024 for a defect this struct
  has too, and the two are constructed side by side. `AppStateParts` is all
  public fields with no private field and no constructor guard, so any crate
  could write an `AppStateParts { .. }` literal — including the
  functional-update form — which made *adding a field* a source break under
  `constructible_struct_adds_field`.

  Not hypothetical, and recent: #1049 added `audit_sink`, and #1051 nearly added
  `app_state_locks` before the break was spotted and routed around by taking the
  value off the built `AppState` instead. That workaround was the right call for
  a feature PR, but it treated the symptom.

  Construction inside this crate is unaffected. Outside it, `Default` plus field
  assignment replaces the literal:

      let mut parts = AppStateParts::default();
      parts.audit_sink = Some(sink);

  `tests/audit_sink.rs` now does exactly that. It is worth noting *why* that file
  had to change: an integration test is a separate crate, so it was the first
  thing the attribute broke — which makes it a fair proxy for what a consumer
  has to do, and a standing check that the supported shape keeps working.



### Chore

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



## [0.20.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.19.0...vta-service-v0.20.0) — 2026-08-22


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



## [0.19.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.18.0...vta-service-v0.19.0) — 2026-08-21


### Fixed

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

- **service**: Make AppState non-exhaustive so adding a field stops being a break ([#1024](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1024))

`AppState` is 46 public fields, no private field, no constructor guard. Any
  crate could write an `AppState { .. }` literal, which made *adding a field* a
  source-breaking change under `constructible_struct_adds_field`. Twenty-nine
  commits have added at least one field; c93c7b57 added five.

  That break has never once been reported. `cargo semver-checks` cannot build
  this crate's baseline — the published ranges resolve two `trust-tasks-rs`
  versions into one graph — and a crate whose baseline fails to build is
  silently not compared rather than reported as unchecked.

  The version numbers came out right anyway, and it is worth recording why,
  because the reason is two coincidences rather than a working process:

    - at 0.x a break needs a MINOR bump, and conventional commits already force
      one for `feat:`;
    - every field addition since release-plz adoption happened to be a `feat:`.

  Neither holds in general. `refactor:`, `fix:`, `perf:` and `chore:` all yield
  a patch and can add fields just as easily — c93c7b57 is a `refactor:` and
  added five, which is the largest single addition in the file's history.
  Moving state between structs is what a refactor does, so the commit type most
  likely to add public fields is one of the types that yields a patch. And the
  alignment fails completely at 1.0, where a break needs a MAJOR and `feat:`
  gives only a MINOR: the cover expires exactly when the consequences become
  external.

  `#[non_exhaustive]` closes the class permanently instead of relying on any of
  that continuing to hold.

  Nothing outside the crate is affected. Both construction sites are in-crate
  (`build_app_state` and `test_support`), `MockVta` is the supported entry
  point for consumers, and `tests/app_state_single_construction.rs` already
  goes through `build_app_state` rather than a literal — that test is from the
  P1.1 work in c93c7b57, so a single canonical constructor was already the
  crate's intent. This makes it enforceable from outside rather than
  conventional.

  Marked `!` because it is one: outside this crate, `AppState { .. }` and
  exhaustive destructuring stop compiling. That is the point — it is the last
  such break this struct can have.

  cargo test --workspace: 145 suites, 0 failed. cargo check --all-features
  clean, zero warnings.



## [0.18.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.17.1...vta-service-v0.18.0) — 2026-08-20


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

- **service**: Signal every superseded REST route, from one layer ([#1007](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1007))


### Documentation

- **service**: Record why a witness is typed or raw, and when that flips ([#1021](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1021))

The conformance sweep's witnesses are typed for some families and raw JSON
  for others, and nothing in the module said why. The reasoning lived only in
  #1015's PR body, where it does not reach anyone reading the table.

  The rule: typed when the spec preceded the type, raw JSON when it did not,
  and the second case is a debt.

  Typed is the stronger form — it proves our types conform rather than that
  someone can hand-write an acceptable body — but only when the type did not
  derive its shape from the same misreading that produced the witness. When
  the contexts/webvh schemas arrived, create_did_webvh was sending context_id
  against a schema naming contextId, and update_context was dropping
  contextPolicy entirely. Witnesses built from those types would have encoded
  both defects and passed green.

  Same principle scripts/check-bindings-conformance.mjs applies a layer down
  by re-implementing the binding rules instead of importing them.

  This also makes the retro-fit legible as a real step rather than tidying:
  converting the 22 to typed bodies is only sound now that #1015 corrected
  the types, and would have laundered the bugs before that.

  Docs only; no behaviour change.



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



## [0.17.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.17.0...vta-service-v0.17.1) — 2026-08-18


## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.16.1...vta-service-v0.17.0) — 2026-08-17


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



### Chore

- **deps**: Track trust-tasks 0.9 across the workspace ([#996](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/996))

Moves all five `trust-tasks-*` requirements and `trust-tasks-capability-client`
  (0.5 -> 0.8) together, as the family requires: `trust-tasks-rs`'s core types
  cross the public API of `-https` / `-didcomm` / `-proof`, so a graph mixing
  majors does not type-check. Takes the `affinidi-messaging-*` releases built on
  0.9 (sdk 0.19.8, mediator 0.18.18, didcomm-service 0.3.26, test-mediator 0.2.51)
  in the same move, so the lockfile carries exactly one copy of everything.

  There are no `consume_inbound` call sites in this workspace, so 0.9.0's new
  `PayloadPolicy` argument costs nothing here, and nothing matches on
  `StandardCode`, so 0.7.0's `#[non_exhaustive]` costs nothing either. The
  `validate` feature stays enabled and unused, as before.

  What did change is the wire version of the error documents this stack emits.

  `trust-task-error` moved 0.3 -> 0.4 -> 0.5 upstream, each step for the same
  reason the 0.3 step happened: a new standard code that the older payload
  schema's `code` enum does not list and whose extended-code pattern does not
  match, so a document carrying it would not validate as the older version. 0.4
  carries `idConflict`, 0.5 carries `cancelled` (SPEC §8.3).

  Both services hand-write that version on their one unrouted path — where there
  is no request document to reject from, and so no framework call to ask —
  and both were left naming 0.3 while `reject_with` stamped 0.5 on every routed
  rejection. One service emitting two versions is a trap for exactly the consumer
  that pins one of them. `unrouted_and_routed_errors_agree_on_the_type_uri` exists
  in both services to catch precisely this, and it did: the bump failed those two
  tests rather than shipping two dialects. Constants updated, rationale extended.

  Two in-`src` VTC test fixtures that also named 0.3 now take the version from
  `framework_error_type_uri()` instead of repeating it, so they follow the emitter
  on the next bump rather than stranding a version behind. That also keeps
  `trust_task_manifest`'s unpublished-URI census at one URI for the family; the
  census is deliberately exact so the debt can shrink but never grow unnoticed,
  and raising the expected count would have been the wrong fix.

  Backward acceptance of an *older* error document keeps its coverage:
  `vtc-service/tests/registry_didcomm.rs` pins 0.1 on purpose, and is left alone.

  Per SPEC §5.2 forward-minor compatibility, a consumer still pinned to
  `trust-task-error/0.3` SHOULD accept 0.5. Marked `!` because this changes the
  version on the wire, not because any Rust signature moved.



## [0.16.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.16.0...vta-service-v0.16.1) — 2026-08-16


## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.4...vta-service-v0.16.0) — 2026-08-16


### Added

- **vta-vault**: Bind an mdoc to the VTA key that can present it ([#990](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/990))

An mdoc's holder binding is a key, not a DID: the MSO carries a deviceKey, and
  only its private half can sign DeviceAuth. Nothing in the stored envelope said
  which VTA key that was, so a received mdoc could be stored and then turn out to
  be unpresentable — with the failure surfacing much later, at presentation, and
  nothing pointing at the cause.

  Receive now resolves that binding and refuses the credential if this VTA does
  not hold the key. Storing a credential you can never present is a trap, and the
  right moment to find out is the moment it arrives.

  mdoc_device_key_sec1 extracts the MSO deviceKey as a compressed SEC1 point —
  the same encoding the VTA stores its own P-256 public keys in — so the caller
  can compare without re-deriving either side. Extraction lives in vta-vault
  because it reads mdoc internals; the matching lives in vta-service because that
  is the layer that can see the keyspace. vta-vault does not depend on vta-keys,
  and this keeps it that way.

  find_key_by_public_multibase is a linear scan: the keyspace is indexed by key
  id, not by public key, and a reverse index for one receive-path caller is not
  worth the write amplification on every mint. It takes no AuthClaims because it
  answers a factual question, not an authorization one — the caller gates on the
  returned record's context_id, because binding a credential to a key in a
  context the caller cannot act in would be a cross-tenant escape.

- **vta-service**: Accept ISO mdoc over the credential-receive Trust Task ([#989](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/989))

Everything shipped for mdoc so far — the format identity ([#984](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/984)), receive-side
  verification ([#986](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/986)) and the IACA trust anchors ([#987](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/987)) — was reachable only
  through the library. handle_receive was hardcoded to the Data-Integrity path:
  a JSON credential, an issuer DID resolved through the DID cache, no format
  parameter. An mdoc could not arrive at the VTA at all. This connects it.

  ReceiveBody gains an optional format tag and a credentialBase64 carrier, since
  an mdoc is CBOR and cannot travel as JSON. Absent format still means
  Data-Integrity, which is the shape every existing client sends, so a deployed
  wallet is unaffected — pinned by a test that parses a pre-existing body and
  asserts it still routes to the DI path. Exactly one of credential or
  credentialBase64 must be present; both, or neither, is a malformedRequest.

  The mdoc arm is where the two credential families genuinely diverge. A DI
  credential names its issuer as a DID and the key is resolved through the cache;
  an mdoc names its issuer as an X.509 Document Signer, so the credential is
  decoded first to read its x5chain and the key comes from the configured IACA
  anchors instead. That asymmetry is the whole reason the anchors exist.

  AppState carries the parsed anchors, built once in build_app_state from
  [vault] mdoc_iaca_trust_anchors. A malformed certificate fails the boot rather
  than surfacing as a puzzling rejection on the first mdoc that arrives. Empty is
  legal and means this VTA accepts no mdoc issuers; the resolver fails closed on
  it, so wiring the wire surface does not by itself make any VTA start trusting
  mdocs — an operator still has to configure anchors deliberately.

  No schema change: vault/credentials/receive/0.1 is in UNSPECCED_DISPATCHED_URIS,
  so there is no published payload schema to update and dispatch validation is a
  no-op for it either way.

  Note for a follow-up, not changed here: test_support.rs constructs an AppState
  literal directly, so build_app_state is not in practice the single constructor
  its doc comment claims. Adding a field has to be done in both places.



## [0.15.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.3...vta-service-v0.15.4) — 2026-08-16


### Added

- **vta-vault**: Verify and store ISO mdoc credentials on receive ([#986](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/986))

#984 gave mdoc a CredentialFormat identity but receive still refused it, because
  affinidi-mdoc had no way to turn a stored body back into an IssuerSigned. 0.2.6
  added that codec, so receive can now do the real work.

  Verifies three things per ISO 18013-5 S9.3.1, rejecting-without-storing on any
  failure: the issuerAuth COSE_Sign1 over the MSO, every item digest against the
  MSO valueDigests (a good signature over an MSO whose digests do not match means
  the items were swapped after signing), and the validityInfo window.

  issuer_pub is the caller-resolved Document Signer key — deliberately the same
  shape as the DI path's issuer key, and for the same reason: deciding *which*
  key to trust is policy that belongs to the wire layer. That seam matters more
  here, because mdoc anchors issuer trust in an X.509 chain (x5chain, COSE label
  33, rooted in an IACA) while this stack is DID-rooted end to end. Taking a
  resolved key keeps that unresolved question out of the storage layer instead of
  quietly settling it.

  ES256 only, checked explicitly before the signature so a mismatched algorithm
  is refused by name rather than failing as an opaque bad signature. ISO 18013-5
  and the EUDI profiles mandate ES256, which the VTA already has via
  KeyType::P256, so no new curve enters the graph.

  subject_did and issuer_did are left None: an mdoc binds to its holder through
  the MSO deviceKey, not a subject DID, and carries no issuer DID. Inventing
  either would put an unverifiable identifier into a secondary index.

  coset and time are declared as direct dependencies rather than used
  transitively through affinidi-mdoc — the receive path names their types, and
  depending on a transitive is how an unrelated version bump breaks a crate.

  DCQL matching and presentation are deliberately NOT in this change. dcql_format
  still returns None for mdoc: admitting it without a present_single arm trips
  formats_admitted_for_dcql_are_all_presentable, and that guard is right — a
  matched-but-unpresentable credential bails the entire vp_token, not just itself.
  Presenting an mdoc needs DeviceResponse::to_cbor_bytes (affinidi-mdoc 0.2.7,
  under review as affinidi/affinidi-tdk-rs#712), so matching and presentation land
  together in a follow-up.

- **vta-vault**: Give ISO mdoc a first-class CredentialFormat identity ([#984](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/984))

An mdoc arriving at the credential vault previously deserialised into the
  `Other(String)` escape hatch, so every downstream `match` treated one of
  the two eIDAS-mandated credential formats as an unknown vendor tag.

  Adds `CredentialFormat::MsoMdoc`, tagged `mso_mdoc` — the OpenID4VP
  `CredentialQuery.format` spelling, explicitly renamed rather than taking
  the enum's kebab-case `mso-mdoc`, so storage and protocol agree on one
  token. A test pins the exact bytes, not just the round-trip.

  Receive refuses an mdoc rather than storing a body it cannot re-read, and
  `dcql_format` returns `None` for it, keeping the existing matchable-implies-
  presentable invariant true. Both carry the reason: affinidi-mdoc 0.2.5 has
  no CBOR codec for `IssuerSigned` (it derives only Debug + Clone, with no
  Serialize/Deserialize and no to/from_cbor_bytes), so the body cannot be
  decoded, verified, or re-encoded for presentation. Wiring receive, DCQL
  matching and presentation is blocked on that codec landing upstream.

  The invariant guard in credential_exchange enumerates formats by hand, so
  MsoMdoc is added there too — otherwise a new variant is silently uncovered.



## [0.15.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.2...vta-service-v0.15.3) — 2026-08-14


### Added

- **nitro**: Un-bake tenant config, deliver to the enclave over vsock ([#939](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/939))

* feat(nitro): un-bake tenant config, deliver to the enclave over vsock

  The Nitro enclave image no longer bakes tenant config.toml into the EIF, so one image (one PCR0) serves every tenant. The entrypoint fetches a versioned config envelope from the parent over vsock:5800 (bounded connect/read timeouts, 1 MB size cap, version check), fails closed unless VTA_ALLOW_DEFAULT_CONFIG=true, and writes /etc/vta/config.toml before start. Adds jq to the runtime; documents the KMS-policy isolation requirement and the tee-mode enforcement floor.



## [0.15.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.1...vta-service-v0.15.2) — 2026-08-14


## [0.15.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.15.0...vta-service-v0.15.1) — 2026-08-14


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



### Fixed

- **trust-tasks**: Stop emitting two versions of the framework error document ([#973](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/973))

* fix(trust-tasks): stop emitting two versions of the framework error document

  Both services routed their rejections through `TrustTask::reject_with`, which
  stamps whatever version `trust-tasks-rs` emits — `trust-task-error/0.3` since
  the framework's own 0.3 release. But each service also has one *unrouted* path,
  for a body that never parsed into a Trust Task at all, and with no request
  document to reject from it had to write the Type URI out by hand. Both wrote
  `0.1`.

  So a single service spoke two dialects, distinguished only by whether the
  request happened to parse. That is a trap for exactly the consumer that pins a
  version, and it is not hypothetical: a client enumerating `0.1`/`0.2` read every
  `0.3` rejection as a **success**, because an unrecognised error document falls
  through to the success branch and its payload is returned as the operation's
  result (OpenVTC/vta-browser-plugin#115, affinidi/affinidi-webvh-service#160).
  The version a service emits is wire contract; emitting two is worse than
  emitting the wrong one, because whichever a consumer pins is right half the time.

  `trust-tasks-rs` keeps `trust_task_error_type_uri()` `pub(crate)`, so the value
  cannot be read from the framework. Each service now names it once, in
  `framework_error_type_uri()` beside the unrouted builder, and a test compares
  that against the Type URI a real `reject_with` produces. A framework bump now
  fails a test instead of silently re-splitting the service in two. A second test
  asserts the bytes on the wire carry it, not just the value we compute.

  Test fixtures that stood in for a peer's rejection were built at `0.1` — a
  version no peer on trust-tasks-rs 0.4 sends. They now use what a peer actually
  emits. Those assertions pass either way (the matchers key on the slug, which is
  the right way to match), but a suite that exercises a wire nobody speaks is how
  the client-side version pin survived this long unnoticed.

  Left alone deliberately: `vtc-service::messaging`'s `.unwrap_or(…/0.1)` default,
  which labels an inbound document that carries no `type` at all. It is not an
  emitted document, and every consumer of that label matches on the slug.

- **webvh**: Sign with the update keys in force, not the ones the head restated ([#972](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/972))

A DID whose most recent log entry did not restate `updateKeys` could not be
  updated again. Every attempt died with

      webvh library error: log entry has no update_keys — DID is deactivated or malformed

  about a DID that was neither deactivated nor malformed, and the operator reads
  that as lost keys. Nothing was lost. The keys were never consulted.

  webvh parameters are a delta: an entry that omits `updateKeys` leaves the
  previous entry's in force. `didwebvh-rs` models that as two fields —
  `update_keys` is what the entry *declared* (`None` when it declared nothing) and
  `active_update_keys` is the effective set validation carried forward
  (`parameters/mod.rs`, the `None =>` arm: "If absent, keep current updateKeys").
  Only the second answers "which key signs the next entry". The orchestrator read
  the first, got an empty list, and handed it to `load_active_update_key`, whose
  first line rejects an empty list — so the DID's real update key was never looked
  up in the handle cache, never re-derived from the seed, never tried.

  The head entry that triggers it is one this code writes itself: for a
  metadata-only update with no pre-rotation, `set_update_keys` is `None` (nothing
  forces a key reveal, and rotating on a no-op change would be wrong), so the
  entry lands as `"parameters": {}`. One such update and the DID is permanently
  un-updatable by this VTA. Found on a live hosting-server DID whose v3 was
  exactly that; v1 declared the keys, v2 rotated them, v3 declared nothing.

  `next_key_hashes` needs no equivalent change: the library inherits that one into
  the field itself, so the pre-rotation path was always reading the effective set.
  That is also why the failure looked so selective — a DID whose head happens to
  restate its keys, which every document-changing update does, works fine.

  Regression test drives the real sequence: create, metadata-only update, then
  update again. It asserts the intermediate entry really does omit the parameter,
  so it cannot pass for the wrong reason if the write path ever changes. Reverting
  the one-line read reproduces the production error verbatim.

- **cli**: Make `dids list` show the DID, and plan errors say what failed ([#967](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/967))

Two unrelated fixes to the same delegated-update path, found chasing a
  `webvh/dids/update` that failed after its consent gate passed.

  **`pnm dids list` rendered a wide name beside an unreadable DID.** A
  ratatui `Table` lays out exactly as many columns as it has width
  constraints — a widths list shorter than the row is not padded, it
  truncates. `dids list` builds its header and its rows with a conditional
  Name column but built the widths without one, so every width landed a
  column to the left: Name inherited the DID's flexing `Min`, the DID
  inherited Context's fixed 16 (`did:webvh:Qm0M8Cr`, cut mid-SCID) and
  `Created` fell off the right-hand end. The servers table above it had the
  same shape of bug from the other direction — its widths were written
  against a different column order, and their own comments still said so.

  Header and widths are now returned together from `did_list_columns`, so
  the two cannot drift, and the DID column starts at 46 columns: `shorten_did`
  abbreviates only the SCID and keeps host and path in full, which is what
  makes the value copyable.

  **Every webvh dry-run failure became `internalError`.** The planner runs
  on the consent path and only there, so that flattening applied to exactly
  the report an approver-gated update produces: a DID the VTA does not hold,
  a context the requester cannot act in, and a genuine signing bug all
  arrived as one opaque internal error — while the *ungated* execution of
  the very same task answered `taskFailed: did not found: …`. Turning
  consent on made the diagnosis worse than leaving it off.

  Dry-run failures now route through the existing
  `From<UpdateDidWebvhError> for AppError`, so plan and execute answer with
  the same variant for the same cause, with `webvh update dry-run:` framing
  the message. The Forbidden-collapses-to-NotFound rule that stops a
  dry-run being used to probe for DIDs in unseen contexts is preserved, and
  pinned by a test.



## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-service-v0.14.37...vta-service-v0.15.0) — 2026-08-13


### Added

- **release**: Publish vta-service and its closure again ([#962](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/962))

* feat(release): publish vta-service and its closure again

  #938 unpublished `vta-service` and the twelve subsystem crates behind it,
  on the finding that nothing external depended on them. The audit read
  normal dependencies. `openvtc-core` depends on `vta-service` as a
  **dev-dependency**, for `test_support::MockVta` — an in-process VTA its
  end-to-end tests run against. That harness boots the real service, so no
  client crate can stand in for it.

  Unpublishing did not merely freeze the crate. It broke it.

  `vti-common` re-exports `vta_sdk::acl::{ActScope, ApproveScope,
  ContextDirection}` as its own public API, so **a re-export makes the
  re-exported crate's version part of your public API**: any graph
  combining `vti-common` with another `vta-sdk` consumer must resolve one
  `vta-sdk`. The frozen `vta-service` 0.14.37 asks for `vta-sdk ^0.21`
  while `vti-common` has moved to `^0.23`. A downstream `cargo update`
  resolves both and `vta-service` fails to compile with

    expected `vti_common::acl::ApproveScope`,
       found `vta_sdk::acl::ApproveScope`

  at ten call sites — which is how this surfaced, in openvtc #213. Nothing
  downstream can fix that; only a release that moves the requirements
  together can.

  So the thirteen manifests go back to the workspace default. The cost is
  the closure — twelve subsystem crates return to crates.io, which is
  exactly what #938 set out to stop. Taken deliberately over the
  alternatives: yanking the published copies breaks OpenVTC's tests with no
  replacement, and leaving them up ships a crate on the registry that
  cannot be built.

  **On release ordering.** `cargo publish --dry-run -p vta-service` fails
  today, and will until the closure is on the registry: packaging strips
  path deps, so `vta-keys = "0.2"` resolves the *published* 0.2.1, which
  still asks for `vta-sdk ^0.21` — two nodes, same error. That resolves
  itself in the release, which publishes in dependency order: every
  subsystem crate in this workspace already requires `vta-sdk = "0.23"`, so
  once they upload, `vta-service` verifies against them. Crates whose
  dependencies are all published already dry-run clean (verified on
  `vta-keyspaces` and `vta-config`).

  Docs updated to match: CLAUDE.md, RELEASING.md and the release-plz.toml
  header all said 7-of-21. They now say 20-of-26, name the six that stay
  internal, and record the rule the audit missed — check dev-dependencies,
  in sibling repos, before unpublishing anything.

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

- **vta-service**: Add --mediator-did to create-did-peer for DID-routing mediators ([#952](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/952))

`vta create-did-peer` could only advertise a URL-style DIDComm service, built
  from `--mediator-url`. A new `--mediator-did` produces the **DID-style** shape
  instead — a single `DIDCommMessaging` service whose `serviceEndpoint.uri` is
  the mediator's own DID.

- **vta-service**: Import an external Ed25519 key for a deterministic did:key ([#953](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/953))

`vta create-did-key` always derived a fresh key from the VTA seed off a
  counter-allocated BIP-32 path, so the resulting `did:key` changed on every run.
  A new `--private-key-file` imports caller-supplied Ed25519 key material
  instead, making the `did:key` deterministic in those bytes: a redeploy onto a
  fresh volume reproduces the SAME DID. That is what lets a vault signing entry
  stay bound to a persona DID whose key is held off-box.

  The key is stored exactly like any other imported key — `KeyOrigin::Imported`,
  no derivation path, secret encrypted at rest under the VTA seed via
  `keys::imported::store_secret`. `key_id` is derived from the key material, so a
  re-run overwrites the same record with the same value rather than conflicting.

  Handling of the secret follows the discipline
  `vta_sdk::protocols::backup_management` already applies to this material:

  * It is read from a **file**, not an argv flag value. A secret on the command
    line is visible in `ps`, in shell history, and in container / CI process
    listings.
  * The file text, the decoded bytes, and the 32-byte key are all `Zeroizing`, so
    none of them outlive the import.
  * A group- or world-readable key file warns (mode is printed); it does not fail,
    since the operator may be mid-pipeline.

  With `--admin` this grants admin to a DID whose private key lives outside the
  VTA, so the flag help says so plainly. The command remains behind the existing
  `check_seal` gate.

  Tests cover the determinism property the feature exists for, and the file
  reader's accept/reject paths (trailing newline, wrong length, bad hex, missing
  file).

  Split out of #843 (third of three), rebased onto current main. Reworked from
  the original `--private-key-hex` flag per review: file input, zeroization,
  permission warning, and coverage of the import path rather than only the pure
  id-derivation helper.



### Build & CI

- **release**: Adopt release-plz, publish 7 crates instead of 21 ([#938](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/938))

Merging and releasing were the same act. publish.yml fired on every push to
  main and shipped whatever versions were newly present, and a CI guard required
  the version bump to live in the feature PR — so every PR was a release
  decision, taken by whoever opened it, days before it merged. Two open PRs
  touching one crate wrote the same number into the same line of the same
  Cargo.toml, and the second to merge had to rebase, renumber, and fix a
  changelog entry that had gone stale. #932/#936/#937 hit it three times in one
  afternoon.



### Fixed

- **vta-service**: Share one key derivation with the interactive DID preview ([#954](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/954))

`vta create-did-webvh` without `--url` still minted a DID advertising keys
  the store could not sign with. #945 fixed that for `--url` by dropping the
  preview; interactive cannot drop it, because the operator has to see and
  edit the document before it is created.

  So both sides derived. `derive_entity_keys` allocates a fresh BIP-32 path
  index per call, and `create_did_webvh` derives unconditionally whenever
  `signing_key_id` is `None` — before the `did_document` match, regardless of
  a caller-supplied document. The preview took indices n, n+1 and built its
  document from them; the operation then took n+2, n+3 and stored those. The
  published DID named one key, `get_key_secret` served another, and nothing
  noticed until a verifier rejected a signature.

- **vta-service**: Stop create-did-webvh minting a DID whose keys the store doesn't hold ([#945](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/945))

* fix(vta-service): prevent double key derivation in non-interactive create-did-webvh

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


