# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.16.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.16.1...vti-common-v0.16.2) — 2026-09-06


### Added

- **rooms**: A VTA joins a room, keeps up, and opens what it holds ([#1250](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1250))

Implements rooms/keys/{key-package,welcome,commit,open} - the delivery
  flow specified in dtgwg-trust-tasks-tf#355 and the decryption oracle from
  #349, on the custody layer from #1248. This is the piece that makes a
  data room readable by an agent that never holds a key.

  Four tasks, four different gates, and only one is a capability. The
  delivery three are inbound - a room's owner reaching this VTA - and an
  ACL of ours has no opinion about who a room's owner is. commit in
  particular is authorized INSIDE the group: MLS authenticates the
  committer as a member of the group we already hold, and a list we kept
  would be this service deciding who may commit to a room it is not part
  of. Only open is our own principal's agent asking us to decrypt, which is
  what a capability is for - RoomOpen, registered upstream in #351.

  The invitation is what makes a Welcome acceptable. A Welcome carries a
  group's secrets, so anyone able to reach a VTA could otherwise push group
  state into it. Joining a room is already a two-party act and the VIC is
  already the consent artefact; this is where that stops being ceremonial.
  Five checks, none optional - it parses as an invitation, its proof
  verifies, the issuer is the room, the subject is us, and it is live and
  unspent - and dropping any one leaves a way in. VerifiedInvitation is
  constructible only by the verifier, so a caller cannot reach consumption
  with something nobody checked.

  The invitation is consumed only AFTER the join succeeds. Burning it on a
  Welcome that then failed to process would strand the member: invitation
  spent, not in the room.

  Joining twice is refused rather than merged. Two group states for one
  room is a condition nothing downstream can resolve - open has no way to
  choose, and choosing wrong returns 'did not open' for a record the member
  can plainly see.

  open reports which epoch the VTA holds when a record is sealed under a
  later one. A member who missed a commit is stuck at their last epoch, and
  the raw symptom is 'this record does not open', which reads like
  corruption; naming the epoch turns it into 'a commit has not been
  delivered', which an operator can act on.

  Two keyspaces, both Cascade on DID deletion: room_groups holds group
  secrets and belongs at the same protection level as the key store, and
  room_invitations outlives the groups it admitted - while the member
  exists, a consumed invitation MUST survive leaving a room, or the same
  invitation would work twice.

  Four censuses had something to say. The MCP guard, where open and welcome
  are Sensitive (plaintext out, key material in) while key-package and
  commit are ordinary mutations. Retry safety, which produced four
  different answers and is the better for it: open is ReadOnly, commit is
  RetrySafe because the spec made replay a no-op precisely so delivery
  could retry, and key-package and welcome are Keyed - one leaves a second
  private half behind, the other cannot tell a lost reply from a completed
  join. Then the conformance witnesses and the namespace list.

  trust-tasks-rs 0.17.8 landed mid-build carrying #351, #354 and #355, so
  all four request types are generated rather than hand-written.

- **rooms**: The presentation oracle, so an agent never holds its human's credentials ([#1247](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1247))

Implements rooms/keys/present/0.1. The data-rooms design turns on a member
  equipping their agent with strictly less than they hold - a chain one link
  longer, conferring read for four hours, bound to one host - and nothing
  minted one. A member wanting to give an agent access had two options: hand
  over their own credentials, which is the outcome attenuation exists to
  prevent, or mint an attenuation by hand, which nobody does.

  So the agent asks, and the VTA mints. The VTA already holds the member's
  keys and is already in their trusted computing base; a host is not, which
  is why the host only ever sees the result.

  Four things a caller cannot obtain by asking, and each closes a way this
  could have quietly become the credential hand-off it replaces:

    More than the principal holds fails in attenuate, which refuses to
    widen - not at a policy check somebody could forget to write.

    A presentation covering everything is unreachable: action is required
    and exactly one action is conferred.

    A presentation made out to somebody else is unreachable: the leaf grants
    to the DID the transport authenticated, never one named in the payload.
    One minted for A is worthless to B even if B obtains it, because the
    presenter binding refuses it on the far side.

    A long-lived leaf is unreachable: the lifetime is a constant, not a
    request parameter. A caller that could ask for a year would be asking
    for the standing credential the oracle exists not to hand over.

  Gated on Capability::RoomPresent - registered upstream as roomPresent in
  dtgwg-trust-tasks-tf#351 - and deliberately not on Sign. An agent that may
  ask for a scoped, audience-bound presentation is not thereby an agent that
  may sign anything at all with its principal's key, and gating an oracle on
  the generic signing oracle grants strictly more than the task needs.

  The credentials are found by issuer, because a room issues its own - the
  same property the host verifies against, so a credential that would not
  verify there is not one this will present. Two authority credentials from
  one room is refused rather than resolved: picking the broader one hands
  out more than necessary, picking the narrower produces a presentation that
  fails at the host for reasons the caller cannot see.

  Five censuses had something to say, and all five were right. The
  conformance witness. The retry-safety classification - RetrySafe, because
  the oracle stores nothing and a retry mints a second leaf conferring
  exactly what the first did, on the same expiry; keying it would buy a
  dedup record against a harmless duplicate at the price of failing a retry
  the caller needs. The MCP guard, where it joins 'authority, moved' beside
  vta/credentials/issue: an MCP host approves a tool, so a blanket vta_call
  approval must not silently cover minting a presentation over its
  principal's standing. And the canonical-namespace list, which gains
  spec/rooms/ for exactly one URI - most of that family is a host's surface,
  and this is the one member a VTA serves.

- **rooms**: Audit every room operation, without learning who ([#1244](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1244))

Room operations wrote no audit entry at all. Every other consequential
  VTC surface does - join, members, credentials, backup - and the VTA has
  a census whose stated position is that a task which did its work and
  left no trace is a gap with no defensible reading. The rooms family was
  that gap.

  Reads are audited alongside writes, and on shared material they are the
  more interesting half: a write log says what a room contains, a read log
  says who has seen it, which is the question an incident review actually
  asks. Listing and fetching are distinct actions in the log - both are
   on the authority axis and different events to anyone reading it.

  The part worth the review time is which actor may be recorded.

  Every host has audit machinery and every one of them wants to write the
  acting party's DID into it. On a private room that single line hands the
  host the membership it was built never to learn - assembled one entry at
  a time by the component least able to notice it is doing so. It is a
  silent failure: nothing breaks, no test goes red, and the log looks
  exactly like an attributed room's.

  So the decision is a function in vti_rooms::audit rather than a judgement
  at each host's call sites, and AuditActor has no constructor that takes a
  DID unconditionally. On the disclosing tiers it carries the verified
  subject; on private it carries Member, which is true - the host verified
  a chain, so it knows a member acted - and is the most it may say. A test
  asserts the presenter appears nowhere in a private room's audit trail,
  including in the Debug rendering.

  for_operation takes the AuthorizedAction rather than a presenter string,
  so a host cannot record an actor for an operation it did not authorize,
  and cannot record a different actor from the one it did.

  The record key is recorded on every tier. An opaque key identifies a
  record without describing it, which is exactly why the schema requires
  opacity on the sealed tiers - and why a host logging a descriptive key
  would be logging content.

  Both hosts reach the same decision and differ only in where the trail
  goes. A VTC writes to its hash-chained audit keyspace; room-host has no
  chain and no business growing one - it is a delivery service, and an
  HMAC key store plus a hash chain is most of a community service again -
  so it emits tracing, where an operator's own pipeline collects it. A
  host that logged the DID because its own logging happened to be simpler
  would have handed itself the membership by the back door.

  A failed audit write is logged and swallowed. Refusing an operation that
  already succeeded turns an audit outage into a room outage and tells the
  caller their write failed when it did not; the chain's own hash makes a
  gap visible to a verifier, which is the right place to notice it.

- **acl**: Add MemoryRead/MemoryWrite and gate the memory tasks on them ([#1234](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1234))

There was no read-only grant on agent memory. The gate in
  trust_tasks/memory.rs was auth.require_context and nothing else, and a
  context is binary: any DID that could reach one could also write and
  delete every memory in it. So an operator could not give an agent
  read-only access to their own memory, and the --read-only flag in
  vta-mcp's guard is a client-side glob filter that a caller talking to the
  VTA directly never encounters.

  The published specification already assumes the split exists.
  specs/vta/memory/delete/0.1/spec.md reasons about "a VTA whose write
  capability is granted more freely than its read capability", and about
  callers holding write without read. There was no read capability and no
  write capability; there was a context. The ACL supplied nothing finer
  either - the act axis is (role, allowed_contexts) decoded to a
  three-valued ActScope, a where with no what.

  Adds Capability::{MemoryRead, MemoryWrite}, wires them through
  derived_capabilities_for_role, and gates the three handlers. Legacy rows
  carry no explicit capability set and fall back to the derived mapping, so
  the roles that write memory today keep writing it.

  Deliberate behaviour changes, both tightenings:

  - reader loses memory write. A read-only consumer of a context should not
    be able to rewrite the memories in it.
  - monitor loses memory access entirely. It is the least-privileged role
    and the Default for AuthClaims, precisely so a fixture that leaks past
    its expected reach lands somewhere harmless - which it did not, while
    memory was context-gated alone.

  application keeps both, deliberately and with a test saying why:
  vta-agent-memory grants exactly that role so the memory service is not
  the user, and every existing install would otherwise stop saving.

  The capability is checked before the context, so a caller missing it
  cannot use the reason text to probe which contexts exist.

  Note the canonical Capability enum in the trust-tasks registry
  (device/_shared/0.1) is already behind this crate - it carries neither
  sign-trust-task nor credential-write. A spec PR reconciling all four
  follows separately; this change does not widen that gap unilaterally so
  much as make it worth closing.

  Implements the orthogonal fix called out in
  docs/05-design-notes/data-rooms.md 11.1.



## [0.16.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.16.0...vti-common-v0.16.1) — 2026-09-01


## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.15.0...vti-common-v0.16.0) — 2026-08-29


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



### Fixed

- **vti-common**: Gate the keyspace name on the feature that reads it ([#1190](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1190))

`cargo build -p pnm-cli` (and every other default-feature consumer) warned
  `field `name` is never read` on `LocalKeyspaceHandle`. The field is not
  unused — it is the keyspace name bound into the AES-GCM associated data, so
  a value cannot be relocated to another keyspace that shares the storage key
  and still authenticate. But every read of it builds an AAD, and all of them
  sit behind `#[cfg(feature = "encryption")]`, which is off by default. With
  the feature off there is genuinely nothing to read it.

  So it is now gated with the feature it serves, exactly as the sibling
  `encryption_key` field already is, and cfg'd at its one construction site.
  The alternative — carrying it unconditionally under an `allow(dead_code)` —
  would leave a security-relevant field looking like it might be doing
  something in builds where it cannot.

  No behaviour change in either configuration: with `encryption` on the field
  and its readers are unchanged; with it off nothing referenced the field.
  Verified warning-free on `cargo build --release -p pnm-cli` (defaults and
  `config-session`), `cargo check -p vti-common --all-features --all-targets`,
  and `cargo test -p vti-common --all-features` (476 passing).



## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.14.0...vti-common-v0.15.0) — 2026-08-28


### Added

- **vtc**: State artifact lifecycle precedence once, and apply it on read ([#1179](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1179))
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



## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.13.2...vti-common-v0.14.0) — 2026-08-26


### Added

- **vtc**: Implement the VPC as the deliberate-correlation mechanism on an edge ([#1074](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1074))

* feat(vtc): implement the VPC as the deliberate-correlation mechanism on an edge

  `PersonaCredential` appeared nowhere in this repo and
  `DTGCredential::new_vpc` was never called, so the P-DID had no
  implementation and the word "persona" drifted onto the membership DID for
  want of anything to anchor it ([#1067](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1067)).

  What the absence cost, concretely. After the publish proof-of-possession
  change ([#1054](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1054)) a member had exactly two settings: publish under a pairwise
  relationship DID and correlate with nothing, or publish under the
  membership DID and correlate with everything, permanently, for anyone who
  retains the credential. DTG Credentials §Privacy Considerations 3 says
  correlation "should occur only through the holder's deliberate assertion of
  a persona (via a VPC) or an M-DID". The precise instrument was missing, so
  members had only the blunt one.

  This adds the VTC half of it: `POST` / `DELETE
  /v1/relationships/{id}/persona` (`vtc-service/src/routes/relationships.rs`).
  A VPC is an *annotation* credential — it creates no graph structure, it
  attaches to structure that already exists — so there is no "publish a VPC",
  only "attach this persona to that edge", and the annotation is stored on the
  edge row (`vtc-service/src/relationships/mod.rs`) rather than in a keyspace
  of its own. The P-DID surfaces on `GET /v1/relationships/graph` as
  `personaDid`, which is where the correlation becomes visible; an annotation
  nothing reads would leave #1067 in the state it describes.

  trustoverip/dtgwg-cred-spec#9 asks how a VPC binds to a specific
  relationship and is open. Nothing here answers it. A VPC names its persona
  (`issuer`) and the counterparty (`credentialSubject.id`) and not the
  relationship DID the persona used, so it does not identify an edge on its
  own.

  Rather than add a field to the credential and present that as the
  resolution, the binding is made at the request level:

  1. the caller names the edge by id in the URL;
  2. the caller proves control of that edge's `issuerDid`, with the same
     proof-of-possession construction publishing the edge required;
  3. the VPC's `credentialSubject.id` must equal the edge's `subjectDid`.

  (2) is what makes it safe — the only party who could have published this
  edge is the only party who can annotate it, so no new trust is extended.
  (3) is a consistency check, not a binding. If #9 lands an in-credential
  binding (a `digest` over the VRC, as the VWC already has), the endpoint can
  require it as well without changing the stored shape.

  Stated limitation: the spec says a VPC's subject is "typically the R-DID or
  M-DID used in the relationship". A VPC naming the counterparty's M-DID, on
  an edge whose `subjectDid` is their R-DID, fails check (3) and is rejected.
  That case is real and needs the same #9 answer; guessing would mean
  accepting a VPC naming a party the VTC cannot tie to the edge, which is the
  problem restated.

  - **No uniqueness check on the P-DID**, in direct contrast to the R-DID rule
    the publish path enforces unconditionally. A relationship DID that recurs
    across counterparties is a defect; a persona DID that recurs is the entire
    purpose of the credential.
  - **Detach is in scope.** A privacy mechanism that cannot be reversed is
    worse than none, so withdrawing a persona is as available as asserting one
    — and gated identically, or anyone could strip another member's persona.
    The two authorization `type` values are distinct so neither can stand in
    for the other.
  - **No `persona.rego`.** Attach is gated on a live member session plus proof
    of control of the edge's issuer. A community that already decides whether
    an edge may be published has not obviously earned a second say over what
    its issuer calls themselves. Additive if that is wrong.
  - **No P-DID secondary index.** "List every edge of persona P" is answerable
    from the admin graph; an enumeration surface deserves its own design
    rather than falling out of an index write.
  - **`new_vpc` is used in a wire-shape test, not a mint path**
    (`vtc-service/src/credentials/dtg.rs`). The VTC has no key that may
    legitimately sign a VPC — it is self-issued by a person — so there is no
    `issue_persona`. Pinning the catalog's VPC shape matters more here than
    for the credentials the VTC does mint: drift changes what we *accept*, and
    the failure mode is every conformant VPC in the ecosystem being rejected
    by a VTC that still compiles and still passes its own tests.
  - **Audit** (`VpcAttached` / `VpcDetached`, `vti-common/src/audit/event.rs`)
    records the P-DID with the authenticated member as actor — the same
    attribution decision, and the same accepted residual, as VRC publish. The
    `info!` on both paths carries the persona and not the member.

  `vtc/relationships/persona/0.1` is bound ahead of its publication in the
  upstream Trust Task registry and recorded in `UNPUBLISHED_CANONICAL_OK`
  (`vtc-service/tests/trust_task_manifest.rs`) — the first entry the
  `spec/vtc/` family has had. Deliberate: a payload schema authored now would
  encode this request-level binding as if #9 were closed.

  Design note: `docs/05-design-notes/vpc-persona-annotation.md`.

- **vtc**: Let a member publish a relationship edge without naming themselves in it ([#1061](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1061))

* feat(vtc)!: let a member publish a relationship edge without naming themselves in it

  Publishing a VRC required the credential's `issuer` to equal the caller's
  session DID. That one line is why a member's membership DID ends up inside
  the durable, publishable credential — and the community graph built from
  those credentials is a correlatable member-to-member edge set. DTG
  Credentials asks for the opposite: R-DIDs are RECOMMENDED, unique per
  counterparty "even within the same community", and M-DID edges are a
  bootstrapping allowance to migrate away from.

  The pin was conflating two properties. The first — the VRC was made by the
  party it names as issuer — is provided by the data-integrity proof and is
  untouched here. The second — the party publishing it is the party that
  issued it — is what the pin actually provided, and it is worth keeping:
  issuance and publication are different disclosures, and appearing in the
  community graph should be the issuer's disclosure to make, not that of
  whoever happens to hold a copy.

  So the pin is replaced rather than removed. The session proves community
  membership; a publish authorization signed by the issuing key proves control
  of it. Neither requires them to be the same string.

  The authorization binds to `{type, vrc-hash, aud, sessionId, issuedAt}`, each
  field covering a distinct replay: signatures made over other objects, other
  credentials, other communities, other members' sessions, and unbounded reuse
  within a live session. It is verified and dropped — never stored, logged or
  audited, because it carries `sessionId` and persisting that would rebuild the
  exact membership-to-relationship linkage pairwise identifiers exist to
  remove. Two tests assert that directly, on the stored row and on the audit
  store, since it is the kind of property a later debug log undoes silently.

  The subject-must-be-a-member check is dropped on the pairwise path. It is not
  merely unanswerable once the subject is an R-DID; DTG Credentials is explicit
  that "community membership is not a precondition for issuing, holding, or
  presenting a VRC". The subject's consent to the edge is their publication of
  the reciprocal VRC — the two-VRC edge model — not this community's assertion
  that they exist.

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

- **vtc**: Speak the endorsement model the spec defines ([#1096](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1096))

The endorsement family — `issue`, `list`, `show` — spoke a different model
  from the one the spec defines. Three renames, one per row, and a request
  member that had been deliberately renamed away from the spec's name.

  | canonical `Endorsement` | this service sent |
  |---|---|
  | `endorsementId` | `id` |
  | `typeUri` | `endorsementType` |
  | `issued` | `createdAt` |
  | `subjectDid`, `statusListIndex`, `claim`, `revokedAt` | already matched |

  ## Mapping at the boundary, not renaming storage

  The stored `Endorsement` derives `Deserialize` and serialises `camelCase`,
  so `id` / `endorsementType` / `createdAt` are the on-disk keys of every row
  already written. Renaming those fields would rewrite the persisted fjall
  format and need a migration — for a naming problem that only exists on the
  wire.

  So `EndorsementRow` is a wire type mapping from the stored row, the same
  split `GenerationRow` uses ([#1095](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1095)). Storage keeps the names it has; the API
  publishes the names the spec gives.

- **common**: Send the pagination wrapper in camelCase, as the schemas always said ([#1078](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1078))

`Paginated<T>` carried no `rename_all`, so every list task sent `next_cursor`
  and `total_estimate` against published schemas that say `nextCursor` and
  `totalEstimate`. A direct R3.1 violation, and the same casing-drift class as
  #656/#658 — where an empty `allowed_contexts` silently minted a super-admin.

  Nothing caught it because nothing compared the two. The service sent one
  spelling, `vtc-client` mirrored the service rather than the schema, and the
  admin SPA typed its fields from the service too. All three agreed with each
  other and none agreed with the contract. The conformance witness added in
  #1076 is what finally put them side by side.

  Four consumers move together: the wrapper in `vti-common`, `vtc-client`'s
  `Page<T>`, and the `joinRequests` and `members` admin plugins. `audit.tsx`
  reads a `cursor` member of a different shape and is untouched.

  ## The count goes 33 → 32, not 33 → 28

  The witness refused 28 and accepted 32, which is the useful part of this
  change and the reason the module doc is rewritten rather than decremented.

  Five entries cited the wrapper. Only `relationships/list` becomes fully
  conforming, because it was the only one whose drift was the wrapper alone —
  its spec types `items` as free objects. The other four still diverge at row
  level (`createdByDid`, `vpClaims`, `MemberResponse` members) and keep their
  entries, now describing only what is left rather than restating a casing bug
  that is fixed.

  Closing a shared root cause moves four entries without closing them. A drift
  count that fell by five would have implied more progress than happened, and
  `known_drift_entries_still_diverge_where_they_say_they_do` is what stopped it
  saying so.



## [0.13.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.13.1...vti-common-v0.13.2) — 2026-08-22


## [0.13.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.13.0...vti-common-v0.13.1) — 2026-08-21


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

