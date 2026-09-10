# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.1.3...vti-rooms-v0.2.0) — 2026-09-09


### Added

- **rooms**: Traces, and a response type for the single-record read ([#1368](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1368))

A commitment lets a reader catch a host that equivocates. A trace proves a
  particular record sits under the root that host just asserted. This serves
  them — and fixes the conformance defect that adding them uncovered.

  Implements trust-tasks-tf#419, released as trust-tasks-rs 0.19.1.

  `rooms/records/get` has never conformed to its published schema. Both hosts
  answered a read by serialising `vti_rooms::Record` — the *storage* record — and
  adding `dataCommitment` to whatever came out:

      "c2VhbGVk" is not of type "object";
      Additional properties are not allowed
      ('author','epoch','nonce','pinned','status','updatedAt' were unexpected)

  It survived because `vti_rooms::wire`'s rule — every wire type appears in
  tests/schema_conformance.rs — can only be applied to types that exist. A
  response that was never a type had no line to be missing from, and a storage
  record reached the wire because nothing stood between them. The consumer is not
  hypothetical: `@openvtc/pnm-core`'s `roomsRecordsGet` is typed on the generated
  payload, so a caller reading `sealed.ciphertext` got `undefined` from a live
  host, with a green type-check on both sides.

  The leaf preimage was not reproducible either. `leaf_hash` canonicalised the
  storage record, so every root it produced was unreachable by any reader:
  `updatedAt` is unix seconds in storage and RFC 3339 on the wire, `epoch` and
  `nonce` are flat in storage and inside `sealed` on the wire, and `epoch`
  serialises as `null` on an open room where the wire has it absent. Survivable
  while the only use was comparing two roots from the same build; not survivable
  once a trace has to be computable by someone else.

- **rooms**: Hosts compute and serve the data commitment ([#1351](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1351))

* fix(rooms): a commitment is a DigestMultibase, not bare hex

  Owed from #1346. The spec that landed with it
  (trustoverip/dtgwg-trust-tasks-tf#411) types `dataCommitment` as the
  framework's `DigestMultibase`, and the helper shipped emitting hex.

  Bare hex hard-codes SHA-256 into the wire contract, which is precisely what
  `DigestMultibase` exists to prevent: multihash names the algorithm in-band,
  so moving off SHA-256 later is a change of value rather than another schema
  revision. `0x12 0x20` then the digest, base58btc with the `z` prefix — the
  same shape `sealed_transfer::bundle_digest_multibase` already produces, so
  the two agree by construction rather than by memory.

  `from_multibase` refuses anything that is not a sha2-256 multihash. A
  commitment is what a comparison turns on, so silently accepting an algorithm
  this build cannot compute would turn "these two roots differ" into "these
  two roots are not comparable" without saying which.

  Two tests, both about the encoding being a contract rather than a detail: a
  commitment decodes to the 34-byte multihash and round-trips, and bare hex, a
  foreign algorithm, a truncated digest and non-multibase are each refused.

  The tree, the leaves and the proofs are untouched — this is the wire
  boundary only.

- **rooms**: A browser can be a room member ([#1347](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1347))

* feat(rooms): a `host` feature, so a room's member half reaches wasm

  `vti-rooms` already had two halves and no name for them: `vta-service`
  imports `mls`/`sealed`/`wire` and nothing else, while `vtc-service`,
  `room-host` and `vti-rooms-dtg` import `storage`/`authz`/`audit`. This
  names the second half `host`, on by default, and makes `vti-common`
  optional behind it.

  `vti-common` describes itself as server-side infrastructure and pulls
  axum, fjall and tokio, so it was the whole of what kept a room's member
  code off `wasm32-unknown-unknown`. With it optional,
  `--no-default-features --features mls` builds there — which is what lets
  a browser hold a room's keys itself rather than ask an agent to. See
  `docs/05-design-notes/data-rooms-demo-site.md`.

  The member half needed **no source changes** to get there. That is a
  property of `error.rs`, which deliberately does not use
  `vti_common::error::AppError` because key material is not a service's
  concern; a decision made for its own reasons that paid for itself here.

  `lifecycle` is deliberately left ungated: only hosts consume it today,
  but it needs nothing from `vti-common`, and a member computing a room's
  lifecycle state to explain it on screen should not need a host's
  dependencies.

  Three things about the wasm plumbing, each of which reports as a
  `compile_error!` that reads like an unsupported target:

  - OpenMLS 0.9 has a first-class `js` feature (`web-time` for the
    `SystemTime` wasm lacks, plus getrandom's JS backend). Declared
    per-target rather than as a feature of this crate, so building for
    wasm just works — verified wasm-only: `web-time` appears in the wasm
    tree and not the native one.
  - There are two getrandom majors in the graph. The 0.4 is ours; the 0.2
    arrives transitively under `openmls_rust_crypto` via RustCrypto's
    elliptic-curve stack, so no feature declared here could reach it.
    `getrandom_02` is a feature shim, not a dependency this crate calls.
  - With both declared per-target, **no `RUSTFLAGS` are needed** — the
    `wasm_js` feature alone selects the backend.

  CI gains two steps in the `features` job: clippy on the member half with
  no host, and a wasm32 `--lib` check, so neither property rots silently.

  `vta-service` now takes `default-features = false`: a VTA holds room keys
  and is never a room's host, so it no longer compiles one.

  * feat(rooms): vti-rooms-wasm — a data room's member half, in a browser

  The MLS group, record sealing and the epoch key chain, compiled to
  WebAssembly, so a tab can *be* a member rather than drive an agent that
  is one. `vti-rooms` supplies all of it; this crate is only the boundary,
  and its job is deciding what crosses.

  **Secrets do not cross.** Everything returned is public — a KeyPackage,
  ciphertext, an epoch number — with one deliberate exception: the
  snapshot, which is key material because OpenMLS persists a group through
  its provider rather than as a value. It goes in IndexedDB and nowhere
  else; the docs say so at the method, since it is the one thing here a
  caller could reasonably mishandle.

  ## Two layers, and why

  Every method appears twice: a plain Rust one with the logic, and a
  one-line `#[wasm_bindgen]` wrapper that converts the error. Not
  ceremony — `JsError` and `JsValue` are imported JS functions, so
  constructing one on a native target panics. A crate whose only entry
  points were wrapped would have no reachable native tests at all, and the
  tests worth having are exactly the ones asserting a *failure*.

  Both tests are of that kind, and both are round-trips rather than unit
  assertions, because everything worth catching happens between the steps:

  - a record must not open at a version or under a key it was not sealed
    for — the binding is in the AEAD's associated data, not merely
    alongside it;
  - a snapshot taken before a commit must *refuse* rather than return
    garbage, which is the failure mode a browser member will actually hit
    (a tab closed for a week, reopened after somebody else joined).

  ## Two API decisions

  - **JSON strings in and out**, not `serde-wasm-bindgen`. The structures
    crossing are the published `rooms/*` wire types and JSON is the form
    they already travel in, so the boundary speaks the transport's
    language and there is one fewer representation to get wrong.
  - **`applyCommit` returns `{ epoch, link }`**, not just the epoch. The
    rung is minted in the one moment any party knows both the outgoing and
    incoming keys; it is added to the member's own chain here, and
    returned because it is also what a host stores on their behalf. A
    member who never uploads one keeps their history only as long as this
    browser does.

  ## Size

  A `wasm-release` profile (`opt-level = "z"`, fat LTO, `panic = "abort"`)
  takes the artifact from 693 KB gzipped to **540 KB**. Separate from
  `release` because it trades compile time and native performance for
  bytes — right for one downloaded module, wrong for the services.
  `wasm-opt -Oz` is worth another slice and is not a cargo concern.

  CI reports both sizes rather than gating on a threshold: one picked today
  would be either slack enough to mean nothing or tight enough to fail on a
  dependency's patch release, and what a reviewer needs is the number in
  the log beside the diff that moved it.

  * feat(rooms): gate the browser member on a room invitation

  A VIC is the consent artefact: joining a room is a two-party act and the
  invitation is the other party's half. Ported from vta-service's
  operations::room_invitation, including its check order.

  The gate is on the MEMBER's side, which looks wrong until you ask what it
  defends. Not the room — this key holder. Minting retains a private key
  against a Welcome that may never come, so a key holder that minted for
  anyone is one anyone can fill; and a Welcome carries a group's secrets,
  so accepting an uninvited one holds keys for a room nobody agreed to
  join. The room's own protection is the owner refusing an uninvited key
  package. Two parties, two threats, neither substituting for the other.

  Verification is lexical: the proof is checked against raw public-key
  bytes and a did:key room carries its key in its own name, so a browser
  needs no resolver and cannot be offline. A did:webvh room would need real
  resolution, and that is the one thing this would grow.

  ## A check the original is missing

  Writing a test per clause — rather than one 'a bad invitation is refused'
  case, which passes with any four of five — showed the forgery clause did
  not bite. Nothing binds the proof's verification method to the ISSUER.
  verify_proof_with_public_key checks a signature against whatever bytes it
  is handed, so resolving the method the proof names and verifying against
  that proves somebody signed it, which is also true of a forgery: mint an
  invitation naming the room as issuer, sign it with your own key, point
  the proof at your own verification method, and every other check passes.

  Added here as its own clause. vta-service's copy has the same shape and
  needs the same fix — reported separately; this is a second copy of a gate
  that should live in vti-rooms where both can share it.

  * feat(rooms): the member's key and its authority presentation, in wasm

  Two halves of one thing: everything a member signs is signed in wasm, so
  the private key never crosses into JavaScript.

  The first cut minted the key with WebCrypto and kept the JWK in
  `localStorage` — a raw private key in a page's heap and in a string store
  any script on the origin can read, contradicting this crate's own rule
  that secrets do not cross. Minting it here costs nothing (`ed25519-dalek`
  already arrives through OpenMLS) and leaves JS holding two opaque
  snapshots and no key. `Debug` is hand-written to redact: the places a
  `Debug` reaches — a log line, a panic, a test failure — are exactly the
  places key material must not turn up.

  `present` mints the authority presentation every host task takes:
  attenuate the room's VAC to one action, sign as the member, and return
  `{membership, authority: [leaf, root], nonce}`. Attenuation refuses to
  widen, so asking for more than the room granted fails here — where the
  member can be told why — rather than as a refusal from a host worded as
  though they were at fault.

  ## It takes no `audience` parameter, and that is the point

  `audience` is not who the presentation is addressed to. `verify_chain`
  compares it to the PRESENTER — "the leaf must be presentable by whoever
  is presenting it" — so it is holder binding, and its job is to make a
  captured presentation worthless to anyone else. A browser member always
  presents its own, so the only correct value is its own DID, and offering
  the choice is offering a way to get it wrong.

  Not hypothetical: `vta-cli-common`'s `RoomTarget` passes the HOST's DID
  as the audience, so `pnm-cli rooms --host-did …` mints a leaf bound to an
  audience no presenter can match — refused as `WrongAudience` every time —
  while omitting the flag leaves the presentation bearer-shaped for four
  hours. Its doc states the intent exactly ("with it, a captured
  presentation is worthless to anyone else") and names the wrong party.
  Reported separately.

  Tests assert against `dtg_credentials::authority::verify_chain` itself,
  not a restatement of it: the presentation verifies, a narrowing to `read`
  does not authorise `curate`, over-asking is refused locally, and a
  captured presentation fails for the thief as `WrongAudience` rather than
  as a bad signature. Also pins the shape the server path never produces —
  a browser member is its own agent, so the leaf's subject and the chain
  root's are the same DID.

  * fix(rooms): a presentation travels as strings, not objects

  AuthorityPresentation types membership as a String and authority as a
  Vec<String>: the credential TEXT is the wire form, and vti-rooms-dtg
  decodes base64url or bare JSON on the way in. present() was emitting
  parsed objects, so room-host refused the whole request as "invalid type:
  map, expected a string" — which reads as a malformed payload rather than
  as the shape mismatch it is, and points at the wrong field.

  Found by sending one to a real host rather than by reading the type.

  The root is now passed through exactly as received instead of being
  re-serialised, so nothing on this side can touch the bytes its proof was
  made over. Both tests assert the wire form — that each authority link is
  a string and membership is one too — because a chain that verifies in a
  test and is refused on the wire is the failure this cost an hour to.

  * fix(rooms): the wasm member links a chain the way its hosts verify one

  dtg-credentials 0.7 changed how an authority chain links — a link's
  `parent` went from naming the parent's `id` to naming a *digest* of its
  claims — so a 0.7 `attenuate` and a 0.6 `verify_chain` cannot
  interoperate. The refusal reads as a broken chain rather than a version
  skew:

      chain link 0 names parent `zQmPvoS…`,
      but was presented after `urn:uuid:0647…`

  Found by pointing a browser member at `room-host` and watching a
  perfectly good presentation be refused. Pinned to what the workspace
  verifies with. Reported upstream as OpenVTC/dtg-credentials#22, which
  asks for ordering guidance and a hint in that error message.

- **rooms**: The record commitment — a Merkle tree over a room's records ([#1346](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1346))

* feat(rooms): the record commitment — a Merkle tree over a room's records

  First of the verified-reads pieces (#1343's build order: the store, then the
  commitment on read responses, then traces). Structure only — nothing serves
  it yet, and no wire shape changes.

  A room's records are signed and room-bound, so a host cannot forge, alter or
  relocate one. **Silence is free**: `rooms/records/list` returns a set and
  nothing says the set is complete, so a host serving nine records from a room
  holding ten is indistinguishable from a room holding nine. This is the
  structure that closes it.

  Three decisions worth stating, because each has a wrong version that looks
  identical from outside.

  **Leaves are sorted by key**, because completeness is a range property. An
  inclusion proof says "this record is here"; only the ordering lets a
  consumer say "and there is nothing between these two keys". A tree over
  unsorted leaves proves everything it contains and nothing about what it
  omits — which is the property being bought. The sort is inside
  `commit_records` rather than assumed of callers.

  **A leaf commits to the whole record**, as canonical JSON (RFC 8785), not to
  a chosen subset. A host that can flip `status` from active to retracted, or
  move `pinned`, or rewrite `author` on an attributed room, rewrites what the
  room means without touching a byte of ciphertext. Picking fields invites
  picking wrongly; a field added to `Record` later is committed automatically.
  The plaintext is never involved — on the sealed tiers the host holds
  ciphertext and commits to what it actually stores.

  **RFC 6962's domain separation and its odd-node rule.** Leaves are prefixed
  `0x00` and nodes `0x01`, without which an internal node's preimage can be
  offered as a leaf. An odd node is promoted rather than duplicated: promotion
  avoids a tree of n leaves colliding with one of n+1 whose last is repeated.
  `root_of` and `inclusion_proof` implement that rule twice and would drift
  silently, so the tests walk every leaf of every tree size 1..=9.

  Ten tests, each written against an attack rather than a mechanism: omitting
  a record moves the root, changing any one field moves the leaf, input order
  does not matter, a leaf and a node over the same bytes differ, a record the
  room does not hold does not prove, and a tampered sibling — or a flipped
  side — fails.



### Fixed

- **rooms**: A commitment is a DigestMultibase, not bare hex ([#1349](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1349))

Owed from #1346. The spec that landed with it
  (trustoverip/dtgwg-trust-tasks-tf#411) types `dataCommitment` as the
  framework's `DigestMultibase`, and the helper shipped emitting hex.

  Bare hex hard-codes SHA-256 into the wire contract, which is precisely what
  `DigestMultibase` exists to prevent: multihash names the algorithm in-band,
  so moving off SHA-256 later is a change of value rather than another schema
  revision. `0x12 0x20` then the digest, base58btc with the `z` prefix — the
  same shape `sealed_transfer::bundle_digest_multibase` already produces, so
  the two agree by construction rather than by memory.

  `from_multibase` refuses anything that is not a sha2-256 multihash. A
  commitment is what a comparison turns on, so silently accepting an algorithm
  this build cannot compute would turn "these two roots differ" into "these
  two roots are not comparable" without saying which.

  Two tests, both about the encoding being a contract rather than a detail: a
  commitment decodes to the 34-byte multihash and round-trips, and bare hex, a
  foreign algorithm, a truncated digest and non-multibase are each refused.

  The tree, the leaves and the proofs are untouched — this is the wire
  boundary only.

- **rooms**: A presentation is bound to its presenter — and dtg-credentials 0.6 → 0.9.1 ([#1356](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1356))

* fix(rooms): bind a presentation to its presenter, not to the host

  `pnm-cli rooms --host-did …` could never work. Every request it made was
  refused as `WrongAudience`, and omitting the flag "worked" only by
  skipping the check it exists to perform — so the flag's two states were
  broken and unprotected.

  `audience` is not who a presentation is addressed to.
  `dtg_credentials::authority::verify_chain` compares it to the PRESENTER —
  "the leaf must be presentable by whoever is presenting it" — so it is
  holder binding, and its whole job is to make a captured presentation
  worthless to whoever captured it. Filled with the host's DID it named a
  party no presenter can ever match.

  The value to bind to was already named a few lines away: `RoomSigner`'s
  doc says "a room request is signed by the party the presentation was
  minted for". This passes exactly that. There is no unbound case left, so
  the warning about one goes, and `--host-did` keeps its real job of naming
  the document's recipient.

  ## The spec says otherwise, and that is filed separately

  `rooms/keys/present/0.1` describes `audience` as "the party the
  presentation is for … a host's identifier, normally". The CLI implemented
  the spec faithfully; the spec and the credential library it runs on
  disagree, identically in dtg-credentials 0.6 and 0.7, so it is not
  version drift.

  This changes the CLI to match the verifier rather than the prose, because
  a presentation that cannot verify protects nobody while being wrong in
  the other direction. Which side should move is a working-group question —
  0.7's own notes point at upstream PR #41, "a key-control demonstration at
  invocation, which removes `audience` as redundant" — and is raised there.

  * fix(rooms)!: stop sending `audience` and `nonce` on rooms/keys/present

  Completes the previous commit, which repointed `audience` at the presenter so
  it would at least verify. It should not be sent at all, and neither should
  `nonce`. Both are removed from `rooms/keys/present` by spec 0.2.

  `audience` named the party that had to PRESENT a credential, not the one it was
  addressed to — so a host DID named somebody no presenter can ever be, and the
  host refused every request. That is now moot: dtg-credentials 0.8.0 removed the
  property and made the real rule explicit, which the VTA was already satisfying.
  The leaf grants to the DID this VTA authenticated, and a host refuses a chain
  whose leaf grants to anyone else. Who may present is established, not declared.

  `nonce` was written into the presentation object, which is closed and has no
  member for it — so a caller supplying one got a presentation the host rejects
  as malformed. It could not have been made to work: every signature in a
  presentation is an ISSUER's, never the presenter's, so a challenge inside it is
  unauthenticated and a replay copies it along with everything else. Freshness is
  the request's, via `issuedAt` and the duplicate-execution rule keyed on
  document `id`.

  ## A second live instance, found while doing this

  `rooms/keys/backfill` passed the caller-named host as the audience in
  `vta-service`, exactly as that spec's normative MUST instructed. Every backfill
  this VTA attempted was refused for the same reason. What actually makes a
  caller-named host safe is that the leaf grants to the VTA: naming a host
  transfers no standing. It does hand that host sight of the principal's
  credentials, which is a disclosure rather than an escalation, and the comment
  now says so.

  ## Nothing binds a presentation to a host, deliberately

  A chain is scoped to the ROOM. One rooted in a room confers nothing anywhere
  else, and any host serving that room would honour it — a room may have more
  than one host, and moving between them without reissuing credentials is the
  point. Binding a request to its destination is `recipient` on the document that
  carries the presentation, per SPEC.md §4.8.2, which its proof covers.



## [0.1.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.1.2...vti-rooms-v0.1.3) — 2026-09-08


### Added

- **vtc**: An operator can see the rooms their community hosts ([#1325](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1325))

* feat(vtc): an operator can see the rooms their community hosts

  A VTC stores rooms and had no way to show its operator which ones. That is not
  a small gap for a host: §9 obliges it to notify a room's owner before reclaiming
  storage, and an operator who cannot list their rooms cannot send that notice.

  `GET /v1/rooms`, admin-gated, plus `vti_rooms::storage::list_rooms` under it.

  ## What a host may honestly say about a room it cannot read

  The row, and nothing derived from the room's contents. Owner, tier, retention
  policy, epoch, lifecycle state, expiry, retention days, mirror-of, timestamps.

  Invariant I1 makes the owner visible at EVERY tier, including `private`,
  precisely so a host has a party it can reach about quota, abuse and lifecycle —
  so listing discloses nothing the design withheld. There is no records endpoint
  here and no member list to return, because no host has one.

  ## Plain REST, deliberately not a Trust Task

  Every `rooms/*` task is authorized by credentials the ROOM issued, verified
  against the room's own identifier — invariant I5, and what lets a room move
  hosts. This asks the opposite question: what is this OPERATOR storing. It is
  answered from the host's own admin authority, so pairing it with a room task
  would claim a room governs an answer it has no view of.

  ## Not paginated, and the comment says when that expires

  A host's room count is bounded by what its operator agreed to store, not by
  anything a caller controls. If that stops being true, `list_records` already has
  the cursor shape to copy.

- **rooms**: Serve the epoch key chain, so a joining member can read the room ([#1314](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1314))

* feat(rooms): serve the epoch key chain, so a joining member can read the room

  Completes the mechanism #1300 built and #1305 made conformant. Wires the two
  Trust Tasks published in dtgwg-trust-tasks-tf#387.

  `rooms/epoch/mint` now carries the rung the advance produced. Minting is the
  only moment one party holds both the outgoing and incoming epoch keys, so it is
  the only call that can carry it — and a room that advances without one keeps
  working while silently losing the ability to read everything written before.

  `rooms/epoch/chain` serves the accumulated rungs, gated on `read`: reading the
  room and reading the parts written earlier are the same act. What leaves is
  ciphertext, since the key that opens a rung is a storage key no host holds — a
  caller with the whole chain and no epoch key learns only how many epochs the
  room has had, which its epoch number told them. That property is what lets a
  *host* answer this at all, rather than requiring the owner to be online whenever
  somebody joins.

  Both hosts implement both. Two MUSTs from the spec are enforced: a rung whose
  epoch does not match the advance is refused outright, and a rung already held
  for an epoch is never replaced — a second one is either a replay or a
  re-pointing of the room's history at key material of somebody else's choosing.

  The keyspace is BACKED_UP, and not optionally: a restore that brings back a
  room's records without its chain hands the members a room they can see the shape
  of and cannot read.

  ## What this does not finish

  A joined member's *agent* still cannot read history. `rooms/keys/open` resolves
  from the chain the member's VTA accrued by applying commits, and a joiner's is
  empty; no task delivers rungs into a VTA. The mechanism, the storage and the
  wire all exist — what is missing is the leg from a member's client into their
  own VTA, which needs another spec round. Recorded in the design note §12.2 and
  the operator guide rather than left implied by a passing demo.



### Fixed

- **rooms**: Make the retention policy govern something ([#1318](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1318))

`RetentionPolicy` shipped in #1300 as a field that was set and never read, and
  `links_epochs()` was defined and never called. A room declared `FromJoin` would
  have had rungs stored for it anyway — the policy was documentation.

  ## The default was also wrong

  It defaulted to `FromJoin`, reasoning that a room stored before the chain
  existed "actually has no links". That confuses what a room *has* with what it
  will *do*. A pre-chain room holds no rungs and never can for the epochs it has
  already left behind — but it can chain from here, and because this policy is
  immutable, defaulting it the other way would condemn every legacy room to keep
  losing its history at every membership change. Which is the defect the chain
  exists to fix.

  So the default is `Chained`, and its unreachable early epochs are a fact about
  its past rather than a policy about its future.

  ## Enforced, not dropped

  Both hosts now refuse a rung for a room that does not chain, rather than
  silently discarding it. Storing it would give the room a chain it declared it
  would not have; discarding it quietly would let a client believe history was
  being retained when it was not.

  `FromJoin` is not reachable over the wire — `rooms/create` has no member for it
  until that spec lands — which is exactly why the guard is worth a test now. An
  unreachable branch is the kind that rots, and this one was inert code until the
  test existed. The room-host test writes the room straight to the store, the same
  technique its succession tests use for states no handler can produce.



## [0.1.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.1.1...vti-rooms-v0.1.2) — 2026-09-07


### Fixed

- **rooms**: Authorize registering a room, which nothing did ([#1274](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1274))

`rooms/create/0.1` was the one verb neither host authorized. The document's
  proof was never verified on that path and the signer was never compared to
  `ownerDid`, so anyone who could reach the endpoint could register a room row
  naming any party as its owner - filling a host's store with rooms attributed
  to people who never agreed to own them, and taking identifiers from under
  their real owners. Every other verb verifies the proof and the authority
  chain; this one fell through because it is the one operation no chain can
  authorize, and the check it needed instead was never written.

  Create cannot be authorized by a chain: at the moment it runs the room has
  issued nothing, so no credential in the world speaks for it. What a host does
  have is the proof on the request, and that is what makes `ownerDid` a fact
  rather than a field anyone can fill with anyone. So the presenter must be the
  party they name as owner, and the room is then written from the authorization
  rather than from the payload.

  The decision lives in `vti_rooms::authz::authorize_create`, beside the chain
  authorization it complements, because a room host and a VTC disagreeing about
  who may register a room is exactly the class of drift that crate exists to
  prevent. It returns an `AuthorizedCreate` with no public constructor, so a
  handler that skips the check does not compile - the same typestate the rest
  of the family uses.

  What this deliberately does not do is prove control of the identifier. A
  party can still register a `roomId` they do not control while naming
  themselves owner, denying that id to its real owner on that host. The row
  confers nothing - every later verb needs credentials the real room issued -
  so it is a nuisance rather than a takeover, and bounding it is quota and
  access control, which is the availability row of the trust model. Proving
  control would mean the room signing its own registration, which would exclude
  every owner whose room key cannot sign a request document.

  Behaviour change for any caller that relayed a registration on an owner's
  behalf: there were none in the workspace, and the two hosts, their tests and
  the `data_room` example all already signed as the owner.



## [0.1.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.1.0...vti-rooms-v0.1.1) — 2026-09-07

