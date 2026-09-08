# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
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

