# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.5.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.1...vtc-client-v0.5.2) — 2026-09-06


### Added

- **rooms**: Succession, so a room outlives one person's availability ([#1251](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1251))

* feat(rooms): succession, so a room outlives one person's availability

  Implements `rooms/owner/transfer` and `rooms/owner/claim` (specs #359, #361,
  published in trust-tasks-rs 0.17.9) across `vti-rooms`, `vti-rooms-dtg`,
  `vtc-service`, `room-host` and `vtc-client`.

  Ownership is load-bearing for liveness, not just administration: a room's owner
  is its sole committer, so a room with no reachable owner cannot advance an epoch
  — and one that cannot advance an epoch cannot be renewed, cannot admit anyone,
  and lapses to read-only. Without succession, one person becoming unreachable
  ends a shared space.

  Transfer is the owner acting while present, gated on `admin`. Claim needs three
  things at once: a nomination the room itself issued naming this claimant, a room
  that has gone *dormant* rather than merely lapsed, and the claimant's own
  membership. Each closes a different route to a takeover.

  A nomination is a VAC granting `succeed` — deliberately a word no room task
  accepts, so it confers nothing at all while the owner is present. Keeping it out
  of the `Action` enum is what makes that structural rather than a matter of
  discipline: `authorize` cannot be handed it, so no later edit there can quietly
  turn a nomination into a working grant. Verification goes through
  `authority::verify_chain` so the property that matters — the chain reaches *the
  room* — comes from the library rather than a second hand-rolled copy.

  The defence against a hostile claim is the same act as ordinary use. An owner
  who was merely away defeats every pending claim by minting an epoch, which is
  what they would have done anyway; nothing has to be revoked and no dispute has
  to be raised. Hence dormancy rather than lapse — a window that opened the moment
  an epoch expired would make every holiday one.

  A claim does not renew the room. `set_owner` hands over a dormant room and
  leaves it dormant, so the new owner's first act is the one that proves they can
  perform it. A claim that silently renewed would hand the room to someone who
  might turn out to be unable to commit, with the room looking healthy until the
  next lapse a year later.

  Neither host checks that an incoming owner is a member of the MLS group, because
  neither can: a host holds no roster and no group state. Refusing what it cannot
  verify would fail every correct transfer, and treating its own ignorance as
  evidence would convert "I don't know" into "no". On claim the host uses the one
  signal it has — the VMC the room issued — and the spec is exact about what that
  proxy is worth.

  Three defects found on the way, fixed rather than worked around:

- **rooms**: Data rooms end to end — storage, dispatch, verification, MLS, and a host ([#1237](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1237))

* feat(rooms): the data-room storage layer

  A data room is a shared space whose access is governed by credentials the
  room itself issues. This lands the storage and its invariants; the
  Trust-Task dispatch that authorizes operations follows once rooms/* is
  published in the registry (trustoverip/dtgwg-trust-tasks-tf#346) - the
  dispatcher refuses a URI the published registry has no schema for, and
  growing the unspecced allowlist is the wrong fix.

  Written first so that the dispatch layer is a thin wrapper over settled
  behaviour rather than a place where storage decisions get made under time
  pressure.

  The row deliberately carries an owner, a visibility, an epoch and a
  retention period, and NO member list. Not omitted for now - there must not
  be one. The moment this service keeps a roster and consults it, three
  things stop being true at once: the room can no longer move to another
  host without reissuing credentials, this service becomes part of the
  room's membership definition, and a room whose contents we cannot read
  acquires a member list we can.

  Invariants enforced in the store rather than trusted to callers, each with
  a test:

  - An open room refuses ciphertext and a sealed room refuses cleartext, so
    a tier promise cannot be broken by a caller passing the wrong shape.
  - A private room refuses a recorded author: on that tier authorship
    belongs inside the sealed body where only members can read it.
  - A record sealed under a stale epoch is refused, because a reader holding
    the current key could not open it.
  - An epoch advances by exactly one. A gap would leave records sealed under
    an epoch nobody holds a key for; a repeat would let a removed member's
    key open material written after their removal, which is the whole point
    of advancing.
  - Versions are monotonic per room, not per record - one comparable number
    is what a sinceVersion watermark needs. A conflict carries the current
    version so a caller need not re-read, because between a bare rejection
    and the re-read the record can change again.
  - A listing returns tombstones to a watermark caller. Without that a
    puller learns of every create and update and never of a delete, so
    retracted records resurrect on its next full rebuild.
  - Retract and purge are separate verbs: a tombstone keeps the key, version
    and epoch so sync converges and the audit chain holds, and erasure is a
    distinct, higher-trust act.

  Keyspaces registered in ALL and BACKED_UP - the two must partition ALL
  exactly - with the census count moved to 27 and the matching AppState
  fields opened, so the documented ALL-matches-AppState invariant stays
  true rather than merely passing a length check.



### Changed

- **rooms**: Move the group-key and sealing layers into vti-rooms ([#1241](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1241))

A VTA must not depend on a VTC client, and rooms/keys/open needs both
  layers inside vta-service - the VTA is what holds the principal's keys
  and opens a record on an agent's behalf. Today they live in vtc-client,
  so that task could not be written at all without a layering inversion.

  vti-rooms is already the shared home for the parts of a room that are not
  a service, and it is where the ciphertext is stored. Putting the AEAD
  binding beside the storage layer that binds to it closes the other half
  of the argument: the associated data commits to roomId | key | version |
  epoch, and until now the code that seals and the code that stores those
  four fields were in different crates. That is how a binding drifts.

  Both live behind an mls feature, off by default, so a host that only
  stores ciphertext still compiles no OpenMLS.

  SealedRoom no longer holds a RoomSession. It holds the room id and the
  group - and the separation is the honest shape rather than a concession
  to the move: the credentials a caller presents travel to the host on
  every request, and the keys never travel anywhere. Pairing them made a
  client the only place a room could be opened.

  The move surfaced a duplication that was invisible while it compiled.
  vtc-client defined its own Visibility, AuthorityPresentation,
  SealedContent, CleartextContent and three response types, plus all five
  Type URI constants - identical to vti-rooms' and with nothing checking
  they stayed identical. The schema-conformance suite added with the open
  tier validates vti-rooms' copies against the published schemas and could
  not see the client's at all, so those could have drifted freely. They are
  re-exports now, which makes the suite cover both.

  RoomKeyError replaces VtcError for this layer, deliberately not
  vti_common::AppError: a record that does not open is a legitimate outcome
  with a specific meaning, and folding it into Internal would say 'this
  service is broken' about the one case the design most wants to be loud -
  a host relocated a record.



## [0.5.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.0...vtc-client-v0.5.1) — 2026-08-29


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.4.0...vtc-client-v0.5.0) — 2026-08-28


### Chore

- **sdk**: Release vta-sdk 0.30.0 for the added CreateKeyBody field ([#1156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1156))

`CreateKeyBody` gained a `key_id` field while the crate stayed at 0.29.0.
  The struct is exhaustively constructible through the public API, so an
  existing literal no longer compiles — a breaking change under 0.x rules,
  which the semver report has been flagging as its one real finding
  (195 pass, 1 fail) since the field landed.

  Bumps the crate and the nineteen intra-workspace requirements that pin it,
  so `cargo check --workspace` still resolves the path copy and a consumer
  resolving from the registry gets a version that admits the break.



## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.11...vtc-client-v0.4.0) — 2026-08-26


### Fixed

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



## [0.3.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.10...vtc-client-v0.3.11) — 2026-08-22


## [0.3.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.9...vtc-client-v0.3.10) — 2026-08-21


## [0.3.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.8...vtc-client-v0.3.9) — 2026-08-20


## [0.3.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.7...vtc-client-v0.3.8) — 2026-08-18


## [0.3.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.6...vtc-client-v0.3.7) — 2026-08-17


## [0.3.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.5...vtc-client-v0.3.6) — 2026-08-16


## [0.3.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.4...vtc-client-v0.3.5) — 2026-08-14


## [0.3.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.3...vtc-client-v0.3.4) — 2026-08-12


## [0.3.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.2...vtc-client-v0.3.3) — 2026-08-12


## [0.3.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.1...vtc-client-v0.3.2) — 2026-08-12

