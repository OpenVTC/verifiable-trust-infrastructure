# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.19.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.18.0...vti-rooms-v0.19.0) — 2026-10-18


### Fixed

- **rooms**: Record a sealed body's version when it is stored, never guess it at curation ([#2187](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2187))

#2185 recorded the sealed-at version at a record's first curation, taking the
  record's version then as the one its body was sealed at. That holds only if the
  record had never been curated — and a record stored by a host that predates
  `sealed_version` may already have been, with nothing recorded. Restoring such a
  record (archived by the old host) stamped the archived version as sealed-at; the
  VTA then opened it only there, and it opened for nobody, with the host now
  asserting the wrong answer instead of saying nothing.

  The spec already says when to record it: "A host MUST record the version a body
  was sealed at when it stores it" (rooms `_shared/0.1` `SealedRecord.version`).
  `put_record` now does, and `curate_record` leaves it alone, so an older record's
  stays unknown and is served without `sealed.version`, which is what tells readers
  to search earlier versions. `committed()` serves it only where it differs from the
  record's own version, so an uncurated record's wire form and commitment are
  unchanged.



## [0.18.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.17.0...vti-rooms-v0.18.0) — 2026-10-18


### Added

- **rooms**: Rooms/revocations/{put,get} — a host refuses what the room withdrew, at once ([#2173](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2173))

A room had no way to take back a grant before it expired: a host authorizes from
  credentials the room issued and keeps no roster, so a removed member's VMC and
  VAC chain stayed good at the host until `validUntil`. trust-tasks-tf #804 adds
  the room's revocation list — signed by the room, cumulative, numbered — which an
  administrator delivers to each host serving the room. This is the host half.

- **rooms**: A room's own profile — rooms/keys/profile/{read,write}, sealed inside the room ([#2171](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2171))

Implements trustoverip/dtgwg-trust-tasks-tf#807 on the key holder's side. A
  room's name, description, tags and emoji (RoomProfile) now live inside the
  room: one record per epoch at profile_key(E) — HKDF-SHA256 over the epoch's
  storage key, info "openvtc/room/profile/v1" || roomId || u64be(E), 16 bytes,
  base64url — sealed like any record, so the host stores one more opaque record
  and cannot tell which one names the room. An open room's is the record at
  `room-profile`, its signed body in cleartext.body.

  VTA (vta-service):
  - rooms/keys/profile/read/0.1: walks from the current epoch down (bound 32),
    fetching each location as the member under their own `read` grant,
    verifying the host's reply as rooms/keys/read does, and takes the newest
    profile it accepts (`found`, `stale` below the current epoch), stops at a
    retraction (`cleared`), or answers `absent`, with `searched`.
  - Readers decide who may name the room
    (operations::room_profile::check_statement): the SealedRecordBody rules
    (1)-(4) — no unknown member, the author's assertionMethod proof, signed for
    the location read, the host-recorded author on attributed — plus
    RoomProfileStatement items 1-4: a profile and nothing a record carries,
    sealed under the epoch that located it, issuedAt within
    [updatedAt − 1h, updatedAt + 5m], and an authority chain conferring
    `curate` or `admin` on the author at the room's scope, every link valid at
    issuedAt (vti_rooms_dtg::profile::verify_profile_authority). Anything that
    fails is ignored and reported in `rejected` with its reason and author; a
    rename by a member holding only `write` is `noAuthority` and the room keeps
    the profile before it. This VTA holds no RevocationList, so item 5 never
    applies (revocation is not retroactive).
  - rooms/keys/profile/write/0.1: refuses `noAuthority` before contacting the
    host without `write` and `curate`/`admin` (`curate` to clear); signs the
    statement as the principal (assertionMethod, through the gated oracle) with
    the room-issued chain inside, pads the signed body to a 1 KiB multiple,
    seals it under the current epoch and puts it as the member under a `write`
    grant; re-seals for the version the host assigned, then `contended`.
    `clear` retracts the current location with a `curate` grant, storing a
    profile there first when it holds none. Delegates are refused.
  - The epoch-advance re-write: rooms/owner/group/{add,remove,renew} read the
    profile before the advance and write it again under the new epoch as the
    owner once the host accepts — never failing, delaying or undoing the
    advance (tried a few times, then logged), never for `absent`/`cleared`,
    never retracting the earlier one (add 0.1 and 0.2, remove, renew; the
    speaker is HostCall::profile_speaker, so a later version reuses it).
  - rooms/keys/read does not open a profile location (answers
    ext["org.openvtc.rooms"].roomProfile) and rooms/keys/browse leaves profile
    records out, counting against everything the host listed.
  - Both tasks dispatched ([None Secret true] / [Mutating Metadata true]),
    classified RetrySafe in vta_sdk::retry_safety, counted in budget, guarded in
    vta-mcp, with conformance entries.



### Fixed

- **rooms**: A curated sealed record opens again — keep the version its body was sealed at ([#2185](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2185))

* fix(rooms): a curated sealed record opens again — keep the version its body was sealed at

  Archiving, restoring or pinning a record on an `attributed` or `private` room
  left it unreadable to every member ("record did not open: it was sealed under
  a different key, epoch, or location"). `curate_record` keeps the body unless it
  retracts but moves the record to a new version, as rooms/records/curate/0.1
  requires; the body is bound — by the AEAD (`sealed.rs`, `room|key|version|epoch`)
  and by its author's signed location (`SealedRecordBody`) — to the version it was
  sealed at, and nothing remembered that version. Every reader opened at the new
  one. No test curated a sealed record and read it back.

  Rooms `_shared/0.1` `SealedRecord` gains `version` (dtgwg-trust-tasks-tf):

  Host (vti-rooms, both room-host and vtc-service):
  - `Record::sealed_version` keeps the version a kept body was sealed at, set at
    the first curation of a sealed body and never moved by a later one; a new
    body (`put_record`) or a retraction clears it. Stored rows without it load
    unchanged (`serde(default)`).
  - Served as `sealed.version` only where it differs from the record's own, so
    no record changes shape until a curation needs it; part of `sealed`, so the
    committed leaf covers it. Mirrors copy it (`Record::from_wire`).
  - `SealedContent::sealed_at` refuses a `sealed.version` above the record's.

  Agent (vta-service):
  - `room_groups::open_record_at` opens at a given version and, with
    `Search::Earlier`, searches earlier ones newest first — never later — and
    names the version that opened. For records curated by a host predating
    `sealed.version`: the AEAD makes a wrong guess fail rather than mislead.
  - rooms/keys/read and the profile reader open at `sealed.version` (searching
    where the host gave none) and check the profile's location there.
    rooms/keys/open searches from the version the caller passed. Both say where
    the body opened in `ext["org.openvtc.rooms"].sealedAt` when it is not the
    version asked, because the caller verifies the author's signature there.

  CLI (vta-cli-common): `open_and_verify` opens at the sealed-at version and
  verifies where the VTA says it opened (refusing a later one). `pnm rooms file
  get` parses the host's reply with a generated type that gains `version` with
  the next trust-tasks-rs; until then the VTA's search covers it.



## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.16.0...vti-rooms-v0.17.0) — 2026-10-16


### Added

- **rooms**: Rooms/owner/group/add 0.2 — a repeated admission is answered with its Welcome ([#2146](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2146))

* feat(rooms)!: rooms/owner/group/add 0.2 — a repeated admission is answered with its Welcome

  Serve `rooms/owner/group/add/0.2` (trust-tasks-tf #795) beside 0.1, and
  raise the trust-tasks-rs floor to 0.31.11, which carries it.

  Under 0.1 a caller that lost an admission's answer and sent the identical
  request again was refused `alreadyMember`: the member had a leaf and no
  Welcome anyone could give them. 0.2 item 8:

  - The owner's VTA keeps the last admission it applied for a room —
    member, the KeyPackage's KeyPackageRef (RFC 9420 §5.2), epoch and
    Welcome — in `room_groups` (`room-admitted/<room>/<persona>`, beside the
    pending advance that already holds the same Welcome, under the same
    storage encryption and backup membership). It is discarded when the
    owner builds its next advance of the room, after 24 hours (checked on
    read, and swept by the storage thread), and with the member's group.
  - A request naming the same room, a string-equal member and a KeyPackage
    with the same KeyPackageRef is answered — after item 1 and the
    authorization checks — with that epoch and Welcome: the host is not
    contacted, the group not changed, no new Welcome built. Anything else
    for a member with a leaf stays `alreadyMember`.
  - Item 6 hands over to item 8: a pending admission settled by the
    identical request becomes the retained one and answers it.
  - 0.1 is unchanged.

- **vtc**: The `rooms` topic on the admin console's live channel (vtc/admin/events 0.2) ([#2136](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2136))

Serve `vtc/admin/events/subscribe/0.2` beside 0.1 (trust-tasks-tf #767, in
  trust-tasks-rs 0.31.2+). The topic set is closed per version: 0.2 adds `rooms`
  and nothing else, a 0.1 subscribe that names it is refused by its schema, and
  every stream answers — its `#response` and every hint — at the version it was
  opened with, so 0.1 consoles and `cnm actions watch` are unchanged.

  `rooms` is effective for holders of `vtc.rooms.admin` (subscribe 0.2
  §Authorization; `admin_events::read_capability`), who are answered on
  `vtc/rooms/list`, `vtc/rooms/usage` and `vtc/storage/configs/list`. It is a
  countless hint, sent per event 0.2 producer rule 4 when a room is registered or
  removed, a room's lifecycle state changes, a room's usage or a storage config's
  held bytes crosses 80/95/100 % of its limit or capacity in either direction, or
  a storage config is created, changed or changes state. The stream fingerprints
  exactly those facts, read as the rooms reads report them, so holdings moving
  inside a band or a live room renewing send nothing. Lifecycle is computed from
  the clock and never written, so a stream holding `rooms` also wakes itself at
  the next transition (`vti_rooms::Room::next_lifecycle_change`).



## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.15.0...vti-rooms-v0.16.0) — 2026-10-15


### Added

- **rooms**: Direct uploads — rooms/blobs 0.2 straight to storage, presigned by the VTA (trust-tasks-tf #775) ([#2121](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2121))

* build(deps): trust-tasks-rs 0.31.5 floor — external/credentials/issue 0.2 (trust-tasks-tf #775)

- **vta**: Rooms/owner/group/renew renews a sealed room; pnm rooms renew refuses a sealed room ([#2112](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2112))

Implements trustoverip/dtgwg-trust-tasks-tf#773.

  A sealed room's (`attributed` / `private`) epoch is its MLS group's epoch plus
  one, so a bare `rooms/epoch/mint` moves the host and no member: every write is
  then refused as sealed under a superseded epoch, and the owner's next
  group/{add,remove} fails epochConflict. Until now a sealed room with a stable
  membership had no correct way to renew, and one way to brick itself that
  looked like a renewal.

  The VTA now serves `rooms/owner/group/renew/0.1`, the third advance beside add
  and remove, on the same remote-first machinery:

  - Item 1: `noGroup` (an open room renews with rooms/epoch/mint), `noAuthority`
    before anything is settled or built.
  - Items 2, 3, 7: `vti_rooms::sealed::SealedRoom::renew` builds a self-update
    commit (no proposal adding or removing anyone) and the epoch link on a copy;
    `room_groups::prepare_renew` retains it durably as the room's one pending
    advance, of the new kind `AdvanceKind::Renewal`, before anything is sent.
  - Items 4, 5: `rooms/epoch/mint` (epoch, link, commit, the owner persona's
    `admin` presentation, reason), signed as the owner persona; applied on
    acceptance, discarded on refusal (`hostRefused`, or `epochConflict` with
    `details.hostEpoch` on `nonSequential`), kept on an unknown outcome
    (`hostUnreachable`).
  - Item 6: any pending advance — admission, removal or renewal — is settled
    through `rooms/info` before another is built.

- **rooms**: Rooms/blobs 0.2 — the single-use upload key, and reads straight from storage (trust-tasks-tf #771) ([#2108](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2108))

* build(deps): trust-tasks-rs 0.31.4 floor — rooms/blobs 0.2 and rooms/keys/act (trust-tasks-tf #771)

- **rooms**: Backfill from the CLI, and say plainly when a member was removed ([#2097](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2097))

Found in a live run of a two-VTA room on a VTC:

  - A member who had just joined could not read anything written before they
    joined from the CLI: the VTA's rooms/keys/backfill fetches the history from
    the host, but nothing called it. New `pnm rooms keys backfill --room
    --host-did` (VtaClient::room_backfill) walks the chain down until the whole
    retained history reads or the host has no more.
  - `pnm rooms get` told every member who could not open a record to ask for the
    latest commit, including one whose record was older than their group. It now
    names the remedy for each case: backfill for an older record, `keys commit
    --host` for a newer one.
  - A removed member applying their own removal got GroupStateError
    (UseAfterEviction) from the key export. vti-rooms now detects the eviction
    when the commit merges and returns RoomKeyError::Removed ("this commit
    removed this holder from the group…"), and the CLI says what it means.
  - Wording: "an authority credential"; group-create's next step no longer tells
    an owner to issue credentials they already issued.

- **vtc**: Console Storage page, moving a room's storage, and the rooms' defaults ([#2081](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2081))

P9 part 3b (docs/05-design-notes/data-rooms-files.md §7, §8.1).

  - Storage (/storage, vtc.rooms.admin): every storage config with what it
    holds against its capacity, its credential state (never a credential) and
    its health; configs whose credential is `required` — as after a restore —
    are listed first. A config's own page probes it (optionally writing,
    reading back and deleting a canary) and shows each step, changes its
    label, capacity or default, and retires it. "New storage" creates a
    `local` config or an `s3` config through an external account at the
    community's VTA, named by its context and identifier: the form asks for
    nothing secret. Kinds and auth modes this build does not serve (ambient,
    sealed, gcs, walrus) are not offered.
  - A room's page gains "Send new uploads to other storage"
    (vtc/rooms/storage/assign/0.1). Its existing files stay where they are.
  - Create, update, retire and assign take the requester's operation-bound
    step-up and are parked for another holder of vtc.rooms.admin (§7.4); the
    screens say "Sent for approval" and link the action, never "Saved".
    Retiring the default or a config with rooms is not offered, as the VTC
    refuses both.
  - Data rooms gains a Defaults card (the design's Settings ▸ Rooms; the
    console has no Settings area): each room's and each member's limits, the
    host-wide largest file, capacity and how long a deleted file is kept,
    read-only, with the configuration sections that change them.

  To carry those defaults, vtc/rooms/list's ext["org.openvtc"].roomFiles now
  holds, when files are on, `defaults.{room,member}` (each byte measure capped
  at the host ceiling, as reported limits are), `maxFileBytes`,
  `orphanGraceHours` and `storageCapacityBytes` when set. Files off still
  answers `{ enabled: false }` and nothing else. vti-rooms gains a read-only
  BlobHost::host_limits() accessor.

  The storage response shapes are rendered from the specification
  (vta_sdk::openapi wrappers → admin-ui/openapi.json → wire.ts). Census
  updates: the list-limit census and its Rust counterpart gain
  vtc/storage/configs/list (100), the sidebar census gains Storage, and the
  console document-type manifest gains the seven storage tasks.

- **vtc**: Room usage, room detail and limit overrides — vtc/rooms/{get,usage,limits/set} and rooms/usage ([#2077](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2077))

P9 part 2 (docs/05-design-notes/data-rooms-files.md §6.2–6.3, §8.1): the host
  tasks the console's room detail and Usage pages read, over the history and
  overrides #2073 put in vti-rooms.

  vtc/rooms/get (vtc.rooms.admin): one room's host record, assigned config and
  every earlier config still holding its blobs, effective limits with each scope's
  source and the host ceiling, usage and orphans, the ten largest blobs by size
  only, and on rooms that are not private a count of members with files — never
  their DIDs (item 5).

  vtc/rooms/usage (vtc.rooms.admin): rows grouped by room, member, storage config
  or day, filtered by room, member, config and an inclusive date range (default
  the last 30 days; invalidRange past 400 days, inverted, or before the oldest
  kept day), sorted, and paged by a cursor bound to its query (invalidCursor
  otherwise). Member figures only on rooms that are not private
  (memberUsageUnavailable when one is named). Activity by config is attributed to
  each room's current assignment.

  vtc/rooms/limits/set (vtc.rooms.admin): an override for the room, its members by
  default, or one member; refuses aboveCeiling, memberLimitsUnavailable and
  invalidCombination as declared, answers the effective limits, the target scope's
  usage and overLimit, and is audited (new RoomLimitsChanged event: room, target,
  previous, current, reason). Not parked, as the specification says: an allowance
  is reversible and loses nothing.

  rooms/usage (the room owner's read, an admin chain) on both hosts, through
  vti_rooms::blob_tasks::usage: one entry per member holding storage or an
  override, paged; notAvailable on a private room.

  vtc/rooms/list moves to vtc.rooms.admin, as §6.2 says it should: a community can
  hand room hosting to someone who is not a full administrator.

  Both censuses carry the new tasks: conformance witnesses for the three, and
  error-code witnesses for every code they declare.

- **rooms**: Daily usage history, member index and limit overrides for room files ([#2073](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2073))

The host-side data the console's room detail and Usage pages read
  (docs/05-design-notes/data-rooms-files.md §6.2–6.3, phase P9), in vti-rooms so
  a community and a standalone room host count the same way.



### Fixed

- **pnm**: Rooms and setup messages say what happened and print the fix ([#2126](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2126))

Three operator-facing messages from a live run.

  A sealed-room write at a superseded epoch (after `pnm rooms owner
  group-renew`, before the member applied the commit) printed a raw HTTP 400
  body. The VTC and room-host now refuse it with the declared
  `rooms/records/put:epochMismatch` (vti_rooms::blob_tasks::record_epoch_refused,
  checked before the store, which keeps its own check as the backstop), and
  pnm matches that code to say the room moved on and print
  `pnm rooms keys commit --room <room> --host <url> [--host-did <did>]` with
  the real values.

  A member removed from a sealed room was told "a commit has not been
  delivered" when reading a newer record. The VTA now records the removal
  (`room-removed/<room>/<persona>`) when it applies the commit that removed
  its member, clears it on a fresh join, and `rooms/keys/open` answers the
  declared `unknownEpoch` with `details.reason` `removed` or `notDelivered`
  (as `rooms/keys/file-key` already does). `pnm rooms get` tells a removed
  member so, without suggesting `keys commit`; a member who is only behind
  gets the catch-up command with the real values.

  `pnm setup continue` always ended with the `vta import-did` advice. It now
  authenticates as the phase-1 identity (which is also the cold start's
  rotation) and prints the advice only when the VTA refused it or could not
  be reached; on success it reports the rotated DID, which is also what the
  non-interactive JSON line now carries as `admin_did`.

- **vtc**: Admit room traffic on what it proves, not the anonymous per-IP governor ([#2102](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2102))

Every `rooms/*` Trust Task reaches the VTC on the unauthenticated chain and
  was charged to the per-IP `unauth` governor: a burst of 10, then one request
  every 5 s, shared by everyone behind one address. Two members on one machine
  were refused within seconds, and `pnm rooms file get` of a 300 KB file 429'd
  every time. Upload chunks fared worse: above 64 KiB they also took the
  large-document budget, five a minute per address and sixty across the node.

  A `rooms/*` document (the closed set the rooms dispatcher serves) now leaves
  the anonymous governor and is charged, in `routing::trust_task_admission`:

  - before anything is verified, to its address's room ceiling
    (`room-address`, default burst 400 then one every 10 ms). A document that
    never verifies, or that its room never authorizes, costs that ceiling 25
    more, so an unverifiable flood from one address is held to about four a
    second once its burst is spent;
  - once the room has authorized it and before the work, to the presenter's
    budget in that room (`room-presenter`, burst 120, one every 100 ms), or for
    an upload/download chunk, once the presenter is shown to hold the transfer
    (`BlobHost::transfer_room`), to the transfer budget (`room-transfer`, burst
    200, one every 20 ms: a 100 MB file at 256 KiB chunks waits ~4 s past the
    burst). Keys are a hash of (room, presenter) under a per-process secret, and
    are charged only after the room's chain verifies, so two members behind one
    NAT have independent budgets and nobody drains a member's by naming them.

  An upload chunk charged to the room ceiling over HTTPS skips the
  large-document budget (`size::check_for_known_issuer_with`); over DIDComm/TSP
  it keeps it. Every refusal keeps the 429 contract (x-rate-limit-source: vtc,
  Retry-After, JSON body naming the limiter); the three limiter names join the
  table in `routing::rate_limit`.

  The budgets are an optional `[rooms.rate_limits]` section (address_*,
  presenter_*, transfer_* as `_burst` and `_interval_ms`); absent, the defaults
  above. Documented in docs/02-vta/data-rooms.md §8.2 and
  docs/03-vtc/website-and-admin.md.

  vtc-client's room calls now wait out a Retry-After of up to 30 s and retry
  (up to 5 attempts, re-signed each time) for reads only: records get/list,
  info, epoch chain/commits, blobs get and download chunks. Writes are never
  retried.

  vti-rooms gains `BlobHost::transfer_room` (additive).



## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.14.0...vti-rooms-v0.15.0) — 2026-10-13


### Added

- **vtc**: Storage configs — where a community keeps its rooms' files, changed only with consent ([#2052](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2052))

Phase P4 (first part) of docs/05-design-notes/data-rooms-files.md §7.



## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.13.0...vti-rooms-v0.14.0) — 2026-10-12


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.12.0...vti-rooms-v0.13.0) — 2026-10-11


### Added

- **vtc**: Serve room files — blobs, records 0.2 and rooms/info, off until enabled ([#2040](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2040))

A community VTC now hosts room files the way room-host does
  (data-rooms-files.md P5), so `pnm rooms file put/get` works against a VTC.

  One implementation for both hosts: vti_rooms::blob_tasks. room-host's file
  handlers mapped each task onto BlobHost, with the spec's declared codes and
  generated response types. That mapping moves into vti-rooms. Each function
  takes the room, the authenticated presenter and the chain's authorization,
  and returns a body checked against the generated response type, or a Refusal
  the host renders. room-host keeps only its transport, parsing and chain
  verification, and its 47 tests pass unchanged. The VTC renders the same
  results through its own reply helpers, so the two hosts cannot answer one task
  two ways.

  The VTC:
  - registers, by generated payload type: rooms/blobs/upload/{begin,chunk,
    commit,abort}, rooms/blobs/{get,chunk}, rooms/info and
    rooms/records/{put,get,list} 0.2, and adds them to the shared
    ROOMS_DISPATCHED_URIS, pinned against the registry;
  - uses the same record path as room-host. put (0.1 too, since a rewrite that
    names no blobs releases them) holds prepare_record across the write and
    applies it after. A curate that retracts releases the record's blobs.
    get/list 0.2 read under a snapshot;
  - holds a BlobHost in AppState and runs a GC sweeper;
  - adds the keyspaces room_blobs (backed up: the index and usage) and
    room_blob_transfers (excluded: transfers in flight);
  - has a new `[rooms.files]` section mirroring room-host's flags.

  **Uploads are off by default** on a VTC (`enabled = false`). Until storage
  configs exist, a file goes to a local directory under limits that apply to
  every room alike, and an operator should choose that. When off, `begin`
  answers filesDisabled, while stored files and records without files are still
  served. room-host, a standalone host, keeps its default.

  Size gate. Upload chunks (360 KiB) and begin (320 KiB) declare sizes above the
  64 KiB default, which the VTC granted only to issuers with an ACL entry, and
  room members hold none. Room tasks now count as served for sizes. A large
  upload/chunk is admitted only from a claimed issuer holding an open, unexpired
  upload here (BlobHost::holds_open_upload). A large begin is admitted only when
  uploads are on and its payload names a room hosted here. Both are charged to
  the same per-address LargeDocumentBudget, and a claim that fails verification
  doubles the address's cost, like any other.

  rooms/info's specification said RECOMMENDED for its proof, though the chain
  must bind to the signer. trustoverip/dtgwg-trust-tasks-tf#750 makes it
  REQUIRED. Until that reaches trust-tasks-rs, an interim
  DISPATCHED_WITHOUT_PROOF entry records why the rooms arm refuses an unsigned
  caller anyway. The census fails once the specification agrees, which forces
  the entry out with that bump.



## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.11.0...vti-rooms-v0.12.0) — 2026-10-11


### Added

- **rooms**: Room files on the host — blob store, uploads, downloads and limits ([#2018](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2018))

* feat(common): a BlobStore for room files, with local-directory, S3 and GCS backends

  Room files are a record plus a blob; the blob is the file's ciphertext, held outside the room's keyspaces. vti_common::blob_store is node-neutral, beside backup_transfer, so a standalone room host and a community share one store and one conformance suite (data-rooms-files.md §5.3).

  - BlobStore: put (idempotent on the key), get_range, delete (Deleted | Lapses | Unsupported), health.
  - LocalDirStore: plain files, written via a synced temp file and renamed, owner-only. Always compiled.
  - ObjectStoreBlobs over object_store 0.14: S3-compatible (feature blob-s3) and GCS (feature blob-gcs), credentials from the environment for now. object_store passes cargo deny (advisories, bans, licences, sources).
  - Keys are rooms/<first 32 hex of SHA-256(roomId)>/<blobRef>: the store never learns a room's identifier, and the per-room prefix is what a downscoped credential will name.
  - blob_ref_of_manifest: the BlobRef is the sha2-256 DigestMultibase of the manifest's JCS form, computed by the host.
  - conformance::run, which every backend's own test calls.

- **rooms**: Room files — file keys, STREAM sealing and rooms/keys/file-key ([#2017](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2017))

* feat(rooms): file keys, STREAM sealing and blob manifests in vti-rooms

  Adds vti_rooms::files, the construction rooms/_shared/0.1/blobs.schema.json FileManifest specifies (trust-tasks-tf #739): a per-file key, HKDF-SHA256 over the epoch storage key salted with the fileId and bound to the room and epoch; ChaCha20-Poly1305 STREAM segments whose nonce counts and whose associated data carries the final flag, so truncation, reordering and splicing fail to authenticate; one sealed segment per transfer chunk; the blob manifest and its BlobRef (sha2-256 over JCS); Padmé padding; and streaming sealer and opener that refuse a file whose plaintext digest is not the one its author signed. The manifest and digests build without the mls feature so a host can check them; the keyed half is behind mls with the rest of the member half. SealedRoom gains file_key_for_seal and file_key_for_open, walking the epoch chain as open_record does. Test vectors in vti-rooms/tests/fixtures/file-vectors.json.



## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.10.0...vti-rooms-v0.11.0) — 2026-10-06


## [0.10.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.9.0...vti-rooms-v0.10.0) — 2026-10-06


## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.8.0...vti-rooms-v0.9.0) — 2026-10-05


## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.7.0...vti-rooms-v0.8.0) — 2026-10-04


## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.6.1...vti-rooms-v0.7.0) — 2026-10-02


## [0.6.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.6.0...vti-rooms-v0.6.1) — 2026-10-02


## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.5.0...vti-rooms-v0.6.0) — 2026-10-02


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.4.0...vti-rooms-v0.5.0) — 2026-10-01


## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.3.0...vti-rooms-v0.4.0) — 2026-10-01


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.23...vti-rooms-v0.3.0) — 2026-09-30


## [0.2.23](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.22...vti-rooms-v0.2.23) — 2026-09-30


## [0.2.22](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.21...vti-rooms-v0.2.22) — 2026-09-27


## [0.2.21](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.20...vti-rooms-v0.2.21) — 2026-09-27


## [0.2.20](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.19...vti-rooms-v0.2.20) — 2026-09-26


## [0.2.19](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.18...vti-rooms-v0.2.19) — 2026-09-26


## [0.2.18](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.17...vti-rooms-v0.2.18) — 2026-09-24


## [0.2.17](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.16...vti-rooms-v0.2.17) — 2026-09-23


## [0.2.16](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.15...vti-rooms-v0.2.16) — 2026-09-23


## [0.2.15](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.14...vti-rooms-v0.2.15) — 2026-09-22


## [0.2.14](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.13...vti-rooms-v0.2.14) — 2026-09-22


## [0.2.13](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.12...vti-rooms-v0.2.13) — 2026-09-21


## [0.2.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.11...vti-rooms-v0.2.12) — 2026-09-21


## [0.2.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.10...vti-rooms-v0.2.11) — 2026-09-21


## [0.2.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.9...vti-rooms-v0.2.10) — 2026-09-20


## [0.2.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.8...vti-rooms-v0.2.9) — 2026-09-17


## [0.2.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.7...vti-rooms-v0.2.8) — 2026-09-17


## [0.2.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.6...vti-rooms-v0.2.7) — 2026-09-16


## [0.2.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.5...vti-rooms-v0.2.6) — 2026-09-16


## [0.2.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.4...vti-rooms-v0.2.5) — 2026-09-16


### Added

- **rooms**: The wire types name the task they are the payload of ([#1498](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1498))

Groundwork for keying dispatch on the **type** rather than on a URI written out
  at the registration site. `trust_tasks_rs::Payload` is the framework's statement
  that a Rust type *is* the payload of a task URI; with it, a dispatcher derives
  routing, `unsupportedType`-vs-`unsupportedVersion`, and its own served-URI list
  from the registrations themselves.

  The URI stops being an argument someone has to supply correctly. That matters
  here because this repo has already shipped the bug that a string-keyed router
  invites: `rooms/records/curate` was dispatched and named in neither URI list, so
  every version hint the service emitted was wrong about it. The list and the
  router were two descriptions of one fact, and they disagreed.

  ## This does not adopt the generated types

  `wire.rs`'s header argues at length for keeping these hand-written — the
  generated bindings use newtypes, `NonZeroU64`, `#[non_exhaustive]` and builders,
  which are right for a client constructing a request and friction for a crate
  whose types are also its storage records. Nothing here reverses that.

  `Payload` is a trait, not a type. Implementing it says what a type is *for* on
  the wire and leaves its Rust shape exactly as the storage layer needs it. The
  generated bindings stay the authority on the schema, which is what the new flags
  test reads them for.

  ## The flags test failed on its first run, against this commit's own impls

  `Payload`'s policy consts all default to `false`, so an omission is silent
  **and permissive**. Writing the impls with only `TYPE_URI` gave:

      rooms/create/0.1:  left: (false, false, false, false)
                        right: (false, true,  true,  true)

  Every `rooms/*` request declares `proof`, `recipient` and `issuedAt` REQUIRED in
  its published schema. A missing `IS_PROOF_REQUIRED` would mean unsigned requests
  accepted for a task whose specification demands a proof — and no round-trip test
  could see it, because both ends of the round trip are this same struct. That is
  the same shape as the defect `tests/schema_conformance.rs` exists to prevent, in
  a dimension that file does not cover: it checks what these types *serialise to*,
  not what the framework is told to *require* of them.

  So the flags are read from `schema_index::spec_policy_for` — the same published
  schemas — and pinned per type. A task with no published schema yet is skipped
  rather than failed, and becomes a check the moment one publishes.

  ## trust-tasks-rs becomes a normal dependency

  It was a dev-dependency. The impls are production API, and the orphan rule
  leaves no choice about where they live: `Payload` is foreign and these types are
  this crate's, so the impls belong here or nowhere — a consumer cannot add them.



## [0.2.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.3...vti-rooms-v0.2.4) — 2026-09-15


## [0.2.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.2...vti-rooms-v0.2.3) — 2026-09-12


## [0.2.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.2.1...vti-rooms-v0.2.2) — 2026-09-12


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

