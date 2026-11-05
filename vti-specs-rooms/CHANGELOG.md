# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-rooms-v0.5.0...vti-specs-rooms-v0.6.0) — 2026-11-05


### Added

- **rooms**: Members' names in a room (memberProfile), and rooms/watch with its rooms/changed signal on both hosts ([#2457](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2457))

A member's name in a room (trust-tasks-tf #1035, rooms/_shared/0.3
  member-profile): a record of kind `memberProfile` whose `title` is the
  name. `vti_rooms::member_profile` holds the writer's and reader's rules
  (MemberName: one line, no controls, at most 64 code points after NFC;
  empty or white space withdraws; MemberProfileRecord /
  MemberProfileCleartext shapes; `Names`, which takes per author the most
  recently stored version and refuses a rewrite by anyone but the original
  author). `record_members::used` names `memberProfile` for a body of that
  kind, so the writer's rule asks for `kind` and `memberProfile` listed;
  the SDK's copy (`RECORD_KIND_VALUES`, `MEMBER_PROFILE_KIND`) is pinned
  equal by the existing test. No host, seal or act change: a key holder
  seals the body unchanged, as the schema says. `pnm rooms name set|clear`
  writes the record (seal/0.3 + act/0.11 on sealed tiers, put/0.5 on open),
  over the member's existing name record when it holds one; `pnm rooms
  list|get|read` show a name record as a name, never a note, and an
  author's name beside their DID.

  rooms/watch/0.1 and rooms/changed/0.1 (trust-tasks-tf #1036), pinned in
  vti-specs-rooms. `vti_rooms::watch` is the host-neutral half both hosts
  call: authorized as a listing (`read`), with the task's chainTooDeep and
  subjectBindingMissing; one watch per room and address in its own
  keyspace (host state, never backed up, never consulted to authorize);
  lease 7 days by default, 30 at most, never past the presentation's
  first credential lapsing (`VerifiedChain::valid_until`, new);
  addressUnreachable when the address offers no transport the host
  speaks; limitReached past 1024 per room or 16 per member. After any
  successful room task the room's watches past their watermark are
  removed under one lock and signalled once, after a 2-6 s randomised
  delay, with the room and its latest version only; a watch whose
  presentation the held revocation list withdraws never fires. room-host
  signals over its mediator session (TSP before DIDComm, by service type);
  the VTC over `PeerTasks::send_one_way`, signed as the community. Neither
  sends REST or retries.



## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-rooms-v0.4.1...vti-specs-rooms-v0.5.0) — 2026-11-04


### Added

- **rooms**: Record kinds, replies and image previews at the VTA — serve rooms/keys/seal/0.3 and act/0.11, carry recordMembers ([#2449](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2449))

The first stage of trust-tasks-tf #1027: a record says what it is to a
  reader (kind), what it answers (inReplyTo), when it was written and edited
  (writtenAt, editedAt), and a file can carry an image's width, height and
  preview. A room's profile lists which of these its writers may use
  (RoomProfile.recordMembers).

  Pinned in vti-specs-rooms beside the versions already pinned:
  rooms/keys/seal/0.3, rooms/keys/act/0.11, rooms/records/put/0.5,
  rooms/records/list/0.6, rooms/records/get/0.3, rooms/keys/browse/0.4 and
  rooms/keys/read/0.2. Every bundle referencing rooms/_shared was re-vendored:
  #1027 changed SealedRecordBody, RoomProfile and FileManifest in place.



## [0.4.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-rooms-v0.4.0...vti-specs-rooms-v0.4.1) — 2026-11-04


## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-rooms-v0.3.0...vti-specs-rooms-v0.4.0) — 2026-11-04


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-rooms-v0.2.0...vti-specs-rooms-v0.3.0) — 2026-11-02


### Added

- **vtc**: Archive, unarchive and remove a community-owned data room ([#2380](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2380))

A community could create, describe and staff a room it owns, but never close
  or remove one. This adds the owner's lifecycle beside the host's computed one,
  stored on the owner's record: active -> archived (readOnly | noAccess) ->
  removalScheduled -> purging -> removed
  (vtc/rooms/community/{archive,unarchive,remove}/0.1,
  vtc/rooms/community/removal/cancel/0.1).

  - readOnly freezes the host record (vti_rooms::Room::frozen_at): the host
    refuses every task but a read, except the owner's own Admin acts. Open
    offers are withdrawn.
  - noAccess, and every removal, resets the room: one `room` withdrawal through
    rooms/owner/revoke, the only withdrawal a private room's host applies.
    Admitted members become `suspended`. The community's own credentials are
    re-issued after the second the reset falls in, because a credential whose
    validFrom is before revokedAt is withdrawn. The reset is recorded as a
    pending change before it is asked for, and rooms::community_lifecycle (the
    one retry owner) finishes it; a reset the host accepted is never repeated.
  - Unarchiving restores suspended members with fresh credentials (same actions
    and expiry), delivered as an offers/list renewal.
  - Removal only from archived, with a grace period (default 30 days,
    `[rooms.community] removal_grace_days`) or at once. The purge deletes host
    rows, every blob (including moved copies), usage, the storage assignment,
    group bindings and the served DID log; it asks the VTA to delete the DID (a
    SHOULD, reported and never holding the purge); and it keeps a tombstone.
  - get/list 0.4 carry `status`, members/list 0.2 and memberships/list 0.2 the
    `suspended` state, and members/add 0.2 refuses `wrongState`. The 0.3 and 0.1
    reads stay served: purged rooms are hidden from them, and a suspended
    admission reads as admitted. members/add 0.1 is no longer served.
  - The VTA serves rooms/keys/act 0.10, which adds memberships/list 0.2.
    vta-sdk and pnm move to it.
  - cnm rooms archive|unarchive|remove|cancel-removal, list --state; the admin
    console's state chips, filter, Lifecycle card and dialogs (remove requires
    typing the room's label); the member portal's room-state wording.



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-rooms-v0.1.0...vti-specs-rooms-v0.2.0) — 2026-10-30


### Added

- **rooms**: Files in open rooms — serve rooms/records/put/0.4 and rooms/keys/act/0.9 ([#2348](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2348))

An open room could hold notes and nothing else: a file's manifest only
  travelled inside a sealed body, and its key could only be derived from a
  storage key an open room does not have. rooms/records/put/0.4
  (trust-tasks-tf #987) puts the manifest in cleartext.file, with the random
  key its blob is sealed under in fileKey; rooms/keys/act/0.9 ([#990](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/990)) adds put
  0.4 to the closed table a member's VTA completes.

  Hosts (room-host, vtc-service, through vti-rooms):
  - Serve rooms/records/put/0.4 beside 0.3. The cleartext, file included, is
    stored and served as received (Host item 13).
  - On an open room, refuse as malformedRequest a record whose blobs is not
    exactly [cleartext.file.blobRef], or whose file has no fileKey — before
    blobNotFound and before anything changes (Host item 12). 0.3 is unchanged.



## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-specs-rooms-v0.1.0) — 2026-10-30


### Added

- **specs**: Generate the Trust Task wire types VTI pins, with trust-tasks-build ([#2340](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2340))

* feat(specs): generate the Trust Task wire types VTI pins, with trust-tasks-build

  trust-tasks-rs 0.36 deprecates every prebuilt trust_tasks_rs::specs module.
  Five new crates generate the versions VTI uses instead:

  - vti-specs-rooms, vti-specs-vta, vti-specs-vtc, vti-specs-core: each
    build.rs runs trust-tasks-build (.index(true)) over its own
    trust-tasks.lock and vendored bundles. Each version is pinned in exactly
    one crate, so a type is the same type across the workspace. rooms stands
    alone so vti-rooms-wasm compiles nothing else.
  - vti-specs: re-exports every family at its trust_tasks_rs::specs path and
    merges the four Type URI indexes (type_index::lookup) into a drop-in
    schema_index, plus is_pinned. Framework specs fall through to
    trust_tasks_rs::schema_index.
  - vta-sdk re-exports it as vta_sdk::specs.

  664 versions are pinned: every version module the workspace names, plus the
  Type URIs it sends or serves as strings (registry/*, did-management/*,
  push/provision, ...).

  spec_pin_census in vta-service and vtc-service fails on a dispatched,
  served, sent or TASK_* Type URI no crate pins: an unpinned URI answers None
  from the index, and the gates that read None as nothing to check fail open.

  Nothing moves to the new crates yet; the import rewrite follows.


