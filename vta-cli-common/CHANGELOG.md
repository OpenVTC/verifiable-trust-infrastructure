# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.45.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.44.0...vta-cli-common-v0.45.0) — 2026-10-18


### Added

- **rooms**: Rooms/owner/register 0.2 and group/remove 0.3 — a room's revocation list is reported and redelivered, and a refused redelivery never loses a withdrawal (trust-tasks-tf #821) ([#2191](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2191))

* feat(rooms)!: rooms/owner/register 0.2 and group/remove 0.3 — a room's revocation list is reported and redelivered, and a refused redelivery never loses a withdrawal (trust-tasks-tf #821)

  Implements trust-tasks-tf #821 on trust-tasks-rs 0.32.

  rooms/owner/register/0.2
  - A registration the host accepted answers success whatever became of the
    room's revocation list, with `revocation {head, status, code?}`: `inForce`
    only when the host answered with that list's head, `refused` with the host's
    code, `pending` otherwise (item 3). `hostUnreachable` / `hostRefused` report
    the registration alone, now mapped from the host's answer (they were bare
    task failures before, at 0.1 too; the census baseline loses both rows).
  - The outstanding delivery (room, host, sequence, and the persona whose `admin`
    grant delivers it) is retained durably *before* the delivery is attempted, so
    a process dying mid-delivery leaves it for the sweeper.
  - `trust_tasks::room_list_delivery` is the single retry owner (item 4): every
    30 s it attempts what is due, as that persona under authority confined to the
    persona key's own context, delivering the latest list held; capped
    exponential backoff (30 s .. 1 h) with full jitter; `inForce` and `refused`
    both end it, and a refused list is never delivered again (item 5). `stale`
    with no later list of this agent's own is logged at warn with
    `security_alert` as possible key equivocation. Remote first: the record is
    dropped only after the host's answer. Any delivery that reaches the host
    (revoke, a removal) settles it; a revoke the host refuses ends it.
  - 0.1 is still served as before: a failed delivery is refused with a message
    saying the room is registered and naming `pnm rooms owner revoke`.

  rooms/owner/group/remove/0.3
  - Item 8.2, by refusal code, when a pending removal's list is refused on
    redelivery: `listInvalid` / `entryNotPermitted` / `sequenceConflict` discard
    the whole removal (the list only while it is still the one held;
    `sequenceConflict` surfaced as equivocation); `stale` with a later held list
    delivers that list and confirms the withdrawal through it; anything else
    discards the advance and keeps the list. Whatever is discarded, the request
    is refused and does none of its own work: `earlierRemovalRefused`
    `{member, code, listKept}` at 0.3; `hostRefused` with the same details at
    add / renew / remove 0.1.
  - The settle path is shared, so this fixes every version: 0.2 used to discard
    the list on any refusal and carry on, losing an entry a host may enforce.
    0.2 has no `earlierRemovalRefused`, so it answers its closest declared code,
    `hostRefused` at `stage: revocation` (details closed to `{stage, code}`),
    with the earlier member and whether the list was kept in the message.
  - An unanswered epoch query while settling now carries `details.stage:
    advance` at 0.2/0.3, which their schema requires.

  Clients
  - SDK: `room_owner_register` asks 0.2 and falls back to 0.1 on
    `unsupportedType`/`unsupportedVersion`, returning 0.2's response;
    `room_group_remove_v0_3` asks 0.3 and falls back to 0.2. Both new URIs are
    classified in `retry_safety` (RetrySafe / Keyed) and in the budget set.
  - pnm: `rooms owner register` says plainly when the list is not in force and
    prints the `pnm rooms owner revoke` fix (never re-register);
    `rooms owner group-remove` uses 0.3 and explains `earlierRemovalRefused`.
  - VTC: community `members/remove` and the departure worker ask
    `group/remove/0.3`, falling back to 0.2; an `earlierRemovalRefused` is
    surfaced to the administrator as `keyHolderRefused` saying what to do.

  trust-tasks-rs 0.32 breaks handled
  - `SealedRecord` gains `version` ([#816](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/816)): `pnm rooms file get` now opens and
    verifies at `sealed.version`, which the previous release could not read.
  - The device `Capability` enum gains `sign-document` ([#819](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/819)): this VTA neither
    grants nor serves it; mapping goes through serde, so nothing else moves.



## [0.44.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.43.0...vta-cli-common-v0.44.0) — 2026-10-18


### Added

- **rooms**: Every surface shows a member the same community rooms, and finishes an acceptance any other began ([#2186](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2186))

* feat(rooms): every surface shows a member the same community rooms, and finishes an acceptance any other began

  A member reaches their community from several surfaces — the member portal
  through their wallet, pnm, OpenVTC — and each kept no shared view: offers/list
  drops an accepted offer after seven days, so a room accepted in one surface
  was invisible to the others after that, and an acceptance one surface began
  could be finished by no other (its mint replaced the private half the kept
  Welcome is sealed to, and the community answered alreadyAccepted).

  VTC
  - vtc/rooms/memberships/list/0.1: the community's own record of the signer's
    admissions to the rooms it owns — offered, admitted, removed; never a
    withdrawn offer, never a credential — with repeatAcceptUntil while a sealed
    admission's Welcome is kept. Answers only an active member, for themself.

  VTA
  - rooms/keys/key-package/0.2: returns the outstanding KeyPackage for the same
    room, member and invitation (alreadyMinted: true, original expiresAt), and
    mints only otherwise; serialised so concurrent requests get the same one.
    RetrySafe, where 0.1 is Keyed.
  - rooms/keys/welcome/0.1: a Welcome under a spent invitation, for the member
    who joined with it, is alreadyJoined (welcome/0.1's rule) rather than
    "invitation already used" — so a surface finishing another's acceptance
    reads it as success.
  - rooms/keys/act/0.5: 0.4 ([#2183](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2183)), and vtc/rooms/memberships/list/0.1 —
    COMMUNITY_TYPES, 0.4's OFFER_TYPES_0_4 and memberships/list. 0.3 and 0.4
    refuse memberships/list (their schemas' type pattern); an acceptance's
    KeyPackage may come from key-package 0.1 or 0.2.

  SDK / pnm
  - VtaClient::room_key_package_v0_2, room_act_community (act 0.5, then 0.4 and
    0.3 for the offer types an older VTA completes), unsigned_community_request,
    is_community_type.
  - pnm rooms memberships: the community's record beside the VTA's custody, as
    every surface shows it. pnm rooms offers accept checks custody first, asks
    for the KeyPackage at 0.2 (0.1 against an older VTA), and reads
    alreadyJoined as joined.

  pnm's offer steps keep #2183's OfferStepError and offers/list 0.2 to 0.1
  fallback, now through room_act_community.

  trust-tasks-rs floor 0.31.16.

- **rooms**: Rooms/keys/act 0.4 — a member reads each offered room's description (vtc/rooms/offers/list 0.2) ([#2183](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2183))

Serve `rooms/keys/act/0.4` (trust-tasks-tf #810) beside 0.3, 0.2 and 0.1.

  - VTA: 0.4's offer row adds `vtc/rooms/offers/list/0.2` beside `0.1`, on
    the same terms — no presentation, `issuer` required and resolved without
    a room credential (recipient item 2b). `room_act::OFFER_TYPES` stays
    0.3's closed table; `OFFER_TYPES_0_4` is 0.4's, and `ActVersion::
    completes_offer` picks by the version asked, so a 0.3 request wrapping
    list 0.2 is still refused `typeNotActable` (0.3 recipient item 1).
    Dispatch, policy-gate subject (`/document/issuer`), conformance witness
    and `RetrySafe` classification as for 0.3.
  - SDK (breaking): `TASK_ROOMS_KEYS_ACT_0_4`; `room_act` and
    `unsigned_room_request` take and return the 0.4 generated types. A room
    request is asked at 0.4 → 0.3 → 0.2 → 0.1, list/accept 0.1 at 0.4 → 0.3,
    and list 0.2 at 0.4 only (`UnsupportedTaskType` otherwise).
    `is_offer_type` includes list 0.2.
  - pnm: `rooms offers list` asks list 0.2 through act 0.4 and prints each
    room's description on an `about:` line, every control character replaced.
    It falls back to list 0.1 (act 0.3 when the VTA lacks 0.4) when either
    the member's VTA or the community answers `unsupportedType` /
    `unsupportedVersion` — each party's refusal is kept apart
    (`OfferStepError`). `accept` reads the offer the same way.
  - Member portal: the offers card shows the description the wallet carries
    (`PageOffer.description`), as text, bounded to the schema's 1000.
  - Docs: community-rooms (the description gap closes; what remains is an
    older VTA or VTC), the quickstart, data-rooms, the files design note.
  - trust-tasks-rs floor 0.31.15 (the act 0.4 and offers/list 0.2 generated types).

- **rooms**: Rooms/owner/revoke and group/remove 0.2 — the owner's VTA withdraws a member at the host before it advances ([#2174](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2174))

The key-holder half of trust-tasks-tf #804. Only the room signs a revocation
  list, and the owner's VTA holds the room's key, so the VTA is where lists are
  made.

  - The list is kept with the room's key: `room_groups` (backed up, encrypted),
    `room-revocations/<roomId>`, one per room whatever persona signs. Building
    and signing a room's next list is serialized per room (owner/revoke item 3),
    signed as the room through `RoomKeySigner` — the gated oracle that mints the
    room's credentials, `ProtocolDefined` — and kept and persisted before it is
    delivered anywhere (item 4).
  - `rooms/owner/revoke/0.1`: roomSubject, noSigningKey, noAuthority, noList
    before anything is signed (item 1); the tier from registration or
    `rooms/info` when a withdrawal names anyone (entryNotPermitted on private,
    tierUnknown otherwise; item 2); `revokedAt` stamped at signing; delivered to
    every host with `rooms/revocations/put` presenting the owner persona's
    `admin`, each outcome reported (`accepted` only when the host answered with
    this list's head; item 5). A success whatever the deliveries (item 6); a
    `stale` answer is surfaced as a security signal. Before signing it asks each
    host for its list and adopts a later one the room signed (verified under the
    room's own key and a method under the room's DID) — recovery for a key
    holder restored from an old backup.
  - `rooms/owner/group/remove/0.2`: signingKeyId required, `mirrors`, `until`;
    refuses a private room (privateRoom). The commit, link and the signed list
    are retained as the room's pending advance before anything is sent (item 5);
    the list goes to the host first and nothing advances until it is accepted
    (item 6: a refused list discards the whole removal, list included, rolling
    the held list back only while nothing was built on it); then the advance (a
    refused advance keeps the withdrawal); then the mirrors (`mirrorsPending`).
    A later request settles a pending removal by delivering its list again first
    (item 8). `hostUnreachable`/`hostRefused` carry `details.stage`.
  - `rooms/owner/register` records the room's tier and delivers the list it
    holds to the host before answering, so a room moving hosts arrives with its
    withdrawals.
  - SDK: `room_group_remove_v0_2`, `room_owner_revoke`; both `Keyed` in
    `retry_safety`, in the budget's host-reaching set and the MCP guard as
    Sensitive. `room_group_remove` stays 0.1.
  - pnm: `rooms owner group-remove --signing-key` asks 0.2 and falls back to
    0.1 only on `privateRoom` — the one case the specification hands to 0.1;
    without `--signing-key` it is 0.1 and says the credentials stay valid.
    `rooms owner revoke --host … [--subject|--credential|--reset]` (no
    withdrawal re-delivers).

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

- **rooms**: A member's own private name, description, notes and tags for each room they hold ([#2167](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2167))

* build(deps): trust-tasks-rs 0.31.14 — rooms/keys/label/0.1 and rooms/keys/list/0.2



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

- **rooms**: Say whose each rooms/keys/list entry is, and let a client name the member a custody task acts as ([#2161](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2161))

One VTA can hold two members of one room: an administrator whose VTA is also
  the community's holds the community's own place in a room the community owns
  and their own membership in it. rooms/keys/list then returned the room twice
  with nothing saying whose each entry was, and every custody task refused as
  ambiguous ("act from the context of the one you mean") — which a client whose
  session acts in both contexts cannot do. The wallet and the member portal hit
  both in a live test: the room listed twice, and sharing it with the portal
  refused as rooms/keys/act:principalAmbiguous.

  - rooms/keys/list: one entry per (room, member) as before, and
    ext["org.openvtc.rooms"].held, index for index with rooms: the member
    (persona DID), the trust context its key lives in, and the actions the
    room's grant to it confers. The specification's entry has no member of its
    own and forbids extra members, so it rides in ext.
  - read, browse, backfill, open, seal 0.1, file-key, commit and chain take
    ext["org.openvtc.rooms"].member, naming the persona to act as. It only
    narrows: a persona the caller may not act as answers as "no group state",
    the same as one nobody here holds. Naming none keeps the refusal for two
    (rooms/keys/read/0.1: "acts as the one its caller acts as, and refuses
    rather than choose"); rooms/keys/act keeps taking the member as issuer
    (act 0.3 recipient item 2).
  - pnm rooms keys list prints the member of each entry.
  - Member portal: Share rooms passes the signed-in member to the wallet
    (choose({ hostDid, member })), which only picks among the identities it
    holds for this community; each shared room says whom it is shared as; a
    wallet refusal for a room held as two identities is explained in plain words.



## [0.43.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.42.0...vta-cli-common-v0.43.0) — 2026-10-16


### Added

- **rooms**: Rooms/keys/act 0.3 — a member takes up a community's offer as themself, with only a KeyPackage their VTA minted ([#2148](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2148))

Serve `rooms/keys/act/0.3` (trust-tasks-tf #797) beside 0.2 and 0.1.

  - The table gains `vtc/rooms/offers/list/0.1` and
    `vtc/rooms/offers/accept/0.1`, with no presentation inserted
    (`room_act::OFFER_TYPES`, apart from the 0.1/0.2 host-bound table;
    0.1 and 0.2 still refuse them by schema).
  - Recipient item 2b: for the offer types `issuer` is required
    (`principalAmbiguous` without it, never picked for the caller), and the
    VTA acts as it only where it holds a key that DID lists for
    `authentication` and the caller may act as it (`issuerNotPrincipal`).
    No room credential is asked for.
  - Recipient item 10 (security): an acceptance's `keyPackage` is completed
    only when this VTA minted it with `rooms/keys/key-package` for that room
    and member and still holds its unused, unexpired private half —
    compared by KeyPackageRef (`room_groups::holds_key_package`), never by
    the leaf credential — else `keyPackageNotHeld`. The existing per-member
    pending-KeyPackage row is the record: a Welcome consumes it (used), its
    `expiresAt` bounds it. Completing an acceptance does not consume it, so
    a retry after a lost answer is the identical acceptance and is answered
    with the same Welcome (rooms/owner/group/add 0.2 item 8).
  - Policy and audit subject is the member, as at 0.2.

- **rooms**: Rooms/keys file-key, open and act 0.2 — removed, beyondChain, and the member as act's subject ([#2145](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2145))

trust-tasks-rs 0.31.10 (trust-tasks-tf #786, #787, released in #788) publishes
  rooms/keys/file-key/0.2, rooms/keys/open/0.2 and rooms/keys/act/0.2. The
  workspace floor moves to 0.31.10.

  VTA (served beside 0.1, whose behaviour is unchanged):

  - file-key 0.2: a file sealed at or after the member's removal is
    `unknownEpoch` with `{reason: removed, removedAtEpoch}` (oracle item 4 —
    an oracle that knows of the removal MUST NOT answer `notDelivered`). 0.1's
    closed details schema has no `removed`, so 0.1 still answers
    `notDelivered` with the removal in its message.
  - open 0.2: `unknownEpoch` carries the declared closed details. An older
    epoch the retained chain does not reach is `{reason: beyondChain,
    earliestEpoch}`; 0.1 still answers it as a bare validation failure.
    `room_groups::OpenError` gains `BeyondChain` (the enum is
    `#[non_exhaustive]`).
  - act 0.2: `subjectPath` is `/document/issuer`. The policy gate evaluates
    act 0.2 against the member — `issuer`, or where it is absent the one member
    of the room the caller may act as (`room_act::act_subject`) — never against
    no subject. The 0.2 audit row names the member as its target, with the type
    and room in its detail; a 0.1 row still names the room. Recipient item 2a
    (a room-less type is completed only as its `issuer`; absent is
    `principalAmbiguous`, never a member picked here) was already this VTA's
    behaviour and is now tested at 0.2.
  - Dispatch, conformance witnesses, and `vta_sdk::retry_safety`
    (open/file-key ReadOnly, act RetrySafe) for the three new URIs.



### Fixed

- **rooms**: Say a removed member's file key is a removal, and keep NoMatchingProtocol typed ([#2135](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2135))

Three rough edges from the end-to-end data-rooms run.

  FileKeyError gains Removed and becomes #[non_exhaustive] (breaking for
  vta-service). file_key now reads the room-removed row exactly as
  open_record_detailed does, so a file sealed at or after the member's
  removal is Removed rather than NotDelivered. On the wire it stays
  rooms/keys/file-key:unknownEpoch with reason notDelivered: the spec's
  detailsSchema for that code is closed (reason in {notDelivered,
  beyondChain}, additionalProperties false), so there is no `removed` to
  send until the specification declares one. The message says it was a
  removal, and `pnm rooms file get` now prints the same remedies a record
  refusal prints (catch up / backfill / removed), sharing one hint function.

  AppError gains NoMatchingProtocol(Box<vti_common::error::NoMatchingProtocol>)
  (peer, ours, theirs, note; boxed for clippy::result_large_err), breaking
  for vti-common. Outbound::pick_transport returned AppError::Validation,
  which the Trust Task spine renders as malformedRequest: the producer was
  told its document was wrong and lost both transport sets. It is now
  taskFailed (SPEC 8.3 defines no transport code, and the peer is not
  unavailable), not retryable, with details.reason no_matching_protocol
  plus counterpartyDid/ours/theirs; REST renders 502 with the same members.
  The SDK maps both back to VtaError::NoMatchingProtocol and the CLI prints
  which side can add which service.



## [0.42.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.41.0...vta-cli-common-v0.42.0) — 2026-10-15


### Added

- **vta**: External/credentials/issue 0.3 — responseTooLarge, sized before the rate, and the VTC splits ([#2127](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2127))

* build(deps): trust-tasks-rs 0.31.8 — external/credentials/issue 0.3 (trust-tasks-tf #781)

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

- **rooms**: Act as the member's persona — rooms/keys/act, seal 0.2, and read/browse/backfill as the principal ([#2107](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2107))

Implements the member-acts-as-persona half of trustoverip/dtgwg-trust-tasks-tf#771
  (trust-tasks-rs 0.31.3, now the workspace floor).

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

- **pnm**: Rooms owner register/invite/issue-* and rooms keys verbs — a sealed room from the CLI end to end ([#2092](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2092))

The owner's credential tasks and the joiner's key-holder tasks had no `pnm`
  verb, so a sealed room could not be run on a VTC from the command line.

  Owner (`pnm rooms owner …`), each a call to the owner's own VTA:
  - `register` → rooms/owner/register/0.1 (the VTA signs rooms/create as the
    owner's persona DID)
  - `invite` → rooms/owner/invite/0.1, writes the VIC to --out
  - `issue-membership` → rooms/owner/issue-membership/0.1
  - `issue-authority` → rooms/owner/issue-authority/0.2 (expiry required)
    Both issue verbs write to --out and/or --store the credential in this VTA's
    vault.

  Key holder (`pnm rooms keys …`):
  - `key-package` → rooms/keys/key-package/0.1, writes the KeyPackage base64url
  - `welcome` → rooms/keys/welcome/0.1, from the file group-add wrote
  - `commit` → rooms/keys/commit/0.1, one commit from a file, or every missed
    commit fetched from the host's relay (rooms/epoch/commits) with --host
  - `list` → rooms/keys/list/0.1

  Every party these name — owner, subject, member — is a persona DID the VTA
  holds, never the CLI's session key, so none defaults to the session; that
  includes `owner group-create --member`, now required. `pnm rooms create` is
  marked as the client-key path for a standalone room-host or testing.

  The SDK gains typed `VtaClient::room_owner_*`, `room_key_package`,
  `room_welcome`, `room_commit` and `room_keys_list`, built through the
  generated `trust_tasks_rs::specs` payloads and read through the generated
  responses; vtc-client gains `epoch_commits`. The keys tasks speak MLS epochs
  per their specification; the CLI converts so every number it shows is a room
  epoch. docs/02-vta/data-rooms.md now uses the verbs.

- **sdk**: Keep a Trust Task rejection's code and details ([#1952](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1952)) ([#2093](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2093))

* feat(sdk)!: keep a Trust Task rejection's code and details ([#1952](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1952))

  A rejection no other variant covers now arrives as
  `VtaError::Rejected { code, message, details }` instead of
  `Protocol("trust task failed [code]: message")`. The code was only in a
  sentence and `details` was dropped, so callers string-matched codes and lost
  data the VTA sent: `persona/profile/delete:bound`'s `details.personaDids`,
  a `versionConflict`'s `details.currentVersion`.

  `Display` is unchanged, so logs, CLI output and anything reading the text
  see the same string. New helpers `rejection_code()` / `rejection_details()`.

- **vta**: Rooms/owner/group/remove — remove a member from a sealed room's group from the owner's agent ([#2090](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2090))

The VTA now serves `rooms/owner/group/remove/0.1`, the mirror of
  `rooms/owner/group/add`, on the same remote-first machinery:

  - Item 1: `noGroup`, `notMember` and `ownLeaf` (the key holder's own leaf;
    an owner leaving hands the room on with rooms/owner/transfer). `ownLeaf`
    is answered before any host is contacted. No `admin` grant is
    `noAuthority`, before anything is built.
  - Items 2-3: the commit removing the leaf and the epoch link are built on a
    copy (`vti_rooms::sealed::SealedRoom::remove_member`, which already existed)
    and retained durably as the room's pending advance before anything is sent.
  - Items 4-5: `rooms/epoch/mint` (epoch, link, commit, the owner's `admin`
    presentation, reason) goes to the host; only an accepted advance replaces
    the live group. A refusal discards the pending removal (`hostRefused`, or
    `epochConflict` with `details.hostEpoch` on `nonSequential`); an unknown
    outcome keeps it (`hostUnreachable`).
  - Item 6: the next add or remove asks the host its epoch (`rooms/info`) and
    applies (host at the pending epoch), discards (host at the previous one) or
    discards and refuses `epochConflict` (anywhere else).

  One pending-advance slot per room (item 3). `room_groups::PendingAdd` becomes
  `PendingAdvance { kind: Admission | Removal, welcome: Option<_>, .. }`, stored
  at `room-advance:<room>` and claimed with an atomic insert-if-absent, so a
  second advance cannot be retained over a first. The admission-only row
  `room-add:<room>` is still read (its JSON deserialises with `kind`
  defaulting to `Admission`), settled like any other, and cleared with the
  slot; it is never written. `forget` clears the slot too. add and remove
  share `HostCall::{settle_pending, admin_presentation, advance}`, each with
  its own task's error codes, so a pending admission found at a removal is
  settled first and vice versa.

- **vta**: Rooms/owner/group/{create,add} — found a sealed room's group and admit members from the owner's agent ([#2088](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2088))

* feat(vta): rooms/owner/group/{create,add} — found a sealed room's group and admit members from the owner's agent

  A sealed room (`attributed`, `private`) cannot be written to until its MLS
  group exists, and the owner's half of a group — founding it, admitting a
  member — was library code only. The VTA now serves both owner tasks
  (trust-tasks-tf #763):

  - `rooms/owner/group/create/0.1` founds the group with the owner as its only
    leaf, at room epoch 1, the epoch a host records at registration. The gate
    is the one issuing the room's credentials uses — control of its signing
    key — checked by a new `keys::require_key_nameable` that applies
    `sign_payload`'s scope, status, context and caller-key-filter gates
    without signing anything. A room this VTA already holds a group for is
    refused `alreadyExists`, never replaced.
  - `rooms/owner/group/add/0.1` admits a member's KeyPackage, remote first:
    the add is built on a copy and kept as a pending admission
    (`room-add:<room>` in `room_groups`, the advanced group snapshot with its
    link, commit and Welcome) beside the untouched live group; the room is
    advanced at its host with `rooms/epoch/mint` (link, commit, the owner's
    `admin` presentation); only an accepted advance replaces the live group.
    A refusal (`hostRefused`, or `epochConflict` on `nonSequential`) discards
    it. An unknown outcome (`hostUnreachable`) KEEPS it, and the next admission
    asks the host its epoch (`rooms/info`) and applies or discards it first —
    a key holder cannot process its own commit from the wire, so the pending
    group is the only way to follow a host that did advance. The Welcome is
    returned for delivery to the newcomer's key holder, never sent to the host.
    The KeyPackage must identify `member` (`keyPackageInvalid` otherwise); a
    member already in the group is `alreadyMember`; no `admin` grant in the
    vault is `noAuthority`, before anything is built.



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



## [0.41.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.40.0...vta-cli-common-v0.41.0) — 2026-10-13


### Added

- **pnm**: Pnm keys sign-csr — a certificate request for a key that stays in the VTA ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2058](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2058))

Wraps keys/sign-csr/0.1 ([#2057](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2057)) for the admin workstation: an EUDI verifier's access-certificate key can be certified without leaving the VTA, which is what custody B needs before the VTC signs request objects through it.

  Named flags (--country, --organization, --organization-identifier, --common-name, OU, ST, L, serialNumber, emailAddress; --dns/--uri/--email alternative names) become the subject in encoded order whatever order they are given in. As keys/sign-csr asks of a producer, the publicKey the VTA answers with is compared with the key's record before the PEM is written. vta-cli-common: CsrSubjectArgs, cmd_key_sign_csr.



## [0.40.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.39.0...vta-cli-common-v0.40.0) — 2026-10-12


### Added

- **services**: Complete DIDComm enable with a soft restart and a readiness wait ([#2045](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2045))

* feat(services): complete DIDComm enable with a soft restart and a readiness wait

  `services didcomm enable` published the DID document change but left the
  VTA without a running messaging runtime until the next manual restart. The
  operation now signals `ext["org.openvtc"].restarting` and performs a soft
  restart after the reply reaches the transport send boundary, and `pnm`
  waits for the restarted listener before returning.

  Also fixes a TEE fleet image that could not boot REST-only, by removing the
  baked `[messaging]` placeholder that pre-empted the tenant overlay's
  "materialize messaging only when a mediator_did is supplied" branch.



## [0.39.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.38.0...vta-cli-common-v0.39.0) — 2026-10-11


### Added

- **rooms**: Pnm rooms file put/get, and signed sealed bodies for rooms put/get ([#2037](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2037))

A member can now put a file in a sealed room and fetch it from the CLI, end to
  end (data-rooms-files.md P6), and `pnm rooms put`/`get` work on sealed rooms.

  Sealed record body (vtc_client::rooms::body). This implements
  `SealedRecordBody` (rooms/_shared/0.1/room.schema.json,
  trustoverip/dtgwg-trust-tasks-tf#747): the JSON inside a sealed record. It is
  signed by its author with a Data Integrity proof (eddsa-jcs-2022, or
  ecdsa-jcs-2019 for P-256) and names the room, key and version it was written
  for. `verify_record_body` is the only way to a `VerifiedRecordBody`. It
  refuses, rather than warns about, a body that:
  - names an unknown member or breaks a bound;
  - carries a proof that does not verify for `author` for assertionMethod, or
    uses another suite;
  - was signed for another location;
  - on attributed, was signed by someone other than the author the host recorded.
  There is no generated type for the body, because no host task carries it (the
  same as FileManifest).

  pnm rooms put on a sealed room:
  - reads the tier from `rooms/info`, signs the body as the operator, and seals
    it through the VTA's `rooms/keys/seal`, which seals what it is given and
    signs nothing;
  - predicts the version from the room head. The host assigns versions from a
    room-wide counter, so a write that lands at another version is re-sealed at
    the next one and rewritten over exactly what landed, up to 4 times, then
    named with the --expected-version to retry with.
  Without a file, `put` and `get` stay on records 0.1, which the VTC host serves.

  pnm rooms get:
  - verifies the sealed body before showing it;
  - reads `sealed` as the object the host returns. It had read it as a bare
    string, so it could open no sealed record.

  pnm rooms file put/get. A file is sealed and opened locally with one file's
  key from the VTA. `put` seals the file, uploads its ciphertext (begin, the
  missing chunks, commit; abort on failure), checks the committed blobRef, then
  writes a create-only record (records/put 0.2) whose signed body carries the
  FileManifest. `get` writes nothing unless every check holds:
  - the body is verified;
  - the blob is named on the record and is the one the author named;
  - each chunk matches the manifest;
  - the plaintext matches the author's digest.
  Another member's text has control characters stripped, and a file name keeps
  only its last path component, never written over an existing file. Files need
  records/put 0.2, which room-host serves and the VTC does not yet.

  Client calls:
  - vtc-client: begin/upload/commit/abort, get_blob/download_chunk, room_info,
    get_record_v2 and put_sealed_record_with_blobs, on the generated
    trust_tasks_rs types;
  - vta-sdk: VtaClient::room_seal, and
    trust_task_sign::sign_object_for_assertion for signing an object that is
    not a Trust Task.



## [0.38.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.37.0...vta-cli-common-v0.38.0) — 2026-10-11


### Added

- **rooms**: Room files — file keys, STREAM sealing and rooms/keys/file-key ([#2017](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2017))

* feat(rooms): file keys, STREAM sealing and blob manifests in vti-rooms

  Adds vti_rooms::files, the construction rooms/_shared/0.1/blobs.schema.json FileManifest specifies (trust-tasks-tf #739): a per-file key, HKDF-SHA256 over the epoch storage key salted with the fileId and bound to the room and epoch; ChaCha20-Poly1305 STREAM segments whose nonce counts and whose associated data carries the final flag, so truncation, reordering and splicing fail to authenticate; one sealed segment per transfer chunk; the blob manifest and its BlobRef (sha2-256 over JCS); Padmé padding; and streaming sealer and opener that refuse a file whose plaintext digest is not the one its author signed. The manifest and digests build without the mls feature so a host can check them; the keyed half is behind mls with the rest of the member half. SealedRoom gains file_key_for_seal and file_key_for_open, walking the epoch chain as open_record does. Test vectors in vti-rooms/tests/fixtures/file-vectors.json.

- **vta**: External accounts — short-lived provider credentials with no inbound surface ([#2016](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2016))

* feat(vta): external-accounts capabilities and keyspaces

  Adds the two capabilities the external/* family (trust-tasks-tf #740) gates on: external-accounts-manage, derived by admin alone, and external-auth-use, derived by every role that holds sign (the account's binding, not the role, bounds a consumer). Both are non-additive members of the non-exhaustive Capability enum.

  Registers two keyspaces: external_accounts (settings, bindings, state) in BACKED_UP, and external_secrets (wrapped provider secrets) in EXCLUDED_FROM_BACKUP, so a portable password-protected backup is never a way to take a provider secret away. DID deletion: an account's binding names its consumer, so external_accounts blocks; external_secrets is unrelated.

  The device-binding Capability registry (device/_shared 0.2) does not list the two yet, so device listings carry them under ext until it does.



## [0.37.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.36.0...vta-cli-common-v0.37.0) — 2026-10-06


## [0.36.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.35.0...vta-cli-common-v0.36.0) — 2026-10-06


## [0.35.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.34.0...vta-cli-common-v0.35.0) — 2026-10-05


## [0.34.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.33.0...vta-cli-common-v0.34.0) — 2026-10-04


## [0.33.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.32.1...vta-cli-common-v0.33.0) — 2026-10-02


## [0.32.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.32.0...vta-cli-common-v0.32.1) — 2026-10-02


## [0.32.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.31.0...vta-cli-common-v0.32.0) — 2026-10-02


## [0.31.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.30.0...vta-cli-common-v0.31.0) — 2026-10-01


### Added

- Serve vta/webvh/dids/create/1.1, whose response states `serverless` (VTI-20) ([#1886](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1886))

A serverless did:webvh exists only in the VTA until the caller serves its
  first log entry. create/1.0 said so only by leaving out `serverId`, so a
  client could infer it but not be told. The Keyring report met a persona
  minted on a VTA with no hosting server get through whoami, contexts, mint
  and key borrow, then fail resolving a document nobody published, with an
  error naming the persona rather than the cause.

  create/1.1 (dtgwg-trust-tasks-tf#702, trust-tasks-rs 0.25.4) REQUIRES
  `serverless` in its response. The VTA serves both. 1.1 states it. 1.0 is
  answered in 1.0's shape, whose response refuses unknown members.
  VtaClient::create_did_webvh sends 1.1. CreateDidWebvhResultBody gains
  `serverless: Option<bool>` (None from a 1.0 answer or a bundle written
  before 1.1) and `is_serverless()`, which falls back to an absent
  `server_id`. `pnm did-mgmt dids create` reads it: the summary says
  "Hosting: serverless" and the hosting guidance keys off it.

  The VTA already refuses a create that names neither `serverId` nor `url`,
  so a serverless mint is always one the caller asked for. Choosing it when no
  hosting server is registered is a client decision.

  trust-tasks-rs floor 0.25.4.



## [0.30.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.29.0...vta-cli-common-v0.30.0) — 2026-10-01


## [0.29.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.28.0...vta-cli-common-v0.29.0) — 2026-10-01


### Fixed

- Keyring findings round — proof sets, verify-as-received, VTC delivery (VTI-44, VTI-45, VTI-50, VTI-56) ([#1868](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1868))

* fix(vta-cli-common): opening a bundle to inspect it keeps the request seed

  pnm, cnm and vta `bootstrap open` consumed the single-use request seed
  right after decrypting, even when they wrote nothing. The seed is the only
  key that opens the bundle, so inspecting a template bundle destroyed the
  integration's keys, and cnm's own follow-up hint (`cnm auth login
  --credential-bundle`) could never succeed (VTI-53).

  Inspection now opens with the seed kept and says where it is. pnm consumes
  it only after a successful --out write, so a refused bundle no longer costs
  a fresh request cycle either. open_armored_bundle_keeping_secret and
  consume_request_secret are now public.



## [0.28.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.27.0...vta-cli-common-v0.28.0) — 2026-09-30


## [0.27.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.26.1...vta-cli-common-v0.27.0) — 2026-09-30


### Added

- **vta**: Clear a context's DID with vta/contexts/update-did/1.1 ([#1828](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1828))

* feat(vta): clear a context's DID with vta/contexts/update-did/1.1

  Once a context had a DID it could be replaced but never removed:
  update-did/1.0 requires a non-empty `did`, and contexts/update only sets
  one. `webvh/dids/delete` refuses a DID a context still acts as and says
  "reassign it first", so a context's last DID could not be retired short
  of assigning another the operator did not want.

  Serve update-did/1.1 (trust-tasks `feat(vta/contexts/update-did): 1.1`)
  beside 1.0 through one handler. `did: null` clears — the record comes
  back with `did` absent, and clearing a context with no DID succeeds. A
  string `did` must be a DID; 1.1 is parsed into the generated
  `update_did::v1_1::Payload`, whose `PayloadDid` holds the pattern, and
  1.0 keeps its original body. 1.0 is listed as superseded by 1.1, and the
  legacy `PUT /contexts/{id}/did` now names 1.1 as its successor.

  - vta-sdk: `TASK_CONTEXTS_UPDATE_DID_1_1` (retry-safe);
    `update_context_did` sends 1.1; new `clear_context_did`.
  - pnm / cnm: `contexts update-did <id> --clear`, and
    `contexts update <id> --clear-did` (conflicts with `--did`), both on
    update-did so a context admin can do it.
  - The delete blocker offers both fixes and names update-did rather than
    contexts/update (super-admin only); its text also carried a run of
    literal spaces from an unjoined line wrap.

  Needs a trust-tasks-rs release carrying update_did::v1_1; see the TODO
  on the floor in Cargo.toml.



### Fixed

- **vta**: Provision mediator ACL during DIDComm enable and update ([#1843](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1843))


## [0.26.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.26.0...vta-cli-common-v0.26.1) — 2026-09-27


## [0.26.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.25.0...vta-cli-common-v0.26.0) — 2026-09-27


### Added

- **vta**: Health, restore status, session revoke and the wrapping key are Trust Tasks ([#1790](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1790))

* feat(vta)!: health, restore status, session revoke and the wrapping key are Trust Tasks

  Four REST routes become spine-dispatched, signed Trust Tasks reachable over
  TSP, DIDComm and HTTPS (`/trust-tasks`), from trust-tasks-rs 0.23.6, and the
  routes are removed rather than deprecated.

  vta/health/details/0.1 (replaces GET /health/details)
  - Public: in `vta_sdk::trust_tasks::PUBLIC_URIS`, so an anonymous HTTPS caller
    (on the unauthenticated limiter) and a DIDComm/TSP sender the ACL does not
    know are answered; request proof optional, response signed.
  - Returns only the fixed non-identifying flags the schema admits: status,
    mediatorUrl/mediatorDid, teeStatus (as vta/attestation/status answers it,
    `sev_snp` spelled `sev-snp`, absent without a provider), sealed,
    storageEncrypted, tspEnabled. The same answer for every asker; never the
    software version or the restore record.

  vta/restore/status/0.1 (the version and restore half of GET /health/details)
  - Administrators of the VTA only (any admin, scoped or not, read from the ACL
    now rather than the token); anyone else is `permissionDenied` before any
    restore state is read. Request proof required, response signed.
  - Answers `version`, `restored`, and the VTI-VTA-051 `restore` record from
    `keys ▸ restore:provenance` exactly when restored. The SDK refuses a reply in
    which the two disagree. `pnm health` gains a Deployment section showing both
    tasks' answers.

  auth/revoke-session/0.2 (replaces GET /auth/sessions, DELETE
  /auth/sessions/{id}, DELETE /auth/sessions?did=)
  - Adds the `subject` form and implements `all: true` (0.1 refused it). A caller
    may end another subject's sessions exactly when it could remove that
    subject's ACL entry (VTI-SES-043, VTI-ACL-050, `may_manage_subject`); outside
    that, `permissionDenied`, decided before the subject's sessions are read and
    identical whether or not the subject exists. A named session outside the
    caller's authority is answered as a missing one (`revokedCount: 0`).
  - The payload is checked against its schema and the one-form rule is enforced
    in the handler on the validated JSON, not left to the generated type: two
    forms, none, or `all: false` are `malformedRequest`.
  - Every revocation and refusal is audited with caller and subject; `reason`
    goes to the audit detail.
  - 0.1 is no longer served (every 0.1 payload is a valid 0.2 payload);
    vta-mobile-core's builders move to 0.2. The hand-written
    `RevokeSessionRequest`/`RevokeSessionResponse` are deleted in favour of the
    generated types. Listing another subject's sessions has no replacement: no
    published task enumerates them.

  keys/import-wrapping-key/0.1 (replaces GET /keys/import/wrapping-key)
  - The wrapping key is now an Ed25519 keypair returned as a `did:key`, with
    `keyId` and `expiresAt`; only its X25519 counterpart is kept, in memory,
    single-use, 60 seconds. Admin only, as keys/import. Response signed.
  - `VtaClient::get_wrapping_key` returns the generated response and always
    verifies the reply's proof (a client with no identity is refused, and
    `trusting_unsigned_replies` does not apply to this task). `pnm keys import`
    seals to the did:key's X25519. The sealed path over HTTPS works through the
    task; the cleartext carrier stays refused there.

- **cli**: Make pnm usable from a script ([#1753](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1753))

* feat(cli)!: pipe gets json, terminal gets table

- **services**: Service management is Trust Tasks only, over any transport ([#1782](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1782))

* feat(services)!: service management is Trust Tasks only, over any transport

  `pnm services …` (and every SDK caller) reached the VTA's service management
  through bespoke REST routes — twenty `/services/*` plus `/mediators/*` — via
  `VtaClient::rpc`, whose DIDComm and TSP arms answered `UnsupportedTransport`.
  So the whole surface worked only over REST, although the VTA already served the
  `vta/services/*` Trust Tasks. Under the rule that every remote API is a
  spine-dispatched Trust Task reachable over TSP, DIDComm and HTTPS, the SDK now
  dispatches the tasks and the REST routes are removed.

  Spec gaps closed first (trustoverip/dtgwg-trust-tasks-tf#656, trust-tasks-rs
  0.23.3):
  - `vta/services/report/0.1` — the mediator-attribution report had no task.
    Operator-only, request proof REQUIRED: it is a contact log of other parties'
    DIDs. Served from the telemetry sink; `since` after `until` is the declared
    `invalidWindow`.
  - `vta/services/update/1.1` — adds `drainTtlSecs` for the mediated transports.
    The REST route and `pnm services didcomm update --drain-ttl` carried an
    operator-chosen drain; 1.0 could not, so moving to the task would have
    silently dropped it. The handler honours it for DIDComm, raising a value
    below the 1h floor to the floor over a request that arrived through the
    mediator being replaced (the spec's MUST), refuses it for rest/webauthn, and
    reports no `drainUntil` for tsp — this VTA has one mediator connection, which
    a TSP update does not tear down, so there is nothing to drain.

  SDK
  - Every `services` method keeps its signature and return type, builds the spec
    payload, dispatches over `rpc_tt`, and maps the generated response back.
    `enable_didcomm` is no longer REST-only: a REST-only VTA receives it over
    HTTPS on `/trust-tasks`. `didcomm_status` is `services/get`; the live
    websocket state is not published state (`GET /health/details` has it).
  - The producer census (`producer_payload_conformance`) now drives every
    services method through the loopback and validates each payload against the
    published schema; the wiremock REST-shape tests are gone with the routes.

  Removed (breaking)
  - `/services/*`, `/mediators/report`, `/mediators/drain/cancel` and their
    deprecation-registry entries; the REST-auth tests for them (the same
    super-admin gates are on the task handlers).
  - Responses lose two cosmetic fields the task does not carry (the mediator
    endpoint on enable/update); the CLI already printed them only when present.

  VTC
  - 0.23.3 publishes a generated `acl/revoke/0.1`, so the VTC's hand-written
    `RevokeRequest` / `AclRevokeResponse` (which the generated-wire-types census
    now names) are replaced by the generated payload on the spine and the
    generated response, wrapped as `vta_sdk::openapi::AclRevoke01Response`, on
    both the spine and `DELETE /v1/acl/{did}`. Behaviour is unchanged — the
    declared `subjectNotPresent` / `lastAuthorityProtected` codes and the session
    end on full removal. The console's `openapi.json` / `wire.ts` are regenerated
    for the schema's new name.

  Not closed here: `vta/services/rollback/1.0` has no drain member, so a DIDComm
  rollback that lands on a drain transition takes the default window; and
  per-transport mediators remain unbuilt, so advertising a TSP mediator the VTA is
  not connected to is still possible.



### Fixed

- **cli**: Pnm keys import works over DIDComm and TSP ([#1784](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1784))

`keys import` always fetched the VTA's wrapping key first, and that is a REST
  route (`GET /keys/import/wrapping-key`), so on a DIDComm or TSP client the
  command failed before it sent anything. The SDK's `import_key` already sends
  `keys/import/0.1` on every transport, and the VTA accepts the cleartext
  `privateKeyMultibase` carrier over a transport confidential end to end.

  The CLI now picks the carrier from the client's Trust Task transport: multibase
  over DIDComm and TSP, with no wrapping-key fetch; sealed to the wrapping key
  over REST, where the VTA refuses a cleartext key (unchanged). A wrapping-key
  Trust Task for HTTPS needs its own specification and is not part of this.



## [0.25.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.24.0...vta-cli-common-v0.25.0) — 2026-09-26


### Security

- **acl**: No principal widens its own entry, and no grant exceeds its granter (VTI-ACL-052, VTI-ACL-053) ([#1738](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1738))

* security(acl)!: no principal widens its own entry, and no grant exceeds its granter (VTI-ACL-052, VTI-ACL-053)

  A context-scoped admin, such as a companion service's credential
  (`--role admin --contexts vgi-bridge`), could raise its own authority.
  `update_acl` had no self check and no test either way. Tests written
  against main confirm every case below. Adding a foreign context or
  raising the role was already refused. What went through was clearing
  any narrowing on the caller's own entry, and minting a sibling entry
  that carried none of it:

  - Self-update to clear its capability narrowing, drop its key filter,
    or extend its expiry. All three succeeded.
  - A create for another DID it controls, in the same context, with none
    of its own narrowing: full capabilities, no key filter, no expiry.
  - An update that cleared another entry's narrowing past what the caller
    itself held.
  - Self role change (`acl/change-role`).
  - Rotation (`acl/swap-key`) rebuilt the entry field by field. It dropped
    `expires_at`, `allowed_keys`, `approve_scope` and the step-up fields,
    so a one-hour bootstrap grant became permanent. It also dropped
    `created_by`. This violated VTI-CLT-029.
  - An initiator could grant approve authority it did not hold
    (VTI-ACL-042).
  - A context admin could update or delete an entry that also acts in a
    context it does not administer, because overlap was enough.

  VTA (`operations/acl.rs`, the choke point for REST, DIDComm, TSP and the
  Trust Task spine):

  - update and change-role refuse the caller's own entry (VTI-ACL-052).
    Delete already did.
  - create, update and change-role measure the resulting entry against
    the caller's stored entry (`validate_within_caller`, VTI-ACL-053). The
    entry must not exceed the caller's effective capabilities (additive
    ones stay under VTI-ACL-033), key filter, expiry, or confer authority
    (VTI-ACL-042). A caller with no live entry writes nothing.
  - update, change-role and delete require the caller to cover every
    context the entry acts or approves in, not just overlap
    (VTI-ACL-050 as tightened).
  - update re-runs the role and act-scope checks on the patched entry, so
    a role change alone cannot turn "nowhere" into "everywhere".
  - swap-key copies the entry exactly and only moves the subject. It
    refuses an expired entry (VTI-CLT-029).

  VTC (`routes/acl.rs`, `routes/admin/invites.rs`,
  `routes/members/update.rs`):

  - An `acl/grant` rewrite of your own entry is refused. Before, a re-grant
    with no `expiresAt` made a time-boxed admin permanent.
  - `acl/change-role` refuses your own entry in either direction; the
    ceremony already refused self-promotion.
  - `vtc/members/update` refuses a role or label change on your own entry.
  - Rewrite, change-role and revoke (including scoped revoke) require
    full coverage for every role, not only admin targets.
  - A grant cannot outlive the granter's expiry, and a granter with no
    live entry is refused.
  - `vtc/admin/invites/create` requires an unrestricted admin. It writes
    a community-wide admin entry, and a context admin could previously
    invite a DID it controls into one.



## [0.24.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.23.1...vta-cli-common-v0.24.0) — 2026-09-26


### Added

- **pnm**: Answer this VTA's consent requests from the CLI ([#1761](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1761))

A task under a `requires: consent` rule waits for its approver set, and only
  a device enrolled for the task-consent push could answer. `pnm` showed the
  requester the code and waited.

  `pnm consent {show,approve,deny} <file|->` is the approver's side. It takes
  the refusal the requester relays (the body, its `details`, or a bare request
  document) and picks the request addressed to this profile. It checks that
  this VTA signed it, that it is addressed to this approver and that it has
  not expired. Approving requires typing the requester's match code, or
  `--match-code`. The decision is dispatched as a Trust Task, which the client
  signs with the profile's key under assertionMethod.

  The operator-facing half is now shared with `cnm consent`: reading the
  input, what is shown, the code comparison, the report and the refusal
  hints, all in `vta_cli_common::consent_approve`. `cnm consent` moves onto
  it, keeping its VTC-specific hint for `permissionDenied`.

  Tested end to end in `delegated_consent_e2e`: a real VTA-signed request
  verifies through `vta_sdk::task_consent`. It is refused when it is
  addressed to someone else or has been tampered with, and the decision
  built from it is granted.

- **cnm**: Answer the community's consent requests from the CLI (VTI-APV-014) ([#1759](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1759))

Making or widening an unrestricted administrator at the VTC needs another
  unrestricted administrator's consent (VTI-APV-014), but only a device
  enrolled to handle the task-consent push could answer. An approver with a
  cnm profile had no way to sign a decision.

  `cnm consent {show,approve,deny} <file|->` takes the request the
  requester relays (the refusal body, its `details`, or a bare request
  document), picks the one addressed to this profile, and verifies it. The
  VTC must have signed it, it must be addressed to this approver, and it
  must not have expired. Approving requires typing the requester's match
  code (or `--match-code`); a mismatch sends nothing. The decision is
  signed with the profile's key under assertionMethod and posted to the
  document endpoint.

  The approver's shared half is a new `vta_sdk::task_consent` module:
  `match_code`, `ConsentRequest::verify` returning a
  `VerifiedConsentRequest` (the only type a decision can be built from),
  and `decision`. `vtc-client` gains `decide_task_consent`.

  It also fixes a mismatch between the two screens: the requester prompt
  in `vta_cli_common::consent` printed the whole `zQm…` digest as the
  "code", while approver devices show six hex characters of the decoded
  digest. Both now call `vta_sdk::task_consent::match_code`, and so does
  `vta-mobile-core`, which drops its copy.

  Tested end to end in `unrestricted_admin_consent`: a real VTC-signed
  request verifies through the SDK, is refused when it is addressed to
  someone else, comes from another issuer, or has been tampered with, and
  the decision built from it grants the consent.



### Fixed

- **vta-service**: Close the key-material follow-ups from the export audit ([#1743](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1743))

* fix(vta-service): apply the key-export and sign capability checks on every transport

  The KeyExport capability was checked only by the keys/export-secret
  Trust-Task handler, so GET /keys/{id}/secret and DIDComm get-key-secret
  released private keys to an admin whose entry was narrowed without
  key-export. Capability::Sign was checked nowhere.

  Both checks now live in the operation layer (VTI-VTA-003, VTI-VTA-007):

  - get_key_secret requires key-export before any lookup, refuses a
    hop-by-hop channel (keys/export-secret/0.1 requires a channel
    confidential to the two parties), keeps the internal-key and
    non-exportable refusals, and writes the key.secret_export audit row
    durably before releasing the material, refusing if it cannot.
  - The Trust-Task binding (https, didcomm, tsp) is recorded at the three
    entry points and named in the export's audit channel.
  - vta/contexts/secrets and provision-integration use the same gate.
  - sign_payload requires sign for opaque caller bytes; derive-and-sign
    and derive-and-sign-document require sign.
  - The legacy REST and DIDComm key routes now consult the policy gate
    with the matching Trust-Task URI.
  - The TEE mnemonic export writes a durable audit row before release.

- **vta-service**: Require a document proof bound to the sender on every DIDComm and TSP trust task ([#1739](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1739))


## [0.23.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.23.0...vta-cli-common-v0.23.1) — 2026-09-24


### Added

- **pnm**: Show the VTA's DID as a QR code with `pnm vta qr` ([#1700](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1700))

`pnm vta qr` prints the active VTA's DID as a terminal QR code, for a
  phone (Keyring) to scan instead of retyping it. It runs offline: the DID
  comes from this machine's config, `--vta` picks which VTA, `--did <DID>`
  draws any other DID, and `--out <file.svg>` also writes the code as an SVG.

  The code carries the bare DID and nothing else, the same choice as the VTC
  landing page's `/v1/community/did-qr.svg` ([#1698](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1698)). A DID is already a URI
  (scheme `did`), so no `did://` or app-specific wrapper is added.

  The terminal code is drawn with half blocks and paints its own colours,
  black modules on a white ground, on every line. The terminal's default
  colours would draw it inverted on a dark theme, and many phone cameras
  refuse an inverted code. The four-module quiet zone is part of the output.

  The renderer lives in `vta_cli_common::qr` (`terminal_lines`, `svg`) so
  `cnm` can use it too. A test unpacks the half blocks back into a module
  grid and checks it against the encoder's, module by module. `qrcode` is
  added with the `svg` feature only.



## [0.23.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.22.1...vta-cli-common-v0.23.0) — 2026-09-23


### Added

- **persona**: Worlds on the wire, and a narrow read of one attribute ([#1690](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1690))

Takes trust-tasks-rs 0.22, which has been unreachable since 0.21.21:
  affinidi-messaging-sdk required ^0.21.20 and `MediatorAcl` crosses that
  SDK's API, so a graph holding both versions failed to compile rather than
  merely carrying a duplicate. affinidi/affinidi-tdk-rs#885 moved the
  messaging crates; this takes the line they are now on. One
  `trust-tasks-rs`, one `affinidi-messaging-sdk`, one `affinidi-tdk`.

  **Worlds.** `persona/facet/*` is `persona/world/*`, `facetId` is
  `worldId`, and `correlation/analyze` takes a 1.1 for its three renamed
  members. `face` and `facet` shared a stem while naming different things —
  a projection of the pool, and an arrangement of those projections — and
  every UI had already resolved it by saying "world" on screen, which left
  the collision live for anyone reading both.

  The retired spellings stay routable for a release and answer in their own
  words: `facetId` for `worldId`, `facets` for `worlds`, `crossesFacets`
  for `crossesWorlds`. A document already issued against one still
  validates, and refusing it would break a caller for a rename that costs
  it nothing. The whole alias is marked for deletion in one commit.

  **`persona/attribute/get`.** Reading one value meant
  `persona/attribute/list` with a type prefix, filtered by the caller — so
  revealing one email address decrypted every email address the holder has,
  and the audit row recorded a listing of the pool rather than a decision
  about one fact. `PersonaStore::get_attribute` applies exactly what a
  listing applies: visibility, retention, credential re-derivation.
  `versionPurged` is distinct from `notFound` because the attribute is
  still there, and `retainedVersions` lets a holder see what purging would
  take away rather than deciding blind.

  Two latent defects, both found by the new tests:

  - `correlation/analyze/1.0` was already answering with 1.1's member
    names. Nothing noticed because 1.1 did not exist.
  - A world with no faces and no attributes serialised without `faceIds`
    and `attributeIds`, which its own response schema requires, so listing
    an empty one returned a 500. `skip_serializing_if` on a required
    member; no test had made an empty one.

  The `pf:` storage prefix is unchanged — it is an opaque key prefix, not
  the noun, and renaming it would orphan every world already stored.



## [0.22.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.22.0...vta-cli-common-v0.22.1) — 2026-09-23


### Added

- **cli**: Pnm reaches worlds and the claim-type registry ([#1663](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1663))

`persona/facet/{put,list,delete}` and `persona/claim-types/list` had no
  method on `VtaClient` at all, so `pnm` could not reach them even though
  both graphical clients do. The SDK gains the four, built from the
  generated specification types rather than hand-written bodies, and
  decoding their responses into the generated `Response` — a shape the
  specification does not describe is then an error at the call rather than
  a `None` three screens later.

  `pnm persona world {list,put,delete}` and `pnm persona claim-types`
  follow. Both id lists on a put replace: the specification is explicit
  that a member whose absence meant "keep" would make emptying a world
  impossible, so the CLI passes them through as given and says so.

  The colour is a ValueEnum whose mapping to the specification's tokens is
  written out rather than derived, pinned from both sides — `pnm-cli` does
  not depend on the generated types and `vta-cli-common` does not know the
  CLI's enum, so the pair of tests is what holds the wire value end to end.



## [0.22.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.21.0...vta-cli-common-v0.22.0) — 2026-09-22


### Added

- **persona**: Wear a face here without naming a persona DID ([#1654](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1654))

Implements trustoverip/dtgwg-trust-tasks-tf#589 (design note
  persona-context-first.md §9.7).

  binding/set takes an omitted `personaDid`, and profile/compose takes
  `wear: true`: the agent uses the persona the holder already uses in the
  context — the one DID with a binding record there, current or cleared —
  and names it in the response. None is refused (`noPersonaHere`),
  several are refused (`personaAmbiguous`, naming them), and compose
  refuses `wear` beside a `personaDid` (`wearAndPersona`). Neither task
  mints a persona: a DID has a lifecycle of its own, and a write that could
  half-create one would leave a published identity nobody holds.



## [0.21.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.20.1...vta-cli-common-v0.21.0) — 2026-09-22


### Added

- **persona**: Derived provenance, and endorsements as inventory ([#1639](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1639))

* feat(persona)!: derived provenance, and endorsements as inventory

  Implements trustoverip/dtgwg-trust-tasks-tf#582 (design note
  docs/05-design-notes/persona-context-first.md §5.7).

- **persona**: Where a face may be worn, where it is, and what it has done ([#1635](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1635))

Implements trustoverip/dtgwg-trust-tasks-tf#577 (design note
  docs/05-design-notes/persona-context-first.md §5.4, §9.6).

  Face reach. A pool face carries `reach` — FaceReach::Anywhere (default)
  or Only { context_ids } — an enum rather than a context list, so
  unrestricted and nowhere cannot be confused (#746/#769/#770).
  binding/set refuses a face outside its reach (`outsideReach`);
  profile/put refuses to narrow it past a context the face is worn in
  (`boundOutsideReach`, naming them). An omitted reach on profile/put keeps
  the face's current one: a client written before reach existed must not
  lift a restriction by saving an edit.

  persona/profile/usage — where a face is worn now, each binding's
  `until`, and the reach beside them.

  persona/profile/timeline — one face's history, oldest first: composed,
  worn, unworn, expired, disclosed, valueChanged, promoted, retired,
  reinstated. A binding taken off left no trace, so each face now has an
  append-only event log (`pft:`, agent-scoped, ULID-keyed so recording
  never takes the write lock), written after the change it describes and
  never failing it; the timeline joins it with the disclosure records. A
  face from before the log reports its composition from createdAt. A
  promoted face keeps its log; a deleted one loses it. FaceEvent has no
  member a value or label could go in, and a test holds that none reaches
  the wire.

  profile/compose takes `until` (`untilNotFuture`).

  `pnm persona profile usage|timeline`, `put --reach-only/--reach-anywhere`,
  `compose --until`. Takes trust-tasks-rs 0.21.14.

- **vtc**: A self-hosted community installs its own DID log over did-management/did/register ([#1632](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1632))

Keyring VTI-35. A community whose DID is `did:webvh:<scid>:<host>` serves
  its own did.jsonl, but the VTA holds the keys that extend it and cannot
  reach the community's copy, and the VTC keeps no VTA credential after
  setup. So an entry the VTA appends later — a TSP transport added to the
  community's services, a key rotated — had no way to the community except
  an operator copying the file by hand. (A community on a DID host needs
  none of this: the VTA publishes each entry to the host itself.)

  The VTC now answers `did-management/did/register/0.1` — the task a DID
  owner sends a DID host, where a second register with a longer log is an
  update — for its own DID at the root slot `.well-known`, over
  `POST /v1/admin/did/register` (super-admin). Before serving, it verifies
  the whole log (every entry's proof under the update keys in force, SCID,
  hash chain), that it is the community's own DID, and that every served
  entry survives unchanged as a prefix; then swaps the file atomically,
  with no restart. So an administrator's authority covers delivery only: a
  log the key holder did not sign, or one that moves the served log
  backwards, is refused whoever delivers it. The prefix rule is stricter
  than `register` alone and carries a consumer-minted code (SPEC §8.5).

  - `cnm did-log install --file did.jsonl`, fed by `pnm did-mgmt dids
    get-log`. It authenticates to the community directly, with the
    community's DID as the audience (`VtcClient::connect`), not through the
    profile's VTA session, whose audience is the VTA's DID — a VTC refuses
    that. The community DID comes from the log; the URL from its host.
  - `VtcClient::install_did_log`; `MockVtc::start_with` for a test VTC with
    a self-hosted DID; a live test authenticates and installs over HTTP.
  - AuditEvent::CommunityDidLogInstalled.
  - The redeploy hint for a DID the VTA manages but does not serve names
    the new command.

- **persona**: Retire a face, warn before deleting one, and let a binding end on its own ([#1628](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1628))

Implements trustoverip/dtgwg-trust-tasks-tf#570 (design note
  docs/05-design-notes/persona-context-first.md §9.4, §9.5).

  persona/profile/retire and persona/profile/reinstate, for pool and
  context-local faces. Retire marks the face before clearing its bindings,
  so an interrupted retire leaves a face that cannot be newly worn and a
  repeat finishes the clearing; the cleared bindings come back in
  `unbound`. binding/set and local/binding/set refuse a retired face
  (`profileRetired`), profile/list leaves retired faces out unless
  `includeRetired`. Reinstate binds nothing. Profile gains `status` and
  `retiredAt`.

  Binding `until` on binding/set and local/binding/set, returned by
  binding/get and binding/list; `untilNotFuture` refuses one in the past or
  on a cleared binding. A lapsed binding reads as cleared at once — every
  binding read decodes through BindingRecord::into_read, and present
  refuses a preview whose persona no longer wears a face — whether or not
  the sweeper has run. The storage-thread sweeper (expire_bindings,
  audited as persona.binding.expire) makes the clear durable and retires a
  face the expiry left worn nowhere; never one still worn elsewhere, and
  never deletes.

  profile/get and profile/delete return `disclosedTo` {partyCount,
  contextCount}; `pnm persona profile delete` says "deleting does not
  un-tell them". Disclosure records now carry the face they were made
  through; an older record is attributed through its binding where that
  still wears the face.

  `pnm persona profile retire|reinstate`, `list --include-retired`,
  `binding set --until`, `local binding set --until`. Retire is
  Destructive for the MCP guard (it withdraws access everywhere at once),
  reinstate Mutating; both RetrySafe.

  Takes trust-tasks-rs 0.21.12.

- **persona**: Compose a face where it is asked for, and promote a local value ([#1623](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1623))

* feat(persona)!: compose a face where it is asked for, and promote a local value

  Implements persona/profile/compose/1.0 and persona/attribute/promote/1.0
  (trustoverip/dtgwg-trust-tasks-tf#569; design note
  docs/05-design-notes/persona-context-first.md §2.1, §5.3).

  compose — a face for one context, from values typed now and attributes
  already held, optionally worn there in the same act. Local by default: a
  typed value is carried inline and enters no pool unless the claim says
  `share: pool`, when a self-asserted pool attribute holding exactly that
  type and value is referenced, and created only if none exists. Where the
  face lives follows from its claims — all local makes a context-local
  face, anything pooled or held a pool face. Everything is validated before
  anything is written (unresolvedReference, duplicateSlot,
  labelWithoutPersona), and a later failure removes the attributes the
  compose created.

  promote — named entries of a context-local face become pool attributes
  and the face moves into the pool with its id, name, order, slots and
  wearers unchanged. One-way. The pool face is written and the bindings
  moved before the local face is removed, so an interrupted promote leaves
  the local face worn and a retry finishes it, reusing what it made.
  versionConflict and entryOutOfRange refuse a stale or out-of-range read.

  Both holder-only (Reach::Holder), classified Keyed for retry, Mutating
  for the MCP guard. `pnm persona profile compose` and `pnm persona
  attribute promote`. The design note records what the built form changed:
  the `profile` noun, no inline findings (analyze with `candidate` is the
  pre-write warning), no facetId, self-asserted-only reuse, and §9.7's
  DID minting left for its own design.



### Fixed

- **cli**: A self-hosted VTA is not told to redeploy the log it serves ([#1624](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1624))

Keyring VTI-36. After a service mutation on a self-hosted ("serverless")
  VTA, the CLI said to fetch the log and "redeploy did.jsonl to your host".
  But the VTA serves its own did.jsonl from its store at the DID's canonical
  path, read per request, so the new entry is already published — the host
  the operator was told to redeploy to is the VTA. The hint now says so,
  names the URL, and notes the resolver cache window; only a copy published
  elsewhere needs replacing. The offline `vta services` surface says the
  entry is served once the daemon starts.

  `dids edit` on a self-hosted DID the VTA manages for someone else (a
  community's) still gets the redeploy advice, which is right there, now
  without calling it "this VTA's DID".



## [0.20.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.20.0...vta-cli-common-v0.20.1) — 2026-09-21


### Fixed

- **cli**: A serverless mint says the operator must host it, and a hosted one says nothing ([#1616](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1616))

Keyring finding VTI-20. `pnm did-mgmt dids create` returns the new DID's log
  entry for **both** kinds of mint, and printed the same advice for both:

      To self-host this DID, place the log entry in a file named `did.jsonl`
      at the URL path corresponding to your DID URL.

  That was wrong in each direction:

  - **Serverless**, it read as one option among several, when it is the only way
    the DID will ever resolve. The VTA that minted it does not serve it; its URL
    answers 404 until someone publishes the file by hand.
  - **Server-managed**, it told the operator to do something the hosting server
    had already done.

  The advice now branches on `server_id`. A serverless mint says plainly that the
  DID will not resolve until the operator publishes it, and where it goes — the
  `--did-url` path, or `/.well-known/did.jsonl` for a bare domain, which is the
  `didwebvh-rs` mapping. A server-managed mint names the server and says no action
  is needed.

  The exact URL is described rather than computed. Computing it would mean adding
  `didwebvh-rs` as a real dependency of `vta-cli-common` (it is only a
  dev-dependency of `vta-sdk`), or a new member on a published wire type — both
  out of proportion to one line of output, and the finding asked only that the
  output say serverless means *you* host it.

  Two similar messages in `vta-service` (the offline `vta did-webvh` path and the
  setup wizard) are left as they are: different surfaces, the first already names
  the exact URL, and neither is what was reported.



## [0.20.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.19.0...vta-cli-common-v0.20.0) — 2026-09-21


### Added

- **persona**: Keep a pinned value through an edit, and let the holder purge it ([#1606](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1606))

Implements the retention half of trustoverip/dtgwg-trust-tasks-tf#538
  (design note docs/05-design-notes/persona-context-first.md §9.1).

  A pin ({ref, pinVersion}) is for the counterparty who verified a value
  and must keep being shown it -- after a name change, the bank that has
  not been told yet. The store did not keep the version an edit replaced,
  so a pin resolved stale from the first edit onward: pinning worked only
  until the one event it exists for.

  Retained by reference (new vta-persona `retention` module, `pav:` keys):
  - An edit keeps the version it replaces when a face pins it, and a pin
    is served from that copy.
  - A kept version is reaped the moment no face pins it (after profile put
    and delete); an edit nothing pins keeps nothing.
  - Deleting the attribute drops every kept version with it.
  - Attribute.retained_versions lists what is kept and the faces pinning
    it, on attribute/list; filled on read, never stored.
  - A face pinning a kept version still presents that value, so the
    correlation index counts it among what the face carries, and a face's
    own analysis treats such a pin as carried rather than as the live
    attribute.

  The holder's override: persona/attribute/purge-version/1.0 removes kept
  versions (named, or all), re-pushes and names every face that pinned one
  (stalePins). Those faces present the entry as stale -- never the current
  value, which the holder did not choose for that counterparty. The current
  version is refused (currentVersion); that is attribute/delete. New
  PersonaStore::purge_versions, VtaClient::persona_attribute_purge_version,
  `pnm persona attribute purge-version`.

  profile/put now refuses a pin to a version neither current nor kept with
  the spec's pinnedVersionUnavailable code, naming the pins, instead of
  storing a face that presents nothing for that entry.



## [0.19.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.18.0...vta-cli-common-v0.19.0) — 2026-09-21


### Added

- **persona**: Say who holds an old value, where an edit landed, and what a context may call a face ([#1597](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1597))


## [0.18.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.17.2...vta-cli-common-v0.18.0) — 2026-09-20


### Added

- **vta**: Report the subtree and the host copies a context delete could not remove ([#1577](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1577))

Takes trust-tasks 0.21.4, which added the two members the context-delete work
  needed and had nowhere to put (trustoverip/dtgwg-trust-tasks-tf#513).

  `subContexts` on `vta/contexts/preview-delete/1.0`. The preview already
  measured the subtree — #1576 made every array the union over it — but could
  not say which contexts those arrays covered, so both CLIs and the browser
  console each derived the list from `contexts/list` and matched paths
  themselves. Three copies of the agent's own cascade rule, none authoritative,
  in front of a destructive prompt. The agent decides what the cascade reaches;
  it now says so, and the consumers read it.

  `daemonCleanupErrors` on `vta/contexts/delete/1.0`. A DID whose hosting server
  would not confirm removing the published log left the deletion reported as a
  plain success, with the orphan visible only in the agent's own logs — which is
  the shape of the defect this whole change set started from. It is the
  subtree-wide form of the `daemonCleanupError` that `webvh/dids/delete/1.0`
  already reports for one DID, and both CLIs now print it after the deletion
  rather than letting a partial success read as a complete one.



### Fixed

- **vta**: Preview the whole subtree a context delete destroys ([#1576](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1576))

`preview_delete_context` collected the named context and nothing else, while
  `delete_context` cascades the whole subtree. Two functions answering
  different questions about the same act, and the preview's was the wrong one.

  A context whose own keyspaces were empty over children holding keys, DIDs
  and grants previewed as holding nothing. Every consumer decides from that
  preview whether the deletion needs `force`, so every consumer decided from
  the wrong set: send `force: false` and the agent refuses with nothing on
  screen explaining why, or — when the parent happens to hold one key — send
  `force: true` and destroy an entire unlisted subtree under a confirmation
  listing one key.

  `collect_subtree_resources` answers for the delete set, and is not a loop
  over the per-context collector. The difference is the ACL classification.
  The per-context question is "does this entry hold *only* this context?",
  which for a subtree gets it backwards: an entry scoped to both `acme` and
  `acme/eng` looks like it holds another context, so a loop reports it twice
  as merely narrowed — when deleting `acme` takes both scopes and the entry
  goes entirely. Asked once against the whole set it comes out as `removed`,
  which is also where the deletion's deepest-first cascade converges. Telling
  an operator that a subject keeps authority it is about to lose completely is
  the one error this preview must not make.

  Both CLI front-ends prompted off that preview and passed `force = true` to
  the deletion regardless, so `vta context delete acme` on a parent that held
  nothing itself took the subtree with no prompt at all. They now name the
  sub-contexts — derived locally, since the task has no member for them yet —
  and count them, and DID templates, toward "does this destroy anything".
  The renderer never printed `didTemplates` and never counted them, so a
  context whose only contents were templates skipped the prompt too.

  Both new tests were confirmed to fail against the old preview.

- **acl**: Pnm acl always says which capabilities an entry holds ([#1574](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1574))

An ACL entry with no capabilities granted by name printed no
  `Capabilities:` line at all. An operator reading `pnm acl get` to find
  out whether a DID holds `persona-holder` got silence, which reads as
  "this tool does not show capabilities" rather than "this entry has
  none" — a different answer to the question being asked.

  That matters for `persona-holder` specifically. It is additive: no role
  derives it, so it is held only where an operator granted it by name, and
  its absence is a fact about the entry rather than a gap in the output.
  Checking for it was the one case the display could not serve.

  Empty now renders as what it means, naming the role that still applies
  so "none granted by name" is not misread as "this DID can do nothing".
  `acl create` echoes the same way, so a `--capabilities` the server
  declined is visible at the point of creation rather than later at the
  gate it was meant to open.

  The names are echoed as stored rather than decoded into `Capability`
  and re-rendered. That type is `#[non_exhaustive]` so a newer VTA can
  store a name this build has never heard of, and dropping it would hide a
  grant from the very output somebody is reading to look for grants.



## [0.17.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.17.1...vta-cli-common-v0.17.2) — 2026-09-18


### Added

- **sealed-transfer**: A template-bootstrap variant that can carry a second signing key ([#1556](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1556))

* fix(did-templates): a key slot beyond the historical pair, and the literal it used to publish

  `slot_var`'s `{SLOT}_KEY_MB` rule is mechanical, and before this it was
  mechanical in one direction only. A `schemaVersion` 2 template could *declare* a
  third key slot — a post-quantum signing key beside the classical pair, which is
  the shape a hybrid-credential issuer needs — and then could not be loaded,
  because the placeholder that slot's own rule produces was rejected:

      Invalid("undeclared placeholder(s) { PQ_SIGNING_KEY_MB } in document
               — add them to requiredVars or optionalVars")

  Only `SIGNING_KEY_MB` and `KA_KEY_MB` were ambient, because only those two are
  in `RESERVED_VARS`. So `keys` at schemaVersion 2 ([#1530](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1530)) could express exactly
  the pair it was introduced to move beyond.

  ## Following the error's advice published a literal into a write-once log

  The advice is the defect. `optionalVars` supplies a **default**, and the
  renderer substitutes a default for any name the caller did not supply — and the
  minting flow does not supply a slot's key under a name it has never heard of.
  So declaring `PQ_SIGNING_KEY_MB` to get past the rejection passed validation
  *and rendered*:

      {
        "id": "did:webvh:x#key-2",
        "type": "Multikey",
        "publicKeyMultibase": "PLACEHOLDER-NEVER-SUBSTITUTED"
      }

  — inside `assertionMethod`, in a `did:webvh` log that is signed once and cannot
  be re-signed. `check_key_slots` already refuses a slot the document never
  publishes: a key minted and thrown away. This is the same failure wearing the
  other hat, a key published and never minted, and it arrived through the one door
  that check does not watch.

  ## What changes

  - `DidTemplate::slot_vars()` — the placeholder names the declared slots occupy,
    built from `key_slots()` rather than a second fixed list. For a v1 template it
    is exactly the two already in `RESERVED_VARS`, so v1 behaviour is untouched;
    it is what lets a v2 template name a third slot at all.
  - `check_placeholders_declared` treats those names as ambient. An author cannot
    declare a value they have no way to know.
  - `check_slot_vars_not_declared` refuses the reverse — a slot's placeholder in
    `requiredVars` or `optionalVars` — naming the slot and saying why. A v1
    template still gets `ReservedVar` from the check that runs first, unchanged.
  - An undeclared placeholder that is *shaped* like a slot's is told to declare a
    **slot**, not a variable. The generic advice pointed at exactly what the new
    check refuses; an error that recommends the defect is worse than no error.

  ## The state this leaves

  A third slot is expressible, and a VTA that cannot yet mint for it fails at
  render with `Unresolved` naming the placeholder — rather than emitting a
  document with a hole in it. Wiring derivation to the `keys` block is the next
  change; until then the loud failure is the correct one.

  Found while tracing what stands between a VTC and a second signing key: nothing
  in the chain from template to `LocalSigner::with_additional_key` could carry one.



## [0.17.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.17.0...vta-cli-common-v0.17.1) — 2026-09-17


### Added

- **keys**: An operator can create a post-quantum key, and see which axis it protects ([#1535](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1535))

Two gaps, one of which made everything upstream unusable in practice.

  ## `keys create` could not make a PQC key

  The VTA has been able to derive ML-DSA-44 and ML-DSA-65 since the BIP-32 work
  landed, and since the derived key started carrying its own algorithm it records
  them correctly too. But the CLI matched exactly three strings:

      "ed25519" | "x25519" | "p256" => ..., other => Err("unknown key type")

  So every post-quantum capability in the stack sat behind a front door that could
  not ask for it. `--key-type mldsa44` now works.

  `keys import` deliberately still refuses them, and says why. The VTA validates
  imported key material per algorithm and has no ML-DSA checker, so offering it
  here would take an operator's private key and fail at the far end. The refusal
  names the gap and points at `keys create`, rather than the generic "expected
  ed25519, x25519, or p256" — which reads as "no such algorithm" and would send
  someone looking in the wrong place.

  ## "Is this post-quantum?" has no single answer

  `QuantumPosture` makes that structural rather than a matter of remembering.
  Signature resistance and confidentiality resistance are separate facts, they
  migrate on different timetables, and today the second is false almost
  everywhere: an identity can sign with ML-DSA-44 while still agreeing keys with
  X25519.

  Collapsing those into one badge is wrong in the direction that matters. A reader
  shown "post-quantum" for such an identity has been told its recorded traffic is
  safe from harvest-now-decrypt-later, and it is not. So every label names its
  axis — `mldsa44 (post-quantum signing)`, `x25519 (classical key agreement)` —
  and a test holds them to it.

  There is deliberately no `PostQuantumKeyAgreement` variant. Nothing a DID
  document publishes can answer that axis affirmatively today: the hybrid KEM this
  stack uses lives in the TSP transport, not in a verification method. Adding the
  variant before that is true would let a renderer claim something nothing can do.



## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.16.0...vta-cli-common-v0.17.0) — 2026-09-16


### Added

- **vta-service**: Tune the VTA's rate limits at runtime ([#1519](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1519))

* feat(vta-service)!: tune the VTA's rate limits at runtime

  The per-IP limiters were tower_governor layers built once with the router, so
  changing a quota needed a config edit and a restart — exactly when an operator
  facing 429s can least afford one.

  The limiters are now our own axum middleware over governor's keyed limiter
  (already in the graph via tower_governor, whose spoof-safe client-IP key
  extractors are reused unchanged). The running service reads the four [server]
  quotas from the shared config on every request and swaps in fresh buckets when
  a quota changes; a change resets that limiter's buckets, and a patch that
  leaves a quota alone keeps them. trust_xff stays restart-only. The 429 contract
  is unchanged.

  rate_limit_interval_secs, rate_limit_burst, did_log_rate_limit_interval_secs
  and did_log_rate_limit_burst are registered in the config registry as mutable
  integer keys, applied live and persisted to config.toml: intervals 1-3600,
  bursts 1-10000, super-admin only, through config/patch like every other key.
  Their names come from vta_sdk::rate_limit, which the 429 hints also use.
  pnm and cnm `config update` gain --rate-limit-interval-secs,
  --rate-limit-burst, --did-log-rate-limit-interval-secs and
  --did-log-rate-limit-burst; `config get` shows the keys.

  Adds docs/02-vta/rate-limiting.md and links it from the docs index,
  non-interactive setup and the setup example.



### Fixed

- **webvh**: Refuse to delete a DID whose hosting server is unregistered ([#1518](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1518))

`dids delete` on a DID whose `server_id` was no longer registered deleted the
  local record and skipped the delete on the hosting server without reporting
  it. `get_server` returning `None` set no `daemon_cleanup_error`, so the published
  did.jsonl stayed live on the host, and the only credentials that could remove
  it (the record's mnemonic and the DID's keys) were deleted with the record.

  VTI R2.1 (Remote-First): no local commit before the remote effect. The deletion
  now refuses up front, before revoking or deleting anything, as a `Conflict`
  blocker on REST, DIDComm and TSP. The message names the fix: re-register the
  server with `servers add --id <id> --did <server-did>` and retry. The offline
  preview shows the same blocker. Serverless DIDs are unaffected.

  `vta did-mgmt dids delete --local-only` is the explicit opt-in for a host that
  is gone for good, where `servers add` cannot succeed because the server DID no
  longer resolves. It is honoured only for an unregistered server. For a
  registered or serverless DID it is refused. The result says the host copy
  remains. It is offline-only because the `vta/webvh/dids/delete/1.0` payload is
  generated from the specification with `additionalProperties: false`. An online
  opt-in needs a `localOnly` member in dtgwg-trust-tasks-tf first.

  `pnm did-mgmt dids delete` also discarded `daemonCleanupError`, the partial
  success the specification says a consumer MUST surface, because the SDK's
  `delete_did_webvh` returns `()`. The new
  `VtaClient::delete_did_webvh_with_outcome` returns the generated response type,
  and the CLI prints the warning.

  Library additions: `DeleteDidOptions`, `delete_did_webvh_with`,
  `plan_did_deletion_with`, and `MockVta::webvh_host_deletes`.



## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.15.5...vta-cli-common-v0.16.0) — 2026-09-16


### Added

- **cli**: Name removal commands `delete`, and say what a delete leaves behind ([#1513](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1513))

* feat(cli): name removal commands `delete`, and say what a delete leaves behind

  Removal commands across pnm, cnm and the offline vta CLI are named
  `delete`. Each old name stays accepted as a hidden alias, so no script
  breaks:

  - `did-mgmt servers remove` -> `did-mgmt servers delete` (pnm + vta)
  - `pnm vta remove` -> `pnm vta delete`
  - `cnm community remove` -> `cnm community delete` (gains --yes/-y)
  - `pnm memory forget` -> `pnm memory delete`
  - `vta approvals disable` -> `vta approvals delete-all` (`disable` still
    works and prints a note naming the new command)

  Where a delete is not complete, the command now says what remains and
  how to remove it: `vta delete` / `community delete` keep the VTA's ACL
  entry (the notice prints the `acl delete <did>` that revokes it);
  `servers delete` lists DIDs still registered against the server, whose
  logs stay hosted there; `vault delete` / `cred-vault delete` without
  --force name `purge` / `--force`.

- **sdk**: Type rate-limit refusals and say who sent them ([#1511](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1511))

A 429 became VtaError::Other("429: Too Many Requests"), with no hint and
  the Retry-After header discarded; through the boxed session auth path it
  became VtaError::Auth, telling the operator to re-authenticate.

  Add VtaError::RateLimited { limited_by, retry_after, limiter, url } with a
  non_exhaustive RateLimitSource (Vta, Vtc, Mediator, DidHost, Upstream) read
  from the x-rate-limit-source header; an unlabelled 429 is Upstream (proxy,
  load balancer, or older VTA). Every VTA HTTP status mapping in the SDK now
  reads headers. idempotent retries a rate limit whose wait fits
  MAX_RETRY_AFTER and surfaces a longer one at once. The CLI renders who
  refused, how long to wait, and which knob to turn; every key name lives in
  vta_sdk::rate_limit.



## [0.15.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.15.4...vta-cli-common-v0.15.5) — 2026-09-16


## [0.15.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.15.3...vta-cli-common-v0.15.4) — 2026-09-14


### Fixed

- **webvh**: Key records follow the document's verification-method ids, and a repair for the ones that don't ([#1466](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1466))

* fix(webvh): name a created DID's key records after the document it published

  A key record's id **is** a verification-method id. `save_entity_key_records`
  says so in its own name, and `vta_sdk::did_secrets::select_secret_kid` rule 1
  depends on it: the kid a mediator matches inbound JWE recipients against is the
  record id, on the reasoning that "the DID document decided what the key is
  called".

  Create never read the document to find out. It named the records `{did}#key-0`
  and `{did}#key-1` while the document was whatever the caller or the template
  said — and the `room` and `room-host` built-in templates number their methods
  from `#key-1`. So on every room and every room host this VTA has ever minted:

  - the document's `#key-1` is the **signing** key and the keystore's `#key-1` is
    the **x25519** one. One name, two keys, no error anywhere. Hand the id the
    document publishes to `keys/sign` — the natural thing to do, having read it
    off the document — and the oracle fetches an x25519 record for an EdDSA
    signature;
  - the document's `keyAgreement` (`#key-2`) matches no record at all, so an
    authcrypt message addressed to it finds no local secret. That is the storm.ws
    outage of #337 reached from the other side: there a decorative label
    overwrote the right kid, here the right kid was never stored;
  - `next_fragment_id` was stored as the constant 2, so the DID's first rotation
    allocates `#key-2` — over the id its key-agreement method is already
    published under.

  Room credentials still verify, which is why this stayed quiet: `RoomKeySigner`
  hardcodes `{room_did}#key-1` to match the template, and the public keys line up
  positionally, so the proof names a method that resolves to the key that signed
  it. Everything that addresses a key *by name* is what breaks.

  ## The fix reads the document rather than renumbering the templates



## [0.15.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.15.2...vta-cli-common-v0.15.3) — 2026-09-12


## [0.15.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.15.1...vta-cli-common-v0.15.2) — 2026-09-10


## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.14.1...vta-cli-common-v0.15.0) — 2026-09-09


### Fixed

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



## [0.14.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.14.0...vta-cli-common-v0.14.1) — 2026-09-08


### Documentation

- **persona**: Say "attribute" on screen, not "fact" ([#1319](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1319))

`design-docs/persona-vocabulary.md` translated `attribute` to **fact** for
  everything a person reads. That was wrong in two independent ways.

  It asserts what the model cannot promise. What a holder keeps in the pool is
  self-asserted until a credential backs it, and a face exists so a person can
  choose what to show — an old value, a pinned version, a value overridden for one
  context, or a value that is simply not true. The step-up card said "Approve
  disclosing 1 fact" about exactly that.

  And the word was already spent: `fact` is the VTC ceremony engine's term for a
  *verified* policy input (`vtc-service/src/ceremony/facts.rs`, `Facts` assembly,
  every `.rego`) — very nearly the opposite meaning, in the same product.

  `detail` is the persona audit envelope's own field, `trait` is a keyword,
  `entry` names an entry in a face and `value` is the field inside an attribute,
  so the spec word comes to the screen instead and that row stops translating.
  Truth is carried by the provenance beneath the value, never by the noun.

  - step-up approval card: "1 fact" → "1 attribute" (the string an approver reads
    on their phone)
  - `pnm persona …` help text and `vta-cli-common` printed output: "Your facts:"
    → "Your attributes:", "Fact:" → "Attribute:", and the surrounding guidance
  - `vta-persona` doc comments that define the model in the old word

  Commands, flags, task URIs and wire records are untouched — they always said
  `attribute`. Nothing in `vtc-service/src/ceremony/` is touched; that `Facts` is
  the other meaning.

  vta-persona 88 tests and vta-service persona_trust_task 23 tests pass.



## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.13.0...vta-cli-common-v0.14.0) — 2026-09-07


### Added

- **rooms**: A member's CLI surface, driven through the oracle ([#1285](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1285))

Rooms had no CLI. Using one meant writing Rust against `vtc-client` or hand-
  building signed Trust Task documents, which is not a surface an operator has.
  `pnm rooms {create,list,get,put,curate,renew}` is that surface for a member.

  ## Two parties, never confused

  Every command talks to both and keeps them apart: the operator's **VTA** mints
  a presentation (`rooms/keys/present`) and opens sealed records
  (`rooms/keys/open`), and the room's **host** stores the bytes. The credentials
  the presentation is derived from and the group key that opens a record stay
  inside the VTA - this CLI holds neither at any point.

  That makes the CLI the oracle's first real consumer, and it works: a member
  who holds less than an action needs is refused by their own VTA, before
  anything reaches the host, which is the earlier and clearer of the two
  refusals.

  Each command mints its own presentation for exactly the action it performs -
  `read` for list/get, `write` for put, `curate` for curate, `admin` for renew.
  Caching one across commands would mean re-binding it (impossible without the
  VTA) or sending it unbound, which is a bearer token.

  ## Where the pieces had to live

  `vta-sdk` gains `room_present` / `room_open`, because those are calls to your
  own VTA. It cannot gain the room *wire types*: `vti-common` re-exports
  `vta_sdk::acl`, so `vta-sdk -> vti-rooms -> vti-common -> vta-sdk` is a cycle.
  So `vta-cli-common` takes `vtc-client`, which despite its name is the
  host-neutral room client - `room-host`'s own example drives itself with it. A
  second copy of the `rooms/*` wire types in the CLI is exactly the duplication
  that crate deleted.

  `vtc-client` gains `curate_record`, which nothing had implemented.

  ## What it deliberately cannot do

  **Write to a sealed room**: sealing needs the room's group key, and no task
  seals on a caller's behalf. **Issue credentials**: minting a VIC, VMC or VAC
  needs the room's own signing key, which is the owner's - a different party with
  different custody. Both are refused with the reason rather than half-served,
  and `get` translates the epoch-mismatch failure into "a commit has not been
  delivered", which is what it means and not what it reads like.

  Five tests on the two pure decisions: rebuilding a session from what the VTA
  minted (each missing member refused rather than defaulted, a subject binding
  surviving, a non-string chain link refused rather than silently shortening the
  chain), and the pin/unpin tri-state where absence must stay distinct from
  false.

- **acl**: Create an entry already narrowed, rather than narrowing it after ([#1280](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1280))

#1279 left `acl/grant` refusing a capability narrowing and pointing at
  `acl update`, because taking one meant a fifteenth positional parameter on
  `create_acl`. Refusing was honest but it leaves a real window: between the
  grant and the narrowing the entry holds everything its role implies, and a
  subject that authenticates inside that window is authorized by what it found
  there.

  `create_acl` now takes a `CreateAclParams` struct - the shape `update_acl`
  already had - so the narrowing is one more named field rather than a
  fourteenth argument nobody can read at the call site. Test call sites state
  the two or three members they care about and default the rest instead of
  spelling every one to reach the last.

  The rule is the update path's, applied where the entry is born: a name the
  role does not carry is refused rather than dropped, an unknown name is
  refused, and neither leaves a row behind. `pnm acl create --capabilities
  memory-read,room-present` is now the form to prefer, and the agent runbook
  says so.

  Also echoes the stored narrowing from `acl create` and `acl show`, so the
  restriction can be read back from wherever it was set.

- **acl**: Enforce an entry's capabilities, and give an operator a way to set them ([#1279](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1279))


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.12.4...vta-cli-common-v0.13.0) — 2026-09-07


### Added

- **vta-sdk**: Make the growth-prone wire bodies non-exhaustive ([#1270](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1270))

Sixteen public request bodies gained an `ext` member in #1231 — under a `fix:`
  type, which derives the smallest bump there is — and every consumer building one
  with a struct literal stopped compiling. `vta-sdk` 0.32.4 shipped that as a patch
  release, which a caret requirement takes on a routine `cargo update`.

  `ext` is the framework's extension member (SPEC §4.5.1); these bodies gain
  members whenever the schema revises. So the fix is not to remember the `!` next
  time, it is for the addition to stop being breaking: fourteen of them are now
  `#[non_exhaustive]` with a `new()` taking the members the schema requires. The
  optional members stay public — set them on the returned value.

  Deliberately NOT applied to `AclEntry` or `AppStateWrite`, which the same report
  flagged. `AclEntry` has 68 construction sites, and its own doc comments record
  that `None` and `Some([])` on `allowed_keys` are OPPOSITE grants: absent means
  every key the entry's scopes reach, present-but-empty means no keys at all. A
  generated constructor defaulting that to `None`, migrated mechanically across 68
  sites, is precisely how the narrowest grant becomes the widest — the same class
  of mistake CLAUDE.md already attributes to #746, #769 and #770 on the adjacent
  `allowed_contexts` axis. That one wants per-site review, not a script, and it is
  better done on its own.

  The compiler was a better census than grep: I estimated 19 external construction
  sites and it found 21, across five files including integration tests, which count
  as outside the defining crate for this purpose.

  Two of my own automation passes needed correcting on the way, both worth naming
  because the second was nearly silent: the first brace matcher mis-parsed `//`
  comments sitting inside the literals, and the second dropped the comment attached
  to `authorization_context: None` while filtering out `None`-valued fields. That
  comment records that `authorizationContext` is a member the published schema does
  not define, so a producer cannot send it through the validated transport at all.
  It is restored against the constructor default.

  Breaking, so this wants the minor slot on vta-sdk. #1256's guard will say so if
  the release proposes otherwise.



## [0.12.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.12.3...vta-cli-common-v0.12.4) — 2026-09-06


### Added

- **persona**: The operator surface, and a preview built to be read ([#1257](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1257))

* feat(persona): SDK wire types and client methods for the persona family

  Twenty-four request bodies under `protocols::persona` and the client
  methods that dispatch them, against the specs merged in
  trustoverip/dtgwg-trust-tasks-tf#360.

  Responses come back as `Value`, as they do for `app-state`: these are the
  shapes a caller must get right to be understood, and a response is read
  by whatever renders it.

  **Hand-written here, generated in the service.** `vta-service` builds
  these payloads from `trust-tasks-rs` directly, because a mirror is a
  second definition of one contract and free to drift. This crate cannot do
  the same: `trust-tasks-rs` is an optional dependency here and the `client`
  feature does not enable it, so a types-only consumer must not be made to
  pull the generated tree in. Two source-level censuses cover the gap —
  `payload_ext_census` and `payload_null_census`.

  **The boundary is in the types.** `LocalProfileEntry` is a separate type
  from `ProfileEntry` rather than the same type with variants unused,
  because the published schema for `persona/local/profile/put/1.0` closes
  its entries to a single `inline` member. A profile built inside a trust
  context has nowhere to name an attribute in the agent-scoped pool. That
  closure is load-bearing rather than incidental, which is why it is
  mirrored as a distinct type instead of a shared one used carefully.

  **Three census exemptions, and why they are not the easy way out.**
  `OverrideValue`, `InlineValue` and `LocalProfileEntry` deny unknown fields
  and carry no `ext`, which `payload_ext_census` flags. Adding one would be
  wrong: the published schemas close all three with
  `additionalProperties: false` and declare no `ext` slot, and
  `trust-tasks-rs` generates them with `deny_unknown_fields` and no `ext`
  for the same reason — so the field would make this crate emit documents
  the VTA's own `validate_payload` rejects. They join
  `IssuedCredentialSummary` in `NO_EXT_BY_DESIGN`, which exists for exactly
  this case: a member of a payload rather than a payload.

  `ProfileEntry` carries `untagged` **and** `deny_unknown_fields`, with the
  variants in reading order, for the reason recorded on the store-side type:
  the clause is the only thing keeping the four forms apart, so a test can
  prove it is working.

- **pnm-cli**: Add memory command group ([#1222](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1222))

* feat(pnm-cli): add memory command group

  Add `pnm memory` for CRUD over the VTA's per-context agent memory
  (`spec/vta/memory/{put,list,delete}/0.1`): plant, recall, forget, wipe.
  Context-scoped via `--context` (default `default`); `--json` supported.



### Fixed

- **sdk**: Accept the `ext` member every payload schema declares ([#1231](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1231))

SPEC §4.5.1 gives every Trust Task payload an `ext` slot, and the published
  schemas declare it — `acl/list/0.1` lists `ext` among its properties, as do
  `policy/list/0.2`, every `vta/memory/*` body, `app-state` writes, config show
  and patch, and both credential-issuance bodies.

  Sixteen `deny_unknown_fields` structs had no field for it, so a producer doing
  exactly what the schema permits had its whole document rejected:

      malformed request: payload parse: unknown field `ext`, expected one of
      `role`, `scope`, `direction`, `subjectPrefix`, `pageSize`, `cursor`

  Seven sibling structs already carry `ext`, with the reasoning written out on
  each; this completes that work rather than starting it. `deny_unknown_fields`
  stays: carrying `ext` explicitly is what keeps a *typo* refused, which is the
  guard that clause was there for, while letting through the one member the spec
  says is always allowed.

  Found from a browser-based VTA management console: its Access and Policy panes
  died outright, and the operator was shown a parse error naming a field the
  spec had told the client it could send. Nothing caught it earlier because
  whether a caller trips this is decided entirely by whether it populates `ext`
  — the conformance table exercises the members its fixtures set, and this
  defect lives in the member they leave unset.

  So the guard is a census over the source rather than another fixture:
  `payload_ext_census.rs` fails on any `deny_unknown_fields` type under
  `protocols/` that carries no `ext`, with an exceptions list that has to state
  a reason. Verified to fail by reverting one struct.



## [0.12.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.12.2...vta-cli-common-v0.12.3) — 2026-09-01


### Fixed

- **vta**: Keep not-found, conflict and gone typed across the Trust-Task boundary ([#1219](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1219))

`pnm approvals list` failed on a VTA that had never had an approval rule:

      Protocol error: trust task failed [taskFailed]:
      task failed: not found: policy `approvals` not found

  A VTA with no approval rule has no `approvals` policy row — that is the
  shipping default, and the CLI is written for it: `load()` maps a missing
  row to an empty model. The arm could never fire.

  The Trust-Task framework defines no `notFound` / `conflict` / `gone`
  standard code, so `app_error_to_reject` sent all three out as `taskFailed`
  with `details: None`. The SDK had nothing to key on and fell through to
  `VtaError::Protocol(String)`, so the `Err(VtaError::NotFound(_))` arm in
  the approvals CLI was dead code on the only transport that surface uses
  (it is Trust-Task-only; no `/policies` REST route exists).

  The blast radius is the whole surface, not just `list`: every `pnm
  approvals` subcommand reads the row through the same `load()`, `require`
  included. Since `require` must read before it writes, the *first* rule was
  uncreatable — DTTE could not be configured on a fresh VTA at all.

  REST keeps this distinction in an HTTP status (`from_http`) and DIDComm
  protocol-messages keep it in a problem-report code (`from_problem_report`).
  The Trust-Task path was the only one that lost it, against the workspace
  rule to preserve type information across every transport.

  `taskFailed` remains the correct wire code — there is no other. The
  discriminator goes in `details.reason`, the channel the consent gate
  already established for exactly this reason, with the values defined once
  in `vta_sdk::protocols::trust_task_reject_reasons` so both sides derive
  from one definition. `VtaClient::trust_task_error` maps them back to
  `NotFound` / `Conflict` / `Gone`.

  Fixing `Conflict` alongside `NotFound` also restores the CLI's
  suggest-the-fix guidance, which switches on the typed variant.

  A `taskFailed` with no `details` stays `Protocol` — that is both a genuine
  failure and the shape an older VTA emits, so a new client does not misread
  every pre-upgrade failure as typed. Against such a VTA the workarounds are
  `pnm policy list` or the offline `vta approvals list`, both documented.



## [0.12.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.12.1...vta-cli-common-v0.12.2) — 2026-08-29


### Fixed

- **vta**: Refuse a malformed DID instead of reporting it missing ([#1195](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1195))

`pnm did-mgmt dids delete <did>` answered `webvh DID not found` for a DID
  that was sitting in the registry. The argument was the problem: it had been
  copied out of the `dids list` table, which elides the middle of the SCID, so
  it carried a literal `…` (U+2026). The store was asked for a DID that does not
  exist and said so, accurately.

  Accurately, and misleadingly. "Not found" is a claim about the world — it says
  the DID is not here — so it sends the reader looking for something deleted
  rather than at what they typed. It cost two people an hour and a wrong
  diagnosis each: one concluded an earlier command had removed the DID, the
  other that the VTA had never hosted it. Neither was true.



## [0.12.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.12.0...vta-cli-common-v0.12.1) — 2026-08-29


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.5...vta-cli-common-v0.12.0) — 2026-08-28


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



## [0.11.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.4...vta-cli-common-v0.11.5) — 2026-08-26


## [0.11.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.3...vta-cli-common-v0.11.4) — 2026-08-22


## [0.11.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.2...vta-cli-common-v0.11.3) — 2026-08-21


## [0.11.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.1...vta-cli-common-v0.11.2) — 2026-08-20


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



## [0.11.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.11.0...vta-cli-common-v0.11.1) — 2026-08-18


## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.33...vta-cli-common-v0.11.0) — 2026-08-17


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



## [0.10.33](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.32...vta-cli-common-v0.10.33) — 2026-08-16


## [0.10.32](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.31...vta-cli-common-v0.10.32) — 2026-08-16


## [0.10.31](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.30...vta-cli-common-v0.10.31) — 2026-08-14


### Fixed

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



## [0.10.30](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.29...vta-cli-common-v0.10.30) — 2026-08-12


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



## [0.10.29](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-cli-common-v0.10.28...vta-cli-common-v0.10.29) — 2026-08-12


### Fixed

- **vault**: Send entryId on vault release, from both the CLI and the MCP bridge ([#948](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/948))

* fix(vault): use entryId instead of id in vault release payload

  cmd_vault_release was constructing the vault/release/0.1 Trust Task
  payload with key `id`, which fails schema validation. The schema
  requires `entryId` (matching VaultReleaseBody's camelCase
  serialisation on the server side).


