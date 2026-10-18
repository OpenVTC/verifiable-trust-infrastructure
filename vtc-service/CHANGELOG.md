# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-service-v0.11.58...vtc-service-v0.12.0) — 2026-10-18


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

- **vtc**: Vtc/rooms/community/members/remove 0.2 — a removed member is refused at the room's host at once ([#2175](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2175))

* feat(vtc): vtc/rooms/community/members/remove 0.2 — a removed member is refused at the room's host at once

  The community half of trust-tasks-tf #804. A member removed from a room the
  community owns kept every credential the room gave them, honoured at the host
  until `validUntil`; on an `open` room removal withdrew nothing at all.

  `vtc/rooms/community/members/remove/0.2` (0.1 still served, unchanged):
  - item 2, admitted member: `open` — the community's VTA withdraws them
    (`rooms/owner/revoke`, one `subject` withdrawal, delivered to this community
    as the room's host); `attributed` — `rooms/owner/group/remove/0.2`,
    withdrawing first and then advancing (a member with no leaf is withdrawn
    alone); `private` — `group/remove/0.1`, the group alone;
  - item 3: an open offer is withdrawn, and on `open` and `attributed` its
    credentials at the host too;
  - recorded only once the VTA answered and, on `open`/`attributed`, the host
    accepted the withdrawal; a refused delivery is `keyHolderRefused`, an
    unconfirmed one `keyHolderUnavailable`;
  - item 4: the answer carries `revocation` (the list's head) and `revokedAt`
    beside `member` and, on a sealed tier, `epoch`; the `ext` notice says what
    the tier's removal does.

  The removal is one function (`rooms::departures::remove_member`) used by the
  administrator's request and by the departure worker ([#2156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2156)), so a member who
  leaves the community is withdrawn at the host of every room it owns too. Every
  departure removal now asks the VTA, so a pass stops at the first silent VTA.

- **vtc**: Runtime community themes — a checked stylesheet editor, built-in themes, a no-write preview, and decisions the theme cannot reach ([#2181](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2181))

* feat(vtc-admin-ui): community themes — built-in themes, a checked stylesheet editor, and a preview of the console and portal that writes nothing

  The browser half of vtc/community/theme/* (trustoverip/dtgwg-trust-tasks-tf#811);
  storing a theme for the community follows once the tasks reach the daemon.

  Theme card (Community profile page):
  - Six built-in themes (Default, Forest, Ocean, Slate, Sunset, High contrast),
    upload a .css, edit in place, download.
  - Checked against the theme profile (P1-P8) as you type; the first thing
    outside it is named by line, column and profile item.

  Theme profile checker (lib/theme-profile.ts):
  - Tokens on :root (light/dark, prefers-color-scheme media only); on elements,
    colours, gradients, bounded borders/radius, fonts, bounded letter-spacing.
    No url()/@import/@font-face, no !important, no escapes or `<`, nothing that
    moves, sizes, hides, overlays or adds content.
  - theme-profile.vectors.json: the cases the community's own checker must
    answer identically. Vitest is told to load the theme .css files whole;
    it empties ?raw stylesheets otherwise, which made every built-in pass
    vacuously.

  Theme preview (lib/theme-preview.ts), opened in a new tab from the card and
  following the draft live:
  - The console sends reads only: at both seams every request leaves through
    (lib/api.ts request + postDocument), a document goes only when its task is
    a read and a plain request only when it is a GET. Default-deny; anything
    else is refused before it is sent and the preview bar says nothing changed.
    Wallet and portal sign-in paths are guarded the same way.
  - No third-party plugin loads in a preview: it could write past the guard.
  - The member portal answers its own routes from a sample member (signed-in
    home or sign-in page, switched from the bar), so an administrator who is
    not a member can preview it; public reads are real; rooms never reach the
    member's wallet.
  - The preview bar is drawn in its own shadow tree with literal colours, so
    the theme under preview cannot restyle the notice that nothing is saved
    (theme/show client items 2 and 4).

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

- **rooms**: Rooms/revocations/{put,get} — a host refuses what the room withdrew, at once ([#2173](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2173))

A room had no way to take back a grant before it expired: a host authorizes from
  credentials the room issued and keeps no roster, so a removed member's VMC and
  VAC chain stayed good at the host until `validUntil`. trust-tasks-tf #804 adds
  the room's revocation list — signed by the room, cumulative, numbered — which an
  administrator delivers to each host serving the room. This is the host half.

- **vtc**: The last proof-required tasks are served only as signed documents ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#2180](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2180))

* feat(vtc)!: an admin's own passkeys and the cookie bridge are served only as signed documents ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641))

  #1641's last batch. Six of the seven tasks still served on a bearer token
  while their specifications declare `proof` REQUIRED (VTI-OPS-020) move to the
  signed door, the admin console signs them, and their bearer routes are
  deleted.

  - `auth/passkey/list/0.1`, `auth/passkey/enroll/{start,finish}/0.2` and
    `auth/passkey/revoke/{start,finish}/0.1` (`trust_tasks::admin_passkey_tasks`;
    operations in `routes::admin::passkeys`). Authority is `admin_signer` (the
    routes took exactly `AdminAuth`); every passkey named is the signer's own,
    or its administrator's for a console key. The in-request UV against an
    existing passkey is unchanged and is required on `enroll/finish` even
    though 0.2 makes `uvCredential` optional for a first enrolment, which this
    door never serves (`enroll/start` answers `reauthUnavailable`). The declared
    codes (`credentialNotFound`, `enrollmentNotFound`, `attestationInvalid`,
    `revocationNotFound`, `userVerificationFailed`, `lastCredential`) are
    emitted. Removed: `GET /v1/admin/passkeys` and
    `POST /v1/admin/passkeys/{register,revoke}/{start,finish}`.
  - `vtc/auth/admin-session/0.1` (`trust_tasks::admin_session_tasks`), HTTPS
    only, setting the cookies through the door's `HttpContext` as
    `auth/oob/redeem` does. The signer must be the access token's subject, or a
    console key with an active delegation from it — a token alone no longer
    becomes a cookie session. The console has the wallet sign it as the
    identity that signed in, falling back to its console key. Removed:
    `POST /v1/auth/admin-session`.

  `auth/whoami/0.1` does not move: it is the console's probe of its own cookie
  session and runs before a browser may hold a signing key, so a signed whoami
  has no signer to attribute for that browser. Moving it needs a design
  decision, recorded in vtc-trust-task-proof-enforcement.md §6c.

  The console's My passkeys page and the SIOPv2 sign-in sign their calls
  (`lib/my-passkeys-api.ts`, `lib/admin-session.ts`); openapi.json and wire.ts
  regenerated. Design notes brought up to date: vtc-trust-task-proof-enforcement
  (status, final batch, §6c, `vtc/backup/import/0.1` superseded by the chunked
  `backup/*` family) and vtc-console-signing §8 (decided, #1684).

- **vtc**: Community rooms carry their own name — create 0.3 and update 0.2 write the label and description into the room ([#2179](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2179))

Implements the community side of trustoverip/dtgwg-trust-tasks-tf#807:
  vtc/rooms/community/create/0.3 and vtc/rooms/community/update/0.2, on top
  of the community-room details ([#805](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/805)).

  - create 0.3 (step 5, items 8-9): once the room is stored, the community's
    own VTA is asked (rooms/keys/profile/write, as the community, with this
    VTC as host) to write the label as the profile's `name` and the
    description as its `description` — never the tags. The answer's
    `roomProfile` is `written` only when the VTA answered written, otherwise
    `pending`; the room stands either way.
  - update 0.2 (items 10-12): a change of label or description writes the
    profile again, first reading the current one and carrying over the tags,
    emoji and ext a curator set in the room; a room made before create 0.3 (or
    one still pending) is written even when nothing changed, and that is not
    audited as a change; a tags-only change answers `unchanged`. The change to
    the owner's record never depends on the write. Update 0.1 still never
    reaches the VTA.
  - rooms::community_profile: the one retry owner for `pending` profiles — a
    record per room (`room-profile:<room>`, beside the owner's record),
    written pending before the VTA is asked and written only after it
    answered, one attempt per due room per pass with a capped backoff and
    jitter (1 min to 6 h), always writing the room's label and description as
    they are at the attempt, so a later update supersedes a pending one.
  - get/list carry ext["org.openvtc"].roomProfile (written / pending with the
    retry state / none); the console shows it on a room's page and creates at
    0.3 and updates at 0.2, toasting a `pending`; cnm rooms create/update use
    0.3/0.2 (falling back to 0.2/0.1 against an older VTC) and get/list show
    the state.
  - The community's entry at its VTA needs `room-open` for the profile tasks:
    added to the capabilities the VTA-access fix commands name, and to the
    docs. The community's own authority already confers admin, write and
    curate (create item 6), so item 12's re-issue is never needed here.
  - Both new versions dispatched, with conformance entries, OpenAPI wrappers
    (openapi.json and wire.ts regenerated) and the console manifest.

- **vtc**: Community-room details administrators can see, edit and track (trust-tasks-tf #805) ([#2170](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2170))

* build: raise the trust-tasks-rs floor to 0.31.14 (trust-tasks-tf #805)

  0.31.14 carries vtc/rooms/community/update/0.1, the 0.2 community-room
  create/get/list and vtc/rooms/offers/list/0.2.

- **rooms**: A member's own private name, description, notes and tags for each room they hold ([#2167](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2167))

* build(deps): trust-tasks-rs 0.31.14 — rooms/keys/label/0.1 and rooms/keys/list/0.2

- **vtc-admin-ui**: The member portal shows this community's room offers and accepts them through the wallet ([#2165](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2165))

A member took up a community's offer of one of its rooms only with
  `pnm rooms offers accept`. The portal's Data rooms page now shows
  "Offers from this community" — label, tier, actions, valid until, the
  identity it is addressed to — read through the member's wallet
  (`window.vtaWallet.rooms.offers`), and *Accept…* asks the wallet
  (`rooms.acceptOffer`), where the member decides in the wallet's own
  window. The wallet stores the offer's credentials in the member's VTA,
  has the VTA mint the KeyPackage, accepts as the member
  (rooms/keys/act/0.3) and joins from the Welcome; none of it crosses to
  the page, and no /v1/member/* route carries any of it (data-rooms-files
  §8.5). After an accept the page offers to share the room here
  (`choose` with `suggest`).

  The card appears only with a wallet that has the methods and only when
  something waits; a decline reads as "the offer stays open", and a wallet
  not yet allowed to reach the community says where to allow it.

  Pairs with OpenVTC/vta-browser-plugin's room-offers PR, which adds the
  methods. Without it the card does not appear; nothing else changes.

- **vtc-admin-ui**: The member portal titles a community's own rooms by name ([#2163](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2163))

"Your rooms here" and a room's page showed only a room's DID. For a room
  the community owns, the member's wallet now returns the label its
  administrators gave it — read from the community's offer to the member
  (vtc/rooms/offers/list, signed as the member through rooms/keys/act/0.3),
  never from a portal route — on each `rooms.list` entry (`label`,
  `visibility`).

  - wallet-rooms.ts: PageRoom gains optional `label` and `visibility`;
    `roomName` is the one place the portal decides a room's title, so a name
    from a sealed in-room profile can come in there later.
  - Rooms.tsx: a named room is listed by its name with the DID beneath, its
    page is headed by the name with the full DID under it, and a "Not shared"
    line names it. A member's own room, and every room under a wallet that
    returns no names, keeps its DID as before.
  - data-rooms-files.md §8.5 records where the name comes from.

  No REST route, no spec change. The wallet half is OpenVTC/vta-browser-plugin


  #334; with an older wallet the portal shows DIDs, as today.

- **vtc**: A VTA permission refusal shows the pnm commands that fix it ([#2160](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2160))

When the community's VTA refuses a community-room step for lack of
  permission, the console and `cnm rooms` show the `pnm acl` commands that
  fix the VTC's entry at its VTA, filled in with the VTC's DID and contexts.

  The entry must cover the context holding the VTC's own DID, not only the
  `[rooms.community]` context: the VTA acts as the community only for a DID
  in a context the entry covers, and a scope covers descendants, never a
  parent. An entry scoped to `vtc-test/rooms` with the DID in `vtc-test` is
  refused "... is not a persona you may act as".

  The fixes ride `vtc/rooms/community/list`
  (`ext["org.openvtc"].communityRooms.vtaAccess`), answered to holders of
  `vtc.rooms.manage`, not the refusal: a trust-task-error message may not
  carry consumer-internal state such as VTA contexts, and keyHolderRefused's
  details admit only the VTA's code and message. Each fix names the refusals
  it answers, so clients apply one rule set as data. The list also warns
  when the rooms context is outside the DID's context or `vta_context` is
  unknown.

  New optional config key `vta_context` (written by `vtc setup`) records the
  VTA context holding the VTC's DID; absent, the commands use a placeholder.
  Docs gain a troubleshooting section; quickstart §12 now passes
  `--contexts vtc`.

- **vtc-admin-ui**: Show a community room's name on the host pages ([#2157](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2157))

A room the community owns showed only its DID on Data rooms → Rooms and on
  the room's host page, so an administrator could not tell which room was
  which. The community knows each such room's label (set at
  vtc/rooms/community/create, returned by vtc/rooms/community/list/0.1).

  For a viewer holding vtc.rooms.manage, the host pages now join the
  community's list on room DID (`rooms/useRoomNames.tsx`, sharing the
  Community rooms tab's query under ["rooms"], so the live `rooms` hint
  re-reads it): the label is the page title, the list's primary text and
  the breadcrumb, with a "Community room" badge linking to
  /rooms/community/<DID>, and the DID kept as secondary text with its copy
  button. A room missing from a complete list is a member's, and says
  "Named by its owner; this community never sees room names" — no name is
  ever fetched for it. A viewer with only vtc.rooms.admin, or a refused or
  failed read, sees the DID as before, with no error.

  The Rooms list also gains a search over name and DID, tier and lifecycle
  filters, and sortable Room / Tier / Lifecycle / Created columns. A
  community room's page always shows its created date and, for a holder of
  vtc.audit.read, links to the Audit trail — unfiltered, since the trail
  cannot filter to one room (a CommunityRoomChanged row names the room in
  its event data, not its target). It leaves a marked place for renaming
  and a description, which wait on a community-room update task.

- **vtc**: Renew the community's own authority over the rooms it owns before it lapses ([#2155](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2155))

vtc/rooms/community/create item 6 says a community SHOULD renew its own
  authority credential well before it lapses; until now that was a manual
  `pnm rooms owner issue-authority` at the community's VTA.

  A sweeper (`rooms::community_renewal`, every five minutes) finds each
  community room whose `ownerAuthorityValidUntil` falls within
  `[rooms.community] authority_renew_within_days` (new, optional, default 30,
  never more than half of `authority_valid_days`) and has the community's VTA
  issue a fresh membership and `admin` authority (rooms/owner/issue-membership,
  rooms/owner/issue-authority/0.2, same four actions), each valid
  `authority_valid_days`. Both are renewed because create issues them with the
  same expiry.

  Each new credential is stored (vault/credentials/receive with `id`) under the
  handle of the one it replaces: the VTA refuses to act for a persona holding
  two authority credentials from one room, so a copy beside the old one would
  stop every admission and removal. A create now records the handles the VTA
  answered (`authority-renewal:<room>` in the community_rooms keyspace); for a
  room created earlier they are found with vault/credentials/query + get, which
  needs `vault-read` on the community's entry at its VTA.

  Remote first (R2.1): the owner's record's new `ownerAuthorityValidUntil` is
  the one local write, after the VTA holds both credentials. A pass cut off
  mid-way is finished by the next one under the same handles. The sweeper is
  the only retry owner: a failure waits a capped exponential backoff with
  jitter (1 min doubling to 6 h), is logged at warn (error once lapsed),
  audited when a run of failures starts (CommunityRoomChanged
  `authorityRenewalFailed`; success is `authorityRenewed`), and shown in
  vtc/rooms/community/{get,list}'s ext["org.openvtc"].authorityRenewal, which
  the console renders as "renewal failing" with the reason and next attempt.

  Rooms are not renewed while community rooms are off or there is no VTA
  link, nor when the room is no longer hosted here, no longer owned by this
  community at its host, or reclaimable. No spec task exists for a manual
  "renew now", so there is none.

- **vtc**: Run membership-sync jobs waiting on a backoff now — sync-jobs/retry/0.2 ([#2154](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2154))

Adding a trust registry to a running community queues a publish job for
  every existing member, and the first failures put them on an exponential
  backoff that reaches an hour. retry/0.1 only requeues failed jobs, so an
  operator who had fixed the cause could only wait.

  The VTC serves vtc/registry/sync-jobs/retry/0.2 (trust-tasks-tf #802,
  trust-tasks-rs 0.31.13) beside 0.1: jobId accepts a pending job waiting out
  its backoff, and allWaiting brings every such job forward with a fresh
  attempt budget, each reported with from: failed | pending. An RTBF-batched
  job is held and never brought forward, whichever member names it — the
  batch window is what keeps a removal from being timed back to the request.
  An in-flight job is skipped as inFlight.

  The console moves to 0.2 and shows "Run waiting jobs now" under the queue
  tiles while any job is backing off; skip toasts name inFlight / held /
  notFound. Operator docs updated.

- **vtc-admin-ui**: Community rooms tab — create and run rooms the community owns ([#2152](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2152))

* feat(vtc-admin-ui): Community rooms tab — create and run rooms the community owns

  Data rooms gains a fourth tab, Community rooms (/rooms/community, one room at
  /rooms/community/<room DID>), shown to holders of vtc.rooms.manage — the
  owner's authority, distinct from hosting's vtc.rooms.admin. Everything goes
  through the signed Trust Task door as vtc/rooms/community/*/0.1; no REST route.

  - List: label, tier, lifecycle, admitted / offered counts, and when the
    community's own authority over each room lapses (flagged 30 days ahead).
    When [rooms.community] is absent, the tab shows the section to add from the
    list's ext["org.openvtc"].communityRooms.
  - New community room: label, tier (attributed by default; private shown but
    not offered), history, retention, storage location (for vtc.rooms.admin
    holders) and a reason.
  - A room's page: its facts and members, filtered by state. Add a member makes
    an offer (actions, days valid, reason); Remove / Withdraw says what removal
    does on the tier and the member's validUntil before anything is signed
    (members/remove producer item 1) and reports validUntil and epoch from the
    answer (item 2).

  create, members/add and members/remove use postSignedWithStepUp: the VTC's
  operation-bound step-up (passkey or step-up approver), then the identical
  document again. Refusals carry the fix (noKeyHolder, visibilityNotPermitted,
  notAMember, alreadyMember, keyHolderUnavailable with the minted DID, missing
  vtc.rooms.manage).

  The generated shapes reach the console through vta_sdk::openapi wrappers for
  the vtc/rooms/community payloads and responses, registered in the VTC's
  OpenAPI document (snapshot and wire.ts regenerated). The two listings are
  pinned in list-limits.json.

  The pages poll once a minute: the live channel's rooms topic hints on a
  create (a room registered) but carries no offer, admission or removal, and
  goes only to vtc.rooms.admin holders — a specification gap, recorded in
  community-rooms.md rather than hinted outside event 0.2 producer rule 4.

- **vtc**: Hidden-vetting publish and withdraw park for administrators' consent (VTI-APV-023) ([#2151](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2151))

Hidden vetting is a way of meeting a join criterion: turning it on lets an
  applicant prove vetting without naming the vetters, and turning it off takes
  that route away. Under VTI-APV-023 (dtgwg-vti-spec#66, now explicit about
  it) that is a change to the criteria, and #2149 left vtc/vetting/hidden/
  {publish,withdraw} ungated.

  - Both tasks now settle consent right before they write the criterion, after
    every refusal of their own: the requester's bound gesture, then parked as
    Act::ChangeHiddenVetting (kind join.criteria.hiddenVetting) for the other
    holders of vtc.vetting.manage; the N-th approval re-runs the task against
    the criterion as it is then (VTI-APV-017), pinned to the stored criterion.
  - A sibling of Act::ChangeJoinCriteria rather than the same act: the tasks
    are vtc.vetting.manage's, not vtc.surface.admin's, so the approvers and the
    requester's re-check at execution follow the capability that makes the
    change. The pin and the requirement are shared.
  - A publish that leaves the stored parameters exactly as they are, and a
    withdrawal from a criterion with nothing to withdraw, ask nothing. An event
    approval is still recorded in the requester's name; the second
    administrator consents to it.
  - Single-administrator mode waives it on the bound gesture, audited Critical.
  - Two pinned summary templates (server and console, shared vectors); the
    console's hidden-vetting section asks for the gesture and shows a parked
    change as sent for approval.

- **witness**: Witness 0.2 — the member presentation and personhood outcome evidence as spec members, and vta/witness/list ([#1068](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1068)) ([#2147](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2147))

* feat(witness)!: witness 0.2 — the member presentation and personhood outcome evidence as spec members ([#1068](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1068))

- **vtc**: Join criteria and personhood policy changes park for administrators' consent (VTI-APV-023) ([#2149](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2149))

Who may become a member, what evidence counts and who is recognised as a
  person are the inputs every membership decision follows from. #2140 put the
  trusted-witness list behind a second administrator; the join criteria and the
  personhood policy it feeds were still one administrator's to change alone.
  VTI-APV-023 (dtgwg-vti-spec#66) recommends second-party consent for all three.

  - vtc/schemas/accepts/register and /delete park as Act::ChangeJoinCriteria
    (kind join.criteria.change) for the other holders of vtc.surface.admin, after
    the requester's operation-bound gesture. Every change parks: a new criterion,
    any changed requirement, admission mode or description, and a removal. A
    re-save of a criterion exactly as stored is no change, and a write the
    handler refuses (invalidQuery, notFound, ...) is refused before any gesture.
    The consent is pinned to the stored criterion, so another write to it voids
    the action; the N-th approval re-runs the handler (VTI-APV-017).
  - policy/upsert and policy/activate for the personhood purpose park as
    Act::ChangeRecognitionPolicy (kind policy.recognition.change) for the other
    holders of vtc.policy.admin @ policy:personhood.
  - Personhood is deliberately not added to PolicyPurpose::decides_authority:
    that predicate also makes vtc.policy.admin at the purpose
    authority-conferring (Capability::is_authority_conferring), which would turn
    granting or removing it into an APV-018/-019 act. Recognising a person
    confers no authority; what needs a second party is each change. A new
    decides_recognition predicate and requires_consent (= authority or
    recognition) drive the gate instead, and approvers are told the policy
    decides recognition, not authority.
  - Single-administrator mode (VTI-APV-022) waives both on the bound gesture,
    audited at Critical. Seeding default criteria at first boot is not gated.
  - Four new summary templates, pinned in the build and in the console, with
    shared vectors. The console's criteria editor and removal ask for the
    gesture and show a parked change as sent for approval.

  Hidden vetting's publish/withdraw, which write parameters onto a criterion
  through their own tasks, are not gated here.

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

- **vtc-admin-ui**: One Data rooms page — rooms, usage and storage as tabs ([#2144](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2144))

The console's Community group carried three entries for data rooms (Data
  rooms, Storage, Room usage). They are now one entry, Data rooms, with tabs
  Rooms · Usage · Storage, each a route so the open tab is in the URL:

    /rooms                     Rooms
    /rooms/usage               Usage
    /rooms/storage             Storage
    /rooms/storage/<configId>  one storage location
    /rooms/r/<roomId>          one room

  A room's page moved under r/: a room's identifier is whatever its owner
  minted — the rooms/create schema types roomId as a bare string and neither
  vti-rooms nor the VTC constrains it to a DID — so a bare /rooms/<roomId>
  could be /rooms/usage. Old links redirect: /rooms/<roomId> to
  /rooms/r/<roomId> (taken from the still-encoded path, so a did:web port's
  %3A survives), and the shell sends /storage[/<id>] and /room-usage to their
  tabs (lib/legacy-routes.ts) unless a plugin claims the old path.

  Each tab names its own capabilities (all vtc.rooms.admin today) and is shown
  only to a holder; a room's or a storage location's page is gated as its tab
  is. The menu entry is registered on the union of the tabs' capabilities, so
  a later Community rooms tab on vtc.rooms.manage is one entry in
  DATA_ROOMS_TABS and makes the menu visible to its holders without showing
  them the other tabs.

  The command palette finds Data rooms for "storage" and "usage", and offers
  two actions that open those tabs. Live updates are unchanged: the rooms
  topic still re-reads the ["rooms"], ["room-usage"] and ["storage"] queries.
  Docs updated (website-and-admin, data-rooms, quickstart, design note).

- **vtc**: Community-owned data rooms — the community's VTA as key holder (vtc/rooms/community/*, vtc/rooms/offers/*) ([#2141](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2141))

* feat(vtc): community-owned data rooms — vtc/rooms/community/* and vtc/rooms/offers/*, the community's VTA as key holder

  P13 of data-rooms-files.md §8.4 (trust-tasks-tf #768, trust-tasks-rs 0.31.2).
  The community owns and hosts the room; its own VTA mints the room's DID from
  the `room` template, founds the group, issues and vaults the community's own
  VMC + admin VAC, and issues members' VIC/VMC/VAC, over vta_link, signed as the
  VTC's DID (a persona the VTA holds in `[rooms.community] context`). The VTC
  holds no room key and never falls back to one (noKeyHolder).

  - vtc.rooms.manage capability (community-admin ceiling), distinct from
    vtc.rooms.admin.
  - Optional [rooms.community] (absent = off; the list answer says what to add).
  - community_rooms keyspace (backed up): the owner's record, never read on the
    host path (I5).
  - Remote first: create stores the room only after mint/group/credentials; an
    offer, an admission and a removal are recorded only after the VTA answered.
  - Creates, adds and removes take the requester's bound step-up and are
    audited (AuditEvent::CommunityRoomChanged); no Welcome, KeyPackage or
    credential is logged or audited.
  - Serverless room identities are served at /room-dids/<id>/did.jsonl.
  - rooms policy input gains room.communityOwned; the shipped default allows
    community-owned open/attributed rooms, and a VTC still on the earlier
    shipped default is upgraded at boot (an operator's own policy untouched).
  - Integration tests against a stand-in VTA signing real DTG credentials,
    including a record written and read on the host path with the offered
    credentials; every declared code witnessed in the error-code census.

- **vtc**: A trusted-witness list change parks for administrators' consent ([#1068](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1068)) ([#2140](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2140))

Which witnesses a community trusts decides whose attestations count as
  evidence there, for personhood and joining and for credentials members already
  hold. That is a major trust change, and VTI-CMP-090 asks that a configuration
  change to trust semantics attract the same review as a code change: for a
  community, another administrator's. Until now one holder of vtc.config.admin
  could change `witnesses.trusted` alone.

  Every runtime change to the list now goes through the action list, as
  lowering the consent threshold does (VTI-APV-020):

  - `config/patch` and the confirming `vtc/config/import` that add, remove or
    relabel a witness take the requester's operation-bound gesture, then park
    as `Act::ChangeTrustedWitnesses` (kind `config.witnesses.change`) for the
    other holders of vtc.config.admin, by approve scope. The requester never
    approves, one decline closes it, and the N-th approval runs the patch with
    every check re-run.
  - The consent is pinned to the list in force, so another change landing first
    voids the action.
  - Removal parks too: it can strip the evidence a member's personhood rests on.
    A reorder of the same entries is no change, and a value the write would
    refuse asks for no gesture.
  - In single-administrator mode (VTI-APV-022) the bound gesture stands in for
    the consent, audited at Critical, as every other waiver of the mode.
  - A write that both changes the list and lowers the threshold is refused with
    the two to send apart: one parked action is one consent.

  Approvers see the proposed list through a pinned summary template (patch and
  import), mirrored in the console's pin table with a shared vector; the
  action's summary text names the list it changes from. `config.toml` stays the
  host's, outside the action list like every other host-only setting.

- **vtc**: Direct admission on the generated vtc/members types (trust-tasks-rs 0.31.9) ([#2138](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2138))

* build(deps): trust-tasks-rs 0.31.9 — vtc/members/admit and make-membership (trust-tasks-tf #784)

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

- **vtc-member-portal**: Data rooms through the member's wallet (P8) ([#2133](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2133))

P8 — member-owned data rooms in the VTC member portal, through the wallet extension's page channel (P7b).

  **Depends on** (extension, merge first): OpenVTC/vta-browser-plugin#330 (file engine acts as the persona) → OpenVTC/vta-browser-plugin#331 (`window.vtaWallet.rooms`). Without them the portal shows a "your rooms are in your wallet" card; nothing breaks.

  ## Design (`docs/05-design-notes/data-rooms-files.md` §8.5)

  - **Pages**: `#/rooms` (rooms shared with this portal, *Share rooms…*), `#/rooms/<roomId>` (tier, epoch, member identity, room/member storage vs limits; records with sealed titles opened through the wallet; note as plain text; file download; add note / add file with limit checks before the wallet is asked).
  - **How room ops happen**: only via `window.vtaWallet.rooms.*`. The wallet fixes the verb, acts as the member's **persona** through their VTA (`rooms/keys/act`, `seal/0.2`), and returns views. `requestTask`/`signTrustTask` still refuse `rooms/*`.
  - **Allow-list**: the page's browser-attested origin must equal the origin of `hostDid`'s verified `SignInPortal`; host requests go to that document's `TrustTaskHTTPS`.
  - **Room scope**: a room's DID names no host and `rooms/keys/list` returns IDs only, so the **member shares rooms one by one** in the wallet's own window; each is confirmed with the host as the member; grants last 30 days, revocable in the extension. **A `private` room is never shared with a portal** (the portal is the host's own page).
  - **Consent**: reads ride the share; **every write is confirmed** (room, signing persona, what is written), no "remember".
  - **Never reaches the page**: keys (file, upload, wallet, persona), presentations, persona-signed documents, raw VTA/host replies, unshared rooms, unverified bodies or file bytes.
  - **Threat model**: compromised portal page (XSS / dependency / hostile VTC operator) — table in §8.5.
  - **Deferred**: owner flows (*Run a room*), curation, direct-to-storage transfer from the browser (extension holds no permission for the storage origin; browser transfers are proxied).

  No spec change: the page channel is a wallet API, and every Trust Task used (`rooms/keys/{act,seal/0.2,list,browse,read,file-key}`, `rooms/info`, `rooms/records/*`, `rooms/blobs/*/0.2`) already exists in trust-tasks-rs 0.31.x / @openvtc/trust-tasks 0.26.9.

  ## Portal invariants kept
  Separate bundle (imports only `./InstallWallet`, `./wallet-rooms`, lucide); no new `/v1/member/*` route; member session re-check unchanged; nothing about a room crosses the daemon. Root CLAUDE.md member-portal section gains the rule.

  ## Tests
  `src/members/Rooms.test.tsx`: no wallet → explains; list/share go to the wallet with the community DID and never `fetch`; a member's note body renders as text (an `<img onerror>` stays inert); adverse listing → banner; note → wallet; file-fit messages; download name sanitising; hash routing. Full `npx vitest run` (1044), `tsc -b --noEmit`, `wire:check`, `build:members` green locally.

- **vtc-admin-ui**: Wallet sign-in lets a known identity straight in ([#2132](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2132))

After a wallet approved a sign-in, the page always stopped at "Continue
  as <identity>?" and waited for a click, even when the same person signs
  in on the same browser every time.

  The question guards against someone else signing this browser in as
  themselves (login CSRF, T4 in the QR-login design), so it stays for any
  identity the browser does not know. Pressing Continue now remembers the
  subject in localStorage, per audience (member portal and operator console
  separately), and a later redeem for that same subject goes straight to
  onSignedIn. A different subject is always asked, and "Not me" on it
  leaves the remembered identity alone. Storage that is cleared, blocked or
  private only means the question is asked again.

  The test walks first sign-in (asked, remembered), the same identity again
  (not asked), and a different identity (asked; Not me keeps the first).

- **vtc**: Trusted witnesses — a VWC counts only from a listed witness, with its session's outcome evidence ([#1068](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1068)) ([#2128](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2128))

The VTC's half of P3 (docs/05-design-notes/witness-host-service.md §3.5).

  Until now any `witnessed/1` statement whose digest bound to a held edge was
  personhood evidence, whoever signed it, and the personhood route verifies no
  embedded credential proof — so anyone could mint a VWC that counted
  (VTI-CMP-030: verification is not authority).

  - `[witnesses] trusted` / runtime key `witnesses.trusted`: a list of
    `{ did, label? }`. Empty — the default — trusts no witness; a corrupt or
    unreadable stored list also trusts none. Patched through `config/patch` and
    `vtc/config/import` under `vtc.config.admin`, audited as `ConfigChanged` with
    both lists, read live. The community's own DID is refused (VTI-KEY-007).
    `ConfigKeyDef` gains `trust_semantics`, set on this key and the consent
    threshold, and logged on every change (VTI-CMP-090, VTI-CMP-092).
  - One host verdict per VWC, in a fixed order: `untrustedWitness`, then
    `noOutcomeEvidence` / `outcomeInvalid` (VTI-CMP-022/023: the session
    document and the witness's `submit#response`, paired by the framework's
    four checks plus VWC identity and `vwcDigestMultibase`), then the existing
    digest states. Every later state implies the earlier checks passed, so no
    policy can accept a VWC the host refused (VTI-VTC-022).
  - The evidence rides `vtc/members/personhood/assert/0.1`'s
    `ext["org.openvtc.witness"].outcomeEvidence` — the `evidence` that
    `vta/witness/accept` returns. The namespace is closed.
  - Join paths carry no evidence yet: a VWC there is `untrustedWitness` or
    `noOutcomeEvidence` and meets no criterion.

- **vta**: External/credentials/issue 0.3 — responseTooLarge, sized before the rate, and the VTC splits ([#2127](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2127))

* build(deps): trust-tasks-rs 0.31.8 — external/credentials/issue 0.3 (trust-tasks-tf #781)

- **rooms**: Direct uploads — rooms/blobs 0.2 straight to storage, presigned by the VTA (trust-tasks-tf #775) ([#2121](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2121))

* build(deps): trust-tasks-rs 0.31.5 floor — external/credentials/issue 0.2 (trust-tasks-tf #775)

- **rooms**: Rooms/blobs 0.2 — the single-use upload key, and reads straight from storage (trust-tasks-tf #771) ([#2108](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2108))

* build(deps): trust-tasks-rs 0.31.4 floor — rooms/blobs 0.2 and rooms/keys/act (trust-tasks-tf #771)

- **secrets**: Encrypted-at-rest file backend ([#1820](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1820)) ([#2101](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2101))

* feat(secrets)!: encrypted-at-rest file backend ([#1820](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1820))

  Add `encrypted_file` to vti-secrets: the secret is kept in one file under
  AES-256-GCM, keyed from an explicitly configured key-encryption key, so a
  headless host with no OS keychain has a secure local option instead of
  `plaintext`.

  KEK sources (`[secrets.encrypted_file] kek = { source = ... }`):
  - `passphrase`: Argon2id (m = 64 MiB, t = 3, p = 4; salt and parameters in
    the header, floors enforced on read), passphrase from a file or a systemd
    credential, never from the config or an environment variable;
  - `systemd_creds`: a 32-byte KEK from $CREDENTIALS_DIRECTORY, HKDF-SHA256;
  - `tpm` (feature `tpm`, Linux, tss-esapi 7.7): a random KEK sealed under the
    owner-hierarchy SRK, optionally bound to SHA-256 PCRs, stored sealed in the
    header, HKDF-SHA256.

  Envelope v1: magic, version, AEAD id, KEK source id, salt, nonce and a
  length-prefixed descriptor, all of it the AEAD's associated data. Fresh salt
  and nonce per write. Writes are atomic (0600 temp file via
  `secure_file::write_secret_file`, fsync, rename, directory fsync). Fails
  closed: only a missing file is "no secret"; a wrong key, any modified byte,
  an unknown version, a malformed header or a header from another KEK source
  is an error. Key material and passphrases are zeroized; no derived Debug
  holds a secret.

  Selection is explicit only, in both the VTA factory and the VTC's
  `create_secret_store` (`encrypted-file`): implicit resolution never picks it,
  and a `[secrets.encrypted_file]` table without the selector is a config
  error. The VTA setup TOML and interactive wizard offer it; vta-keys
  re-exports the store; vta-service, vta-keys and vtc-service gain a `tpm`
  feature.

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

- **vtc**: Console verifier-identity status — vtc/oid4vp/identities/list ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2080](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2080))

A verifier identity is assembled out of band — a key cached here or kept by
  the VTA, an EUDI access certificate, swiyu trust statements — and each part
  expires or breaks on its own schedule, while a wallet that refuses a request
  object tells the community nothing. The console's new Community → Wallet
  verifier page shows, per identity, the client_id wallets see, the DID and
  signing method, where the key is held, the access certificate's subject,
  issuer and validity, each verifier_info attestation with its expiry, whether
  it is the default, and whether a session could be opened on it now.

  vtc/oid4vp/identities/list/0.1 (trust-tasks-tf #761, trust-tasks-rs 0.31.1
  floor), for holders of vtc.config.admin. Problems use the specification's
  vocabulary with error/warning severity, each with the vtc oid4vp command that
  fixes it: keyCustodyInvalid, signerNotLoaded (installed after start),
  agentLinkMissing (VtaHeldSigner with no link — VerifierSigner::can_sign),
  certificateMissing / NotYetValid / Expired / ExpiresSoon (30 days),
  identityStatementMissing, statementExpired / ExpiresSoon; and community-wide
  noPublicUrl and defaultIdentityNotInstalled. isDefault mirrors wallet::start's
  choice. Never a private key, nor the key's id at the VTA.

- **vtc**: Console room detail and Room usage pages — limits, per-member usage, activity and CSV ([#2079](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2079))

P9 part 3a (docs/05-design-notes/data-rooms-files.md §8.1): the admin
  console's view of what the community stores for its rooms, over the
  vtc/rooms/{get,usage,limits/set}/0.1 tasks #2077 serves.

  - Room detail (/rooms/<roomId>, linked from each row of Data rooms): the
    room's facts; its storage, files still on earlier configs and files
    awaiting deletion; its ten largest files by size only; its limits with
    where each came from (override, rooms policy, community default);
    per-member usage on rooms that are not private (members who added nothing
    are not listed — the host never saw them, so it is no roster); daily
    activity over 30, 90 or 365 days. From it an administrator overrides the
    room's limits, its members' default or one member's, clears an override,
    or pauses and resumes uploads (filesEnabled alone, leaving every limit as
    it is). Each change takes a reason, which the audit trail records.
  - Room usage (/room-usage): the figures grouped by room, member, storage
    config or day; rooms and configs past 80, 95 or 100 percent of a limit or
    of capacity, listed first; CSV export of what is shown, with cells a
    spreadsheet would run as a formula prefixed (OWASP CSV injection).
  - Both pages need vtc.rooms.admin, as the room list now does. Neither shows
    a record title, a file name or a file's contents: the host has none.

  The response shapes are rendered from the specification
  (vta_sdk::openapi wrappers → admin-ui/openapi.json → wire.ts), not written
  by hand. Charts are hand-drawn SVG; the console has no chart library.

  A size field is pre-filled in the largest unit that states it exactly
  ("1 GiB", "1536 KB"), so re-saving a form changes nothing it was not asked
  to. The room identifier is taken from the route as the router decoded it:
  decoding it again would turn a did:web port's %3A into ':' and ask for a
  different room.

  Census updates: the list-limit census and its Rust counterpart gain
  vtc/rooms/usage (100), the sidebar census gains Room usage, and the console
  document-type manifest gains the three tasks.

- **vtc**: Swiyu issuer trust from the trust registry — [oid4vp.swiyu_trust] ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2076](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2076))

A swiyu credential's issuer is a `did:webvh` that the swiyu trust registry
  vouches for by publishing an Identity Trust Statement about it. Until now the
  VTC trusted such an issuer only as any DID issuer: under `credentialIssuers:
  any`, which admits every issuer whose credential verifies.

  With `[oid4vp.swiyu_trust]` (`registry_url`, `trust_anchor_did`) set, an issuer
  counts as one the community recognises when the registry serves a statement
  about it (`/api/v2/identity-trust-statement/{did}`) that:
  - is `swiyu-identity-trust-statement+jwt`;
  - is signed by a key of the configured trust anchor;
  - has the issuer's DID as `sub` and has not expired;
  - names a Token Status List, also signed by the anchor, whose entry is valid.
    A statement with no status list is refused.

  A `recognised` criterion then admits swiyu issuers and a `community` one still
  does not. No spec change: this is how the community decides whom it
  recognises.

  Like recognition through the community's own trust registry, the verdict is
  never cached, so a withdrawn statement stops counting at the next
  presentation. The fetch uses the shared foreign-fetch client: SSRF-guarded,
  redirects off, body capped. An `http` registry or an anchor that is not a DID
  stops the VTC at boot.

  Not done yet: the protected-issuance and non-compliance trust lists, and the
  per-type scope of a statement.

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

- **vtc**: Swiyu trust statements in verifier_info — vtc oid4vp trust-statement ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2072](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2072))

Under swiyu Trust Protocol 2.0 a verifier tells the wallet who it is by
  carrying the statements the trust registry issued about it in every request
  object's `verifier_info`, each `{"format": "jwt", "data": <JWS>}`, the
  Identity Trust Statement first (the generic test wallet reads it by position).

  - `vtc oid4vp trust-statement --identity <id> --file <jwt>…` installs them on a
    swiyu identity. Each is checked first: a swiyu `typ`, `sub` equal to the
    identity's DID, not expired; one bad file installs none. A newer identity
    statement replaces the held one; protected-verification statements are told
    apart by `jti`. The wallet verifies the signature against the registry.
  - A session's request object leaves out a statement that has expired, with a
    warning naming the command, rather than sending one every wallet refuses.
  - `vtc oid4vp list` shows each statement's expiry, and says when a swiyu
    identity has no current identity statement.
  - A Verification Query Public Statement is refused for now: it describes one
    query and pairs with `scope`, where the VTC sends each criterion's DCQL.

- **vtc**: DCQL trusted_authorities held at the response, not only published ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2067](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2067))

A criterion's credential query may carry `trusted_authorities` (OpenID4VP 1.0
  §6.1.1). The wallet uses it to choose a credential; the verifier still has to
  check it, and the DCQL matcher does not read it. Until now the VTC published it
  and ignored it.

  - `vta_sdk::x509_issuer::x5c_issuer` returns, beside the issuer key, the key
    identifiers of the authorities certifying it: each certificate's AKI, the SKI
    of every certificate above the leaf, and that of the anchor reached.
  - `aki` is held on both paths: a wallet response whose credential no named
    authority certifies is refused `issuerNotTrusted`, and the join criterion
    match rewrites a gated query to keys only such a credential offers. A DID
    issuer has no chain and meets no such query. The anchors still decide trust;
    `trusted_authorities` only narrows them.
  - Registration refuses what cannot be held: `etsi_tl`, `openid_federation`,
    `trusted_authorities` on a non-`dc+sd-jwt` query, an empty list, or an `aki`
    value that is not base64url.

- **vtc**: Room files in S3 through the community's VTA — one presigned request per object, no storage credential held ([#2063](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2063))

A storage config of kind `s3` with `auth: {mode: vta-account, context,
  account}` (vtc/_shared/0.1 room-storage, dtgwg-trust-tasks-tf#758) keeps
  room files in a bucket whose credential only the community's VTA holds.
  For each object operation the VTC asks its VTA for one presigned request
  (`external/credentials/issue/0.1` against an `s3-static-presign` account):
  one action on one object, prefix `<config prefix>rooms/<hash>/`, for 300
  seconds. The VTA checks the binding, `external-auth-use`, the account's
  state, the scope against its ceiling, the TTL and the rate, audits the
  issuance, and seals the request to this community's X25519 key inside a
  `#response` whose proof is verified as the VTA's before it is read.

  The VTA is reached over the VTC's existing messaging socket (TSP >
  DIDComm, by the VTA's advertised services), so the VTA needs no inbound
  address for this, and the community holds no storage secret at rest.

  - vti-common: `blob_store::presigned` (feature `blob-presigned`) — a
    `BlobStore` over a `Presigner`. Each request is checked before use
    (https, the asked method, a path ending in the object's key); no
    redirects; GETs are reused until shortly before they expire; a put
    streams with Content-Length; a ranged get checks the length returned.
  - vtc-service: one link to the VTA. `vta_link::VtaLink` (#2060's
    `keys/sign-jws` link) now runs on `outbound::PeerTasks`, the
    sign/send/await-verified-reply exchange the git bridge also uses, and
    `rooms::vta_storage::VtaStorage` issues storage credentials over it.
  - storage configs: create/update ask the VTA about the account (a canary
    read under `<prefix>probe/`) and refuse `unknownAccount`, or name the
    member at fault for a scope or TTL the binding cannot cover; the probe
    authenticates through the store's own health check; `credentialState`
    carries the context.
  - Docs: `docs/02-vta/data-rooms.md` setup at the VTA;
    `data-rooms-files.md` P4b.

- **vtc**: Verifier identities whose key the VTA keeps — request objects signed through keys/sign-jws ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2060](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2060))

Custody B, VTC side. A verifier identity can now name a key the VTA keeps
  instead of caching it: every OpenID4VP request object is signed by the VTA
  through keys/sign-jws ([#2057](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2057)), and the VTC holds no private key.

  - VerifierSigner signs a whole JWS (header members + claims) rather than a
    signing input, since keys/sign-jws builds the input at the VTA. The signer
    sets alg; a caller's alg is refused. LocalP256Signer is unchanged in effect.
  - VtaHeldSigner sends keys/sign-jws over a late-bound link and verifies each
    returned JWS under the identity's recorded public key before a wallet sees
    it (the spec's producer SHOULD).
  - vta_link::VtaLink: the VTC's runtime link to its VTA (vta_did), TSP >
    DIDComm by the VTA's advertised service types on the existing mediator
    socket, documents signed with the operational key, replies accepted only
    when their proof verifies as the VTA (PendingReplies). No REST arm. One
    attempt per call; the session start owns the retry.
  - VerifierIdentityRecord: privateKeyMultibase is optional and vtaKeyId new;
    exactly one must be present (KeyCustody). Records written before still read.
  - vtc oid4vp attach records a VTA-held identity (swiyu with --did/--kid, EUDI
    without) from the VTA key id and its P-256 public key, and prints the
    pnm acl grant (sign-jws) and, for EUDI, the pnm keys sign-csr step;
    vtc oid4vp csr points a VTA-held identity there; list shows where each key
    is held.
  - Boot refuses a VTA-held identity without vta_did, vtc_did, the signing key
    or a resolver, naming the identities.

- **vta**: The VTA as hidden-vetting (PCS) engine — vta/pcs/* for clients that cannot run PCS ([#2056](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2056))

* feat(vta)!: the VTA as hidden-vetting (PCS) engine — vta/pcs/* for clients that cannot run PCS

  A community that runs hidden vetting admits an applicant on a zero-knowledge
  proof that distinct eligible vetters vetted them. Every vetter and applicant
  holds a PCS secret key, and until now the member side ran only in a client
  linking the PCS library, so a mobile wallet (Keyring) could not take part.

  The VTA now holds those keys and runs every member-side operation (design
  vetting-hidden-vetters-pcs.md §13 C7); the client carries messages and never
  holds a key. Twelve Trust Tasks (trust-tasks-tf #756):

  - applicant: applications/{create,show,delete}, verify-attestation, prove
  - vetter: root-request, root-accept, tokens/{request,accept,abandon}, attest,
    vetter/show

- **vtc**: Credential issuers known by an X.509 chain — x5c trust anchors for EUDI PID and Rulebook credentials ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2053](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2053))

An EUDI credential (the PID, or one a Rulebook governs) is issued by an https
  URL whose JWS names its key by an x5c chain, not by a DID. The VTC now trusts
  such an issuer only through operator-configured anchors, never by the chain
  alone.

  vta-sdk (feature `x509-issuers`): `x509_issuer` — `X509TrustAnchors`,
  `x5c_issuer_key` (validity, CA flags, chain signatures, ends at an anchor or a
  certificate an anchor signed, leaf key usage, leaf SAN URI = iss or dNSName =
  its host; P-256, secp256k1, Ed25519) and `issuer_jws_key`. Token Status Lists
  signed the same way verify through
  `verify_status_list_token_with_anchors` / `resolve_token_status_with_anchors`.

- **vtc**: Storage configs — where a community keeps its rooms' files, changed only with consent ([#2052](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2052))

Phase P4 (first part) of docs/05-design-notes/data-rooms-files.md §7.

- **vtc**: EUDI verifier identity — x509_hash, access-certificate CSR and chain, pnm keys bundle-key ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2050](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2050))

A VTC can now present itself to EUDI wallets as well as swiyu ones. An EUDI
  wallet identifies a relying party by its X.509 access certificate, not a DID:
  client_id is x509_hash:<SHA-256 of the certificate> and the request object
  carries the chain as x5c.

  - pnm keys bundle-key <key-id>: seals one P-256 key that no DID publishes
    (SealedPayloadV1::RawPrivateKey) to a recipient. The VTA audits the export
    (keys/export-secret/0.1); the key leaves the CLI only sealed.
  - vtc oid4vp install accepts that bundle as an EUDI identity (VerifierKind::
    Eudi; did/kid are now optional on the record, which still reads stored
    swiyu records).
  - vtc oid4vp csr writes a PKCS#10 request signed by the identity's own key
    (rcgen, no crypto backend; the signature is DER-encoded from ES256 r||s).
  - vtc oid4vp certificate installs the issued chain: the leaf must certify the
    identity's key, be valid now and allow digitalSignature; each certificate
    must be signed by the next; a lone self-signed certificate is refused and a
    trailing self-signed root is left out of x5c. An optional registration
    certificate goes into every request's verifier_info, its format named by
    the operator.
  - Wallet sessions: an EUDI identity signs with x5c (no kid, no swiyu
    profile_version), offers A128GCM and A256GCM, invokes haip-vp://, and opens
    no session until its certificate is installed (verifierNotConfigured).

  Not yet: issuers named by an x5c chain to a configured trust anchor; today an
  issuer is still accepted only by DID.

- **vtc**: Wallet evidence decides the join — on the named request, or the next submission ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2047](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2047))

A wallet session's verified presentation ([#2044](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2044)) was recorded on the session
  and read by no decision. It now counts, as `wallet-session/start/0.1` consumer
  rule 11 says, toward the criterion the session was opened for and no other:

  - With `requestId`: the evidence is recorded on that request (`join_wallet:`
    beside it, like the criterion and vetting records, deleted with it). A
    `deferred` request is decided again at once — its own presentation plus
    every wallet evidence on it, under the criterion it was decided under, the
    path a supplement takes (`orchestrate::redecide`, now shared). A `pending`
    request is recorded for its reviewer and not decided underneath them. A
    decided or withdrawn one takes nothing.
  - Without: the evidence is held for the applicant's next submission until the
    session's `heldUntil`. A submission decided under that criterion counts it,
    binds the session to the new request (the status task then reports
    `requestId`, no `heldUntil`) and records the evidence there. Held evidence
    for other criteria stays held.

- **vtc**: OpenID4VP wallet sessions — swiyu wallets present evidence for a join ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2044](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2044))

A swiyu wallet speaks OpenID4VP 1.0 over HTTPS and signs no Trust Task, so the
  applicant's own agent opens the exchange for it. The VTC now serves the whole
  round trip against an installed verifier identity ([#2039](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2039)).

  - `vtc/join-requests/wallet-session/start/0.1`: the proof signer opens a
    session for a criterion named by its `requirementsDigest` (and optionally
    their own join request). The VTC signs an ES256 request object as a JAR in
    swiyu's profile (`profile_version`, `aud` https://self-issued.me/v2,
    `client_id` `decentralized_identifier:<did>`), asking for the criterion's
    published DCQL query unchanged, with a fresh nonce, `state` and P-256
    response key, and returns the `swiyu-verify://` wallet URI. Every declared
    code is served: criterionNotFound, noWalletPresentation,
    verifierNotConfigured, requestNotFound (unknown and somebody else's alike),
    requestClosed, tooManySessions.
  - `GET /v1/oid4vp/request/{session}` answers the request object once;
    `POST /v1/oid4vp/response/{session}` accepts one `direct_post.jwt` answer.
    It is checked in order: decrypts (A256GCM) under the session key and echoes
    `state`; each presentation's issuer signature, validity and KB-JWT over the
    session nonce with the prefixed `client_id` as audience (VTI-CRD-020…022),
    one holder; status valid, never assumed (VTI-CRD-014); every issuer admitted
    by the criterion's `credentialIssuers`; the query satisfied
    (`DcqlQuery::evaluate_presentation`). Both are a declared foreign-protocol
    exception (VTI-OPS-095): REST_EXCEPTIONS and GOVERNED_UNAUTH rows, behind the
    unauthenticated governor; the response reads its body against
    `[oid4vp] max_response_bytes`.
  - `vtc/join-requests/wallet-session/status/0.1`: only the signer who opened a
    session reads it; the evidence names the wallet's holder key beside the
    applicant and each credential's query id, format, issuer and vct, never a
    claim value; a refusal names its reason.
  - New keyspace `oid4vp_sessions`, encrypted at rest, excluded from backup. A
    minute sweeper closes unanswered sessions at `expiresAt` (dropping the
    response key) and drops records an hour after closing, or when held evidence
    lapses. State changes run under one lock, so one response wins.
  - `[oid4vp]` config: session TTL, open sessions per applicant, evidence hold,
    response cap, default identity, wallet URI scheme.
  - Workspace floors: affinidi-openid4vp 0.1.4 (`direct-post-jwt`),
    affinidi-oid4vc-core 0.1.10 (`jwe`), affinidi-sd-jwt 0.1.7;
    trust-tasks-rs 0.28.1 for the wallet-session specs.

  Evidence is recorded on the session. Deciding a join on it — on the named
  request, or on the applicant's next submission — follows. P3 of
  docs/05-design-notes/oid4vp-wallet-verifier.md; docs/03-vtc/oid4vp-verifier.md
  covers operating it.

- SignInPortal in did-host-http* templates and a VTC DID self-check for wallet sign-in ([#2042](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2042))

* feat(vta-sdk): advertise SignInPortal from the did-host-http* templates

  Wallet sign-in with a trigger link (auth/oob, contract C4/C9) needs the
  service's DID document to list SignInPortal on the origin of its login
  page. DID hosting publishes <origin>/login for itself, but a node minted
  from a did-host-http* template lacked the entry, so wallets refused its
  sign-in links with "This code can't be used" (webvh.storm.ws).

  did-host-http, did-host-http-tsp and did-host-http-didcomm now declare
  SERVICE_SIGN_IN_PORTAL (null default, bare service member). When a
  template declares it and the caller does not supply it, the renderer
  derives { id: <did>#sign-in-portal, type: SignInPortal,
  serviceEndpoint: <origin of URL>/login } from URL, https only. A caller
  may supply its own entry or null to omit it. Templates for nodes with no
  login page (did-host-didcomm, did-host-tsp, didcomm-mediator) are
  unchanged. Existing DIDs are untouched; the doc explains adding the
  entry with pnm did-mgmt dids edit.

  New public helpers: sign_in_portal_endpoint, sign_in_portal_service,
  SIGN_IN_PORTAL_SERVICE_TYPE, SIGN_IN_PORTAL_SERVICE_VAR.

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

- **vtc**: OpenID4VP verifier identities — a sealed key hand-off and a separate ES256 signer ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2039](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2039))

A swiyu wallet presents only to a verifier whose request object is signed by a
  P-256 key of a DID in the swiyu Base Registry. That identity is not the
  community's DID, and its key must not join the credential signer — every key
  there puts a proof on every credential the community issues. The VTC keeps no
  VTA credential after setup, so the key reaches it by a hand-off the operator
  relays, the way other secrets move between these tools.

  - `vtc oid4vp request --identity <id>` (offline) writes a sealed-transfer
    request and keeps its private half, with the nonce the bundle must carry,
    in the data directory (0600).
  - On the admin workstation: `pnm did-mgmt dids create --template
    swiyu-verifier --did-url <swiyu slot URL> --context <ctx>`, upload the
    printed log to the slot, then `pnm keys bundle <ctx> --recipient
    request.json`.
  - `vtc oid4vp install --identity <id> --bundle <file> --digest <hex>`
    (offline) opens the bundle — the request's key, the out-of-band digest, the
    request's nonce — takes the DID's P-256 key (`--kid` when there is more than
    one), checks it is a verification method of the bundle's DID and that its
    private half is the published key, and stores it.
  - New keyspace `oid4vp_keys`, encrypted under the storage key like `install`
    and `passkey`, and backed up (a restore of the same key bundle reproduces
    the key that decrypts it). `server::offline_storage_key` derives that key
    for offline writers exactly as the daemon does.
  - `crate::oid4vp::VerifierSigner`: the signer request objects will be signed
    with — `LocalP256Signer` (ES256, r||s) now, a VTA-held key through
    `keys/sign-jws` later. Loaded at boot into `AppState::oid4vp_signers`; a
    record that does not load fails the boot.
  - `vtc oid4vp list` / `remove`.

  docs/03-vtc/oid4vp-verifier.md walks the steps. P2 of
  docs/05-design-notes/oid4vp-wallet-verifier.md; the wallet-facing endpoints
  (P3) and EUDI's X.509 identity follow.

- **vtc**: Local GeoIP for the wallet sign-in requester location ([#2027](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2027))

Wallet sign-in (`auth/oob`) shows the approver where the request came
  from as `requester.location`. The hook was a stub, so every location was
  "unknown". It now reads a local MaxMind DB (`.mmdb`) file — DB-IP "IP to
  City Lite" (CC BY 4.0) or MaxMind GeoLite2 City — and never makes a
  third-party call (base design §12.6).

  - `[geoip] database = "<path>"`, or `VTC_GEOIP_DATABASE` (empty turns it
    off). Unset keeps today's behaviour. A missing or invalid file is a
    startup warning, not a boot failure: location is advisory.
  - Output is "City, CC", or the country name when the record has no city,
    capped at the schema's 128 characters. Private, loopback, link-local,
    CGNAT, unique-local, documentation, benchmarking, multicast and
    reserved addresses are never looked up.
  - The file is checked once a minute (mtime + size) and re-read when it
    changes, then swapped in behind an `RwLock<Arc<Reader>>`, so a monthly
    refresh needs no restart. A replacement that cannot be read keeps the
    database already loaded.
  - The handle lives on `AppState` (`state.geoip`); `oob::locate` is gone.
    Addresses are never logged — warnings name the path and error only.

  Adds `maxminddb` 0.32 (ISC, no default features — no mmap). Tests build
  their databases with a minimal in-test MMDB writer, so no fixture file.
  Operator guide: docs/03-vtc/geoip.md.

- **admin-ui**: Console redesign phase 3 — dashboard, Actions, Members, ACL, ⌘K palette and theme switcher ([#2025](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2025))

* feat(admin-ui): a Switch component for on/off settings

  A native checkbox with role="switch" under a drawn track, so the label
  click, Space, focus and form behaviour are the checkbox's own and screen
  readers announce it as a switch. The off track uses the faint text grey
  so it meets 3:1 against the page in both themes.

  Adopted where a control is one setting that is on or off: automatic
  vetter naming, the criterion editor's five switches (already
  role="switch", now drawn as one), join discovery, the audit trail's
  "Show system events" and the ACL form's "May approve others' actions".
  Multi-select lists (capabilities, vetting methods, role ceilings) and
  consent ticks stay checkboxes.

- **rooms**: Room files on the host — blob store, uploads, downloads and limits ([#2018](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2018))

* feat(common): a BlobStore for room files, with local-directory, S3 and GCS backends

  Room files are a record plus a blob; the blob is the file's ciphertext, held outside the room's keyspaces. vti_common::blob_store is node-neutral, beside backup_transfer, so a standalone room host and a community share one store and one conformance suite (data-rooms-files.md §5.3).

  - BlobStore: put (idempotent on the key), get_range, delete (Deleted | Lapses | Unsupported), health.
  - LocalDirStore: plain files, written via a synced temp file and renamed, owner-only. Always compiled.
  - ObjectStoreBlobs over object_store 0.14: S3-compatible (feature blob-s3) and GCS (feature blob-gcs), credentials from the environment for now. object_store passes cargo deny (advisories, bans, licences, sources).
  - Keys are rooms/<first 32 hex of SHA-256(roomId)>/<blobRef>: the store never learns a room's identifier, and the per-room prefix is what a downscoped credential will name.
  - blob_ref_of_manifest: the BlobRef is the sha2-256 DigestMultibase of the manifest's JCS form, computed by the host.
  - conformance::run, which every backend's own test calls.

- P-256 and secp256k1 members — Trust Task proofs, rotation and OID4VCI key binding ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2021](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2021))

#2010 accepted P-256 and secp256k1 for credentials others issue. A member
  holding such a key — a secure-enclave or EUDI-wallet key, `did:key:zDn…` /
  `did:key:zQ3s…` — still could not sign as one: the SDK signed Trust Tasks
  Ed25519 only, and the VTC's hex holder signatures and OID4VCI key-binding
  proof read every key as Ed25519. Every one of these now goes through
  `vta_sdk::jws::JwsKey`, so the key decides the algorithm and nothing in the
  request can choose one.

  - Trust Task proofs: the shared verifier already accepted `ecdsa-jcs-2019`
    (P-256) once phase 1 taught the VM resolver P-256 keys; a test now holds
    it. `trust_task_sign` signs `ecdsa-jcs-2019` for a P-256 holder — a private
    multibase with the `p256-priv` prefix, or a bare one beside a
    `did:key:zDn…`. The Trust Tasks framework has every consumer SHOULD-verify
    that suite, for hardware-backed signers. There is no secp256k1 Data
    Integrity suite, so a secp256k1 key signs no Trust Task.
  - `vtc/members/rotate`: the old and new signatures (hex, 64 bytes) may be
    EdDSA, ES256 or ES256K by the key that made them; ECDSA is `r || s` over
    the SHA-256 of the canonical bytes, as JWS encodes it. The `did:webvh` path
    resolves `#key-0` through `TrustTaskVmResolver` (bound to authentication,
    VTI-KEY-022, with the cached-document refresh, VTI-KEY-134) instead of
    reading Ed25519 bytes off the document. Join's REST holder binding shares
    the same verifier.
  - OID4VCI key-binding proof: `EdDSA`, `ES256` or `ES256K`, whichever the
    `kid`'s key signs; a header naming another is refused before the
    signature. `DidVmResolver::resolve_verifying_key` (Ed25519) becomes
    `resolve_jws_key`.
  - `vta_sdk::jws`: `JwsKey::from_did_key`, and `verify_signature` is public
    for signatures that are not a JWS.

  What the workspace mints, and every key `sealed_transfer` seals to, stays
  Ed25519 / X25519: the VTA's sealed credential delivery (`seal_issued_credential`)
  still needs an Ed25519 `did:key` holder, and a sign-in `sessionKey` is still
  Ed25519. Accepting more algorithms widens what VTI-KEY-013 (retirable
  algorithms) would have to retire; that requirement is already an open
  divergence in the specification's register.

- **vtc**: Add a member and make an ACL entry a membership, governed by an admission policy ([#2022](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2022))

* feat(vtc): add a member and make an ACL entry a membership, governed by an admission policy

  Add vtc/members/admit/0.1 (admit a DID directly, without a join request)
  and vtc/members/make-membership/0.1 (give an ACL entry with no member
  record - the bootstrap administrator - the member record and membership
  credentials, leaving the entry untouched). Both are decided by a new
  ceremony purpose, admission (vtc.admission): allow admits, deny refuses,
  refer parks the operation in the action list (Act::DirectAdmission) for
  another holder of vtc.members.manage (VTI-APV-015, VTI-APV-017). Roles
  beyond member take vtc.roles.assign and are bounded by the actor's own
  entry (VTI-ACL-071); admin is never seated this way (VTI-APV-018).

  Wire types are local until the specifications are published; the spine
  enforces their document policy through a local SpecPolicy. ACL entries
  gain ext.org.openvtc.membership so the console can offer the action.
  Audited as MemberAdmittedDirectly. The console gains Add a member and
  Make this a membership. Wallet sign-in declines are now logged with their
  reason and request id; the wire answer stays notAuthorized (T15).

- **vtc**: Wallet sign-in by trigger link on the operator console's login page ([#2014](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2014))

* feat(vtc): wallet sign-in by trigger link on the operator console's login page

  The console's login page (`/admin/`) gets the `auth/oob/*` key-grant
  sign-in the member portal has, and is rebuilt on the community's sign-in
  look, with a way back to the community's home page.

- Read IETF Token Status Lists for SD-JWT VCs, signed by the credential's issuer ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2015](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2015))

An SD-JWT VC from the swiyu stack or an EUDI issuer names its status as
  `status.status_list = { idx, uri }`, a `statuslist+jwt`. The VTC fed that
  reference to the W3C Bitstring fetcher, which could never read it (Unknown at
  every join), and the vault held such credentials Unknown for good. Both now
  read it, through affinidi-status-list 0.1.7's `token` module.

  - `vta_sdk::token_status_list` (new): `verify_status_list_token` and
    `resolve_token_status`. A list decides revocation, so it is trusted only as
    the credential issuer's: the token's `kid` must name one of that issuer's
    `assertionMethod` keys (`sd_jwt_issuer_method`), the signature is checked
    with that key's algorithm (`JwsKey`) before the payload is read, and an
    `iss` naming anyone else is refused. `typ`, `sub` = the referenced `uri`,
    `iat` and `exp` are checked by the TDK, and the list is decompressed under
    a cap. The fetch is SSRF-guarded, takes no redirects and caps the body. A
    separate Status Issuer linked by certificate chain (draft §13.5) is not
    supported; its lists are refused.
  - `vta-vault`: `StatusListResolver::resolve_token_status` (a defaulted method,
    so existing resolvers compile and refuse) is implemented by
    `HttpStatusListResolver`. `refresh_status`, which the present gate runs
    first, takes the Token path when a credential carries `status.status_list`
    and no W3C `credentialStatus`: `INVALID` → `Revoked` (terminal),
    `SUSPENDED` → `Revoked` tagged `tokenStatus:suspended` so a later `VALID`
    restores it, an application-specific or unregistered value → `Unknown`
    (VTI-CRD-012). Receive still stores such a credential `Unknown`: its status
    has not been read until that refresh.
  - `vtc-service`: `StatusListFetcher::check_token_status`, implemented by the
    verifying `HttpStatusListFetcher`. `resolve_presented_status` (join, join
    criteria, invitations) maps `VALID` / `INVALID` / `SUSPENDED` to Valid /
    Revoked / Suspended, and anything unreadable to Unknown for the join policy.
  - `affinidi-status-list` 0.1.3 → 0.1.7. `docs/03-vtc/credentials.md` gains
    *Reading another issuer's status*.

- **vtc**: Shared console components on every screen, and styles.css split by area ([#2013](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2013))

* refactor(vtc): split the console stylesheet by area

  styles.css (4,500 lines) becomes styles/index.css importing, in cascade
  order, tokens.css, base.css, shell.css, components.css, pages.css and one
  file per plugin (ceremonies, vetting, policy-flow, repos, actions, members,
  recognition). Rules move with their comments and keep their order within
  each area. The few generic rules that sat inside a plugin's section (form
  hints and errors, the switch and colour fields, a.button, the banners the
  attention strip holds, the nav badge) move to components.css or shell.css;
  each is a single-purpose selector that no plugin rule overrides at equal
  specificity.

  Checked by screenshotting every built-in screen in light and dark before
  and after the split: all 40 are pixel-identical.

- **vtc**: Shared design tokens and the operator console shell ([#2012](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2012))

Phase 1 of the operator console redesign: the console, the member portal and
  the home page share one token file and one typeface, and the console gets a
  frame that says which community it runs.

  Tokens and type
  - `admin-ui/src/styles/tokens.css` is the one token file: indigo brand
    (500 #5b5bd6 light, 400 #7c7ce8 dark, violet accent), the semantic and
    verdict colours (allow/deny/refer/more unchanged), grey ramp, type, spacing,
    control and row heights, radius, motion and elevation, light and dark. The
    console and the portal import it; the static home page carries a
    byte-identical copy (`website-default/tokens.css`), pinned by a test in
    `website/default_site.rs`.
  - IBM Plex Sans and Plex Mono everywhere, self-hosted: the console and portal
    from the @fontsource packages the console already bundled, the home page
    from woff2 copies under `website-default/fonts/` (OFL 1.1). Fraunces is
    dropped, and its package with it — nothing else used it.
  - A community accent (the Branding card's accent colour) overrides `--brand`
    via `:root[data-community-accent]`, with a legible foreground chosen by
    contrast and a lifted variant for dark mode.

  Shell
  - A top bar with the community's mark and name from the public profile, an
    "Operator console" pill, the live indicator and an account menu.
  - The account menu holds My passkeys and Signing keys (routes unchanged),
    the theme switcher and Sign out.
  - The sidebar is grouped: Overview, Membership, Governance, Community, then
    More. Ceremonies is labelled Policies and Community profile is labelled
    Profile; their routes are unchanged. A group the viewer can see nothing in
    is hidden. The collapsed rail (same localStorage key) and the mobile
    slide-over stay.
  - One attention strip replaces the stacked banners: most severe first, a
    count and a Show-more control. Critical items (operator writes,
    cooling-offs, break-glass and its cannot-check variant) and
    single-administrator mode (VTI-APV-022) are always visible and cannot be
    dismissed; the signing-key expiry item moves here with its Renew link; the
    actions-waiting item stays dismissible for the session. Every message keeps
    its wording, links and role.

  Plugin API (additive)
  - `registerPlugin` takes an optional `group` (`overview` | `membership` |
    `governance` | `community` | `account`). Built-ins set it. A plugin without
    one, or with an unknown value, is listed under "More"; `window.VtcPluginApi`
    and custom-element plugins are unchanged.

- Verify ES256 / ES256K SD-JWT-VCs from did:web and did:webvh issuers ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2010](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2010))

Credentials issued on the swiyu stack and the EUDI profiles could not be
  received or verified: the vault and the VTC verifier accepted only EdDSA,
  the vault only a `did:key` issuer, the shared resolver only a
  `publicKeyMultibase` key, and holder binding only an Ed25519 `cnf.jwk`.

  - `vta_sdk::jws` (new): compact-JWS verification over a resolved key —
    EdDSA, ES256 (P-256) and ES256K (secp256k1). The header's `alg` must be
    the one the resolved key's curve signs with, checked before the
    signature; `crit` is refused. `JwsKey::from_jwk` reads a `cnf.jwk`
    (refusing one that carries `d`), `did_key()` names a P-256 holder
    `did:key:zDn…` and a secp256k1 one `did:key:zQ3s…`.
    `sd_jwt_issuer_method` binds the issuer JWS `kid` to `iss`: a `did:key`
    issuer's own key whatever the fragment, any other DID must name its
    method with a DID-URL `kid` (VTI-CRD-002: the issuer is resolved, not
    guessed).
  - `TrustTaskVmResolver` reads a `publicKeyJwk` method (Ed25519, X25519,
    P-256, secp256k1) and a secp256k1 Multikey; PQC keys stay Multikey-only.
  - `vta-vault`: `receive_sd_jwt_vc` and `stored_claims` take the issuer
    resolver, so a `did:web` / `did:webvh` issuer resolves for
    `assertionMethod`. `receive` with `IssuerKey::None` resolves locally
    (`did:key` / `did:peer`); the VTA's issued-credential path passes its DID
    cache. A credential carrying an IETF `status.status_list` reference is
    stored `Unknown`, not `Valid`: no `statuslist+jwt` resolver exists yet, so
    its status cannot be read (VTI-CRD-012).
  - `vtc-service`: the SD-JWT-VC presentation verifier takes ES256 / ES256K
    issuers and P-256 / secp256k1 `cnf.jwk` holders.

- **vtc**: Member portal, with wallet sign-in by trigger link ([#2007](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2007))

* feat(vtc): a member portal at /members, and a home page that explains the community

  Members could not sign in anywhere: VTC sign-in admitted administrators only,
  and every session it minted read as an admin session. This adds a member
  portal as a separate application from the console, with the separation
  enforced by the daemon rather than by what each page shows.

  Member portal (`crate::member_portal`, `routes::member_portal`):
  - Only an active member signs in — a live ACL entry that is not expired,
    suspended or an `application` entry, plus a member record that has not been
    removed — checked at challenge (VTI-SES-006/007 via the shared handler), at
    authentication, on every refresh and on every request (VTI-SES-020..022).
  - Sign-in by the browser wallet (SIOPv2 at `<origin>/v1/member/wallet`) or a
    portal passkey only. A passkey is added from the portal after a wallet
    sign-in; adding or removing one requires a wallet-proven session (`amr`
    contains `did`). Audited as the new `MemberPasskeyChanged` event.
  - Tokens carry audience `VTC-member` (`JwtKeys::for_audience`), so console
    extractors refuse them and the portal refuses console tokens.
  - Sessions and passkeys live in their own keyspaces (`member_sessions`,
    `member_passkeys`, excluded from backup), so a member who is also an
    administrator cannot redeem a portal refresh token or passkey at the console.
  - Cookies `vtc_member_session` / `vtc_member_refresh` are `Path=/v1/member`;
    `vtc_member_csrf` is the portal's own double-submit value, and the CSRF gate
    picks the cookie pair by path.
  - The portal is its own Vite bundle (`vite.members.config.ts`), baked by
    build.rs into `$OUT_DIR/member-ui-dist` and served at `/members/`; it loads
    no console code. In subdomain mode it is served on the API host.
  - The sign-in page carries manual install steps for the VTA Wallet extension
    (OpenVTC/vta-browser-plugin).

  Default landing page: rebuilt around a visitor who does not know what a VTC
  is — "Get started" at openvtc.net, member sign-in, capability cards (git
  across GitHub, Forgejo/Codeberg and Gitea, verifiable data rooms, access
  management, credentials, recognition), a quieter operator-console link, and
  the existing status panel. Fixes hidden status rows rendering empty.

  The step-up passkey route test now compares an unrouted response with the
  website fallback byte for byte; its old "no 'credentials' in the body" check
  tripped on the new landing page copy.

- **vtc**: The console explains itself, uses the full width, and Recognition lists every trust record ([#1984](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1984))

* fix(vtc): the console explains what it shows, uses the full width, and marks setup steps a repository does not use

- **vtc**: Hidden vetting (PCS) is turned off, read back and run with events from the console ([#1956](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1956))

* feat(vtc): hidden vetting (PCS) is turned off, read back and run with events from the console

  Completes the console's hidden-vetting surface on top of #1955, with the
  three tasks trust-tasks-tf #729 specified (trust-tasks-rs 0.27.5):

  - `vtc/vetting/hidden/withdraw/0.1` turns hidden vetting off for a criterion.
    Named vetting is untouched; enrolment rows and the spent-token ledger stay,
    so a later publish works with the same keys. Withdrawing a criterion with
    none is `withdrawn: false`, not an error.
  - `vtc/vetting/hidden/show/0.1` answers an administrator with the stored
    configuration — each event's `approvedBy` and `graceDays`, which the
    manifest leaves out — plus how many members are enrolled under each live
    vetter label and each event's demand against its floor. Counts only, never
    which members.
  - `vtc/vetting/hidden/publish/0.1` now holds the approval rules its draft
    states: a new or changed `approvedBy` must be the publishing signer
    (`approverNotSigner`) — it was an unchecked string, so an administrator
    could approve in anyone's name — and an approver who has asked to vet at the
    event is refused (`approverInEvent`). An approval already stored may be
    re-sent by anyone, so a re-publish keeps it.
  - Every publish and withdrawal is audited as `HiddenVettingChanged` (new
    `vti-common` audit variant; the enum is `#[non_exhaustive]`).

- **vtc**: Hidden vetting (PCS) is visible and run from the admin console ([#1955](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1955))

An administrator could not tell whether their VTC supported hidden vetting,
  and could not turn it on from the console at all: the only way was a signed
  `vtc/vetting/hidden/publish/0.1` built by hand. Worse, any edit made to a
  criterion in the console then turned it off again without a word.

  - Saving a criterion keeps its hidden vetting. `accepts/register/0.2`
    carries no member for the parameters, so a replacement built from it
    always arrived without them, and `register_accepts_inner` stored it that
    way. They are now carried over like `position`, and dropped only when the
    replacement asks for no vetting at all, which publish refuses anyway.
  - The dashboard has a "Hidden vetting (PCS)" tile, read from
    `trust-task-discovery/0.3`: whether this build routes `hidden/publish`,
    not a guess from the version.
  - Each criterion's card has a hidden-vetting section, read from the join
    manifest's `vetting.ext["org.openvtc.hidden-vetting"]` (what applicants and
    vetters receive): status, labels, drip rate, suite and keys. From it an
    administrator turns hidden vetting on, sets the drip rate, and rolls the
    live labels to the current month, which the daemon never does on its own.
    A criterion with events is shown but not edited: publish replaces the
    events, and the manifest omits each event's `approvedBy`, so a re-publish
    from it would un-approve them.
  - The trust-task census gains a feature-gated allowlist: `hidden/publish` is
    dispatched exactly when `vetting-pcs` is compiled in, and the console sends
    it only after discovery says so.

  Turning hidden vetting off, reading the stored configuration, and managing
  events need `vtc/vetting/hidden/{withdraw,show}/0.1`, specified in
  dtgwg-trust-tasks-tf#729; they follow once it reaches trust-tasks-rs.

- **vtc**: A community serves governance/capability/* — members list its capability modules, administrators enable them, and the trust registry follows ([#1948](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1948))

* feat(vtc): a community serves governance/capability/* — members list its capability modules, administrators enable them, and the trust registry follows

  OpenVTC's Capabilities panel sends a signed governance/capability/list/0.1
  to the community's VTC DID over DIDComm or TSP, and the VTC answered
  unsupportedType: it only ever relayed git-trust writes outward. The VTC is
  the source of truth for which capability modules a community has enabled;
  its Trust Registry is a projection, whose own enable/disable are admin-only
  and only switch which record families it accepts.

  "Capability module" (a pluggable governance capability, git-trust first) is
  kept apart from ACL capabilities throughout: crate::capability_modules,
  trust_tasks::capability_module_tasks, AuditEvent::CapabilityModuleChanged.

  list/enable/disable 0.1 are served on the document spine (DISPATCHED_URIS),
  so DIDComm, TSP and HTTPS route them and discovery lists them; every reply,
  refusals included, is signed, addressed to the requester and threaded.

  - list answers members and administrators (an application entry and unknown
    DIDs get permissionDenied), filters on status as the registry does (absent
    means enabled), and answers the generated #response that
    trust-tasks-capability-client's parse_capability_reply reads. Admins
    holding vtc.config.admin also see each decision's projection in ext.
  - enable/disable need vtc.config.admin (VTI-ACL-030) and a step-up bound to
    the document (VTI-APV-015) — the destructive class. They do not park for
    consent: VTI-APV-018–020 / VTI-VTC-022 ask that of authority-conferring
    acts, and a module confers no ACL authority. config.authority defaults to
    the VTC DID and may name nothing else; any other config member is
    configInvalid rather than silently ignored. Declared codes
    unknownCapability, alreadyEnabled, configInvalid, notEnabled are emitted.

  The decision (version, config, enabledAt/By, generation, projection status)
  is persisted in the community keyspace first and audited; the new
  capability_modules::Projector then sends governance/capability/enable|
  disable as the registry's admin via TrustRegistryClient::
  project_capability_module (TSP > DIDComm selection, schema-checked payload).
  alreadyEnabled/notEnabled are success. Transient failures back off 5 s to
  1 h with jitter; a refusal is marked failed, audited once
  (projectionFailed), warned, and still retried at the cap so fixing the
  registry converges. Results are recorded only against the generation sent;
  no lock is held across the round trip.

  The git-trust manifest is a pinned copy of the registry's; enablement does
  not yet gate [hooks.git-trust] or the git-ns projection.

- **vtc**: A suspended subject's git rights are withdrawn from the registry and the forge until its cooling-off closes (VTI-APV-019) ([#1945](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1945))

* feat(vtc): a suspended subject's git rights are withdrawn from the registry and the forge until its cooling-off closes (VTI-APV-019)

  While a cooling-off reduction holds an entry suspended (vtc-action-list.md
  §8.2), the git-ns projection now treats its holder as holding nothing: its
  Trust Registry records (the implied git.commit.sign of own/maintain/ns.admin
  and any role-derived grant included) are withdrawn, and its linked accounts
  leave every repository's desiredRoles, so the bridge takes off the forge roles
  it gave them. Nothing stored changes. Cancelling the cooling-off republishes,
  from the stored rights, exactly what they still give; a removal that lands
  takes the rights with the entry and withdraws nothing twice.

  The projection reads the records through a new projection::ProjectionView —
  the stored rights less every row of a subject with a suspension marker. It is
  a separate type from Snapshot that lends no Snapshot or RightsSet, so no write
  path (each loads its own Snapshot and writes with put_rights) can persist the
  filtered rows; the shared Snapshot::load is unchanged. Registry reconcile,
  role projection, a created repository's initial roles, a drift revert's
  desiredRoles, withdrawal_pending and projection/show all read the view.

  The view is a pure function of (stored rights, suspension markers) recomputed
  by every projector pass, so a crash between the marker and the withdrawal, or
  between lifting it and republishing, converges on the next pass (R2.1). Role
  jobs go through the existing job queue and dispatch with retries (R1.1).
  Each change is audited once as GitNsOperation gitNs.projection.withheld /
  .restored / .released, naming the subject and the action id; the projector
  records these before the tail so the row wakes the same pass.

- **vtc**: A cooling-off suspends its subject, and single-administrator mode can remove now (VTI-APV-019, VTI-APV-022) ([#1944](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1944))

* feat(vtc): a cooling-off suspends its subject, and single-administrator mode can remove now (VTI-APV-019, VTI-APV-022)

  Removing another unrestricted administrator when nobody else can consent
  waits out a cooling-off (acl.removal_cooling_off, default 24 h). Until now
  the subject kept full authority for that whole window, and in
  single-administrator mode there was no way past it.

  Suspension (vtc-action-list.md §8.2). From the moment a cooling-off
  reduction is raised until it lands or is cancelled, the subject's entry
  authorizes nothing. The suspension is set on the entry wherever it is read
  (acl::storage::get_acl_entry / list_acl_entries), and VtcAclEntry::can,
  can_any and can_approve answer false for it, so every gate refuses without a
  per-handler check. The signed administrative door (resolve_admin_claims,
  console keys included), the git-ns door (acting_as), require_capability and
  ACL reads refuse with a message naming the action and when it lands. The
  subject can still sign in, read the action list (callerRole: subject) and
  cancel a request of its own; its event stream carries only actions and the
  mode banner. It approves and decides nothing, acknowledges nothing, and is no
  role assigner for the attrition guard; raising a cooling-off checks the guard
  as though the subject were already gone, and only one cooling-off runs on a
  subject at a time. Its sessions are revoked at suspension, as any reduction's
  are. The row is never changed, so cancelling restores it exactly. A
  suspended subject cannot raise a counter-removal, so the first to act wins
  outright; refuse_if_reduced_first stays as a backstop.

  The suspension is derived from the open action and kept beside the entry as
  a marker (suspended:<did> in the ACL keyspace). admin_actions::save writes
  it before an action that suspends and lifts it after one that no longer does
  (R2.1), so a crash can only over-restrict, and reconcile_suspensions settles
  either half at start (before serving), on every sweep, and after a restore.

  Remove now (vtc-action-list.md §8.5, single-administrator mode only). No new
  task: a reduction's payload carries ext["org.openvtc"].immediate =
  {confirm, actionId?}. confirm must be the subject's DID (or the action id
  being landed), checked before any gesture; the gesture is bound to the
  payload digest, which includes `immediate`, so a gesture for the delayed
  removal is never spent on the immediate one or the reverse (VTI-APV-015).
  Sending the same operation with `immediate` naming an open cooling-off lands
  it now. Refused without the mode (naming the cooling-off and that the mode
  is host-set), on a mismatched confirmation, without the gesture, and by the
  attrition guard. Audited Critical as SingleAdminMode reductionImmediate
  before the write, then AuthorityReducedUnopposed, and the subject is told.
  The landed cooling-off closes landedAfterCoolingOff with ext landedNow; a
  reduction that never waited enters the history with the same marker.

- **vtc**: A subject may relabel its own entry; single-administrator mode is one person under many identifiers (VTI-ACL-052, VTI-APV-022) ([#1941](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1941))

Implements trustoverip/dtgwg-vti-spec#54 and #55 (both merged).

  VTI-ACL-052 item 2 — a subject may change its own entry's label and
  nothing else, on every door that writes it (acl/update 0.1 and 0.2,
  acl/grant re-stating the same entry, vtc/members/update). No step-up: the
  label confers no authority (VTI-ACL-001). The change is audited as a
  MemberUpdated row naming the old and new label and `labelSetBySubject`,
  and the entry carries `label_set_by_subject` (serde-default false,
  cleared when anyone else sets the label), shown to other parties as
  `ext["org.openvtc"].labelSetBySubject` on acl/list and acl/show 0.2 — an
  ext member, so the published response schemas are untouched. A request
  that changes the label and anything else is refused whole. A subject's
  own write never re-affirms a delegation under review.

  VTI-ACL-052 item 3 (as widened by #55) — in single-administrator mode a
  subject whose entry has unrestricted act scope (granting::is_unrestricted:
  a community-admin acting everywhere with its full ceiling) may modify its
  own entry on acl/update/0.2 and acl/change-role/0.2. It takes the
  subject's step-up bound to the operation (VTI-APV-015) and a Critical
  SingleAdminMode{event: selfEditWaived} row written before the write
  (acl::single_admin::authorize_self_edit), and is refused if it would leave
  no live unrestricted entry (narrowing, demoting or shortening the life of
  the only one). Ending the subject's vtc.roles.assign is attrition-checked
  like any removal. Every other self-edit is refused as before, and the
  refusals now say what the subject may do instead.

  VTI-APV-022 ([#55](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/55)) — single-administrator mode waives second-party consent
  whether or not other administrators' entries exist: one person may hold
  an administrator entry per device, and the node cannot tell one person's
  identifiers from two people's. gesture_then_consent_for and the session
  door's require() no longer test for an empty approver set; git-ns rule 7
  is waived the same way (others_eligible is gone). A reduction of another
  administrator (VTI-APV-019) is not parked for a third party's consent in
  the mode: it takes the unopposed path — step-up, notice to the subject,
  Critical row — and keeps its cooling-off, which now lands in the mode even
  with a third administrator present (recheck_cooling_off and the sweeper's
  invalidation skip the "a third party can now consent" check).

- **vtc/git-ns**: PR-open gate — close pull requests from openers the policy does not allow ([#1937](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1937))

* feat(vtc/git-ns): PR-open gate — close pull requests from openers the policy does not allow

  The VTC side of git-ns/bridge/event 0.4 (pullRequestOpened) and
  git-ns/bridge/job 0.5 (closePullRequest), trustoverip/dtgwg-trust-tasks-tf#723,
  published in trust-tasks-rs 0.27.3 (now the workspace floor).

  - bridge/event 0.4 is served (and so listed in trust-task-discovery) beside
    0.1-0.3, which are read as 0.4; every earlier event kind is unchanged.
  - On pullRequestOpened for a repository recorded active in a bridge-mode
    namespace, the author (matched by forge + id through account links) is
    checked against the gitNamespace policy's new settings: pr_open
    ("anyone" default | members | committers | maintainers | {"roles": [...]}),
    pr_open_overrides (per namespace / repository), pr_exempt (default
    ["dependabot[bot]"]), pr_close_message and pr_join_hint. Owners and
    maintainers (explicit or implied), the bridge's app account and exempt
    logins are always allowed; unlinked accounts only under "anyone". A reopen
    by an owner, maintainer or the bridge is an override; anyone else's
    re-checks the author.
  - A disallowed pull request gets a queued closePullRequest job whose message
    renders only {author} (login), {repo}, {community} and {join_hint}.
  - Jobs go as 0.5 to a bridge that lists 0.5 and as 0.4 to a 0.4-only bridge;
    closePullRequest never goes to a bridge without 0.5, whose namespace's
    administrators are told once (gitNs.pullRequest.gateUnenforced).
  - Only closes are recorded: the job (activity gitNs.job.closePullRequest) and,
    on a succeeded close, the audit row gitNs.pullRequest.closed
    {number, author login, level}. bridge/job/list 0.1 omits closePullRequest
    jobs, whose kind its JobKind enum does not yet name.

  Hygiene, not the merge gate: the required commit-trust check is unchanged and
  the gate fails open.

- **vtc/git-ns**: Single-administrator mode waives git self-grant separation of duties ([#1936](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1936))

* feat(vtc/git-ns): single-administrator mode waives git self-grant separation of duties

  A community in single-administrator mode (VTI-APV-022, #1925) has one
  administrator. Fixed rule 7 of git-ns/right/grant/0.3 still refused every
  elevated self-grant, so `cnm git adopt <repo> --owner <own DID>` failed with
  git-ns:selfGrantNotAllowed. Break-glass left records nobody could ever ratify.

  Single-administrator mode now reaches rule 7. It uses the same discipline as
  the consent waiver (`git_ns::single_admin`):

  - Only where nobody else is eligible. `others_eligible` reuses
    `admin_consent::approvers_for` over the namespace's `git.ns.admin`. That
    covers the break-glass deciders and any approve scope reaching them. It also
    counts any other member whose git rights could make this grant (rules 1 and
    2). One eligible party, or the mode off, and the refusal stands.
  - Every path the rule covers: right/grant, repo/create (implied repo.create
    naming self as owner), repo/adopt naming self, namespace/reseat to self, and
    drift/resolve adopt for one's own account. The rules accept a `Waivable`
    token only for that exact actor, right and resource. Rules 1, 2 and 5, the
    granter-covers floor, the consent-class gate and policy all still apply.
  - Requires the requester's operation-bound step-up. This is the break-glass
    mechanism (`bound_step_up`), bound to the document actually signed (for an
    adoption, the drift/resolve document).
  - Writes a Critical `SingleAdminMode { event: selfGrantWaived }` audit row
    before the write. It names the rule, task, digest, git-ns action, right and
    resource. If the audit write fails, the operation is refused and nothing is
    recorded.
  - Marks the result. The record carries `singleAdmin { at, task }`, which is
    never published. The answer carries `ext.org.openvtc.selfGrantWaived`.
    git-ns/view 0.4/0.5 lists waived records under the same ext member. The ACL
    resource grant shows `selfGrantWaived: true`. A `gitNs.right.selfGrantWaived`
    activity item is written.
  - Counts for invariants. Waived records count toward the last-owner and
    last-admin invariants, unlike unratified break-glass.

- **vtc**: Live admin console — a hint-only event stream over HTTPS (binding 0.3 streamed responses) ([#1932](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1932))

* feat(vtc): live admin console — a hint-only event stream over HTTPS (binding 0.3 streamed responses)

  An open admin console now holds one live channel per session:
  `vtc/admin/events/subscribe/0.1` POSTed as a signed document to the ordinary
  `/v1/trust-tasks` door with `Accept: text/event-stream, application/json;q=0.5`,
  answered as an HTTPS binding 0.3 §2.1 streamed response — the signed
  `#response` as the first SSE event, `vtc/admin/events/event/0.1` hints after it
  (one document per `data:` line, no `event:` field, SSE `id` = resume token,
  heartbeats as comments). No new route; every other task is unchanged.

  Hints only: `topic`, `at`, `resumeToken`, and `count` on actions /
  acknowledgements / joinRequests. Never a record, an id or a DID. The console
  reacts only by re-reading the topic's own signed read, so authorization stays
  on every read.

  VTC (`vtc-service/src/admin_events`, `trust_tasks/event_tasks.rs`):
  - a process-wide broadcast bus fed from the storage seams (action save/delete,
    join-request store/delete, member store/delete, ACL store/delete, config
    overrides, community profile); no row data travels on it;
  - effective topics = requested ∩ readable (joinRequests needs vtc.join.decide,
    config needs vtc.config.admin); standing re-checked on every ACL change,
    before every hint and once a heartbeat — a shrink ends the stream;
  - per-recipient digests so a change the caller's read would not show sends no
    hint; at most one hint per topic per second;
  - refusals stay JSON and open no stream (notAdministrator, streamUnavailable,
    tooManyStreams, permissionDenied, malformedRequest for a Last-Event-ID that
    disagrees with `since`); 5-minute issuedAt window; a replayed subscribe
    answers 204 (its response is never recorded for redelivery);
  - resume tokens are MAC'd, per-caller masked positions under a per-process
    key; unknown/foreign/expired `since` → `resumed: false`, never an error;
    in-memory history 10 min / 4096 changes;
  - the stream ends with the client, at shutdown, when the signer's ACL entry,
    console-key delegation or document expiresAt lapses, after an hour, or on a
    write stalled for 2× heartbeat; never a trust-task-error after the response;
  - caps: 5 concurrent streams per administrator, 256 in all;
  - hints are signed with the VTC key (proof RECOMMENDED);
  - no lock held across an await (R1.3).

- **vtc**: Break-glass ratification, join review and vetting review live in the action list; lists count and filter before paging ([#1931](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1931))

The three queues of vtc-action-list.md §8.2 ("Existing queues") are now
  action-list items of category `queue`, with no wire task changed:

  - git-ns break-glass ratification (`gitNs.breakGlass.review`): raised when a
    break-glass is recorded unratified, for holders of `git.ns.admin` at its
    namespace, never its subject. Ratify calls `right_ratify`, Revoke calls
    `right_revoke`, as the decider, so the Critical audit row, the
    break-glass-notice and the rule that an unratified record never counts
    toward the last-owner/last-admin invariants are all unchanged. It never
    expires into acceptance and nobody cancels it.
  - join review (`member.join.review`): raised when a join request is referred
    for review, for holders of `vtc.join.decide`. Approve/Reject call
    `vtc/join-requests/decide`'s `decide_inner`. The Join requests page keeps
    working, and either route closes the item.
  - vetting withdrawal review (`vetting.withdrawal.review`): one per current
    member whose admission counted a withdrawn statement (`needsReview`), for
    holders of `vtc.vetting.manage`. Keep member records the decision; Start
    removal runs `vtc/members/admin-remove` as the decider, with its own rules.

  Each item names a record type (urn:openvtc:vtc:...), its payload is the record,
  and its summary template is pinned in Rust and in the console with shared
  vectors. Deciders hold the capability (`admin_consent::may_decide`) rather than
  approve it; one decision either way; single-administrator mode changes
  nothing, since a queue item is a decision, not a consent. Queue items do not
  count toward the action-list limits. An item closes when its record is decided
  by any route: at once through hooks in decide_inner, right_ratify and
  right_revoke, otherwise at the next read. A refused decision leaves it open.
  Items are raised when the record is written and again by the minute sweeper
  for any record without one (crash-safe, CLAUDE.md R2.1); new capability holders
  get a slot at the next sweep.

  `vtc/join-requests/list/0.1` and `vtc/members/list/0.1` now apply their filter
  (status; role and live ACL entry) before paging, so the cursor walks only
  matching rows and a page is never empty while a match lies further on, and they
  fill `totalEstimate` with the exact count (cheap: the page is cut from the
  keyspace already in memory). The console's Join requests badge, the Members
  and Join requests tiles and the ceremonies count are one `limit: 1` read each;
  the Join requests page shows the total, and the "Awaiting a vetting decision"
  tile reads it.

- **vtc**: Git-namespace rights are capabilities on the ACL entry — one authority model (VTI-VTC-020, VTI-ACL-035 – 037) ([#1930](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1930))

Phase C3 of docs/05-design-notes/vtc-admin-roles.md. The git-ns/* Trust
  Tasks authorize from the signer's ACL entry; the separate rights store
  (`rights:*` in the git_ns keyspace) is gone.

  - Each git right is a resource grant on the holder's entry
    (`resourceGrants`, acl/resource_grant.rs): git.ns.admin at
    git-ns:<forge>/<owner>; git.repo.manage graded create (at the namespace),
    own or maintain (at git-repo:<forge>/<owner>/<repo-id>); git.commit.sign at
    either. Each grant keeps its own delegatedBy, time, expiry, reason and
    break-glass mark. A grade narrows git.repo.manage (VTI-ACL-035 bounds from
    above): own is the capability in full on one repository, maintain confers
    no management, create confers nothing over existing repositories. That
    keeps the owner/maintainer forge roles and "an implied repo.create carries
    no creator ownership".
  - VtcAclEntry::can answers for resource grants; git_ns::store::{get,put}_rights
    and Snapshot::load read and write the entries (through a git-holder: index
    in the acl keyspace), so the fixed rules, policy, projection and bridge
    code run unchanged over the same rows. All git-ns invariants are kept:
    fixed rules before the gitNamespace policy, rights keyed by repository id,
    withdraw-before-publish with implied commit rights published, reason never
    published or audited, grant/revoke at 0.3 and repo/create at 0.3,
    separation of duties and break-glass, no forge role from ns.admin alone,
    bridge jobs 0.4 only. No wire change on any git-ns task.
  - A grant is bounded by the granter's own entry at a covering qualifier
    (granter_covers, VTI-ACL-037 / VTI-ACL-071), checked after the fixed rules
    and refused as escalation.
  - A non-member holding a grant (the bridge's service grant, an external
    signer) holds it on an entry of the new community role `application`:
    never a membership, never signs in, never an elevated right, not
    assignable by any caller, removed with its last grant. Joining turns such
    an entry into a membership and keeps its grants. The bridge is still
    authenticated by the DID its namespace records.
  - Removing an entry tombstones its grants (git-departed:) for the lifecycle
    sweep, which audits each revocation and orphans sole-owned repositories.
  - A departed granter's git grants go to review: one acl.grants.review item
    with payload gitGrants; approving re-affirms each under a covering
    approver, declining or the deadline withdraws them. The default that kept
    them in force is gone; cascade_on_departure still revokes at once.
  - acl/* writes keep an entry's grants (commit_grant re-reads them under the
    git-ns lock); acl/show and acl/list 0.2 render them in
    ext["org.openvtc"].resourceGrants without reasons; acl/list's capability
    filter sees them; key rotation moves them and repoints delegatedBy.
  - Migration (git_ns/migrate.rs): at boot after the ACL migration and right
    after a backup import, every rights:* row moves onto its holder's entry,
    idempotently, audited once (gitNs.rights.migrated); unmappable rows (an
    elevated right with no member entry, a vanished scope) are kept inert under
    rights-unmapped:* and raised as an acknowledge item. The store is removed,
    not kept read-only.
  - Console: Repos is shown for git.ns.admin / git.repo.manage at any
    qualifier; bind and reseat need git.ns.admin community-wide; unbind,
    re-project, adopt, assign-owner and namespace grants need git.ns.admin at
    that namespace; New repo needs creation there.
  - Docs: git-namespaces.md, admin-access.md, vtc-admin-roles.md, CLAUDE.md.

  VtcRole gains the `Application` variant (vtc-service is not published).

- **vtc-console**: Join-request badge, member and join-request dashboard tiles, and a list-limit guard ([#1929](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1929))

Join requests nav badge: the number of join requests awaiting an
  administrator's decision, shown beside the entry when above zero, for a
  viewer holding vtc.join.decide. Refreshed like the Actions badge — at
  sign-in, on tab focus/visibility and every 60 s (the focus listener is now
  a shared `useRefetchWhenSeen`).

- **vtc**: Custom roles, capability approver sets, admin-key rollover and capability-driven console (VTI-CLT-025 – 032, VTI-APV-018) ([#1927](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1927))

Phase C2 of role-based administration (docs/05-design-notes/vtc-admin-roles.md).

  Single-administrator mode (VTI-APV-022, #1925): ChangeRoles and RestoreBackup
  go through gesture_then_consent_for, so with the mode on and nobody else
  eligible they run on the requester's bound gesture, the waiver audited
  Critical; both are tested. A restore replaces the audit log, so its waiver row
  is written again into the restored log after the commit.

  Custom roles (§6.2). vtc/roles/{define,list,show,delete}/0.1 are served on the
  signed-document spine with the generated types. A role is a record in the acl
  keyspace (role:<name>, carried by a backup), resolved onto every entry read
  from its stored definition; an entry naming an undefined role confers nothing,
  sign-in included (VTI-ACL-011). define/delete take vtc.roles.assign +
  vtc.approvals.admin, the requester's bound gesture and the N-of-M consent of the
  other holders (new Act::ChangeRoles). A ceiling is bounded by what the requester
  and every approver hold and may approve (exceedsDefinerAuthority, VTI-ACL-042,
  -071); git.commit.sign is additive and never in a ceiling. delete is refused
  while any entry (expired ones too) or pending grant holds the role (inUse),
  counted and removed under the admin-set lock a custom-role grant commits under.

  Approver sets (§7). may_approve reads approve authority alone (VTI-ACL-040), so
  the least-privilege approver counts for every act (VTI-ACL-041); a test covers
  every Act.

  Departed-granter review (§6.3). A removed, narrowed or expired granter's
  grants become one acl.grants.review action for the holders who may approve
  vtc.roles.assign (the subjects excluded): approve re-affirms each grant the
  approver covers, decline withdraws at once, a lapse is withdrawn by the
  delegation sweeper (kept as the backstop; it now also notices expired
  granters).

  Key rollover. acl/swap-key/0.1 rolls the signer's own entry to a new key with
  exactly its authority (VTI-CLT-025 – 032, VTI-ACL-052): no console key, a
  required short-lived VP-JWT link proof from the new key addressed to the VTC,
  AclKeyRotated audited before one atomic move_if_unchanged, the member row and
  delegatedBy pointers following the key, old sessions revoked. A member's own
  rotation now re-points delegations too. cnm community continue rotates the
  granted key this way; cnm community rotate rotates a configured one
  (vtc-client: VtcClient::acl_swap_key). Note: VTI-ACL-054 – 058 (hand-off
  markers) are a different mechanism and are not implemented here.

  Backup restore. backup/finalize-import with confirm: true is previewed, then
  parked (Act::RestoreBackup) for the holders of vtc.backup.restore; approvers see
  the payload without its password, and the staged bundle is kept alive for the
  action's lifetime.

  Console. auth/whoami returns the caller's live capabilities (the published
  member) and ext["org.openvtc"].{adminRole, approves}; navigation and action
  buttons render per capability; a Roles page lists, defines and deletes roles
  through the action list; the new action kinds have pinned summary templates.

- **vtc**: Single-administrator mode, set at install, for communities with one administrator (VTI-APV-022) ([#1925](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1925))

A community run by one person has nobody to give second-party consent
  (VTI-APV-014, -018 - 020). Without this, its administrator could add a
  colleague or change an authority rule only through the offline break-glass.
  VTI-APV-022 lets a node run in single-administrator mode instead. This
  implements it at the VTC.

  - Config: `[acl] single_admin_mode` (default false). Host configuration
    only (item 1). It is read at start, kept out of the runtime registry,
    and refused by name by `config/patch` and `vtc/config/import`, with the
    host-side fix in the refusal. It is written to config.toml only when on.
  - Setup: `vtc setup --single-admin` (interactive and `--from`),
    `single_admin_mode = true` in the setup TOML, and an interactive
    "Run as a single-administrator community?" (default No). Setup warns when
    it is chosen beside `co_admin_did`, because the mode has no effect while
    that administrator is eligible.
  - Gate: where the approver set is empty and the mode is on, the consent
    gate neither refuses nor parks. The requester's operation-bound step-up
    (VTI-APV-015) stands in for the consent. Spending it writes a Critical
    `SingleAdminMode{consentWaived}` audit row naming the requirement, task,
    kind and digest. The row is written before the write, and a failure to
    audit refuses the operation. Once the write lands, the operation enters
    the action history marked `ext.org.openvtc.consentWaived`. A non-empty
    approver set parks exactly as before (item 2).
  - Reductions (VTI-APV-019) are unchanged and keep their cooling-off.
    Removing the subject at once would let one credential first remove the
    only other eligible party and then act on the waiver
    (vtc-action-list.md section 8.5).
  - Boot (item 4): Critical `inEffect` at every start with the mode on, and
    `enabled`/`disabled` when the value differs from the last start (stored in
    the install keyspace). A start that cannot audit does not proceed.
  - Visibility (item 3): `vtc/admin/actions/list` carries
    `ext.org.openvtc.singleAdminMode`. The console shows a permanent,
    non-dismissable banner on every page and a dashboard tile, and marks
    waived operations in Actions. `cnm actions list` prints a notice and marks
    waived operations.
  - Docs: admin-access section 2.1a, bootstrap runbook, non-interactive setup
    and example TOML, vtc-action-list section 8.5, vtc-admin-roles section 7,
    the infographic, and CLAUDE.md.

  Adds the `AuditEvent::SingleAdminMode` variant to vti-common. The enum is
  `#[non_exhaustive]`, so this is additive.

- **vtc**: Trust-tasks 0.27 — cooling-off actions, the reduction-pending notice, offline-write records, and approver-device approvals ([#1922](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1922))

trust-tasks-rs 0.27.1 (trust-tasks-tf #719) specifies what the action list's
  A2 phase had to express by workaround. This adopts it.

  - trust-tasks-rs and its sibling crates move to 0.27.1, in lockstep with the
    TDK release built on it: affinidi-tdk 0.23, affinidi-messaging-sdk 0.33,
    affinidi-messaging-test-mediator 0.18 (mediator 0.37), and
    affinidi-messaging-mediator-{admin,tui} 0.8. The graph holds one
    trust-tasks-rs (and one trust-tasks-proof), so the mediator `MediatorAcl` is
    one type and no bridge is needed. 0.27.0's typed git-ns
    `ActivityItem.source` needed no change: the VTC builds that response from
    JSON, and its wire is unchanged.
  - `vtc/admin/actions/{list,show,cancel,acknowledge}/0.2` are served beside 0.1.
    At 0.2 a cooling-off (VTI-APV-019) is category `coolingOff` with `landsAt`
    and `cancellableBy: requester`, no threshold, expiry or approvers remaining,
    closes `landedAfterCoolingOff`, and its subject sees it as `callerRole:
    subject` in `all` and `history`, never `waitingForMe`. 0.1 keeps answering
    as before (`ext["org.openvtc"].coolingOff`, `thresholdMet`). A parked
    operation's next step expects show/0.2. vtc-client, cnm and the console use
    0.2; cnm and the console count down to `landsAt`.
  - A reduction parked for its cooling-off sends the subject
    `vtc/members/authority-reduction-pending-notice/0.1` (durable push). The
    landing still sends the authority-reduced notice (`unopposed`); a cancelled
    one reduces and sends nothing more. Landing never waits on delivery.
  - An operator's offline write (VTI-VTC-023), the emergency bootstrap
    included, is raised with `typeUri` the record type
    `vtc/operator/offline-write/0.1` and the record `{command, dids, host, at}`
    as payload, replacing the URN placeholder and four per-command templates
    with one pinned template. The emergency marker now records the recovery DID
    and the administrators it wiped. A document of the record type answers
    `unsupportedType`; the manifest census lists it as embedded-only.
  - The console approves with the admin's approver device through the plugin's
    `approveDecision` (vta-browser-plugin #293): the device signs a
    decision-purpose statement over the per-approver salted wire digest, and
    the wallet signs `task-consent/decision/0.2` carrying it as `approverSigned`
    evidence. Precedence: approver device, passkey, wallet signature alone,
    then the `cnm consent approve` guidance.
  - A crash between a `policy/upsert` revision write and its effect marker was
    reconciled `failed` although the revision existed, because the upsert moves
    no state pin (CLAUDE.md R2.1). An executing action's revision is now stored
    under an id derived from the action and execution
    (`admin_actions::policy_revision_id`), so the row is its own evidence.

- **vtc**: Administration is role-based — capabilities, built-in roles and explicit act scope (VTI-ACL-030 – 037, VTI-APV-018) ([#1924](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1924))

Phase C1 of docs/05-design-notes/vtc-admin-roles.md. A VTC ACL entry no longer
  reads "admin with an empty context list" as unrestricted: it carries explicit
  administrative authority beside its community role.

  Model (vtc-service/src/acl/capability.rs, entry.rs)
  - VtcAclEntry gains adminRole (seven built-ins: community-admin, moderator,
    vetting-lead, repo-manager, credential-officer, auditor, approver; custom
    roles are a C2 placeholder), act all|none, capabilities ceiling|none|listed
    with resource qualifiers (git-ns, git-repo, policy, criterion) and additive
    grants, approve and approveCapabilities. Absent means none.
  - A typed registry of 20 capabilities with authority-conferring flags. The
    effective set is ceiling ∩ listed (plus additive), and every gate asks one
    question: entry.can(capability, resource). No authority list is tested
    with is_empty().

  Gates (§4)
  - Every require_super_admin / is_super_admin / "any admin" gate is replaced
    by the specific capability. Reads need any administrative role; writes need
    their capability. Console sign-in admits every administrative role. git-ns
    community-admin standing is git.ns.admin unqualified.
  - vtc/members/update refuses a move to or from a community role that implies
    an administrative role (moderator, issuer, admin) with adminRoleForbidden;
    acl/change-role carries the bound gesture for it.

  Consent (VTI-APV-018, -019, -009)
  - APV-014 generalises to any authority-conferring capability: approvers are
    holders of the same capability at a covering qualifier who may approve it;
    the requester (and, for a reduction, the subject) is excluded. A2's
    after_reduction, agreements, cooling-off, record_effect and notices are
    kept; actions record the capabilities at stake. An expiry put on or brought
    forward is a reduction of everything the entry holds. The last holder of
    vtc.roles.assign is never removed.

  Granting bounds (§6.3; VTI-ACL-031, -033, -042, -050, -053, -071)
  - A granter must hold each capability and vtc.roles.assign at a qualifier at
    least as wide, may confer approve only within its own, never past its own
    expiry, never to itself. delegatedBy is recorded. A departed or narrowed
    granter's grants go under review and are withdrawn after the action
    lifetime unless re-affirmed (review listing + sweeper, not an action-list
    item).

  Wire
  - acl/{grant,update,show,list,revoke,change-role}/0.2 are served with the
    generated trust_tasks_rs types beside 0.1, mapped per acl/_shared/0.2
    CONVENTIONS §8; an entry 0.1 cannot express is refused at 0.1. Six 0.2
    summary templates are pinned (Rust and console).

  Migration (§9)
  - At boot, before anything is authorized, every ACL row in the pre-role shape
    is rewritten in place with the same mapping a backup import uses. All rows
    are mapped before any is written, and each is one put, so a refusal or a
    crash leaves no half-migrated row. A second boot is a no-op. The run is
    audited once (new AuditEvent::AclMigrated, Critical: counts plus the
    context-scoped admins left with no administrative role), and those losses
    are raised as an acknowledge item for the remaining community-admins
    (VTI-VTC-023; new pinned template, urn:openvtc:vtc:operator:acl-migration).
    A row that cannot be mapped refuses the boot, naming the DID and the
    offline fix (vtc acl remove, which now removes an undecodable row, then
    vtc acl add). It is never dropped.
  - Backup import maps legacy rows: unrestricted admin -> community-admin,
    context-scoped admin -> no administrative role (listed for re-grant in the
    import report), moderator / issuer -> the matching role, custom -> none.
  - Install bootstrap and the co-admin are community-admins; offline
    `vtc acl add --role admin` writes a community-admin, and gains
    --admin-role and --capability cap[@resource]; --contexts is refused.

  Clients
  - vtc-client gains the 0.2 calls; cnm access list/show/grant/update use 0.2
    with --admin-role / --capability / --approve.
  - The console's Access control shows each entry's administrative role and
    capabilities, adds and edits with role and capability narrowing, and no
    longer calls a least-privilege entry "all" ([#746](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/746)).

- **vtc**: Operator writes need acknowledging, reductions notify and cool off, and execution survives a crash (VTI-VTC-023, VTI-APV-019) ([#1920](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1920))

Phase A2 of the administrator action list (docs/05-design-notes/vtc-action-list.md).

- **vtc**: An approver device can be an administrator's step-up factor (VTI-APV-015, VTI-APV-016) ([#1919](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1919))

An administrator who signs in with a VTA wallet holds no passkey at the
  community, so every operation behind the operation-bound step-up was refused
  for them. A step-up approver — an Ed25519 did:key bound to one subject as
  their step-up factor, such as the browser plugin's approver identity — can
  now answer it.

  - Gate: the inline request is auth/step-up/approve-request/0.4, accepting
    `approverSigned` (naming the subject's approvers) and/or `webauthn`.
    auth/step-up/approve-response/0.6 carries the approver's attest/0.1
    statement, verified as received against this service's own pending
    record; the answer itself must be signed by the subject's own DID, never
    a console key. Once a subject holds a dedicated factor (approver or
    step-up passkey) their session passkeys stop counting. Audited as
    OperationStepUpApproved with the evidence kind and approver DID.
  - Store: new backed-up keyspace `step_up_approvers`; one approver DID per
    subject, once (revoked DIDs are burned), at most five per subject,
    distinct from the subject's DID, DID-document keys and every console key,
    checked at enrolment and at every use (VTI-APV-015 as amended).
  - Enrolment on the signed-document spine, every binding resting on an anchor
    independent of the subject's signing key and audited with `enrolledVia`
    (VTI-APV-016): auth/step-up/approver/{invite,redeem/start,redeem/finish}
    (R2), enroll (R3, behind a factor already held, bound to the terms
    digest), list and revoke; vtc/install/claim/{start,finish}/0.3 (R1,
    claim under the token's DID verified against its live document, binding
    written at bootstrap); `vtc admin enrol-approver` (R4, offline invite,
    audited at boot as a break-glass).
  - Console: approverSigned via a feature-detected window.vtaWallet
    approveStepUp, falling back to WebAuthn; Approver devices card; member
    invite; redemption page.

- **vtc**: Consent-gated operations wait in an action list and complete on the N-th approval (VTI-APV-017) ([#1918](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1918))

A VTC operation that needs other administrators' approval -- an unrestricted
  grant (VTI-APV-014), a reduction of another unrestricted admin (VTI-APV-019),
  a lowered consent threshold (VTI-APV-020), an authority-policy change
  (VTI-VTC-022) -- is no longer refused with `auth:consent_required` and re-sent.
  Phase A1 of docs/05-design-notes/vtc-action-list.md.

  Once every other check passes and the requester's operation-bound step-up is
  spent (VTI-APV-015), the operation is parked as an action in the new
  `admin_actions` keyspace (excluded from backup: it binds the ACL as it stood on
  this host). The record keeps the requester's signed document verbatim, the
  payload, requester, step-up evidence, approver set, threshold, one challenge
  per approver, a state pin and its lifetime. The requester is answered
  `trust-task-next-step/0.1` (202, continuation `proceed`, expecting
  `vtc/admin/actions/show/0.1` with the action id) and never sends it again.

  Approvers decide with `task-consent/decision/0.1` or `/0.2`, signed by their
  own DID (a delegated console key is refused). The approval that reaches the
  threshold moves the action out of `open` under a lock -- so concurrent final
  approvals execute it once -- and dispatches the stored document through the
  handler it was submitted to, re-running every check against the community as
  it is then; the consent gate re-checks approver eligibility, threshold and
  state pin. It closes `completed`, or `failed` with nothing written. One deny
  closes it for everyone; the requester can cancel; it expires; it is
  invalidated when the requester loses authority, the pinned state moves, or the
  eligible approvers can no longer reach the threshold (VTI-APV-004/-005/-006/
  -007/-008/-009/-017). Freshness and replay are held once, at submission
  (VTI-OPS-024..027).

  decision/0.2 `webauthn` evidence is verified against the approver's passkeys
  with user verification required, as an additional factor. `approverSigned`
  evidence is refused (evidenceInvalid, approverSignedUnsupported) until the
  approver store lands.

  New config keys, runtime-patchable: acl.action_lifetime (72 h, 15 min-14 d),
  acl.action_max_open_per_requester (5, 1-20), acl.action_max_open (50,
  10-500), acl.action_decline_cooldown (1 h, 0-24 h). More than three actions by
  one requester in ten minutes writes a Critical `AdminActionBurst` audit row
  and flags approvers' cards; an approver may decide at most ten a minute
  (VTI-APV-021, section 7a.1).

  Summaries are templates as data (title/effect prose, JSON Pointer fields, a
  closed format set) keyed by (kind, typeUri), each pinned by digest in the
  build, with shared vectors run by the service and the console (VTI-APV-011,
  -013).

  Served on the signed-document spine: vtc/admin/actions/{list,show,cancel,
  acknowledge}/0.1 (acknowledge answers notAcknowledgeable until A2 raises
  acknowledge items), with conformance witnesses and declared-code witnesses.

- **vtc**: Join criteria state their own admission (Keyring VTI-13) ([#1907](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1907))

A community's join criteria are its join rules, and the VTC now decides a
  submission by them as vtc/join-requests/submit/0.3 specifies
  (dtgwg-trust-tasks-tf#710, trust-tasks-rs 0.26.1). Nothing in the service
  assumes a criterion: open admission, review only, invitation only and any
  combination are all criteria an administrator registers.

  - Criteria (vtc/schemas/accepts/{register,list,show}/0.2) carry `admission`
    (automatic | review), an optional DCQL query with `credentialIssuers`
    (community | recognised | any), `invitationRequired` and `vetting`.
    `recognised` without a trust registry is `unsupportedRequirement`.
  - The manifest (vtc/join-requests/manifest/0.3) publishes them in the order
    the community decides by — registration order, kept on replacement.
  - A submission is decided under the criterion it names by digest, else the
    first it meets, else the first published. No criteria → `notAccepting`;
    an unpublished digest → `criterionUnknown`. Superseded versions are kept
    and govern while their `requirementsGrace` lasts.
  - The host verifies the presentation's embedded credentials (proof set,
    validity window, revocation, subject = applicant) and matches the query,
    applying DCQL `type_values`, which the matcher alone ignores.
  - The host holds the policy to the criterion: unmet → never admitted or
    referred (requestMore naming what is missing); met review → refer; met
    automatic → the policy's verdict. Policy may tighten, never loosen.
    The default join.rego follows the criterion.
  - A new community is seeded once with `invited` (automatic) →
    `member-credential` (automatic) → `review`.
  - The criterion and version that governed are recorded beside the request;
    a supplement re-decides under it.

- **vtc-service**: Serve auth/signing-key/enroll/0.2 — wallet-authorized enrolment and key replacement ([#1903](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1903))

Served beside 0.1 (trust-tasks-tf #712, trust-tasks-rs 0.26.2).

  - authorization: an embedded auth/signing-key/authorize/0.1 signed by
    identityDid is the authority evidence in place of the passkey step-up
    (item 13). Verified as received: its own proof, issuer == identityDid,
    recipient == this VTC, its acceptance window, its payload RFC 8785-equal to
    the enrolment's without `authorization`, not signed by a delegated key, and
    its id spent in accepted_ids when the delegation is written. Any failure is
    authorizationInvalid; no fallback to the step-up.
  - replaces: an active delegation of the same identity, revoked in the same
    critical section as the enrolment and audited as the identity's revocation
    (item 14); replaceNotFound for every other case, after the evidence.
  - tooManyKeys decided after evidence and standing, counting a replaced key as
    gone; 0.2 lists details.activeKeys (least recently used first, at most 16),
    never before the evidence is accepted.

- **vtc**: An approved applicant can ask for its credentials again (tf#709) ([#1900](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1900))

A join can be approved while its credentials are lost in delivery: the
  persona is a member, its client stays Pending, and nothing ever re-sends a
  failed push. `join-requests/status/0.1` now lets the applicant ask for the
  credentials again, and the VTC answers.

- **vtc**: Deliver the community's own vetted/1 to its subject ([#1898](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1898))

vtc/endorsements/issue under vetted/1 records the community's own identity
  check, which the member presents as personhood evidence, but the statement was
  only returned to the issuing admin and never reached the member's wallet.

  Deliver it over credential-exchange/issue, as the role VAC is, and keep the
  signed document on the endorsement row so it can be delivered again. Best
  effort: issue and record stand whether or not delivery succeeds.

- **vtc**: Bind the community's own check to a uniqueness pseudonym server-side ([#1876](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1876))

A community enforcing `personhood.singleMembership` could not satisfy it with
  its own `vetted/1` identity check, because the statement has no member for a
  pseudonym. The binding now happens server-side, at issue.

  - `vtc/endorsements/issue/0.1` under `vetted/1` reads the payload extension
    `ext["org.openvtc.uniqueness"] = { "pseudonym": "<value>" }`. It is never
    written into the credential. The pseudonym is bound to the subject in the
    existing pseudonym store (`members::pseudonym::claim_for_statement`), which
    stores only the community-scoped salted digest. The claim row is tagged
    with the statement's endorsement id. The binding is made before anything is
    minted, and released again if minting fails.
  - A pseudonym already bound to another member refuses the issue with
    `AppError::Conflict`: `taskFailed` with `details.reason` `conflict`, the
    same collision semantics personhood assert already has. Nothing is minted.
    No declared `endorsements/issue` code fits a duplicate person, and
    `claimSchemaViolation` would tell the caller to fix a claim that is valid.
  - The extension is read only under `vetted/1`, and only as
    `{ "pseudonym": "<non-empty string>" }`. Anything else is
    `malformedRequest`.
  - At personhood assert under `singleMembership`, the community's own
    `vetted/1` statement about the member satisfies uniqueness only when the
    community holds a binding for that member DID (`pseudonym::is_bound`).
    Credentials from an accepted IDVP still use `credentialSubject.pseudonym`.
  - `vtc/endorsements/revoke/0.1` on a `vetted/1` row releases the binding it
    made (`pseudonym::release_for_statement`). A binding an outside provider's
    credential made is untagged and is kept. Purge still releases every binding
    of the member.
  - vtc-client gains `issue_endorsement_with_ext` (additive).
    `cnm member endorse` gains `--uniqueness-pseudonym`.

- **vtc-service**: Send the step-up passkey change notice (vtc/members/step-up-passkey-notice/0.1) ([#1875](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1875))

Lands the TODO left in #1872: a signed, unsolicited notice to a member
  whenever a step-up passkey is enrolled for them or revoked from them, on
  every enrol and revoke including self-service. `by` names who acted —
  the member themselves for self-service, the administrator for an invite
  or an on-behalf-of revoke — which is the whole signal the spec exists to
  carry: a recipient's agent treats `by != did` as a takeover prompt.

  Delivery reuses the existing member-push path (`crate::member_push`,
  TSP > DIDComm > REST) and is best-effort: a notice that fails to queue
  is logged and swallowed, never undoing the enrol or revoke that already
  took effect.

  Bumps trust-tasks-rs to 0.25.3 (first release carrying the spec) and its
  pinned siblings, keeping one copy of each in the lock file.

  No census edits were needed: `every_bound_canonical_task_exists_in_the_registry`
  derives its check from the registry rather than a hand-maintained list,
  so the new URI passed once the crate was bumped.

- Record the community's own identity check as a vetted/1 statement ([#1874](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1874))

* feat(vta-sdk)!: vetted/1 vetter-only members are optional and all-or-nothing

  Registry `vetted/1` (trustoverip/dtgwg-vsc-registry#24) admits the community
  itself as issuer of a statement recording its own identity check. Such a
  statement carries none of the three vetter-only members; a vetter's statement
  carries all three. The schema makes them all-or-nothing (`dependentRequired`).

- **vtc-service**: Step-up passkey self-revoke, change notices, approve-response 0.5 ([#1872](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1872))

* feat(vtc-service): step-up passkey self-revoke, change notices, approve-response 0.5

  A member can now revoke their own step-up passkey (auth/passkey/revoke
  0.2's Authorization section): payload.subject absent (or equal to the
  producer) targets the producer, verified with their own remaining
  step-up passkeys; an administrator still revokes for someone else, now
  gated inside step_up_passkey::revoke_start/finish rather than by
  admin_signer, which refused any non-admin signer outright.

  The member is now told, over the existing member-push mechanism, when
  a step-up passkey is enrolled or revoked for them by someone else, so
  a takeover through a compromised administrator key is not silent.

  auth/step-up/approve-response/0.5 is served alongside 0.4: it requires
  the approver's assertionMethod proof on every response (0.4 still
  admits an unsigned console-passkey answer), enforced by the spine's
  own proof policy before the handler runs. The 0.5 payload converts to
  0.4's generated type to reach the one verifier rather than forking it.

- **vta-service**: Retire superseded REST routes; pre-session auth moves to Trust Tasks ([#1858](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1858))

* feat(vta-service)!: retire superseded REST routes; auth family moves to Trust Tasks

  Deletes the ~56 REST routes `deprecation::SUPERSEDED` marked as superseded
  by a Trust Task (acl, audit, config, contexts, did_templates, keys, webvh
  servers/dids, POST /vta/restart, the /api/trust-tasks alt spelling) and the
  always-403 POST /attestation/mnemonic stub. The REST-route half of
  `deprecation.rs` (the SUPERSEDED table, mark_superseded middleware) is
  removed now that it's empty; the unrelated SUPERSEDED_TASKS (Trust-Task URI
  supersession) table is untouched.

  Pre-session auth (auth/challenge/0.1, auth/authenticate/{0.2,0.3},
  auth/refresh/0.2) moves onto `/trust-tasks`, dispatched by a new
  family-owned bypass (`trust_tasks::auth::owns`/`dispatch_pre_session`) that
  runs ahead of the ACL-gated pipeline on all three transports (REST,
  DIDComm, TSP) — mirroring affinidi-webvh-service's `trust_tasks_auth`
  pattern. The document's own proof (required on authenticate, absent on
  challenge/refresh) is the whole of the authority these four carry, so
  there is no session and no ACL pre-filter to apply. authenticate/refresh
  0.1 are retired outright (this is a test deployment); 0.2/0.3 add
  sessionKey and delegation fields this VTA declines with a typed refusal
  rather than silently ignoring.

  Kept as tested REST_EXCEPTIONS: POST /bootstrap/request, GET+POST
  /backup/blob/{bundle_id}, GET /openapi.json, GET /attestation/mnemonic,
  GET /metrics.

  Client-side (vta-sdk, vta-mobile-core) callers move onto the Trust-Task
  form; cnm-cli/pnm-cli/vta-mcp needed no changes (already Trust-Task only).

- DTG Credentials v1 — role VACs, vetted/1 and witnessed/1 statements, IDVCs, issuerScope ([#1859](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1859))

* feat(vta-sdk)!: vetting statements are vetted/1 VSCs; role credentials are VACs

  Conform the SDK's vetting artifacts to the DTG Credentials Core
  Specification (v1 context, `issuerScope`) and the DTG VSC predicate
  registry, following the regenerated vetting specifications
  (dtgwg-trust-tasks-tf feat/dtg-vsc-conformance).

  Vetting Statement (vetting/session/0.1): no longer an
  EndorsementCredential. `sign_statement` builds a StatementCredential with
  `new_vetted_vsc` under `https://registry.trustoverip.org/dtg/vsc/vetted/1`;
  the body is `credentialSubject.object.value`, with no `type` member.
  `taskContext` and `taskDigestMultibase` are both read from the
  `vetting/session` document, which `StatementDraft::session` now carries
  in place of `task_context`, and `StatementDraft::issuer_scope` is
  `directed` or `public` (pairwise is refused by the profile).
  `verify_statement` parses through `dtg-credentials`, so the v1 context,
  the one-subtype rule and the profile are checked by the code that issues
  them; `VerifiedVettingStatement::check_against_session` binds a statement
  to the session document by id and task digest.

  - `IdentityVettingEndorsement` -> `VettedObjectValue` (no `type`; digests
    and commitment must be base58btc, as the registry schema requires).
  - `IDENTITY_VETTING_ENDORSEMENT_TYPE` -> `VETTED_PREDICATE`.
  - `VerifiedVettingStatement::endorsement()` -> `value()`; new
    `issuer_scope()`, `task_digest_multibase()`.

  Vetter role credential (vtc/vetting/vetters/grant/0.1, vetting/request/0.1):
  a community-issued VAC, `issuerScope` public, `authority` { scope:
  <community DID>, actions: ["role:vetter"], maxAttenuation: 0 }.
  `eligibility::community_role` -> `community_roles`, returning every
  `role:<name>` of a VAC the community issued in its own scope with no
  parent; `verify_eligibility_vp` parses the VAC strictly and refuses a
  non-public scope or an attenuation.

  - `COMMUNITY_ROLE_ENDORSEMENT_TYPE` removed; new `ROLE_ACTION_PREFIX`,
    `VETTER_ROLE_ACTION`, `role_action`, `role_of_action`.
  - `protocols::members::ENDORSEMENT_CREDENTIAL_TYPE` removed; new
    `AUTHORITY_CREDENTIAL_TYPE` and `STATEMENT_CREDENTIAL_TYPE`.
  - `VerdictWith::role_vec` -> `role_vac` (wire `roleVac`).

- **vtc-service**: Website content moves as signed Trust Tasks ([#1839](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1839))

* feat(vtc-service)!: the policy log and the community's DID log are signed Trust Tasks

  policy/{list,get,active,upsert,activate}, vtc/policies/test and
  did-management/did/register are served by the spine
  (trust_tasks::policy_tasks) on every transport, with the signer's ACL row
  as authority: Admin for the policy verbs, an unrestricted Admin for the
  DID log, as the bearer routes' AdminAuth and SuperAdminAuth asked.
  policy/activate refuses a purpose the revision does not decide. The
  console signs every policy call.

  Per-type document limits come from the specifications: size.rs reads the
  codegen'd maxDocumentBytes (schema_index::max_document_bytes_for) and keeps
  an interim entry only for policy/upsert and did/register, whose specs
  declare none yet. A raised limit applies to a served type only, and only
  when the claimed issuer holds a live ACL entry (or is a signing key
  delegated by one), looked up before verification. The HTTPS cap is the
  largest served limit; a refusal does not echo an oversized type.

- **vtc-service**: Console signing keys are auth/signing-key Trust Tasks ([#1836](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1836))

* feat(vtc-service)!: the policy log and the community's DID log are signed Trust Tasks

  policy/{list,get,active,upsert,activate}, vtc/policies/test and
  did-management/did/register are served by the spine
  (trust_tasks::policy_tasks) on every transport, with the signer's ACL row
  as authority: Admin for the policy verbs, an unrestricted Admin for the
  DID log, as the bearer routes' AdminAuth and SuperAdminAuth asked.
  policy/activate refuses a purpose the revision does not decide. The
  console signs every policy call.

  Per-type document limits come from the specifications: size.rs reads the
  codegen'd maxDocumentBytes (schema_index::max_document_bytes_for) and keeps
  an interim entry only for policy/upsert and did/register, whose specs
  declare none yet. A raised limit applies to a served type only, and only
  when the claimed issuer holds a live ACL entry (or is a signing key
  delegated by one), looked up before verification. The HTTPS cap is the
  largest served limit; a refusal does not echo an oversized type.

- **vtc**: Last member-facing REST routes retire to signed Trust Tasks ([#1846](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1846))

* feat(vtc): last member-facing REST routes retire to signed Trust Tasks

  Bumps trust-tasks-rs/trust-tasks-capability-client to 0.24.8
  (trustoverip/dtgwg-trust-tasks-tf#689), which adds:

  - vtc/relationships/revoke/0.2: an optional pop, a VrcRevokeAuthorization
    proof of possession by the relationship's issuerDid, bound to the
    document's own id and to the edge (relationship) rather than to a REST
    session. Reuses the REST handler's DI-proof verification path
    (verify_di_proof); the three authorization routes (issuer, admin,
    pairwise-via-pop) are checked in the order the spec requires, collapsing
    to the same notFound for all three failure modes. The bearer-less REST
    route is deleted; vtc-client's revoke_relationship and cnm's
    `relationships revoke` gain an optional --pop-file.
  - vtc/vetting/vetters/resend/0.2: an optional memberDid, gated on the
    community-administrator capability (admin_signer, including console-key
    delegation), for an admin resending another member's grant. The
    admin-only REST route is deleted; the admin console signs 0.2 instead.

  vtc/endorsements/{list,show,revoke}/0.1 were already served on the spine;
  their REST routes had no caller left once the console and cnm moved onto
  the signed door, and are deleted too.

  Census tests (openapi_tests, conformance witnesses, trust_task_manifest,
  error_code_census), the checked-in admin-ui/openapi.json and its generated
  wire.ts are all updated to match. Integration tests move onto the signed
  door via tests/common/signed.rs and tests/common/legacy.rs's translate(),
  following tests/members_crud.rs's established pattern.

- **vtc**: Member verbs served as signed Trust Tasks — callers wired, REST retired ([#1845](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1845))

* feat(vtc-client): member verbs — renew, rotate, personhood, relationships, endorsement issue

  Adds signed-door client methods for the batch-1 member-facing verbs
  vtc-service already dispatches on the spine (trust_tasks::member_tasks,
  #1809): renew, rotate-challenge/rotate, personhood/revoke,
  relationships/{list,publish,revoke}, and endorsements/issue. Every call
  rides POST /trust-tasks, matching the pattern vtc-client already uses for
  its other admin verbs.

- **vtc-service**: Git-ns admin reads are signed Trust Tasks ([#1841](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1841))

* feat(vtc-service)!: git-ns admin reads are signed Trust Tasks

  Served by the spine (git_ns::admin_reads) on every transport, with the
  signer's ACL row or namespace-scoped git.ns.admin right as authority:

  - git-ns/right/list/0.1 — every right the VTC knows of, recorded and
    role-derived, across every namespace (community-administrator capability)
  - git-ns/right/issued-by-departed/0.1 — recorded rights whose granter has
    since left, grouped by granter (community-administrator capability)
  - git-ns/bridge/job/list/0.1 — bridge jobs in the caller's administered
    namespaces (community-administrator capability, or git.ns.admin)
  - git-ns/projection/show/0.1 — what is published to the Trust Registry
    (community-administrator capability)
  - git-ns/account/list/0.1 — every member's linked forge account,
    community-wide (community-administrator capability)
  - git-ns/activity/list/0.1 — rights changes, drift and bridge jobs in the
    caller's administered namespaces (community-administrator capability, or
    git.ns.admin)

  Each pages: limit clamped to 1..=500 (default 100), cursor bound to the
  request's own filters so a mid-page filter change is refused
  malformedRequest rather than silently reinterpreted.

  trust-tasks-rs bumped to 0.24.7 (trustoverip/dtgwg-trust-tasks-tf#686), the
  first release carrying these six specs.

- **vtc-client**: Every VTC call is a signed Trust Task ([#1840](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1840))

* feat(vtc-client)!: every VTC call is a signed Trust Task

- **vtc-service**: The community's REST-only admin surfaces are signed Trust Tasks ([#1835](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1835))

* feat(vtc-service)!: the policy log and the community's DID log are signed Trust Tasks

  policy/{list,get,active,upsert,activate}, vtc/policies/test and
  did-management/did/register are served by the spine
  (trust_tasks::policy_tasks) on every transport, with the signer's ACL row
  as authority: Admin for the policy verbs, an unrestricted Admin for the
  DID log, as the bearer routes' AdminAuth and SuperAdminAuth asked.
  policy/activate refuses a purpose the revision does not decide. The
  console signs every policy call.

  Per-type document limits come from the specifications: size.rs reads the
  codegen'd maxDocumentBytes (schema_index::max_document_bytes_for) and keeps
  an interim entry only for policy/upsert and did/register, whose specs
  declare none yet. A raised limit applies to a served type only, and only
  when the claimed issuer holds a live ACL entry (or is a signing key
  delegated by one), looked up before verification. The HTTPS cap is the
  largest served limit; a refusal does not echo an oversized type.

- **vtc-service**: The policy log and the community's DID log are signed Trust Tasks ([#1834](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1834))

policy/{list,get,active,upsert,activate}, vtc/policies/test and
  did-management/did/register are served by the spine
  (trust_tasks::policy_tasks) on every transport, with the signer's ACL row
  as authority: Admin for the policy verbs, an unrestricted Admin for the
  DID log, as the bearer routes' AdminAuth and SuperAdminAuth asked.
  policy/activate refuses a purpose the revision does not decide. The
  console signs every policy call.

  Per-type document limits come from the specifications: size.rs reads the
  codegen'd maxDocumentBytes (schema_index::max_document_bytes_for) and keeps
  an interim entry only for policy/upsert and did/register, whose specs
  declare none yet. A raised limit applies to a served type only, and only
  when the claimed issuer holds a live ACL entry (or is a signing key
  delegated by one), looked up before verification. The HTTPS cap is the
  largest served limit; a refusal does not echo an oversized type.

- **vtc-service**: The administrator's community verbs are signed Trust Tasks ([#1827](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1827))

* feat(vtc-service)!: the administrator's operational verbs are signed Trust Tasks

  The trust-registry reconciler, the audit log, the runtime configuration,
  admin invites and the auth service's sessions are served by the spine
  (trust_tasks::admin_tasks) on every transport, with the signer's ACL row
  as authority: the role and scope questions the bearer extractors asked,
  and an invite's step-up bound to the document.

  auth/sessions/list/0.1 answers { sessions: [Session] } under the
  revocation's authority (caller_covers_target); auth/revoke-session/0.2
  is served on the spine, and a refused revocation by subject is audited
  (SessionRevocationRefused). The console's drift read moves to
  git-ns/view/0.5.

  The bearer routes are removed, except GET /v1/audit/verify, which
  vtc-client still calls.

- **vtc-service**: The administrator's operational verbs are signed Trust Tasks ([#1824](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1824))

The trust-registry reconciler, the audit log, the runtime configuration,
  admin invites and the auth service's sessions are served by the spine
  (trust_tasks::admin_tasks) on every transport, with the signer's ACL row
  as authority: the role and scope questions the bearer extractors asked,
  and an invite's step-up bound to the document.

  auth/sessions/list/0.1 answers { sessions: [Session] } under the
  revocation's authority (caller_covers_target); auth/revoke-session/0.2
  is served on the spine, and a refused revocation by subject is audited
  (SessionRevocationRefused). The console's drift read moves to
  git-ns/view/0.5.

  The bearer routes are removed, except GET /v1/audit/verify, which
  vtc-client still calls.

- **trust-tasks**: Advertise the acceptance window over trust-task-discovery 0.3 (VTI-TRN-047) ([#1817](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1817))

Both VTI node types refuse a document more than ten minutes (plus 60 s of
  skew) past its issuedAt (VTI-OPS-024). A sender holding a document before
  delivery has to know that window to decide when to issue a new attempt
  instead, and until now the only way to know it was to share the constant.
  trust-task-discovery/0.3 (trust-tasks #677, trust-tasks-rs 0.24.4) lets a
  responder state it.

  - Raise the trust-tasks-rs floor to 0.24.4, the first release carrying
    discovery 0.3, and trust-tasks-capability-client with it. Only those two
    lockfile entries move.
  - vti-common: `trust_task::acceptance::AcceptanceWindow` and
    `VTI_ACCEPTANCE_WINDOW` (ACCEPTANCE_WINDOW + DEFAULT_SKEW). This is the one
    value the consumers apply (`freshness_policy()`), the responders advertise
    (`advertised()`, rounded down so it is never wider, VTI-TRN-047), and the
    push engine judges staleness by (`past_max_age`, `refuses`).
    `trust_task::discovery` has the pattern grammar and the 0.1/0.3 response
    builders, so both nodes answer the same way.
  - VTA: serves trust-task-discovery/0.3 next to 0.1, answering each in the
    version it was asked. The window goes at response level, since the VTA
    applies one window to everything it dispatches. The 0.1 frameworkVersion was
    "0.2", a stale copy of the framework crate's default. It is now "0.6",
    the MAJOR.MINOR of the 0.6.0 that 0.3 writes, so one responder no longer
    names two framework releases.
  - VTC: serves trust-task-discovery/0.3 for the first time. It answers
    identified callers only, as the VTA does, and lists the routing table itself
    (DISPATCHED_URIS plus the rooms and git-ns registrations).
  - Registrations: TASK_TRUST_TASK_DISCOVERY_0_3 in vta_sdk::trust_tasks and
    its task list, ReadOnly in retry_safety, the VTA dispatch table and its
    conformance witness (built from the real builder, not a literal), and the
    VTC DISPATCHED_URIS and its declared-URI census.
  - Push engine (VTI-TRN-045): its two staleness predicates now read
    VTI_ACCEPTANCE_WINDOW, the same value the nodes advertise, where before
    they combined two separate constants. It still reads no advertised window.
    A lookup would be a request/reply exchange, and every push is one-way.
    None of the recipients (approvers' devices, wallets, requesters) serves
    discovery. The window only matters when the recipient cannot answer. The
    engine never sees an `expired` refusal, so 0.3's "re-ask after an
    unexpected refusal" would have no trigger. The module docs and
    docs/05-design-notes/retry-and-idempotency.md say so. What remains of the
    spec's divergence F.3 is the producer side only.

- **vtc-service**: The console's signed calls have no bearer twins ([#1808](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1808))

* feat(vtc-service)!: the console's signed calls have no bearer twins

  Delete the REST twins of Trust Tasks the spine already dispatches and the
  admin console now signs (the ACL, the profile edit, purge, self-remove,
  personhood challenge and assert, the endorsement-type writes, the vetter
  listing and the admin join manifest). Drop signedOrBearer: the console's
  signed verbs are signed-only. Keep the routes vtc-client still calls over
  REST until it sends them signed.

  Rebind the session revocations to auth/revoke-session/0.2 and unbind
  sign-out; delete the unmounted step-up passkey and join-request handlers.
  Give each Trust Task type its own document size limit (64 KiB unless its
  specification needs more), checked before the document is parsed.

- **vtc**: Member verbs are Trust Tasks on the spine (renew, rotate, personhood, relationships, endorsements) ([#1809](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1809))

Eleven VTC tasks were bound to published specifications (trust-tasks-rs
  0.24.2) but served only on their HTTPS REST routes, so a member on TSP or
  DIDComm could join a community and then do none of them. They are now
  dispatched by the Trust Task spine (`trust_tasks::member_tasks`) and so
  reachable over TSP, DIDComm and HTTPS `/trust-tasks`:

  - vtc/members/renew/0.1, vtc/members/rotate-challenge/0.1,
    vtc/members/rotate/0.1, vtc/members/personhood/revoke/0.1
  - vtc/relationships/list/0.2, vtc/relationships/publish/0.2,
    vtc/relationships/revoke/0.1
  - vtc/endorsements/{issue,list,show,revoke}/0.1

  Each arm calls the operation its REST route calls. The route bodies were
  factored into shared inner functions (renew_inner, challenge_inner,
  rotate_inner, personhood revoke_inner, relationships list_inner,
  publish_inner, revoke_authorized, endorsements issue/list/show/revoke_inner);
  the REST routes keep their gates and stay mounted.

  Authority is the verified proof signer's current ACL row, read at execution
  time, never a bearer session; an expired row refuses:

  - renew / rotate-challenge / rotate: the signer acting on its own membership
    (rotate additionally requires signer == oldDid; the two in-payload
    signatures authorize the swap). No console-key delegation.
  - personhood/revoke: the subject (with a current row) or an administrator.
  - relationships/list: any current member or administrator.
  - relationships/publish: the signer, through the same publish_inner as the
    bearer-less REST route (rate limit, VRC proof, pop, policy); a limiter
    refusal is `unavailable` with limiter + retryAfterSecs.
  - relationships/revoke: the edge's issuer or an administrator; any other
    member gets the declared notFound, as the specification requires
    (anti-probing); a non-member is refused before lookup.
  - endorsements/*: an Admin or Issuer row (admins may act via a console-key
    delegation, as on the other admin verbs).

  A VTC bearer session is minted only for an Admin row, so the REST routes were
  in practice admin-only; this door admits the member or issuer the
  specifications and the handlers' own checks name, as members/personhood/
  challenge already does. No arm admits a party its handler would refuse.

  Payloads are held to their published schema (generated types) and every
  reply is read back through the generated #response type and validated
  against its schema before it is sent, so this door cannot answer in a shape
  the specification does not publish. endorsements/list now applies the
  subjectDid / typeUri / includeRevoked filters its Conformance requires,
  before pagination (list_endorsements_matching); the REST route passes no
  filter and is unchanged.

  Limits, recorded in the design note: a pairwise edge is still retracted only
  on the bearer route (its VrcRevokeAuthorization binds to a REST session and
  revoke/0.1 carries no authorization member); endorsements/revoke's `reason`
  is accepted and not persisted (the audit event has no field for it).

  Tests (trust_tasks::member_tasks::tests, 28): every task succeeds on REST,
  DIDComm and TSP contexts and conforms to its #response schema, and each
  authorization refusal is held (non-member, expired row, wrong party, missing
  issuer role, unsigned proof-optional reads). The proof-REQUIRED dispatched
  count moves 52 -> 60.

- **storage**: Optional Fjall memory settings for the VTA and VTC ([#1803](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1803))

Add STORAGE_FJALL_BLOCK_CACHE, STORAGE_FJALL_WRITE_BUFFER and
  STORAGE_FJALL_MAX_JOURNAL, plus a matching [fjall] config-file table, so
  an operator can keep fjall's block cache, buffered writes and startup
  journal replay inside a pod's Kubernetes memory limit.

  All three are optional and shared, unprefixed names for every consumer
  (vti_common::config::FjallTuning, apply_fjall_env_overrides). Unset
  leaves fjall's own defaults byte for byte; an env var overrides the
  config file; an invalid, zero, or absurdly small value is refused at
  startup naming the setting. Values accept a plain byte count or a
  suffixed size ("64MiB", "512MB", "1GiB").

- **vtc-service**: Git-ns administrator reads as signed Trust Tasks ([#1781](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1781))

* feat(cnm,vtc-client): send cnm git Trust Tasks over TSP, DIDComm or HTTPS

  Every signed `cnm git` command now reaches the VTC over TSP when it
  advertises it, else DIDComm, else as a signed document over HTTPS, through
  one shared connect helper (`vtc::connect_for_tasks`, which `cnm backup`'s
  end-to-end connect now also uses). The global `--transport` flag pins a
  transport; the session is closed on every path out.

  vtc-client's git-ns calls go over the session when the client holds one.
  The document is signed and bound to its sender the same way on every
  transport: over a session the key must be the session's own DID, and a key
  naming another DID is refused before anything is sent. A session refusal
  comes back as `VtcError::Refused` carrying the trust-task-error document,
  so `task_error` and `step_up_request` read the code and details alike on
  every transport (VTI-OPS-021/093).

  vta-sdk gains `VtaClient::dispatch_trust_task_document`, which answers the
  whole reply document (refusals included) rather than its payload.

  The admin listings (namespace list, repos, view --admin, break-glass-list)
  are console projections with no git-ns Trust Task and stay HTTPS admin reads.

- **cnm**: Send cnm access Trust Tasks over TSP, DIDComm or HTTPS ([#1780](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1780))

* feat(cnm,vtc-client): send cnm git Trust Tasks over TSP, DIDComm or HTTPS

  Every signed `cnm git` command now reaches the VTC over TSP when it
  advertises it, else DIDComm, else as a signed document over HTTPS, through
  one shared connect helper (`vtc::connect_for_tasks`, which `cnm backup`'s
  end-to-end connect now also uses). The global `--transport` flag pins a
  transport; the session is closed on every path out.

  vtc-client's git-ns calls go over the session when the client holds one.
  The document is signed and bound to its sender the same way on every
  transport: over a session the key must be the session's own DID, and a key
  naming another DID is refused before anything is sent. A session refusal
  comes back as `VtcError::Refused` carrying the trust-task-error document,
  so `task_error` and `step_up_request` read the code and details alike on
  every transport (VTI-OPS-021/093).

  vta-sdk gains `VtaClient::dispatch_trust_task_document`, which answers the
  whole reply document (refusals included) rather than its payload.

  The admin listings (namespace list, repos, view --admin, break-glass-list)
  are console projections with no git-ns Trust Task and stay HTTPS admin reads.

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

- **cnm,vtc-client**: Send cnm git Trust Tasks over TSP, DIDComm or HTTPS ([#1778](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1778))

Every signed `cnm git` command now reaches the VTC over TSP when it
  advertises it, else DIDComm, else as a signed document over HTTPS, through
  one shared connect helper (`vtc::connect_for_tasks`, which `cnm backup`'s
  end-to-end connect now also uses). The global `--transport` flag pins a
  transport; the session is closed on every path out.

  vtc-client's git-ns calls go over the session when the client holds one.
  The document is signed and bound to its sender the same way on every
  transport: over a session the key must be the session's own DID, and a key
  naming another DID is refused before anything is sent. A session refusal
  comes back as `VtcError::Refused` carrying the trust-task-error document,
  so `task_error` and `step_up_request` read the code and details alike on
  every transport (VTI-OPS-021/093).

  vta-sdk gains `VtaClient::dispatch_trust_task_document`, which answers the
  whole reply document (refusals included) rather than its payload.

  The admin listings (namespace list, repos, view --admin, break-glass-list)
  are console projections with no git-ns Trust Task and stay HTTPS admin reads.

- **attestation**: The TEE attestation reads are public Trust Tasks, over any transport ([#1776](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1776))

* feat(attestation)!: the TEE attestation reads are public Trust Tasks, over any transport

  A TEE VTA answered three attestation reads only as unauthenticated REST routes
  (`GET /attestation/status`, `GET`/`POST /attestation/report`,
  `POST /attestation/config-report`), plus a bare DIDComm protocol arm that
  nothing sent to. Under the rule that every remote API is a spec-first,
  spine-dispatched Trust Task reachable over TSP, DIDComm and HTTPS, they are now
  `vta/attestation/{status,report,config-report}/0.1` (trustoverip/
  dtgwg-trust-tasks-tf#654, trust-tasks-rs 0.23.2), dispatched on the spine.

  Public tasks
  - `vta_sdk::trust_tasks::PUBLIC_URIS` names the tasks a caller may send with no
    identity: no session, no ACL entry, no request proof. A verifier asks before
    it trusts the VTA; the nonce bound into the evidence is what makes a report
    its own, and every response is the VTA's signed operational document.
  - HTTPS: `/trust-tasks` takes an optional credential. An anonymous caller may
    send only a public task (anything else is 401), capped at 64 KB, and those
    requests are charged to the unauthenticated limiter — which charges only
    requests presenting no credential, decided by the extractor's own rule
    (`vti_common::auth::extractor::presents_credential`), so a junk header cannot
    move a request between the two classes.
  - DIDComm/TSP: a sender the ACL does not know gets a zero-authority claim for a
    public task, and `bind_document_to_sender` accepts it unsigned — the spec
    makes the request proof OPTIONAL and HTTPS accepts it unsigned, so refusing it
    here would make the requirement depend on the transport (VTI-OPS-021). An
    attached proof is still verified and bound.
  - A census (`every_public_task_is_proof_optional_and_read_only`) fails if a task
    whose spec requires a proof, or whose dispatch class changes state, discloses
    a secret or acts as its subject, is ever added to `PUBLIC_URIS`.

  Behaviour
  - `report` and `config-report` require a 32-byte verifier nonce; the cached,
    nonce-less report is not carried over — evidence nobody asked for is evidence
    anybody can replay.
  - Failures carry the specs' declared codes: `notAttested` (no provider),
    `noConfigSnapshot` (only the enclave front-end captures one),
    `evidenceUnavailable` (the platform refused a quote).
  - The VTA still requires `issuedAt` on every document (bounding its replay
    record), stricter than the spec; the deploy README examples send it.

  Removed (breaking)
  - The REST routes above and the DIDComm `firstperson.network/vta/1.0/
    attestation/*` arms, with their SDK constants; `TASK_ATTESTATION_{STATUS,
    REPORT}_1_0` become `TASK_ATTESTATION_{STATUS,REPORT,CONFIG_REPORT}_0_1` and
    leave `REST_ROUTED_URIS`.
  - The `TeeAttestation` DID-document service, which pointed at the REST route
    (user decision: removed, not re-pointed). `tee.embed_in_did` and
    `VTA_TEE_EMBED_IN_DID` are **refused** at config load as retired, naming the
    replacement, rather than silently ignored. The shipped Nitro configs drop the
    key; the deploy scripts' health hints point at `/health`.

- **sdk**: Remove the last legacy backup and webvh surfaces; realign-keys is a Trust Task ([#1783](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1783))

* feat!: remove the last legacy backup and webvh surfaces; realign-keys is a Trust Task

  Every remote API is a spine-dispatched Trust Task over TSP, DIDComm and
  HTTPS. What was left off the spine on these two surfaces was deprecated,
  and most of it could no longer succeed anywhere. Test deployments carry no
  compat, so it is deleted rather than refused.

  Backup
  - SDK `backup_export`, `backup_import`, `backup_import_with` (deprecated
    since 0.21.3 / 0.49.0), the `backup-management/1.0` message constants, and
    `ExportRequest` / `ImportRequest`.
  - `pnm backup {export,import} --use-rest-legacy`. It could not work on any
    transport: the VTA answered 403 over REST (VTI-VTA-003), and the SDK's
    `rpc` refuses DIDComm and TSP. Its doc said "works only over DIDComm".
  - The VTA's `POST /backup/{export,import}` and the VTC's
    `POST /v1/backup/{export,import}`, which only ever answered 403. A backup
    is the `vta/backup/*` (VTA) or `vtc/backup/export` + `backup/*` (VTC) Trust
    Tasks, over an end-to-end transport only; that policy is unchanged.

  webvh
  - SDK `update_did_webvh` / `rotate_did_webvh_keys` (the `(context, scid)`
    forms, deprecated since 0.20.32) and their message constants. The by-DID
    `update_did_webvh_by_did` / `rotate_did_webvh_keys_by_did` are the only
    forms.
  - The VTA's `POST /contexts/{ctx}/dids/{scid}/{update,rotate-keys}` and
    `POST /webvh/dids/{did}/realign-keys`.
  - `realign_did_webvh_keys` was REST-only "deliberately". The reason was out of
    date: the VTA already dispatched `webvh/dids/realign-keys/1.0`. The SDK now
    sends the task, so `pnm did-mgmt dids realign-keys` works over TSP and
    DIDComm too.

  Tests
  - The REST behaviour tests for update and rotate (metadata-only update,
    document update, rotate, unknown DID, invalid document) are ported to
    `/trust-tasks`. The removed routes are held gone.
  - The webvh REST-parity consent test is dropped. The Trust Task consent path
    it compared against is covered by the rest of `delegated_consent_e2e`.
  - `mock_vta` drives the by-DID update.

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

- **vtc**: List a member's step-up passkeys as auth/passkey/admin-list/0.1 ([#1779](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1779))

* feat(vtc/git-ns): separation of duties and break-glass for elevated git rights

  Implements trustoverip/dtgwg-trust-tasks-tf#641.

  - Fixed rule 7: no elevated self-grant (git.ns.admin, git.repo.create,
    git.repo.own) through grant 0.1/0.3, drift adopt, repo/adopt or reseat;
    refused git-ns:selfGrantNotAllowed, naming cnm git break-glass.
  - git-ns/right/break-glass/0.1: grant authority, or a community admin on a
    headless namespace; always an operation-bound passkey step-up
    (acl::bound_step_up, whose spent mark now yields its evidence); mandatory
    justification; immediate, no expiry; flagged breakGlass on the record.
  - git-ns/right/ratify/0.1 and revoke 0.3: another administrator ratifies,
    bound to breakGlass.at; any community admin may revoke an unratified one,
    which policy cannot refuse. Unratified records do not count toward the
    last-owner and last-admin invariants.
  - Visibility no policy can turn off: AuditEvent::GitNsBreakGlass at
    AuditSeverity::Critical with the step-up evidence, activity items, a signed
    git-ns/right/break-glass-notice/0.1 to every community admin and ns admin,
    view 0.4, GET /v1/git-ns/break-glass, and breakGlass on the rights rows.
  - git_ns.rego settings: break_glass (enabled by default), a delay and a
    minimum justification; deny decisions on right.breakGlass and right.ratify.
  - cnm: git break-glass, git ratify and git break-glass-list; git view flags
    break-glass rights; grant and revoke move to 0.3.

- **vtc**: Step-up passkeys a member enrols through an admin's invite ([#1756](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1756))

* feat(vtc/git-ns): separation of duties and break-glass for elevated git rights

  Implements trustoverip/dtgwg-trust-tasks-tf#641.

  - Fixed rule 7: no elevated self-grant (git.ns.admin, git.repo.create,
    git.repo.own) through grant 0.1/0.3, drift adopt, repo/adopt or reseat;
    refused git-ns:selfGrantNotAllowed, naming cnm git break-glass.
  - git-ns/right/break-glass/0.1: grant authority, or a community admin on a
    headless namespace; always an operation-bound passkey step-up
    (acl::bound_step_up, whose spent mark now yields its evidence); mandatory
    justification; immediate, no expiry; flagged breakGlass on the record.
  - git-ns/right/ratify/0.1 and revoke 0.3: another administrator ratifies,
    bound to breakGlass.at; any community admin may revoke an unratified one,
    which policy cannot refuse. Unratified records do not count toward the
    last-owner and last-admin invariants.
  - Visibility no policy can turn off: AuditEvent::GitNsBreakGlass at
    AuditSeverity::Critical with the step-up evidence, activity items, a signed
    git-ns/right/break-glass-notice/0.1 to every community admin and ns admin,
    view 0.4, GET /v1/git-ns/break-glass, and breakGlass on the rights rows.
  - git_ns.rego settings: break_glass (enabled by default), a delay and a
    minimum justification; deny decisions on right.breakGlass and right.ratify.
  - cnm: git break-glass, git ratify and git break-glass-list; git view flags
    break-glass rights; grant and revoke move to 0.3.

- **vtc**: Serve acl/{show,list,update,revoke} as Trust Tasks on the spine ([#1772](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1772))

* feat(vtc)!: serve acl/{show,list,update,revoke} as Trust Tasks on the spine

  The VTC served only acl/grant and acl/change-role as signed Trust Tasks;
  reading an entry, listing the ACL and revoking one existed only as bearer
  REST routes, so the VTI-ACL-050 full-cover check on revoke lived on one
  door and a community could not take authority away over TSP or DIDComm.

  Server (vtc-service)
  - acl/show, acl/list, acl/update and acl/revoke are dispatched by the
    spine (trust_tasks/acl_tasks.rs). Authority is the verified signer's ACL
    row at execution time; payloads are validated against the generated
    trust-tasks-rs schemas.
  - One code path: routes::acl::{list_entries, show_entry, revoke_entry,
    plan_update} are the operations; GET /v1/acl, GET and DELETE
    /v1/acl/{did} are thin adapters over them.
  - acl/update is planned by plan_grant with the role held fixed, so it
    inherits VTI-ACL-052 (no self-modification), VTI-ACL-050 (full cover)
    and VTI-ACL-053 (bounded by the granter). It refuses a missing entry
    (acl/update:notFound), a narrowing (acl/update:narrowingNotPermitted),
    a role (acl/update:roleChangeNotPermitted), and the VTA-only members
    allowedKeys/approve/stepUp. Widening an admin needs the bound passkey
    gesture, and community-wide authority another admin's consent, through
    the same gate acl/grant uses (settle_signed_gate).
  - acl/revoke emits acl/revoke:subjectNotPresent and
    acl/revoke:lastAuthorityProtected, and now revokes the subject's live
    sessions on a full removal too.
  - acl/list gains `direction` (acting-in, subtree, any).
  - acl/grant: restating an admin with a later or no expiry now counts as
    widening (needs the gesture); a rewrite that reduces authority revokes
    the subject's sessions; the audit row names the actual actor rather
    than the entry's original creator, and an update is audited as
    AclUpdated.

- **credential-exchange**: Every step is a signed Trust Task on the spine, over any transport ([#1771](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1771))

Every credential-exchange step — offer, request, issue, query, present — and
  the VTC's `vtc/members/request-vmc` and `join-requests/submit-receipt` pushes
  were bare DIDComm messages typed as their task URI, served beside the binding
  envelope. `bindings/didcomm/0.2` §2 requires a consumer to refuse that
  carriage; it skipped the spine's proof, freshness, recipient and replay checks;
  and no transport but DIDComm could carry it. They were never missing a TSP
  binding. Each is a signed Trust Task now.

  VTC
  - Pushes `offer`, `issue`, `query`, `request-vmc` and `submit-receipt` through
    the durable push engine (TSP > DIDComm > REST, escalating on no delivery
    evidence) as documents signed with its operational key under
    `authentication` — `credentials::delivery::push_document`, the one outbound
    funnel. `AppState::send_to_member` and `push_to_holder` are gone.
  - Serves `credential-exchange/request` and `present` on the dispatcher, from
    every transport. None of the five steps defines a response, so what goes
    back on the carrying transport is the SPEC §4.4.2 empty `#response`
    acknowledgement; the answer is the next step, pushed on the thread (`issue`
    after `request`, threaded on the offer; `submit-receipt` after `present`,
    threaded on the query, to whoever sent it).
  - The bare `request`/`present` arms are deleted; typed as themselves they are
    refused naming the envelope.
  - The git-ns break-glass notice ([#1745](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1745)) was the last caller of the removed
    DIDComm-only send; it now goes through the push engine too, signed with the
    operational key under `authentication` like the removal notice it copies.

  VTA (holder)
  - Serves `offer`, `issue` and `query` on the spine and pushes `request` and
    `present` back. They are counterparty tasks: an issuer or verifier holds no
    ACL entry here, so they dispatch on a zero-authority claim beside the
    ceremony carve-out (`is_counterparty_task`), and each handler acts with the
    VTA's own authority under the gate it always had — an offer only with a
    configured `credential_holder_did`, a presentation only to a trusted verifier
    or after operator approval.
  - This restores `query`, whose bare arm #1739 deleted, leaving a holder that
    could not answer a verifier. A deferred query is answered with silence (an
    acknowledgement would claim a task not yet performed); `pending-approve` now
    also pushes the `present` to the verifier on the query's thread.
  - The bare `offer`/`issue` arms are deleted. The helpers only the TEE
    attestation arms still use are gated on `tee` until those arms go.

  Breaking (wire): a holder or wallet must read the pushed documents and send
  `request`/`present` as signed documents with `threadId`. openvtc #392 is the
  companion and is merged.

  Not fixed here, found on the way: the push engine carries one signed document
  for the whole delivery window, while a receiving VTA refuses an `issuedAt`
  older than ten minutes, so a holder offline when its credential is pushed gets
  it `expired` (removal notices share this). And a counterparty's `issue` or
  deferred `query` still costs this VTA a durable write from any sender, as the
  bare handlers did; a floor like the ceremony one is a follow-up.

- **vtc**: Git-ns/account/unlink and cnm git unlink ([#1746](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1746))

* fix(vtc): one forge account per member, and only current members' accounts count

  - Link uniqueness (git-ns/account/link item 4) was already enforced under
    the git-ns store lock. The check and the recording are now one step
    under the member-row lock too, and a regression test pins it: a
    second member completing a link to an already-linked forge id ends
    `failed` and the account stays with the first.
  - A departed member who held no git right kept their linked accounts for
    good: the link deletion sat after sweep_departures' early return for
    "no departed member held a right". It is now its own pass in the
    lifecycle sweep (git-ns/account/link, Consent/purpose: MUST delete it
    when the member leaves).
  - linked_accounts, which the role projection and drift adoption read,
    now holds only current members' accounts. A member whose access lapsed
    but who has not left keeps the account, so nobody else can link it,
    but it projects no role.
  - GET /v1/git-ns/accounts gains memberCurrent, and the console's Repos
    plugin no longer offers adoption for an account whose member is not
    current. The daemon already refused that adoption.

- **vtc/git-ns**: Separation of duties and break-glass for elevated git rights ([#1745](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1745))

* feat(vtc-service): re-project git roles, and use the bridge's reported role map

  Implements two follow-ups to the configurable bridge role map (VGI #84),
  spec-first in trustoverip/dtgwg-trust-tasks-tf#639.

  git-ns/bridge/event 0.3 (roleMapReported)
  - Served beside 0.1 and 0.2; all three are read as 0.3 by one handler.
  - The report is refused malformedRequest when a map is unordered
    (own >= maintain >= commit, commit <= write) or lists a repository
    twice, and permissionDenied when a repos/stale resource lies outside
    the namespace. Otherwise it is kept on the namespace (git_ns::role_map),
    and only while the same bridge DID serves it.
  - Each stale active or orphaned repository has its roles digest
    forgotten, so the projector re-sends its complete desiredRoles without
    anyone asking. A repository leaves `stale` when a projectRoles job
    queued after the report succeeds.
  - drift/resolve adopt derives the right from the map: the lowest right
    whose role is the observed one. A revert weighs as revoking own when
    the role is at or above the one own projects to. Without a report the
    default map is assumed. A namespace admin gets no forge role under any
    map.

  git-ns/roles/reproject 0.1
  - Open to a community administrator, or to git.ns.admin on the namespace
    by explicit record. A repository owner is refused. Covers a namespace
    (every active or orphaned repository) or one repository. Normal consent
    class, policy action roles.reproject, audited as
    gitNs.roles.reprojected. Refused with manualMode or noForgeAccess.
  - `cnm git reproject <resource> [--reason]` and
    vtc-client git_ns_reproject.

  Console (Repos)
  - The namespace and repository rows carry the effective role map
    (roleMap, roleMapSource, roleMapStale).
  - The people tables show each person's effective forge role, and "no
    forge role" for a namespace admin.
  - Drift adopt and revert use projectedRight / driftRevertImpact over the
    repository's map. rightForForgeRole is removed.
  - Stale repositories are flagged, and the namespace card and repository
    header gain a "Re-project roles" button.

  Behaviour change: on a personal account a revert of collaborator write
  (or above) now weighs as revoking own, because write is the role own
  projects to there. Before, it weighed as revoking maintain.

- **git-ns**: An adoption names the member who receives the right ([#1735](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1735))

* feat(vtc-service): re-project git roles, and use the bridge's reported role map

  Implements two follow-ups to the configurable bridge role map (VGI #84),
  spec-first in trustoverip/dtgwg-trust-tasks-tf#639.

  git-ns/bridge/event 0.3 (roleMapReported)
  - Served beside 0.1 and 0.2; all three are read as 0.3 by one handler.
  - The report is refused malformedRequest when a map is unordered
    (own >= maintain >= commit, commit <= write) or lists a repository
    twice, and permissionDenied when a repos/stale resource lies outside
    the namespace. Otherwise it is kept on the namespace (git_ns::role_map),
    and only while the same bridge DID serves it.
  - Each stale active or orphaned repository has its roles digest
    forgotten, so the projector re-sends its complete desiredRoles without
    anyone asking. A repository leaves `stale` when a projectRoles job
    queued after the report succeeds.
  - drift/resolve adopt derives the right from the map: the lowest right
    whose role is the observed one. A revert weighs as revoking own when
    the role is at or above the one own projects to. Without a report the
    default map is assumed. A namespace admin gets no forge role under any
    map.

  git-ns/roles/reproject 0.1
  - Open to a community administrator, or to git.ns.admin on the namespace
    by explicit record. A repository owner is refused. Covers a namespace
    (every active or orphaned repository) or one repository. Normal consent
    class, policy action roles.reproject, audited as
    gitNs.roles.reprojected. Refused with manualMode or noForgeAccess.
  - `cnm git reproject <resource> [--reason]` and
    vtc-client git_ns_reproject.

  Console (Repos)
  - The namespace and repository rows carry the effective role map
    (roleMap, roleMapSource, roleMapStale).
  - The people tables show each person's effective forge role, and "no
    forge role" for a namespace admin.
  - Drift adopt and revert use projectedRight / driftRevertImpact over the
    repository's map. rightForForgeRole is removed.
  - Stale repositories are flagged, and the namespace card and repository
    header gain a "Re-project roles" button.

  Behaviour change: on a personal account a revert of collaborator write
  (or above) now weighs as revoking own, because write is the role own
  projects to there. Before, it weighed as revoking maintain.

- **vtc-service**: Re-project git roles, and use the bridge's reported role map ([#1736](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1736))

* feat(vtc-service): re-project git roles, and use the bridge's reported role map

  Implements two follow-ups to the configurable bridge role map (VGI #84),
  spec-first in trustoverip/dtgwg-trust-tasks-tf#639.

  git-ns/bridge/event 0.3 (roleMapReported)
  - Served beside 0.1 and 0.2; all three are read as 0.3 by one handler.
  - The report is refused malformedRequest when a map is unordered
    (own >= maintain >= commit, commit <= write) or lists a repository
    twice, and permissionDenied when a repos/stale resource lies outside
    the namespace. Otherwise it is kept on the namespace (git_ns::role_map),
    and only while the same bridge DID serves it.
  - Each stale active or orphaned repository has its roles digest
    forgotten, so the projector re-sends its complete desiredRoles without
    anyone asking. A repository leaves `stale` when a projectRoles job
    queued after the report succeeds.
  - drift/resolve adopt derives the right from the map: the lowest right
    whose role is the observed one. A revert weighs as revoking own when
    the role is at or above the one own projects to. Without a report the
    default map is assumed. A namespace admin gets no forge role under any
    map.

  git-ns/roles/reproject 0.1
  - Open to a community administrator, or to git.ns.admin on the namespace
    by explicit record. A repository owner is refused. Covers a namespace
    (every active or orphaned repository) or one repository. Normal consent
    class, policy action roles.reproject, audited as
    gitNs.roles.reprojected. Refused with manualMode or noForgeAccess.
  - `cnm git reproject <resource> [--reason]` and
    vtc-client git_ns_reproject.

  Console (Repos)
  - The namespace and repository rows carry the effective role map
    (roleMap, roleMapSource, roleMapStale).
  - The people tables show each person's effective forge role, and "no
    forge role" for a namespace admin.
  - Drift adopt and revert use projectedRight / driftRevertImpact over the
    repository's map. rightForForgeRole is removed.
  - Stale repositories are flagged, and the namespace card and repository
    header gain a "Re-project roles" button.

  Behaviour change: on a personal account a revert of collaborator write
  (or above) now weighs as revoking own, because write is the role own
  projects to there. Before, it weighed as revoking maintain.

- **vtc**: Push to a member over TSP once it has spoken TSP here, when its DID document says nothing ([#1765](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1765))

A member whose DID document advertises no transport — a `did:key` wallet,
  which cannot carry services — was always pushed to over DIDComm, even when it
  was demonstrably listening on TSP. The VTA already solved this for device
  push by learning from inbound (`tsp_reach`): a verified TSP frame proves the
  sender is on TSP now. The VTC had no equivalent.

  - `TspReachability` moves from vta-service to `vti_common::tsp_reach` so both
    nodes share one. The VTA re-exports it at its old path, unchanged.
  - The shared push engine (`vti_common::trust_task_push`) takes it through
    `PushContext::learned_tsp`. A recipient whose document advertises nothing
    is tried over TSP first while fresh, with DIDComm behind it. A peer that
    switched back gives no error on TSP, only silence, and escalation on
    missing evidence is what recovers. What a document does advertise still
    wins: learning only fills in for one that says nothing.
  - The VTC records the verified sender of every inbound TSP frame
    (`handle_tsp`) in `AppState::tsp_reach`, and `member_push` passes it to the
    engine.

- **vta-service**: Sign operational documents with the operational key ([#1740](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1740))

* fix(vta-service)!: require a document proof bound to the sender on every DIDComm and TSP trust task

  A Trust Task that reaches the VTA or the VTC over an intrinsic-sender
  transport (DIDComm, TSP) is now accepted only when the document carries a
  Data Integrity proof that verifies as its `issuer`, and that issuer is the
  transport-reported sender. The transport's sender alone no longer
  authorizes anything (VTI-OPS-021/093).

- **vtc/git-ns**: A namespace admin gets no forge role; bridge jobs are git-ns/bridge/job 0.4 ([#1729](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1729))

* fix(vtc/git-ns): a namespace admin gets no forge role

  Role projection counted what git.ns.admin implies, so every namespace
  admin went to the bridge as git.repo.own on every repository, and the
  namespace-level projectRoles job listed them as organisation owners,
  which the bridge always refused notCapable.

  desiredRoles now carries, per person, the highest right recorded in their
  own name: own, maintain or commit.sign on the repository, or commit.sign
  on its namespace. A namespace admin with none of those is sent as
  git.ns.admin, which the bridge maps to no role, so a stale role it manages
  is taken off instead of left in place. An admin who is also an explicit
  owner is still sent as the owner. The namespace-level job is no longer
  sent, and a reseat no longer queues it.

  Drift follows: a roleChanged adoption compares against the projected
  right rather than the implied one, so a namespace admin's forge admin role
  can be adopted as own; and reverting a roleAdded role held by an admin
  with no right of their own drops them from desiredRoles and names them in
  removeAccounts only.

  The admin console's grant and reseat previews no longer say an ns.admin
  is projected onto the forge.

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

- **vtc**: Member pushes follow TSP > DIDComm > REST, with escalation (VTI-TRN-042) ([#1754](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1754))

* feat(vtc): member pushes follow TSP > DIDComm > REST, with escalation (VTI-TRN-042)

  Every Trust Task the VTC pushed to a member went out over DIDComm, whatever the
  recipient advertised: removal notices, task-consent requests, granted notices.
  The workspace rule is that the DID document is authoritative, and the transport
  is the highest-preference one both parties speak, TSP > DIDComm > REST. This
  makes the VTC follow it for pushes. It is the Phase B flip that
  `docs/05-design-notes/tsp-enablement.md` §14 Q4 had deferred.

- **vtc**: Tell the requester when unrestricted-admin consent is granted (VTI-APV-014) ([#1751](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1751))

A requester waiting on another admin's consent had to re-send the operation to
  find out it had been approved. Once enough approvers have approved, the VTC
  now sends the requester `task-consent/granted/0.1` over DIDComm, the same
  notice the VTA sends. The requester can send the operation again straight
  away instead of polling.

  - VTC-signed. The specification makes the proof optional, and this service
    signs every document it originates.
  - Threaded on the ceremony's `correlator`, the value the refusal handed the
    requester, never on the digest (framework 0.5.0, identifier correlation).
  - Carries the salted `payloadDigest` and the `taskType`, and is validated
    against the generated schema before it is sent.
  - Advisory and best-effort. The single-use grant found on re-send is still the
    authorization. A failure to build or send the notice is logged and never
    fails the decision, and a denial sends no notice, as the specification
    requires.

  `tests/consent_granted_didcomm.rs` (`didcomm-harness`) drives the consent to
  a grant and holds the notice at the requester's end of a real mediator.

- **vtc**: Install a co-admin, and audit the offline ACL break-glass (VTI-APV-014) ([#1750](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1750))

Last of four for VTI-APV-014. Since #1741, making anyone an unrestricted
  admin needs another unrestricted admin's consent. That left two gaps.

  A community installed with one unrestricted admin has nobody to consent, so
  it could only add a second offline. `vtc setup` now takes an optional
  `co_admin_did` (a prompt interactively) and refuses one equal to the first
  admin. The install bootstrap writes the co-admin as an unrestricted admin in
  the same step as the first, audited as `AclGranted` by `did:key:vtc-install`.
  The co-admin needs no passkey to consent, since a decision is a document its
  DID signs. It gets the empty admin sister record a promotion writes, so it can
  enrol a passkey later through an invite.

  The offline ACL writers are the way out when there are too few admins. They
  skip the step-up, the consent and the attrition rules by design, and they left
  no trace: `vtc acl add` and `remove`, `vtc create-did-key --admin` and `vtc
  admin invite`. Each now queues a record in the `install` keyspace in the same
  store session as the write. On its next boot the daemon writes an
  `AclBreakGlassWritten` audit row for each, under `did:key:vtc-break-glass`,
  naming the command, the change, the DID and the host. This is how the
  emergency-bootstrap marker already works, because the offline commands hold no
  audit writer.

  The new audit variant is additive (`AuditEvent` is `#[non_exhaustive]`).

- **vtc-admin-ui**: Show members' git rights and linked forge accounts ([#1727](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1727))

* feat(vtc-admin-ui): show members' git rights and linked forge accounts

  Design §7.1: the Members page gains each member's git rights and linked
  forge account. Until now an administrator could see who holds what only
  repository by repository, on the Repos page.

  The list gains a Git column: the member's strongest recorded right, how
  many more they hold, and their linked forge logins (the forge id on
  hover, since the login is display only). A member's page gains a Git
  rights card: each recorded right with its resource (repositories link to
  their Repos page), granter (flagged when departed, or role-derived) and
  expiry (flagged within 14 days), and each linked account with its forge
  id and when it was linked.

  Both read GET /v1/git-ns/rights and /v1/git-ns/accounts under the Repos
  plugin's query keys, once for the whole page. Those need a community
  administrator, so for a scoped administrator the column is dropped and
  the page says why.

- **vtc-admin-ui**: Adopt drift through git-ns/drift/resolve ([#1728](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1728))

* feat(vtc-admin-ui): adopt drift through git-ns/drift/resolve

  Adopt on a drift item built a plain git-ns/right/grant. It now sends
  git-ns/drift/resolve 0.1 with action adopt, carrying the same selector as
  revert (type, account forge + id, and the observed value read here), so the
  VTC adopts nothing if the forge has changed since (driftNotFound), records
  the right as the resolver's own grant, and takes the item off the
  outstanding drift itself. An optional reason becomes the right's reason.

  The right shown is the one the server projects: the review noted Adopt used
  rightForForgeRole, which read write/push as commit.sign, so on a personal
  account write said "No git right corresponds" where the VTC projects
  maintain. It now uses projectedRight (git_ns::drift::projected_right), and
  rightForForgeRole, which had no other caller, is gone.

  adoptStanding mirrors git_ns::drift::adopt, in its order: an active or
  orphaned repository; git.repo.own on it, explicit or implied; a roleAdded or
  roleChanged item (notAdoptable otherwise); an account a member linked
  (accountNotLinked); a right projecting to the observed role
  (noMatchingRight); for roleChanged, a raise over what the member already
  holds, explicit or implied and unexpired (a lowering is notAdoptable,
  accepted by revoking); and the grant's consent class, which right_grant_via
  gates as right.grant, so adopting own is elevated and needs a community
  administrator. Offered to the same viewers as revert; others see why and
  the cnm git drift resolve <resource> adopt command, quoted fish-safe.

- **vtc-admin-ui**: Revert drift on a repository through git-ns/drift/resolve ([#1725](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1725))

A drifted repository's Drift card now offers "Revert to the VTC's state" on
  each item: a signed git-ns/drift/resolve 0.1 task with action revert, which
  has the bridge re-apply the VTC-authoritative state (take off a forge role
  the projection does not give, re-project a missing or changed role,
  re-apply the ruleset and required check, or re-run the bootstrap plan) and
  changes no right. The item is selected as the spec selects it: by type, by
  account (forge + id) for the role types, and by the observed value read
  here, so a revert decided about one forge state is refused (driftNotFound)
  rather than applied to another. An optional reason goes to the audit record.

  It is offered only where the VTC would accept it, mirroring
  git_ns::drift::drift_resolve and revert:
  - the namespace is in bridge mode (a manual one answers notRevertible);
  - the repository is active or orphaned;
  - the session's DID (whose git rights a console key acts under) holds
    git.repo.own there, explicitly or implied by the namespace's git.ns.admin;
  - a revert that weighs as revoking own (taking an admin role off the forge)
    also needs a community administrator, as consent_gate does under
    elevated_requires_admin.
  Anyone else sees why, and the cnm git drift resolve command to hand to an
  owner, quoted with the shell-safe shellQuote from #1723.

  The consent class mirrors the server: a drift revert is gated as the
  right.revoke it amounts to, so consentClass("drift.resolve", impact) classes
  it by that impact. The drift/resolve URI joins the trust_task_manifest
  signed-document census, and the activity feed names gitNs.drift.resolved.

- **vtc**: The backup/* chunked transfer on the signed door ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#1724](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1724))

`vtc/backup/import/0.1` carries the whole encrypted envelope in one document,
  which no real community's backup fits inside the 64 KiB the signed door accepts
  before it has checked a proof. So it was the one admin verb #1641 could not move
  off its bearer route. The node-neutral `backup/*` family
  (trustoverip/dtgwg-trust-tasks-tf#633, trust-tasks-rs 0.22.7) moves a backup as a
  bundle of small signed documents instead, and #1721 put the transfer the agent
  already ran into `vti_common::backup_transfer` so this node runs the same code.

  This dispatches all seven tasks on the signed door, over REST, DIDComm and TSP:

  - `initiate-export` encrypts the community exactly as `vtc/backup/export` does
    (`routes::backup::export_inner`, which audits `BackupExported`), stages the
    bytes and returns the chunk manifest; `get-chunk` serves one chunk by index;
    `complete-export` releases the bundle and deletes its bytes.
  - `initiate-import` commits to a manifest before any byte moves; `put-chunk`
    checks each chunk against its committed digest before writing it;
    `finalize-import` checks every chunk is present and the assembled bytes are
    the committed ones, then previews or applies exactly as `vtc/backup/import`
    does (`routes::backup::import_inner`, split out of the bearer route and
    auditing `BackupImported` on a commit), answering the per-keyspace `counts`.
  - `abort` cancels either.

  Only `chunkedTrustTask`: this node publishes no blob endpoint, so `stream`, named
  or meant by absence, is refused `transportUnavailable`, as the specification
  requires of a recipient that recognises the algorithm but cannot serve it.
  Chunks are at most 32 KiB, the largest whose `put-chunk` document fits the door.
  A larger import manifest is `chunkSizeUnacceptable`, and an export never uses
  larger chunks. A test pins that a full-size chunk's document fits.

  Authority is an unrestricted administrator's, from the signer's ACL row, as
  `vtc/backup/{export,import}` require, and a bundle belongs to whoever opened it:
  another administrator's handle is `notFound`. The shared export and import raise
  `vtc/backup/*` declared codes; the two this family names differently are renamed
  (`weakPassword`, `decryptionFailed`), and any other goes out as its underlying
  error rather than under another task's code.

  Bundles live in a new `backup_bundles` keyspace, excluded from backup, with
  bytes staged owner-only under `<data_dir>/backups`; the retention sweeper runs
  the shared bundle sweeper.

  Over REST, `/v1/trust-tasks` is behind the per-IP unauthenticated limiter,
  which bounds a chunked transfer there to about 12 chunks a minute. DIDComm and
  TSP are not behind it. The operator guide says so.

  Tests (`trust_tasks::backup_tasks`): a community backup round-trips chunk by
  chunk — export, upload at a different chunk size, preview writes nothing, commit
  restores a removed row; `stream` and an unknown algorithm; an oversized chunk
  size; a full-size `put-chunk` document fits the door; a scoped administrator is
  refused; another administrator's bundle is `notFound`; an incomplete upload
  names what is missing; a wrong password is `decryptionFailed`.

- **vtc-admin-ui**: Reseat a headless git namespace ([#1722](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1722))

The headless-namespace finding said reseat would work once this VTC
  serves it; it does (git-ns/namespace/reseat 0.1). The finding now says
  what a reseat is: a community administrator seats a current member as
  namespace admin, with a required statement kept in the audit record,
  refused while the namespace has any live git.ns.admin.

  A headless namespace card offers Reseat (destructive class): a member
  picker for the subject, a required statement, and the SignTaskDialog
  showing the subject and namespace, confirmed before a console key signs
  it, or handed over as cnm git reseat otherwise. The reseat URI joins the
  trust_task_manifest document-type census, and consent_class classes
  namespace.reseat destructive so the console mirror stays exact.

- **vtc**: Acl/change-role on the signed door, with a promotion's gesture bound to it ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#1719](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1719))

The second of the three verbs gated on a passkey gesture moves onto the
  signed-document door, behind the operation-bound step-up #1718 built for
  `acl/grant` (`vtc-operation-bound-step-up.md`, VTI-APV-015).

  A promotion is the role-change ceremony, whose host invariant `StepUpForAdmin`
  reads a `step_up` fact the pipeline resolves itself — #1645 took that boolean
  away from callers. The pipeline now takes a `StepUpSource`: the bearer route's
  live session, as before, or a gesture bound to the operation. On the bound
  source it decides as if the gesture were present and acts on that verdict only
  after spending the mark, under `PROMOTE_LOCK`, so:

  - a promotion the policy or another invariant refuses is refused for that
    reason and never asks for a passkey it could not use;
  - a promotion nothing else refuses, with no gesture recorded, is refused
    `permissionDenied` with the ceremony inline (`details.stepUpRequest`), and the
    identical document, re-sent after `approve-response/0.4` records the gesture,
    completes;
  - a gesture recorded for a grant does not promote — the digest covers the
    task's type.

  `update_acl`'s body is now `routes::acl::change_role_inner`, shared by both
  doors: the `fromRole` compare-and-swap, the scope checks, the ceremony, the
  admin sister record, session revocation on a privilege reduction and the audit
  rows. On the signed door `AdminPromoted.authorising_session_id` is empty; the
  gesture is the `OperationStepUpRecorded` row under the same actor.

  The signed `acl/grant` handler also checks `require_manage()` explicitly, the
  bearer route's `ManageAuth`. `plan_grant`'s role checks already refused every
  role it refuses, so this states the gate rather than closing a gap.

  Tests (`tests/signed_step_up.rs`, 15 now): the promotion loop end to end, a
  grant's gesture not authorizing a promotion, a stale `fromRole` as the
  conflict, a demotion needing no gesture, and a member refused — including
  promoting themselves — without being asked for one.

  Left in the design note's order of work: VTI-APV-014's second-party consent,
  console-key enrolment once `auth/signing-key/*` is published, then retiring the
  bearer routes.

- **vtc**: Acl/grant on the signed door, with a passkey gesture bound to the grant ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#1718](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1718))

`acl/grant` is the first verb on the VTC's signed-document door that confers
  administrative authority, and the reason none had moved: conferring admin
  needs a passkey gesture, the bearer route reads that from the session's live
  elevation, and a signed document has no session. `admin_signer` builds its
  claims with an empty `session_id`, so the gate could only ever fail closed.

  The design (`vtc-operation-bound-step-up.md`, #1713) binds the gesture to the
  one operation instead, as VTI-APV-003 now permits and VTI-APV-015 describes
  (dtgwg-vti-spec#40), using the wire dtgwg-trust-tasks-tf#631 published in
  trust-tasks-rs 0.22.7:

  1. A signed `acl/grant` that would confer admin authority runs every check the
     bearer route runs — the same `plan_grant` — and then finds no gesture for
     `(acting admin, digest of type + payload)`. It starts a WebAuthn ceremony
     over the acting admin's own passkeys, parks it for 300 s, and refuses
     `permissionDenied` with the ceremony inline as `details.stepUpRequest`: an
     `approve-request/0.3` payload with `boundTo` (the digest salted with the
     challenge) and no `sessionId`. The spine releases the refused document's
     `id`.
  2. The admin answers with `auth/step-up/approve-response/0.4` carrying
     `webauthn` evidence. The assertion must verify against the parked ceremony,
     assert user verification, and come from a passkey registered to the acting
     admin. The answer is `recorded`; nothing is elevated.
  3. The identical document is sent again. The recorded gesture is removed before
     the grant commits, so it authorizes that grant once and nothing else.

  A console key acts as its admin, so it can sign the grant and redeem the
  gesture, but cannot make one: only a `webauthn` assertion records a gesture,
  and a `didSigned` or absent `evidence` is refused `noGate`. The bearer route is
  unchanged and keeps its session gate; the two doors now share `plan_grant` and
  `commit_grant` and differ only in where the gesture is read from.

  - `vtc-service/src/acl/bound_step_up.rs`: the digest (`vtc/step-up/v1\0`,
    length-prefixed URI and JCS payload, SHA-256 multihash), the pending and
    redeemable marks, and the TTL sweep. New keyspace `step_up_marks`, excluded
    from backup.
  - `vti-common`: `AuditEvent::OperationStepUpRecorded` names the task, the salted
    `boundTo` and the credential. `AuditEvent` is `#[non_exhaustive]`, so the
    variant is additive.
  - trust-tasks-rs floor raised to 0.22.7 for `approve-request/0.3` and
    `approve-response/0.4`.

  `tests/signed_step_up.rs` drives the loop with the soft authenticator and holds
  the refusals the design lists: a gesture for one grant does not authorize
  another, a spent gesture is gone, a challenge is answered once, a signature
  alone records nothing, a silent (non-UV) assertion and another admin's passkey
  are refused, a grant that confers nothing asks for no gesture, and a grant that
  would be refused anyway never asks.

  One difference from the design note, recorded in its new §8: the gate is not a
  spine step ahead of dispatch. Whether a grant needs a gesture depends on the
  entry it would replace, and a gesture must not be asked for a grant another
  check would refuse, so the verb calls the gate between `plan_grant` and
  `commit_grant`. The handler is transport-neutral, so REST, DIDComm and TSP
  still reach the same call.

  `acl/change-role` is next, then VTI-APV-014's second-party consent.

- **vtc-service**: Git-ns drift/resolve, namespace/reseat, view 0.2 ([#1703](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1703))

* feat(vtc-service): git-ns drift/resolve, namespace/reseat, view 0.2

  Implements the git-ns tasks added in trust-tasks #625 and #627, on
  trust-tasks-rs 0.22.5.

  - git-ns/drift/resolve 0.1: an owner adopts a forge-side role as the
    git-ns/right/grant it is (same fixed rules, policy, consent class), or
    reverts a forge-side change through the bridge. Items are selected by
    type, account (role items) and observed (required to adopt). Every
    declared code: driftNotFound, notAdoptable, accountNotLinked,
    noMatchingRight, notRevertible, plus the family's codes.
  - git-ns/bridge/job 0.2: sent only for the revert of a roleAdded item
    (projectRoles with removeAccounts), in-line, so a bridge implementing
    only 0.1 is answered notRevertible; every other job stays 0.1.
  - git-ns/namespace/reseat 0.1: a community administrator grants a
    permanent git.ns.admin on a headless namespace to a current member,
    atomically with the headless check; notHeadless otherwise. The audit
    record keeps the statement and how earlier admin records ended.
  - git-ns/view 0.2 (served beside 0.1): the caller's own linked forge
    accounts, narrowed to the resource's forge.
  - git-ns/bridge/event 0.2 (served beside 0.1, same handler): a transfer
    detaches wherever it goes; an event any of whose resources, drift items
    included, lies outside its namespace is refused before anything is
    applied.
  - cnm: `cnm git drift resolve`, `cnm git reseat`; `cnm git view` asks for
    view 0.2. vtc-client gains the matching methods.
  - Default gitNamespace policy: namespace.reseat receives a right;
    drift.revert documented.

- **vtc-admin-ui**: Repos plugin for git namespaces ([#1696](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1696))

* feat(vtc-admin-ui): Repos plugin for git namespaces

  The admin console's view of the git namespaces #1694 adds: namespace
  cards (kind, bridge or manual mode, installation state, admins, repo
  creators, the bridge's Dependabot service grant, the active git namespace
  policy), each namespace's repositories with the four-dot VGI bootstrap
  indicator and a lifecycle-then-sync status with the action it needs
  (resolve drift, assign an owner, adopt), a repository page (people x
  rights with granter, expiry, departed-granter and external-signer flags;
  the bootstrap checklist; the guard design section 9 expects; the Trust
  Registry records it publishes, implied commit rights included; drift;
  recent activity), namespace rights, the issued-by-departed-members
  review, and the bind flow.

  Every git-ns change is a signed Trust Task authorized by the signer's own
  git rights, the daemon mounts no bearer route for any of them, and the
  console cannot sign a document yet ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)). So each action is built
  exactly as it will be sent and handed to the administrator as the
  `cnm git` command that signs it, and as the document itself where cnm has
  no command (transfer, archive). The dialog states the task's design
  section 6 consent class and how this VTC enforces it
  (`elevated_requires_admin`) rather than running a passkey step-up that
  would elevate a session the signed document never uses.

  Reads go through the eight `/v1/git-ns/*` admin routes under the
  `git-ns/view/0.1` Trust-Task header, typed from the generated wire.ts.

- **vtc**: Git namespaces — forge governance, registry projection and bridge messaging ([#1694](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1694))

* feat(vtc): git namespaces — forge governance, registry projection and bridge messaging

  A VTC now governs repositories on the forges it has bound and publishes who may
  do what there to its Trust Registry: the `git-ns/*` Trust Task family
  (trustoverip/dtgwg-trust-tasks-tf `specs/git-ns/**`, and #623 — an
  `ns.admin`'s implied `git.commit.sign` is published on the namespace).

  vtc-service `git_ns`:
  - store (`git_ns`, `git_ns_jobs`, `git_ns_projection`); rights keyed by an
    internal repository id so a forge rename moves them and a new repository at
    the old name inherits nothing; per-scope rights sets so a transfer is one
    write; every mutation under one process-wide lock (last-owner and last-admin
    are set invariants).
  - the fixed rules of `git-ns/right/grant` in code: whole-segment containment,
    level check, grant-authority table (`repo.create` not re-delegable), last
    owner, last admin, members-only floor for namespace rights.
  - `PolicyPurpose::GitNamespace` (`gitNamespace`, package
    `vtc.git_namespace`), default `git_ns.rego`: members only, no external
    signers, except the namespace bridge's own service grant. Evaluated after the
    fixed rules and able only to refuse (`git-ns:policyDenied`); carries the
    community's `settings` (maintainer grants, `cascade_on_departure`,
    `role_drift`).
  - handlers for bind, unbind, repo create/adopt/transfer/archive, right
    grant/revoke, view, account link/link-status, bridge result/event on the
    document dispatcher, proof-required per their specifications; every declared
    error code is emitted.
  - consent classes (design §6): no member step-up exists on a signed document,
    so `[git_ns] elevated_requires_admin` (default true) admits elevated and
    destructive actions only from a community administrator (VTI-VTC-021 gap,
    narrowing only).
  - an audit-tailed projector writing `registry/record/{put,delete}` (new
    `TrustRegistryClient::{put,delete}_trust_record`): one authorization record
    per live right, the implied `git.commit.sign` of every own/maintain/ns.admin,
    `context` carrying framework (VTI-REG-002), grantedBy, activeFrom/activeTo;
    a reason is never published. Idempotent against a mirror, withdraws before
    it publishes, and holds a renamed repository's new tuples until the old are
    gone.
  - lifecycle: departure revokes every git right (VTI-MEM-033), orphans
    sole-owner repositories, keeps grants a departed member issued for review
    (or revokes them under `cascade_on_departure`), deletes forge links; expiry
    and stale-binding sweeps.
  - bridge messaging: `git-ns/bridge/job` signed and sent over TSP or DIDComm by
    service type, acknowledged through `PendingReplies`; durable queue (role
    projection retries forever), results and events accepted only from the
    namespace's recorded bridge. A bound bridge namespace grants its bridge
    `git.commit.sign` on the namespace as a service grant (Dependabot re-signing).
  - read-only admin REST under `/v1/git-ns/*`, OpenAPI via new
    `vta_sdk::openapi::GitNsView01*` wrappers; `openapi.json` and `wire.ts`
    regenerated.

- **vtc-client**: The admin verbs with a signed binding are sent as signed documents ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#1709](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1709))

#1641 named two blockers to retiring the VTC's bearer routes, and this closes
  the second for every verb `vtc-client` reaches that has a signed binding: a
  join decision (`approve_join` / `reject_join`), `update_member_extensions`,
  `remove_member`, `member_credentials` and `export_backup`.

  A client built with `VtcClient::connect` already holds the operator's own
  `did:key` — it authenticated with it. The VTC authorizes a signed admin
  document from the signer's own ACL entry (`admin_signer`), so the client signs
  as the operator: no console-style delegation is involved. Those verbs now go
  **only** as documents, posted to `POST {base}/trust-tasks`, and over a DIDComm
  or TSP session they ride the session — which lifts `NoRestTransport` for them.

- **vtc**: The backup export is served as a signed document ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#1708](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1708))

#1641 phase 2, batch 5. `vtc/backup/export/0.1` declares `proof` REQUIRED and
  was served only as bearer REST. It is now bound in `DISPATCHED_URIS` /
  `dispatch_typed`, reachable over REST, DIDComm and TSP. The bearer route took
  `SuperAdminAuth`, so the signer's ACL entry must be an unrestricted admin
  (`require_super_admin`, as `members/purge` asks) — a context-scoped admin is
  refused on both doors. The bearer route stays because `vtc-client` calls it.

  - The route body moved into `export_inner`, which both doors call.
  - The reply is the whole encrypted envelope, and the spine records it against
    the document's `id`, so a redelivery is answered with the same envelope
    rather than a second export under a fresh salt and nonce. That keeps a
    second, password-encrypted copy in `accepted_ids` for the acceptance window;
    the keyspace is excluded from backup, so it cannot end up inside a later
    export.
  - The password rides in a signed, unencrypted document — no worse than the
    bearer body: REST is TLS, DIDComm and TSP encrypt end to end, and the spine
    records a document's id and digest, never its payload.

  `vtc/backup/import/0.1` does not move: its request carries the whole envelope,
  which a 64 KiB document cannot hold, and raising the cap on the unauthenticated
  chain is not the answer. The design note now sets out the fix — a chunked
  transfer session (`begin` / `chunk` × n / `commit`, each document signed and
  small, the digest checked at commit) — to be proposed in dtgwg-trust-tasks-tf
  first, since the dispatcher cannot bind an unpublished family.

  VTI-OPS-020, VTI-OPS-025, VTI-OPS-026, VTI-OPS-027.

- **vtc**: The endorsement-type writes are served as signed documents, and the console signs them ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#1705](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1705))

#1641 phase 2, batch 4. `vtc/endorsement-types/register/0.1` and
  `vtc/endorsement-types/delete/0.1` declare `proof` REQUIRED and were served only
  as bearer REST. Both are now bound in `DISPATCHED_URIS` / `dispatch_typed`,
  reachable over REST, DIDComm and TSP, with authority read from the verified
  signer's ACL row at execution time (`admin_signer`). The bearer routes applied
  exactly `AdminAuth`, so a context-scoped admin is admitted and a member refused.
  `list` declares no proof and stays where it is.

  The admin console's statement-types card calls both, so the bearer routes stay
  as documented transitional paths. The card now sends each write through
  `signedOrBearer` — the first console call site to do so — so a browser holding
  a console key uses the signed door and one without falls back; a refused signed
  call is not retried over bearer.

  - Each route body moved into `register_inner` / `delete_inner`, which both
    doors call.
  - `claimSchema` had no bound in the task or the route, so a schema between
    ~63 KiB and 1 MB registered over bearer but could not fit a 64 KiB signed
    document. The operation now caps it at 32 KiB serialised on both doors.
  - `description`'s published `maxLength: 1024` was not enforced on the bearer
    route; the signed door's schema check already held it. Both enforce it now.
  - The dispatcher panicked on a declared framework code. `register` refuses a
    `claimSchema` that is not a JSON Schema with `malformedRequest`, carried as
    `TaskError::declared` so the bearer route can put the code in its body, and
    `task_error_to_reject` read every declared code as `<slug>:<local>`. It now
    parses the code the way the framework does, so a standard code goes out as
    itself.
  - An absent `claimSchema` stays absent: the arm reads the raw payload as the
    route's `RegisterBody`, because the generated type folds absent into an empty
    map.

  VTI-OPS-020, VTI-OPS-025, VTI-OPS-026, VTI-OPS-027.

- **vtc**: The config export and import are served only as signed documents ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#1702](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1702))

#1641 phase 2, batch 3. `vtc/config/export/0.1` and `vtc/config/import/0.1`
  declare `proof` REQUIRED and were served only as flat-payload REST behind a
  bearer JWT. Both are now bound in `DISPATCHED_URIS` / `dispatch_typed`,
  reachable over REST, DIDComm and TSP, with authority read from the verified
  signer's ACL row at execution time (`admin_signer`). The bearer routes applied
  exactly `AdminAuth`, so a context-scoped admin is admitted and a member refused.

- **vtc**: Show the community DID as a QR code on the landing page ([#1698](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1698))

A wallet (Keyring first) can now add a community by scanning its DID off
  the default landing page instead of retyping a 70-character string.

  The daemon renders the code: `GET /v1/community/did-qr.svg`, public and
  unauthenticated like `public-profile`, 404 until the community profile is
  initialised. It encodes the bare DID and nothing else: the same string the
  page's Copy button copies, taken from the profile's `communityDid`. A DID
  is already a URI (scheme `did`), so no `did://` or app-specific wrapper is
  added; a phone's camera hands the scan to whichever app registers `did`.
  Rendering it server-side keeps the default site free of a build step and
  inline script, and gives an operator site under `website.root_dir` the
  same code with one `<img>` tag.

  The landing page's hero gains a pass card beside the community name: the
  QR code, "Scan with Keyring", and the DID with Copy. The community DID row
  moves out of the Daemon card into it. The code stays hidden until it loads
  (no broken image before setup), stays dark on white in the dark theme, and
  on a touch device the caption says to copy the DID, since a phone cannot
  scan its own screen. The DID text now comes from `public-profile`, the
  QR's own source, with `/health` covering only the pre-profile window.

  `qrcode` is added with the `svg` feature only; its default `image`
  feature would pull the image crate in for nothing.

- **vtc**: The admin console signs its Trust Task documents ([#1695](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1695))

* feat(vtc): the admin console signs its Trust Task documents

  Client side of #1684, against the design note in #1685 (Option A) and the
  server half merged in #1692. The console had no signing primitive at all — no
  `eddsa-jcs-2022`, no Ed25519, no `crypto.subtle.sign` — which is the single
  reason every bearer route #1641 would retire is still mounted. It has one now.

  The key. `crypto.subtle.generateKey({name:"Ed25519"}, false, …)`, stored in
  IndexedDB as `CryptoKey` objects and never as bytes. The `false` is
  load-bearing: WebCrypto sets `publicKey.[[extractable]]` unconditionally for a
  generated pair, so the raw public half still exports to derive `did:key:z6Mk…`,
  while `true` would hand the private half to any script in the origin. That is
  the defect fixed in affinidi-webvh-service#210, in the very file this was
  lifted from, so the reason is in the code and a test asserts the private key
  does not export.

  The signature is built at one seam, `lib/api.ts::postSignedTrustTask`:
  `hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document minus proof))`,
  signed through WebCrypto because the key is non-extractable, `proofValue` as
  base58btc multibase, `created` back-dated 60s. JCS and base58btc are lifted
  near-verbatim from `pnm-browser-plugin` and `did-hosting-ui`, which are the
  same code; the custody around them is not.

  Timestamps are stamped at whole seconds, and that is not cosmetic. The VTC
  verifies the proof over the re-serialised parsed document, where `issuedAt` is
  a `chrono::DateTime<Utc>` that serde writes with `SecondsFormat::AutoSi` — no
  fractional digits when the sub-second part is zero. `toISOString()` always
  writes three. A document stamped on a whole second would have verified nowhere,
  once in a thousand and never twice. `tests/console_signed_document.rs` caught
  it against the real verifier; nothing on the TypeScript side could have.

  Three calls move to `POST /v1/trust-tasks`: `vtc/members/credentials/0.1`,
  `admin-remove/0.1` and `purge/0.1`. `members/update/0.1` — the fourth #1681
  task — is not reachable from any console screen. Its 64 KiB question is
  answered anyway, and it fits: a document carrying the maximal 16 KiB
  `extensions` bag, a 256-character label and every optional member is under
  20 KiB, pinned by a test.

  Degradation is the default. A browser below the WebCrypto Ed25519 floor, or an
  operator who has not enrolled, keeps using the bearer routes; `signedOrBearer`
  catches `SigningUnavailableError` and nothing else, so a refused signed call
  propagates rather than silently retrying over the session the signed door
  exists to stop relying on. No bearer route is retired here.

  A new Signing keys screen beside My passkeys lists this operator's keys, labels
  them, revokes one, and marks the row this browser holds. `active` is the
  server's computation and is not re-derived.

  One finding for whoever owns the OpenAPI document, deliberately not fixed here:
  #1692's `ListResponse` and `RevokeResponse` collide with `admin/passkeys`'s and
  four other routes' types of the same name, so `GET /v1/admin/passkeys` now
  `$ref`s a schema describing `{consoleKeys}`. The fix is `#[schema(as = …)]`
  server-side; `wire-types.ts` records it where the stale alias was.

- **vtc**: A console signing key is a credential of the operator's admin DID ([#1692](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1692))

Server side of #1684, against the design note merged in #1685
  (`vtc-console-signing.md`, Option A). The admin console cannot author a signed
  Trust Task document, which is what keeps every bearer route #1641 would retire
  mounted — 34 of the 49 are console-reachable, including all four #1681 kept.

  A console signing key is a credential of the operator's existing admin DID, the
  way a passkey is. Not an identity of its own and not an ACL row: giving a
  console key its own admin row is self-promotion by a longer path, and #1658's
  `Invariant::SelfPromotion` (VTI-OPS-050) refuses it. What the VTC stores is a
  delegation — "console key K may act as admin DID D" — which confers no role.
  Authority remains D's ACL row, read at execution time, so the property #1681
  established (`admin_signer` never consults `sessions_ks`) survives intact.

  - `console_keys` keyspace, `console_key:<consoleDid>` → the delegation, and
    EXCLUDED_FROM_BACKUP. That exclusion is a security decision rather than
    housekeeping: a restore into a rebuilt host, a staging clone or different
    hands must not hand a browser profile the ability to sign as an administrator
    again.
  - Enrolment behind `AdminAuth` plus `acl::elevation::verified`, which reads the
    session row — a stolen session alone cannot leave a signing key behind. The
    subject is the proven caller and the body cannot name it, so self-targeted is
    the only case this surface can express. That inverts `acl/grant`'s rule
    deliberately: a delegation confers nothing, so there is nothing to promote,
    and it is a credential of your own identity.
  - `admin_signer` gains one step. A signer with no ACL row of its own may be a
    delegated console key, in which case the delegating admin's row is resolved,
    at execution time, as before. A signer that has a row is answered by that row,
    including when it refuses — tighter than the note's sketch, so a stale
    delegation cannot route around a demotion.
  - List and revoke on the passkey management model. Revocation tombstones the row
    (a burned key cannot be re-enrolled), takes effect on the next document, and
    needs no second factor: an operator who suspects a browser should not have to
    find their authenticator before disowning it.
  - `AdminConsoleKeyEnrolled` / `AdminConsoleKeyRevoked` audit events.

  No published Trust Task covers this. `device/register/0.1` registers a device as
  a consumer in its own right, with a granted `Capability` set — the shape
  VTI-OPS-050 refuses here — and `auth/passkey/*` is WebAuthn end to end. So the
  three routes are mounted without a Trust-Task binding, the same exemption
  `relationships::{suspend,restore}` carries, and `routes/admin/console_keys.rs`
  records what the upstream `auth/signing-key/{enroll,list,revoke}` family should
  be. The bodies here are already those payloads.

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

- **vtc**: The join decision and the profile edit are served as signed documents ([#1689](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1689))

#1641 phase 2, batch 2. `vtc/join-requests/decide/0.1` and
  `vtc/community/profile/update/0.1` declare `proof` REQUIRED and were served
  only as flat-payload REST behind a bearer JWT, so they got none of what the
  document dispatcher enforces: no proof, no recipient binding, no acceptance
  window, and nothing in the accepted-id record. Both are now bound in
  `DISPATCHED_URIS` / `dispatch_typed`, reachable over REST, DIDComm and TSP.

  Authorization is the verified signer's ACL entry, read at execution time
  (`admin_signer` → `acl::resolve_auth_role`), never a bearer token — this
  endpoint reads none. Checked task by task rather than copied from batch 1:
  both bearer routes apply exactly `AdminAuth` and nothing further. No
  super-admin bar, no context scoping, no vetter/admin split — a VTC community
  is one scope, and `resolve_auth_role` admits only `VtcRole::Admin`, so
  `admin_signer` returning at all is that gate. The one difference is batch 1's
  and is stricter: the ACL row is read now rather than when the session was
  minted, so an expired or removed row refuses here.

  `decide` is the first migrated verb whose second execution would be materially
  wrong rather than redundant — approving issues a membership credential and a
  role endorsement, so a replayed decision would issue two of each and strand the
  first on a status-list slot nothing points at. Nothing was added at the handler
  for it: the spine claims the document's `id` before dispatch and settles it
  after, so a redelivery is answered with the recorded response and never
  re-enters the arm, and a handler-level "have I seen this?" would be the
  check-then-act the claim exists to replace. The `notPending` refusal stays what
  it was — the answer to a second, *different* decision on an already-decided
  request.
  `vti_ops_025_a_replayed_decision_does_not_issue_a_second_credential` drives the
  redelivery through issuance and checks the credential and status-list slot the
  member ends up holding, not only the reply.

  Each route handler's body moved into a transport-free inner both doors call, so
  the two cannot answer differently; `decide_inner` takes the transport label so
  the audit row says which door a decision came through instead of claiming
  `rest` for a document that arrived over DIDComm.

  The 64 KiB cap on the signed door was checked against `profile/update` rather
  than assumed: every field the operation accepts is capped before anything is
  written (name 200 chars, description 4 000, logoUrl 2 048 and `http(s)`-only so
  a `data:` image cannot ride in it, contactEmail 320, the extensions bag 16 KiB
  measured serialised), summing to about 44 KiB at the worst encoding and nearer
  25 KiB for a realistic maximal profile. So it fits, and the cap refuses with
  413 rather than truncating.

  Both bearer routes stay, each carrying the transitional note and its removal
  point in its OpenAPI description: the admin console has no signing primitive at
  all and its second factor is a passkey, which cannot produce a Data-Integrity
  proof, so it holds no key with which to author a Trust Task document.

  One divergence found and pinned rather than fixed: the task says the nullable
  profile members may be set to `null` to clear them, and they cannot be —
  `CommunityProfileUpdate` types them `Option<Option<String>>` with no
  double-option deserializer, so serde folds `null` onto the outer `None` and the
  update reads it as "unchanged". It is the store's behaviour, identical on both
  doors, and fixing it moves both at once.

  VTI-OPS-020, VTI-OPS-025, VTI-OPS-026, VTI-OPS-027.

- **vtc**: The admin member tasks are served as signed documents ([#1681](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1681))

#1641 phase 2, batch 1. `vtc/members/{credentials,update,admin-remove,purge}`
  declare `proof` REQUIRED and were served only as flat-payload REST behind a
  bearer JWT, so they got none of what the document dispatcher enforces: no
  proof, no recipient binding, no acceptance window, and nothing in the
  accepted-id record. All four are now bound in `DISPATCHED_URIS` /
  `dispatch_typed`, reachable over REST, DIDComm and TSP.

  Authorization is the verified signer's ACL entry, read at execution time
  (`admin_signer` → `acl::resolve_auth_role`), never a bearer token — this
  endpoint reads none. Every check the REST extractors made is still made:
  `AdminAuth`'s `VtcRole::Admin` on all four, and `SuperAdminAuth`'s unrestricted
  `ActScope` on `purge`, decided through `ActScope` rather than
  `allowed_contexts.is_empty()`. Two differences, both stricter: the ACL row is
  read now rather than when the session was minted, and revocation is ACL removal
  rather than session revocation.

  Each route handler's body moved into a transport-free inner both doors call, so
  the two cannot answer differently. The accepted-id claim is the spine's —
  claim, execute, settle — so these arms are inside it.

  The bearer routes stay, each carrying the transitional note and its removal
  point in its OpenAPI description: the admin console has no signing primitive
  at all (no `eddsa-jcs-2022`, no Ed25519, no `crypto.subtle.sign`) and its
  second factor is a passkey, which cannot produce a Data-Integrity proof, so it
  holds no key with which to author a Trust Task document. Routing the bearer
  door through the accepted-id record would be a no-op: it takes a flat payload
  and a JWT, has no document `id` to claim, and no body shape that could carry a
  captured document.

  VTI-OPS-020, VTI-OPS-025, VTI-OPS-026, VTI-OPS-027.

- **vtc,room-host**: Warn on unknown and misplaced config keys (Keyring VTI-06) ([#1678](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1678))

* feat(vtc,room-host): warn on unknown and misplaced config keys (VTI-06)

  vtc-service parsed config.toml with plain toml::from_str, so a typo'd
  key, a removed setting, or a key appended below the last [table] header
  (and so filed under that table) took no effect in silence.

  Port the vta-config pattern: parse through serde_ignored, keep the
  dotted paths on AppConfig (serde(skip)), and warn on each once tracing
  is installed. The message names the full path and notes that a key
  placed after a [table] header belongs to that table. Reported, never
  rejected.

  room-host's --secrets file gets the same treatment: a typo'd [secret]
  table left the plaintext default in place without a word.

- **vtc**: The accepted-id record is shared across bindings (VTI-OPS-027) ([#1674](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1674))

VTI-OPS-027 requires the record of accepted document identifiers to be
  shared across every binding a node exposes: "A document accepted on one
  binding MUST NOT be acceptable on another." #1659 left that record as a
  process-local `InMemoryReplayGuard` reachable only from the Trust Task
  dispatcher, which is adequate while the dispatcher is the only door.

  only as flat-payload REST behind a bearer JWT onto the dispatcher, and
  the bearer routes stay as a transitional path while the admin SPA, `cnm`
  and `vtc-client` migrate. A task reachable through both doors would keep
  a record on one and none on the other, and the specification's own
  rationale says what that is worth: "the node's replay protection is
  exactly as good as its least-used transport." So this has to land
  before the first batch, not with it — otherwise the migration opens the
  hole it exists to close.

  The record is now `crate::trust_tasks::accepted_ids`, backed by the new
  `accepted_ids` keyspace. Any binding reaches it as
  `AppState::accepted_ids()`. `AcceptedIds::claim(&doc, retain_until, now)`
  answers `Acceptance::{Fresh, Duplicate, Conflict}`; a `Fresh` claim is
  settled with `AcceptedClaim::{completed, release}`, and the claim is
  `#[must_use]` and warns on drop if it is neither — an early `?` between
  the claim and the effect would otherwise burn the document id silently.
  Each phase-2 call site is that match, not a redesign.

  What a replayed id answers is unchanged, and is what SPEC §7.2
  (*Disposition of a duplicate*) asks for: the same document again is
  answered with the recorded response (or `202` while the original is
  still running, `204` where the specification defines none), never
  `taskFailed` — "the task did not fail, it already happened". A
  *different* document under a spent id is `idConflict`.

  Two properties fall out of moving into the store: the record survives a
  restart, and it is no longer capacity-evicted — the in-memory guard
  could push a live record out under a burst of distinct documents and let
  a replay through. What does not fall out is a bound, so
  `accepted_ids::sweep_expired` runs on the retention sweeper's tick and
  `claim` bounds a caller who bounded nothing. #1659's `retain_until` cap
  is unchanged: a producer-chosen `expiresAt` still cannot pin an id past
  `issuedAt + max_age + skew`.

  Claim-and-insert is atomic **within the process**. A claim is not one
  store operation — an expired record must be treated as absent, so the
  path is read, remove-if-expired, insert — and two callers racing on an
  expired record can each remove and each insert, which is the TOCTOU
  async mutex held across the claim, whose scope is the same as the
  store's own per-keyspace write locks: fjall holds an exclusive lock on
  the store directory, so a second process cannot open it. It is *not*
  cross-replica, and no shared store backend exists for the VTC to make it
  so; closing that needs a native conditional write (Redis `SET NX`,
  DynamoDB `ConditionExpression`) behind a new `KeyspaceHandle` primitive,
  at which point `claim` becomes one call to it. Said so in the module and
  in the design note rather than left to be discovered.

  No route moves here. Every assertion in `spine_proof_tests` is
  unmodified and passes against the new store.

- **vtc**: A by-DID vetter status lookup ([#1671](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1671))

The vetter listing omits a vetter with no published profile and one whose
  grant was revoked in exactly the same way: both are simply absent. An
  applicant whose vetter went quiet could not tell which had happened, and a
  vetter could not check their own standing at all (Keyring VTI-Q3, #1651).

  `vtc/vetting/vetters/show/0.1` answers by DID with `live`, `revoked`,
  `expired` or `none`, the grant's id, the timestamp that ended or will end it,
  and — for a live grant — whether the vetter is listed. That last member is
  what separates "unlisted by choice" from "not a vetter".

  Served over `/v1/trust-tasks`, DIDComm and TSP for applicants and members,
  and as `POST /v1/vetting/vetters/show` for the console. `vtc-client` gains
  `show_vetter`.

  The live case goes through the same `live_grant` lookup the listing and every
  grant check use, so "live here" cannot drift from "live there". Where a grant
  is both revoked and expired the answer is `revoked`: the community
  withdrawing trust and a grant lapsing are different statements, and a vetter
  told `expired` would reasonably ask for a renewal.

  `CheckShape` on the response enforces what one object's schema cannot — which
  members belong to which status. A response saying `revoked` while carrying
  `validUntil` and no `revokedAt` reads as an expiry to a client branching on
  members rather than status.

  Requires trust-tasks-rs 0.21.21, which publishes the spec merged as
  trustoverip/dtgwg-trust-tasks-tf#603.

- **vtc**: Deliver an invitation to the DID it admits — pushed as an offer, or as a QR ([#1648](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1648))

Keyring VTI-21 and VTI-32. `vtc/invitations/issue` returned the signed
  invitation to the inviter once and nothing carried it further, and the
  credential was too large for a QR code (the console said so).

  `vtc/invitations/deliver/0.1` (`POST /v1/invitations/deliver`, inviter
  roles) records a single-use OID4VCI offer for the invitation, bound to the
  invited DID and withdrawing any earlier one, then either sends it to that
  DID as a `credential-exchange/offer` over DIDComm (`message`; `noRoute`,
  422, when the DID advertises no DIDComm service) or returns it (`offer`).
  The offer names the credential rather than containing it, so it fits a QR
  code as an `openid-credential-offer://` link.

  The invitation is released only through `credential-exchange/request` with
  a key-binding proof by the invited DID's key, so a photographed code admits
  no one else. Two things that required:

  - Key-binding proofs now verify for a holder of any DID method: the `kid`
    resolves through the community's DID resolver (`DidVmResolver`), where
    the verifier refused anything but a `did:key`. `redeem` and
    `issue_on_request` take the resolver.
  - `POST /v1/credential-exchange/request` redeems over HTTPS, for an invitee
    with no messaging service. Unauthenticated, on the rate-limited unauth
    chain: the proof is the authority. It answers with the
    `credential-exchange/issue` payload a messaging binding sends on-thread.

  The signed invitation is kept on its registry row so it can be delivered
  later (never listed). Invitations issued before this cannot be delivered
  and say to reissue. The admin console gets Send and QR-offer buttons on
  each live invitation. AuditEvent::InvitationDelivered.

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

- **vtc**: Serve a member's credential bodies and show them in the admin console ([#1631](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1631))

`GET /v1/members/{did}/credentials`, bound to the now-published
  `vtc/members/credentials/0.1` (trustoverip/dtgwg-trust-tasks-tf#336,
  already in the locked trust-tasks-rs 0.21.11). AdminAuth. It reads the
  four fields #1213 keeps on the member row (`current_vmc`,
  `current_role_vec`, `member_vmc`, `member_vmc_bound`): no new storage and
  no new verification. `memberVmcBound` is the answer recorded at receipt,
  never recomputed.

  The response is the generated `specs::vtc::members::credentials::v0_1`
  type, documented through a new `vta_sdk::openapi::MemberCredentials01Response`
  wrapper. Bodies are carried as stored. `memberVmcReceivedAt` is only sent
  alongside `memberVmc`, because the spec says a maintainer MUST NOT send one
  without the other, and a row from before #1213 has the receipt time but no
  body.

  An unknown member gets a 404 whose body carries the spec's declared code,
  `vtc/members/credentials:notFound`, next to the usual `error` member.
  "Unknown" means what it means for `members/show`: no member row, or no ACL
  row, so a tombstoned member counts. A member who holds nothing gets a 200
  with every document absent and `memberVmcBound: false`, as the spec
  requires.

  The spec says a maintainer SHOULD record that the read happened, so every
  successful read writes a new `MemberCredentialsRead` audit event. The event
  names which documents were disclosed and never includes their contents.
  The audit write happens before the response. `AuditEvent` is
  `#[non_exhaustive]`, so the new variant does not break any consumer.

  A conformance witness checks the task. It builds its response with the
  handler's own `credentials_response`, over a row filled by the real
  `record_issued_credentials` / `record_member_vmc`, so it tests what the
  service sends rather than a hand-typed fixture.

- **vtc**: A community can ask an applicant to tell it about themselves ([#1614](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1614))

Implements trustoverip/dtgwg-trust-tasks-tf#543 (trust-tasks-rs 0.21.9),
  design note docs/05-design-notes/persona-context-first.md §5.2. A join
  manifest could ask only for credentials, so a community wanting a
  display name had nothing to put on the "what's required" screen, and
  nothing connected the join ceremony to an applicant's persona.

  - Requested attributes are one community-level row beside the branding
    (`community/requested-attributes`, backed up with it), managed with
    admin GET/PUT /v1/community/requested-attributes (audited:
    CommunityRequestedAttributesUpdated, types added/removed only), and
    published as `requestedAttributes` on join-requests/manifest/0.2.
  - join-requests/submit/0.2 accepts `attributes`. Before anything is
    stored -- before the open-request dedup -- the answers are checked:
    a required type unanswered is attributesMissing, a type the manifest
    does not request is attributesUnrequested (refused, not trimmed), both
    with details.types. Accepted answers are stored on the request and
    returned by show/list as `attributes`. They are self-asserted and are
    never fed to the join policy.
  - Only the Trust Task form carries them: the legacy REST submit's holder
    signature covers a fixed member set that does not include them, so an
    answer there would be unsigned. A community that requires one refuses
    that route with attributesMissing.
  - VtcClient::requested_attributes / set_requested_attributes, and
    `cnm vetting ask show|set --require/--optional/--purpose/--nothing`.
  - vta_sdk::openapi gains JoinManifest02RequestedAttribute, rendered from
    the specification's own schema by JSON pointer (`Name@<pointer>`),
    because the spec declares the item inline; admin-ui openapi.json and
    wire.ts regenerated.

- **vtc**: Implement vtc/join-requests/supplement/0.1 — answer a deferral in place ([#1593](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1593))

Closes the second half of Keyring's KR-03, the one `join-requests/withdraw`
  ([#1591](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1591)) left open. A community that cannot decide a request on what it was
  given defers it and says what more it needs — and the applicant had nowhere to
  put the answer. The request stays open, the dedup guard refuses a second
  application, and the only exits were withdrawing (losing your place) or waiting
  for a retention sweep neither party controls. A deferral was a dead end dressed
  as a question.

  Spec'd upstream first (dtgwg-trust-tasks-tf #526, corrected by #531, shipped in
  trust-tasks-rs 0.21.6) and implemented here against the generated types.

  ## Submit and supplement now share one definition of every verdict effect

  `apply_verdict_to_request` is extracted out of `realize_join_verdict`, which
  could not be reused as-is because it opens with `JoinRequest::new` — it decides
  a request it is creating, and a supplement decides one that already exists. The
  extraction is the point rather than a tidy-up: an admission granted by a
  supplement must mean exactly what one granted by a submission means, and two
  copies of the effect table would eventually disagree.

  The response needs no such care because it is already shared —
  `outcome_to_verdict` and `verdict_response` are submit's, and a supplement's
  `{requestId, verdict}` *is* a submission's. A client reads both with one code
  path, which is why the spec chose that shape.

  ## Vetting travels in the presentation, and the first draft of the spec said otherwise

  `vetting_facts` reads attestations out of the VP's `verifiableCredential`
  array (`vetting_credentials(vp)`). The per-request `StoredVettingFacts` row
  looks like it contradicts that — it is keyed by request id and written on every
  submit — but nothing reads it into a decision: it serves the admin view, the
  vetter sweep, and tracing a withdrawn statement to the admissions it counted
  toward.

  So a supplement that omits the attestations is one with no vetting, and this
  implementation does not quietly carry the superseded ones forward. Doing so
  would decide the request on evidence the applicant is no longer presenting —
  the same defect as merging the two presentations, by a different route. #526
  asserted the opposite; I found it writing this code, and #531 corrected the
  specification.

  ## Other decisions

  **Only a deferred request.** A `Pending` one waits on the community, not the
  applicant; accepting evidence into it would replace what a maintainer is
  mid-review on, leaving the document they were reading no longer the one they
  were asked to decide. `notAwaitingEvidence`, with an annex naming the request.

  **An invitation presented now counts.** The policy re-runs over the whole new
  presentation, and a VIC in it is part of that presentation. Consumption routes
  through the extracted applier, so the burn happens once and on the same path a
  submission's does.

  **`JoinRequestSupplemented`, not `JoinRequestSubmitted`.** Nothing was
  submitted. Conflating them would make a community's audit trail report more
  applications than it received, and lose that an admission was granted on the
  second set of evidence. `AuditEvent` is `#[non_exhaustive]`, so additive.

  ## Tests

  Five, including a dispatcher-level one pinning all three spec-declared codes.
  The deferred-only guard was verified to fail its test when removed. The
  ownership test asserts the *rendered messages* of "not yours" and "does not
  exist" are equal, not merely that both refuse — equality is what makes the task
  useless as an id oracle.

- **vtc**: Add vtc/join-requests/withdraw/0.1 — the applicant closes their own request ([#1591](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1591))

Keyring finding KR-03. An applicant could open a join request and then had no
  way to close it. A `deferred` request — the community answered `requestMore` —
  was the sharp case: it stays open forever, the dedup guard in `submit_inner`
  keeps matching the row so no resubmission is possible, and the only exit was
  to ask a community admin to reject it, which records the wrong outcome for
  what is actually the applicant changing their mind. Nothing but the retention
  sweeper ever closed it, on a schedule neither party controls.

  The task was spec'd upstream first (dtgwg-trust-tasks-tf #518, shipped in
  trust-tasks-rs 0.21.5) and is implemented here against the generated types.
  Payload, response and the `withdrawn` status all come from
  `trust_tasks_rs::specs::vtc::join_requests::withdraw` — never a local copy.

  ## Authorization is ownership, not membership

  An applicant holds neither a role nor a capability; that is what they are
  applying for. So the entitlement is that the proven caller is the applicant
  recorded on the request. `resolve_holder` supplies the proof — authcrypt
  sender on DIDComm, document proof signer on REST — exactly as `self-remove`
  does.

  ## The two refusals are shaped differently on purpose

    * A request that does not exist and one belonging to somebody else both
      answer `notFound`. Separating them would let a caller probe whether a
      given request id exists on this community — the same enumeration-
      resistance reasoning the vault read paths use.
    * An already-decided request answers `alreadyDecided`, because the applicant
      is entitled to the outcome of their own request and no retry changes it.

  Both go out as the extended codes the spec declares rather than through the
  generic `AppError` → reject mapping, which flattens `NotFound` and `Gone` into
  a bare `taskFailed` carrying only English. Telling "nothing to withdraw" apart
  from "already decided" without parsing prose is the whole reason the spec
  declares two codes, so a dispatcher-level test pins them.

  ## requestId is optional

  For the same reason it is optional on the status poll: an applicant whose
  submit response was lost never received one, and the id-less form is all they
  have. A supplied id is preferred over inferring from the caller, as the spec
  requires.

  ## Where the applicant's reason goes

  To the audit log, not onto the row. `JoinRequest` is a canonically-typed wire
  shape with no member for it, and `decision` means *refusal* — writing it there
  would make a withdrawn request read as rejected.
  `AuditEvent::JoinRequestWithdrawn` carries the reason alongside the previous
  status, and is the one join event whose actor and subject are the same party.
  `AuditEvent` is `#[non_exhaustive]`, so the new variant is additive.

  ## Also, partially, KR-04

  The same defect seen from the other side: the duplicate-submit `Conflict` said
  "withdraw or await its decision" while naming neither the status nor any
  withdraw mechanism. It now names both — `pending` is waiting on the community
  and will move on its own, `deferred` is waiting on the applicant and is the
  case this task exists for.

  KR-04's remaining half is not in this PR and needs an upstream change first:
  making that refusal a *typed* answer requires a `requestAlreadyOpen` code on
  `vtc/join-requests/submit`, which declares no such code today. Likewise the
  second half of KR-03 — letting a deferred applicant supplement the existing
  request rather than open a second one — is a task that does not exist yet.
  Both are follow-ups.

  ## Dependency

  The `trust-tasks-rs` workspace requirement moves 0.21.4 -> 0.21.5 because
  `vta-sdk` re-exports the generated module in its public API, so a consumer
  resolving 0.21.4 would not build. The three unrelated lines in Cargo.lock
  (`syn`, two `base64`) are pre-existing drift between the committed lock and
  what cargo resolves — any `cargo update` of any package rewrites them.

  A conformance witness is added in `trust_tasks/conformance.rs`, projected
  through the same generated builder the handler returns through rather than
  transcribed.

- **vtc**: Keep an active admin signed in, and make the idle timeout settable ([#1586](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1586))

An admin was thrown out of the console on a hard cliff, with no warning and
  no way to change it. The cliff was also shorter than the config suggested
  and differed by sign-in door: passkey login mints at `acr=aal2`, and the
  aal2 access TTL is a third of the base, so the cookie died after 300s —
  of wall-clock, not idle time. Working continuously made no difference,
  because the request path never wrote to the session row. The first sign of
  expiry was a request failing.

  Tokens stay short and rotating. The idle timeout becomes a separate
  server-side policy measured on `Session.last_seen`:

  - `last_seen` advances on cookie-borne requests — the console doing
    something — and not on bearer ones, which are the CLIs and service
    integrations, have no idle timeout, and would otherwise pay a store
    write per call.
  - `handle_refresh` refuses once `now - last_seen` exceeds the configured
    timeout, with its own error rather than the generic "authentication
    failed" the other auth failures share. Reaching that point proves
    possession of a valid refresh token, so there is nobody left to withhold
    the reason from, and "you were away" sends an operator somewhere
    different from "your session hit its ceiling".
  - The console renews before expiry, single-flight, and re-probes `whoami`
    before declaring a session dead — rotation is atomic, so two tabs
    renewing together means one is refused on a perfectly live session.

  Refresh no longer resets `last_seen`. It used to set it to `now`, which
  would have made the timeout unreachable: the renewal timer would push the
  deadline out on every cycle. Rotating a token is the client's timer, not
  the operator. Safe for the sweeper, which judges refresh-bearing sessions
  by `refresh_expires_at` and never reads `last_seen`.

  `/v1/auth/refresh` is no longer CSRF-exempt. That exemption was sound only
  while the sole credential was a token in the request body, which an
  attacker cannot read. A refresh cookie the browser attaches automatically
  removes the property, and a forged cross-site refresh would rotate the
  victim's token away — a logout DoS. Body-token callers carry no session
  cookie and still pass unenforced, so SDK and CLI clients are unaffected.

  `auth.admin_idle_timeout` joins the runtime config registry, bounded
  60s-86400s by a new `U64Range` kind so a scripted `config/patch` is held to
  the same limits as the console. Save is PATCH + reload, because PATCH alone
  persists the override without touching the running config.

- **vtc**: Remove a statement type from Vetting → Requirements, and say what depends on it ([#1584](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1584))

The Requirements page could register a statement type but never remove
  one. That was deliberate — the card said so — on the grounds that the
  daemon refuses to delete a type anything still references and the console
  had no view of what did.

  The half the console *can* see is the half that blocks an operator in
  practice. Peer-vetting statements are signed by vetters' own wallets, so
  they never enter this community's endorsement store; what actually depends
  on a statement type is an Accepts criterion naming it, and the Requirements
  page has already loaded every criterion. Each type now says which criteria
  require it, and Remove is disabled while any do.

  Closes a correctness gap behind the feature. `POST /v1/schemas/accepts`
  refuses a criterion whose `statementType` is not registered, but the delete
  handler only counted live endorsements — it never looked at criteria. So a
  delete could strand a criterion in exactly the state registration forbids:
  still advertising a type the community no longer recognises, and no longer
  saveable. `DELETE /v1/endorsement-types/{uri}` now gathers both references
  and reports them in one 409 rather than making the operator discover the
  second after clearing the first.

  Also fixes a documentation defect found on the way. Three structs in
  vtc-service are named `DeleteResponse`; utoipa's component registry keeps
  one, and `routes::schemas`' `{ id }` won — so `openapi.json` documented
  this route as returning `{ id }` when it returns `{ typeUri }`, and the
  console's generated `wire.ts` carried that error. Renamed to
  `EndorsementTypeDeleteResponse` and gave the path a real `operation_id`
  (it was the bare `"delete"`). The JSON body is unchanged.

  The published `spec/vtc/endorsement-types/delete/0.1` describes the 409 as
  the live-endorsement case only. The new condition adds no wire shape and
  reuses the same `endorsement-type-in-use` code, but it is behaviour the
  specification does not yet state and should reach dtgwg-trust-tasks-tf.

- **vtc**: Let a community choose whether it answers the join manifest publicly ([#1563](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1563))

The join manifest is a public read by design — an applicant has to know
  what is asked of them before they disclose anything, which is the whole of
  informed non-application — and `POST /v1/trust-tasks` answers it with no
  session at all. That is what lets someone read a community's admission
  criteria on their very first join, when they have no messaging channel to
  ask over.

  It was also unconditional. A closed or invite-only community had no way to
  say "you can learn what we require once you are talking to us", short of
  not running the endpoint.

  `GET`/`PUT /v1/community/join-discovery` is that choice, with a "Joining"
  card on the console's Community profile page. Off refuses only a caller the
  community cannot name: an identified one — a signed Trust Task document
  over REST, or an authcrypt DIDComm sender — is answered exactly as before,
  because refusing those would break the join ceremony rather than close
  anything. The refusal says how to ask rather than only that it failed.

  The default is `true`. Every community answered before this existed, and a
  default of `false` would stop answering applicants who were being answered
  yesterday, for operators who never chose it — a setting that changes
  behaviour nobody opted into is a regression with a checkbox.

  Its own keyspace row, beside `branding`, rather than a member of the
  community profile: `vtc/community/profile/show/0.1` is a published schema
  with `additionalProperties: false` and `ProfileWithStatus` flattens the
  profile into its response, so a new profile member is a new member of a
  canonical answer this service is not the place to add. The conformance
  witness caught exactly that on the first attempt, which is what it is for.
  The profile is a published description of the community; this is an
  operational choice about how one endpoint behaves.

  Turning it off is its own audit event. "When did we stop publishing our
  admission criteria, and who decided?" is a question an operator is later
  asked, and a line in a profile field-diff is a poor answer.

- **vtc**: A VTC provisioned from the v2 template issues hybrid credentials ([#1557](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1557))

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

- **credentials**: The VTC signs with every key it holds, and can hold a post-quantum one ([#1553](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1553))

Issuance, the other half of hybrid credentials. `LocalSigner` holds a list of
  signing keys rather than one, and `sign` / `sign_doc` go through `sign_multi` —
  so a credential carries one proof per key, each under the cryptosuite that key's
  own type selects.

  ## The feature flag that made all of this unreachable

  Writing the tests found it, and it is the most consequential thing in this
  change:

      affinidi-data-integrity = "0.7"        # no features — `ml-dsa` OFF

- **credentials**: Every VTC verification path reads a proof set ([#1550](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1550))

The follow-up #1548 promised. All six remaining single-proof readers are
  converted, so no `vtc-service` path now rejects a hybrid credential as
  malformed.

  ## Three of them had a latent bug the array case would have hidden

  `recognition/verify` (both sites) and `routes/relationships` read
  `verificationMethod` off the **raw JSON**:

      let vm = proof_value.get("verificationMethod").and_then(|v| v.as_str())

  For an array that is `None`, so on a hybrid document the issuer-binding check
  was not merely unperformed — it was **unreachable**. Each now reads the parsed
  proof's own field, which is correct and also the more direct source.

  Worth stating plainly because it is the argument for having done these one at a
  time rather than as a bulk edit: a mechanical swap of the parse line would have
  left three binding checks reading a field that no longer existed.

  ## Two needed more than a swap

  **`credentials/exchange/verify`** derives `holder_did` from the proof and uses
  it downstream. It now comes from `accept_any`, which has already refused a set
  whose verifying proofs disagree about the signer — so there is exactly one
  answer rather than "whichever proof came first". `proof_purpose` is checked on
  every proof: a presentation carrying one `authentication` proof beside an
  `assertionMethod` one is ambiguous about what the holder attested, and the
  permissive reading is the dangerous one.

  **`routes/members/personhood`** resolves the holder's DID document once and
  looks up each proof's own verification method within it. A hybrid holder's two
  keys are both found, and no proof can reference a method belonging to another
  DID because the document searched is always the holder's.

  ## The status list deserves its own note

  `recognition/verify`'s second site verifies a **status list** — the document
  that decides whether a credential is revoked. A proof set mixing issuers there
  is exactly the substitution attack the URL-based issuer check immediately above
  it already refuses, so binding every proof to the list's own issuer closes the
  same hole by the other route.

  ## Still not converted, deliberately

  `vta-sdk/src/provision_integration/{credential,template_verify}.rs`. Those are
  VTA-issued bootstrap credentials — one-shot, sealed, opened once and archived —
  where a hybrid proof set is not a realistic shape, and the helper lives in
  `vtc-service`. Promoting it to `vta-sdk` for two call sites that will not use
  the capability is not worth the published-API surface.

  VTC and workspace suites clean; clippy clean under `-D warnings`; rustfmt clean.

- **credentials**: Verification can read a document carrying more than one proof ([#1548](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1548))

Groundwork for hybrid credentials, and deliberately the verification half
  first: a credential signed with both Ed25519 and ML-DSA-44 arrives as a JSON
  **array**, and every verification path here did

      serde_json::from_value::<DataIntegrityProof>(proof_value.clone())

  which fails on an array. So a hybrid credential was rejected as malformed — by
  this stack, including one it had issued itself, had issuance been wired first.
  That is why verification moves before issuance, and it is a fact rather than a
  convention: it was checked before anything was written.

  `affinidi-data-integrity` has had `sign_multi` / `verify_multi` since it was
  written, with zero consumers anywhere in this workspace. This is the first.

  ## Two rules that are not about cryptography

  **Every proof is bound to the issuer before any signature is verified.** A proof
  naming someone else is not a failed signature — it is a document claiming the
  wrong author — and it must not become reachable merely by being the one that
  happens to verify.

  **All proofs that verify must name the same issuer.** A document carrying a
  valid proof from Alice and a valid proof from Mallory is not "verified" in any
  sense one answer can express, and a caller handed one `Ok` and one DID would
  reasonably assume one signer. The test covers it with BOTH signatures genuinely
  valid, which is what makes it worth refusing; it also closes the obvious trick of
  appending a proof from a party the reader trusts more.

  `RequireAny` is the acceptance rule. During the transition a verifier is
  expected not to understand every suite on a document, so demanding all of them
  would make a post-quantum proof a liability to the classical verifier that
  cannot check it. Tightening to `RequireAll` once the fleet holds PQC keys is a
  policy change, not a code one.

  ## Scope, stated rather than implied

  Two paths are converted: `LocalSigner::verify` and invitation verification.
  **Six are not**, and this does NOT yet mean the stack accepts hybrid
  credentials:

      vtc-service/src/members/inbound_vmc.rs:348
      vtc-service/src/recognition/verify.rs:277, :531
      vtc-service/src/routes/relationships.rs:1606
      vtc-service/src/routes/members/personhood.rs:690
      vtc-service/src/credentials/exchange/verify.rs:433

  Each is a third-party credential path with its own issuer binding and error
  handling. Converting six of those in bulk is how a security check gets quietly
  weakened, so they get a focused follow-up that can attend to each.

  Safe to land in this state because nothing issues a hybrid credential yet, so no
  path can receive one. The value of landing it separately is that the two rules
  above are established once, and the remaining six reuse them rather than each
  inventing an answer.

  `vta-sdk/src/provision_integration/{credential,template_verify}.rs` also read a
  single proof and are deliberately excluded: those are VTA-issued bootstrap
  credentials, one-shot and sealed, where a hybrid proof set is not a realistic
  shape.

  VTC and workspace suites clean; clippy clean under `-D warnings`; rustfmt clean.

- **tsp**: The VTC registry client re-forms a dropped relationship on a reply timeout (D4) ([#1546](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1546))

Rev 3 §7.2.2 is symmetric and silent: if the trust-registry loses its half of
  the relationship (a fresh or reset durable store, idle eviction, key rotation),
  it drops the VTC's next Trust Task with no reply. Since #1543 the VTC persists
  its relationship half, so once it reads "related" it never re-invites — and every
  send to the registry then times out, forever.

- **tsp**: The VTC persists + answers TSP relationships and relates before sending to the registry (Rev 3 §7.2.2) ([#1543](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1543))

The VTC is a server like the VTA, but its TSP was half-wired: it drove the
  delivery layer yet built the ATM with a bare `ATMConfig::builder().build()`
  (in-memory relationship store, wiped on restart), its `handle_tsp` had no
  relationship-control answering arm, and `MessagingRegistryClient` sent Trust
  Tasks to the trust-registry with a plain `send_routed` and no relationship. So
  the registry §7.2.2-dropped every frame ("no relationship with ...trust-registry"),
  and a VTC restart would have dropped the registry's replies too.

  Bring the VTC to VTA parity:

    - Lift the durable relationship-store adapter (`KeyspaceRelationshipKv` +
      `maintenance_loop`) out of `vta-service` into a shared, feature-gated
      `vti_common::relationship_store`, alongside `VtiOutboxStore`. `vta-service`
      now re-exports it and keeps only its VTA-specific §7.2.2 drop telemetry.
    - Inject the store into the VTC ATM (`with_relationship_store`) over a new
      `tsp_relationships` keyspace — distinct from the VTC's social-graph
      `relationships`, and excluded from backup (transport state). Spawn the
      boot-enumerate + idle-eviction maintenance loop once at startup.
    - `handle_tsp` now answers `InboundKind::RelationshipControl` via a
      `decide_control` policy (accept an invite, record an accept, answer a
      cancel) — the ACL gate stays at the Trust Task layer.
    - `MessagingRegistryClient` sends over `send_reestablishing`: it forms the
      relationship (sends an invite) when readiness demands, then sends the
      payload (§3.6). A `TODO(D4)` marks the reply-timeout reset that belongs at
      the correlated-reply wait site.

  This is the sender-and-responder half of the same recovery work already landed
  in `vta-service` and the trust-registry. The `VtaClient`/`SessionStore` Auto
  path is a different client and was handled separately ([#1540](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1540)).

- **tsp**: Adopt Rev 3, and give a TSP session a way to form a relationship ([#1512](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1512))

* docs(tsp): inventory what Rev 3 costs this repository

  Trust Spanning Protocol Rev 3 changed the crypto mode, the version byte,
  the long count-code prefix, the ciphertext code and layout, the `-E`
  count's meaning, the signature code and every payload layout at once.
  There is no compatibility mode: nothing a Rev 2 peer packs can be
  unpacked by a Rev 3 one, in either direction. So the stack flips
  together, and this repository is the last part of it with no plan
  written down.

  The inventory was produced by reading the `tsp-rev3` branch of
  affinidi-tdk-rs against this repository's own call sites, so it names
  files rather than describing intentions. Three things worth knowing
  without reading it:

  **The functional change is one arm.** §7.2.2 says an endpoint SHOULD
  drop an application message from a VID it holds no relationship with,
  and the SDK gates on that by default. SDK 0.22's `unpack_message`
  returns an `InboundTsp` enum instead of a payload, and its `Control`
  variant is what `handle_tsp` has to grow: record the invite, then decide
  whether to accept it. `affinidi-messaging-didcomm-service`'s listener is
  a worked reference for the shape.

  **It fails silently.** A dropped message answers nothing, so a VTA that
  does not answer invites looks from every client like a transport that
  accepts connections and never replies. The wallet already sends the
  invite and waits five seconds before sending anyway, which means an
  unmigrated VTA that does not gate keeps working and one that does goes
  quiet — and neither state produces an error anyone can see. That is the
  reason this is written down before the work rather than during it.

  **There is an authorization decision to take.** Whether the VTA accepts
  an invite from any authenticated sender, or only from one the ACL
  already knows. The narrow reading breaks provisioning — a wallet talks
  to the VTA *in order to* be provisioned — so the broad one is almost
  certainly right, but it should be a decision rather than whatever the
  first implementer assumes.

  No code change. The work is blocked on an `affinidi-tdk` release
  carrying `affinidi-tsp` 0.2.0, and this workspace deliberately has no
  `[patch.crates-io]` to get ahead with — the note at the bottom of
  Cargo.toml records the duplicate-`vta-sdk` incident that removed it.

- **vtc**: Route rooms tasks by payload type, so the served list is the router ([#1503](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1503))

Eleven hand-written match arms, eleven copied URI entries, and a census test
  whose only job was to keep the two in step — replaced by eleven registrations
  that name a Rust type and nothing else.

      .on_async(handle_create)
      .on_async(handle_put_record)
      …

- **vtc**: Verify a Trust Task's proof in the spine, where the bytes still exist ([#1501](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1501))

* feat(vtc): verify a Trust Task's proof in the spine, where the bytes still exist

  A proof covers the document as it was **sent**. `rooms/*` handlers verified it
  themselves, from the `TrustTask<Value>` they were handed — which works only
  while they are handed the document verbatim.

  They cannot keep doing that. Keying dispatch on the payload type hands a handler
  `TrustTask<P>`, and re-deriving the signed bytes from a parsed payload is sound
  only if `P` round-trips losslessly. None does: parse a document into a type that
  does not know one of its members and the member is gone, so the canonicalisation
  differs and a valid proof is refused. Pinned by
  `vta-sdk/tests/typed_proof_verify.rs`.

  So verification moves to `dispatch_trust_task_core`, which is the last point at
  which the received bytes exist, and the verified signer travels on
  `JoinAuthCtx`.

  ## Gated on the specification, so nothing existing moves

  The spine verifies when — and only when — `Payload::IS_PROOF_REQUIRED` says to,
  read through `schema_index::spec_policy_for` from the same generated bindings
  the schemas come from. That is framework §7.2 item 8 rather than a new rule, and
  it is a no-op for every task whose specification does not require a proof, so no
  request this service accepts today starts being refused.

  Two tests hold both halves: every `rooms/*` URI must declare the requirement
  (otherwise the handlers below would receive an empty presenter), and at least
  one dispatched task must *not*, or the condition would be indistinguishable from
  verifying unconditionally and the change would stop being additive.

  ## The rooms handlers keep invariant I5

  They take the verified signer and no context. That is not a weakening: a signer
  is a cryptographic fact about the request, not an authority this service
  confers. A room operation is still authorized by the authority chain the room
  itself issued — never by this service's ACL, roster or session.

  Ten call sites of `presenter_and_verifier` collapse to a synchronous, infallible
  call, and `handle_create`'s own verification block goes with them.

  ## The tests still prove what they proved

  A test that called a handler with a presenter of its own choosing would assert
  nothing about the signature — only that the handler uses the argument it was
  given. So the test module shadows each handler with a shim that verifies the
  document exactly as the spine does and passes the resulting signer. The call
  sites are untouched, and what they demonstrate is unchanged: the identity a room
  operation is authorized against is the one that signed the request.

  Rebased onto `main` after #1500 merged; `verify.rs` is identical to what landed
  there, so only this change remains.

- **vtc**: Accept a Trust Task in the DIDComm binding envelope ([#1497](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1497))

This service has one dispatcher and three ways in. REST and TSP each reach it in
  a single hop — TSP's inbound has no type surface at all, it opens carriage and
  hands over bytes. DIDComm had a hand-written router keyed on **task URIs**, so a
  verb was reachable there only if somebody had also written it down in
  `messaging::route`.

  **Thirteen of the twenty-four dispatched URIs had not been**: every `rooms/*`
  task and both `members/personhood/*` verbs. They dispatch over REST and TSP and
  answered `unsupported message type` over DIDComm — not because the service lacks
  them, but because the router is a second list nobody remembered to extend. That
  class of omission has already shipped here once: `rooms/records/curate` was
  dispatched and named in neither URI list, so every version hint this service
  emitted was wrong.

  One arm fixes all thirteen, because the binding envelope's type says "a Trust
  Task is inside" and nothing more. The document names the task and the spine
  routes on that, so a verb is reachable because it is *dispatched* — not because
  it appears in two places.

  ## An enveloped request was previously dropped in silence

  The envelope arm in `dispatch` existed, but only as reply demux: it completed a
  waiter and returned `None` **unconditionally**. So a request in the binding
  envelope was accepted by the transport, matched against no waiter, and discarded
  without an answer — a conformant peer built on `trust-tasks-didcomm` could not
  reach this service over DIDComm at all, and saw a timeout rather than a refusal.

  The waiter now decides: `complete` returns `true` only when a waiter took the
  document, so a capability write reply is still absorbed and anything else falls
  through to routing.

  ## The generic arm uses only the proven sender

  `auth_sender` is the authcrypt-proven DID; the plaintext `msg.from` is never
  consulted. Some per-verb handlers do consult it, deliberately, for public reads
  — but a generic arm cannot make that judgement per task, and defaulting to the
  unproven value would hand every authenticated verb a spoofable caller. The
  context carries `None` when nothing was proven and authorization fails closed
  inside the handler that cares; a public read never looks.

  ## Tests

  `vtc-service/tests/didcomm_envelope_binding.rs` sends
  `members/personhood/challenge/0.1` — dispatched, and absent from the router —
  both ways. Enveloped, it must not come back `unsupported message type`; that
  assertion fails without this change, with the exact production symptom:

      Problem(ProblemReport { code: "e.p.msg.bad-request",
        comment: "unsupported message type: …/binding/didcomm/0.1/envelope" })

  The sibling test pins the task-typed shape still being refused, so the first
  cannot pass for a reason unrelated to the envelope. When the legacy task-URI
  arms are eventually retired that assertion flips — and it should be re-read
  then, not deleted.

  The harness gained `try_request_enveloped`, differing from `try_request` in one
  field: the DIDComm `type`. That one field is the whole of what the router keys
  on, so a harness that could only send the task-typed shape could not observe
  this at all. Its reply-classification tail is now shared rather than copied.

  ## Additive

  Nothing changes what this service sends, and every existing task-URI arm stays.
  This is the dual-accept step that must land before any client flips to the
  binding — the step the TSP cutover skipped, which is what made today's outage
  silent rather than loud.

- **vtc**: Browse the recognition graph, from either side of it ([#1495](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1495))
- **vtc**: Retry and discard a failed sync job from the console ([#1493](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1493))

The queue became visible in #1487 and comparable against the registry in #1489,
  and in both the answer to "so fix it" was: stop the daemon and run a CLI. The
  mutation could not be a route, because binding a `spec/vtc/registry/…` Trust
  Task URI ahead of its upstream specification is what `trust_task_manifest.rs`
  refuses.

  trustoverip/dtgwg-trust-tasks-tf#460 specified the family and trust-tasks-rs
  0.20.6 publishes it, so the four tasks bind and the buttons work:

  - `GET  /v1/registry/sync-jobs`         `…/sync-jobs/list/0.1`
  - `POST /v1/registry/sync-jobs/retry`   `…/sync-jobs/retry/0.1`
  - `POST /v1/registry/sync-jobs/discard` `…/sync-jobs/discard/0.1`
  - `GET  /v1/registry/records`           `…/records/list/0.1`

  The offline `vtc sync-jobs` CLI stays. It is the break-glass path for a daemon
  that will not start, which is exactly when an HTTP route is no use, and both
  surfaces go through `sync_jobs_cli::requeue` and the same eligibility rule, so
  "only a Failed row may move" is written once.

  Where the two deliberately differ is in how they refuse. Retry *reports* an
  ineligible row (`skipped`, with `notFailed` or `notFound`) rather than failing,
  so one row the reconciler picked up cannot defeat a bulk retry, and a job swept
  between the page load and the click is an ordinary race. Discard *raises*
  409/404, because the request names exactly one job and there is no partial
  outcome to describe. Bulk retry is `allFailed: true` rather than an omitted
  `jobId` — a client bug that drops the identifier must not become a bulk
  operation — and discard has no bulk form at all.

  Two census gates caught real defects on the way, both worth recording:

  - `generated_wire_types_census` rejected the two query structs I had written
    by hand. It was right: they restated `…/list/0.1`'s payload. The handlers now
    take the generated `Payload` as the `Query` extractor, and the OpenAPI
    parameters are declared inline rather than derived from a mirror.
  - `every_bound_published_uri_has_a_witness` required a conformance fixture per
    bound URI. Added four, transcribed from what the handlers build — including
    that a failed job carries no `nextAttemptAt`, because it has no schedule and
    claiming one would be the response asserting something untrue.

  Every `#[non_exhaustive]` generated enum is matched with an explicit refusal
  rather than a catch-all that guesses. A future spec release naming a fourth
  retry target must not be silently read as one of the existing two.

- **vtc**: Compare the registry mirror against the registry, and show it ([#1489](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1489))

The `registry_records` keyspace has held what this community believes it
  published since Phase 3. `RegistryRecord`'s own doc comment says it exists "so
  the daemon can detect drift at boot". Nothing ever detected any: `list_records`
  had no caller in the service, and the mirror was written on every successful
  sync and never read.

  That gap is why a lost write was invisible. The Recognition page carried three
  signals and none of them answered the question that matters:

    registryStatus           does the registry respond?
    membership sync counters were our writes accepted?
    (nothing)                are they still there?

  And the third outlives the second. A failed sync job is swept after 30 days;
  the member stays unpublished, and at that point no surface in the service said
  so at all.

  - `registry::drift` compares the two views on its own timer (`[registry]
    drift_check_interval_seconds`, default 900, `0` disables). Its own timer and
    not the diagnostics handler, because enumerating the graph is several round
    trips and the console polls diagnostics every 15 seconds — on-demand would
    turn one open browser tab into steady load on a third party.
  - A disagreement is reported in one of three directions, because they have
    opposite fixes: missing at registry (a lost write — the member is invisible
    to every other community), unknown locally (benign, so reported without being
    counted a fault), status mismatch (a removal that half-landed). Truncation
    sorts faults first, so a community with more benign extras than lost writes
    does not have the lost writes pushed off the end.
  - A failed check annotates the last snapshot rather than replacing it. A
    registry that was briefly unreachable is not evidence that drift went away,
    and clearing a real finding on a transient error cancels an operator's alarm
    without fixing anything.
  - Absent is not empty. `registryDrift` is omitted until a check completes, and
    the console renders "not checked yet" distinctly from "the two views agree" —
    a VTC whose check never ran must not look healthy.
  - `TrustRegistryClient::list_records` defaults to a typed "cannot enumerate"
    rather than an error, so a REST-only transport reports unsupported rather
    than an outage. The messaging arm pages `record/query` and refuses to compare
    a partial enumeration: a short list against a complete mirror would invent a
    lost write for every member past the cap.

  Rides in the diagnostics `ext` envelope, so no new canonical URI is bound —
  `trust_task_manifest.rs` refuses one ahead of its upstream spec. The
  corresponding online browse and retry surfaces are specified in
  trustoverip/dtgwg-trust-tasks-tf#460 and land here after a trust-tasks-rs bump.

- **vtc**: Make a failed registry sync job visible and recoverable ([#1487](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1487))

A `Failed` membership-sync job is terminal — the syncer skips it on every
  tick, boot recovery rescues only `InFlight`, and nothing re-derives it — so
  the row names a condition that never resolves on its own. The only operator
  surfaces were a bare count on `/v1/health/diagnostics` and a line in the
  service log, and there was no way at all to act on one: the member stayed
  absent from the trust registry until the retention sweeper purged the row
  ~30 days later, clearing the failure without fixing it.

  Worse, the page above the counter could say `active` throughout. The
  liveness probe counts any correlated reply as proof of life, including a
  rejection, and a permanent rejection never touches `RegistryHealth` — so a
  registry answering `unsupportedType` to every call read as healthy, with a
  failed job beside it and no `lastError`.

  - `RegistryError::Incompatible` splits `unsupportedType` out of `Permanent`.
    It is not a bad request; it says the deployed registry does not route the
    task at all. The probe now fails on it (still re-falsifiable — upgrade the
    registry and the next tick flips back), while an ordinary rejection still
    counts as liveness, because that one really does prove the dispatcher read
    and routed our document. The syncer records it on the health signal at the
    moment of failure rather than waiting a probe interval.
  - `ext["org.openvtc"].failedJobs` carries every failed row: member DID,
    operation, attempts, the registry's verbatim error, and when the sweeper
    will purge it. The plaintext member DID is the field the audit trail cannot
    give — `RegistrySyncFailed` envelopes carry only `targetDidHash` (§11.1) —
    and it is what turns "1 failed" into something actionable. Under `ext`
    because the published response is `additionalProperties: false`.
  - `vtc sync-jobs {list,retry,discard}` is the write half. Offline, on a
    stopped daemon, beside `vtc acl` for the same reasons — and not a REST
    route because the mutation would need a new `spec/vtc/registry/…` URI, and
    binding one ahead of its upstream spec is what `UNPUBLISHED_CANONICAL_OK`
    refuses. `retry` is the only thing that re-drives a failed row; the sync
    cursor passed the originating audit envelope long ago.
  - Recognition page lists the failed jobs and banners the version-skew case,
    which an operator would not otherwise infer from a queue of failures.

- **vtc-admin-ui**: Chart what a policy decides, by evaluating it rather than reading it ([#1472](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1472))

The console could only draw a policy it had authored itself. Both visual views
  read the `@vtc-rule-ir` header, so a hand-written module — which is most of what
  an operator uploads, and every policy predating the editor — had one view: its
  own Rego.

  The obvious fix is a Rego parser, and it is the wrong one. It would cover the
  subset we happened to think of, and a partial parser that quietly mis-draws a
  policy is worse than no picture, because an operator would believe it.

  So the Flow tab does not read the policy. It evaluates it. A ceremony manifest
  already declares the inputs its dry-run can vary, so their combinations are a
  finite space; evaluating the policy at every point of it
  (`POST /v1/policies/{id}/test`, the daemon's own evaluator) gives a decision
  table, and a decision table induces a flow chart. Twenty-four evaluations for
  join.

  That renders **any** policy. It is also more truthful than the authored view for
  the policies that do carry an IR: the header is a claim its author maintains by
  hand, and the shipped `join.rego` has already drifted from its own — the header
  says the invitation route admits as `member`, the body admits at `invited_role`
  from the invitation's scopes. The Plain English tab shows the header. The chart
  shows what runs.

  How the chart is built (`lib/policy-flow.ts`):

  - At each step it asks the input that separates the endings best, weighted by
    how much of the space each branch covers. Weighting is load-bearing: summing
    branches unweighted penalises a five-way question for having five branches,
    and the chart then opens with a toggle that settles almost nothing.
  - A question whose every answer leads to the same ending is dropped. That is
    what keeps an irrelevant control out: once the vetters verified different
    identities, nothing about an invitation changes the outcome, so nothing about
    an invitation is asked.
  - Where the probes disagree and no declared input separates them, the chart
    says **varies** rather than picking one. That is the policy reading a fact
    the ceremony does not expose, and hiding it would be the same lie as the
    partial parser.
  - `probeSpace` refuses a space larger than the evaluation cap instead of
    truncating one, for the same reason: a chart drawn from part of the space is
    wrong about the rest of it, and silently so.

  The drawing is inline SVG in the console's own tokens, like the pipeline strip
  above it — no diagramming dependency, no second visual language, and a surface
  the dry-run can point at: set the simulator's inputs and the chart lights the
  path they take.

  The property under test is that the chart never disagrees with the evaluations
  it was built from: for every probe, walking the chart with those inputs reaches
  the ending the policy gave. A chart that is merely plausible is the failure this
  replaces.

  Also moves `pluckDecision` beside the other policy calls so the dry-run and the
  probes read the verdict the same way, and corrects the directive docs
  `ceremony-manifest.ts` had not caught up on since #1471.

- **vtc-admin-ui**: Let the join dry-run reach the vetting routes it cannot test ([#1471](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1471))

The Join ceremony's simulator offered one control — "presented credential is
  trusted" — so of the shipped policy's eight routes it could reach two. Every
  vetting route and the invitation route were unreachable, which means the
  routes that decide a vetted admission could not be dry-run at all: the only way
  to find out what the policy does was to run a real applicant through a real
  vetting session with a real second person.

  The join facts template now carries an invitation and a vetting block:

  - **Presents a valid invitation** adds `evidence.invitation` (verified, trusted,
    unconsumed). Absent unless set, because "no invitation" and "an invitation
    that fails" are different questions to the policy.
  - **Peer identity vetting** is one select, not five toggles: not required,
    not enough statements yet, vetters verified different identities, vetters not
    independent enough, requirements met. The host derives `satisfied` from the
    others, so separate switches would let an operator assemble a fact set the
    host can never produce and then draw a conclusion from it.
  - **…and the requirements also demand an invitation** appears only once the
    statements are in, since that is the only state it changes.

  `evidence.vetting` is omitted entirely for "not required", because that absence
  is exactly what `vetting_ok` reads.

  Two directives grew to carry this, both in the materializer the admin UI
  already had:

  - `$if` takes an optional `eq`, the comparison `showWhen` already speaks. Bare
    truthiness cannot read a five-way select: every non-empty option is truthy.
  - a branch that names nothing drops its key rather than writing `null`, because
    `not input.evidence.vetting` is how "this criterion does not vet" is asked and
    a `null` answers it wrongly.

  A test checks the simulator against the shipped `join.rego` itself: every
  `input.evidence.vetting.*` member the policy reads must be one the template can
  set. A rename on either side now fails here, rather than quietly making a route
  untestable again.

  Also caps blurbs in a unit test. `ceremonies/list/0.1` allows 256 characters and
  the response validator turns an over-long blurb into a 500 for the whole
  listing — every ceremony page blank, not just the one whose text grew. Found by
  the integration test while writing this; cheap to catch a layer earlier.

- **vtc-admin-ui**: Write admission criteria and statement types from the console ([#1465](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1465))

* feat(vtc-admin-ui): write admission criteria and statement types from the console

  Turning vetting on took two calls no interface could make. The Requirements
  panel read the join manifest and said so in its own header — "read-only on
  purpose: this console has no criteria editor" — and `cnm` has no schema-store
  command either, so the first thing an operator has to do was the one thing
  nothing could help them do. Worse, the two steps fail in the wrong order: a
  criterion naming an unregistered `statementType` is refused, so the missing
  endorsement-type registration surfaces as a refusal of the criterion.

  The panel now writes what it used to only show.

  - **Criteria.** Add, edit and remove them (`/v1/schemas/accepts`). The form
    writes the `vetting` object member by member: how many statements, from which
    methods, per-method floors, the vetter role, claims each vetter verifies,
    statement age, the documentation floor, independence caps, invitation, the
    deadlines and the governance link. The DCQL query is a field of its own,
    starting from the shape a vetting criterion uses and kept verbatim on an
    existing criterion.
  - **Statement types.** Register them (`/v1/endorsement-types`), with one button
    for the identity-vetting type when the community has none — the prerequisite,
    on the page that needs it, before the refusal it causes.
  - **The rules are not written twice.** `validateRequirements` already mirrored
    the daemon's checks for the read-only view; a draft is converted to a
    requirements object and answered with those same sentences, and the daemon
    runs all of them again on save. A count that is not a number becomes `NaN`,
    which the existing rule refuses in the existing words.
  - **Two things the form does that a JSON body cannot.** A per-method minimum is
    only offered for a method the criterion accepts, so the commonest refusal
    cannot be written. And "each vetter decides what documentation they accept"
    is a switch separate from the list, because an absent `acceptedDocumentClasses`
    and an empty one mean opposite things to a vetter (D16) and look almost
    identical in JSON.
  - Before saving, the page says in sentences what applicants will be told, using
    the summary the read-only view already had.

  The schema store is one of the daemon's Trust-Task-exempt routes, so `api.ts`
  gains `postJsonExempt` and `deleteJsonExempt` beside the existing `putJsonExempt`
  — named at the call site, like the rest of that carve-out.

  `AcceptsCriterion`, `EndorsementType` and their bodies are aliased from the
  generated wire types rather than described again.

- **vtc-admin-ui**: Author the vetter-eligibility policy, in the package the daemon requires ([#1467](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1467))

Who the automatic sweep names a vetter is a Rego policy, and the console let an
  admin reach it but not write it. `canAuthor` was `CEREMONY_PURPOSES.includes()`,
  so `vetterEligibility` — which has no ceremony — got the raw textarea, and the
  textarea's placeholder printed `package vtc.${purpose}`: `vtc.vetterEligibility`,
  which `validate_purpose_package` refuses, at the moment the operator most needs
  the right answer. So the console pointed at the policy, and then handed over a
  wrong package name and a blank box.

  **The package.** `pkgFor` moves to `policies-api.ts`, beside the purposes it
  describes, and derives the package from the purpose rather than special-casing
  one: every shipped policy in `policies/default/` is the snake_case of its
  camelCase purpose. The upload placeholder now uses it, which also corrects
  `roleChange`, `roleDefinitions` and both cross-community purposes. A test reads
  the daemon's own `.rego` files and asserts every purpose maps to a package one
  of them declares — the console's idea of where a policy lives is now the
  daemon's, not a list kept in parallel.

  **The vocabulary.** A `vetterEligibility` block: membership active, admission
  under review or not, how they were admitted, tenure in days, vetting depth from
  a founding member, and roles held. Enough to write the policy the shipped
  default's own comment suggests, by clicking.

  Three things it does *not* do, each because the sweep's input is a member
  record rather than somebody's request:

  - The shared conditions are withheld. `actor_is_admin` and its siblings read
    `input.actor`, `input.subject` and `input.state`, none of which exist here:
    every one would be false. Offering them would be offering a trap, so
    `conditionsFor` gives this purpose `always` plus its own block.
  - Only `allow` and `deny` are offered, named "Name a vetter" and "Do not name a
    vetter". `refer` and `request_more` are logged as undecided and act on no one,
    so authoring one would be authoring a policy that quietly does nothing.
  - A blank policy starts at `deny`, the posture the daemon ships and the only
    backstop the sweep acts on.

  **Arguments that must match.** `admittedVia` is compared exactly, so a typo
  compiles cleanly and then matches nobody. The IR's argument spec gains
  `options` (rendered as a choice) and `kind: "number"` (compiled unquoted), and
  the editor will not add a condition whose argument is empty, not a whole number,
  or not one of the choices. The compiler stays total anyway: a count that is not
  a number is emitted quoted, which Rego compares across types and finds false,
  rather than as text that would not compile.

  `ConditionDef` also gains an optional `phrase`, so a parametrised condition
  reads as a sentence — "is at most 2 vetting hops from a founding member" rather
  than "is within vetting hops of a founding member 2" — in both the route card
  and the plain-English view, which now agree. `effectToEnglish` takes the purpose
  for the same reason: this policy's `allow` is "name them a vetter", and no
  applicant is waiting on it.

  Follow-up to #1465, which made the Requirements panel write what it showed.

- **vtc-admin-ui**: Vetting panels for vetters, registry, auto-grants and join requests ([#1431](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1431))

Community admins can now run peer identity vetting from the console instead
  of the REST API:

  - Join requests: a request's page shows the vetting facts it was decided on
    (criterion, requirements digest, each statement's vetter, method, declared
    relationship, checks and whether it counted, distinct vetters, per-method
    counts, identity consistency, independence, what is still needed), in plain
    words with the daemon's codes kept beside them. Approving an unmet request
    says so in the confirmation.
  - Vetting → Vetters: grants with live/revoked/expired, manual/automatic,
    validity and profile summary, filterable; grant a current member for one day
    to two years; resend a grant's credential; revoke after a confirmation that
    the vetter's statements stop counting.
  - Vetting → Registry preview: the vetters/list listing with its filters, paged.
  - Vetting → Automatic grants: enabled, sweep minutes and validity, the last
    sweep, and a link to the vetterEligibility policy in Ceremonies (which now
    opens a purpose from ?purpose=).
  - Vetting → Withdrawals: notices with review state, linking to the join
    requests and members they touch.
  - Vetting → Requirements: criteria are not editable in the console, so this is
    a read-only view of each criterion's vetting requirements and
    requirementsDigest from join-requests/manifest/0.2, checked against the
    daemon's rules.
  - Community profile: branding (display name, accent colour picker and #rrggbb
    field, https logo URL) with a preview and a note that the logo's host sees
    each fetch.
  - Dashboard: tiles for pending join requests with vetting facts and
    withdrawals to review.

  Two admin routes, because the console's only REST credential is its session
  and the Trust Task forms of these reads identify an applicant by the document
  proof, which a browser session cannot sign:

  - POST /v1/vetting/vetters/list, bound to vtc/vetting/vetters/list/0.1, runs
    the same profiles::list an applicant's listing does.
  - GET /v1/join-requests/manifest, bound to vtc/join-requests/manifest/0.2,
    returns the same manifest_inner answer, so every Trust-Task header the
    console sends is one a route enforces (trust_task_manifest.rs).

  The SDK's listing types derive ToSchema, so both routes are in openapi.json
  and wire.ts and the console writes no response shape by hand. Integration
  tests assert each admin answer equals the applicant's.

  The console gains a test runner (Vitest, jsdom, Testing Library) with unit
  tests for the vetting vocabulary and validators and component tests for each
  panel.

- **cnm-cli**: Vetting admin commands and a PGP web-of-trust vetter bootstrap ([#1432](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1432))

* feat(vtc-client): drive the vetting admin surface

  Add the community-admin vetting verbs to VtcClient, so a CLI or an
  integration names and manages vetters through the client rather than
  hand-built requests:

  - list_vetter_grants        GET    /vetting/vetters
  - grant_vetter              POST   /vetting/vetters            (vetters/grant/0.1)
  - revoke_endorsement        DELETE /credentials/endorsements/{id} (endorsements/revoke/0.1)
  - resend_vetter_grant       POST   /vetting/vetters/{memberDid}/resend (vetters/resend/0.1)
  - auto_grant, configure_auto_grant   GET/PUT /vetting/auto-grant
  - branding, set_branding             GET/PUT /community/branding
  - vetting_revocations       GET    /vetting/revocations

  Routes bound to a Trust Task carry its header; the listing, automatic
  grants, branding and withdrawals are mounted with no binding and are
  called without one. Path segments (member DIDs, endorsement ids) are
  percent-encoded rather than interpolated. A grant reports whether it was
  issued (201) or an existing live grant returned (200). New response types
  are #[non_exhaustive]; vta_sdk::protocols::vetting is re-exported as
  vtc_client::vetting.

  tests/vtc_client_live.rs drives every verb against MockVtc, so client and
  router drift fails the build.

- **vtc**: Vetter registry, grant resend, community branding and automatic vetter grants ([#1430](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1430))

* feat(vtc)!: vetter registry, grant resend, community branding and automatic vetter grants

  The vetter role credential ([#1429](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1429)) names a vetter, but an applicant had no way
  to find one, a vetter who lost the credential could not get it back, and every
  vetter had to be named by hand. This adds the community side of the vetter
  registry: CONTRACT-vetter-registry §1–§8, as specified in
  trustoverip/dtgwg-trust-tasks-tf#453.

- **vtc**: Name vetters with a revocable vetter role credential ([#1429](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1429))

A vetter was a member holding the ACL role `custom:vetter`: a fact only the
  community could see, with no history, so "held the role when signing" was
  approximated and an applicant could not tell whether a vetter's statement
  would count.

  A vetter is now named by a community-issued vetter role credential — a DTG
  EndorsementCredential with endorsement
  `{ type: "CommunityRole", role: "vetter", communityDid }`, a credentialStatus
  on the Revocation list and a bounded validity.

- **vtc**: Let a vetter withdraw a vetting statement ([#1428](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1428))

* feat(vtc): let a vetter withdraw a vetting statement

  Adds vtc/vetting/revoke-statement/0.1 (OpenVTC vetting-process design
  §9.6, D18). A vetter sends the community a notice naming a statement's
  id and digestMultibase; the community records it under the
  authenticated sender, and a presented statement whose issuer, id and
  digest all match stops counting (`revoked` in the vetting facts).

  Keying by the sender means a notice can only ever withdraw a statement
  its sender signed. Senders must be members. Repeats are idempotent and
  return the first recordedAt. The first recording is audited as the new
  AuditEvent::VettingStatementRevoked (the enum is non_exhaustive).

  Notices live in a new, backed-up `vetting_revocations` keyspace: a
  withdrawn statement has to stay withdrawn across a restore.

- **vtc**: Count vetting statements in the join decision ([#1427](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1427))

* feat(vtc): count vetting statements in the join decision

  The community now verifies and counts the identity-vetting statements a join
  presentation carries (OpenVTC docs/design/vetting-process.md §10).

  The raw submit path verifies none of the credentials inside the VP, so each
  statement is verified here: proof by its issuer, bound to the proven holder,
  issued by a current member holding the vetter role who had joined before
  issuing. Survivors are counted with vta_sdk's evaluate, the same rule the
  applicant's checklist uses; distinct vetters are distinct members
  (VTI-CMP-070). The result reaches join policy as input.evidence.vetting.

  The default join.rego gains four mutually exclusive vetting outcomes, and
  neither an invitation nor a trusted credential bypasses required vetting.
  A visually authored policy can only return needs ["vetting"]; decide_join
  expands that into the precise shortfall. The admin console's rule-IR
  catalogue carries the same conditions, and the default's IR header is
  regenerated from them. Without vetting facts the default is unchanged.

- **vtc**: Advertise vetting requirements in the join manifest ([#1426](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1426))

* feat(vtc): advertise vetting requirements in the join manifest

  A community can now say what vetting it requires before anyone applies
  (OpenVTC docs/design/vetting-process.md §6).

  AcceptsCriterion gains an optional vetting object. store_accepts refuses
  requirements no applicant could satisfy, and POST /v1/schemas/accepts refuses
  a statementType that is not a registered endorsement type, where the operator
  can act on it rather than at an applicant's submit.

  vtc/join-requests/manifest/0.2 is served beside 0.1 over the document
  endpoint and DIDComm. A 0.2 criterion carries its vetting requirements and a
  requirementsDigest computed over the criterion exactly as delivered, so an
  applicant recomputes it from what it received and can tell when requirements
  change mid-application. A 0.1 answer keeps its own shape.

- **vta-sdk**: Wire types and crypto for peer identity vetting ([#1425](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1425))

* feat(vta-sdk)!: wire types and crypto for peer identity vetting

  The shared half of vetted admission (OpenVTC docs/design/vetting-process.md):
  an applicant is vetted by existing members before joining a community.

- **keys**: Export one key by name, and retire seeds/export-mnemonic ([#1404](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1404))

* feat(keys): export one key by name, and retire seeds/export-mnemonic

  `keys/export-secret/0.1` (trustoverip/dtgwg-trust-tasks-tf#446, in
  trust-tasks-rs 0.20.3) replaces `vta/seeds/export-mnemonic/1.0`.

  ## What the old URI was

  It exported no mnemonic and no seed. It was a per-key secret export that kept
  the name of the thing it was migrated from (`GET /keys/{key_id}/secret`), in the
  seeds family rather than the keys one, with **no published spec at all**, gated
  on **global Admin** — so a caller wanting one key needed authority over every
  other context in the VTA.

  Three operator commands sit on it and keep working, because they go through
  `VtaClient::get_key_secret`, which is the seam: `keys get --secret`,
  `keys secrets`, and the contexts DID-export flow. `keys bundle` already moved to
  `vta/contexts/secrets` in #1400.

  ## Two things that were never true

  Retiring it meant reading what it actually did, and two long-standing
  descriptions turned out to describe nothing:

  - Its retry-safety entry was `KeyedSecret` "because the export guard is
    one-shot". There is no guard in `get_key_secret` and there never was. The
    replacement is `ReadOnly` — true, and it keeps the response out of the dedup
    store by taking that path out entirely rather than by carrying a stronger
    label.
  - The handler's doc claimed "one-shot mnemonic export under
    `MnemonicExportGuard`; the returned payload zeroizes on drop", none of which
    was in the function it sat on.

  The name said mnemonic, the comment said guard, the code did neither.

  ## Authority

  `require_admin` for the role floor and `get_key_secret`'s own `require_context`
  for the scope: admin **of the key's own context**, not of everything. The two
  refusals the spec makes consumer requirements — an internal key is never
  released, a non-exportable key is refused about the key rather than the asker —
  are already enforced inside `get_key_secret`, which is the single place a
  private key leaves. Re-checking them in the handler would be a second set of
  rules to keep in step.

  ## The SDK fallback goes too

  `fetch_did_secrets_bundle` no longer falls back to the per-key walk. That
  fallback existed so a service could be upgraded before the VTA it talks to; a
  VTA carrying #1400 is deployed, so the gap it bridged is closed. It was also the
  last caller keeping the old URI alive. An older VTA is now a clear
  `UnsupportedTaskType` naming the missing task — "upgrade the VTA" rather than a
  puzzle — and there is one route to a bundle instead of two that could drift.

  Retired here: the handler, the dispatch entry, the const, its
  `UNSPECCED_DISPATCHED_URIS` row (the allowlist shrinks, which is the direction it
  is supposed to move), and the deprecation-registry row for
  `GET /keys/{key_id}/secret`, which now points at the new URI so the legacy REST
  route still names its replacement.

- **vta**: A service can fetch the keys of the DID it operates ([#1398](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1398))

* feat(vta): a service can fetch the keys of the DID it operates

  `vta/contexts/secrets/1.0`. An integration whose identity the VTA manages — a
  mediator, a room-host, a did-hosting service — has to hold that DID's private
  keys to decrypt what is addressed to it. It cannot ask the VTA per frame, so it
  fetches them at startup.

  The only path that did that was `seeds/export-mnemonic/1.0`, and it is wrong in
  three ways at once: it exports no mnemonic (it is a per-key secret export that
  kept the name of the thing it was migrated from), it takes one `key_id` so a
  caller assembling a bundle makes one call per key, and each of those calls is
  gated on **global Admin**. Being a service therefore required authority over the
  whole VTA — over every other context's keys included — in order to be itself.

  One request naming one context, one response carrying that context's DID and its
  key material, one authorization decision about the one thing being decided.

  ## Application, not Admin, and what makes that safe

  Reading the keys of the DID you already operate is not an administrative act.
  The loosening is real and worth being explicit about: the role floor drops from
  Admin to Application. What makes it sound is that the entitlement is a **scope**
  and not a **rank** —

  - `require_write()` is the floor: a Reader may see that keys exist and a Monitor
    may not even do that, and neither may hold one;
  - `require_context()` is the scope, and it narrows Admin too. Only an *empty*
    `allowed_contexts` means "all contexts", so an Admin of some other context
    reaches nothing here.

  Five tests assert that rather than describing it, including the two mistakes a
  reimplementation would actually make: treating the entitlement as a privilege
  level (`an_admin_of_another_context_cannot_either`), and checking existence
  before entitlement (`entitlement_is_checked_before_existence`, which compares the
  two refusals against each other so "no such context" cannot become an oracle for
  contexts the caller may not reach).

  ## Delegating rather than re-walking

  The operation is a thin wrapper over `build_did_secrets_bundle`, which already
  existed for the offline export path. Its first draft re-walked the context
  itself, and re-walking it got two things wrong that the existing traversal has
  right: it passed `None` where the label belongs, silently dropping every key
  whose store id is a derivation path and whose label carries the VM id (rule 2 of
  `select_secret_kid`, which exists for exactly those records), and it did not page,
  so a context with more keys than one page would have been truncated without
  saying so. The only thing that legitimately differs between the two callers is
  the role floor — the offline path runs as a local super-admin — so that is the
  only thing the wrapper adds.

  ## The dispatch class is `Secret`

  `[ None Secret false ]`. This classification, not the published registry, is what
  the PDP feeds into `PolicyInput`, so it is what sets the consent bar. The first
  draft said `Metadata`, which would have treated a private-key release as a
  metadata read on the most disclosing task in the surface.

  ## Wire form

  `ContextSecretsResultBody` is a wire type of its own rather than serialising
  `DidSecretsBundle` directly. They are not the same thing: `DidSecretsBundle` is
  the internal and on-disk form, snake_case, shared with `sealed_transfer` and with
  operator exports already written to disk, while the spec is lowerCamelCase as
  SPEC §4.10 requires. Renaming the existing type would rewrite a format that has
  been written to disk to fix a format that has never been on the wire. `From` in
  both directions, and a test that fails if anyone collapses the two.

- **rooms/owner**: Anchor a room's state where a host cannot reach it ([#1391](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1391))

* feat(rooms/owner): anchor a room's state where a host cannot reach it ([#1390](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1390))

  Implements trust-tasks-tf#429. Everything else in this family produces values a
  host asserts; an anchor is the one statement a host does not make, cannot forge,
  and cannot show two members two versions of — because witnesses co-sign the
  `did:webvh` log entry it rides.

  **Assembled from a read, because the owner holds one of the three values it
  publishes.** `epoch_authenticator()` this agent has; `headVersion` and
  `dataCommitment` are facts about the room's records and live at the host, so the
  handler presents as a member, reads the head, and takes all three from ONE
  response — a root and a version from two reads can straddle a write, and the pair
  is then individually correct and jointly false.

  `room_anchor` carries the two refusals and the shape decision the update path
  knows nothing about:

  - **A room with no witnesses cannot anchor.** `is_witnessed` reads the log's own
    entries rather than the record or the document — the record does not carry it,
    and inferring it from the document would be inferring it from the thing being
    signed. An entry nobody co-signed looks like an anchor and carries none of the
    property, which is worse than its absence because a member checking it would
    believe they had checked something.
  - **A commitment is published with its count or not at all.** One alone would put
    something that looks like evidence into a witnessed entry, where it is
    permanent.
  - **An anchor supersedes rather than accumulates.** One service entry per room,
    replaced in place: a document that grew one per anchor would carry a history
    the log already keeps, in a place with no ordering.

  The authenticator is published as a `DigestMultibase` like every other digest in
  this family, rather than as a bare blob whose algorithm is implied by context.

  `reconciled` is reported and never enforced: an owner withholding an anchor from
  a suspect room leaves it with no witnessed statement at all, which is the
  position a misbehaving host benefits from.

  Six census sites. `Keyed` rather than `RetrySafe` in the retry table, and the
  reason is worth reading: a second anchor supersedes the first and says the same
  thing, so it converges on state — but each attempt appends a permanent witnessed
  log entry AND rotates the room DID's update key, and both are durable artefacts
  that persist and matter. `Destructive` in the mcp guard, because nothing here can
  be taken back.

  * feat(rooms): a member checks a host against the room's own anchor, and a room says how often it means to publish one

  Completes the anchor: publishing it (the commit before this) is only half, and an
  anchor nobody reads is a log entry.

  **`ReadVerification.anchor` is the only one of this family's comparisons a
  first-time reader can make.** `priorRoots` needs this agent to have read the room
  before; `count` needs a complete unfiltered listing. This needs neither — every
  member resolves the same room DID and reads the same witness-co-signed entry.

  It is also the only place a **rollback** is visible. A host serving a state older
  than the room's own published statement is `behind`, and nothing else in this
  family catches that: not the trace, which binds a record to whatever root the
  host asserted; not `priorRoots`, which needs a prior read at that same version.

  Two verdicts are deliberately narrower than they could be. A room past its anchor
  is `ahead` — the ordinary case, since an anchor describes a moment rather than the
  present. And an anchor that pinned a version and **not** a root reports `ahead`
  rather than `agrees`, because saying the contents agree would claim a comparison
  that was not made. A resolver failure is `notChecked`: an agent that could not
  resolve the room has learned nothing about the host, and putting a network
  failure in the same sentence as a finding is how a detection loses its meaning.

  **`anchorCadence` makes silence legible.** It enforces nothing — nothing here can
  make an owner anchor — but a room that says `renewal` and has not anchored in ten
  epochs is telling a member something, and a member who did not know what to expect
  could not have noticed. Deliberately not a duration: a room promising "daily"
  would make a claim its owner's availability cannot keep, and a member comparing
  against a clock would read an owner's holiday as a host's misbehaviour. `Manual`
  is the default and the honest reading of a room stored before this existed.

  Both hosts record what the caller asked for and echo **what was recorded**, never
  what was asked — the two differ on a host that predates the member, and echoing
  the request would tell a caller their choice took effect when it did not.

- **rooms/epoch**: A host relays commits and forgets a chain on request ([#1394](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1394))

Implements trust-tasks-tf#431 and #432 — the last two verbs the rooms family
  owed, both host-served.

  **The relay.** Every epoch change is a commit, and every member must apply it or
  fall out of the group. Without somewhere to fetch one, the only way it reaches a
  member is the owner sending it: O(n) deliveries per renewal, to parties the owner
  must have addresses for, all of which must be online. `rooms/epoch/mint` gains an
  optional `commit` — published where it is produced, because that is the moment
  the committer holds it and a separate task would be a second chance to forget —
  and `rooms/epoch/commits` serves them.

  `commits_since` **stops at the first gap rather than skipping it**. MLS commits
  apply in sequence, so serving 4, 5, 7 hands a member something the group rejects
  with nothing to point at. A short answer is recoverable; a set with a hole in it
  is a member stuck at an epoch who cannot say why. `room_epoch` is read from the
  room and never computed from the answer, because the difference is exactly what
  tells a member a delivery is missing rather than their own state being broken.

  `put_commit` refuses to replace one, on the same terms as `put_epoch_link` and
  with a sharper consequence: the first published is the one members may already
  have applied, and a second forks the group the relay exists to hold together.

  **The prune.** `rooms/epoch/prune` drops the chain below an epoch. The rungs go,
  not the records — a pruned room still holds every record and still serves them,
  and what is gone is the ability to derive the keys they were sealed under. It
  takes `admin` rather than `curate`: pruning makes no statement about any record,
  and every member who can write can curate.

  `prune_chain` reports **reach, not the request**. A chain can already have a gap,
  and a prune below one changes nothing about how far back a member can walk;
  `a_prune_below_an_existing_gap_reports_the_gap` pins it at 7 where the request
  said 4. And `beforeEpoch` at or above the room's current epoch is refused rather
  than performed: it reads like "keep from here" and would drop the whole chain.

  Commits live in the epoch-links keyspace rather than a new one — same lifetime,
  same owner, same deletion semantics, and a new keyspace would owe a
  DID-deletion-effect census entry for no benefit.

  Two defects this found in its own making, both worth the next person knowing:

  - An **unimported constant in a `match` arm does not fail to compile — it
    becomes a binding that matches everything.** `ROOMS_EPOCH_PRUNE_TYPE` was
    missing from room-host's import list, so every arm after it was dead and owner
    transfer, owner claim and the unknown-task refusal were all parsed as prune
    requests. Three tests said so precisely: `unknown field 'newOwnerDid',
    expected one of 'roomId', 'beforeEpoch', ...`.
  - `vtc-service` declares its supported URIs in a list **separate** from the
    dispatch match, and the census caught the omission with the right words: a
    client would be told the task is unsupported at every version.

  Also corrected: the `put_epoch_link` fixtures started at epoch 1, which it
  rightly refuses — a rung wraps the PREVIOUS epoch's key, so epoch 1 has no
  predecessor to link to.

- **rooms**: A tree head, so two roots can be compared at all ([#1375](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1375))

Implements trust-tasks-tf#422, released as trust-tasks-rs 0.19.2. The last
  implementation piece of verified reads: a reader now gets a root, the state that
  root describes, and a path from their record to it.

  The commitment shipped as a bare root, and the prose claimed a host showing two
  members two different roots "cannot claim a transient". It can — a room moves on
  every put, curate and retraction, so the host answers *there was a write between
  your reads* and nothing contradicts it. Certificate Transparency does not have
  that problem because a signed tree head is a root AND a size; this family had
  shipped the root alone.

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

- **rooms**: Cut over to present/0.2 and issue-authority/0.2 ([#1365](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1365))

The consuming half of trustoverip/dtgwg-trust-tasks-tf#415 and #418, unblocked
  by affinidi/affinidi-tdk-rs#784.

  `trust-tasks-rs` 0.19 carries both new spec versions, but this workspace could
  not take it: `affinidi-messaging-sdk 0.22.0` required 0.18, so pinning 0.19 put
  two `trust-tasks-rs` nodes in the graph and broke `vta-sdk` on `expected
  MediatorAcl, found a different MediatorAcl`. TDK #784 moved the messaging family
  to 0.19 and 0.23.0.

  Taking it exposed pins that had drifted apart underneath: `vta-sdk` was on
  messaging-sdk 0.22 while `vta-service` and the e2e tests were on 0.21, and three
  `trust-tasks-rs` versions were resolving at once. All of it is now consolidated:
  the lockfile holds exactly ONE `trust-tasks-rs` and ONE `affinidi-messaging-sdk`,
  where before it held three of each.

  `rooms/keys/present` 0.1 -> 0.2 and `rooms/owner/issue-authority` 0.1 -> 0.2.
  Both 0.1s are retired upstream. Neither is dual-accepted, deliberately: for
  `present`, 0.1's extra members are exactly the two nothing could honour; for
  `issue-authority`, accepting 0.1 means accepting a request with no `validUntil`,
  which is the thing 0.2 exists to refuse.

  The hand-rolled `validUntil` guard in `room_owner.rs` is deleted. 0.2 makes the
  member REQUIRED, so the generated payload types it as a `DateTime` and the
  envelope schema rejects a request without one before dispatch. Same rule, one
  layer up, which is where a shape constraint belongs.

  `every_witnessed_task_round_trips_through_its_generated_types` refused two
  witnesses that had been green for as long as they existed:

  1. The `issue-authority` witness carried no `validUntil` — a chain root with no
     expiry, the exact request 0.2 forbids, and one this service could have sent.
  2. The `present` witness carried `"audience": "did:key:z6MkHost"` — a HOST DID,
     the precise shape #414 reported as impossible to satisfy, since the field
     named the party that had to PRESENT the credential.

  `room_oracle` emitted `membership` and `authority[]` as JSON **objects**;
  `AuthorityPresentation` types both as strings, and the host's opener reads
  base64url or bare JSON text. So the oracle's output could not deserialize at a
  host at all — `rooms/keys/present` had never worked end to end. It went unseen
  because 0.1's response typed `presentation` as an opaque object; 0.2 names the
  shared component, which turned a runtime refusal nothing exercised into a type
  error. The oracle now serialises each credential. That is the first half of
  have caught all three of these years earlier.

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

- **vtc**: A rooms console, and the policy tab that was silently missing ([#1330](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1330))

#1325 gave the daemon `GET /v1/rooms`. This is the screen for it, plus the
  one thing an operator actually decides about a room hosted here.

  The list is deliberately thin, and the thinness is the design: a host
  cannot read a room's records and holds no member list, because every
  operation is authorised by a credential the ROOM issued and checked against
  the room's own DID. There is no records view to add later. The owner IS
  shown at every tier including private — that is invariant I1, and the reason
  is operational rather than incidental: a room whose contents nobody here can
  read still has a party a quota or reclamation notice must reach.

  The lifecycle copy follows `vti_rooms::lifecycle` rather than the intuition
  about it. None of the four states is an outage: a lapsed room is read-only
  with nothing destroyed or hidden, and reads keep working right up to the
  moment a reclaimed room's bytes go. The two that ask an operator to act are
  surfaced above the table and they are not interchangeable — `dormant` is
  where the owner is owed the notice and where a nominated successor may
  claim, `reclaimable` is past the retention agreed at creation. Putting the
  notice at `reclaimable` would tell an operator to send it after the period
  it was meant to precede.

  The second card asks the live `rooms` policy what it permits, per tier,
  using the same `data.vtc.rooms.decision` query and the same input shape
  `VerifiedRoomCreation` serialises to — a probe built from a guess answers
  about a policy nobody runs. It exists because the shipped default DENIES the
  private tier, deliberately, and that is a surprise better met on screen than
  in a Rego file.

  **The console's purpose list had already drifted.** It named ten purposes as
  a hand-written literal while the daemon served eleven, so the `rooms` policy
  had no tab under Ceremonies and could not be read, tested or replaced from
  the console at all. Nothing failed — the tab was simply absent, which is the
  quietest way for a policy to go unmanaged. `Purpose` is now the generated
  `PolicyPurpose` and the order is a `Record<Purpose, true>`, so the next
  purpose added to the Rust enum fails to compile here until someone places
  it. Verified by deleting an entry and watching tsc reject it.

  Also corrects `api.ts`'s claim that `/health` is the daemon's single
  Trust-Task-exempt endpoint. `GET /v1/rooms` is the second, for its own
  reason: naming a room task on the host's own view of what it stores would
  claim a room governs an answer it has no view of.

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

- **rooms**: Read mirrors — a host that serves a copy and writes nothing ([#1289](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1289))

§7.3's optional half. A room has one write-primary; another host can now hold a
  read-only copy of it, fed by `sinceVersion` pulls, serving reads and refusing
  every write.

  ## A mirror pulls as a member

  The design said "fed by sinceVersion pulls" without saying by whom, and reads
  are authorized - so the decision this makes, and states rather than hides: **a
  mirror presents a room-issued chain conferring `read`**, exactly as any other
  reader does. No mirror-shaped exemption at the primary, no new verb. The room
  admits a mirror the way it admits a person and can stop admitting it the same
  way.

  Two consequences, both stated in the module and the guide. On `attributed` /
  `private` a mirror only ever holds ciphertext, so mirroring gives its operator
  nothing the primary's operator lacks. On `open` it reads cleartext, because
  everything on that tier is cleartext to whoever holds it - mirroring an `open`
  room to a host you would not let read it is not a thing this can do, and
  pretending otherwise would be the dishonest option.

  ## What a mirror cannot do

  Tamper. Records are signed and AEAD-bound to `roomId | key | version | epoch`,
  so an altered or renumbered copy does not verify and does not open. Its only
  failure modes are **stale** and **silent**, and a client watching the version
  watermark sees both.

  `store_mirrored_record` therefore keeps the primary's version verbatim rather
  than assigning its own - renumbering would break the binding and give the
  watermark a different meaning from the one every `sinceVersion` pull compares -
  and refuses a version at or below what the mirror already holds, because
  records only gain versions and accepting a lower one would serve a fresh member
  an older room than the copy already had (R2-5).

  It also skips the primary's visibility and epoch validation, deliberately:
  re-running it would mean a mirror refusing to copy a record its primary
  accepted, which is a copy silently diverging - the one failure mode a mirror
  must not have.

  ## The write refusal covers admin

  `authz` refuses every non-read action on a mirror and names the primary. `Admin`
  is *not* exempt, unlike the lapse gate: a mirror that accepted an epoch mint
  would fork the lifecycle clock its primary owns, leaving the room live on the
  copy and lapsed at home.

  ## Operating one

  `room-host --mirror-config mirrors.json [--mirror-interval-secs 300]`. The file
  holds a private key and the room's credentials, so it is hardened to owner-only
  on load and read from a file rather than a flag - a credential on a command
  line is a credential in the process table. One sequential pass per interval
  rather than a task per room: a mirror is not latency-critical, and a task per
  room turns one unreachable primary into unbounded concurrent retries. A failed
  pull is logged and the loop carries on, because a stale mirror is a state the
  design allows and stopping would make every other mirror stale too.

  Tested end to end against a real socket: two hosts, records written at the
  primary, pulled, and served from the copy under the primary's own numbers; an
  unreachable primary leaving the mirror serving what it has; and the write
  refusal naming the primary over the wire.

- **rooms**: Let a community decide whose rooms it hosts ([#1282](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1282))

Registering a room on a VTC was ungoverned. #1274 made the request prove who
  its owner is, which stops anyone registering a room in somebody else's name -
  but nothing stopped a stranger registering one in their own, on a community
  that had never met them. §7.4 of the design says a VTC governs what its
  members may create on it; this is that, in the policy engine the service
  already has.

  ## A new policy purpose, not a new mechanism

  `rooms` joins the ten existing purposes: a bundled default, an active-policy
  row, `POST /v1/policies` to replace it. `handle_create` assembles facts, loads
  the active policy, and refuses on a deny with the policy's own code, so an
  operator reading a refusal sees which rule produced it.

  The shipped default hosts `open` and `attributed` rooms for the community's
  own members and refuses `private` until an operator activates a policy
  permitting it. Not because a private room is dangerous, but because a
  community that has not decided should not discover it is hosting rooms whose
  membership it cannot see.

  ## Why this does not break invariant I5

  I5 says room *authorization* never touches a host's ACL, and it is what makes
  a room portable. Creation is a different question and the design names it as
  the exception: a host refusing to store a room is not deciding who belongs to
  it - the room does not exist yet and has issued nothing - it is deciding
  whether to lend its disk. `govern_creation` is the only place in the rooms
  handlers that reads the roster, it runs before the room exists, and no
  operation on an existing room consults it. A standalone `room-host` has no
  policy engine and no roster at all: T1's governance is its owner, which is the
  whole model.

  ## Three refusals, all closed rather than open

  - A policy that answers **nothing** is a deny. Rego is permissive about a
    missing rule, and reading an empty result as "no objection" would turn a
    typo in a package name into an open host.
  - A **threaded** verdict (`refer` / `request-more`) is a deny. Registration is
    one synchronous call with no thread to resume, so a verdict this surface
    cannot carry out is refused rather than approximated.
  - **No active rooms policy** is a deny, not a 500. `install_defaults` fills
    the row at boot, so the gap means a first boot that has not reached it or an
    operator who deleted it; both are a closed door rather than a server fault,
    and the message says which so an operator checks their policy list instead
    of their credentials.

  ## What a policy can see

  The creator (DID, whether a member row exists, their ACL role) and the room's
  identifier, visibility and owner. **Not** the design's `didControlledBy` /
  `contentStoredAt` hosting axes: the published `rooms/create/0.1` schema has no
  member for either, so no host can know them, and inventing them locally would
  put this service's rooms out of conformance with the schema every other host
  reads.

  Existing room tests now seed a member row for the fixture owner - they were
  creating rooms as strangers, which is exactly what this refuses - and the
  private-tier tests activate a permissive policy, which doubles as the worked
  example of enabling the tier.

- **vtc**: Let the console explain the transport advertisement, not hint at it ([#1278](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1278))

The dashboard's "Transport advertisement" card re-derived its own analysis
  in TypeScript from the per-protocol `advertised`/`serviceable` booleans,
  rather than reading `transport_capability::findings_for_build` — the
  function whose own doc comment says it exists "so the boot gate, the
  messaging listener, and `vtc status` say the *same* thing about the same
  document". The console was the one surface that did not participate, and it
  could not say what the others said:

  - Two of the four findings are statements about the *shape* of the
    advertised set — "advertises TSP with no DIDComm fallback" and
    "advertises no messaging at all" — and no pair of per-protocol booleans
    encodes them. So a VTC advertising TSP alone showed a grey "served but not
    advertised: DIDComm" line with nothing to say why that mattered, while
    `vtc status` printed the warning that explains it.
  - `serviceable` is build-capability AND live-connection, so a transient
    mediator disconnect rendered as "a client resolving this community's DID
    will choose it and fail" — a document defect the operator did not have.
  - The card appeared only when something looked wrong, making its absence
    ambiguous between "everything agrees" and "we never resolved the DID".
  - Nothing on it named whose document it described, so it read as
    contradicting the trust-registry tile beside it, which describes a
    different party's.

  `Finding` now carries a stable `code`, the `protocol` it concerns, and a
  one-line `summary` alongside the full remediation `message`, so a consumer
  can style and order findings without parsing prose that exists to be
  reworded. The daemon log tags each line with `finding = <code>` for
  alerting; `vtc status` prints the summary as a headline with the
  remediation beneath.

  The console reads the list from `/v1/health/diagnostics` and renders the
  `transports` table, then the findings at their own severity, with a line
  saying the card is about this community's own document. Findings ride in
  `ext["org.openvtc"]`: `spec/vtc/registry/diagnostics/0.1#response` is
  `additionalProperties: false` and the response-conformance layer enforces
  it, so promoting the field to the top level is a trust-tasks-rs release,
  not a change here.

  Fixing the call site also found `TransportStatus`, `RegistryTransport` and
  `DiagnosticsResponse` still hand-written in `api.ts` beside the fetch,
  duplicating generated aliases that `wire-types.ts` already exported and
  nothing imported — the #1186 shape, still live for this endpoint. They had
  drifted before anyone read them: the daemon serialises `messagingStatus`
  and `transports` unconditionally and `oldestPendingAgeSeconds` as nullable,
  where the local copies said optional and never-null. `tsc` could not
  notice, because the hand-written interface *is* what it checks the console
  against. Deleted in favour of the generated ones, which turned up two null
  tests that had only been safe by assumption.

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

- **rooms**: A member can curate a record ([#1245](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1245))

retract_record, purge_record, Action::Curate and RecordStatus::{Deprecated,
  Retracted} all existed, were tested, and were unreachable - there was no
  Trust Task that could invoke any of them. A member who had put something
  into a shared room by mistake had no answer.

  Implements rooms/records/curate/0.1 (dtgwg-trust-tasks-tf#354) in both
  hosts, against hand-written wire types until the generated bindings
  publish - the same arrangement the rest of the family shipped under.

  Separate from put for two reasons, and the second is load-bearing. A
  record's standing is not its content: on a sealed tier the host cannot
  read what it stores, so 'replace this with the same body, marked
  deprecated' would make a member re-seal and re-upload bytes the host
  already holds, to say something that is not about the bytes. And curate
  is its own authority action, deliberately not implied by write - deciding
  what a room's shared knowledge is worth is a different grant from being
  able to add to it. A test drives that end to end: the fixture's agent
  chain confers read alone, so an agent that can read a room cannot demote
  what a person wrote in it.

  Retraction is a tombstone, not an erasure. The body goes; the key,
  version and epoch stay, because that is what makes incremental sync
  converge - a caller that never saw the tombstone resurrects the record on
  its next full rebuild, which is why list returns them. A test retracts
  and then asserts the listing still reports it while the body is gone.
  Restoring a retracted record is refused rather than reported as a success
  that restored nothing.

  A demotion keeps its body. deprecated means demote in recall, not hide -
  an agent that could no longer read a deprecated record could not explain
  why it ranked it lower.

  Every curation assigns a new version. A change others are expected to
  converge on is a change like any other, and one that left the version
  alone would be invisible to every sinceVersion watermark in the room.
  That is also why pinning goes through this path rather than being a cheap
  side-channel: a pin nobody syncs is a pin only its author can see.

  pinned is orthogonal to status - a room may want its superseded canonical
  decision kept in view - so Record carries both.

  Curation is a write, so a lapsed room refuses it. The gate is the one
  added with the lifecycle, not a second copy.

  The three curation inputs travel as a Curation struct rather than three
  parameters: they are one decision, they land as one version, and clippy's
  argument-count lint was right to ask.

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

- **rooms**: The lifecycle §9 describes, with the host never deciding ([#1242](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1242))

retention_days was stored and nothing read it. A room, once created, was
  live forever - so §9 of the design note existed entirely on paper.

  Live -> Lapsed -> Dormant -> Reclaimable, and every one of them is undone
  by a single renewal until the last. Lapsed is read-only: nothing is
  destroyed, nothing is even hidden, and the room simply stops accepting
  writes, which is a condition a member can notice and fix.

  The state is computed, never stored. A stored state is a decision
  somebody made and can get wrong; a computed one cannot drift from the
  facts, and there is no code path where a host marks a room dormant. That
  is §9's 'the host never decides' made structural rather than promised: on
  a sealed room the host cannot read the content and inactivity is not
  worthlessness, so it is the worst-placed party to judge.

  Minting an epoch is the renewal. There is no separate verb and there
  should not be one: a renewal that could be called without committing
  would let a room look live while its key material stood still. Admin is
  therefore exempt from the write gate - a gate that refused the one
  operation that escapes it would leave a lapsed room lapsed forever, and
  the exemption holds all the way to Reclaimable, because until the bytes
  are deleted the members' choice is renew or export.

  Two rules the tests pin because they are easy to get subtly wrong.
  Retention runs from the lapse, not from the dormancy notice, or the 90
  days an owner agreed to silently becomes 120. And reclamation never
  happens before the notice, so a retention shorter than the grace window
  skips Dormant rather than reclaiming early - erring later destroys
  nothing, erring earlier destroys a room somebody would have renewed.

  epoch_expires_at is Option, and None means never lapses rather than
  already lapsed. A room stored before this field existed deserialises to
  None, and the other reading would have turned every existing room
  read-only on deploy - the wrong direction for a migration to fail in.

  The design note gains a correction rather than a quiet divergence. §9
  said read activity counts as liveness; the implementation does not do
  that, because a host counting reads to decide a sealed room's lifecycle
  would make it depend on the one signal the host can see - the exact
  correlation the tiers exist to deny, and an access-frequency profile a
  private room's members were promised they would not have. The archive
  case is served by retentionDays, which is the member's own statement of
  how long the room matters.

  Not here, and it cannot be: anchoring renewals in the room's witnessed
  DID log. That log is controlled by the room's DID controller, which is
  the owner, not the host. A host's half of §9 is the above - never
  deciding, and never destroying anything a renewal could have saved.

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

- **vta**: Discharge the backup family's spec debt, and audit what it was hiding ([#1239](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1239))

* feat(vta): discharge the backup family's spec debt, and audit what it was hiding

  trust-tasks-rs 0.17.7 carries the six specs from
  trustoverip/dtgwg-trust-tasks-tf#347, so `vta/backup/*` and
  `vta/management/reload-services` come off `UNSPECCED_DISPATCHED_URIS` and
  gain conformance witnesses. The reduction plan's §D suggestion of a
  top-level `backup/*` was not taken: the family is agent lifecycle, and
  `vta/` is where the rest of it lives.

  That was meant to be bookkeeping. It was not.

  ## Making them visible showed three of them succeeding silently

  The audit census could not see these tasks before, because an unspecced
  task has no witness and an undriven task reports nothing. The moment it
  could, it found three consequential successes leaving no trace at all:

  - **`initiate-export`** — mints a *fetchable copy of the entire agent* at
    a known address.
  - **`initiate-import`** — opens a *writable endpoint into* the agent.
  - **`reload-services`** — restarts the agent, dropping every open session.

  None of the three alters stored state, which is why nothing state-shaped
  ever caught them: the only evidence these operations happened is the row
  that was not being written.

  `reload-services` is the sharper case. It *had* an audit call — the
  `audit!` macro, which emits a `tracing` event and never touches the
  `AuditSink`, so nothing it recorded reached `audit/list` or an operator's
  sink. That is precisely the defect the census module header describes,
  sitting undetected in a task the census could not drive. Its sink write is
  placed **before** `trigger_restart`, because the restart tears down the
  runtime the write runs in.

  ## Three more the census structurally cannot reach

  `complete-export`, `finalize-import` and `abort` were silent on success
  too, and the sweep would never have said so: all three need a real bundle,
  the census drives an empty store, and it therefore only ever sees their
  not-found refusals. It would have reported this family green.

  Found by reading rather than by the sweep, and the blind spot is written
  into the helper's doc comment — a test that cannot reach a path cannot
  vouch for it, and the next person should not mistake a green census for
  coverage of these three.

  `finalize-import` is the one that matters most. On commit it replaces the
  agent's keys, ACLs, contexts **and its audit trail**, so a row written
  into imported state would document its own erasure. It is recorded to the
  sink after the op returns, which is outside the state the import replaced.

  ## Witnesses

  Both `password` fixtures carry an obvious non-secret, and so does
  `transportToken`. The specification's schema directory deliberately holds
  no specimen password — a fixture value is the one thing implementers copy
  — and a witness is read far more often than a spec. `finalize-import`'s
  request pins `confirm: false`: a committing witness would be the one shape
  in that table whose meaning is "replace the agent".

  `cargo test -p vta-service` green — 1014 lib tests and all 25 integration
  binaries; `cargo fmt --check`, `cargo clippy --all-features`, `cargo check
  --workspace` clean.

- **vta**: Implement vta/credentials/list, and check the vault/credentials family ([#1235](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1235))

* feat(vta): implement vta/credentials/list, and check the vault/credentials family

  `vta/credentials` served `issue` and `revoke` and nothing else, so an issuer
  could not ask its own agent what it had issued. The `credentialId` that
  `revoke` is keyed on is returned exactly once, in the `issue` response; a
  caller that did not record it at that moment could not recover it at all.

  Specified upstream as `vta/credentials/list/0.1`
  (trustoverip/dtgwg-trust-tasks-tf#342). This implements it — a read over
  records that already exist. `IssuedCredentialRecord` carries the id, holder,
  both instants and the revocation instant and reason, and revocation is a
  tombstone rather than a delete, so a revoked credential is still there to list.
  No new storage.

  Bodies are never returned. `vault/list/0.1` states the rule this follows —
  list enumerates, release uses — and `summarise` is the one place the projection
  happens, so "a summary never carries the credential" is enforced rather than
  remembered. `status` is derived at read time with `revoked` beating `expired`:
  reporting a revoked credential as merely expired would hide that somebody
  acted, and a stored status is wrong one second after it is written.

  Gated on `require_manage`, not the Admin-plus-step-up its mutating siblings
  use. An operator who may read the ACL and the policy set may read what their
  own agent issued — same category of question — and a step-up that fires on
  every page of a list is one people learn to clear without reading. The read is
  audited anyway: "who enumerated the issuance log" is what an incident review
  asks, and nothing else would record it.

  ## Bumping trust-tasks-rs to 0.17.4 surfaced the vault/credentials family

  Those eight URIs have been dispatched since before they had a specification.
  Specifying them (#338, shipped in 0.17.4) made them *published*, which is what
  finally let the conformance sweep see them — and it found two real defects in
  shapes that had never been checked against anything:

  - **`ReceiveBody` serialized `credentialBase64: null`.** `#[serde(default)]`
    without `skip_serializing_if` leaves an unset member as `null`, and the
    schema's `oneOf` counts a null member as *present* — so the body matched
    neither branch. Same defect class as the sibling registry's
    `payload_null_census`.
  - **`force` was accepted by four verbs that ignore it.** `CredLifecycleBody`
    was shared across archive, unarchive, delete, restore and purge, but only
    `delete` reads `force`. A caller asking for something stronger than the verb
    it named got the weaker thing and a success. `delete` now has its own body;
    the other four refuse the member, as their schemas always said they should.

  Three debt ratchets moved in the right direction as a consequence, each
  discharged by specification rather than deletion: eight entries out of
  `UNSPECCED_DISPATCHED_URIS`, one out of the producer-payload census's
  `UNPUBLISHED` list (so that payload is now validated rather than skipped), and
  vtc-service's bound-URI count from 12 to 4 — what remains is the four
  *secrets*-store lifecycle verbs, which still have no spec.

  ## Tests

  `page_rows` is split out of `list_issued` and unit-tested because the cursor is
  where a bug hides: it is the last storage key of the previous page and
  resumption is strictly after it, so a credential issued mid-walk cannot shift a
  window and skip a row nobody has seen. That case is a test. So are the status
  precedence, an unreadable expiry reading as active rather than expired, and
  that a serialized summary contains no credential.

  `IssuedCredentialSummary` is the census's first `NO_EXT_BY_DESIGN` entry: it is
  a list row rather than a payload root, and its published schema declares no
  `ext` slot, so adding the field would make this crate emit documents the schema
  rejects — the inverse of the defect that census exists to catch.

- **vtc**: Complete the membership edge and draw it on the trust graph ([#1213](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1213))

DTG Core Credentials makes VRCs and VMCs the two subtypes of *edge credential*
  — "in both cases, a bi-directional pair of credentials forms a complete DTG
  edge" — and the community a node like any other. The Relationships page called
  itself "the community's trust graph" and drew only VRC pairs, so a community
  whose members had published no VRCs saw an empty page while every membership was
  an edge it was not drawing.

  Completing that edge needs the digest binding the spec requires, and that needed
  something this service did not keep.

  Keep the credentials we issue. `admit` minted the VMC + role VEC, sent them, and
  stored `top_level_id(&vmc)` — the id, not the body. Three things needed the
  body: verifying a member's `digest` against the grant (an id cannot be
  digested), re-delivering a grant a member lost without minting a *different*
  credential that silently invalidates the acknowledgement they already sent, and
  answering "what does this member hold from us" at all.

  Verify the acknowledgement. `verify_member_vmc` checked issuer, type, subject
  and proof, and never looked for a digest — so no membership edge in the system
  was ever complete. Three outcomes now, not two: a mismatch is refused, because
  an acknowledgement that does not answer the grant we hold would let the
  community show consent it does not have; an absent digest is stored but leaves
  the edge incomplete, because refusing it would unmake memberships validly formed
  under the rules then in force. The asymmetry is safe — an unbound
  acknowledgement claims less, a mismatched one claims something false.

  Draw both kinds of edge. `build_graph` takes membership halves lifted from the
  member rows, where they already sit verified. Lifted rather than copied into the
  relationships keyspace: two records of one fact are free to disagree, and the
  VMC pair has its own lifecycle (status list, renewal, departure) that keyspace
  does not model. One `complete` rule covers both kinds.

  No wire change: `relationships/graph/0.2` pins the response with
  `additionalProperties: false`, and no `kind` field is needed — an edge with the
  community's own DID as an endpoint is the membership one, and the community
  knows its own DID. That is how the console tells them apart.

  Re-issuing a grant clears the acknowledgement bound to the previous one. The
  digest covers claims, so a renewed grant no longer matches, and the member
  visibly owes a fresh one rather than a stale consent standing against a
  membership they never agreed to. `POST /v1/members/{did}/request-vmc` is how an
  operator asks for it.

  Admin console:

  - member detail gains the membership-edge state and the relationship
    credentials naming that member, bodies included, from
    `relationships/list/0.2` — an endpoint that already existed and which nothing
    in this console had ever called. Completeness is read from the graph rather
    than recomputed, so there is one definition of it.
  - the login page shows the community's DID with a copy button, from the
    unauthenticated `/health`. Several VTCs look identical at the login screen,
    and the DID a prospective member needs in order to join was readable only from
    behind a login they did not have.

  The VMC and role VEC *bodies* are still not on `members/show/0.1`: that response
  is `additionalProperties: false` and its own text says the body is not echoed
  there, so surfacing them needs a task authored upstream rather than a field
  added locally.

  Pre-merge checklist (design-docs/vti-stack-development-guide.md):
  - [x] No new HTTP clients; no locks held across a network await (R1.2, R1.3)
  - [x] No local state committed before its remote effect — the digest check runs
        before every write, and a failure writes nothing (R2.1, R7.5)
  - [x] Verification order preserved: a wrong-signer delivery still reports as a
        bad credential, not as "no such member" (R6.4)
  - [x] No wire types changed; the new SPA task URI is bound by a route, asserted
        by `every_admin_ui_task_is_enforced_by_a_route` (R3.*)
  - [x] An unverified digest is reported as unverified, never assumed (R6.3)
  - [x] New Member fields are `#[serde(default)]`; existing rows read as
        unverified, which is the truthful answer for all of them

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

- **vtc**: Generate the console's wire types from the daemon ([#1188](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1188))

#1186 fixed six endpoints where the admin console read a shape the daemon had
  stopped sending. It fixed the six; it could not stop the seventh, and while
  this was being written a user hit exactly that — "Cannot read properties of
  undefined (reading 'challenge')" on the sign-in screen, from a console bundle
  older than the daemon serving it, with no passkey prompt and nothing on screen
  naming the endpoint or the field.

  The defect class is structural, not careless. A hand-written TypeScript
  interface is what `tsc` checks the console *against*, so it cannot be caught
  being wrong. Four consecutive breaking response PRs each left the console a
  little more broken behind entirely green gates.

  So the console's shapes are no longer written. They are derived, through three
  links that each have their own gate:

    routes::openapi_spec()  ⟶  admin-ui/openapi.json   (openapi_snapshot.rs)
    openapi.json            ⟶  src/lib/wire.ts         (npm run wire:check)
    wire.ts                 ⟶  the console             (tsc)

  `wire-types.ts` aliases each generated schema to the short name the plugins
  already used, so call sites read unchanged. Nine files stop declaring wire
  shapes; `BuildInfo` and `HealthResponse` stay hand-written, being served
  outside the `/v1` mount the document describes.

  ## Making the document worth generating from

  The document is assembled from the live route wiring, so its *paths* cannot
  drift — but its response bodies come from a hand-written `body = T`, and
  nothing compared that against the handler's `Json<T>`. Generating from it
  naively would have shipped a console built on whatever the annotations
  claimed. Four had already drifted, each the same way: a PR added a response
  envelope and left the annotation describing the bare row.

  - `backup/export` said `BackupEnvelope`, returns `ExportResponse` ([#1082](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1082))
  - `members/removed` said `[RemovedMember]`, returns `RemovedMembersResponse`
    ([#1082](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1082)) — the same defect #1186 fixed on the console side, still live here
  - `endorsement-types/register` said `EndorsementType`, returns
    `RegisterResponse` ([#1092](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1092))
  - `audit/list` said `Object` for a response typed all along

  `openapi_response_census.rs` now asserts every `#[utoipa::path]` names the type
  its handler returns, with an only-shrinks exception list for the one type that
  genuinely cannot carry a `ToSchema`. A name check is sufficient: the members of
  each schema are derived, so only the name is ever written by hand.

  Attempting the generation surfaced three more document defects, none of which
  was visible in any single annotation:

  - **A dangling `$ref`.** utoipa collects schemas transitively from
    `request_body` and `body =`, but not through an `IntoParams` field, so
    `PolicyStatusFilter` was referenced by `GET /v1/policies` and never
    registered — and `openapi-typescript` refuses to emit anything at all from a
    document containing one. Now `no_dangling_refs`.
  - **Six duplicate `operationId`s over twenty-one operations.** utoipa defaults
    the id to the handler's function name, and handlers are named for what they
    do within their module: seven `list`s, four `revoke`s, three `challenge`s.
    Unique per module, collided per document. Now `operation_ids_are_unique`,
    with explicit `operation_id` on the twenty-one.
  - **`VtcRole` was documented as an object.** It has a hand-written `Serialize`
    emitting `"admin"` / `"custom:editor"`, and a *derived* `ToSchema`, which
    described the Rust enum instead — `"Admin" | {"Custom": "…"}`. The two have
    disagreed for as long as both existed. `role` decides what an operator may
    do and the console compares it against `"admin"`, so the document was
    telling every generated client that comparison can never hold. It surfaced
    as a type error on the promote-to-admin guard. `ToSchema` is now written by
    hand beside the `Serialize` it has to match.

  ## Diagnostics for the console that was not built correctly

  The chain above makes this class a compile error, so in a correctly-built
  console the checks below can never fire. They are for the console an operator
  is actually looking at when something has gone wrong.

  `TrustTaskOpts` gains `requires`: the dotted paths a caller is about to read,
  checked at the fetch seam. The sign-in ceremony, the step-up behind admin
  promotion, passkey enrol/revoke and `whoami` declare theirs — the calls whose
  failure an operator otherwise meets as `undefined` several frames away. The
  message names the endpoint, the missing member, what did arrive, and the two
  things that actually cause it: a cached bundle, or a daemon built with
  `VTC_SKIP_ADMIN_UI_BUILD=1` over a stale `admin-ui/dist/`, which embeds it
  as-is.

  `Login.tsx` also tracks whether the ceremony reached
  `navigator.credentials.get`. A failure before that point cannot involve the
  operator's passkey, authenticator, or browser, and saying so rules out the
  half of the problem space they would search first. That is the report this
  started from: "they don't even get prompted."

- **vtc**: State artifact lifecycle precedence once, and apply it on read ([#1179](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1179))
- **vtc-service**: Enforce Trust Task Context Binding on presented credentials ([#1178](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1178))

`taskContext` had zero occurrences in `vtc-service`. DTG Credentials marks it
  REQUIRED on the VWC and defines Trust Task Context Binding as the mechanism
  that keeps a credential from escaping the exchange that produced it; Security
  Considerations 5 names what its absence permits — **context collapse**, where a
  credential that is genuinely signed, correctly typed, unrevoked and in date is
  presented as evidence that *this* ceremony reached its terminal state, when it
  was issued during some other exchange entirely.

  The ceremony pipeline was exposed to exactly that: it evaluates credentials as
  facts and decides on them, and nothing in a fact said which exchange a
  credential came from.

  Three parts, following the division of labour `credentials::witness` ([#1161](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1161))
  established — the host settles what needs storage or keys, the policy branches
  on a settled state:

  - **Captured.** `VerifiedPresentation` gains `task_context`, read at verify
    time from the credential's top level. It had to be captured there for the
    same reason `credential_status` is: the DI and bbs paths keep only
    `credentialSubject` in `claims`, so a `taskContext` read downstream would
    have been unconditionally absent on those paths — a verifier structurally
    unable to see the binding it is required to enforce.

  - **Enforced on receipt.** A VWC with no `taskContext` is refused, at both
    ingress points: `credentials::ingress::classify_dtg` for JSON-LD arrivals
    (where the catalog's own `TryFrom` puts the same check) and the
    credential-exchange present path for SD-JWT-VC / DI / bbs arrivals. Refused
    rather than defaulted to the current thread — defaulting would manufacture
    the binding being checked, and would award the strongest verdict to the
    credential least entitled to it.

  - **Asserted in the evidence.** `Context.thread_id` names the exchange the
    ceremony *is*; `Credential.task_context` names where each credential came
    from, as a resolved `TaskContextBinding`. A policy asserting an outcome can
    now require `sameExchange`; without the pair, "a credential from another
    exchange" is not expressible.

  A mismatch is reported, not refused. A VWC's `taskContext` names the exchange
  the *witnessing* happened in, which is never the join exchange it is later
  presented in, so rejecting on mismatch would refuse every honest witness. The
  specification's own note draws that line: a verifier must not read a
  `taskContext`-bearing credential as proof the associated task completed without
  the matching outcome evidence. Thread ids are compared verbatim; there is no
  specified canonicalization, and inventing one would fail open.

  Not included: issuance. Nothing in this workspace mints a VWC — `new_vwc` has
  no caller — so there is no issuance flow to carry `taskContext` through. The
  catalog constructor already takes it as a required parameter, so the first
  issuance path cannot omit it.

- **vtc**: Verify the digest binding on a presented witness credential ([#1161](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1161))

A VWC asserts that its issuer witnessed one specific relationship, and the
  only thing saying *which* is `credentialSubject.digest`. Nothing recomputed
  it. The ceremony engine took `WitnessCredential` as a policy fact carrying
  trusted-issuer, validity and holder-binding predicates and reasoned to a
  decision on the assertion that a witness was present, with no code path that
  could have established which edge — if any — it witnessed.

  DTG Credentials Security Considerations 4 is explicit: without recomputing
  the digest against the referenced VRC, a VWC "should not be treated as
  evidence of which edge was witnessed".

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

- **vtc**: Close the two DTG personhood-conformance gaps ([#1089](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1089))

* feat(vtc): let a community publish what its governance says about personhood

  DTG Credentials puts PHC status outside the credential: "PHC status is
  determined by governance and trust registries, not by credential structure",
  and the `PersonhoodCredential` type this daemon stamps on a vetted member's
  VMC is described there as a *non-authoritative hint*. §Governance
  Considerations item 2 is blunter — "Whether a VMC qualifies as a PHC is a
  governance determination, not a schema property."

  Nothing carried that determination. A conformant verifier holding one of this
  community's VMCs was told by the type array not to trust the type array, and
  had no second place to look.

  `CommunityProfile` now carries a `personhood` block — the two clauses of the
  spec's definition as separate booleans, the identity-verification providers
  this community accepts, and where its governance framework can be read. The
  shape follows `relationshipIdentifierDefault`, which already exists to let a
  client read what a community expects.

  Served **unauthenticated** on `/v1/community/public-profile`. The party who
  needs this is a verifier who is not a member, holds no token, and may have no
  relationship with the community at all; behind auth it would answer the
  question only for people who did not need to ask it.

  Two rules the type enforces:

  - **Both booleans default to false.** A community that has never considered
    the question asserts nothing. Any other default has every existing
    deployment publishing a claim a verifier might act on.
  - **Claiming both requires naming an accepted IDVP.** A community asserting
    PHC status while naming nobody it trusts to verify identity has not written
    its governance down, and a verifier cannot distinguish an unwritten policy
    from a permissive one. A community that vets in person lists its own C-DID —
    §IDVC explicitly permits acting as your own identity-verification provider.

  `realHuman` and `singleMembership` are separate fields because they are
  separately achievable. This daemon's in-person vetting supports the first and
  does nothing for the second, and a community in that position should be able
  to say so rather than choosing between overclaiming and silence.

  A patch replaces the block wholesale rather than merging field by field. The
  two booleans are a conjunction an operator asserts together, and a partial
  patch flipping one while the other kept whatever it happened to be is how a
  community ends up claiming PHC status it never meant to.

- **vtc**: Authenticate publishing by the document's own proof ([#1088](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1088))

`POST /v1/relationships` took a bearer token and a bare `{vrc, pop}` body. It
  now takes a signed Trust Task document and no token at all.

  ## Why the bearer went

  The specification for the publish authorization binds it to the enclosing
  document's `id` (trustoverip/dtgwg-trust-tasks-tf#259). This route received no
  document, so the merged schema was unimplementable on the surface it governed
  — #1084. Accepting a document fixes that and supplies the members the schema
  assumes: `id` for the binding, `recipient` for the audience, `issuedAt` for
  freshness.

  Once the document carries a proof, the token answers a question already
  answered, and better: a proof is transport-independent and cannot be used by
  whoever captured it. Two of the three reasons to keep it dissolved — audience
  binding is the document's `recipient`, and rate limiting had no business being
  tied to a session in the first place.

  What a session gave that a proof cannot is **immediate revocation**. A
  signed-out session stops working on the next request; a proof has no such
  handle. Publishing is therefore governed by ACL membership rather than session
  state, and that is deliberate: a member who has signed out but not been removed
  is still a member, and it is not obvious they should be barred from publishing
  an edge they hold the key for. Removing them from the community still stops
  them immediately, because `is_current_member` reads the ACL live.

  ## Rate limiting moved to the member

  Keyed on an HMAC of the signer, not the address they arrived from — one member
  moving between addresses evaded the per-IP governor, while a community behind
  one NAT was throttled as a single caller. Hashed for the same reason the audit
  writer hashes actors: a counter keyed on raw DIDs is a live register of who is
  active here.

  It runs after proof verification, so it cannot bound the cost of verification
  itself. That stays the governor's job, and the route has moved onto the
  governed chain to keep it — the same reason `auth/recognise` lives there, since
  both run DID resolution and signature checks on attacker-supplied JSON before
  they know who is calling.

  The window is per process: N replicas enforce it N times. A sizing property,
  stated in the module rather than discovered later.

  ## One digest, the one the specification names

  Every hash in this path was a bare lowercase-hex SHA-256 over a recursive key
  sort. That form hard-codes an algorithm into the wire contract, names no base
  encoding, and — worse — names no canonicalization a second implementation could
  reproduce, so two conforming services could digest the same credential
  differently and neither be wrong.

  All of them are now RFC 8785 + multihash + base58btc: the stored row, the
  idempotency key, the publish authorization, and the VPC authorization.
  `canonicalise()` is deleted. Its doc comment argued "we only need a
  deterministic form, not a standard one", which was true while the value was
  internal and stopped being true when it went into a response.

  That in turn made `relationships/publish/0.2` the right version to bind: 0.1
  asks for a bare-hex `vrcSha256` this service no longer computes.

  ## Tests

  Both responses are `#response` documents, so the suite asserts the envelope as
  well: `threadId` correlation, and issuer/recipient swapping.

  Three tests pinned properties that no longer exist and were rewritten one layer
  up, where the property moved — replay into another document, a document
  addressed to another community, an expired document. The last two are the only
  things in the suite that prove `validate_basic` is wired in at all.

  Three more were retired with their reasons recorded in place, not deleted
  silently: they asserted a session DID differing from the VRC issuer, a
  malformed VRC now covered more thoroughly by the catalog-backed shape tests,
  and an ordering this change deliberately reverses.

  Mutation-tested rather than assumed: neutering the `documentId` binding fails
  `rejects_an_authorization_replayed_in_another_document`; accepting an unsigned
  document fails `rejects_a_document_with_no_proof`. Both reverted.

- **vtc**: Reach personhood over messaging, and bind its challenge to something signed ([#1086](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1086))

Personhood was REST-only. `openvtc` — which talks to communities over
  DIDComm and TSP and holds no bearer token — could not run the ceremony at
  all, so the member half of the feature had no client that could reach it.

  `members/personhood/{challenge,assert}` now route through the messaging
  Trust Task dispatcher alongside the join verbs. The route handlers keep
  their bodies in `challenge_inner` / `assert_inner`, which both transports
  call, because two implementations of one ceremony is a security difference
  nothing tests.

  Each verb carries its own caller gate, since "an authenticated session" —
  what the REST routes rest on — has no equivalent on a transport that only
  proves who sent the bytes. Challenge requires the caller to be a member of
  this community. Assert requires the sender to *be* the subject, which is
  `assert/0.1`'s own `exposure.actsAsSubject: true`: the member exercising
  authority over their own personhood state.

  ## The challenge was not bound to anything

  `assert/0.1` §Authorization says the challenge binding "establishes that
  this presentation was made for this exchange, and is what stops one captured
  and replayed into another". In W3C Data Integrity that holds because the
  proof options are canonicalised with the document, so `challenge` is signed.

  `affinidi_data_integrity`'s `DataIntegrityProof` has no `challenge` field,
  and `verify_vp_proof` verifies over the presentation with the whole `proof`
  block removed. So `proof.challenge` was **unsigned**. Anyone holding a
  captured presentation — a relaying mediator, anyone with log access — could
  mint a fresh challenge for that member, swap the one unsigned field, and
  replay it. The signature still verified, because it had never covered the
  challenge. For a flag whose revocation is an administrative act, that means
  a revoked assertion could be restored without the member's participation.

  The challenge must now also appear at top-level `nonce`, which is outside
  the proof block and therefore covered by the holder's signature, and the two
  copies must agree. This is what the published task already says the binding
  does; it just did not do it.

- **vtc**: Let a community vet a member in person and have it count as personhood evidence ([#1085](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1085))

* feat(vtc): let a community vet a member in person and have it count as personhood evidence

  Personhood already shipped, and it already matches DTG Credentials: a PHC
  is a VMC, and `new_vmc(personhood: true)` appends `PersonhoodCredential`
  exactly as the spec's worked example shows. What was missing was the
  ceremony an operator actually performs — meeting someone, satisfying
  themselves the DID in front of them is theirs, and having that count.

  The default `personhood.rego` accepted one evidence shape: a
  `WitnessCredential` from some third party. An administrator who did the
  verifying themselves had nowhere to put it.

  So the community's own vetting becomes evidence, issued through
  machinery that already exists. DTG Credentials §Identity Verification
  Credentials defines an IDVC as "any W3C VC satisfying a VTC/VTN's
  identity-proofing requirements" and explicitly *not* a `DTGCredential`
  subtype, so a community acting as its own identity-verification provider
  needs no new credential type. Registering `IdentityVerification` as an
  endorsement type and issuing it per member reuses
  `vtc/endorsement-types/register/0.1` and `vtc/endorsements/issue/0.1`
  verbatim — no new Trust Task family, and revocation comes free via the
  community's existing status list.

  `vtc/members/personhood/assert/0.1` is untouched, which was the
  constraint worth respecting: its Authorization section is explicit that
  holder-equality and challenge-binding are both load-bearing and neither
  substitutes for the other. An admin-asserts-directly path would have had
  to bypass the presentation the task requires, so the vetting is evidence
  the member presents rather than a gate the admin steps around.

  Three bindings, each enforced and each with a test that breaks exactly
  one of them:

  - `issuer == community_did` — an endorsement type is a *name*, not an
    authority. Without this any issuer anywhere could mint a credential
    typed `IdentityVerification` and unlock personhood here. This is why
    `community_did` is now in the policy input at all.
  - `credentialSubject.id == applicant_did` — the route's holder-match
    binds the presenter; this binds the credential, so a member cannot
    present a vetting record issued about somebody else.
  - the endorsement type — a role VEC is community-issued and names the
    member too, so without the type check every member holding a role
    credential satisfies the policy, which is every member.

  Two further tests run a credential from the real builder through the
  real extractor into the real policy. Every other test in the file
  hand-writes `vp_claims`, so they all agree about a shape none of them
  obtained from the code that produces it; if `build_custom_endorsement`
  moved `endorsement` out of `credentialSubject`, they would all keep
  passing while every vetting in production was denied.

  Also adds the spoken match code. `challengeId` is a UUID — fine on a
  wire, hopeless read aloud — so the challenge response carries eight
  Crockford base32 characters derived from it (no I/L/O/U, nothing
  mishearable). It is derived, never transmitted as an independent secret
  and never accepted as one: both parties compute it from the id they
  already hold and say it to each other. Nothing checks it server-side,
  because there is nothing it could prove that `proof.challenge` does not
  already prove. It rides in `ext` because the response schema is
  `additionalProperties: false` — a conformance witness now pins that,
  and it does fail if the field is moved to the top level.

  What this deliberately does not do: enforce uniqueness. DTG Credentials
  requires governance enforcing both real human personhood *and* exactly
  one membership per person, and this is evidence for the first only.
  Nothing stops one human joining twice under two DIDs and being vetted
  twice. The spec also locates PHC status in governance and trust
  registries rather than credential structure — the `PersonhoodCredential`
  type is described there as a non-authoritative hint. Both limits are
  stated in the policy module and in the operator guide rather than left
  for someone to discover.

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

- **vtc**: Distinguish half-edges from complete edges in the relationships graph ([#1073](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1073))

DTG Credentials defines a DTG edge as two VRCs, one in each direction.
  `GET /v1/relationships/graph` returned one entry per stored VRC
  (`vtc-service/src/routes/relationships.rs:793-813` before this change), so a
  mutual relationship and a unilateral claim rendered identically: two members
  who had each vouched for the other looked the same as one member asserting an
  edge the other has never acknowledged.

  That distinction is what the dropped subject-membership check was replaced
  with. #1061 stopped requiring the subject to be a current member, on the DTG
  rule that "community membership is not a precondition for issuing, holding, or
  presenting a VRC", and on the reasoning that the subject's consent to an edge
  is their publication of the reciprocal VRC rather than the community asserting
  on their behalf that they exist. An operator who cannot see whether that
  reciprocal VRC arrived cannot see the consent signal at all.

  The response now groups by unordered pair. Each edge carries `endpoints`
  (DID-sorted, so a pair has one identity whichever half was published first),
  `halves` (every VRC published between them, oldest first, each with the row id
  `DELETE /v1/relationships/{id}` takes), and `complete` (a VRC exists in both
  directions). Grouping is a pure function, `build_graph`, so the rule is unit-
  testable without a keyspace.

  Two cases are easy to get wrong and are pinned by tests:

  - Several VRCs in the same direction do not complete an edge. Idempotency is
    keyed on the credential hash, not on direction
    (`vtc-service/src/routes/relationships.rs`, step 8), so a member can publish
    three A->B VRCs. `complete` checks for a VRC in each direction, not for two
    rows.
  - A self-issued VRC (`issuer == subject`) is never complete. It has no
    counterparty who could reciprocate, and the naive both-directions test
    matches the same row twice. Nothing on the publish path rejects one.

  The admin UI draws a complete edge solid and double-headed, a half-edge dashed
  and single-headed pointing at the party who has not answered, counts the two
  separately in the overview, and labels a selected node's edges "mutual with" vs
  "not reciprocated".

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

- **vtc**: Show which transport each service is actually reached on ([#965](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/965))

"Trust registry: active" and "Mediator: DIDComm transport ready" were
  true of every deployment that had one configured. Neither said which
  protocol was carrying the traffic, and the mediator line said DIDComm
  even on a VTC whose document advertises only TSP — so the tile that
  looked most reassuring was the one most likely to be wrong.

  Diagnostics gains two views. `registry_transport` carries the
  registry's DID (or URL), the protocols its own DID document
  advertises, the protocol the last call actually chose, and the error
  if selection failed. `transports` is this VTC's own advertised-versus-
  servable matrix, from the same helper the unauthenticated community
  profile already publishes — an operator comparing the two should never
  see them disagree.

  Advertised and active stay separate deliberately. A registry that
  advertises TSP while this VTC can answer only DIDComm is configured
  and unreachable at the same time; one merged "protocol" field would
  have to pick one of those facts and drop the other. The same split is
  why a failed selection still records what the peer offered — that is
  the half that says which side to fix.

  The registry client records the outcome on every selection rather than
  caching at boot, because selection is itself per-call: a registry that
  adds `#tsp` mid-life is reached over TSP on the next attempt, and the
  snapshot has to be re-falsifiable in both directions.

  In the UI: the mediator tile names the live protocols, a trust-registry
  tile carries the active one, the registry DID appears under Identity,
  Recognition shows advertised / connecting-over / last error, and a
  "Transport advertisement" card appears when the document and the build
  disagree — the state where a *more* conforming client fails harder,
  and the fix is a document change rather than a restart.

  Not covered: the VTA tile is unchanged. The VTC↔VTA relationship is
  provisioning-time (sealed bundle over REST), with no runtime session
  to report a protocol for, so there is nothing honest to put there.

- **vtc**: Reach the trust registry by DID over TSP or DIDComm ([#963](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/963))

* feat(vtc): reach the trust registry by DID over TSP or DIDComm

  The trust registry was addressed by URL and written to by nobody:
  `publish_member` / `delete_member` / `read_member` were `Permanent`
  stubs against a `tr-admin/1.0/*` premise the registry has since
  replaced, and `with_atm` was never called, so membership never synced.
  Meanwhile `health()` probed `GET /.well-known/did.json`, which stays
  green while every write fails — a health flag that could not go false
  for the thing it was reporting on (R6.2).

  `registry.did` is now the address. The VTC resolves it, reads the
  transports it advertises, and uses the highest-preference one both
  sides speak (TSP > DIDComm > REST, matched on service `type`, never on
  the `#id` fragment). No overlap raises `NoMatchingProtocol` carrying
  both advertised sets rather than silently downgrading. `registry.url`
  becomes the REST arm of that client, and still selects the HTTP-only
  client on its own.

  Everything rides canonical Trust Tasks: `registry/record/put`,
  `registry/record/delete`, `registry/record/query`, and
  `registry/recognition`. Writes carry the VTC's Data-Integrity proof
  from the same assertion key that mints VMC/VEC — the key the registry
  already verifies on the git-trust path. Reads carry none, per the
  specs' own `IS_PROOF_REQUIRED`.

  Health is a read-only `record/query` round trip. It needs no proof and
  no admin ACL, so it works on a registry that would refuse our writes,
  but it exercises mediator, transport, dispatcher and storage. Any
  correlated reply counts as alive, including a rejection; only silence
  is unhealthy.

  Replies reuse the hook writer's `PendingReplies` (field renamed to
  match its widened role), so the DIDComm arm needed no new inbound
  plumbing. The TSP arm did: `handle_tsp` dispatched every frame as a
  request, so a reply would have been answered with an unsupported-type
  error while the caller timed out. It now demuxes `#response` and
  `trust-task-error` documents to their waiters first.

  TSP framing differs between the two repos: this workspace sends bare
  Trust-Task bytes, the registry implements the published
  `trust-tasks-tsp` binding envelope and rejects anything else. We emit
  the envelope and accept either shape inbound.

  The record key tuple (`recognise` / `trust-graph`) moves to shared
  constants read by both clients — publishing under a tuple the
  recognition query does not use would be a silent, green-status
  failure.

  Not covered: no end-to-end test against a live registry. The unit
  tests pin the wire shapes, the reply classification, and the demux;
  the round trip itself needs a mediator and a registry.



### Build & CI

- **vtc-service**: Publish to crates.io ([#2192](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2192))

* build(vtc-service): publish to crates.io

  Make vtc-service publishable again, so an operator can install the VTC with
  `cargo install vtc-service` (the `vtc` binary), as pnm-cli and cnm-cli are
  installed. #938 unpublished it because no crate depended on it; that is still
  true, so it is published as a binary and carries no semver check
  (release-plz.toml `semver_check = false`, excluded in scripts/semver-report.sh).

  The crate name is ours (0.11.58 is the last copy on crates.io, from before
  #938). Its whole normal-dependency closure is published: vti-vetting-pcs
  (optional) and vti-rooms-dtg gain the version requirements they lacked, and
  predicate-credential-system is on crates.io.

  Web bundles. build.rs npm-builds the admin console and member portal into
  OUT_DIR, which a crate built from crates.io must not do: it would need Node and
  the network on every `cargo install`, and `npm install` would write
  node_modules into the registry source directory, which the verify build of
  `cargo publish` refuses (the reason it was once published with `--no-verify`). So the
  package ships the built bundles, not the npm project:

  - scripts/build-vtc-web-bundles.sh builds admin-ui/dist and
    admin-ui/dist-members (`npm ci`, then both vite builds);
  - `include` in vtc-service/Cargo.toml lists those two (gitignored, so only
    `include` brings them in) plus src/, policies/, website-default/ and
    build.rs — everything a non-test `include_dir!`/`include_str!` reads;
  - build.rs, finding no admin-ui/package.json, bakes the bundles it was given,
    and fails naming the script when they are missing. A source checkout is
    unchanged;
  - publish.yml runs the script (Node from admin-ui/.nvmrc) in the release job
    before the Trusted Publishing exchange, so release-plz's and the recovery
    hatch's `cargo publish` both find the bundles. Not in the Release PR job:
    release-plz copies the project honouring .gitignore there, and its package
    comparison stops at the commit the published package records anyway.

  The package is 538 files, 17.4 MiB, 5.7 MiB compressed (crates.io limit 10 MB).

  CLAUDE.md, RELEASING.md, RELEASES.md, release-plz.toml, publish.yml and
  prepare-release-branch.py now give the publish set as 26 of 35.

- Trust-tasks-rs 0.31, affinidi-messaging-sdk 0.36 and affinidi-tdk 0.26 ([#2059](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2059))

The twelfth crossing, step 2. trust-tasks-rs 0.31's one break makes a
  `vta-account` storage config name its account's context as well as its
  identifier (trustoverip/dtgwg-trust-tasks-tf#758). The messaging SDK carries
  trust-tasks-rs types in its public API, so it moves in lockstep:
  affinidi-messaging-sdk 0.36, affinidi-tdk 0.26, mediator-admin and
  mediator-tui 0.11, test-mediator 0.22 (affinidi-tdk-rs #944). One
  trust-tasks-rs in the graph.

  No source change: this build stores to `local` configs only and refuses a
  `vta-account` one, so nothing reads the new member yet. The lock is resolved
  minimally: only these crates move.

- Trust-tasks-rs 0.30, affinidi-messaging-sdk 0.35 and affinidi-tdk 0.25 ([#2049](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2049))

Moves the Trust Task stack to trust-tasks-rs 0.30 (capability-client,
  https, didcomm, tsp and proof with it) and the Affinidi crates that move in
  lockstep with it (affinidi-tdk-rs #940): affinidi-messaging-sdk 0.35,
  affinidi-tdk 0.25, mediator-admin/tui 0.10 and test-mediator 0.21. One copy
  of each resolves; trust-tasks-rs 0.28 no longer appears in the graph.

  0.30 carries dtgwg-trust-tasks-tf #750, which makes the rooms/info and
  rooms/usage proofs REQUIRED. The interim DISPATCHED_WITHOUT_PROOF entry for
  rooms/info ([#2040](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2040)) and its skip in
  every_rooms_task_declares_the_proof_its_arm_requires are removed: the
  census now holds the VTC's rooms/info arm to the specification.

- Trust-tasks-rs 0.28, affinidi-messaging-sdk 0.34 and affinidi-tdk 0.24 ([#2028](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2028))

Moves the workspace to trust-tasks-rs 0.28 (with capability-client, https,
  didcomm, tsp and proof) in lockstep with the Affinidi messaging crates built
  against it (affinidi-tdk-rs #933): affinidi-messaging-sdk 0.34, affinidi-tdk
  0.24, mediator-admin / mediator-tui 0.9 (pnm messaging console) and
  test-mediator 0.20. The lock holds one trust-tasks-rs, one trust-tasks-proof,
  one SDK and one tdk: `MediatorAcl` crosses the SDK's API, so a graph holding
  two trust-tasks-rs does not compile.

  0.28's one break, the rooms 0.1 `NOT_AUTHORIZED` constants withdrawn for the
  standard `permissionDenied` (trust-tasks-tf #743), touches nothing here: the
  room host already answers `permissionDenied`.

  It carries `DeclaredErrorCode::details_schema` / `check_details`
  (trust-tasks-tf #742), so the rooms/keys/file-key handler tests check
  `unknownEpoch` details against the schema the specification declares rather
  than a hand copy, and vta-service's jsonschema dev-dependency, which existed
  only for that copy, is dropped.

  Publishing a vta-sdk on SDK 0.34 / tdk 0.24 is step 2 of the crossing
  affinidi-tdk-rs's workspace-duplicates-allow.txt records; step 3 moves the
  mediator's vta-sdk requirement to it there.

- Trust-tasks-rs 0.27.8, with auth/oob on its generated types ([#2011](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2011))

* build: trust-tasks-rs 0.27.8 — auth/oob, room files and external accounts

- Quote the run lines that end in a test-path filter ([#1865](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1865))

* ci: quote the run lines that end in a test-path filter

  #1862 made two run: values end in `join_tsp::` and `registry_didcomm::`.
  A plain YAML scalar ending in a colon parses as a mapping key, so the
  whole workflow was invalid and CI has not run on main since.

- Faster test loop — no-fail-fast, one test binary per service, skip admin-ui in Rust-only jobs ([#1862](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1862))

* ci: report every test failure per run, skip admin-ui build for Rust-only jobs

  Add --no-fail-fast to every `cargo test` invocation that lacked it, so one
  CI run surfaces every failing test binary instead of stopping at the first.

  Set VTC_SKIP_ADMIN_UI_BUILD=1 in Check, MSRV, Clippy and the all-features
  lint job: none of them execute vtc-service's tests, so none of them need
  the real admin-ui npm build — only routing_modes.rs (in Test (VTC)) reads
  the baked bundle's actual content, and that job is left alone.

- **vtc-admin-ui**: Run the admin console's unit tests ([#1731](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1731))

* ci(vtc-admin-ui): run the admin console's unit tests

  CI only ever built the admin console: `cargo build -p vtc-service` runs
  `npm run build` (`tsc -b && vite build`), so its vitest suite (400 tests)
  and the openapi.json -> src/lib/wire.ts drift check ran nowhere but a
  developer's machine.

  Add `Test (VTC admin UI)`: setup-node from the console's .nvmrc with the
  npm cache, `npm ci` against the lockfile, `npm run wire:check`,
  `tsc -b --noEmit` and `vitest run`. No Rust, no secrets, 10-minute
  ceiling, gated on the VTC closure like Test (VTC). It is the only JS/TS
  package in the repository with tests.

  Also make `Test (VTC)` robust against the timeout #1725 hit (a slow
  runner: disk freeing 7.4 min, tests 21 min, then the no-op guard):

  - free disk only when under 30 GB is available; the image has ~80 GB
    before the removal, which cost 0.6-2.5 min on every normal run
  - the #1243 no-op guard re-runs the test step's own build with
    `--no-run` instead of a separate `cargo build -p vtc-service`, which
    compiled vtc-service afresh (~2 min) before it could check anything
  - its own cache key (it shared `cargo-test-` with Test (workspace)),
    now also caching ~/.npm for build.rs's `npm install`
  - timeout 30 -> 40 minutes for headroom over a slow runner; a real hang
    still ends the job

- **deps**: Dtg-credentials 0.11 ([#1669](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1669))
- **release**: Adopt release-plz, publish 7 crates instead of 21 ([#938](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/938))

Merging and releasing were the same act. publish.yml fired on every push to
  main and shipped whatever versions were newly present, and a CI guard required
  the version bump to live in the feature PR — so every PR was a release
  decision, taken by whoever opened it, days before it merged. Two open PRs
  touching one crate wrote the same number into the same line of the same
  Cargo.toml, and the second to merge had to rebase, renumber, and fix a
  changelog entry that had gone stale. #932/#936/#937 hit it three times in one
  afternoon.



### Changed

- **vtc**: Drop vtc-client's unused bearer token and the uncalled persona REST route ([#2023](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2023))

* refactor(vtc-client): keep no bearer token, and say what the VTC's REST surface now is

  Every verb `vtc-client` sends is a signed Trust Task, and the last bearer
  routes it called are gone, but the client still stored the access token
  `connect` obtained and its docs still described verbs "on bearer REST until
  they have a Trust Task".

  - `VtcClient` no longer holds a token. `connect` still runs the
    challenge-response login: it is the up-front access check, so a DID the VTC
    does not know is refused where `cnm` can print the fix rather than on the
    first verb. Its token was read by nothing but `Debug`, which now reports
    whose signing key is held.
  - Docs: the vetting-admin "stays on bearer REST" note,
    `VtcError::NoRestTransport` (now: no REST base and no session to carry a
    Trust Task), `with_key`, and the `self.token` mentions in `git_ns` and
    `rooms`.
  - vtc-service: the surface-task and join-discovery comments no longer say
    those verbs keep a REST route; the persona route's exception rows say what
    is true — `vtc/relationships/persona/0.1` has no upstream specification,
    which is why the spine cannot dispatch it.
  - cnm: the withdrawal hint pointed at `GET /v1/join-requests/<id>/vetting`,
    which is not mounted; it now points at the join request in the console.
  - admin-ui: a comment named `POST /v1/schemas/accepts` for what is
    `vtc/schemas/accepts/register`.

- **vti-common**: Share the durable Trust Task push engine between nodes ([#1760](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1760))

#1754 gave the VTC a push engine that picks TSP > DIDComm > REST by what the
  recipient's DID document advertises. It records each push durably, queues one
  outbox attempt per transport, settles on delivery evidence and escalates when
  an attempt yields none (VTI-TRN-030, -040, -041, -042). The VTA's own pushes
  (`consent_request::push_one`) are still best-effort TSP followed by DIDComm,
  and to adopt the same model the engine has to live somewhere both nodes can
  reach.

  It moves unchanged to `vti_common::trust_task_push`. The node lends it what is
  its own through a `PushContext`: the records keyspace, the outbox, the
  resolver, its messaging handle and whether it can send TSP. The REST transport
  takes its HTTP client, so each node supplies its foreign-fetch profile.
  `vtc-service::member_push` is now that adapter, and its call sites are
  unchanged.

  The outbox transport ids keep their `member-push-*` values, so attempts queued
  before an upgrade still drain after it. `vti-common`'s `tsp` feature now also
  enables `affinidi-tdk/tsp` and `vta-sdk/tsp` for the TSP transport. That
  exposed two items in `vta-sdk` gated on `tsp` but used only with `client`,
  which are now gated on both.

  The VTA moving onto the engine is a follow-up.

- **vti-common**: Move the task-consent core out of vta-policy so the VTC can share it (VTI-APV-014) ([#1730](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1730))

VTI-APV-014 requires consent from a party other than the requester before
  anyone is granted unrestricted act scope. The VTC is to meet it with the same
  `task-consent/*` ceremony the VTA runs (VTI-VTC-020: one model, not a parallel
  one), but the ceremony's data layer lived in `vta-policy`, which the VTC cannot
  depend on. This moves it to `vti-common` first, so the VTC work that follows
  reuses it rather than copying it.

  - `vta-policy/src/consent.rs` -> `vti_common::task_consent` and
    `vta-policy/src/effects.rs` -> `vti_common::task_consent::effects`, moved
    with their history. `vta_policy::{consent, effects}` re-export them, so
    every existing path still resolves and the VTA's behaviour is unchanged.
  - `domain_digest(domain, type_uri, payload, salt)` exposes the digest
    construction for another domain tag. The VTC's operation-bound step-up
    carried a byte-for-byte copy of it under `vtc/step-up/v1\0`; it now calls
    this instead.
  - `digest_matches_its_pinned_vectors` pins both domains against vectors
    computed independently of this code, so the move provably changed no
    digest: a stored pending or grant, and a mark in flight, still resolve
    after an upgrade.
  - The `vta/task-consent/v1\0` tag is kept, since it keys the pendings and
    grants in flight. It separates this digest from others, not one node from
    another, because a pending never leaves the node that minted it.

  No wire change and no behaviour change.

- **vtc**: One place that packs a Trust Task for the wire ([#1504](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1504))
- **vta-sdk**: Vetting wire types come from the published trust-tasks specs ([#1439](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1439))

* build(deps): bump the trust-tasks crates to 0.20.4

  trust-tasks-rs 0.20.4 is the first release that carries generated Rust
  types for the peer identity vetting Trust Tasks (vetting/request,
  vetting/session, vetting/decline, vtc/vetting/revoke-statement,
  vtc/vetting/vetters/{grant,profile,list,resend}) and for
  vtc/join-requests/manifest/0.2. The binding crates (-https, -didcomm,
  -proof, -capability-client) are released at the same version and move
  with it.

  Only the version requirements and the lockfile change; the feature set
  (`validate`, `all-specs`) already covers the new spec modules.

- **sdk**: Move the Trust-Task proof verifier down from vti-common ([#1340](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1340))

Pure move plus re-exports; no behaviour changes. It exists so the next
  change can be small: `VtaClient` needs to verify the responses it receives,
  and the verifier it needs already exists one layer up where a client cannot
  reach it.

  `vti-common` was the right home while services verifying their *inbound*
  requests were the only consumer. A client verifying its *replies* is the
  same operation over the same document shape, and `vta-sdk` is the layer both
  can see.

  **The part worth not duplicating is the verification-method resolver.**
  Resolving one looks trivial and is not: a DID document may name its methods
  absolutely (`did:webvh:…:glenn#key-0`) or relatively (`#key-0`), while a
  proof always names them absolutely, so a resolver accepting only the
  spelling it expects refuses perfectly good documents from conforming peers.
  A second copy would drift, and drift in a verifier means refusing honest
  documents or accepting dishonest ones. Writing that copy is what this move
  avoids.

  Behind a new `proof-verify` feature rather than `client`, because
  `vti-common` takes `vta-sdk` with `default-features = false` and must not
  acquire reqwest to keep verifying. It adds no dependency to `vti-common` —
  that crate already depended on `affinidi-data-integrity` and the DID
  resolver directly. `client` enables it: a client that cannot verify its
  replies is the gap being closed.

  The resolver rides in the feature deliberately. Verification is only as good
  as the party it resolves — a `did:key` signer needs no I/O, and a
  `did:webvh` one, which is what a real agent is, cannot be verified without
  resolving its document.

  Call sites that used the module path (`vti_common::auth::di_proof::…`) now
  use the flat re-export, so there is one canonical path rather than an alias
  to go stale. Two doc comments naming the old location updated with them.

  `cargo clippy --workspace --all-targets` clean; `vta-service --lib` 1063
  passed; `vta-sdk` + `vti-common` suites pass, including the four resolver
  tests that moved with the code.

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



### Documentation

- **vtc**: Console design language for the redesign (phase 4) ([#2030](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2030))

admin-ui-design-language.md is rewritten to describe what the console,
  member portal and home page do now: the shared tokens.css and its
  byte-identical home-page copy, IBM Plex Sans and Mono self-hosted, the
  indigo brand with the community-accent override, the colour theme and
  the vtc-admin-theme key shared by all three surfaces, the shell (top
  bar, grouped sidebar, account menu, attention strip, command palette),
  the shared components and the list, dashboard and Actions patterns.

  website-and-admin.md describes the shell and the sidebar groups, says
  Policies and Profile were Ceremonies and Community profile with routes
  unchanged, moves the banners into the attention strip, fixes the fonts
  in the build diagram, and notes that a console or portal served from a
  directory keeps its look until it is exported again. vetting.md and the
  admin-ui README use the new labels and dashboard.

  Stale CSS comments fixed (comments only): the theme switcher's files in
  tokens.css (and its copy), pages.css and index.css on which pages use
  login-card, two components.css section headings left over from the
  split, and Ceremonies in ceremonies.css and policy-flow.css.

- **vtc**: Changing a community's transports after mint; console sign-in says which identity it presents ([#1679](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1679))

Keyring VTI-12: the docs, the setup wizard, the example setup TOML and the
  vtc-host template all still said a VTC serves a "write-once" did.jsonl, so a
  community's transports (and TrustRegistry referral) were "fixed at mint".
  That stopped being true with VTI #1632 (`cnm did-log install`,
  did-management/did/register/0.1), but the only guidance was scattered: a
  module doc, a pnm hint, and one line in each of two docs.

  - docs/03-vtc/community-lifecycle.md: a new section, "Changing the
    community's transports after mint". It covers checking `Server:` with
    `pnm did-mgmt dids get`, `pnm did-mgmt dids edit --did`, the #tsp entry's
    shape (serviceEndpoint = mediator DID), `pnm did-mgmt dids get-log <did>
    --out`, and `cnm [--url] [-c] did-log install --file`, with every flag
    checked against the clap definitions. It explains why a VTC on a DID host
    needs step 1 only (the VTA pushes to the host, and cnm refuses a DID with
    a path). It then covers checking the result with `vtc status` and the
    [messaging] / mediator-routing / keep-#didcomm caveats.
  - The stale write-once claims are replaced with pointers to that section in
    did-templates.md, vtc-mvp.md, vtc-setup.example.toml, the wizard prompts,
    the from_toml docs and error text, the transports.rs module docs and the
    vtc-host template description. runtime-service-management.md now links the
    walkthrough.
  - `pnm did-mgmt dids get-log` help no longer says the log is a "snapshot from
    provisioning time" or that it runs without a session. It is the VTA's
    current stored log and uses the authenticated client.

  Keyring Q13: the VTC admin console's two wallet buttons can present different
  DIDs, and the ACL admits a DID. "Sign in with VTA wallet" (window.vtaWallet
  .login) presents whatever the wallet uses for this site. That is the persona
  bound to this site if there is one; otherwise the wallet asks, and one of the
  answers it offers is its own holder did:key. Wallets older than the per-site
  persona change always present the holder did:key. "Sign in via VTA-proxied
  SIOP" (walletProfile + proxyLogin) always presents a VTA-held did-self-issued
  persona, which the VTA signs for. Each button now says which identity it
  presents:

  - "Sign in with this browser's wallet". The wallet presents the identity it
    uses for this site: its own key (a did:key) unless you have chosen a VTA
    identity here.
  - "Sign in as a VTA identity". Your VTA signs as the identity bound to this
    community.

  A refused VTA-identity sign-in now names the DID it presented, with the `vtc
  admin invite --did` fix, on every attempt rather than only the first
  (SignInAsError). A refused browser-wallet sign-in points at the other button,
  because the wallet does not report which DID it presented.

- **vtc**: Correct the policy comment that said uniqueness was unenforced ([#1090](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1090))

The default `personhood.rego` carried a note ending "this daemon does not
  enforce it", written when that was true. The preceding commit made it false,
  and a comment in the file an operator reads to understand personhood is the
  worst place to leave a stale "we don't do that".

  Replaced with what is actually true, including why it is not a rego rule and
  could not be: deciding whether a pseudonym is already spoken for is a read
  against stored state, and a policy evaluated over a single presentation has
  none. A community wanting the property turns the governance flag on rather
  than editing this file.



### Fixed

- **vtc-service**: The OpenAPI snapshot pins the API, not the crate version ([#2193](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2193))

openapi.json recorded info.version = CARGO_PKG_VERSION. Now that vtc-service
  publishes ([#2192](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2192)), every Release PR bumps it, and the snapshot test failed with
  no API change (Release PR #2188: Test (VTC) and Test (VTC, vetting-pcs)). The
  checked-in document records 0.0.0-snapshot instead; the served document is
  unchanged.

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

- **vtc-admin-ui**: The rooms usage page asks from the community's oldest retained day ([#2166](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2166))

The Usage tab (and a room's Activity and Members' usage cards) sent a fixed
  30/90/365-day window ending today. `vtc/rooms/usage/0.1` item 2 requires the
  community to refuse `invalidRange` for a range starting before its oldest
  retained day, and that day is the first day any file activity was recorded
  (`meta:first-day`, written by the first upload). So from a community's first
  upload on, every window longer than its file history was refused, and the page
  rendered the refusal as "Usage could not be read. This is a failure to ask,
  not a community with none." Before the first upload there is no oldest day,
  nothing was refused, and the page worked — which is why it broke as soon as
  file uploads started working.

  The server is conformant and is unchanged. `fetchUsage` now reads the
  refusal's `details.earliest` and asks the same query once more from that day
  when it lies inside the requested range; the report carries
  `historyStartsAt`, and the page says "This community has kept usage since
  <day>, so the report starts there." Any other refusal is passed on.

  The usage reads' error branches now render the shared rooms `RefusalCard`
  (message + code) instead of a fixed sentence, so the next failure explains
  itself.

  A new integration test sends the console's exact payloads — every grouping x
  30/90/365 days x every sort, over open/attributed/private rooms, a
  community-owned room and a room that has held nothing — on a history that
  began today: each is refused `invalidRange` with `details.earliest` = today,
  and each is answered when re-asked from that day.

- **rooms**: A member who leaves the community leaves its rooms, and a Welcome to an expired KeyPackage is refused ([#2156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2156))

Two gaps in community-owned data rooms (P13).

  A departing member kept their community rooms. `vtc/rooms/community/members/add`
  item 6 says the community SHOULD remove a member from every room it owns when
  they leave; until now an administrator had to remove them room by room.

  - A departure records a removal owed for each room the member holds an
    admission or an open offer in, durably, in the `community_rooms` keyspace
    (backed up), without asking the VTA anything: at the leave and admin-remove
    ceremony (`ceremony::execute::depart`, before the member row changes), an ACL
    revocation (`routes::acl::remove_entry`), a suspension
    (`admin_actions::save`), and `vtc acl remove` offline.
  - `vtc_service::rooms::departures` is the one retry owner (R2.1). Its worker
    withdraws an open offer, records an open room's removal, and on a sealed
    room has the VTA remove the member from the group (`rooms/owner/group/remove`)
    before recording it — the removal and the dropped row one batch. A VTA that
    does not answer or refuses is retried with capped exponential backoff (30 s
    doubling to an hour); a retry after a lost answer is answered `notMember`,
    which counts as done. An administrator's own removal settles the row too.
    Each removal is audited (`memberRemoved` / `offerWithdrawn`, actor
    `vtc:member-departure`, reason naming the departure).
  - A reconciler on the same worker finds what has no event — an ACL entry that
    expired — and any departure a crash cut off, from durable state only, after
    seeing it for a minute so a write in flight (a key rotation) is not read as
    one. Rejoining re-adds nothing.
  - Owed removals are surfaced on `vtc/rooms/community/{get,list,members/list}`
    under `ext["org.openvtc"].departureRemovals` (cause, status
    pending/retrying, attempts, next attempt, last error), and on the console's
    room page.
  - The administrator's `members/remove` now shares `remove_from_group` with the
    worker; its behaviour is unchanged.

  `rooms/keys/welcome` joined from a pending KeyPackage without checking its
  expiry, though `rooms/keys/act/0.3`'s `holds_key_package` already treats an
  expired one as not held, and `rooms/keys/key-package/0.1` requires its private
  half to be discarded at expiry. `room_groups::join` now refuses an expired
  pending KeyPackage, deleting it, and the welcome handler answers the declared
  `rooms/keys/welcome:welcomeInvalid`; the invitation is not spent.

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

- **vtc**: The sync queue's Pending tile says when backing-off jobs retry ([#2153](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2153))

The Pending tile read "4 — nothing waiting" when every queued job had
  failed once and was waiting out its backoff: oldestPendingAgeSeconds counts
  only jobs due now, so a queue that was waiting looked idle. After a registry
  is added to a running community, that is exactly the state every existing
  member's publish job is in.

  Diagnostics now carry ext["org.openvtc"].backingOff: how many pending jobs
  are waiting on a retry backoff and when the soonest is next attempted.
  RTBF-held jobs are excluded; they have their own count. The console's foot
  reads "4 retrying — next in 12m".

- **vtc-admin-ui**: Pin the storage action templates so the console renders them ([#2143](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2143))

The console renders a parked action only when its summary template is pinned
  for the action's (kind, typeUri) in this build, and refuses anything else with
  "This action's summary does not match its payload — do not approve it." The
  server pins four storage templates (storage.config.create, .update, .retire
  and rooms.storage.assign) that the console's PINNED_TEMPLATE_DIGESTS never
  gained, so every parked storage action read as a mismatch and could not be
  approved from the console.

  Adds the four pins, and a server test (the_console_pins_every_template) that
  fails when any server pin is missing from the console's table: the existing
  pin test checked the server's templates against the server's own table only,
  which is how the four went unnoticed. A template digest covers its kind and
  type URI, so the digest alone names the entry.

- **vta-sdk**: A presign part carries uploadId only when one of its operations needs it ([#2134](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2134))

`external/credentials/issue/0.3` Conformance item 4 has a batch name
  `uploadId` exactly when an operation acts on an existing multipart upload
  (`upload-part`, `list-parts`, `complete-multipart`, `abort-multipart`).
  `VtaClient::external_credentials_issue_presign` split a batch refused
  `responseTooLarge` but copied the batch's `uploadId` onto every part, so
  splitting the checks-and-completion batch of consumer item 4 sent a lone
  `head` with `uploadId` and the VTA refused it `invalidBatch`
  (`vta_external::batch::check_batch`). Each part now keeps `uploadId` only
  when one of its operations needs it, as consumer item 5 says (clarified in
  dtgwg-trust-tasks-tf#783).

  The VTC's rooms presigner (`vtc-service` `rooms::vta_storage`) builds each
  part itself and had the same flaw, also reachable through the 64-operation
  chunking in `vti_common::blob_store::presigned`; `batch_request` now names
  `uploadId` only when an operation needs it, via the new
  `StorageOp::needs_upload_id`.

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

- **vtc**: A vetter resend re-signs a grant that names a retired status list URL ([#2119](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2119))

vtc/vetting/vetters/resend delivered the stored grant credential byte for
  byte. A grant issued before public_url changed still names the old status
  list URL after the list itself was re-pointed ([#2087](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2087)), so no holder can
  establish its status: openvtc refuses it as StatusUnknown, and every resend
  replayed the same refusal. Asking again could never help.

  resend now compares the credential's credentialStatus.statusListCredential
  with the URL the revocation list is served at, and when they differ re-signs
  the credential with the same id, revocation slot and validity window
  (issue_role_action_in) before delivering it. The row is replaced only if
  nothing wrote it since it was read (endorsements::replace_if_unchanged, a
  conditional batch), so a revocation landing meanwhile is never overwritten;
  the resend re-reads and either delivers the live grant or answers notGranted.
  The re-issue is audited as VecIssued under the same credential id.

- **store**: Make VTA/VTC multi-step store writes atomic ([#2109](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2109))

* test(store): expose the local journal sequence number to atomicity tests

- **store**: Commit swap and move_if_unchanged as one journal record ([#2104](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2104))
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

- **messaging**: Drop a `#response` no waiter took instead of answering it ([#1949](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1949)) ([#2095](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2095))

A reply that outlives its waiter (the messaging SDK fails pending requests
  when it reconnects at 80% of the token TTL, every 12 minutes for a 15-minute
  token) reached the VTC's DIDComm dispatcher as an ordinary request. The spine
  answered the `#response` with `unsupportedType`, the mediator refused to
  deliver that, and the pair repeated in the log every 12 minutes.

- **vtc**: Status lists follow a changed public_url ([#2087](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2087))

* fix(vtc): status lists follow a changed public_url

  ensure_initial returned an existing status-list row untouched, so the
  list URL minted on first boot stayed in force after public_url changed.
  Every credential issued afterwards named a URL the VTC no longer served,
  and the served list carried an id that was not the URL it was fetched
  from, so no holder could establish its status (openvtc refuses the VMC
  with StatusUnknown).

  An existing row whose list_credential_id differs from the configured URL
  is now re-pointed under the status-list lock, keeping its bits and
  assignments. Credentials issued under the old URL need re-issuing.

- **vtc**: A VTA-held verifier key reads its link live, never latched ([#1988](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1988)) ([#2084](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2084))
- **vtc**: A VTC with no [rooms.files] section starts with room files off ([#2075](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2075))

* fix(vtc): a VTC with no [rooms.files] section starts with room files off

  Every configuration written before room files existed has no [rooms.files]
  section, and startup still opened room storage as if it had one: it created
  the local_storage_bases directories and seeded a `local` storage config under
  <data_dir>/room-blobs. Any failure there — an unwritable directory, a relative
  root — stopped the VTC after an upgrade, for a feature its operator never
  turned on.

  [rooms.files] is now optional. Without it nothing is created or seeded, the
  storage registry opens over whatever configs are already stored, uploads are
  refused (filesDisabled) and stored files are still served. Writing the section
  turns files on: `enabled` defaults to true inside it, and `enabled = false`
  keeps the settings while refusing uploads. A config saved by setup since room
  files landed carries an explicit `enabled = false` and stays off.

  The console learns the state from vtc/rooms/list
  (ext["org.openvtc"].roomFiles.enabled) and, when files are off, the Data rooms
  page shows the section to add:

    [rooms.files]
    local_storage_bases = ["/var/lib/vtc/room-storage"]
    blob_dir = "/var/lib/vtc/room-blobs"

- **vtc**: A relative data_dir no longer stops the VTC at first start ([#2074](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2074))

On first start the VTC seeds a `local` storage config whose root is
  `[rooms.files] blob_dir`, defaulting to `<data_dir>/room-blobs`. With a relative
  `[store] data_dir` that root was relative, the spec's StorageConfig requires an
  absolute one (`root` pattern `^/`), and the seed's own conformance check refused
  it:

    server error: internal error: storage config does not conform: data did not
    match any variant of untagged enum StorageSettings

  A relative blob_dir, or a root or default local_storage_bases derived from a
  relative data_dir, is now created beneath the working directory the store is
  opened from and resolved to an absolute path. Absolute paths are unchanged, and
  explicit local_storage_bases must still be absolute, as documented.

- **vtc**: The storage probe stages its canary without tempfile, a test-only dependency ([#2055](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2055))

The probe added in #2052 staged its canary with `tempfile::tempdir()`, but
  `tempfile` is an optional dependency of vtc-service enabled only by the
  `test-support` feature. Every test and clippy build turns it on, so only the
  MSRV job's plain `cargo check --workspace --locked` compiled the crate
  without it, and main has failed that job since the merge.

  The canary is now staged under the data directory, beside upload staging
  (`room-blob-staging`), under a fresh name, and removed once the probe ends.
  That directory is the service's own, rather than the system temp directory.

- **vtc**: A hidden-vetting criterion never counts named vetting statements ([#2051](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2051))

A criterion that publishes hidden-vetting parameters fell through to the
  named-statement count whenever a submission carried no PCS proof (or the
  build lacked `vetting-pcs`, which compiles the hidden path out entirely).
  Enough named statements from eligible vetters then satisfied it, admitting
  an applicant under a hidden criterion with no proof at all.

  That breaks the design rule that a criterion is named or hidden, never both
  (vetting-hidden-vetters-pcs.md §12.1): a vetter who gave one applicant both a
  named statement and a hidden attestation counts twice, and the community
  cannot tell the two are one person.

  `vetting_facts` now returns unsatisfied facts for a hidden criterion with no
  counted proof. Named statements are recorded, unverified and not counted,
  under `named-statement-on-hidden-criterion`; the applicant is told
  `vetting:hidden:no-proof` (`vetting:hidden:unsupported` without the
  feature). Named criteria are unchanged.

- **tsp**: A relationship accept beaten by a concurrent one was answered, not lost ([#2041](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2041))

Two invites from one peer that arrive together are both recorded first, each
  leaving the pair InviteReceived. The first accept moves it to Bidirectional
  and the second is refused (invalid transition: SendAccept in state
  Bidirectional), which both the VTA and the VTC logged as "could not send a
  TSP relationship accept ... the peer sees no answer". The peer did get an
  answer: an accept for the same pair went out a moment earlier, and receiving
  any accept completes its side.

  Seen at gt-vta on 2026-10-11 against the browser wallet, whose mediator
  socket was being replaced in a loop (fixed in vta-browser-plugin #319), so
  its invites arrived in pairs.

  accept_refusal_is_benign (vti_common::relationship_store) decides it the way
  the SDK's invite_refusal_is_benign does: re-read the relationship state after
  the refusal rather than match the error text (R3.7). Bidirectional means the
  invite was answered and is logged at debug; anything else is a real failure
  and keeps the warning. Both services use the one helper.

- **auth**: Bound wallet sign-in sessions by the grant's notAfter across refresh ([#2026](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2026))

A wallet sign-in (`auth/oob/*`) grant carries `notAfter`, the latest
  moment the member approved the session for, and redeem reports it. The
  member-portal mint clamped only the first window to it — the comment
  "refreshing cannot extend it" was false: `handle_refresh` reset both
  expiries to now + the full TTL on every rotation, so a session approved
  for an hour could be renewed indefinitely. The console session minted by
  wallet sign-in (`mint_admin_cookie_session`, #2014) ignored `notAfter`
  entirely, and reported the refresh deadline as `notAfter`.

- **vtc**: Sign wallet sign-in respond and cancel replies, and call mixed-family networks unknown ([#2024](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2024))

The browser plugin checks every reply to the approver is the community's
  assertionMethod attestation, but only steps 1 and 2 were signed, so an
  approved sign-in completed on the VTC while the wallet showed
  auth/oob/reply-invalid. Sign the respond and cancel replies too.

  sameNetwork compared an IPv4 address with an IPv6 prefix as unequal, so one
  dual-stack machine read as a different network; mixed families are now
  "unknown".

- **vtc**: The member portal names a wallet sign-in as one ([#2009](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2009))

The membership card read "Signed in with: Your VTA (SIOPv2)" for every
  session that was not a passkey, including a wallet sign-in by trigger link.
  That session carries amr [did, oob, uv]; name it "Your wallet" and keep the
  SIOPv2 label for the legacy path.

- **vtc**: Repo page is one column of full-width sections, and the members list searches and sorts ([#1983](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1983))

The repository page squeezed its registry and people tables into a two-up
  grid, where the registry table spilled out of its card and the granter column
  clipped names. It is now one column: a summary strip (owners, maintainers,
  committers, commit trust, registry, drift, each linking to its section), drift
  first when there is any, the people tables, commit trust beside recent
  activity, then the registry table. Short columns have fixed widths, names and
  DIDs wrap rather than clip, and the registry table scrolls inside its card.

  The members list reads every page of vtc/members/list/0.1 (200 a page, up to
  25 pages) and searches, filters and sorts in the browser. Search is lazy:
  every term must match some field — a case-insensitive substring of name, DID,
  role, forge login or git right, or letters in order on the short human fields
  (never the full DID, which nearly any short term is a subsequence of). Results
  rank by match until a column is chosen; every column sorts ascending and
  descending, empties last. The role text box becomes a picker of the roles
  present.

- **vtc**: The request log names the Trust Task, and a TSP request is logged at all ([#1982](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1982))

A member's DIDComm requests all logged as message_type=…/binding/didcomm/0.1/envelope,
  so a community-profile ask and a git-ns view from the same member looked the same,
  and an operator could not tell which one reached the VTC. A TSP request logged
  nothing at all.

  - didcomm_server::request now also records the enveloped task's type, the
    request id, and the reply's type (a #response or a trust-task-error).
  - handle_tsp logs tsp_server::request with the task, the proven sender and the
    status.

  Found while diagnosing OpenVTC's Repos view timing out for a member who joined
  over TSP. The client sent git-ns over DIDComm and the reply was lost; that fix
  is in OpenVTC (openvtc#474).

- **vtc**: A grant holder's DID stays inside its column on the repos page ([#1981](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1981))

A namespace-rights holder with no known name renders as a bare `.truncate`
  DID, whose own cap (22rem) is wider than the holder column in the repos
  overview's three-up row. A long did:webvh ran under the Grant button and
  past the card's edge. Inside `.gitns-holder` the cap is now the column, so
  it ellipsises like a named holder's DID does, with the full DID on hover.

- **messaging**: A receive leg that stops delivering is reconnected, and the SDK alone deletes frames we cannot unpack ([#1979](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1979))

Adopt affinidi-messaging-sdk 0.33.2 and affinidi-messaging-delivery 0.1.20
  (affinidi-tdk-rs #927).

- **messaging**: A node that stops collecting its inbox is noticed, and its peers stop paying for it ([#1978](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1978))

* fix(messaging)!: a node that stops collecting its inbox is noticed, and its peers stop paying for it

  A message waits in its recipient's mediator inbox until the recipient deletes
  it, and while it waits it counts against its sender's per-peer quota
  (`limits.queue.peer`, 50). On 2026-10-05 two OpenVTC admin sessions stopped
  collecting: 49 VTA replies queued for each, and every further reply was refused
  `503 e.p.limits.queue.peer` while the VTA logged a bare "failed to send TSP
  reply" every 30 s. Sends worked; nothing came back. This makes that state
  visible from both ends and stops the stack making it worse. It needs nothing
  from an unreleased affinidi-tdk-rs.

- **vetting**: A new drip rate or live period no longer voids hidden-vetting attestations ([#1977](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1977))

requirementsDigest covered the whole hidden-vetting ext, so republishing how a
  community runs hidden vetting (dripPerTick, tickLength, vetter/token labels,
  events) moved the digest. A hidden vetter's attestation is bound to the digest,
  so every attestation in flight silently stopped counting: the proof verified
  and the join was decided request_more with nothing said. This held a live PCS
  join after the operator lowered the drip rate.

  requirements_digest now leaves those operational members out; the suite and
  keys stay covered, so an applicant still never binds to keys it was not shown.
  Label liveness is checked on its own when a proof is read.

- **vtc**: Say why a hidden-vetting proof did not count (R6.4) ([#1976](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1976))

A PCS ZKP proof that verified but whose attestations were not counted was
  decided requestMore with only vetting:statements:N, and nothing at INFO said
  why. The usual cause is an operator changing the published hidden-vetting
  parameters (dripPerTick, tickLength, live labels, events): the criterion digest
  covers them, so every attestation made before the change binds the old digest
  (requirements-digest-mismatch), or spends a token under a label no longer live.

  - Log at INFO, per hidden submission: attestations, counted, distinct vetters,
    needs and the failure codes (never a tag). Log the stale token labels and the
    digests the attestations were made under, which are public parameters.
  - Report a token under a label no longer accepted as token-label-not-live rather
    than the verifier's no-token, which reads like a forged token.
  - Send the applicant the reasons as needs vetting:hidden:<code>, dropping the
    counting rule's issuer-not-vetter echo when a specific code is present.
  - A hidden-vetting criterion decided on the named path (no proof carried, or a
    build without vetting-pcs) logs it and adds vetting:hidden:no-proof /
    vetting:hidden:unsupported.

  The new needs are outside vta-sdk's Need grammar, so existing clients show them
  verbatim.

- **admin-ui**: The namespace-rights card keeps its holders and Grant buttons inside it ([#1974](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1974))

In the three-up row the card is narrow, and its grid's middle track was a bare 1fr, whose minimum is its content's width. A holder's name plus shortened DID (which does not wrap) widened the track past the card's edge, clipping the DID and pushing both Grant buttons out of view. The track is now minmax(0, 1fr); a holder may shrink, its name and DID stack when the line is short, and the DID ellipsises (the title attribute keeps the full DID on hover).

- **vtc**: Handle inbound messages concurrently, so a bind's bridge reply is read ([#1973](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1973))

The VTC's messaging loop awaited each inbound frame's handler before
  reading the next. An operation that arrives by messaging and then waits
  on a messaging reply therefore waited on itself: `cnm git namespace
  bind` over TSP sends the bridge a beginBind job and waits up to 30 s for
  the answer, which arrives on the same stream and is not read until the
  handler gives up. Observed live: the bridge answered in ~20 ms, the
  mediator relayed it in 0-1 ms, and the VTC read it 30.1 s after the
  request — "TSP reply had no waiter" — while cnm reported "the bridge did
  not answer". Any inline bridge job reached over DIDComm or TSP is hit the
  same way.

  The loop now spawns each frame's handler, bounded at 32 in flight, as
  the VTA's inbound loop has since the same defect was fixed there. Per-
  sender ordering is kept where TSP needs it (a relationship-control frame
  is a barrier for its sender's later traffic, Keyring VTI-43): SenderOrder
  moves from vta-service to vti-common so both nodes share it, and
  vta-service re-exports it at its old path.

  The reader is factored into run_inbound_loop so it can be tested: a
  handler that waits on a later frame completes (it hangs, and the test
  fails at its 5 s bound, with the loop made serial again), and an invite
  is still handled before its sender's following task.

- **vtc**: A vetter who lost the enrolment answer is re-issued it, to the same identifier only ([#1972](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1972))

A vetter whose client lost the `vtc/vetting/vetters/pcs-root` answer
  before unblinding it was refused `alreadyEnrolled` on every re-ask: the
  community keeps only that a member enrolled, never the answer, so the
  vetter had no credential, tokens or tickets until the next label.

- **vtc**: An administrator may withdraw a member's registry consent, never grant it ([#1962](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1962))

A member's consent to be published in the community's trust registry is
  their own privacy decision, given with `registryConsent` on
  `vtc/join-requests/submit` and copied onto the member record as
  `publish_consent`. `vtc/members/update` let an administrator set it either
  way, so an administrator could publish someone who had said no.

  `vtc/members/update` now only lowers it. `publishConsent: true` for a
  member whose consent is `false` is refused with
  `vtc/members/update:consentGrantForbidden` before anything is written, so
  no other field in the request is applied either. `true -> false` (a
  takedown) and re-stating the current value still succeed. The only way
  consent becomes `true` is the member's own `registryConsent` on a join
  submit, including a rejoin, which writes a fresh member record.

  The specification declares no code for this, so it is minted under the
  task's namespace (Trust Tasks SPEC §8.5) as
  `vta_sdk::protocols::members::MEMBER_UPDATE_ERR_CONSENT_GRANT_FORBIDDEN`
  and listed as consumer-minted in the VTC's error-code census, which fails
  the day the specification declares it.

  A withdrawal already reaches the registry: the `MemberUpdated` naming
  `publishConsent` enqueues an `UpdateMember` job, and the syncer deletes the
  member's record (a delete, not `Departed`). An integration test now drives
  that end to end through the route.

  docs/03-vtc/trust-registry.md no longer tells operators to record consent
  for pre-#1682 members with `publishConsent: true`; that is refused now, and
  such a member gives consent by rejoining.

- **vtc**: A hidden-vetting refusal says "validation error" once ([#1961](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1961))

The pcs-root, pcs-tokens and event-mode refusals map onto their declared
  codes by matching the error's rendered text, then wrapped that text in a
  new `AppError::Validation`, so the message a vetter reads began
  "validation error: validation error: ... already holds a credential
  under `vetter/2026-10`". The declared refusal now carries the store's
  reason under the one prefix. Codes and HTTP statuses are unchanged.

- **vtc**: The drip is a window of time, a signing-key change never re-keys hidden vetting, and it runs on one criterion ([#1960](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1960))

Three gaps in hidden vetting (PCS), closed with the rules trust-tasks-tf #734
  specified (trust-tasks-rs 0.27.7):

  - **The drip had no rate.** A tick was a counter the vetter chose, and the
    only rule was one draw per tick — so a vetter could draw ticks 0, 1, 2, …
    back to back. A tick is now the window
    `[label start + t·tickLength, label start + (t+1)·tickLength)`, the label
    start being the first of the month for `token/<YYYY-MM>` and the event's
    first day for an event label. A tick that has not begun is refused
    (`pcs-tokens:tickNotYet`); a begun tick not yet served can still be drawn
    once, so a device that was off catches up and never gets ahead. `tickLength`
    is a new publish member (ISO 8601 days/hours, default `P3D`), stored and
    published; a configuration stored before it reads as `P3D`.
  - **A signing-key change silently re-keyed it.** The helper and token keys
    are derived from the credential signer. Publishing after the signer
    changed replaced them without a word, and every enrolled vetter's
    credential stopped verifying. Publish now refuses when the stored keys are
    not what the signer derives (`hidden/publish:signerChanged`); withdrawing
    and publishing again under a new period is the deliberate way to re-key.
  - **A second criterion was accepted.** Enrolment, the drip and the challenge
    are served from one configuration (the first criterion that has one), so a
    second criterion accepted proofs nobody could mint for. Publish now refuses
    while another criterion has hidden vetting (`hidden/publish:otherCriterion`).

- **vtc**: A departing member who was never published leaves no failed registry job ([#1959](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1959))

A member purged on leaving queued a `DeleteMember` registry job whether or
  not they had ever been published, and the syncer sent the delete with no
  check. For a member who never consented to publication the registry holds no
  record, refused the delete (`taskFailed`, its answer for an unknown key), and
  the VTC classified that as permanent: the job failed on its first attempt and
  sat in the console's Failed jobs until an operator discarded it.

  - `DeleteMember` consults the mirror (`registry_records`, what this
    community believes it published) as `MarkDeparted` already does. With a
    record, it deletes. Without one, the new `SyncAction::DeleteIfPresent`
    asks the registry first and deletes only if it holds the record. A
    purge is an erasure, so a mirror that lost a record must not leave the
    membership published; a read that fails transiently is retried, and a
    registry that cannot answer the read gets the delete anyway.
  - The member delete treats the declared `registry/record/delete:notFound`
    as done, the tolerance `delete_trust_record` already had: already absent
    is the effect a delete wants.
  - The console's Failed jobs copy pointed at `vtc sync-jobs retry` on a
    stopped daemon; it now names the Retry and Discard buttons beside it, and
    says when discarding is right.

  The registry answering an unknown key with the generic `taskFailed` rather
  than its declared `notFound` is a registry-side defect, fixed separately.

- **vtc**: Say why a PCS challenge was refused ([#1954](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1954))

A hidden-vetting proof is bound to a single-use challenge the community
  issues over vtc/vetting/pcs-challenge/0.1, and the community spends it
  when the proof arrives. Every way that spend could fail - the challenge
  expired, was already used, was never issued, or is not the one the proof
  was built over - reached the applicant as one `malformedRequest` with the
  cause in a sentence. A client could not tell "you took too long" from
  "your proof was built over the wrong challenge", which is the difference
  between "try again" and "your client has a bug".

  Each failure is now a typed `ChallengeRefusal` that travels from
  `pcs_challenge::consume` through `pcs::decide`, the vetting facts and the
  criterion evaluation to the join spine, and goes out on the Trust Task
  path under a code of its own:

  - `vtc/join-requests/submit:challengeNotIssued` (details.reason `not_found`)
  - `vtc/join-requests/submit:challengeAlreadyUsed` (details.reason `gone`)
  - `vtc/join-requests/submit:challengeExpired` (details.reason `gone`,
    plus `details.expiredAt`)
  - `vtc/join-requests/submit:challengeMismatch` (details.reason `conflict`)

  and the same four local parts under `vtc/join-requests/supplement:` when
  a supplement carries the proof. Neither specification declares a
  challenge code yet, so they are consumer-minted under the task's own slug
  (SPEC 8.5), as `requestAlreadyOpen` is; the constants live in
  `vta_sdk::protocols::join_requests` for clients to match on, and the
  error-code census lists them as consumer-minted so it fails the day the
  specification adopts them. Surfaces that carry no code keep the same 400
  `Validation`, now with a sentence that says which failure it was. The
  message never contains the challenge value.

  Single-use is unchanged: a submission still spends the challenge whether
  or not it is accepted, including on a mismatch. The row is now taken
  atomically (`take_raw`) rather than read then removed, and a spent marker
  holding no challenge - only the expiry - is left in its place so a second
  attempt is told "already used" rather than "never issued". An expired
  challenge is put back as it was so repeated attempts keep saying
  "expired". Both go at the retention sweep after `expires_at`, as the
  challenge always did; both writes are `insert_if_absent`, so a challenge
  asked for in the meantime is never overwritten. Each refusal is logged
  with its kind and the applicant, never the challenge.

- **vtc**: Working in the admin console counts toward the idle timeout ([#1953](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1953))

The console signed out operators who were using it. The idle timeout
  (`auth.admin_idle_timeout`, 900s) is measured from `Session::last_seen`, and
  only a cookie-authenticated request through the `AuthClaims` extractor
  advanced it. Most of what the console sends is now a signed Trust Task
  document to `/v1/trust-tasks`, which authenticates by its proof and reads no
  session, so a busy operator stopped producing activity. Fifteen minutes after
  the last cookie-borne call the renewal was refused and the session-deadline
  watcher showed Login.

  Counting every signed document would be wrong the other way: the action
  badge, counts and banners post signed reads on timers, and an unattended tab
  would never time out. Only the console can tell input from a poll, so:

  - The console notes real input (pointerdown, keydown, wheel, touchstart) and
    sends `X-VTC-User-Activity` on a document posted within 60s of some
    (`admin-ui/src/lib/user-activity.ts`). Timers in an idle tab send none.
  - The route records activity only for a document that ran successfully, was
    verified as a known signer, and whose principal (the signer, or the
    administrator its console key acts for) owns the session the cookie names
    (`vti_common::auth::touch_cookie_session_for`, which authenticates the
    cookie exactly as the extractors do). A document signed by one identity
    cannot keep another's session alive, and a refused one counts for nothing.

  Renewals and timer-driven reads still never count, so the daemon still
  decides when an operator who walked away is signed out.

- **vtc**: A console key grants the vetter role as its administrator (VTI-ACL-030) ([#1943](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1943))

`vtc/vetting/vetters/grant/0.1` took its actor from the bare proof signer,
  so a grant made from the admin console — which signs with its own did:key,
  acting for the administrator who delegated it — was refused as "<console
  key> does not hold vtc.vetting.manage", even for a community-admin.

  The handler now resolves its actor through `capable_signer`, as every other
  administrative task does: the signer's own entry, or the delegating
  administrator's for a console key, held to vtc.vetting.manage at execution
  time. The other handlers that resolve the bare signer act for members, where
  the signer is the actor.

- **vtc-console**: Admission criteria load within the listing's page limit ([#1921](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1921))

The Requirements tab failed with "could not load the admission criteria:
  malformed request: payload failed schema validation: 100 is greater than the
  maximum of 50". The console's shared paged-listing helper asked every signed
  listing for 100 items, but vtc/schemas/accepts/list (0.1 and 0.2) caps limit
  at 50, so the VTC refused the request as malformed. Each listing now passes
  the page size its specification declares (50 for the admission criteria; the
  vetter-grant and revocation listings keep 100), and a test pins the bound and
  that paging follows nextCursor.

- **vtc**: Removing an administrator, lowering the consent threshold and changing authority policy take a second party (VTI-APV-019, VTI-APV-020, VTI-VTC-022) ([#1917](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1917))

* fix(vtc)!: removing an administrator, lowering the consent threshold and changing authority policy take a second party (VTI-APV-019, VTI-APV-020, VTI-VTC-022)

  One unrestricted administrator could undo VTI-APV-014 alone: remove every
  other administrator one at a time, lower the consent threshold back to 1, and
  rewrite the policy that decides authority (vtc-action-list.md §8.1, holes 1-3).
  These are the stop-gaps of §7b, built on the consent machinery that already
  exists. Each is replaced by its action-list rule once that lands.

  1. Removals and demotions of an administrator take the requester's
     operation-bound step-up (VTI-APV-019). acl/revoke (removal and scope
     reduction), a downward acl/change-role, an acl/update or acl/grant rewrite
     that takes authority from a live admin (narrowed scopes, an expiry brought
     forward), and vtc/members/admin-remove of an admin all go through
     bound_step_up::redeem_or_request. When the subject is another live
     unrestricted admin they also take consent through admin_consent, from the
     unrestricted admins other than BOTH the requester and the subject (approver
     set `unrestricted-admins-except-subject`; the subject's decision is refused
     as notAnApprover). Where that set is empty (two unrestricted admins), the
     step-up suffices, and once the write lands it is audited as the new
     `AuthorityReducedUnopposed` event at AuditSeverity::Critical; a removal also
     sends the subject the signed removal notice. The attrition guards
     (check_attrition, lock_admin_set, last-admin) are unchanged and still run;
     attrition is also asked before the gesture so a stranded removal never asks
     for one. Removing an expired or non-admin entry is unchanged.
     vtc/members/update can no longer demote an admin (it has no operation to
     bind a gesture to) and names acl/change-role instead.

  2. Lowering acl.unrestricted_admin_consent_threshold, by config/patch or an
     applied vtc/config/import, takes the requester's step-up and consent at the
     threshold as it stands (VTI-APV-020), pinned to that value. Raising it, or
     leaving it unchanged, stays immediate; the meetable check is unchanged.

  3. policy/upsert/0.2 and policy/activate/0.1 require an unrestricted admin
     (require_super_admin), not any admin. For the purposes that decide authority
     (roleChange, removal, join, crossCommunityRoles, gitNamespace —
     PolicyPurpose::decides_authority) they also take the step-up and consent of
     another unrestricted admin (VTI-VTC-022). The upload and activation checks
     run before the gate, so a module that would be refused asks nobody.

  4. vtc/members/admin-remove applies acl/revoke's scope-cover check
     (caller_covers_target, VTI-ACL-050): an entry the actor cannot see answers
     as not found, one it does not fully cover is refused.

  admin_consent is generalised over an `Act` (GrantUnrestricted,
  ReduceUnrestricted, LowerThreshold, ChangeAuthorityPolicy) that decides the
  approvers, the refusal wording, what the approvers are shown and the state the
  consent is pinned to. require and gesture_then_consent keep their signatures
  and are Act::GrantUnrestricted, so APV-014 is unchanged. TaskError gains a
  StepUp variant so a gate deep in an operation refuses with the ceremony inline.

- **vtc-console**: Error text wraps inside its box ([#1916](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1916))

Error toasts ran off the right edge when the message carried a long DID: an
  unbroken token gives the browser no break opportunity, and the message, a flex
  item, could not shrink below that token's width. The message may now shrink
  (min-width: 0) and break anywhere (overflow-wrap: anywhere). Error cards,
  findings, field errors and both banners get the same wrapping.

- **vtc-service**: Console key rows stored before expiry existed still read ([#1911](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1911))

A delegation written before #1836 has no expiresAt (it lasted until revoked),
  so reading it failed with 'missing field expiresAt' and console sign-in
  answered 500 even after #1908 defaulted scope. A row with no expiry now reads
  as expiring MAX_LIFETIME_DAYS after creation, the most a fresh enrolment gets,
  so a legacy key never outlives the ceiling and an older one is expired and
  re-enrols.

- **vtc-service**: Box the join-decision dispatch arms ([#1909](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1909))

The Trust Task dispatcher awaits every handler inside one match, so its
  future is the size of its largest arm and every document is dispatched on
  that stack. VTI-13 ([#1907](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1907)) made the join submit/supplement/present arms
  carry the whole criterion decision inline; with vetting-pcs a git-ns/*
  document then overflowed a 2 MiB test thread on Linux
  (git_ns::tests::an_adoption_never_grants_the_resolver_an_elevated_right),
  failing Test (VTC) on main. Boxing the three arms moves their state to the
  heap.

- **vtc-service**: Console key rows stored before scope existed still read ([#1908](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1908))

A ConsoleKeyDelegation written before #1836 has no `scope`, so every read of
  it failed with 'missing field scope' and the console sign-in answered 500
  ('Could not check this browser's signing key'). Every delegation has been a
  console key and `console` is the only scope, so a missing scope reads as
  console; nothing is widened.

- **vtc-service**: An idle console's session ends cleanly ([#1905](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1905))

* fix(vtc-service): signing out of an expired console session succeeds

  A console left open past its access token showed "Sign-out failed:
  unauthorized: missing or invalid Authorization header (401)" when the
  operator clicked Sign out. The session cookie's Max-Age is the access
  token's lifetime (300s at aal2), so the browser had already dropped it;
  the pre-flight renewal was refused for idleness, and `sign_out` required
  `AuthClaims`, so it answered 401. That reported a failure for the outcome
  the operator asked for, and left the refresh cookie in the jar, because
  the clearing headers ride only on the success response.

- **vtc-service**: The console sets up signing before it shows the dashboard ([#1899](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1899))

Every administrator verb the console sends is a signed Trust Task ([#1808](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1808)),
  but an administrator whose browser held no accepted key was shown the full
  console anyway. Each screen then signed with a key the VTC did not know, the
  admission layer charged those documents to the per-address anonymous budget
  (burst 10, one per 5 s), and a few clicks exhausted it — so the enrolment that
  would have fixed it came back 429.

  - After sign-in, an administrator's browser is checked once
    (auth/signing-key/list/0.1). Without an accepted key the operator sees a
    "Set up signing" page instead of the console; nothing signs until then. A
    check that fails for any other reason offers a retry, never re-enrolment.
    A signed document refused outright triggers a re-check.
  - Enrolment always uses a freshly minted key. The VTC never enrols a key
    twice (an expired delegation still answers alreadyEnrolled), so reusing the
    held key made a browser whose 30-day delegation lapsed unrecoverable. The
    new key is stored only after the VTC accepts it, then the key it replaces is
    revoked. Renewal banner five days before expiry.
  - Key storage no longer degrades silently to memory: a refused write is an
    error, the write is read back, persistent storage is requested, and a read
    failure is no longer mistaken for "no key" (which used to overwrite it).
  - A 429 from the signed door is waited out once when the VTC asks for 10 s or
    less, and otherwise says how long to wait.
  - Copy that called signing optional is gone; operator docs describe the gate,
    per-origin keys, lifetime and durability.

- A TSP reply reaches a sender on another mediator ([#1894](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1894))

Both the VTC (`handle_tsp`) and the VTA (`handle_tsp` → `send_to`) answered
  an inbound TSP Trust Task by routing `[own_mediator, sender]`. That ends at a
  mediator that does not host a sender on another one, which refuses it. The
  request arrived and the answer never did. In the field: an OpenVTC persona
  on ic3-mediator joined a VTC on cpunks-mediator, the admin approved it, and
  the persona stayed Pending. Its submit receipt and every
  `join-requests/status` poll reply were refused at the VTC's mediator. #405
  fixed the same failure in the other direction.

- **vta-sdk**: Read a DTG credential's shape without its proof, so a proof set parses (VTI-57) ([#1889](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1889))

dtg-credentials 0.12 models `proof` as one DataIntegrityProof. A community
  holding two signing keys signs each credential once per key and writes a
  proof set, so every DTGCredential parse of such a credential failed. #1868
  taught the proof *verifiers* to read a set (VTI-44), but these shape parses
  were left:

  - vetting::eligibility::community_roles returned None in silence, so
    openvtc filed a two-key community's vetter grant as a plain role and never
    seated the vetter (the Keyring report's VTI-57, blocking TUI-as-vetter).
  - verify_eligibility_vp refused the same grant as malformed when a vetter
    presented it.
  - vetting::statement::verify_statement refused the community's own
    vetted/1 statements.
  - vtc-service's statement intake (credentials/ingress.rs) and its predicate
    check (vetting/mod.rs).

- **vtc**: Emit the declared codes for invitation issue/revoke and hidden-vetting publish ([#1600](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1600)) ([#1887](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1887))

`vtc/invitations/issue`, `vtc/invitations/revoke` and
  `vtc/vetting/hidden/publish` answered every refusal through the generic
  `app_error_to_reject`, so the codes their specifications declare reached
  callers as a bare `taskFailed`.

  - `invitations/issue:unknownRole` for a role that does not parse. `admin`
    parses and stays the framework's refusal (the privilege ceiling); a test
    pins that it is not reported as `unknownRole`. A community keeps no
    register of its `custom:<name>` roles, so any well-formed custom name is
    one it can seat.
  - `invitations/revoke:notFound` for an absent invitation, including one
    outside the caller's inviter scope.
  - `vetting/hidden/publish:noSuchCriterion` and `:noVetting`, now driven by
    a signed-document test.

  Each gains a census witness. The unwitnessed baseline falls from 10 to 8
  (12 to 8 with `vetting-pcs`), and the ceiling ratchets down to match.

- Build clean on rustc 1.99 (CI) without raising the 1.95 MSRV ([#1877](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1877))

CI picked up rustc 1.99.0 (2026-09-28) and builds with -D warnings, so two
  new lints failed Clippy and Test (VTC) on every PR:

  - Atomic*::fetch_update is deprecated in favour of try_update, which is
    newer than the workspace rust-version (1.95.0). The two call sites
    (vta-service test_support, vtc-service member_count_dec) keep
    fetch_update under a statement-level #[allow(deprecated)].
  - clippy needless_borrows_for_generic_args in vtc-service messaging:
    .map(&absolutize) -> .map(absolutize).

  cargo +1.99.0 clippy --workspace --all-targets -D warnings is clean.

- A TSP relationship can be started with a peer on another mediator (VTI-56) ([#1873](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1873))

A node that starts a TSP relationship with a peer on another mediator had
  its invite refused by its own mediator (403 e.p.direct_delivery.denied,
  "must be relayed through a routing envelope"), every attempt. The SDK
  routes a control message across mediators only when it already knows the
  peer's mediator, learned from a routed invite from the peer or set with
  set_peer_mediator. An initiator has neither, and nothing here set it. That
  is why the Farm VTC's TSP push to a member on the other mediator never left
  its own mediator and fell back to DIDComm an hour later. The existing
  cross-mediator tests pre-form the relationship (relate_directly), so they
  never sent an invite.

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

- **vtc-service**: An abandoned backup import releases boot after its TTL ([#1870](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1870))

* fix(vtc-service): an abandoned backup import releases boot after its TTL

  The import-in-progress sentinel was a bare marker with no expiry: stamped
  before the destructive clear-and-replay, cleared only on success. A crash,
  disconnect, or failed finalize between those two points left it behind, and
  boot refuses to start while it's present — permanently, since the daemon
  that would let an operator retry the import is the same daemon the sentinel
  refuses to boot.

  Stamp the sentinel with a timestamp instead of a bare "1", and treat it as
  stale past a 10-minute TTL (generous headroom over the in-process replay's
  real runtime). A stale marker self-heals at the next boot attempt instead of
  needing manual sentinel surgery, while a fresh marker still blocks boot as
  before.

- **admin-ui**: Take brace-expansion 2.1.7 (GHSA-q2hr-2g5m-vwhr) ([#1855](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1855))

A dev-only transitive dependency of the console's build tooling. 2.0.0
  to 2.1.6 expand {a},b}-shaped input in quadratic time (CPU denial of
  service); 2.1.7 fixes it. Lockfile only.

- **vtc-service**: Sign operational Trust Tasks with one proof, not one per held key ([#1851](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1851))

A VTC holding a second (post-quantum) key emitted a proof array on every
  operational document. A Trust Task's proof is a single object, so the
  registry client's reparse failed locally with 'invalid type: sequence,
  expected struct Proof' — the boot health probe, membership sync and the
  hook relay all failed as a 'transient' error that never cleared.

  sign_operational now signs with the primary key only; credentials keep
  signing with every key (proof set).

- **vtc-service**: Admin UI omits blank optional fields on ACL grant ([#1849](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1849))

The New ACL entry form sent `label: null` and `expiresAt: null` when those
  fields were left blank. The acl/grant payload schema types both as strings,
  so the VTC answered 400 "null is not of type string". Blank optional fields
  are now absent from the request. Inline label edit had the same fault for an
  entry with no expiry and is fixed the same way.

- **vtc-service**: A raised document limit only for a known issuer, within a large-document budget ([#1844](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1844))

The per-type raised maxDocumentBytes was granted from the unverified
  in-band issuer alone. Grant it only when that issuer holds an ACL entry,
  charged against a per-address budget (client IP over HTTPS, sender VID
  on the messaging transports) under a service-wide cap that bounds
  freshly minted VIDs. A claim that fails verification, or verifies to a
  different issuer, doubles that address's next cost.

- **vtc-service**: Setup wizard's plaintext choice pins the plaintext backend ([#1837](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1837))

The interactive wizard's "Plaintext file" choice populated no field, leaving
  `SecretsConfig::backend` unset. `create_secret_store` then walked its implicit
  chain and picked the OS keyring whenever it is compiled in, so setup failed on
  a host without a credential store despite the operator choosing plaintext.
  Set the selector explicitly.

- **vtc-service**: Community verbs honour an inviter's scope ([#1833](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1833))

* fix(vtc-service): community verbs honour an inviter's scope

  Signing opened the invitation verbs to a Moderator or Issuer, which the
  bearer routes (admin sessions only) never admitted. Below Admin, an
  inviter now lists, revokes and delivers only the invitations it issued
  (another's answers as absent), and cannot confer a role by invitation.

  The graph refusal test is back to an Issuer, as the route's was.

- **vtc-service**: Charge signed Trust Tasks to the signer, not the anonymous governor ([#1832](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1832))

* fix(vtc-service): charge signed Trust Tasks to the signer, not the anonymous governor

  `POST /v1/trust-tasks` sat behind the per-address unauthenticated governor
  (a burst of 10, then one per 5 s). With the console's reads now signed Trust
  Tasks, an administrator hit it while navigating.

  The door now charges each document to a budget chosen by who signed it
  (`routing::trust_task_admission`):

  - unsigned documents, and ones claiming a DID with no live ACL entry, pay
    the strict per-address bucket before verification. It is the tower
    governor's own limiter state, so an address gets no second anonymous
    budget;
  - documents claiming a known DID (a live ACL row, or a console key whose
    delegating admin has one) first pay a per-address ceiling (120, then one
    per 250 ms) that bounds verification work;
  - once verified, they pay the signer's bucket (60, then one per 500 ms),
    keyed by the principal, so console keys share their admin's bucket;
  - a known-DID claim that fails verification pays the strict bucket too.

  Fresh DIDs never get a bucket. The spine asks the transport once the proof
  has verified and before the duplicate-execution record is claimed
  (`dispatch_trust_task_core_admitted`), so a refused document keeps its id.

  Also points `minted_admin_token_is_accepted` and the CORS preflight tests,
  which still targeted the removed `GET /v1/admin/config`, at
  `/v1/audit/verify` and `/v1/trust-tasks`.

- **vtc-service**: Printed pnm acl create grant carries --handoff ([#1831](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1831))

The VTC setup wizard's "context already exists" fallback, the emergency-bootstrap hint and the getting-started / example-TOML docs printed `pnm acl create … --expires 1h` without `--handoff`. Both flows roll the setup DID over to a VTA-minted long-term admin, which the VTA refuses for an entry with no one-time hand-off (VTI-ACL-053, VTI-ACL-054), so an operator following the printed command hit a forbidden at provision time. The printed command now matches vta_sdk::provision_client::authz::grant_hint.

- **vtc-service**: Config writes and admin invites need an unrestricted admin ([#1829](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1829))
- **vtc-service**: Session revocation takes authority over the subject, and raised size limits need a served type ([#1818](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1818))

Follow-up to #1808's review.

  - DELETE /auth/sessions/{id} and ?did= (auth/revoke-session/0.2) ask the
    acl/revoke question: own sessions, or a subject whose every context the
    caller administers. A named session that is absent, already revoked or
    outside the caller's authority is answered revokedCount: 0 alike.
  - A per-type size limit above the default is in force only while the type
    is dispatched; the HTTPS door's cap is the largest served limit. The
    refusal no longer echoes an oversized type.

- **vta**: Trust Task refusals stay Trust Task errors on DIDComm, and keys/create needs key-mint (Keyring VTI-09, VTI-23, VTI-27) ([#1800](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1800))

Closes out three Keyring findings against current main. Each was checked
  with a test before anything changed; two were partly still true.

  VTI-09 (VTA and VTC disagree on the DIDComm body shape): already fixed.
  The DIDComm binding envelope has been the only carriage on both nodes
  since VTC #1687, and the VTA's `accept_from_proven_sender` binds the
  document to its sender before anything else. A bare payload is refused
  over DIDComm, TSP and HTTPS with the same answer the VTC gives:
  `malformedRequest: body did not parse as a Trust Task document: missing
  field `id``, in a signed `trust-task-error` (VTI-OPS-021). Tests now pin
  it on both nodes and all three transports.

  VTI-27 (an auth or ACL refusal over DIDComm is a problem-report): the ACL
  path was already fixed, two adjacent paths were not.

  - Already fixed: a sender with no ACL entry or a lapsed grant is answered
    `permissionDenied` in a signed `trust-task-error` in the binding
    envelope, threaded to the request, over DIDComm and TSP. `app_try!` and
    `auth_from_message` no longer exist. Tests pin this.
  - Fixed: a frame the DIDComm inbound gate refuses (anoncrypt, an
    unverified sender, plaintext) never reached the router, and the gate
    answered every one of them with a problem-report, a Trust Task in the
    envelope included. Now an enveloped request gets a signed
    `permissionDenied` `trust-task-error` in the envelope (`gate_refusal`).
    Other message types keep the problem-report because there is no
    document to answer in kind, and an inbound error document gets no
    reply at all.
  - Fixed: an inbound `trust-task-error`, or a reply handed to its waiter,
    comes back from the spine as an empty body meaning "nothing goes
    back". The DIDComm handler failed to parse that body, and `finish`
    turned the failure into an `internal-error` problem-report sent to the
    peer. That answered an error with an error, which is the loop the
    spine stays silent to prevent. It is now no reply.
  - VTC parity: the VTC has no transport gate in front of its spine and
    answers refusals as `trust-task-error` documents. Its replies still use
    the document's own type as the DIDComm `type`, not the envelope. That
    is the separate VTI-42 item recorded at `tt_didcomm_reply` and is not
    changed here.

  VTI-23 (every operation a manager needs requires the admin role): #1619
  fixed the two operations the finding named. One more role floor
  remained.

  - `webvh/dids/create` is gated on `key-mint` ([#1619](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1619)). An initiator in the
    context mints a persona DID over TSP, DIDComm and HTTPS (e2e).
  - `keys/export-secret` is gated on `key-export` (VTI-VTA-003), not on a
    role. An admin of the key's context holds it and exports over DIDComm
    and TSP. An initiator, which holds `sign` and not `key-export`, is
    refused on every transport. That is deliberate (VTI-VTA-002 and
    #1619): a manager acts as a persona through the signing oracle. It is
    unchanged here.
  - Fixed: `keys/create` still checked the admin role, in the Trust Task
    handler and in `POST /keys` (`AdminAuth`). So an initiator, whose
    ceiling carries `key-mint` ("creating new keys within scope", spec
    Appendix C.2), was refused, and an admin narrowed without `key-mint`
    got through (VTI-ACL-030). The gate is now
    `operations::keys::ensure_may_mint_key`, in the operation, so both
    surfaces share it. It reads the caller's ACL entry, as every capability
    gate does. The context check still decides where, and key custody
    still reserves caller-chosen derivation paths for a super-admin.
    `create_key` takes the ACL keyspace for this.

  Tests (named by finding):
  - vta-service lib: `messaging::router::keyring_vti_09_27`,
    `messaging::tsp_inbound::keyring_vti_09_27`,
    `messaging::service::keyring_vti_27_gate`, and
    `operations::keys::tests::vti_23_*`
  - vta-service/tests/keyring_vti_09_23_https.rs: HTTPS binding and
    `POST /keys`
  - tests/e2e/tests/keyring_vti_23_27.rs: TSP, DIDComm and HTTPS against a
    VTA on a real test mediator
  - vtc-service: `vti_09_a_bare_payload_is_refused_as_malformed_on_every_transport`

- **push**: Re-issue a push as a new attempt once it outlives its freshness window ([#1799](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1799))

The push engine (vti_common::trust_task_push) signed a document once and
  sent the same bytes for the whole push deadline: within an attempt the
  outbox retries the hop for up to an hour, escalation and the never-queued
  re-queue resend record.document unchanged, and deadlines run to 24 h
  (credential-exchange) or 30 days (removal notice). Both VTI consumers
  refuse a document older than 10 min + 60 s skew as `expired`
  (freshness_policy, issuedAt required), so any delivery after ~11 minutes
  was silently refused at the far end, and a copy collected late by a
  reconnecting recipient was even recorded "delivered".

  Re-signing under the same id is ruled out by SPEC §4.3/§8.4: a re-stamped,
  re-signed document is a different document under a reused id, which the
  consumer's ReplayGuard (keyed on id + digest of the whole document, proof
  included) refuses as idConflict. expiresAt cannot help either:
  validate_freshness applies max_age to issuedAt regardless, and both
  consumers cap the replay record at issuedAt + max_age + skew by design;
  honouring a producer-chosen expiry would stretch an in-memory replay
  record and widen replay exposure across restarts.

  So the engine issues a SPEC §8.4 new attempt (trust_task_push::new_attempt:
  fresh id, fresh whole-second issuedAt, re-signed by the node through the new
  PushReissuer, kept in the original's thread, every other member including
  idempotencyKey unchanged) wherever it would otherwise put a document past
  its acceptance window on the wire: when queuing any attempt; when an attempt
  still waiting for hand-off crosses the window (superseded on the same
  transport, same window end); and when a copy is collected after the window
  plus skew (the recipient is online now and refused what it collected).
  A mediator-held copy is out of reach and not re-sent per window; bounded by
  MAX_REISSUES. The window is now one constant, trust_task::ACCEPTANCE_WINDOW,
  read by both consumers and the engine.

  Duplicate execution across attempts is what idempotencyKey is for
  (VTI-OPS-061/064): the credential-exchange push sites (VTA push_step, VTC
  push_document) now carry a key, and the VTA consumer now keys tasks the
  retry_safety catalogue does not classify, as VTI-OPS-062 requires; before,
  it skipped every counterparty credential-exchange step. Replay exposure is
  unchanged: same window, same replay record, and a byte-identical replay of
  a new attempt is still refused by id.

- **auth**: Split a resolver failure from an invalid proof in reply verification (FTL-29595) ([#1748](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1748))

* fix(auth)!: split a resolver failure from an invalid proof in reply verification (FTL-29595)

  The distinction already existed two layers down and was thrown away one layer
  up. affinidi-data-integrity's DataIntegrityError::Resolver(String) is already
  distinct from InvalidSignature, and TrustTaskVmResolver::resolve constructs it
  specifically on a DID-cache resolution failure — but
  verify_trust_task_proof_with collapsed every DataIntegrityError variant into
  one opaque DiProofError::VerifyFailed. A caller verifying a peer's reply
  therefore could not tell "I could not retrieve the verification key" (a
  retrieval failure — the peer's response may be entirely genuine) from "the
  signature does not verify" (an actual bad proof), and reported both as the
  same "proof does not verify" — which invites blind retries against a mutation
  that already committed.

  Adds DiProofError::ResolverFailed(String), rendering byte-identical to
  VerifyFailed on the wire ("proof verification failed"): DiProofError's
  Display is deliberately opaque because most of its ~15 callers are
  unauthenticated inbound routes, where telling a resolver failure apart from a
  bad signature is an oracle (whether a DID resolves at all). Every one of
  those routes still sees the same string; only the two caller-side sites where
  the audience already knows what it asked for now branch on the variant:

  - vta-sdk::client's reply-verification (a client checking its own outbound
    reply)
  - vta-service::operations::outbound's reply-verification (the VTA acting as
    an outbound caller to a peer/room-host)

  Both now report a resolver failure as a retrieval failure with a distinct
  message, instead of folding it into "is unsigned or its proof does not
  verify".

  One exhaustive match over DiProofError existed at vta-service's
  trust_tasks::step_up::verify_did_signed_gate — the one inbound call site with
  any per-variant branching at all, and so the one actual risk in this change.
  Folded the new variant into its existing VerifyFailed arm; no behavior
  change, since that gate is did:key-only and the resolver path never runs
  there.

- **vtc-service**: The REST backup stubs declare no success body ([#1775](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1775))

POST /v1/backup/export and /import only ever answer 403 since backups moved to Trust Tasks over an end-to-end transport, so their handlers no longer claim to return ExportResponse / ImportResult. The OpenAPI response census failed on main because of that mismatch. The refusal messages name the end-to-end transports rather than one of them.

- **vtc-service**: A community backup travels only over DIDComm or TSP ([#1755](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1755))

* fix(vtc-service)!: a community backup travels only over DIDComm or TSP

  The backup request carries its password, and the backup carries the
  community's signing key bundle. Over REST both exist in plaintext wherever
  TLS terminates.

  - POST /v1/backup/export and /v1/backup/import always answer 403.
  - vtc/backup/export and backup/initiate-export, initiate-import and
    finalize-import are refused on the REST binding, after the super-admin
    check and before any state is serialized, a slot is opened or the
    password is used. The chunks are ciphertext and are unaffected.
  - The export audit row is still written before the envelope is returned,
    and a VTC with no audit trail now refuses to export instead of releasing
    the backup unrecorded.
  - vtc-client export_backup and import_backup use the backup/* chunked
    transfer over a DIDComm or TSP session, verifying every chunk and the
    whole, and refuse without a session.
  - cnm backup connects to the VTC over TSP, or DIDComm when the VTC
    advertises no TSP, and has no REST fallback.

  Implements trustoverip/dtgwg-trust-tasks-tf#646.

- **git-ns**: Git-ns/view 0.4 requires a proof (trust-tasks 0.23.1) ([#1770](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1770))

trust-tasks-rs 0.23.1 makes git-ns/view 0.4 declare its proof REQUIRED,
  matching 0.1-0.3; trust-tasks-capability-client 0.23.1 moves with it
  (still on trust-tasks-rs = "^0.23", so the bump does not split the
  dependency graph).

  vtc-service's git-ns dispatch comments and GitNsCtx::sender field still
  described view and account/link-status as proof-RECOMMENDED reads that
  fell back to the transport's authenticated sender. That was already
  stale for link-status (0.1 has always required a proof) and is now
  stale for every served view version. Corrected, and handle_view's three
  handlers now call the signer-only helper directly instead of the
  caller() fallback, which is dead for view; link-status keeps caller()
  unchanged, since removing its own now-unreachable fallback is a
  separate cleanup.

  Added a test that an unsigned git-ns/view/0.4 is refused with
  proofRequired.

- **vtc**: One forge account per member, and only current members' accounts count ([#1742](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1742))

* fix(vtc): one forge account per member, and only current members' accounts count

  - Link uniqueness (git-ns/account/link item 4) was already enforced under
    the git-ns store lock. The check and the recording are now one step
    under the member-row lock too, and a regression test pins it: a
    second member completing a link to an already-linked forge id ends
    `failed` and the account stays with the first.
  - A departed member who held no git right kept their linked accounts for
    good: the link deletion sat after sweep_departures' early return for
    "no departed member held a right". It is now its own pass in the
    lifecycle sweep (git-ns/account/link, Consent/purpose: MUST delete it
    when the member leaves).
  - linked_accounts, which the role projection and drift adoption read,
    now holds only current members' accounts. A member whose access lapsed
    but who has not left keeps the account, so nobody else can link it,
    but it projects no role.
  - GET /v1/git-ns/accounts gains memberCurrent, and the console's Repos
    plugin no longer offers adoption for an account whose member is not
    current. The daemon already refused that adoption.

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
- **vti-common**: Bind the authcrypt sender key id to the key used, before trusting a DIDComm sender ([#1732](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1732))

An authcrypt (ECDH-1PU) JWE names its sender key twice in the protected
  header: `skid` and `apu` (the PartyUInfo the key derivation is bound to). A
  conforming packer writes the same key id into both. The direct-unpack callers
  now require that the two agree, and that the key the unpack metadata reports is
  that same key, before a sender is trusted.

  - New `vti_common::auth::verify_authcrypt_header(raw_jwe)`: for an ECDH-1PU
    outer layer (JSON or compact serialization) requires `skid` to be a DID URL
    with a key fragment, `apu` to be present, and `BASE64URL-decode(apu)` to be
    exactly the `skid` bytes. Any other `alg` is refused, so authcrypt nested
    inside anoncrypt is not accepted on these paths.
  - `bind_authcrypt_sender(raw_jwe, message, metadata)` now takes the raw
    envelope and requires: the header check; an `authcrypt(plaintext)` or
    `authcrypt(sign(plaintext))` wrapping; `encrypted_from_kid == Some(skid)`;
    and `DID(from) == DID(skid)`.
  - Callers updated: VTA `/auth/`, `/auth/refresh`, vault unseal; VTC
    `/v1/auth/`, `/v1/wallet/auth/` and refresh.
  - New `vti-common` `test-support` feature with builders for authcrypt
    envelopes with a caller-chosen protected header; route tests on both
    services.

- **vtc-admin-ui,cnm-cli**: Shell quoting that is safe in fish, and reseat follow-ups ([#1723](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1723))

shellQuote (admin console) and shell_word (cnm) used POSIX '...'\''...'
  quoting. fish reads \' and \\ as escapes even inside single quotes, so a
  value such as  x\' ; echo INJECTED ; echo \  pasted into fish ran
  `echo INJECTED`. Both now single-quote runs without ' or \ and write each
  ' as "'" and each \ as "\\", which read back byte-exact in sh, bash, zsh
  and fish. A bare word may no longer start with = (zsh's =cmd expansion) or
  % (fish's %self), nor, in cnm, with -.

  Tests run the generated words through sh, bash and, where installed, zsh
  and fish, and assert every hostile value comes back byte-exact.

- **vtc-service**: Git-ns review follow-ups — adopt policy input, legacy revoke, reseat evidence ([#1714](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1714))

Follow-ups from the review of #1703.

  - The policy sees an adopted drift item as `right.grant` with
    `via: "drift.adopt"` (git-ns/drift/resolve, step 6), so a community can
    refuse every adoption and still grant. Default policy comment and docs
    say so.
  - right/revoke still accepts a subject that is not a DID-core DID when a
    recorded right names it — one granted before DID-core was enforced —
    so no right is left that nobody can take away. Grant, transfer, adopt
    and reseat still refuse one.
  - A reseat's evidence comes from the audit log: each earlier git.ns.admin
    record revoked (by whom, why — a revoke now records its reason),
    lapsed (when) or removed on departure (when), plus records not yet
    swept; holders are not named. The subject's own lapsed admin record is
    replaced rather than kept beside the new one.
  - drift/resolve adopt re-checks its item (observed value included) under
    the store lock the grant is written under; a changed item adopts
    nothing.
  - Two string literals that had lost their line continuation (the
    notHeadless message, cnm's --observed error) are fixed.
  - cnm sanitises the VTC's error code as well as its message; the
    notAdoptable hint for a lowering names revoke; the notRevertible hint
    covers manual mode and accounts the projection holds.

- **vtc**: A config import onto a VTC with no profile meets the profile edit caps ([#1706](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1706))

`vtc/config/import/0.1` applied an imported community profile through
  `CommunityProfileUpdate::apply` when a profile was already stored, and stored
  it verbatim when none was. The verbatim path skipped every cap an edit must
  meet — the text-length bounds, the 16 KiB `extensions` bound, the
  `http(s)`-only `logoUrl` and governance URL, the personhood overclaim refusal —
  and those caps exist because the profile is served on the unauthenticated
  public-profile endpoint, where `logoUrl` lands in an `<img src>`. An import was
  the one way to publish a `javascript:` logo URL there.

  Every import now builds the same patch. With no stored profile it is applied
  to a default profile for the incoming community DID, keeping the imported
  `createdAt`, and the result is stored even when nothing differs from the
  defaults. The reported changed members now come from `apply` on both paths,
  which also names `personhood` and `relationshipIdentifierDefault` when an
  import sets them — the hand-written list left both out.

  Reachable only before a VTC has an identity: boot heals a missing profile
  whenever `vtc_did` is configured. Recorded in #1702's design-note entry for
  batch 3, which now points here.

  `an_import_with_no_stored_profile_meets_the_edit_caps` fails on the previous
  code and passes on this.

- **vtc**: OpenAPI schema names are unique, so each endpoint documents its own shape ([#1697](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1697)) ([#1701](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1701))

utoipa keys `components.schemas` by bare type name, and
  `OpenApiRouter::routes` merges each route's schemas with a plain map
  `extend`, so two `ToSchema` types with one name fail nothing: the last
  registered wins and every `$ref` to the name describes that one. The VTC
  document had 18 such names across vtc-service and vta-sdk, and six were
  wrong in the published document — `GET /v1/admin/passkeys` was described
  as the console-key list, `/v1/auth/challenge` as the personhood challenge,
  and five revoke endpoints as the endorsement revoke response.

  - vtc-service: the service-side types get distinct names with
    `#[schema(as = …)]`. Rust type names are unchanged, so no handler moves
    and `openapi_response_census` still compares like with like.
  - vta-service: `RollbackResponse` and `EnrollPasskeyChallengeBody` were
    field-for-field copies of vta-sdk's types registered under the same
    names. The shapes matched, so the document happened to be right; the
    copies are deleted in favour of the vta-sdk types.
  - `openapi_schema_names.rs` in both services: a source-scan census that
    fails when two `ToSchema` definitions in the crate or its path
    dependencies share a schema name, and when the scan finds too few names
    to prove anything.
  - admin-ui: `openapi.json` and `wire.ts` regenerated; `PasskeyListResponse`
    restored as a generated alias and used by `myPasskeys.tsx` in place of
    the local interface that let the drift go unnoticed.

- **vtc**: The registry syncer publishes only members who consented ([#1691](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1691))

`registryConsent` on `vtc/join-requests/submit` is the applicant's consent
  to trust-registry publication (submit 0.2, Consent/purpose). #1682 carried
  it onto `Member::publish_consent`, but the MembershipSyncer never read the
  flag. It published every `MemberAdded` when `registry.rego`'s
  `publish_on_join` was true (the default), so members who declined were
  listed in the community's trust-registry record anyway.

  The syncer now decides each job at dispatch time from current state:

  - Consent is a hard floor enforced in code. A live member is published
    only while `publish_consent` is true. No policy can publish a member
    who did not consent, because consent is the applicant's to give and
    not the community's.
  - `publish_on_join` narrows. It is consulted only for a consenting
    member, on first publication, whichever job asks (`PublishMember`, or
    an `UpdateMember` for a member not yet published). A late grant or a
    role change no longer routes around `publish_on_join := false`. The
    rule's input is now `{action: "publish", member: {did, publishConsent}}`.
  - Withdrawal: a `MemberUpdated` that changes `publishConsent` enqueues
    an `UpdateMember`. Withdrawn (true -> false) deletes the member's
    registry record and mirror row. Granted (false -> true) publishes,
    subject to the policy.
  - A `MarkDeparted` for a member who was never published is skipped.
    Otherwise it would publish a `Departed` record and disclose the
    membership as it ends.

  BEHAVIOUR CHANGE: every member admitted before #1682 holds
  `publishConsent = false`. Such a member may already be in the registry.
  Their record is removed the next time the syncer re-decides them: a role
  change, a consent change, a retried job, or an audit-log replay. Nothing
  removes them all at once on upgrade. To keep a member listed who agrees
  to it, set `{"publishConsent": true}` via `PATCH /v1/members/{did}` or
  `vtc/members/update` (see docs/03-vtc/trust-registry.md, "Who is
  published: member consent").

- **vtc**: A Trust Task over DIDComm rides the binding envelope only (Keyring VTI-42) ([#1687](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1687))

The DIDComm binding (bindings/didcomm/0.2 §2-§5) makes the envelope
  https://trusttasks.org/binding/didcomm/0.1/envelope the only carriage for a
  Trust Task, and requires a consumer to refuse any other type at the DIDComm
  layer with no trust-task-error.

  The VTC router still carried twelve task-typed arms beside the envelope arm
  (join-requests submit/manifest 0.1+0.2/status, members/self-remove,
  members/vmc, six vtc/vetting URIs). Every other served verb answered
  'unsupported message type' when typed as itself. Two of the arms
  (self-remove, vmc) parsed bespoke bodies and bypassed
  dispatch_trust_task_core, so they skipped freshness, recipient and proof
  checks. All twelve are removed. Every one of these URIs is dispatched by the
  spine via the envelope.

  The VTC and VTA fallbacks now answer a https://trusttasks.org/spec/ type
  with a threaded problem-report that names the envelope type.

  Parity tests walk each dispatcher's own list (VTC DISPATCHED_URIS +
  ROOMS_DISPATCHED_URIS; VTA dispatched_uris()). An enveloped request is never
  answered 'unsupported message type'. A task-typed one gets the
  envelope-naming problem-report. The VTA's two remaining task-typed arms
  (acl/swap-key/0.1, provision/integration/0.3) are pinned in a shrink-only
  list.

- **vtc**: Carry the applicant's registryConsent onto the admitted member ([#1682](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1682))

registryConsent on vtc/join-requests/submit was stored on the join request
  and never read: every admission wrote publish_consent=false. EffectPlan::Admit
  now carries publish_consent, written in the member row's first store, and
  every admitting path sets it from the request (auto-admit and supplement via
  apply_verdict_to_request, operator approval via decide). A verdict-derived
  plan writes false. Keyring round-3 Q14.

- **vtc**: Answer the auth tasks with the error codes their specs declare ([#1668](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1668))

`routes/auth.rs` and `routes/recognise.rs` carried no declared code at all:
  every refusal was a bare status and prose, so a client had to match on
  English to tell one from another. Three of the five codes the auth
  specifications declare are now on the wire.

  - `vtc/auth/admin-session:invalidToken` — the mirrored access token did not
    verify (signature, audience, or expiry).
  - `vtc/auth/recognise:credentialInvalid` — the VEC or VMC failed proof
    verification, fell outside its validity window, or was revoked. The
    specification's words are "failed proof verification, was expired, or was
    revoked via credentialStatus", so `IssuerKeyUnresolved` and `Malformed`
    stay uncoded: they are refusals about a document that could not be checked
    at all, not one that was checked and failed.
  - `vtc/auth/recognise:roleNotMapped` — policy allowed the issuer but mapped
    the foreign role to no local role. Different from the above to a caller:
    one is an operator's policy decision, the other is the credential.

  Both handlers now return `TaskError` rather than `AppError`, because
  `From<TaskError> for AppError` drops the code — returning `AppError` would
  have built each code and thrown it away.

  The census baseline drops 11 to 8. The two remaining auth codes are not
  oversights and the baseline now says so: `rateLimited` is declared by the
  challenge task but the limiter in front of it is the chain-wide per-IP
  governor, whose error handler is handed a `GovernorError` with no request
  and so cannot know which route was refused; `issuerNotRecognised` needs a
  trust registry that answers "no", and every fixture here wires
  `registry_client: None`.

- **vtc**: Stop a caller's JSON Schema from fetching a URL or reading a file ([#1660](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1660))

The `jsonschema` crate enables `resolve-http` and `resolve-file` by default,
  and the workspace took the default. Every schema the VTC compiles is supplied
  by a caller — a `credentialSchema` at `POST /v1/schemas`, an endorsement
  type's `claimSchema`, and both again at issuance — so an external `$ref`
  made the service fetch a URL or read a local file while compiling it. Both
  are admin-reachable.

  It is not theoretical: with the resolvers on, registering a `credentialSchema`
  of `{"$ref": "file:///<a real file>"}` answers 201 Created, having read that
  file. With them off the same registration is refused 400, which is what
  `validator_for` already reports to the caller.

  Nothing in the repo uses an external `$ref`, and a schema that needs one
  belongs inlined. `idna` is kept (the hostname format check; pure computation),
  `tls-aws-lc-rs` goes with `resolve-http`. The lockfile drops `reqwest` and
  `rustls` from the jsonschema tree.

  Two tests hold the manifest honest, one at each compile site, and both fail if
  the features return.

- **vtc**: Admin promotion goes through acl/change-role, behind a step-up ([#1658](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1658))

`vtc/members/update/0.1` carried an in-handler step-up for `role: admin`.
  That gate bounded one route. `acl/change-role` and `acl/grant` reach the
  same ACL row and assign the same `admin` role, and neither asked for a
  step-up, refused self-promotion, or ran the role-change pipeline — so the
  gate was walked around by using a different door. The task also *declares*
  `adminRoleForbidden` for exactly this: promotion is a separate, gated flow,
  not a metadata update.

  The gate now sits on the operation. `role_change_via_pipeline` took a
  `step_up: bool` from its caller, which made the handler the gate; it now
  resolves the elevation from the caller's live session, and two host
  invariants are applied around the policy in `ceremony::decide`, where an
  operator's policy edit cannot reach them: `StepUpForAdmin` (VTI-OPS-051)
  and `SelfPromotion` (VTI-OPS-050, new). The VTC has no `policy.enforcement`
  switch and its pipeline always runs, so neither can lapse by configuration.
  `acl/grant` of `admin` checks the same predicate directly — it writes an
  entry rather than moving one, so there is no transition to hang an invariant
  on — and refuses a self-mint.

  Everything the members/update path did came with the promotion: the promote
  lock moved into the ceremony (the window is a property of the operation, and
  with the lock on one handler the second door raced it), the already-an-admin
  re-check generalised into a compare-and-swap re-read under that lock, the
  role-change policy and role-VEC re-mint, the admin sister record, and the
  `AdminPromoted` audit row.

  `update_acl` also never ran `validate_acl_modification`. The existing
  `caller_covers_admin_target` guard only fires on an entry that is already
  admin, so a context admin of ctx-a could not demote a peer scoped to
  `[ctx-a, ctx-b]` but could promote a member with those scopes into exactly
  that entry. It is checked now, decoded through `ActScope`.

  `RemintOutcome.role_vec` is now `Option<VerifiableCredential>`: a role VEC is
  re-minted only where there is a member row to repoint it on, so an ACL-only
  subject no longer needs a credential signer to change role.

- **vtc**: Refuse an invalid claimSchema at registration, and name the broken type at issuance ([#1657](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1657))
- **vtc**: Emit the error codes the admin, backup, directory, endorsement and install tasks declare (#1600, part 2) ([#1649](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1649))
- **auth**: A signed REST sign-in must be addressed to the service that receives it ([#1646](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1646))
- **vtc**: Emit the error codes the join, member, vetting and relationship tasks declare ([#1644](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1644))
- **vtc-client**: Upload_policy sends the canonical policy/upsert body; add member_credentials ([#1643](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1643))
- **cnm**: Vetting, audit and backup authenticate to a VTC with its own DID as audience ([#1637](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1637))

`cnm vetting`, `cnm audit verify` and `cnm backup` could not sign in to a
  VTC. All three took a token from `SessionStore::ensure_authenticated`, whose
  audience is not a parameter: it is always the session's bound *VTA* DID, and
  the DIDComm authenticate envelope it builds is encrypted to that DID's
  key-agreement key. A VTC holds only its own keys, cannot open the envelope,
  and refuses the login. `cnm vetting` then also built its `VtcClient` with the
  VTA's DID as the community's DID. main connected to the VTA first, so without
  `--url` the requests went to the VTA's REST URL too.

  They now authenticate the way `cnm did-log install` does ([#1632](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1632)):
  `VtcClient::connect(base, vtc_did, client_did, key)` with the profile's DID
  and key, and the VTC's DID as the audience. They are exempt from
  `requires_auth`, so no VTA connection is made first.

  Where the VTC's DID comes from: `--vtc-did` (env `CNM_VTC_DID`), else a new
  optional `vtc_did` on the community profile, set with
  `cnm community set-vtc <did>`. The DID is never read from the server (for
  example the VTC's `/health`): it is the audience the sign-in is signed for,
  and a server allowed to name it could name another community's DID and
  relay the signed document there. Discovery runs from DID to URL, as it does
  for a VTA: `--url` if given, otherwise the `VTCRest` service in the DID's
  document, matched on `type` and checked by the same endpoint guard as a
  VTA's advertised REST URL.

  The root cause is a generic "token for this base URL" helper sitting on a
  session bound to one audience. `cnm`'s `auth::ensure_authenticated` wrapper
  is removed, so nothing in `cnm` can reach the VTC through the VTA session
  again, and `SessionStore::ensure_authenticated` now documents that it
  authenticates to the session's VTA only. Nothing else in the workspace
  used `SessionStore` against a VTC.

  When the VTC refuses the sign-in, `cnm` prints the fix with the DID filled
  in: `vtc --config <config.toml> acl add --did <DID> --role admin --label cnm`,
  or Access control, Add entry in the console. A VTC answers every
  authentication failure the same way (VTI-SES-007), so the message names the
  usual cause rather than claiming it.

  Routing these through a live VTC exposed two more faults on the same paths,
  fixed here:
  - `cnm backup export` saved the `{ envelope }` response (the export shape
    since #1059) instead of the envelope, so the file printed `(none)` for
    its source DID and could not be imported. `VtcClient::export_backup`
    returns the envelope, and accepts a pre-#1059 bare one.
  - `cnm audit verify` read the signed-checkpoint result from the top level,
    but #1110 moved it under `ext["org.openvtc"]`. Every report therefore
    looked like it had no checkpoint result, and a truncated log that the
    community key contradicts passed as long as its hash chain did. It reads
    both places now, and fails on any checkpoint status it does not know
    rather than passing it.

  vtc-client gains `audit_verify`, `export_backup`, `import_backup`,
  `REST_SERVICE_TYPE` and `api_base_from_did_document`, plus the three task
  URIs. All are additive.

- **vtc**: A witness credential is personhood evidence only when its digest binds ([#1630](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1630))

The witness-digest verifier from #1161 read the Working Draft 01 member
  `credentialSubject.digest` and digested stored VRCs with the Trust Task
  framework digest, which includes the `proof`. DTG Credentials WD02
  §Digest Encoding names `digestMultibase` and excludes the top-level proof,
  so a VWC built by `DTGCredential::new_vwc` to the specification resolved
  `Absent`. With the right member it would still have resolved `Unresolved`
  against any signed VRC. The verifier now reads `digestMultibase` first and
  still accepts the WD01 name. It recomputes with `digest_multibase_json` and
  decodes with `decode_digest_multibase`, both from `dtg-credentials`, so the
  producer and the verifier use one implementation of the digest.

  The personhood `assert` path handed policy a projection with no binding
  verdict, and the default `personhood.rego` admitted any `WitnessCredential`
  with a non-empty issuer. The host now writes a `witness_binding` verdict
  onto every witness entry of `vp_claims`, using the key and shape of the
  ceremony fact. The key is host-owned, so a presenter-supplied value is
  overwritten or removed. The default policy allows only `bound`.
  `unresolved` is not forgery, but this community cannot see the witnessed
  edge, so accepting it is left to an operator policy.

  `install_defaults` never revisits a filled pointer, so a VTC first booted
  on an earlier binary would keep the permissive default. At boot,
  `upgrade_unbound_witness_personhood_default` replaces the active
  personhood policy only when it was authored by the workspace
  (`DEFAULTS_AUTHOR`) and still admits an unbound witness. The replacement
  is a new revision, and the old one is kept. An operator's policy is never
  touched.

  VWC issuance (the first item in #1068) is not included, because the VTC
  is not a specified VWC issuer. See the PR description.

- **vtc**: An offline command run beside the daemon says so, and `admin invite` names its online twin ([#1618](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1618))

Keyring finding VTI-16. Run while the daemon is up, `vtc admin invite` failed
  with the storage engine's own words:

      Invite failed: store error: FjallError: Locked

  From that, Keyring concluded that admitting a new administrator meant taking the
  community offline. **It never did.** `POST /v1/admin/invites` mints the same
  invite through the running daemon — its own docs say it "mirrors the `vtc admin
  invite` CLI exactly" — and the admin console's access page already calls it. No
  client and no error message ever pointed there.

  This is the case CLAUDE.md's rule is written for: when the operator's real
  intent maps to a different command, print that command.

  ## The class, not the instance

  fjall permits one process per data directory, and every offline `vtc` command
  opens the store directly: `admin invite`, the three `acl` commands, `did-key`,
  `sync-jobs`, and `status`. Each produced the same bare `Locked`.

- **sdk**: The vtc-host template advertises the REST base the VTC actually serves ([#1615](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1615))

Keyring finding VTI-15. A VTC's DID document published

      { "type": "VTCRest", "serviceEndpoint": "{URL}" }

  but `vtc-service` serves its API under `/v1`, so every request a client derived
  from the document answered 405. Its sibling `VTCStatusList` has always carried
  `{URL}{STATUS_LIST_PATH}`; `VTCRest` never got the equivalent.

  ## Why we never saw it

  Nothing in this workspace consumes a `VTCRest` entry — `rest_url_from_did_doc`
  looks for `vta-rest`. It exists for third parties, so a wrong value is invisible
  here and costs only the integrator who trusts it. Keyring found it for that
  reason, and it (with VTI-14, fixed in #1601) is why their repository carries its
  own admin client.

  That also corrects our remediation plan, which promised to "accept both forms on
  the resolver side for DIDs already minted". There is no resolver side to make
  tolerant.

  ## The fix

  `REST_PATH`, an optional template variable defaulting to `/v1`, exactly as
  `STATUS_LIST_PATH` already works — so a deployment serving the API elsewhere, or
  at the root (empty string), can say so. The VTC setup wizard already passes
  `URL` as the host base precisely to avoid a double `/v1` in the status-list
  endpoint; its comment now covers both variables.

  ## Already-minted communities

  A VTC's `did.jsonl` is write-once — it cannot re-sign its own log — so this
  fixes new communities only. An existing one needs a VTA-side `dids edit` to
  correct its `VTCRest` entry and a redelivered log. That is an operator action,
  not something code here can do for them.

  ## Tests

  The existing test pinned the bare URL; it now asserts `/v1` and says why, so the
  value is not quietly reverted. A new test covers the override and the empty
  root case, and that an empty `REST_PATH` leaves no trailing slash.

- **vtc**: A caller-visible failure reaches the client typed, and an internal one says nothing ([#1607](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1607))

Two defects in `vtc-service`'s Trust Task reject mapping, both of which
  `vta-service` fixed long ago and this service never did. Found by following
  #1602, which fixed the client half of the first one for a single code.

  ## Every NotFound, Conflict and Gone arrived as an opaque string

  §8.3 defines no `notFound` / `conflict` / `gone`, so all three ride out under
  `taskFailed`. That is the correct wire code and it is not enough on its own: a
  caller cannot tell "the row you asked for is absent" — very often a *normal*
  state it knows how to handle — from "this operation genuinely failed".

  The VTA puts the discriminator in `details.reason`, and
  `VtaClient::trust_task_error` reads it back into the same typed `VtaError` the
  REST and problem-report paths produce. The VTC passed `details: None`, so
  every one of these collapsed into `Protocol(String)` — the exact failure
  `CLAUDE.md` names by name ("never collapse a Conflict into a string").

  #1602 recovered `NotFound` for extended codes whose local part is literally
  `notFound`. That leaves everything else, including four of the six codes added
  this week (`submit:requestAlreadyOpen`, `supplement:notAwaitingEvidence`,
  `supplement:alreadyDecided`, `withdraw:alreadyDecided`) and the pre-existing
  `vetting/vetters/resend:notGranted`, which is a `NotFound` underneath whose
  local part is not `notFound`.

  `reject_with_code_because` carries both. A client that knows the extended code
  gets the precise reason; one that does not falls back to `taskFailed` per
  SPEC §8.5 and still recovers the right typed variant from the marker. The
  marker is **merged** into `details` rather than replacing it, because the
  spec'd annex members (`requestId`, `status`) are what the applicant's client
  acts on — a marker that overwrote `requestId` would take away the thing they
  need to withdraw.

  ## An internalError sent its cause to the caller

  Framework 0.5.0, *What a `message` May Not Say*: a `message` MUST NOT reveal
  consumer-internal state. The catch-all arm was
  `RejectReason::InternalError { reason: message }` with `message =
  err.to_string()`, so an unauthenticated caller received things like
  `vtc_did not configured`, `audit_writer not initialised`, or a raw fjall or
  serde failure — the deployment's shape and which invariant just broke.

  The producer needs one fact from an `internalError`: the failure was not its
  document's doing. The cause is what the *operator* needs, and now goes to the
  log. Every other arm describes the caller's own request back to it, which is
  not internal state, and passes through unchanged.

  ## Tests

  Three, each verified to fail when its fix is reverted:

  - `an_internal_error_does_not_send_its_cause` — two causes of different
    shapes, because the leak was in a catch-all rather than in `Internal` alone.
  - `caller_visible_failures_carry_their_reason_marker` — all four variants.
  - `a_coded_reject_carries_the_reason_marker_a_client_reads` — end to end
    through the dispatcher, asserting the spec'd annex survives the merge.

- **vtc**: Name the open request when a duplicate submit is refused ([#1592](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1592))

Keyring finding KR-04, the other half of the withdraw work in #1591. When the
  dedup guard refuses a second application, the refusal now says *which* request
  is in the way and what state it is in, as a typed code with a machine-readable
  annex rather than English prose on a bare `taskFailed`.

  The applicant's actual question is "wait, or withdraw?", and it is not
  answerable without the status. A `pending` request is waiting on the community
  and will resolve on its own; a `deferred` one is waiting on the applicant, so
  "await its decision" is advice that would never come true. That is the position
  Keyring's applicants were left in.

  ## The code is consumer-minted, not a spec change

  `vtc/join-requests/submit` declares no code for this. SPEC.md §8.5 permits a
  consumer — not only the spec author — to mint a namespaced code for an
  invariant the specification did not enumerate, provided the namespace is the
  slug of the request being processed. The same section's fallback rule means a
  client that does not recognise the code reads it as `taskFailed`, so this is
  additive for every existing caller and needs no upstream round-trip.

  (#1591's body claimed this half was blocked on an upstream change. That was
  wrong — §8.5 covers it.)

  ## Why a typed refusal rather than a re-read

  `submit_inner` now returns `SubmitRefusal`, whose `AlreadyOpen` variant carries
  the request id and status the dedup guard already held at the moment it fired.
  The alternative — have the Trust Task handler re-read the open request to
  describe it — would race a concurrent decision on the very request being
  described, and would report a status that was never the one the guard matched.

  `From<SubmitRefusal> for AppError` is what keeps one wording for one refusal:
  the prose lives there, and the handler renders it through the conversion rather
  than restating it.

  Both live submit surfaces move together, and deliberately so. Submit is
  reachable only as a Trust Task — over HTTPS (`post_tt`) and over DIDComm — and
  both now carry the code, which is why the two existing dedup tests changed.
  Worth recording for whoever reads those test names: the one called
  `rest_submit_dedups_...` posts a Trust Task document over HTTPS, so "REST"
  there means the transport binding, not a flat-JSON route.

  There is a flat-JSON `routes::join_requests::submit::submit` handler that
  answers 409, and it is **not mounted on any router** — `read`, `manifest`,
  `decide` and `present` are registered in `routes/mod.rs`, submit is not. It
  is dead code, left alone here because deleting it is separate scope.

  `AppError` was the obvious place for this and is the wrong one: it is not
  `#[non_exhaustive]`, so a structured variant there would be a breaking change
  to published `vti-common` for a refusal that concerns one task.

  ## Tests

- **vtc**: Return the response wrapper the delete route documents ([#1589](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1589))

`main` is red on `openapi_response_census`: the handler declares
  `body = EndorsementTypeDelete01Response` and returns
  `Json<DeleteTaskResponse>`. The census requires those to name the same
  type, because the annotation is what generates the console's `wire.ts` —
  a mismatch ships a console reading a shape the daemon never sends, and it
  does so silently, since the generated types typecheck against themselves.

  #1587 moved the route onto the generated type but returned it bare. The
  `spec_types!` wrapper is what carries `ToSchema` for a foreign type, and
  `routes::vetting` already shows the shape: return the wrapper, build it
  from the generated value with `.into()`. Doing that here makes the
  annotation and the return type agree.

  Only the doc comment moves in `openapi.json`; the schema `$ref` is
  unchanged, so the wire contract is identical and no client sees a
  difference.

  Verified against both CI test jobs this time, not one:
  `cargo test -p vtc-service -p vtc-client` (63 targets, 1687 tests) and
  `cargo test --workspace --exclude vtc-service --exclude vtc-client`
  (128 targets, 4652 tests). #1584 was checked with only the first and
  missed the `vta-sdk` census; #1587 with only the second, which excludes
  `vtc-service` and so could not see this.

- **vtc**: Return the generated endorsement-type delete response, not a copy of it ([#1587](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1587))

`main` is red. #1584 renamed this route's hand-written response struct out
  of a three-way `DeleteResponse` collision and, in doing so, gave it a doc
  comment naming the task it restates — which is exactly what
  `vta-sdk/tests/generated_wire_types_census.rs` looks for. The type had
  been violating that census all along; it was invisible only because it
  carried no doc comment saying so.

  The census does not take new baseline entries, and it is right not to:
  `trust_tasks_rs::specs::vtc::endorsement_types::delete::v0_1::Response` is
  the published shape, and a local `{ typeUri }` beside it is a second
  definition that can drift. The handler now returns the generated type and
  builds it through its builder, so a response that does not match the
  schema is a construction error rather than a struct literal that compiles
  and lies.

- **vtc**: Move "Request member VMC" to the Credentials card it acts on ([#1585](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1585))

The button sat under Admin actions, four cards below the row it changes —
  past Published relationships, Disposition + consent and Vetter role — in a
  block otherwise about promoting and removing people. Asking a member for
  their half of the membership pair is neither of those things.

  The Membership edge row's own copy already said "request a fresh one
  below", which was a reference across four cards to a button an operator had
  to go looking for. It now points at something adjacent.

  The mutation's error and success feedback move with it. Left where they
  were, a click in Credentials would have reported its result four cards
  down, out of view.

- **resolver**: Take the shared DID resolver instead of building one ([#1581](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1581))

* fix(resolver): take the shared DID resolver instead of building one

  Twelve call sites across `vta-service`, `cnm-cli` and `vtc-service` each
  constructed their own `DIDCacheClient`. A client owns its cache, so the
  same DID was fetched once per construction rather than once per process,
  and a `did:webvh` host saw a burst of requests for what is one logical
  operation — enough to earn a 429 from its own rate limiter.

  Every one of them built
  `DIDCacheConfigBuilder::default().with_host_policy(webvh_host_policy())`,
  which is byte-for-byte what `build_did_cache_config(None)` produces, so
  taking `shared_did_resolver_from_env()` preserves behaviour and collapses
  twelve caches into the one the SDK already keeps per runtime, sidecar URL
  and host policy.

  It also fixes a second problem those sites had: by calling
  `DIDCacheClient::new` directly they never read `PNM_RESOLVER_URL`, so an
  operator who had configured a resolver sidecar — the documented mitigation
  for exactly this load — did not get it on any of these paths. The env var
  existed to spare the SDK's public API, and these call sites went around
  it.

  Three sites are deliberately left alone, and each looks convertible:

  - `vtc-service/src/server.rs` and `room-host/src/main.rs` build a plain
    default with no host policy. Converting them would add
    `webvh_host_policy()` and change which hosts are permitted — a
    security-relevant change, not a caching one, and not one to make inside
    this change.
  - `pnm-cli/src/bootstrap.rs` passes `None` on purpose. Bootstrap resolves
    the DID locally so the operator verifies the SCID and signed log on
    their own machine rather than trusting a sidecar; that `None` is the
    trust boundary, not an oversight.

  Adds the test that was missing for the property all of this now rests on:
  that two callers on one runtime get one resolver. Sharing could have
  broken and every converted site would have quietly gone back to a private
  cache with nothing failing.

  Reported as VTI-19 by the Keyring wallet team, who saw one command fetch
  `/.well-known/did.jsonl` forty times in five minutes.

- **trust-tasks**: Keep a duplicate-execution record in the VTC and room-host (SPEC §7.2 item 11) ([#1571](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1571))

Live delivery is at-least-once by design. The mediator re-pushes a recipient's
  whole undelivered inbox when a socket enables live delivery (VTI#918) and when
  a duplicate socket displaces an existing session ([#374](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/374)), fetched `DoNotDelete`,
  on the stated understanding that a client which already had a message "simply
  sees it again and deletes it as usual". So a document these services have
  already executed arrives again as routine traffic, not as an attack.

  Neither service kept a record of what it had run. The VTC's spine checks expiry
  and the recipient binding and nothing else; room-host checks the document's
  proof. None of those catch a redelivery, and for the same reason: the second
  copy satisfies them exactly as the first did, because it IS the first document.

  The mechanism is `trust_tasks_rs::ReplayGuard`, already in the stack — the VTA
  has run it since the §7.2 work, and the trust registry has its own claim-and-
  resolve store. Deliberately not a cache of each service's own: the guard is
  digest-keyed, so a DIFFERENT document arriving under an already-spent id is
  `idConflict` rather than silently absorbed as a retry, and it claims before
  dispatch, so two simultaneous deliveries cannot both pass a check-then-act test.

  - vtc-service: claim in `dispatch_trust_task_core`, after the proof check so an
    unauthenticated flood cannot spend another sender's ids — matching where the
    webvh control plane puts its gate. One choke point covers REST, DIDComm and
    TSP, since all three share the spine.
  - room-host: claim around routing, for the consequential tasks only. Reads take
    no record (§7.2's narrow disapplication): they change nothing, and a slot
    spent on one is a slot a write cannot have. The split is listed positively by
    type, so a new task nobody thought about lands on the guarded side.

  Both resolve the claim afterwards: a success records its response, so the
  redelivery this exists to absorb is answered with the original result rather
  than with silence; a failure releases, or a document refused downstream of the
  claim would burn its id and a corrected resend under the same id would come
  back `idConflict` until the record expired.

  Both guards are in-memory and single-process, like the VTA's. A replicated
  deployment needs a shared store behind the same trait — two replicas each hold
  their own map, so a document accepted at one is `Fresh` at the other.

  Retention is computed from the document's own `expiresAt`, with a fallback
  window for one that carries none. It is retention only and must not become an
  acceptance policy: the VTC does not enforce freshness today and turning it on
  here would refuse documents it accepts now.

  Five tests, covering: a redelivered write executed once and answered with the
  original result; a different document reusing an id refused and leaving no
  state behind; and a repeated read still answered every time.

- **rate-limit**: Key the per-IP limiter on trusted-proxy CIDRs, not a global XFF flag ([#1562](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1562))

* fix(rate-limit)!: key the per-IP limiter on trusted-proxy CIDRs, not a global XFF flag

  Replaces the boolean `trust_xff` flag with `trust_xff_cidrs: Vec<CIDR>` (VTA + VTC). The per-IP rate limiter now reads `X-Forwarded-For` only when the request's peer address falls inside an explicit trusted-proxy CIDR allowlist, keying on the rightmost entry.

  Fixes two issues with the old flag: an untrusted peer could forge a leading XFF entry to evade its own limit, and every request behind a trusted proxy shared one bucket — one client's burst could 429 unrelated clients.

  Breaking config change: replace `trust_xff = true/false` with `trust_xff_cidrs = ["<cidr>", ...]`.

- **proof**: A verification method's key type is read, not assumed ([#1528](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1528))

`TrustTaskVmResolver` ended both of its resolution paths with

      Ok(ResolvedKey::new(KeyType::Ed25519, bytes))

  regardless of what the DID document declared. That was never wrong, because
  every key this stack minted was Ed25519 — and it stops being true the moment a
  DID carries an ML-DSA key.

  The failure it produces is the bad kind. A PQC key is not rejected: it is
  extracted successfully and handed to the verifier **labelled Ed25519**, so
  "this proof uses a suite I must check differently" presents as "this Ed25519
  signature does not verify". That points an investigator at the signature, which
  is fine, rather than at the key, which is not. A hardcoded type cannot be wrong
  in a way anyone notices until it is wrong in a way nobody can debug.

  `get_public_key_bytes` cannot answer the question — it decodes the multikey and
  returns the payload, dropping the prefix that names the algorithm — so
  `declared_key_type` reads the `publicKeyMultibase` and matches its multicodec
  prefix against `KeyType::multicodec_public()`. That is this workspace's single
  codec table (VTI#1502), pinned against a named revision of the multicodec
  registry by affinidi-tdk-rs#798, so a wrong prefix is wrong in exactly one
  place and a test already says so.

  The match has no wildcard, deliberately. `#[non_exhaustive]` binds other
  crates, not the one defining the type, and this module is inside it — so adding
  a `KeyType` variant breaks this match on purpose, and whoever adds a key type
  is made to say how a verifier should read it rather than having it fall to a
  default. Defaulting is what caused this.

  ## The VTC half is a message, not a check

  `resolve_verifying_key`'s `[u8; 32]` coercion stays: that path builds an
  Ed25519 `VerifyingKey` and nothing else will do. What changed is what it says.

  "key is not 32 bytes" names the symptom and hides the cause. The realistic way
  to reach it is a verification method carrying a post-quantum key — ML-DSA-44 is
  1312 bytes, ML-DSA-65 is 1952 — and an operator reading "not 32 bytes" has
  every reason to suspect a truncated or corrupt key and none to suspect the
  algorithm. It now reports the actual length, names the likely algorithm, and
  says which path refused it.

- **vtc**: Say which limiter refused on every VTC 429 ([#1514](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1514))

An operator refused with a bare 429 could not tell whether the VTC, a VTA, a
  mediator, a DID host or a proxy in front of any of them had done it. Every 429
  the VTC's own limiters emit now carries the ecosystem attribution contract:
  `x-rate-limit-source: vtc`, `Retry-After: <seconds>` (never 0), and an
  `application/json` body
  `{"error":"rate_limited","limiter":"<name>","message":"...","retryAfterSecs":N}`.
  The header name comes from `vta_sdk::rate_limit::SOURCE_HEADER` ([#1511](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1511)), and
  tests read each refusal back through `VtaError::rate_limited_from_http` as
  `RateLimitSource::Vtc`, so server and client cannot drift.

  Limiters covered:

  - `unauth`: the per-IP tower-governor on the unauthenticated chain (auth,
    wallet auth, passkey login, install claim start/finish, recognise,
    relationships publish, POST /v1/trust-tasks). Reshaped with a governor
    error handler; key-extraction failures keep their 500.
  - `relationships`: the per-member publish window. It used to refuse with a
    400 `AppError::Validation`; it now returns a 429 whose Retry-After is when
    the oldest counted publication leaves the window.

  There are no other request limiters in vtc-service; the install claim secret
  relies on the unauth governor. Neither limiter is on the DIDComm/TSP dispatch
  path, and the Trust Task framework defines no rate-limit error code, so no
  Trust Task error document reports one.

  Also corrects prose calling the governor "5 rps": `per_second(5)` is a
  replenishment interval (a burst of 10, then one request per 5 s).

  The publish route documents the 429 with a `RateLimitedBody` schema, so the
  OpenAPI snapshot and the generated admin-ui wire types are regenerated.

- **tsp**: Every client seals Trust Tasks in the binding envelope ([#1488](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1488))

#1478 gave the VTA's TSP receiver the published `trust-tasks-tsp` binding and
  cut the browser wallet over with it. Every Rust client kept sealing the bare
  document, so the VTA refused all of them:

      refused a TSP frame that is not a binding envelope
        reason=TSP payload is not a `…/binding/tsp/0.1/envelope` envelope
               (got `…/spec/messaging/ping/0.1`)

  A TSP trust ping, and `keys/export-secret/0.1` from openvtc, are the two that
  were reported; the cause is one missing call, in the send funnels every TSP
  client in this workspace goes through — `TspSession::send_document` (so
  `announce`, `request`, and the mobile approver), `DIDCommSession::
  send_tsp_document` (so `request_tsp`, so every `VtaClient` trust task on TSP),
  and the two `TspPingSession` probes behind `pnm health`.

  ## The binding is now one module, not one per crate

- **vtc-admin-ui**: The flow chart grows downwards, so it fits the panel it lives in ([#1473](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1473))

Reported from a live console: the chart renders into a tangle. Two causes, both
  mine from #1472.

  **A column per depth, in the narrow half of the layout.** The decision policy
  sits in the right-hand panel, about 600px wide. The chart gave each level of the
  tree its own 250px column, so the join policy — four questions deep once vetting
  is not required — wanted a thousand, and its endings ran off the edge. Depth is
  now an indent of 26px and each node owns a row, so the width is fixed and it is
  the height that grows. A panel can give height.

  **Nothing cut a label to its box.** "…and the requirements also demand an
  invitation" is three times the width of the box it was drawn in, so it ran
  across whatever sat beside it, and the branch labels did the same to the boxes
  below them. Labels are now cut to the box they are in, with the whole text kept
  in a `<title>` so nothing is lost — the tooltip is the reason truncating is
  acceptable rather than a second way to mislead.

  One row per node is what makes overlap impossible rather than unlikely: nothing
  is positioned relative to another node's text. A test asserts it directly —
  every box inside the viewBox, no two boxes sharing vertical space — because
  "looks right on my screen" is what shipped this.

  Also drops the 620px floor the chart had, which is what turned the overflow into
  a horizontal scrollbar rather than a visible mistake.

- **admin-ui**: Pin js-yaml past the merge-key advisory ([#1384](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1384))

Dependabot has been reporting one **high** on this repository's default branch
  for a while. It is `js-yaml` 4.3.1 in `vtc-service/admin-ui` —
  `maxTotalMergeKeys` does not limit CPU use for empty merge sources, fixed in
  4.3.2.

  Worth being accurate about the actual exposure rather than repeating the label.
  It is a **dev** dependency, reached only through `@redocly/openapi-core`, and it
  is not in the shipped bundle. The vulnerability is CPU exhaustion while parsing
  hostile YAML, and the only YAML that parser sees is this repository's own
  OpenAPI description. So the real risk here is low.

  The reason to fix it anyway is not the vulnerability. A standing "1 high" on the
  default branch is a banner on every push, and a banner that is always there is
  one nobody reads — including on the day it means something. The cost of clearing
  it is three lines.

  Done with an `overrides` entry rather than `npm install --save-dev`, which is
  what the obvious command does and which would have been wrong: this package does
  not use `js-yaml` and declaring it a direct dependency would say that it does.
  `overrides` is the mechanism for constraining something a dependency pulls in,
  and is what the plugin repo already uses to hold `@swc/core` below a version
  that breaks its bundler.

  `npm ci` and `npm run build` both clean.

- **rooms**: A listing pages honestly, or a short page means nothing ([#1380](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1380))

`rooms/records/list/0.1` has `cursor` on its request and its response — "present
  when more records remain" — and this implementation had it on neither. Both
  halves of that were defects, and they were symmetrical:

  - `limit` was applied with `take` and the remainder dropped **without a word**,
    so a short page and a complete room were the same bytes. That is worse than
    not paginating: a caller cannot tell the two apart, and every client that
    "worked" was one that had not met a big enough room yet.
  - `ListRecordsBody` is `deny_unknown_fields`, so a conforming client that *did*
    page had its second page refused as malformed. A host that never issued a
    cursor and could not have accepted one back.

  It matters beyond conformance. `rooms/keys/browse` (tt#426) checks a listing's
  length against the `recordCount` its host committed to — the one verification a
  listing can do with no anchor and no second party — and against a silently
  truncating host that check reports `short` on every room past a page.

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

- **vtc**: Sign success responses — 265 specs require it and none got one ([#1334](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1334))

SPEC §7.3 item 7 says a specification declaring a single
  `proofRequirement: REQUIRED` binds its *response* as well as its request:
  "where a specification declares no requirement for the response, the
  request's applies to it, so an omission can never weaken a variant." 265
  published specifications declare exactly that. Only 10 use the per-variant
  form that could relax it.

  This service attached a proof to none of them. `success_response` built the
  document with `respond_with` and serialised it; nothing signed anything on
  the way out.

  Nothing went red because **no consumer verifies one either** — not the SDK,
  not the browser client. Producers not signing and consumers not checking is
  a mutually consistent silence, and it is why this survived a conformance
  ledger, a response-conformance layer that validates every observed body
  against its published schema, and 35 integration binaries. The response
  layer checks the payload's shape; the proof is on the envelope.

  What it cost: no answer this community has ever given is evidence of
  anything. A member cannot show a third party what the host told them, and
  cannot be contradicted when they misreport it. That is the general form of
  the gap `data-rooms-verified-reads.md` §4.1 found from one direction — it
  described the unsigned put acknowledgement as a rooms problem, and it is not
  a rooms problem.

  Signed at the spine rather than at each `success_response`. There are
  twenty-one call sites; signing is the same decision taken twenty-one times,
  and forgetting once is a task whose response is unattributable with nothing
  downstream to notice — which is how every response came to be unsigned in
  the first place. The spine is where the framework's inbound checks already
  live.

  Success responses only. An error response's `type` resolves to
  `trust-task-error`, whose own requirement is RECOMMENDED rather than
  REQUIRED, and whose variant §7.3 makes undeclarable by a task. Signing those
  is a separate decision with its own rationale (a retained compliance refusal
  is the case for it) and is not smuggled in here.

  A community with no signer answers unsigned rather than failing: it has
  nothing to sign with, and refusing would make an unprovisioned VTC unusable
  rather than merely unattributable.

  The guard is verified non-vacuous — removing the call makes
  `a_success_response_is_signed` fail on a real unsigned challenge response.

  **The VTA half is not in this PR and is owed.** It has the same gap and
  needs a decision this one did not: `load_vta_issuer_secret` writes an audit
  entry per key access, so signing every response through it would drown the
  audit trail. The resident path (`secrets_resolver` + `signing_vm_id`) exists
  but is gated on `didcomm`/`tsp`, and conformance must not depend on feature
  flags — so the fix is a non-gated response signer populated at init.

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

- **rooms**: A room stays readable across a membership change ([#1300](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1300))

Adding or removing one member made every record already in the room fail to
  open — for every member, including the one who wrote it.

  Records are sealed under the MLS exporter for the epoch current when they were
  written, and `SealedRoom::open_record` used the group's *current* key regardless
  of the record's own epoch. Every membership change is a commit and every commit
  advances the epoch, so the first add or remove silently destroyed read access to
  the room's entire contents. The failure surfaced as `DidNotOpen`, which reads
  like corruption rather than like a key the caller no longer has.

  Nothing caught it because every test in the crate sealed and opened inside one
  epoch, and the end-to-end demo never advanced one either.

  # The fix: an epoch key chain

  At each commit the committer seals the outgoing epoch's storage key under the
  incoming one — an `EpochLink`. A holder of the current key walks the chain
  backwards to any retained epoch. Backwards only: a member holding epoch 2's key
  derives nothing at epoch 3, so removal stays forward-only and a removed member
  still reads nothing written after them.

  This is the upper tier of the retention system in the Encrypted Spaces
  architecture whitepaper (§4.2), linearised — we have no directory hierarchy for
  a lower tier to align to.

  Links are ciphertext, so a host stores them and learns only that an epoch
  happened, which `Room.epoch` already told it.

  # What it costs, and why it is a policy

  Post-compromise security for record content: once the chain exists, a
  compromised current key reaches every retained epoch. MLS's own PCS is
  untouched — a compromised leaf still heals at the next commit — but the storage
  layer above it no longer inherits that healing. That is the trade a library
  makes and a message stream does not, so it is `RetentionPolicy::{Chained,
  FromJoin}`, fixed at creation beside `visibility`.

  `Chained` is what every host creates. `FromJoin` is the old behaviour kept
  deliberately, and deserialising defaults to it — a room stored before this
  change genuinely has no links, and no policy field can conjure keys that were
  never sealed.

  # Cryptographic deletion

- **admin-ui**: Regenerate the API document that #1282 moved ([#1287](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1287))

`PolicyPurpose` gained `rooms`, and neither `admin-ui/openapi.json` nor the
  `wire.ts` it generates was regenerated with it. The snapshot test has been
  failing on main since — so has every PR opened against it.

  Nothing but the two generated files changes here. The console was typed against
  an API the daemon no longer serves, which is the exact condition the snapshot
  test exists to catch and the one that says nothing on its own: the generated
  types typecheck against themselves either way.

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

- **vtc-service**: Stop build.rs writing to the source tree, so cargo build is a no-op ([#1254](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1254))

* fix(vtc-service): stop build.rs writing to the source tree, so cargo build is a no-op

  `cargo build -p vtc-service` was never a no-op. Two consecutive builds
  with nothing touched in between both recompiled the crate, so every
  local build, test, clippy run and rust-analyzer check-on-save paid for
  it. Cold-cache CI never builds the same tree twice, which is why it went
  unnoticed. `admin-ui` is a default feature, so the plain build reproduces
  it.

  Both causes are `build.rs` writing into the source tree, which is exactly
  what the Cargo build-script docs say not to do — what a script writes
  there feeds the next build's staleness check.

  `npm install` rewrites `admin-ui/package-lock.json`: identical bytes, new
  mtime, so `git status` stays clean and nothing looks wrong. But the
  lockfile is one of the script's own `rerun-if-changed` inputs, so the
  script was dirty the instant it finished and re-ran on every build. Of
  the six watched paths it is the only one npm moves, which makes it the
  whole pump.

  `npm run build` then regenerated `admin-ui/dist`, and `include_dir!`
  expands to one `include_bytes!` per file, so all 78 of them are compile
  inputs of the lib (312 entries across `vtc_service-*.d`). Each re-run
  refreshed their mtimes and turned a cheap script re-run into a full
  recompile.

- **vtc**: Tell a member which side is out of date, not just that the verb is unknown ([#1223](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1223))

The VTC half of #1220, which fixed this on the VTA after an operator spent an
  hour reading

      unsupported type: https://trusttasks.org/spec/provision/integration/0.3

  as "this agent cannot provision" when it meant "this agent is older than your
  client". The VTC's dispatcher had the identical shape: an unrouted URI got
  `RejectReason::UnsupportedType` and nothing else, while the answer sat in the
  `DISPATCHED_URIS` const declared thirty lines below the match that had just
  failed.

  The VTC is more exposed to that misreading, not less. Its `spec/vtc/*` families
  are mid-migration, so a member client and a community can legitimately sit at
  different versions of the same verb — and `DISPATCHED_URIS` is also exactly
  what is reachable over TSP, where a rejection is all the member gets.

  A URI whose family this VTC does dispatch is now `unsupportedVersion` — SPEC's
  code for exactly this, "the consumer recognizes the type but not at this
  MAJOR.MINOR" — naming the versions served in `message` and in
  `details.servedVersions`. Anything else stays `unsupportedType`. Both carry
  `details.requestedType`, because the framework puts the rejected URI only in
  prose and a client should not have to slice a sentence to recover it. The keys
  come from `vta_sdk::protocols::trust_task_reject_details`, so the VTC spells
  them the way the VTA does and the way the SDK reads them.

  The hint is derived from `DISPATCHED_URIS` rather than a hand-kept list, and a
  test asserts every version offered shares the requested family: pointing a
  client at `join-requests/status` because it asked for `join-requests/submit`
  would send it at a verb that cannot serve its request. That const is no longer
  `#[cfg_attr(not(test), allow(dead_code))]` — it answers a rejection now, not
  only a parity test.

  `reject_with_code` and `bound_details` arrive with it. `RejectReason` carries
  `details` on `TaskFailed` alone, so a rejection under any other standard code
  had no way to attach machine-readable data; and this is the first VTC site to
  emit `details` at all, so the framework's bound (4096 JCS bytes, 16 members)
  had nowhere to live. Both are deliberate twins of `vta-service`'s — the bound
  is a framework rule rather than a per-service policy, so the two must not drift
  into different ideas of how much a rejection may carry.

  `bound_details` also now runs inside `reject_with`, which makes it the funnel
  every `RejectReason`-shaped rejection passes through rather than something each
  future construction site has to remember.

  Both members of this particular `details` are bounded by construction —
  `servedVersions` comes from a const of seven, `requestedType` echoes a
  `TypeUri` the framework already parsed and already puts in `message` — but they
  go through the bound anyway, because "bounded by construction" is a property of
  today's callers, not of the funnel.

- **vtc-admin**: Let the wallet choose the identity, instead of reading the vault ([#1212](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1212))

Proxy sign-in began by asking the wallet to enumerate every vault entry
  pinned to this VTC, so it could find one:

      vaultList({ targetDid, secretKind: "didSelfIssued" })

  Two problems, and the second is the one operators hit. It is a
  disclosure of the operator's vault to answer a question about a single
  entry — and it costs its own consent prompt to make. And on a wallet
  with nothing pinned here it returns an empty array, at which point the
  page gave up with "No did-self-issued vault entry is pinned to this VTC.
  Open the wallet, add an entry targeting this VTC's DID, then retry" —
  a setup step in another application, quoted at someone who was trying to
  sign in.

  The wallet now owns that question. `walletProfile({ target })` resolves
  the entry bound to this origin, or asks the operator which identity to
  use and remembers the answer, and returns the persona DID with the entry
  id. It mints nothing.

      const { did, entryId } = await walletProfile({ target });
      const { challenge } = await POST /auth/challenge { did };
      await proxyLogin({ entryId, nonce: challenge, target });

  The DID has to be known before the challenge, because `handle_challenge`
  binds the nonce to it — which is why this is two calls and not one, and
  why `proxyLogin` alone could never have reached it.

  Round trips are unchanged: the profile call replaces the vault listing
  one for one, and passing `entryId` back means `proxyLogin` does not
  repeat the lookup. One fewer consent prompt in the steady state.

  **A first sign-in now says which DID needs admitting.** The persona was
  created a moment ago, so this VTC has never seen it and `handle_challenge`
  refuses on the ACL gate — a 403 an operator cannot act on. `bound: true`
  tells us this was the first time, so the message names the DID and the
  `vtc admin invite --did …` that fixes it.

  **Choosing among several identities is kept, as an explicit action.** An
  operator may hold both an Admin and a member persona here, and the
  wallet returns the one bound to this origin. "Sign in as a different
  identity…" still runs the old enumeration — behind a click, because
  reaching it discloses the vault to this page. It is also the only proxy
  route on a wallet build that predates `walletProfile`, which is what
  `isWalletProfileAvailable()` distinguishes: a capability probe that
  produces an accurate message, not a compatibility fold.

  `loginWithWalletProxy` now delegates to a shared `runProxySiop`, so the
  wallet-resolved and hand-picked paths apply exactly the same rule.

  Requires OpenVTC/vta-browser-plugin#145. `proxyLogin` and `vaultList`
  are untouched there, so this can land in either order — the button
  degrades to the picker until the wallet ships.

- **vtc**: Point the admin UI at relationships/graph/0.2 ([#1211](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1211))

The Relationships page could only ever render "Could not load the
  relationships graph."

  #1112 retargeted the mount to the 0.2 task from
  trustoverip/dtgwg-trust-tasks-tf#266 and left the admin console's copy of the
  URI on 0.1. Every VTC route matches its `Trust-Task` header exactly, so the
  request was rejected 415 before the handler ran and React Query rendered its
  error card. The graph endpoint itself was never reached and is fine.

  The console is the router's only in-repo REST client and nothing paired the
  two. The existing census asks whether a bound URI exists upstream, which
  `graph/0.1` does — it is a real published task, just not the one the service
  mounts. The generated wire types cannot help either: utoipa does not put the
  Trust-Task value in the OpenAPI document (the `graph` operation comes out as
  `header?: never`), so the URI is hand-copied on both sides in two languages.

  So the fix is one character and the guard is the change. Every
  `trusttasks.org/spec/` literal in the SPA must appear in `routes/mod.rs`,
  which is the sole binding site — scanning it rather than all of `src/` stops a
  URI mentioned in a test fixture from vouching for a route that binds a
  different one. No exception table: a header no route enforces is not a case to
  document, it is a dead page. Both scans assert a floor, because a directory
  move would empty them and pass the difference vacuously.

  Verified the guard fails on the pre-fix tree, naming the URI and the fix.

- **vtc**: Surface the daemon's message when wallet sign-in fails ([#1208](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1208))

The admin console's VTA-proxied SIOP login threw on the status code alone
  — `/auth/challenge failed (403)` — and discarded the response body, which
  is where the daemon says what actually went wrong. `Login.tsx` renders that
  message verbatim in the sign-in error card, so the operator got a number
  and nothing else.

  403 is the ambiguous one. `handle_challenge`'s second gate is `check_acl`,
  and `resolve_auth_role` answers it three different ways: the DID has no ACL
  row, the row has expired, or the row's role is not `Admin`
  (`Moderator`/`Issuer`/`Member`/`Custom` all fail closed there). The
  distinction exists only in the body, so diagnosing a failed sign-in meant
  reading the daemon log — or the source.

  The message extraction `request()` already did privately is now
  `daemonErrorMessage()`, exported from `lib/api.ts` and used by both. The
  wallet path cannot route through `request()` itself: it deliberately uses
  raw `fetch` so it sends no `X-CSRF-Token` and does not fire
  `vtc-session-expired` mid-ceremony. Sharing the helper keeps one
  implementation of the `{ error | message }` shape rather than a second copy
  that can drift from `AppError`.

  The messages stay as terse as they were on the unauthenticated path — this
  forwards what the daemon already chose to say (P0.16 keeps it free of role
  names and serde internals), it does not widen it.

  An operator now reads:

      /auth/challenge failed (403): forbidden: DID not in ACL: did:key:z...

- **vtc**: Remove a member whose ACL entry is already gone ([#1196](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1196))

`remove_inner` read the ACL entry first and returned `404 member not found`
  without one. That closed the only exit from the exact state an `acl/revoke`
  aimed at a member leaves behind: a live member row, no authorization, and
  membership credentials still unrevoked.

  The operator was told the member did not exist while `members list` was warning
  about that very row on every call — two surfaces disagreeing about whether
  somebody is here. #1194 stops new instances of that state being created; this
  is how the existing ones get cleaned up, and it is the difference between the
  leave ceremony (which tombstones the row *and* flips the revocation bit on the
  member's VMC and VEC) and a purge, which does neither.

  Removal needs a subject, not specifically an ACL entry. Only genuinely absent —
  neither row — is still `not found`.

  Two details worth stating, because both could have gone the other way:

  The subject's role defaults to `member` when there is no entry. Role *is* the
  ACL entry, so a subject without one holds no authority: they cannot be the
  admin the removal policy protects, and `depart`'s no-last-admin invariant reads
  the same absent row and reaches the same conclusion. Nothing is being assumed
  in the permissive direction.

  The audit row records `prior_role: None` rather than `member`. There was no
  role. Writing one in would assert an authority the community had already taken
  away, into the tamper-evident log, which is the last place to put a convenient
  fiction.

- **vtc**: Refuse an ACL revoke that would orphan a member row ([#1194](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1194))

`DELETE /v1/acl/{did}` deleted the ACL entry and stopped. Aimed at a member,
  that leaves a live member row with no authorization — and membership
  credentials that still verify for anyone holding them.

  It is how a real community reached that state. The audit trail for one member
  reads: JoinRequestSubmitted, JoinRequestApproved, MemberAdded, VmcIssued,
  VecIssued on 16 Aug — then AclRevoked on 29 Aug, and no MemberRemoved, ever.
  Every members-list call since has logged "member row has no matching ACL entry;
  skipping in list response".

  Two surfaces own the ACL row and only one of them knows membership exists. The
  leave ceremony (`DELETE /v1/members/{did}` -> `ceremony::execute::depart`)
  deletes the ACL, tombstones the member row, *and* flips the revocation bit on
  the member's VMC and VEC. This route did the first of those three.

  The reader had already decided this could not happen: `members::read` calls a
  live member row with no ACL entry "genuine out-of-band corruption (e.g. an
  interrupted purge)" and warns. It was not corruption. It was this route doing
  exactly what it was asked, on a DID it could see was a member — the audit row
  it writes even records `priorRole: "member"`. A writer that produces a state
  its reader calls impossible is the defect, not the operator.

  Revoking a live member's entry is now refused with the command that actually
  removes a member, per the workspace's "operator errors should suggest the fix"
  convention. Refused rather than quietly routed into `depart`: removal runs the
  removal policy, resolves a disposition and revokes credentials, and an operator
  who asked to revoke an ACL entry should not get all of that without saying so.

  The guard sits after the scope-reduction branch has returned. Reduction leaves
  the entry in place and orphans nothing, so blocking it would break an ordinary
  privilege reduction on every member in the community. A departed (tombstoned /
  historical) row does not block either — clearing a stray ACL entry beside one
  is legitimate cleanup.

  Not fixed here, and worth knowing: an already-orphaned row cannot be cleared
  through the leave ceremony, because `remove_inner` looks the ACL entry up first
  and 404s without one. `DELETE /v1/members/{did}/purge` is the way out —
  `purge_member` only refuses when neither row exists.

- **vtc**: An admin with no passkeys has an empty list, not a missing one ([#1189](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1189))

Reported from the console: "My passkeys" showed a red **FAILED TO LOAD
  PASSKEYS — not found: no admin entry for caller**, directly above its own,
  correct, "No passkeys registered" empty state. One page disagreeing with
  itself about whether anything had gone wrong.

  Nothing had. `AdminEntry` lives in `passkey_ks` keyed by DID and records a
  passkey *enrolment* — it is not the ACL entry. An operator who signs in with
  their VTA wallet (SIOP, `/auth/admin-session`) holds an admin ACL role and no
  enrolment, which is an entirely ordinary state, and this page is the first
  place they land. `GET /admin/passkeys` answered 404 for it.

  An empty collection is not a missing resource, so it now answers `200
  {"credentials": []}`. `revoke` keeps its 404: that one names a credential
  which must exist.

  ## The button was worse than the error

  `register/start` challenges an existing credential for a step-up UV before
  issuing a new one, so it cannot mint the *first* passkey — it answers 404 too.
  The only path that creates a `PasskeyUser` from nothing is the install-URL
  claim (`install.rs:313`).

  So the page offered "Register new passkey" to precisely the operators for whom
  it could not work, on the page whose entire purpose is to tell them how to get
  one. The button is now hidden until at least one passkey exists, and the empty
  state names the real next step — an install URL, minted on the host with
  `vtc admin invite --did <their-did>`.

  Deliberately *not* fixed by letting `register/start` skip the UV when the
  caller has none: that would make any admin session sufficient to mint a
  passkey with no second factor, putting wallet DID-auth and passkey auth on
  equal footing for enrolment. Keeping "adding a credential requires holding
  one" is worth an out-of-band step.

  ## Coverage

  `list_is_empty_for_an_admin_with_no_passkeys` builds the wallet-sign-in shape
  directly — an ACL admin with no `AdminEntry` — and asserts 200 with a present,
  empty `credentials`. It was checked against the old handler and fails there
  with `left: 404, right: 200`.

  Nothing pinned the 404, which is how it reached an operator. The three `list`
  tests covered the enrolled admin, the wrong role, and no token; the state an
  unenrolled admin is actually in was the one case missing.

  ## Regenerated artefacts

  The response annotation lost its 404, so `admin-ui/openapi.json` and
  `src/lib/wire.ts` are regenerated. #1188's snapshot gate caught the staleness
  before this commit existed, which is the chain working on its first real
  change after landing.

- **vtc-admin-ui**: Read the response shapes the daemon actually sends ([#1186](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1186))

The console was reading five endpoints at shapes the daemon stopped sending.
  Reported as a crash on load, `Cannot read properties of undefined (reading
  'startsWith')` — `shortenDid(whoami.did)` on a `did` that moved. Sweeping the
  ~35 endpoints the SPA calls against their Rust response types found five more
  of the same defect, from three earlier PRs in the same conformance programme.

  Two of them were the console's only two ways in.

  - **`auth/whoami`** ([#1112](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1112)) went flat → `{session:{id,subject,…},roles,scopes}`.
    `App.tsx:159` reads `role === "admin"`, which short-circuits to `false` on
    `undefined` and so hides the failure until `shortenDid` dereferences the DID
    two components later. Fixed in `api.ts` (`WhoamiResponse` + a `SessionView`),
    `App.tsx` and `sessions.tsx`.
  - **`auth/passkey/login/start/0.2`** ([#1112](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1112)) dropped webauthn-rs's
    `{publicKey: …}` wrapper for the inner options. `myPasskeys.tsx` moved with
    it; `Login.tsx` and `members.tsx` did not, so **passkey sign-in and the
    step-up behind admin promotion both threw** in `decodePublicKeyOptions`.
  - **`members/removed`** ([#1082](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1082)) array → `{removed: […]}`. `RemovedMembers`
    does `query.data ?? []` then `rows.map`, so the Members page died with
    `rows.map is not a function` rather than rendering an empty section.
  - **`members/show`** and **`join-requests/show`** ([#1093](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1093)) bare row →
    `{member: …}` / `{request: …}`. Detail views rendered every field blank,
    and the join-request Approve/Reject block never appeared because
    `status === "pending"` is false on `undefined`.
  - **`acl/grant`** ([#1109](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1109)) → `{entry: …}`, so a successful grant toasted
    "Created ACL entry for undefined".

  Each envelope is unwrapped at the fetch seam, leaving the rendering code
  reading a flat row — the shape `profile.tsx` already uses, which is the one
  consumer that moved correctly ([#1094](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1094)). Every changed interface carries a
  comment naming the PR that moved the wire.

  Two stale types with no runtime effect are corrected in passing:
  `DecideResponse` described `{request, member, vmc, roleVec}` where
  `decide/0.1` answers `{requestId, status, vmc?, roleVec?}` (the call sites
  only invalidate, so nothing read it), and three `total_estimate` fields left
  snake_case after #1078 recased the pagination wrapper to `totalEstimate`.

  Also swept and found clean, so the next reader need not repeat it: audit, ACL
  list, admin invites, admin passkeys, community profile, members list,
  join-requests list, policies (list/active/upsert/test), diagnostics,
  invitations, relationships graph, recognition check, ceremonies, the install
  claim ceremony (`ClaimStartResponse` still types webauthn-rs's
  `CreationChallengeResponse`, so its `{publicKey: …}` is correct), the wallet
  SIOP login, `plugins.json` and build-info. Every request body matched too,
  including the four `deny_unknown_fields` ones — this defect class is
  response-shaped.

  No test would have caught any of it. `tsc` checks the SPA against its own
  hand-written interfaces, so a stale interface typechecks, builds and ships;
  the response-conformance witness checks the daemon. Nothing checks the pair,
  which is how four consecutive breaking response PRs each left the console a
  little more broken behind entirely green gates. Generating these types from
  the OpenAPI document the service already emits would close it; until then,
  a `vtc-service` response change wants a grep of `admin-ui/src` for the path.

- **vtc**: Gate the fail-closed backend tests on the feature being absent ([#1162](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1162))

Eight `keys::seed_store` tests assert that a secret backend which is *not
  compiled* fails closed when its config field is set. Left ungated they were
  not merely redundant under `--all-features` — they were guaranteed to fail:
  with the feature compiled, `create_secret_store` correctly returns a store,
  and the test reads that as "did the feature leak on?".

  So `cargo test -p vtc-service --all-features` has been eight-red on every
  run, which is the sort of standing failure that teaches people to skip the
  feature matrix entirely — and the matrix is exactly where a fail-closed
  guard needs checking.

  Each test now carries `#[cfg(not(feature = ...))]` for its own backend,
  matching the `#[cfg(feature = "vault-secrets")]` already on the compiled-side
  counterpart below it. The gate is per-backend rather than one blanket
  `not(any(...))`: under `--features aws-secrets` only the aws case becomes
  unaskable, and the other five still have something to prove.

  Both builds are now green: 12 pass on default features, 5 under
  `--all-features`, and `cargo test -p vtc-service --all-features` no longer
  reports failures.

- **sdk**: Give every authenticated client its identity, and adopt provision/integration 0.3 ([#1147](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1147))

#1146 made every producer sign, and left seven production paths building
  clients that cannot. Each authenticates, takes the token, and drops the DID and
  key on the floor — so every task they dispatch is refused for a missing
  `recipient` and `proof`. `SessionStore::connect` was fixed; nothing else was,
  because no test drives those paths against an enforcing VTA.

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

- **vtc**: Hex digests, and five ways round the extension slot ([#1110](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1110))

* fix(vtc): an invalid ext key, and three acl responses missing their envelope

  Two classes from #1107's inventory, both in the shared task families the
  conformance table's census deliberately excludes. 134 → 68 violations.

  `policy/*` emitted an `ext` key of `org.openvtc.authorDid`. SPEC §4.5.1
  constrains every immediate `ext` key to `^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$`, so
  the capital D made the key invalid — a framework violation rather than a style
  preference, and the only one of five `org.openvtc.*` keys in the workspace that
  failed. Renamed `author-did`, matching `match-code` and `step-up`.

  `acl/grant`, `acl/show` and `acl/change-role` returned a bare row where all
  three schemas require `{entry: …}`. The rows always conformed; only the wrapper
  was missing.

  These survived longer for a structural reason: the shared
  `spec/{acl,audit,auth,config,policy}/*` families are outside the witness
  census — a stated limit, since both daemons serve them — so no fixture ever
  described these responses and nothing could have caught it. The
  response-conformance layer needed neither a census nor a canonical-shape
  decision to observe the divergence. Acting on the remaining shared-family
  violations still needs that decision; a missing required envelope did not,
  being wrong under any reading.

- **vtc**: An invalid ext key, and three acl responses missing their envelope ([#1109](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1109))

Two classes from #1107's inventory, both in the shared task families the
  conformance table's census deliberately excludes. 134 → 68 violations.

  `policy/*` emitted an `ext` key of `org.openvtc.authorDid`. SPEC §4.5.1
  constrains every immediate `ext` key to `^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$`, so
  the capital D made the key invalid — a framework violation rather than a style
  preference, and the only one of five `org.openvtc.*` keys in the workspace that
  failed. Renamed `author-did`, matching `match-code` and `step-up`.

  `acl/grant`, `acl/show` and `acl/change-role` returned a bare row where all
  three schemas require `{entry: …}`. The rows always conformed; only the wrapper
  was missing.

  These survived longer for a structural reason: the shared
  `spec/{acl,audit,auth,config,policy}/*` families are outside the witness
  census — a stated limit, since both daemons serve them — so no fixture ever
  described these responses and nothing could have caught it. The
  response-conformance layer needed neither a census nor a canonical-shape
  decision to observe the divergence. Acting on the remaining shared-family
  violations still needs that decision; a missing required envelope did not,
  being wrong under any reading.

- **vtc**: A null, and a revoke replying under the wrong task ([#1108](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1108))

Three of the five VTC-family violations #1107's response layer found on real
  handler output. The remaining two point at the specification rather than this
  service, and are described at the end rather than guessed at.

  ## `join-requests` sent `extensions: null`

  `JoinRequest.extensions` is `JsonValue` with `#[serde(default)]` and no
  `skip_serializing_if`, so a request with no extensions serialised `null`. The
  canonical component types it `object` and does not require it, so absent is how
  "none" is spelled and `null` is a type error — the same shape as
  `policyDecision` in #1099, and the third member of this family to have it.

  ## `personhood/revoke` replied under the *assert* task

  This is the substantial one, and it was not a serialisation slip.

  `POST` and `DELETE` shared one mount, with a comment saying the collapse was
  "pending per-method selectors". **That workaround had outlived its reason.**
  `task_routes` has supported one task per verb on a shared path since
  `per_method_tasks_on_one_path_are_enforced_independently` landed in
  `vti_common::trust_task::openapi`, and registering the path twice merges the
  OpenAPI operations rather than overwriting them — which is what
  `per_method_split_keeps_both_operations_in_the_spec` exists to prove.

  The consequence was real. A revoke response went out labelled
  `members/personhood/assert/0.1`, so a client was told the wrong task for the
  document it received — and the response could not satisfy the schema it
  claimed: assert requires `personhood: const true` plus `vmc` and `roleVec`,
  while a revoke legitimately sends `false` with neither.

  `members/personhood/revoke/0.1` has been published upstream the whole time, and
  its shape matches `RevokeResponse` exactly: `personhood: const false`, both
  credentials optional. Each verb now carries its own task.

  ### The witness knew, and that is the point

  The assert entry's own comment said the DELETE answered under that URI with the
  wrong shape, and called it "a shared-mount workaround, not a conformance defect
  of this URI, so the witness carries the POST."

  Every clause of that is true. It is also how the defect survived: the witness
  was told to look at the POST, so nothing in the table ever saw the DELETE, and
  a fixture cannot notice a response it was instructed not to examine. The
  response layer had no such instruction — it validated whatever the handler
  actually sent.

  An honest note about a known gap is still a gap. This is the fourth time this
  week the table's prose described something accurately and nothing acted on it.

  ## The census caught the follow-on

  Binding a newly published URI made
  `every_bound_published_uri_has_a_witness` fail, exactly as designed —
  `personhood/revoke/0.1` had no entry. Added as `checked!`; the table is now 59
  tasks, drift still 0.

  ## Not fixed here

  Two remain, and both look like the **specification** being stale rather than
  this service being wrong — which is the question this repository has now got
  backwards three times, so I am not guessing:

  - **`relationships/list`** sends `vrcDigestMultibase`; the schema requires
    `vrcSha256`. Multibase-wrapped multihash was a deliberate decision taken in
    this workspace; the service moved and the published schema never followed.
  - **`relationships/graph`** returns `complete` / `endpoints` / `halves` — a
    materially richer shape than the schema's flat `id` / `issuerDid` /
    `subjectDid` / `createdAt`.

  Both want an upstream `0.2` if the service's shape is the intended one, and
  someone who knows the graph design should confirm that before a spec change is
  proposed for it.

  The eighteen shared-family tasks (`acl`, `audit`, `auth/passkey`, `policy`)
  also remain, still pending the canonical-shape decision the witness header
  names. One of those is worth surfacing early because it is a framework
  violation rather than a shape mismatch: `policy/upsert` emits an `ext` key of
  `org.openvtc.authorDid`, which fails the reverse-DNS namespace pattern in
  SPEC §4.5.1 — the structure belongs *inside* `org.openvtc`, not flattened into
  the key.

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test -p vtc-service --no-fail-fast`
  - `cargo fmt --all --check`

- **vtc**: A false green, and the fixture that caused it ([#1100](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1100))

Stacked on #1099.

  **#1097 promoted `config/export` and `config/import` to `checked!` on a
  fixture that understated what the service sends.** Both routes are
  non-conformant and were reported as conforming. Drift **12 → 14**, which is
  the count moving in the honest direction.

  ## The false green

  `community_profile()` was hand-written JSON and omitted `personhood`. The real
  `CommunityProfile` carries it with `#[serde(default)]` and no
  `skip_serializing_if`, so it is on the wire of every profile the service
  sends — and `CommunityProfileSnapshot` is `additionalProperties: false` and
  does not define it. Add the member to the fixture and the entry fails
  immediately:

  ```
  config/export/0.1: response is not canonical: unknown field `personhood`,
  expected one of `communityDid`, `contactEmail`, `createdAt`, `description`,
  `extensions`, `language`, `logoUrl`, `name`, `publicUrl`,
  `relationshipIdentifierDefault`
  ```

  This is the **third** distinct way the hand-written fixtures have misled, and
  the first one that mattered in the dangerous direction:

  | | |
  |---|---|
  | **stale** ([#1095](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1095)) | `endorsements/revoke` described a response the handler had stopped sending six PRs earlier |
  | **inventing** ([#1099](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1099)) | `totalEstimate: 12`, which nothing in the workspace ever sets |
  | **omitting** (here) | `personhood`, absent from the fixture and always present on the wire |

  The first two made the debt look larger than it was. This one made a
  non-conformant route look green, which is the one direction this table must
  never fail in — the whole point of the assertion is that debt can shrink but
  not grow unnoticed, and an understating fixture shrinks it silently.

  ## The fix, and the durable part

  `community_profile()` now constructs the real `CommunityProfile` and
  serialises it, instead of hand-writing the object. The compiler refuses the
  omission: add a member to the struct and this fixture carries it whether or
  not anyone remembers to.

  Both entries go back to `drift!`, naming `personhood` and pointing at
  trustoverip/dtgwg-trust-tasks-tf#261, which adds it to
  `CommunityProfileSnapshot` and to `CommunityProfile`. They close on the
  release carrying it.

  `KNOWN_DRIFT_COUNT`'s header gains the lesson, because it warns about the
  other two failure modes and not this one.

  ## The `communityDid` question, which is not a missing member

  While preparing #261 I was about to add `communityDid` and `createdAt` to
  `CommunityProfile` — the two members the `profile/show` and `profile/update`
  notes have been asking for. The sibling schema says not to:

  > `vtc/_shared/community`'s `CommunityProfile` … is the update-facing view and
  > **deliberately omits `communityDid` so that a patch cannot re-point a
  > community's identity**.

  That is a documented design decision, and adding the member would defeat it.
  The real problem is that `community/profile/show`'s **response** and
  `community/profile/update`'s **payload** share one component that was designed
  for the update: a read needs the DID, an update must refuse it.
  `CommunityProfileSnapshot` already exists as the read-shaped view, with
  `communityDid` required.

  So the fix is a read-shaped view for `show`, not another member on the update
  view — a design question for the working group rather than something to bolt
  on. Both notes now say that instead of asking for the member.

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test -p vtc-service --no-fail-fast`
  - `cargo fmt --all --check`

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

- **vtc**: Issued is a credential receipt, not a timestamp ([#1098](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1098))

**#1096 shipped a defect and I wrote the wrong explanation into the ledger
  alongside it.** This fixes both.

  ## What went wrong

  `Endorsement.issued` is not a timestamp. It is an `IssuedCredential`
  receipt — *"the registry-wide issuance receipt — credentialId, the signed
  VEC, and expiry"*:

  ```
  issued: { credentialId, credential, expiresAt, issuedAt? }   // first three required
  ```

  #1096 read it as "when it was issued" and mapped `createdAt` onto it, so
  every endorsement row has been sending `"issued": "2026-08-23T00:00:00Z"`
  where a required object belongs. That is worse than the shape it replaced:
  the old row did not claim to speak the canonical model, and this one does
  while getting a required member's type wrong.

  Two claims in #1096's description are false as a result:

  - *"`vecId` is unspecced"* — it is `issued.credentialId`.
  - *"the spec's `Endorsement` component has nowhere to put a credential, so
    `vec` stays and the gap goes upstream"* — it is `issued.credential`.
    There was no upstream gap.

  The sweep's original note had said exactly this — *"the spec returns the
  stored row with the credential nested under `issued`"* — and #1096 replaced
  a correct note with a misreading, then recorded the misreading as settled.

  ## The fix

  `issued` becomes an `IssuedCredential`. The mapping the spec actually asks
  for:

  | spec | service |
  |---|---|
  | `issued.credentialId` | `vecId` |
  | `issued.credential` | the signed VEC |
  | `issued.expiresAt` | `validUntil` |
  | `issued.issuedAt` | `createdAt` |

  `issue` holds all four at the moment it replies — it has just minted the
  credential and computed its expiry — so it fills the receipt completely and
  **now conforms outright.** The top-level `vec` sibling is gone; it rides
  inside the receipt, which is where an `additionalProperties: false` response
  could always have accepted it and never could have accepted a sibling.

  `issuerDid` is dropped from the wire. It is the community DID — the same
  value on every row of every listing, derivable from the community profile —
  so it bought nothing and was the last thing keeping `issue` out of
  conformance. The stored row keeps it; it is a real storage optimisation
  there, saving a signer lookup per listing.

  Drift **16 → 15**.

  ## What `list` and `show` still need, and why it is not here

  Both are now blocked on exactly one thing: `credential` and `expiresAt` are
  required by the receipt and **are not on the stored row**. The `Endorsement`
  keyspace holds the `vecId` and the mint time, never the signed VEC or its
  expiry. So those two routes send the handle and `issuedAt` and stop.

  Closing them means storing the credential and its expiry on the row —
  larger rows plus a migration for existing ones. That is a storage decision,
  not a wire fix, and bundling it into this correction would hide it. The
  entries now say so precisely, instead of the old note's claim that an
  upstream change would close them.

  ## How this was found

  Not by re-reading notes. A throwaway probe walked the drift table printing
  the *actual* parse or schema error for every entry, which said
  `invalid type: string "2026-08-23T00:00:00Z", expected struct
  IssuedCredential` — a sentence no amount of re-reading my own prose would
  have produced. The same probe showed `list` / `show` failing on
  `missing field credential`, which is what scoped the storage question above.

  Worth keeping as a habit: the ledger's notes are prose and can be wrong in
  either direction. The schemas are not.

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test -p vtc-service --no-fail-fast`
  - `cargo fmt --all --check`

  `semver checks` fails as it has on every recent PR — thirteen standing items
  across three crates, none touched here.

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

- **vtc**: Send the member names and types the item schemas require ([#1095](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1095))

* fix(vtc)!: wrap the last three responses the schemas nest

  Stacked on #1093, and finishes the envelope family: after this, **no VTC
  route returns a bare row or array where its published schema wraps one.**

  ## `ceremonies/list` — a top-level array

  `Json<Vec<CeremonyManifest>>` where `vtc/ceremonies/list/0.1` says
  `{ceremonies: […]}`. An array cannot grow a sibling member later without
  breaking every reader, which is the whole reason the spec asks for an
  envelope. `fetchCeremonies` in the admin SPA moves with it.

  ## `community/profile/show` — more than an un-flatten

  `CommunityProfileResponse` used `#[serde(flatten)]`, putting every profile
  field at the top level. Reading the published schema rather than assuming
  the fix: the response is `{profile: …}` and **`additionalProperties: false`**,
  and `registryStatus` is defined *inside* the canonical `CommunityProfile`
  component ("Populated on reads; not settable") — not beside it.

  So un-flattening alone would have left `registryStatus` a sibling of
  `profile`, which the schema forbids. It now nests inside the profile object,
  where the component puts it. The SPA's `ProfileResponse` interface splits
  into `Profile` + a `{profile: Profile}` wrapper, and `getProfile` unwraps.

  ## `members/update` — the bare row

  Returned `MemberResponse` where the spec says `{member: …}`. Reuses
  `MemberEnvelope` from #1093, so `update` and `show` now publish the same
  shape. The admin SPA calls `patchJson<unknown>` and ignores the body, so
  nothing there moves.

  ## Coverage

  `GET /v1/ceremonies` had **no HTTP-level test at all** — the same gap that
  hid the `endorsements/show` drift in #1093. New `tests/ceremonies_list.rs`
  covers it: one test asserts the top level is an object and reads the
  manifests through `ceremonies`, so removing the envelope fails rather than
  passing on a payload that merely contains the right data; one pins that the
  route needs a session.

  Six existing tests read the old shapes and failed as soon as the handlers
  changed — two profile reads (`community_profile`, `install_flow`) and four
  `members_crud` PATCH assertions. All six now read through the envelope and
  would fail without it.

  ## Conformance witness

  `KNOWN_DRIFT_COUNT` stays **26**. All three entries keep their row with the
  fixture updated to what now ships and the note narrowed to what still
  diverges — in every case an unspecced member that belongs upstream, not a
  shape this service controls:

  - `ceremonies/list` — envelope fixed; each manifest still carries
    `factsTemplate`. The admin UI renders the simulator from it, so dropping
    it is not an option; it goes upstream.
  - `community/profile/show` — nesting fixed and `registryStatus` correctly
    placed; the profile still carries `communityDid`, `createdAt` and
    `relationshipIdentifierDefault`, none of which the canonical component
    defines. `communityDid` is the one a consumer most needs, and its absence
    from the component is the same root cause as the `config/export`,
    `config/import` and `profile/update` entries — one upstream change clears
    four rows.
  - `members/update` — envelope fixed; request still carries `label` and the
    row still carries the same five unspecced members as `list`.

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test -p vtc-service --no-fail-fast`
  - `cargo fmt --all --check`
  - `npm run lint` in `admin-ui`

  Note that `semver checks` fails on this branch as it does on every recent PR
  (#1092 and #1093 both). The failing items are identical across all three —
  thirteen `vta-sdk` / `vta-service` entries, none touched here. That gate is
  skipped on `main`, so nothing ever forces it back to green; worth fixing
  separately, because a real API break would currently land invisibly inside
  that noise.

- **vtc**: Wrap the last three responses the schemas nest ([#1094](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1094))

Stacked on #1093, and finishes the envelope family: after this, **no VTC
  route returns a bare row or array where its published schema wraps one.**

  ## `ceremonies/list` — a top-level array

  `Json<Vec<CeremonyManifest>>` where `vtc/ceremonies/list/0.1` says
  `{ceremonies: […]}`. An array cannot grow a sibling member later without
  breaking every reader, which is the whole reason the spec asks for an
  envelope. `fetchCeremonies` in the admin SPA moves with it.

  ## `community/profile/show` — more than an un-flatten

  `CommunityProfileResponse` used `#[serde(flatten)]`, putting every profile
  field at the top level. Reading the published schema rather than assuming
  the fix: the response is `{profile: …}` and **`additionalProperties: false`**,
  and `registryStatus` is defined *inside* the canonical `CommunityProfile`
  component ("Populated on reads; not settable") — not beside it.

  So un-flattening alone would have left `registryStatus` a sibling of
  `profile`, which the schema forbids. It now nests inside the profile object,
  where the component puts it. The SPA's `ProfileResponse` interface splits
  into `Profile` + a `{profile: Profile}` wrapper, and `getProfile` unwraps.

  ## `members/update` — the bare row

  Returned `MemberResponse` where the spec says `{member: …}`. Reuses
  `MemberEnvelope` from #1093, so `update` and `show` now publish the same
  shape. The admin SPA calls `patchJson<unknown>` and ignores the body, so
  nothing there moves.

  ## Coverage

  `GET /v1/ceremonies` had **no HTTP-level test at all** — the same gap that
  hid the `endorsements/show` drift in #1093. New `tests/ceremonies_list.rs`
  covers it: one test asserts the top level is an object and reads the
  manifests through `ceremonies`, so removing the envelope fails rather than
  passing on a payload that merely contains the right data; one pins that the
  route needs a session.

  Six existing tests read the old shapes and failed as soon as the handlers
  changed — two profile reads (`community_profile`, `install_flow`) and four
  `members_crud` PATCH assertions. All six now read through the envelope and
  would fail without it.

  ## Conformance witness

  `KNOWN_DRIFT_COUNT` stays **26**. All three entries keep their row with the
  fixture updated to what now ships and the note narrowed to what still
  diverges — in every case an unspecced member that belongs upstream, not a
  shape this service controls:

  - `ceremonies/list` — envelope fixed; each manifest still carries
    `factsTemplate`. The admin UI renders the simulator from it, so dropping
    it is not an option; it goes upstream.
  - `community/profile/show` — nesting fixed and `registryStatus` correctly
    placed; the profile still carries `communityDid`, `createdAt` and
    `relationshipIdentifierDefault`, none of which the canonical component
    defines. `communityDid` is the one a consumer most needs, and its absence
    from the component is the same root cause as the `config/export`,
    `config/import` and `profile/update` entries — one upstream change clears
    four rows.
  - `members/update` — envelope fixed; request still carries `label` and the
    row still carries the same five unspecced members as `list`.

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test -p vtc-service --no-fail-fast`
  - `cargo fmt --all --check`
  - `npm run lint` in `admin-ui`

  Note that `semver checks` fails on this branch as it does on every recent PR
  (#1092 and #1093 both). The failing items are identical across all three —
  thirteen `vta-sdk` / `vta-service` entries, none touched here. That gate is
  skipped on `main`, so nothing ever forces it back to green; worth fixing
  separately, because a real API break would currently land invisibly inside
  that noise.

- **vtc**: Send the envelope and the casing the schemas ask for ([#1093](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1093))

Four conformance drift entries where the *envelope* was wrong. All four rows
  stay in the drift table — each has a second, separate divergence in its
  members — but the half this PR fixes is the half that made the responses
  unparseable against their published schema.

  ## `registry/diagnostics` — the worst row in the table

  `DiagnosticsResponse` had no `rename_all`, so every member went out
  snake_case. Not one of the four **required** members
  (`registryStatus`, `queueDepth`, `rtbfBatchedCount`, `failedCount`) reached
  the wire under the name `vtc/registry/diagnostics/0.1` gives it — a
  spec-conformant client saw a response with all four required fields missing.
  Fixed with `#[serde(rename_all = "camelCase")]` (R3.1).

  This is a **breaking wire change**, so the consumers move with it:

  - `admin-ui/src/lib/api.ts` — `DiagnosticsResponse` members recased.
  - `admin-ui/src/plugins/{recognition,dashboard}.tsx` — every
    `diagnostics.data.*` access, plus the one `<code>` label that names the
    wire field in operator-facing prose.
  - `tests/diagnostics.rs` — the assertions now read the shipped names.

  `RegistryTransport` and `TransportStatus` are all single-word members, so
  they needed no change. No consumer outside this repo: `openvtc` doesn't read
  diagnostics.

  ## Three `show` routes returned the row bare

  `members/show`, `endorsements/show` and `join-requests/show` each publish a
  wrapped response — `{member: …}`, `{endorsement: …}`, `{request: …}` — and
  each returned the row unwrapped. The rows themselves always conformed; only
  the envelope was missing. Added `MemberEnvelope`, `EndorsementEnvelope`,
  `JoinRequestEnvelope`, and pointed each handler's `utoipa` `body =` at the
  envelope so the generated OpenAPI stops advertising a shape the service
  doesn't send.

  `GET /credentials/endorsements/{id}` turned out to have **no test at all** —
  which is how it returned the bare row past a published schema that wraps it.
  This PR adds one. It asserts the top-level `id` is *absent*, so it fails if
  the envelope is ever removed rather than passing on a shape that merely
  contains the right data. The three existing tests that read these rows
  (`show_member_returns_joined_response`, `show_returns_full_request_including_vp`,
  and two policy tests in `join_requests`) now read through the envelope, and
  would fail without it.

  ## `/health` deliberately left alone

  `HealthResponse` still emits `vtc_did`. `/health` is not a bound Trust Task,
  and `website-default/site.js:212` reads that member. Renaming it would break
  a live page to satisfy a schema that doesn't govern the route. The struct
  carries a comment saying so, so the next person doesn't "fix" it.

  ## Conformance witness

  `KNOWN_DRIFT_COUNT` stays **26**. All four entries keep their row with the
  fixture updated to what now ships and the note narrowed to what still
  diverges:

  - `registry/diagnostics` — casing fixed; nine unspecced members
    (`syncer*`, `messagingStatus`, `transports`, `registryTransport`,
    `vtaDid`, `mediator*`) remain. That half is genuinely useful diagnostics
    and should go upstream, not be deleted.
  - `members/show` — envelope fixed; same five unspecced members as `list`.
  - `endorsements/show` — envelope fixed; row members are still this service's
    spelling (same model disagreement as `issue`).
  - `join-requests/show` — envelope fixed; unspecced `vpClaims` / `decision`
    remain, same as `list`.

  The witness's `known_drift_entries_still_diverge_where_they_say_they_do`
  proves those four are still non-conformant for the stated reason — an
  entry that silently started passing would fail the test.

  ## Gates

  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test -p vtc-service`
  - `cargo fmt --all --check`
  - `npm run lint` in `admin-ui`

  Prettier is neither a dev-dependency nor a CI gate here and the SPA sources
  are not prettier-clean on main, so the TS diff is a pure rename — 57
  insertions, 57 deletions — with no reformatting churn.

  Drift stays **26** — #1092 brought it 27 → 26 by closing
  `endorsement-types/register`; these four rows each keep a live second half,
  so none of them closes here.

- **vtc**: Return a response body where the spec asks for one ([#1092](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1092))

Two more of the divergences #1076 recorded, and one of them is a hole rather
  than a shape.

  **`auth/admin-session` returned 204 and put its result in two `Set-Cookie`
  headers**, where the schema asks for `{sessionId, expiresAt}`. A cookie is not
  a Trust Task response. Nothing but a browser can read one, so every
  non-browser caller — the CLIs, a DIDComm binding, any integration — could
  authenticate here and learn nothing about the session it had just been given.
  The cookies stay, because the admin SPA relies on them; the body is what makes
  the route usable by anything else.

  `expiresAt` is Unix seconds, because that is how the schema types it. I wrote
  it as RFC 3339 first and the witness rejected it — a reminder that "the spec
  asks for a timestamp" is not the same as knowing which one, and that reading
  the schema beats assuming the convention.

  **`endorsement-types/register` returned the bare row** where the spec wraps it
  as `{endorsementType: …}`. The row itself always conformed. Its other half —
  the unspecced `createdByDid` — was taken upstream in
  trustoverip/dtgwg-trust-tasks-tf#260, so the entry stays, now describing only
  what is left and naming what closes it.

  Drift 27 → 26. Twelve of the remaining twenty-six close on a `trust-tasks-rs`
  release carrying #257–#260 rather than on any change here; the entries say so,
  so that nobody goes looking for code to write.

- **vtc**: Return the response shapes the specs publish ([#1082](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1082))

Four of the divergences #1076 recorded, all of the same kind: the handler had
  every value the schema asks for and replied with something narrower.

  - `backup/export` returned the bare `BackupEnvelope`; the spec wraps it as
    `{envelope: …}`. The inner object always conformed member for member.
  - `members/removed` returned a top-level array; the spec says
    `{removed: […]}`. The rows always conformed.
  - `website/files/delete` returned 200 with zero bytes, discarding the `path`
    and the outcome the spec asks for as `{path, deleted}`.
  - `website/rollback` returned 200 with zero bytes, having already computed the
    `noop` the spec asks for — it is the same `from != gen_num` test that decides
    whether to write an audit event.
  - `endorsements/revoke` replied `{id}` where the spec requires
    `{endorsementId, revocation: {credentialId, revokedAt}, statusListIndex}`.
    All four were in hand: the handler bound `updated` and threw it away with
    `let _ = updated;`. The idempotent no-op path answers with the same shape,
    reading the timestamp already on the row rather than inventing one.

  Two things the witness taught me that reading would not have.

  **`website/rollback` types `current` as a boolean and `generation` as a
  string.** `current` answers "did the rollback take", not "which generation is
  live" — I had written it as the generation number, twice, and the sweep
  rejected both. The string typing matches the path segment the spec declares.

  **`website/generations/list` is not envelope-only, and its entry said it was.**
  The missing `{generations: […]}` wrapper is fixed here, but the rows diverge
  too: the spec's row carries `generation` and `current` where the service sends
  `isCurrent` and adds `deployedAt` and `sizeBytes`. It stays a drift entry, with
  the diagnosis corrected — one rename belongs here, and two members worth having
  belong upstream rather than being dropped.

  Drift count 31 → 27.

  A limit worth restating: the witness compares a hand-transcribed fixture with
  its schema, so it proves the fixture conforms, not that the handler emits the
  fixture. The integration tests are the other half, and two of them had to move
  here — `members_crud` read the removed list as a bare array in two places.

- **vtc**: Accept the install flow's own field names ([#1080](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1080))

The two-step install flow was inconsistent with itself. `claim/finish` derives
  `ClaimFinishResponse` with `rename_all`, so it returns `setupSessionToken`.
  `admin/bootstrap` derived `BootstrapRequest` without one, so it demanded
  `setup_session_token`. The service handed a caller one spelling and required
  the other back.

  Only the admin SPA got through it, because `Install.tsx` re-keyed the value by
  hand on its way from one call to the next. A client written from the published
  schema — which has said `setupSessionToken` all along — could not complete an
  install at all: its body deserialised as a missing required field.

  `ClaimStartRequest` and `ClaimFinishRequest` had the same gap, so
  `install_token`, `claim_secret`, `registration_id` and `webauthn_response` were
  all snake_case against schemas naming them in camelCase. All three request
  structs gain `rename_all = "camelCase"`, and the SPA now passes the token
  straight through instead of translating it.

  R3.1 again, and the third find of the same class today after the
  `Verifiable`-prefixed credential tags and the `Paginated<T>` wrapper. The
  common thread is not carelessness about casing: it is that a request struct's
  serde attributes were never compared to the schema its URI publishes. The
  witness from #1076 is the first thing in the repo that does that.

  Drift count 32 → 31. `admin/bootstrap` is promoted to `checked!`; the two
  install/claim entries stay, rewritten to describe only what is left of them —
  `claimSecret` is a real member the spec does not define, and the response
  omits `didBindingChallenge`, which the spec requires because this service
  binds the admin DID at `claim/finish` instead. Those are a spec-and-flow
  reconciliation, not a casing fix.

  Deliberately untouched: `RegisterFinishRequest` (routes/admin/passkeys.rs) is
  also snake_case, and a first pass swept it up with the rest. Reverted — it is
  a different endpoint with its own entry, and widening this change to cover it
  would have buried a decision inside a mechanical fix. `install_flow.rs` calls
  both flows and now shows the two casings side by side, with a comment saying
  why.

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

- **vtc**: Thread `now` into the VPC shape check, unbreaking main ([#1077](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1077))

`main` at 397d087c does not compile.

      error[E0061]: this function takes 4 arguments but 3 arguments were supplied
         --> vtc-service/src/routes/relationships.rs:994

  #1074 added `check_vpc_shape`, which calls `credentials::ingress::require_dtg_type`.
  #1075 gave that function a `now` parameter. Neither diff touched the other's
  lines, so git merged both cleanly and both were green on CI — each having been
  tested against a `main` that did not yet contain the other. A textual merge, a
  semantic conflict.

  `check_vpc_shape` now takes `now` and threads it through, matching
  `check_vrc_shape` beside it.

  That is not only what the compiler wanted. It answers a question neither PR
  was in a position to ask: **should a VPC's validity window be checked when it
  is attached?** It should, for the reason the window is checked on the publish
  path — an annotation that outlived its own credential would go on asserting a
  persona the issuer had stopped standing behind. `now` is read once per request
  and passed in, so every check in the request evaluates at one instant.

  The failure mode is worth recording, because nothing in the repo would have
  caught it: CI green on a pull request proves the branch works against the main
  it was cut from, not against the main it will land on. Two changes to one
  function signature need one rebased onto the other before either merges,
  however disjoint their diffs look.

- **vtc**: Reject a credential whose validity window has passed at ingress ([#1075](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1075))

`routes/relationships.rs` read neither `validFrom` nor `validUntil`, so a
  VRC that had already expired became a permanent edge in the community
  trust graph. Permanent because the graph is read without re-checking
  dates, and because per planning-review D7 a VRC carries no
  `credentialStatus` — the only removal is `DELETE /v1/relationships/{id}`.

  DTG Credentials Security Considerations 2 asks a verifier to reject
  credentials outside their window. That section is marked *informative*,
  so this is a conformance expectation, not a normative MUST. Issue #1069
  (conformance audit F9).

  The check lands in `credentials::ingress` — the module that already owns
  the DTG common-structure check — as `check_validity_window`, and
  `require_dtg_type` now runs it, so a future ingress point gets it by
  calling the same gate rather than writing a third copy.

  Judgement calls, all stated in doc comments at the code:

  - `classify_dtg` is left structure-only. `routes/recognise.rs:329` uses
    it as a *filter* over a presentation's `verifiableCredential` array,
    skipping non-DTG entries, since a VP may legitimately carry others.
    Folding the window check in would turn an expired VEC into a silently
    skipped entry and downgrade the error from `recognition::verify`'s
    "VEC validUntil ... is in the past" to "presentation has no
    EndorsementCredential".

  - The VIC path (`credentials/invitation_verify.rs:361-373`) and the
    recognition path (`recognition/verify.rs:198-228`) are left alone.
    Both already implement the same half-open window, and each carries
    semantics this check does not: recognition also clamps the minted
    session TTL to the earliest `validUntil` across the pair, and both
    *require* `validUntil` to be present. Routing them through the shared
    check would duplicate or weaken them. Three implementations was the
    problem; replacing two working ones with a weaker one is not the fix.

  - Absent bounds are not enforced. Both properties are optional in W3C VC
    2.0, and most VRC fixtures in this repo have no `validUntil`. Whether
    an open-ended edge is acceptable is a community policy question and
    belongs in `relationships.rego`, not in a type check.

  - No clock-skew tolerance. These windows are days to years, so any
    plausible grace changes nothing operationally while making "expired"
    disagree with the two paths this is meant to align with. Contrast
    `PUBLISH_AUTHORIZATION_MAX_AGE_SECS`, which does allow skew because it
    bounds a five-minute freshness window.

  - Both VC 2.0 and VC 1.1 spellings are read. `DTGCommon` in the
    `dtg-credentials` catalog declares `#[serde(alias = "issuanceDate")]`
    / `alias = "expirationDate"`, so a 1.1-named credential parses; reading
    only `validUntil` would leave it unchecked while every other layer
    accepted it. Nothing in this stack emits the 1.1 names. A document
    stating both spellings of one bound is rejected — serde treats the
    alias as the same field, so the catalog parser rejects it too, and
    ingress must not admit what the catalog cannot parse.

  The revocation half of Security Considerations 2 is a deliberate
  divergence, not a gap: D7 makes VRC revocation a row deletion. Said
  explicitly in the `check_validity_window` doc comment so a reader
  comparing against the specification does not read it as a second finding.

  Tests mint through the catalog constructors (`DTGCredential::new_vrc`)
  via `test_support::dtg_json`, never hand-rolled JSON. Unit tests rather
  than integration tests because `dtg-credentials` is a normal dependency
  of `vtc-service` and so is not reachable from `tests/`.

  Mutation-tested. Changing `valid_until <= now` to `valid_until <=
  DateTime::<Utc>::MIN_UTC` fails four tests
  (`rejects_a_credential_whose_window_has_passed`,
  `window_boundaries_are_valid_from_inclusive_and_valid_until_exclusive`,
  `enforces_the_window_under_the_vc_1_1_property_names`,
  `refuses_a_vrc_whose_validity_window_has_passed`). Changing
  `valid_from > now` to `valid_from > DateTime::<Utc>::MAX_UTC` fails
  `rejects_a_credential_not_yet_valid`. Both reverted.

- **vtc**: Route a presented VEC by the type the catalog actually mints ([#1063](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1063))

Cross-community recognition rejected every genuinely-issued VEC.

  `extract_vec_vmc` routed a presented credential to its VEC slot by matching
  the literal `"VerifiableEndorsementCredential"`. Nothing mints that.
  `issue_endorsement` builds through `DTGCredential::new_vec`, and the catalog
  wire-shape guard pins the result as `["VerifiableCredential", "DTGCredential",
  "EndorsementCredential"]` — no `Verifiable` prefix, because the prefix belongs
  to the concept and never to the wire tag. So a real VEC fell through to
  `continue`, the slot stayed empty, and the request died at

      400 presentation has no VerifiableEndorsementCredential

  naming a credential type that does not exist in DTG Credentials.

  The VMC branch beside it was always correct, because it read the shared
  `VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE` constant — whose *value* is
  `"MembershipCredential"`. A comment in `tests/recognise.rs` already warned
  about precisely this trap and said to use the constant rather than a literal.
  The VEC branch used a literal.

  Classification now goes through `dtg_credentials::DTGCredentialType`, so the
  routing side and the minting side share one definition of the wire form and
  cannot drift apart again. Pre-catalog peers are still accepted: recognition is
  cross-community, and a VTC predating `cb06fb31` hand-rolled the prefixed tags,
  so those route with a warning — here and nowhere else.

  The suite was green throughout because the test hand-rolled its VEC with the
  same fictional type the handler matched. Test and bug agreed, and neither
  agreed with what the VTC issues. `sign_vc` now emits the DTG wire form, which
  is what makes this a regression test rather than a restatement: revert the
  handler and `matching_holder_clears_the_binding_gate` fails.

  Three unit tests pin the classification directly — catalog form, legacy form,
  and types the gate must ignore.

  Found while auditing the stack against DTG Credentials for #1054.

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

- **vtc**: Probe the trust registry after messaging is up, not before ([#981](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/981))

The boot-time trust-registry health probe ran inline in `server::run`, a few
  hundred lines before the DIDComm thread that gives it a transport is spawned.
  For a registry addressed by DID that is not a race — it is a guaranteed failure.
  `our_capabilities()` is empty until the messaging listener publishes its handle,
  so `select` returns "no transport available yet" and every boot opens with:

      WARN trust-registry health probe failed at boot — running with
           registry_status=degraded

  Observed end to end on a live deployment, inside 50ms:

      08:07:49.496 trust-registry health probe failed at boot ...
      08:07:49.497 DIDComm thread started
      08:07:49.543 VTC messaging connected to mediator

  The warning is about our own startup order and says nothing about the registry,
  which is the worst property a boot diagnostic can have: it is the first line an
  operator reads when something else is wrong, and it points away from the cause.
  `registry::messaging::classify_no_match` already carries a `Transient` arm
  written for precisely this window, so the first sync jobs are retried rather
  than parked in `Failed` — that guards the consequence; this fixes the cause.

  ## What changed

  The boot probe and the periodic probe are now one task, with the boot probe as
  its first iteration — `tokio::time::interval` fires immediately, so the two can
  no longer drift apart at separate call sites (and the "skip the first tick so it
  doesn't overlap the boot probe" dance is gone).

  Before that first tick, the task waits for the messaging handle. It stays **off**
  the startup path — `run` must reach its shutdown select for a signal to be
  honoured — so the wait lives inside the spawned task, is bounded at 30s, and
  abandons immediately on shutdown. A registry reached over its REST arm waits for
  nothing, since `config.messaging` is `None` and there is no handle to wait for.

  On timeout it probes anyway rather than staying quiet: an operator needs
  `registry_status` to reflect a real attempt, and "messaging never came up" is
  itself the diagnosis.

  Two behaviours are deliberately preserved. Disabling the periodic probe
  (`health_probe_interval_seconds = 0`) still leaves the boot probe — it is what
  populates `registry_status` for an operator opening the dashboard — so the gate
  no longer folds that setting into whether the task spawns at all. And a zero
  interval would panic `interval()`, so it is clamped and the task returns after
  the single probe.

  ## Tests

  The wait is extracted as `wait_for_handle`, generic over the cell's contents
  purely so it is testable — the real handle cannot be constructed without a live
  ATM and mediator socket. Four cases: a handle published mid-wait is picked up, a
  handle that never arrives times out instead of hanging, shutdown during the wait
  abandons it, and an already-published handle does not sleep at all (the last two
  would hang against a 30s budget if the logic regressed).

- **webvh**: Align the reconcile task with the spec published upstream ([#977](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/977))

#976 landed the implementation before its specification did. The spec is now
  merged as trustoverip/dtgwg-trust-tasks-tf#210 and ships in `trust-tasks-rs`
  0.6.1 — and review there moved three names. This brings the implementation onto
  the published contract while nothing has consumed the old one.

  **Type URI.** `vta/webvh/servers/dids/0.1` → `vta/webvh/servers/reconcile/0.1`.
  The sibling this was named after (`servers/domains`) returns *the server's
  domains*; this returns a comparison, so a reader of `servers/dids` would
  reasonably expect a listing and get a diff.

  **`mnemonic` → `slotId`** on the wire. `mnemonic` is what did-hosting's API and
  `WebvhDidRecord` call the host's slot identifier, and both keep that name — the
  rename happens only at the wire boundary, where a published contract should not
  overload a word that already means a BIP-39 recovery phrase everywhere else in
  these deployments.

  **`localOnly` → `agentOnly`.** "Local" is relative to whoever is speaking. The
  spec's parties are producer, agent and host, and the divergence belongs to the
  agent.

  Breaking against `main`, and deliberately timed: the wire form has never been
  released, and the open release PR would have published `servers/dids/0.1` to
  crates.io permanently. Merging this first means what publishes matches what the
  registry serves.

  The two drift-register entries now cite the merged spec rather than an
  intention, and say what actually holds them here: this workspace is on
  `trust-tasks-rs` 0.4, so `schema_for` cannot resolve the URI yet. They clear on
  the 0.4 → 0.6 move, which is its own workspace event — two leading-component
  bumps, with `trust-tasks-{https,didcomm,proof,tsp,capability-client}` moving
  together. The `UNSPECCED_DISPATCHED_URIS` harness is stale-checked in both
  directions, so the entry cannot be forgotten once that lands: it fails on an
  entry the registry *does* publish.

  Docs gained a "wire contract" section pointing at the spec, so slot-keyed
  matching, the required `inBoth` count and the refusal to answer an unobtainable
  listing read as normative rather than as this implementation's habits.

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

- **vtc**: A registry unreachable at boot is retriable, not permanent ([#966](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/966))

The boot log said it plainly: "no transport protocol in common … we
  advertise [], they advertise [Didcomm]". We advertise nothing because
  the registry client is constructed before the messaging listener
  publishes its handle, so for the first seconds of a boot
  `our_capabilities` is empty and every peer reads as having no
  transport in common.

  An empty intersection is normally an operator's configuration fault,
  so it was classified `Permanent` — and that is the damaging part. The
  health probe recovers on its next tick (the deployment flipped to
  active 60s later, which is why a refresh looked fine), but a sync job
  dispatched inside that window is parked in `Failed`, where the syncer
  never retries it. The indicator heals and the queue does not.

  Selection now asks which side is empty. If *we* can currently speak
  nothing, that is our own startup race and it is transient. Only an
  intersection that is empty while we do have a transport available is
  the operator's to fix, and only that one parks the job.

  Also surfaces the sync queue, which is the other half of the same
  problem — a stalled reconciler had no representation in the UI at all.
  Recognition gains a Membership sync card (pending with the age of the
  oldest job, failed, RTBF-batched, syncer liveness + restarts, last
  success/failure/error) polling every 15s, because a snapshot frozen at
  page load shows a drained queue as permanently stuck. The dashboard's
  trust-registry tile reports any failed job, or a queue an hour behind,
  in place of its transport line: a registry that answers while nothing
  lands is exactly the state the old green indicator hid.

  Transport errors are trimmed on the tile — they quote both advertised
  sets and a full did:webvh, which wrapped to five lines and pushed the
  dashboard down. Recognition still shows the whole string.

- **ci**: Stop .gitignore breaking the release, and drop a committed dev VTC ([#941](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/941))

The Release-plz job failed with "fatal: not a git repository" inside its own
  temp copy, then with "uncommitted changes" listing files that are not
  modified. Both come from .gitignore, and neither is visible to git itself.

  1. `.gitignore` listed `.git/`.

     git never tracks .git, so the entry did nothing for git — but release-plz
     copies the worktree honouring ignore rules, and that copy therefore had no
     .git directory. Hence "not a git repository" about a repository.

     This is also why it passed when I tested locally: I ran it in a git
     WORKTREE, where .git is a file, and the pattern `.git/` matches only
     directories. CI has a real .git directory, so CI saw a different bug than
     my machine did. Replaced with a note so it is not re-added.

  2. Ten files are tracked AND matched by .gitignore.

     `vtc-service/{config.toml,VTC-did.jsonl,data/vtc/**}` — a local dev VTC
     instance, including its fjall store, journal and lock file — were committed
     in the initial project import. .gitignore was later written with `**data/`,
     `**config.toml` and `**.jsonl`, which match them, but the tracked copies
     stayed. `git ls-files -ci --exclude-standard` lists them; ordinary git
     status never mentions them, which is why this sat unnoticed.

     Tools that copy a worktree by ignore rules see a file that is in the index
     but absent from the copy, and report it as an uncommitted change.

     Nothing references these paths. The two mentions in tasks/*.md describe the
     setup wizard WRITING vtc-service/config.toml at runtime, not reading this
     committed one.



### Security

- **rooms**: A room credential must be signed by its issuer ([#2158](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2158))

A room credential's proof was verified against whatever key its own
  `verificationMethod` named, but that method's DID was never compared with
  the credential's `issuer`. Everything downstream trusts `issuer` -- the
  authority chain is rooted at it and the membership check compares it to the
  room -- so a credential could claim an issuer whose key never signed it.
  That is the issuer-not-bound-to-proof-key class: a valid signature by
  somebody, read as the issuer's.

- **deps**: Source-map-js 1.2.2 and xxhash-rust 0.8.16 ([#2078](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2078))

Clears the two open Dependabot alerts:
  - GHSA-68fv-2mgg-jv7q (high): source-map-js < 1.2.2 event-loop DoS via
    indexed source-map section offsets — vtc-service/admin-ui (dev dependency).
  - GHSA-6g2r-675j-hx59 (low): xxhash-rust < 0.8.16 xxh3 custom-secret API
    accepts a too-short secret — deploy/nitro/enclave-proxy (via fjall).

  Lockfile-only changes.

- **vtc-service**: A step-up passkey, once enrolled, is the only gesture that counts ([#1850](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1850))

Once a subject holds a dedicated step-up passkey, the operation-bound
  step-up gate (acl/grant, acl/change-role, git break-glass, ...) accepts
  only that passkey — their ordinary session/console passkey stops
  counting, and wallet-signed (didSigned) evidence was, and stays,
  refused unconditionally on this door. A subject with no step-up
  passkey keeps today's route so nobody is locked out.

  Enrolling a step-up passkey also revokes, rather than merely waits
  out, any session elevation the subject already holds.

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

- **vta-sdk**: Verify a proof's key against its proofPurpose (VTI-KEY-022) ([#1752](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1752))

* security(vta-sdk)!: verify a proof's key against its proofPurpose (VTI-KEY-022)

  A verifier accepted any key the signer's DID document listed under
  verificationMethod, whatever the proof declared it was for. A key published
  only for keyAgreement, or authorised only to authenticate, could make an
  assertionMethod proof.

  vta-sdk adds ProofPurpose, PurposeVmResolver and PurposeBound.
  TrustTaskVmResolver now resolves a method only for one purpose, and only
  when all of these hold:
  - the resolved document is the DID's own;
  - the method is listed under the relationship the purpose names, by
    absolute DID URL, by relative fragment, or embedded. A reference resolves
    only against the top-level verificationMethod set;
  - the method's controller is the DID.

- **vta-service**: Require assertionMethod on an approver's decision ([#1757](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1757))

* fix(vta-service)!: require a document proof bound to the sender on every DIDComm and TSP trust task

  A Trust Task that reaches the VTA or the VTC over an intrinsic-sender
  transport (DIDComm, TSP) is now accepted only when the document carries a
  Data Integrity proof that verifies as its `issuer`, and that issuer is the
  transport-reported sender. The transport's sender alone no longer
  authorizes anything (VTI-OPS-021/093).

- **resolver**: One bounded DID-document cache per node, re-resolved once before a verification fails (VTI-KEY-134) ([#1737](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1737))

* security(resolver)!: one bounded DID-document cache per node, re-resolved once before a verification fails (VTI-KEY-134)

  The VTC ran two DID-document caches: the app resolver built in
  `init_auth`, and a second one the messaging TDK built for itself
  because it was given none. Both used the SDK defaults of a 300 s TTL and
  100 entries. Every DIDComm and TSP message on the mediator socket was
  checked against a cache the REST and Trust Task paths could not see or
  evict. Neither cache was ever refreshed when a verification failed, so
  a peer that rotated was refused as a forger until its entry aged out.

  Bounded TTL (key-roles, dtgwg-vti-spec #42: VTI-KEY-060/062/122/123/134):

  - A new `[did_cache]` section (`vti_common::config::DidCacheConfig`)
    holds `ttl_secs` (default 60, refused outside 1..=300) and `capacity`
    (default 1000). The VTA and the VTC read the same type.
  - The TTL is what bounds how long a key revoked for compromise keeps
    verifying: VTI-KEY-123 allows no overlap, and nothing else notices a
    removal. A new key does not wait on the TTL, because of the refresh
    below. 60 s caps the revocation window at a minute, for one resolution
    per active DID per minute. 300 s, the SDK default and the old
    behaviour, is the ceiling.
  - `vta_sdk::resolver::build_verifier_did_cache_config` builds it, with
    the webvh host policy the VTA already used. The VTC now uses that
    policy too, so the private-host opt-in reaches it as well.

  One cache:

  - The VTC messaging TDK is handed the app resolver.
  - The VTA already shared its resolver. Its fallback when there is no
    app resolver now gets the same bounds, not the SDK defaults.

  Re-resolve once, then fail closed (`vta_sdk::did_refresh`):

  - `resolve_for_vm`: when a cached document does not list the method a
    proof names, re-resolve it fresh once. This covers every Trust Task
    proof on both nodes (`TrustTaskVmResolver`) and the VTC credential/VP
    resolver (`DidVmResolver`).
  - `verify_trust_task_proof_with`: when verification fails and the
    signer's document came from the cache, evict it and verify once more.
    This covers a key id kept with its material replaced.
  - `unpack_refreshing_sender`: when an authcrypt unpack fails, evict the
    sender named in the protected header (`skid`) and retry once. It is
    used on the REST DIDComm auth and refresh paths of both nodes.
  - Each forced refresh is rate-limited per DID (5 s, with at most 4096
    DIDs tracked). A failing proof is something anyone can send, and
    without the limit each one would make this node fetch a third party's
    document.

- **vtc**: Invites and attrition respect the unrestricted-admin consent (VTI-APV-014) ([#1747](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1747))

* security(vtc)!: invites and attrition respect the unrestricted-admin consent (VTI-APV-014)

  Third of four for VTI-APV-014. #1741 put another admin's consent in front
  of `acl/grant` and `acl/change-role`. This closes the other ways to reach
  unrestricted admin, and the ways to strand the rule by removing admins
  (VTI-APV-009).

- **vtc**: Unrestricted admin needs another admin's consent (VTI-APV-014) ([#1741](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1741))

* security(vtc)!: unrestricted admin needs another admin's consent (VTI-APV-014)

- **auth**: Retire the superseded refresh token when a DID logs in again ([#1683](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1683))

* security(auth)!: retire the superseded refresh token when a DID logs in again

  Rotation makes a stolen refresh token worth one use, and reuse detection
  notices it when it comes back. Neither could see a token that is never
  presented twice.

  `/auth/` is keyed per DID and overwrites `session:{did}`, but the reverse
  index is a separate `refresh:{hash}` row per token, and `/auth/refresh`
  authorises from that index alone — it never consults
  `session.refresh_token`. A login that merely added its own index row left
  the previous one live, so one account carried two working chains that
  shared no token: each refreshed into its own successor, no replay ever
  occurred, and detection never fired. A token stolen before a re-login kept
  working indefinitely and silently, alongside its owner's, and the one
  recovery step a user can take unaided — logging in again — did nothing to
  it.

  `handle_authenticate` now retires the outgoing token. It reads the prior
  session's `refresh_token` before `store_session` overwrites the row,
  removes that token's index entry with the atomic claim-and-delete (so two
  racing logins cannot both retire it, preserving VTI-SES-030), and leaves a
  tombstone in its place. Ordered after the new chain is durable, as on the
  rotation path; both writes log on error rather than failing a login that
  has already committed and minted its tokens.

  `RefreshTombstone` gains `cause` to record why a token was retired.
  `Superseded` is excluded from the innocent-retry grace window on purpose:
  that concession answers a lost rotation response, and a client that has
  just logged in holds its replacement. Honouring a replay there would have
  handed the new token to whoever replayed a pre-login theft — strictly worse
  than the gap being closed.

  Replaying a superseded token is refused and audited as
  `AuthAuditEvent::RefreshSuperseded` (`warn!`, `security_alert = true`), but
  the session is left running. Unlike reuse, the presented token is already
  dead — the login took its index — so revoking adds nothing against a thief,
  while the ordinary cause is a second device still holding what it was
  issued before the user signed in elsewhere. Killing the session there would
  sign out the client that is demonstrably current, and the re-login it
  forces would set the same trap again. The event still carries
  `security_alert` because a pre-login theft and a stale device are
  indistinguishable from the node's side; only an operator correlating them
  can say which it was.

  `cleanup_expired_sessions` now also sweeps `refresh:` entries that their
  session no longer names. Retirement fixes new logins but cannot reach
  entries already written, and those rows carry no TTL and are not inert: an
  orphan resolves again as soon as its DID has a session row, so it outlives
  a revocation and returns at the next login. The sweep is safe against a
  concurrent login or rotation because every writer stores the session row
  before its index entry, so an entry that disagrees with its row is stale
  rather than half-written.

  Also in this change: `RefreshReuseDetected` takes its `did` from the
  tombstone, so the alert names the account on the `SessionGone` path where
  the session row is absent by definition; the lost-response retry log
  carries `audit = true`, since a stable session id had left it
  indistinguishable from an ordinary rotation; and the module header no
  longer describes a delete-and-recreate the handler stopped doing.

  `refresh_reuse_grace` stays at 30s, now documented as a starting point
  rather than a ceiling — a client only discovers a lost response when its
  own HTTP timeout fires, so a deployment whose clients retry later than that
  may want 60s. It is a user-experience call, not a security one: the
  successor-unspent condition, not the clock, is what keeps the concession
  narrow. `0` still disables it entirely.

- **workspace**: No type derives Debug over secret material ([#1711](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1711))

A derived `Debug` prints every field, so on a type holding a private key, a
  seed or mnemonic, a bearer or refresh token or a password it puts the secret
  into anything that formats the value — a `tracing` field, an `unwrap` or
  `expect` on an enclosing type, a test failure, a panic message. About 55 types
  across twelve crates did exactly that. It surfaced when `vtc-client` began
  holding an operator's key in a `HolderKey`, whose derived `Debug` printed it.

  Each now has a hand-written `Debug` that reports the secret as `<redacted>` —
  presence kept visible for an `Option` — and prints every other field as
  before, the idiom the workspace already used where someone had thought of it.
  Among them: `HolderKey`, `Session`, `ClientIdentity`, `CredentialBundle`,
  `SecretEntry`, `AgentConfig`, `AgentConnect`, `AuthResult`, the key-import and
  seed-rotation requests (mnemonic), `SeedRecord`, `MnemonicExportResponse`,
  `SecretsConfig` (seed, Vault token, AppRole secret id), `VaultSecret`, its
  `CustomField` values and secure notes, `TotpSeed`, the VTC install flow's
  ephemeral signing keys, setup tokens and install JWT, the VTC backup's signing
  bundle and password, mobile-core's X25519 and Ed25519 private keys, auth tokens
  and push tokens (including the Web Push auth secret), and vta-mcp's
  `--agent-key`/`--holder-key`/`--agent-secrets`.

  `Zeroizing<T>` is not a redaction — its `Debug` prints the inner value — so the
  fields wrapped in it were redacted too.

  `vta-sdk/tests/secret_debug_census.rs` keeps the class closed. It parses every
  workspace crate with `syn` and fails on a `#[derive(Debug)]` struct or enum
  whose field has a secret-sounding name (`*_key`, `*token*`, `*secret*`,
  `seed*`, `password`, `mnemonic`, `jwt`, and `secret_id` despite its `_id`)
  and a raw type (`String`, bytes, `Zeroizing<_>`, optionally in an `Option` or
  behind a reference). A field whose type is another workspace type inherits that
  type's `Debug`, which is checked where it is defined. What the name rule
  catches and is not a secret — a claim-type vocabulary token, a webvh path
  called `mnemonic`, the name of an entry in a secret store — is on a
  shrink-only list with what the field holds, and the census also refuses a
  stale entry and a walk that has stopped finding types.

  Not an API change: every type still implements `Debug`; only what it prints
  differs, and no test asserted on the old output.

- **vtc**: A declared proof is required by default ([#1672](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1672))

* security(vtc)!: a declared proof is required by default

  #1659 made the Trust Task dispatcher enforce what a specification declares, but
  gated one refusal — a document carrying no `proof` for a task whose
  specification declares one REQUIRED — behind `[trust_tasks]
  require_declared_proof`, default `false`. That switch had one reason, written
  into its own rustdoc: `openvtc-core` built `join-requests/{submit,status}`,
  `members/{self-remove,vmc}` and `members/personhood/assert` with a deliberate
  "no `proof` is attached", so enforcing would have refused every join on a
  community serving that client.

  The same rustdoc carried the removal condition, exactly: "when `openvtc-core`
  signs the five documents above, the default flips and this field goes with it".
  openvtc#371 signs them, via `trust_task_doc::build_signed_value`. So the
  default flips and the field is gone, closing divergence 2 of the VTI
  specification's Appendix F.2 rather than merely making it visible.

  `narrow_for_transitional_allowance` is deleted. #1659 implemented the
  relaxation by narrowing the policy *value* rather than skipping enforcement, so
  this removes the narrowing and leaves every other rule intact:
  `spec_policy_for(..).enforce(&doc)` now runs against the registry's own policy,
  with the `recipient`-REQUIRED, `issuedAt`-REQUIRED and audience-binding rules
  untouched. A comment at the site records that nothing may put a switch back —
  VTI-OPS-093 forbids a binding weakening a document requirement on the strength
  of a transport property, and a per-deployment setting that lets an operator do
  it is the same weakening reached by a longer path.

  A config still carrying the key is answered, not ignored, and the two values
  are answered differently because they are different intents. `= false` fails to
  load, with an error naming openvtc#371 and saying the client must be upgraded:
  that intent cannot be honoured, and starting anyway would enforce the opposite
  of what the operator's file says. `= true` asked for what the service now does
  unconditionally, so it warns at load and starts — the operator's intent
  survives and only the line is stale. The refusal is in the deserializer, so it
  holds on every path that parses an `AppConfig`; the warning is in
  `AppConfig::load` and goes to stderr, because config loads before
  `init_tracing` and a `warn!` with no subscriber is the silence this is meant to
  avoid. The key is `skip_serializing`, so it is never written back.

  The `vti_ops_021_*` pair that pinned the relaxed path lost its premise and is
  rewritten rather than deleted. One unsigned document is now driven over REST,
  DIDComm and TSP and must be refused on each (the old tests each asserted about
  one transport, so between them they could have agreed with VTI-OPS-021 on two
  and disagreed on the third unnoticed), with a signed counterpart as the control
  — without it the refusal test would pass equally on a spine that refused every
  DIDComm and TSP document outright.

  One fixture relied on an unsigned document reaching a task that declares proof
  REQUIRED: `personhood::one_member_cannot_assert_personhood_for_another` sent an
  unsigned `members/personhood/assert/0.1` over DIDComm. Left alone it would now
  stop at `proofRequired` and keep passing for a reason unrelated to subject
  binding. It signs with a real `did:key` instead. The module's other fixtures
  stay unsigned, which is correct rather than lenient: `personhood/challenge/0.1`
  declares `proof` OPTIONAL.

- **vtc**: Enforce the proof and freshness a Trust Task declares (VTI-OPS-020/021/024) ([#1659](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1659))

The VTC's Trust Task document dispatcher verified a `proof` whenever one was
  present and otherwise took attribution from the transport — including for the
  nine dispatched tasks whose own definitions declare `proof` **REQUIRED**. It
  applied no acceptance window to `issuedAt`, and the replay record it claimed
  for every document was bounded by nothing but the guard's capacity.

  That is the second of the two divergences Appendix F.2 records against this
  service (trustoverip/dtgwg-vti-spec#35). It is the one the first depends on:
  moving the 49 bearer-served tasks into the dispatcher closes nothing while the
  dispatcher does not enforce.

  `docs/05-design-notes/vtc-trust-task-proof-enforcement.md` has the argument,
  the re-derived task census and the migration path.

  ## What is now enforced, on every transport

  In `dispatch_trust_task_core`, before any handler runs, reached identically
  from REST, DIDComm and TSP — which is VTI-OPS-021's whole point:

  - **VTI-OPS-024** — an acceptance window over `issuedAt`: `max_age` 10 minutes,
    `skew` 60 seconds (SPEC §4.2's own "typically ≤ 60s"), `issuedAt` required.
    A future-dated `issuedAt` and an `expiresAt` at or before it are
    `malformedRequest`, not `expired` (SPEC §7.2 item 13 — neither was ever
    acceptable, so telling the producer to wait would be wrong).
  - **VTI-OPS-020 / §7.2 items 5b, 7a, 8, §7.3 17** — the flag-driven rules the
    *specification* declares, via `schema_index::spec_policy_for(..).enforce(..)`:
    `recipient` REQUIRED, `proof` REQUIRED, audience binding, `issuedAt`
    REQUIRED. Read off the generated bindings by URI; there is no list of task
    URIs in this repository to drift from the registry.
  - **VTI-OPS-020, the issuer binding** — a present proof must verify under a key
    the document's own `issuer` controls (SPEC §4.7). Previously a valid
    signature by *any* DID satisfied the requirement, establishing only that
    somebody signed something — which is not what `verified_signer` is read as by
    the `rooms/*` arms.
  - **VTI-OPS-025…027** — the replay record is unchanged in mechanism but now
    *bounded*. `retain_until` caps a producer-chosen `expiresAt` at
    `issuedAt + max_age + skew`, so a document stamped `expiresAt = now + 10
    years` can no longer pin an id for ten years.

  ## What is not enforced, and why

  **One client does not sign.** `openvtc-core` builds
  `join-requests/{submit,status}`, `members/{self-remove,vmc}` and
  `members/personhood/assert` with a deliberate "no `proof` is attached",
  relying on the authcrypt sender or the TSP sender VID. `pnm-browser-plugin`,
  `vtc-client` and `vta-sdk` sign on every channel.

  So the one refusal that is gated is *a missing proof where the specification
  declares one REQUIRED*: `[trust_tasks] require_declared_proof`, default
  `false`. The allowance is narrow and loud —

  - it relaxes a **missing** proof only, never an invalid one, never a missing
    `recipient` or `issuedAt`, never the audience-binding rule;
  - it applies only where the transport authenticated the sender, so a REST
    document with no proof is refused whatever the setting;
  - every waiver logs at `warn!` naming `VTI-OPS-021` and the task URI, so the
    debt is counted rather than assumed away.

  A deployment serving only the three signing clients can set it to `true`
  today and should.

  **Its removal condition is exact**: when `openvtc-core` signs those five
  documents, the default flips and the field goes with it. That is a one-line
  change here and roughly five call sites there. No upstream specification change
  is needed — `openvtc-core` already signs Trust Task documents on its vetting
  path with the same `eddsa-jcs-2022` primitive.

  **The transport cross-check (§7.2 item 6)** stays in the handlers
  (`resolve_holder`), not the spine: a spine-level comparison of in-band `issuer`
  against transport-derived sender would refuse the relayer ≠ holder shape this
  workspace supports deliberately.

  ## What the next phase must do

  1. `openvtc-core` signs. Flip the default, delete `require_declared_proof`.
     Divergence 2 closes.
  2. Bind the 49 bearer-served proof-REQUIRED tasks in `DISPATCHED_URIS` /
     `dispatch_typed`, taking authorization from the verified signer's ACL entry.
     `auth/authenticate/0.1` and `vtc/relationships/publish/0.2` already do this
     and are the model.
  3. Keep each bearer route as a documented transitional path with a stated
     removal point; the admin SPA, `cnm` and `vtc-client` need the signed path
     first.
  4. Remove them, and close the Appendix F.2 entries.

  One thing to carry into step 2: **VTI-OPS-027** requires the accepted-identifier
  record to be shared across every binding. `REPLAY_GUARD` is process-local and
  covers only the dispatcher, so a task served on both a bearer route and the
  dispatcher would have a record on one binding and none on the other.

  ## Re-derived census, and its drift

  Re-derived from `routes/mod.rs` (the single mount site) against
  `spec_policy_for`, rather than taken from the register: **95** distinct task
  URIs on REST routes, **51** declaring `proof` REQUIRED, of which two already
  verify one — so **49** are served on a bearer token, not the 48 recorded. The
  difference is exactly `vtc/invitations/deliver/0.1`, bound by #1648 after the
  entry was written. `vtc/relationships/persona/0.1` has no published spec policy
  in this build. No other drift.

  ## Why `!`

  Three shapes that were accepted are now refused on the wire, on every
  transport: a document with no `issuedAt` (or one outside a ten-minute window),
  a document missing an in-band `recipient` its specification declares REQUIRED,
  and a proof that verifies under a key the `issuer` does not control. Every
  known producer already sends what is now required.

- **auth**: Detect refresh-token reuse and revoke the session it belongs to ([#1650](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1650))

* security(auth): detect refresh-token reuse and revoke the session it belongs to

  Rotation already made a stolen refresh token worth exactly one access
  token, but it said nothing about the theft. Rotation deletes the live
  `refresh:` index, so a replayed token and a token this node never
  issued look identical — both simply absent — and the clearest sign of
  compromise, a token presented after it was spent, arrived as an
  ordinary 401 (RFC 9700 §4.14.2).

  Every rotation now leaves a `RefreshTombstone` at `rotated:{sha256}`,
  and a token that misses the live index is checked against it. No
  tombstone means a plain rejection, as before. A hit means this node
  issued the token and already spent it — theft, or one specific
  non-attack.

  That non-attack is a client whose rotation response was lost in
  flight, retrying the only token it holds. Treating it as theft would
  sign the user out on a dropped connection, so the alarm would fire for
  the routine fault while a patient attacker never tripped it. A replay
  is forgiven only when the session is alive, the replay is inside
  `refresh_reuse_grace` (default 30s; `0` disables the concession), and
  the tombstoned successor is still unspent — which holds only while the
  client demonstrably never received the response. The retry re-serves
  the same pair against the existing `token_id` and does not extend the
  refresh deadline.

  Anything else is reuse: the session is deleted, taking its live
  refresh index and so every descendant of the replayed token with it,
  and `AuthAuditEvent::RefreshReuseDetected` fires at `error!` with
  `security_alert = true` and a triage reason. Both outcomes return the
  same `RefreshTokenInvalid` a stranger's token gets, so detection is
  not an oracle for an attacker probing when to stop.

  Tombstones hold no bearer secret: the token they describe is the
  hashed key, and its successor is stored as a hash. They are reaped on
  time alone by `cleanup_expired_sessions`, at `rotated_at +
  refresh_token_ttl` — deliberately not alongside their session, since
  replay after a revocation is the case most worth catching.

  The logic lives in the canonical handler, so VTA and VTC both get it.
  The two new `SessionStore` methods have no-op defaults, so an
  out-of-tree store keeps exactly the pre-detection behaviour rather
  than failing closed on a live auth path.

- **resolver**: Refuse did:webvh resolution to non-public hosts by default ([#1448](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1448))
- **vtc-admin-ui**: Render a plugin icon as an image, not as markup ([#1442](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1442))

PluginIcon passed plugin.icon to dangerouslySetInnerHTML, putting a third-party plugin string into the document as live DOM. script-src self stops a script element in it from executing, but an onload or onerror attribute is not script-src business, and the icon reaches the shell from plugin JavaScript the shell does not control.

  A string starting with <svg now renders as an img with a data:image/svg+xml URL. Nothing inside an img executes, and img-src self data: is already in the CSP, so this needs neither a sanitiser nor a new dependency. Any other string renders as text, so markup that is not an SVG appears as its own characters rather than as elements.

  PluginIcon is exported and covered by src/App.test.tsx: an SVG carrying onload renders as an img with no on* attribute anywhere and no inline svg in the document, a legitimate SVG survives the round trip byte for byte, and non-SVG markup renders as text. The icon doc comment in plugin-api.ts now states the rendering and its consequence for authors, that an img inherits neither currentColor nor the shell 1.75 stroke width.

  A .nav-icon img rule keeps the 16px box that the .nav-icon svg rule no longer sizes.

- **auth**: Stop the challenge endpoint disclosing enrolment ([#1405](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1405))

* security(auth): stop the challenge endpoint disclosing enrolment

  `/auth/challenge` resolved the caller's ACL entry and refused when
  there was none, so a request naming an enrolled subject was answered
  and one naming an unknown subject was refused. Anyone able to guess or
  harvest identifiers could therefore ask this node which of them it
  holds authority for — the first step in targeting the people behind
  them. The disclosure is in the shape of the answer, so no wording of
  the refusal removes it.

  The ACL entry now decides what the handler does, never what it says.
  Both subjects receive an identically shaped challenge; only an enrolled
  one gets a session to redeem it against. The challenge issued to an
  unenrolled subject is unusable — authenticate finds no session — and
  redeeming it would need that DID's private key in any case, which a
  party probing identifiers it does not control never has.

  Nothing is persisted for an unenrolled subject, so the endpoint cannot
  be used to fill the session store with identifiers nobody enrolled, and
  a failing ACL store reads as absent rather than becoming an oracle of
  its own. The real error still surfaces at authenticate, where the
  caller has proven control of the DID.

  The same signal existed at the other end of the flow: every failure
  reachable without the subject's key — session not found, challenge
  mismatch, signer mismatch, stale message — rendered a distinct message
  under one status code, so an attacker holding a challenge could still
  tell an enrolled subject from an unknown one. They now render one
  message, with the variant kept for the log line.

  Implements VTI-SES-006 and VTI-SES-007. The backend hook added for this
  is defaulted, so no implementation outside this workspace has to change.



### Chore

- **deps**: Affinidi-messaging-test-mediator 0.17 ([#1896](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1896))

test-mediator 0.17 / mediator 0.36 (affinidi-tdk-rs #920) are the releases on
  vta-sdk ^0.61, the line this workspace publishes. vta-service and vtc-service
  expose the test mediator to external consumers behind an optional feature, so
  the requirement is part of what they publish: breaking for those crates.

- **deps**: Affinidi-data-integrity 0.8 / affinidi-tdk 0.22 cascade ([#1891](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1891))

Move the workspace onto the data-integrity 0.8 stack in one step:

  - affinidi-data-integrity =0.7.13 -> 0.8 (the pin is gone), affinidi-bbs 0.3 -> 0.4
  - affinidi-tdk 0.21 -> 0.22, affinidi-messaging-sdk 0.31.1 -> 0.32,
    affinidi-tdk-common 0.6.11 -> 0.7
  - affinidi-messaging-test-mediator 0.15 -> 0.16, mediator-admin/-tui 0.6 -> 0.7
  - didwebvh-rs 0.7 -> 0.8, affinidi-did-resolver-cache-sdk floor 0.8.41
  - trust-tasks-* 0.25 -> 0.26
  - dtg-credentials 0.12 -> 0.13 (the same crate on data-integrity 0.8)

  No source change. cargo tree -d shows no duplicate affinidi, trust-tasks,
  didwebvh, vta, vti or dtg crate.

- **deps**: Take trust-tasks 0.23 ([#1764](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1764))

Bump trust-tasks-rs, -capability-client, -https, -didcomm, -tsp and
  -proof to 0.23 and adapt to what the release breaks. No new spec
  versions are adopted here.

  - vta-mobile-core: CachedDidResolver no longer implements
    VerificationMethodResolver (trust-tasks-proof #637). Verify the
    approval-request proof through PurposeBound bound to assertionMethod,
    the purpose the function already requires.
  - vta-service: device/_shared now registers keyExport ([#643](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/643)), so it is
    published under `capabilities` rather than carried in `ext`. Tests
    updated to the new registry.
  - vtc-service: vetters/profile, vetters/resend and
    members/personhood/challenge now declare proof REQUIRED ([#642](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/642)). The
    proof census moves 41 -> 44 and the personhood challenge tests send
    signed documents from a real did:key member.

- **deps**: Messaging-sdk 0.27.1 + trust-tasks-rs 0.22.3; answer a mutual TSP cancel the SDK could not (Keyring VTI-38) ([#1693](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1693))

Raises the floors on top of #1690's 0.22.1 / 0.27.0 move: trust-tasks-rs and
  -proof to 0.22.3 (the git-ns family, enabled by all-specs; the rest of the
  trust-tasks-* line resolves to 0.22.3 too), affinidi-messaging-sdk to 0.27.1.
  The graph holds exactly one copy of each.

  `affinidi-messaging-sdk` becomes a workspace dependency (floor 0.27.1) in
  place of five hand-kept per-crate literals.

  SDK 0.27.1 answers a peer's §7.3 cancellation of a mutual relationship
  itself, and `reply_expected` now means "the answer is still owed", which is
  true only when that send failed. The VTA's and VTC's `handle_tsp_control`
  retried with `cancel_relationship`, which refuses `SendCancel` out of `None`
  (the relationship is already forgotten). That is the exact VTI-38 failure.
  They now use `TspOps::answer_cancellation`.

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

- **deps**: Trust-tasks-rs 0.11.10, and ten entries the specs now define ([#1102](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1102))

Ten entries close on `trust-tasks-rs` 0.11.10, which carries
  trustoverip/dtgwg-trust-tasks-tf **#261** and **#262**. Drift **14 → 4**, and
  what is left is four decisions rather than a backlog of shapes.

  ## What closes

  | entry | on |
  |---|---|
  | `config/export`, `config/import` | `personhood` on the portable snapshot ([#261](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/261)) |
  | `community/profile/show`, `update` | `CommunityProfileView` — the read-shaped view ([#262](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/262)) |
  | `endorsements/list`, `show` | `CredentialReference` — a pointer, not the credential ([#262](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/262)) |
  | `ceremonies/list` | `factsTemplate` ([#262](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/262)) |
  | `website/files/list` | `etag` ([#262](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/262)) |
  | `website/generations/list` | `deployedAt` / `sizeBytes` ([#262](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/262)) |
  | `registry/diagnostics` | the messaging and transport half ([#262](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/262)) |
  | `install/claim/start` request | `claimSecret` ([#262](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/262)) |

  Measured, not predicted: a throwaway probe walked the table printing the real
  parse error for every entry, before and after the bump.

  ## Two service changes the new shapes require

  **The credential moves off the read row.** `Endorsement.issued` now references
  `CredentialReference` — identifier and lifetime, not bytes — so a page of
  fifty endorsements no longer embeds fifty signed credentials.
  `endorsements/issue` returns the credential as a sibling, because it is the
  one call whose caller cannot get it any other way. That is the shape #1098
  reached for and got backwards: it put the credential *inside* `issued` on
  every read, having concluded the spec had nowhere else for it.

  **`deployedAt` becomes RFC 3339.** This one is a mistake in my own #262: I
  specced the member as `format: date-time` while the service sends unix
  seconds. The probe caught it — `invalid type: integer, expected an RFC 3339
  formatted date and time string`. RFC 3339 is right and the service is the
  side that moves, the same line `website/files/list`'s `modifiedAt` crossed in
  #1095. Worth noting that authoring the spec did not make me immune to
  mis-stating what the implementation does; the probe is what closed the gap,
  both times.

  ## The four that remain, and why none is a shape to fix

  1. **`install/claim/start` response + `install/claim/finish` request** — the
     schemas REQUIRE `didBindingChallenge` / `didBindingSignature`, a proof of
     possession over the candidate `did:key`. This service checks the passkey
     attestation alone and issues no challenge.

     **This is the only entry where the service is behind the spec on a security
     control**, and the fix belongs here rather than upstream. #262 deliberately
     left the requirement alone rather than deleting it so we would conform —
     that would have made this table green and the system weaker, which is the
     one trade this exercise should never make.

  2. **`auth/recognise`** — the payload is two loose credentials; this service
     takes one holder-signed VP embedding both, binding a nonce and this
     community's DID as `domain`. The VP carries holder-binding proof two loose
     credentials cannot, so the service's shape is arguably stronger. Replacing
     a required member is breaking, so it needs a `0.2` folder rather than an
     in-place edit.

  3. **`join-requests/submit`** — the response is `{requestId, status}` with
     `status` a `const: "pending"`; this service returns a four-valued verdict
     (allow / deny / refer / request_more) of which `pending` expresses one.
     Also a replacement, so also a `0.2`.

  ## Header rewritten

  `KNOWN_DRIFT_COUNT`'s doc described a 33-entry table sorted into three
  recurring shapes. All three are gone. It now describes the four decisions, and
  carries the two lessons the number cannot:

  - **Read the pin before believing a note.** Nineteen entries across #1097 and
    this PR closed on dependency bumps, because the specs had moved and the
    notes had not. This table catches the service drifting from the spec and is
    blind to the spec moving toward the service.
  - **A hand-written fixture can understate as well as overstate.** #1097's
    false green is the case that matters, and roughly twenty fixtures remain
    hand-written.

  Plus the technique: walk `table()` and print the actual error. `invalid type:
  string, expected struct IssuedCredential` is a sentence no amount of
  re-reading prose will produce.

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



### Test

- **vtc**: Check ingressed credentials against the catalog, and test validators against it too ([#1072](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1072))

* test(vtc)!: check ingressed credentials against the catalog, and test validators against it too

  Audit findings F2 and F4, together — because either alone reopens the trap. A
  shared ingress validator whose tests hand-roll their input validates the
  implementation against itself, which is the exact condition that let a handler
  match `"VerifiableEndorsementCredential"` for its entire life while nothing has
  ever issued that type.

  **One place decides what a DTG credential is.** `credentials::ingress` checks
  §Common Structure — both required `@context` entries, `VerifiableCredential` +
  `DTGCredential`, exactly one concrete subtype — and classifies through
  `dtg_credentials::DTGCredentialType`, the same catalog the issuing side mints
  from. `check_vrc_shape` becomes a call to it. The recognition path gains the
  check it never had: it classified on `type` alone, so a document carrying the
  right subtype tag and neither `@context` entry was routed as though it were a
  VEC.

  **The tests assert against catalog output, not literals.** A literal in a test
  can agree with a literal in a validator while both disagree with what any
  client sends. So the guards mint through `new_vrc` / `new_vmc` / `new_vec` and
  require the validator to accept the result. Change the catalog's wire form and
  they fail; change a validator away from the catalog and they fail; no literal
  in the file can make them pass.


