# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.7.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.5...vtc-client-v0.7.6) — 2026-09-26


### Added

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

- **cnm-cli**: Cnm git link — link a forge account to the profile's DID ([#1726](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1726))

* feat(cnm-cli): cnm git link — link a forge account to the profile's DID

  A member had no CLI way to link their forge account, so the bridge could
  never give them the forge role their git rights call for.

  `cnm git link --forge <host>` sends git-ns/account/link/0.1 signed as the
  community profile's DID, prints where to authorise (and GitHub's device
  code), then polls git-ns/account/link-status/0.1 every five seconds, as
  the specification asks, until the link is linked, expired or failed.
  `--status <linkId>` follows a link begun earlier, `--no-wait` returns
  after printing, and `--list` shows the accounts linked to this DID from
  git-ns/view/0.2's `accounts`. Refusals (`unsupportedForge`,
  `unknownLink`, a non-member) print the fix.

  vtc-client gains `git_ns_link_status`. There is no unlink: the
  specification defines no task for it, and linking again replaces the
  account on that forge.

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



## [0.7.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.4...vtc-client-v0.7.5) — 2026-09-24


## [0.7.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.3...vtc-client-v0.7.4) — 2026-09-23


## [0.7.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.2...vtc-client-v0.7.3) — 2026-09-23


### Added

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



## [0.7.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.1...vtc-client-v0.7.2) — 2026-09-22


## [0.7.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.0...vtc-client-v0.7.1) — 2026-09-22


### Added

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



### Fixed

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



## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.12...vtc-client-v0.7.0) — 2026-09-21


### Added

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



## [0.6.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.11...vtc-client-v0.6.12) — 2026-09-21


## [0.6.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.10...vtc-client-v0.6.11) — 2026-09-21


## [0.6.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.9...vtc-client-v0.6.10) — 2026-09-20


## [0.6.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.8...vtc-client-v0.6.9) — 2026-09-18


## [0.6.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.7...vtc-client-v0.6.8) — 2026-09-17


## [0.6.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.6...vtc-client-v0.6.7) — 2026-09-17


## [0.6.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.5...vtc-client-v0.6.6) — 2026-09-16


## [0.6.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.4...vtc-client-v0.6.5) — 2026-09-16


## [0.6.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.3...vtc-client-v0.6.4) — 2026-09-16


## [0.6.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.2...vtc-client-v0.6.3) — 2026-09-15


## [0.6.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.1...vtc-client-v0.6.2) — 2026-09-12


## [0.6.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.0...vtc-client-v0.6.1) — 2026-09-10


## [0.5.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.5...vtc-client-v0.5.6) — 2026-09-09


## [0.5.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.4...vtc-client-v0.5.5) — 2026-09-08


### Added

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



## [0.5.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.3...vtc-client-v0.5.4) — 2026-09-07


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



## [0.5.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.2...vtc-client-v0.5.3) — 2026-09-07


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

