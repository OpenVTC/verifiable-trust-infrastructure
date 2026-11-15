# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.9.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.9.0...vti-specs-vta-v0.9.1) — 2026-11-14


### Build & CI

- **deps**: Enforce cargo-deny bans/sources, drop unused deps, hoist shared deps, forbid unsafe ([#2708](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2708))

* build(deps): enforce cargo-deny bans/sources, drop unused deps, hoist shared deps, forbid unsafe

  pgp, openssl only via webauthn-rs 0.5, no wildcards, and
  multiple-versions = "deny" with a skip list of today's duplicates grouped by
  cause. The two advisory ignores cargo-deny reports as not detected
  (RUSTSEC-2026-0381, RUSTSEC-2024-0436) are removed, the stale [graph]
  comment rewritten, and the yanked crypto-bigint 0.7.6 moved to 0.7.11.

  ring leaves the VTA and VTC graphs; it stays only under attest-verify.

  removed from 19 crates; deliberate ones are listed under
  [package.metadata.cargo-machete] ignored. A tier-0 "manifest hygiene" CI job
  runs cargo-machete and the lint check.

  once in [workspace.dependencies]; vta-tee inherits aws-lc-rs. The five
  crypto crates carry real minimum-patch floors, enforced by
  check-workspace-version-reqs.py.

  (check-workspace-lints.py); unsafe_code = "forbid" workspace-wide, with
  the four crates that need unsafe restating the table at "deny" and
  rewritten safely. The two missing publish = false comments are added.



## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.8.0...vti-specs-vta-v0.9.0) — 2026-11-12


### Added

- **vta**: Serve vta/webs/dids/create/0.2 — DID classes, did:webs service DIDs, templates ([#2689](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2689))

Pin vta/webs/dids/create/0.2 beside 0.1 (0.1 is now marked superseded
  upstream and stays served) and serve it.

  - Every 0.2 create states a DID class (relationship | persona | service,
    VTI-KEY-190 – 193), which WebsDidRecord now keeps (`didClass`, serde
    default; a 0.1 create records none and none is inferred). Setup records
    this VTA's own did:webs identity as `service`.
  - A level-1 did:webs service DID is enabled separately from creation by
    the new `[dids] webs_service_dids` (default false,
    VTA_DIDS_WEBS_SERVICE_DIDS), the name the specification's example uses;
    off refuses `service` with serviceDidNotPermitted (CONVENTIONS 0.2 §1.1).
  - didClassConflict (§1.2): a persona/relationship DID made primary of a
    context whose primary is a service DID (this VTA's own DID, or a service
    did:webs it created) — details.requiredClass "service"; a service DID
    replacing a persona did:webs primary. The MAY rule is implemented too:
    a template whose kind names only a node (mediator, dtg-witness,
    push-gateway, trust-registry, vtc-host, room-host, ballot-box,
    did-host-*) under a class other than service.
  - DID templates (§9): template/templateContext/templateVars resolve
    context → global → built-in (the webvh resolver), variables are checked
    (templateVarsInvalid with missing/unknown), and the document is checked
    against §9.2 by a new pure checker in vta-sdk
    (`did_templates::webs::{check_key_shape, map_webs_document}`, returning
    the first failing reason and the JSON Pointers it refused, or the
    designations). The template is rendered and checked once with
    placeholder keys before any key is derived, then again with the real
    DID and keys after the inception: create_did_webs now computes the
    inception (and so the AID and DID) before writing the designations, and
    still publishes before recording anything (R2.1).
  - `resolvedMethods`, carried by VTI's node built-ins, is refused as
    documentMember as §9.2 is written (trustoverip/dtgwg-trust-tasks-tf#1164);
    the fix, should the specification honour it, is one line in
    DOCUMENT_MEMBERS, and a test pins today's behaviour. `ai-agent` and
    `room` are representable today.
  - SDK: TASK_VTA_WEBS_DIDS_CREATE_0_2, retry-safety Keyed,
    VtaClient::create_did_webs_classed, fixes for the new codes.
    pnm webs create gains --class (sends 0.2; without it, 0.1), --template,
    --template-context and --var.

  Specification choices (conservative readings):
  1. 0.2 with didClass service and setPrimary on the context holding this
     VTA's own DID: 0.2 declares no code for "a create cannot re-identify
     this node", and its serviceDidNotPermitted now means only the switch,
     so it is the framework's permissionDenied. 0.1 still answers
     serviceDidNotPermitted.
  2. A templateContext the caller may not act in is permissionDenied
     (CONVENTIONS §8), not a silent fall-through to the global scope.
  3. An unresolved placeholder is reported in templateVarsInvalid's
     details.missing (the details schema has only missing and unknown).
  4. #1164: the specification's own dtg-witness example is refused under
     §9.2 as written.
  5. Setup's own key-role identity is recorded as class service; the service
     switch gates level-1 service DIDs only (key roles are not this family).
  6. A context provisioned for a VTC, VTN or host service carries no marker,
     so §1.2 item 1's second case is not refused (gap documented in
     docs/02-vta/did-webs.md).

  The designated aliases of a did:webs also carry its did:web twin and
  did:keri form (affinidi-did-webs designates them, as for 0.1), beyond the
  specification's example responses.

  Also fixes two clippy findings on this stack (Option::replace in role-key
  rotation, an item after a test module in webs_store).

- **vti-specs-vta**: Pin vta/webs/dids/{create,get,list,update,rotate-keys,delete}/0.1 ([#2562](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2562))

The level-1 did:webs family (trustoverip/dtgwg-trust-tasks-tf#1082), so the VTA
  can serve it: generated payload and response types under
  vti_specs::vta::webs::dids::*. Nothing serves or sends them yet; the handlers
  land with the operation layer (docs/05-design-notes/did-webs-in-the-vta.md,
  step 4 wiring).



## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.7.0...vti-specs-vta-v0.8.0) — 2026-11-10


### Added

- **acl**: Purpose of use on ACL entries and memory reads (VTI-ACL-100 – 110) ([#2539](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2539))


## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.6.0...vti-specs-vta-v0.7.0) — 2026-11-09


### Added

- **vta-service**: Versioned agent memory — vta/memory/{put,delete,list}/0.2 and get/0.1 ([#2115](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2115)) ([#2520](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2520))

Serves the memory versions specified in trustoverip/dtgwg-trust-tasks-tf#1067.
  0.1 keeps working against the same store.

  The store. Memory 0.2 has application state's semantics with one
  namespace: a per-context counter that is both the `expectedVersion` token
  and the `sinceVersion` watermark, conflicts that carry the winner's view,
  tombstones reaped behind a watermark, and a version index that makes the
  change feed paginatable. `operations::memory` therefore stores items as
  application-state records, under a fixed namespace in the MEMORY
  keyspace, instead of keeping a second copy of that machinery. The
  keyspace stays memory's own, so backup, purge-on-context-delete and the
  memory capabilities are unchanged.
  - `app_state::put_measured` with `ValueMeasure`: memory measures the
    UTF-8 text of a value (as `put/0.2` says), not its JSON encoding, so a
    note full of quotes or newlines does not hit the 64 KiB cap early.
  - 0.1 rows (`mem:<ctx>:<key>`) move into the versioned layout at boot
    (`memory::migrate_legacy`). The migration is idempotent and never
    drops data: an over-cap value (0.1 had no cap) moves uncapped, and a row
    it cannot place stays where it is. Context-delete purges both layouts.
  - Memory tombstones are reaped on app-state's retention window.
  - A memory call naming a context id that is not a valid context path is
    refused, keeping the layout's prefixes unambiguous.

  The tasks.
  - put/0.2: `expectedVersion`; `versionConflict` carries `currentVersion`
    and `currentValue`, but the value is withheld from a caller holding
    `memoryWrite` without `memoryRead` (a conflict is a read).
  - delete/0.2: tombstone; optional positive `expectedVersion`; deleting
    nothing succeeds with `existed: false`.
  - list/0.2: a snapshot (prefix, cursor/limit, values by default) or the
    change feed with tombstones; `highWatermark`, `watermarkTooOld`,
    `cursorInvalid`, `filterConflict`.
  - get/0.1: up to 256 named items, answered in `items` / `missing` /
    `deferred`.
  - An access refusal is the declared `contextForbidden` on 0.2 and `get`.
    0.1 still answers `permissionDenied`.
  - 0.1 on the new store: put is an unconditional put, delete leaves a
    tombstone and still answers `notFound` when nothing was live, and list
    drains every page.



## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.5.2...vti-specs-vta-v0.6.0) — 2026-11-05


### Added

- **collection**: Collection by default is a stored setting of each trust context, with an off-only operator suspension (VTI-NTF-094 – 098) ([#2467](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2467))


## [0.5.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.5.1...vti-specs-vta-v0.5.2) — 2026-11-05


### Added

- **elections**: Check a vote after close against the head the community kept (VTI-VOT-053) ([#2460](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2460))

The VTA kept each receipt and could check it against a head and an
  inclusion proof, but nothing ever handed it either after close. Now:

  - VTA: vta/pcs/voter/receipts/list/0.1 returns the receipts kept for an
    election, whole, and the ballot box recorded at registration.
    vta/pcs/voter/read/0.7 also signs vtc/elections/tombstones/show/0.1, so a
    member can read the heads a community keeps once the election's board is
    deleted (VTI-BRD-009). voter/receipt answers notIncluded for a head too
    small to hold the cast before it looks at a path (consumer item 7.2), as
    the ballot box gives no inclusion proof for one.
  - vta-sdk: pcs_voter_receipts_list(_json); pcs_voter_read_json sends 0.7 only
    for a tombstone read, so list and show keep working against an older VTA.
  - pnm elections verify <id>: reads the head the community kept at close
    (show, or the tombstone on electionUnknown), lists the receipts, fetches
    each cast's voting/board/inclusion from the ballot box over its own
    connection, unsigned, and has the VTA check it. A cast the head omits is
    printed in red and the command fails.
  - Member portal: "Check my vote in my wallet" on a closed or tallied
    election, for a wallet that offers checkVote. The wallet answers in its
    own window; the page is told nothing.
  - Docs: pcs-engine.md step 7, elections.md.

  Pins vta/pcs/voter/read 0.7 and vta/pcs/voter/receipts/list 0.1 from the
  Trust Task PR's registry build (read 0.2/0.3/0.6 take its new deprecation
  notes); lock reset to trusttasks.org.



## [0.5.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.5.0...vti-specs-vta-v0.5.1) — 2026-11-04


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.4.0...vti-specs-vta-v0.5.0) — 2026-11-04


### Added

- **vta**: Collection for the principal's identifiers — claims, the collector, collection by default off (VTI-NTF-080 – 093) ([#2421](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2421))

* feat(vti-specs): pin vta/collection/{claim,release,list} 0.1

  From trustoverip/dtgwg-trust-tasks-tf#1023 and #1024: a client's
  collection claim on a persona DID, its release, and the listing of who
  collects for each of a context's identifiers (VTI-NTF-080 – VTI-NTF-093).



## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.3.0...vti-specs-vta-v0.4.0) — 2026-11-03


### Added

- **vetting**: Recover or reset a lost hidden-vetting key (pcs-binding/show, pcs-binding/reset, vta/pcs/vetter/recover) ([#2406](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2406))

* feat(vtc): recover or reset a lost hidden-vetting key (pcs-binding/show, pcs-binding/reset)

  A vetter is bound to the PCS identifier of their first enrolment, and a
  second identifier is refused with pcs-root:identifierRebound. The binding
  was never cleared, so a vetter whose key was lost was locked out of hidden
  vetting for as long as they stayed a member; revoking and re-granting the
  role did not help.

  - vtc/vetting/vetters/pcs-binding/show/0.1: a member reads their own
    binding (identifier, enrolled labels, any pending reset), so their client
    can recover the matching key. Membership is the entitlement;
    notAMember otherwise.
  - vtc/vetting/vetters/pcs-binding/reset/0.1: an administrator holding
    vtc.vetting.manage (as vetters/grant) resets a member's binding with a
    reason. Idempotent; notBound for a member who never enrolled. Audited as
    HiddenVetterBindingReset, never with the identifier.
  - Enrolment after a reset: the recorded identifier cancels it
    (HiddenVetterResetCancelled); a new one is refused (identifierRebound)
    while any label the old one enrolled under is live, judged at each
    request against the caller's configuration and the stored one under the
    enrolment lock, and bound once none is (HiddenVetterRebound) with its
    labels afresh. The old labels are retired on the record.
  - vtc/vetting/hidden/publish refuses to make a retired label live again,
    checked before the consent gate and again under the enrolment lock
    before the write. publish/0.1 declares no code for it, so it is a
    validation refusal.
  - Admin console: a "Reset a hidden-vetting key" card under Vetting ->
    Vetters, shown when discovery lists the task.
  - EnrolmentRecord gains optional reset and retiredLabels members; rows
    without them read and write as before.

  The two specifications are pinned from a locally built registry ahead of
  their publication; trust-tasks.lock records that registry until they are
  re-pinned against trusttasks.org.

- **notifications**: Deposit to the VTA, a community's received notifications and relay decision, and four fixes (VTI-NTF-005, 034, 041, 047, 054 – 056, 070 – 074) ([#2405](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2405))

* feat(vti-specs): pin vta/notifications/deposit 0.1 and vtc/notifications/{list,show,relay} 0.1

  From trustoverip/dtgwg-trust-tasks-tf#1017: the client's hand-over of a
  notification received for a persona DID (vti-specs-vta), and a
  community's administrators' view and relay decision (vti-specs-vtc).
  notifications/notify and relay 0.1 changed in prose only; their pinned
  digests are unchanged.

- **notifications**: Notify/relay, the VTA's held notifications and the election notice (VTI-NTF-001 – 063) ([#2397](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2397))

* feat(notifications)!: notifications/notify + relay, the VTA's held notifications, and the election notice to a member party (VTI-NTF-001 – 063)

  Implements the Notifications chapter of the VTI specification
  (dtgwg-vti-spec #91, VTI-NTF-001 – 063, Appendix G `election`) over the
  tasks pinned from dtgwg-trust-tasks-tf #1012: notifications/notify/0.1 and
  notifications/relay/0.1 (vti-specs-core), vta/notifications/{list,show,
  dismiss}/0.1 (vti-specs-vta).

  - vta-sdk: `notifications::verify_delivery` -> `VerifiedDelivery`, the one
    way to a notification's members: every layer's type and pinned schema,
    each proof over the JSON as received as its own issuer, each forwarded
    document addressed to the relay carrying it, at most four relays,
    `relayable` honoured (VTI-NTF-042). TASK_* constants, retry_safety
    (notify/relay/dismiss RetrySafe, list/show ReadOnly), typed and `_json`
    client methods for list/show/dismiss.
  - VTA: notify/relay are counterparty tasks (zero-authority claim for a
    sender the ACL does not know); the stated acceptance policy
    (`[notifications]`: an ACL entry, an issuer of a membership credential or
    a party of a relationship credential held in the context, `accept_from`,
    `accept_any`) counts the delivering relayer, never the originator
    (VTI-NTF-030/031); one record per (addressee, originator, notificationId),
    higher revision replaces, dismissal kept (VTI-NTF-022); the same receipt
    whatever was done (VTI-NTF-023); bounds per originator and deliverer
    (VTI-NTF-033); held per context in the new `notifications` keyspace
    (backed up), listed/read/dismissed only with standing there
    (VTI-NTF-050 – 052); lapsed records swept after `retain_lapsed_days`.
  - VTC as originator: an election under a credential roll naming a member
    party is notified to that party once registered and withdrawn (higher
    revision) if cancelled or closed before voting closes (VTI-NTF-060/061);
    the notice is recorded before it is sent and queued on the durable member
    push by the election sweeper, its one sender.
  - VTC as recipient and relayer: notify/relay on the open door, verified and
    held by its stated policy in its own `notifications` keyspace (backed up);
    a relay engine that refuses a decision which has not acknowledged what
    the relay discloses (VTI-NTF-046), relays the document exactly as
    received to every member, keeps whom it relayed to until the period ends
    (30 days without one) and relays every later revision, withdrawals
    included, to them (VTI-NTF-044). No remote surface for the relay decision
    yet: the specification defines no administrator task for it.
  - pnm: `pnm notifications list|show|dismiss`.

- **voting**: Credential rolls proven at the ticket claim, and elections shown only to whom they concern (VTI-VOT-015 – 018, VTI-VOT-025 – 029) ([#2395](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2395))

* build(specs): pin the credential-roll and election-privacy task versions

  voting/_shared/0.4 and every task carrying it (dtgwg-trust-tasks-tf #1008,
  #1010, #1011): voting/election/register/0.4, show/0.4;
  vtc/elections/create/0.5, show/0.6, list/0.5, tickets/issue/0.3;
  vta/pcs/voter/register/0.5, voter/read/0.6, vote/0.4, vote-encrypted/0.5,
  trustee/{deal,justify,keys}/0.5, enrol/0.4, read/0.4. Older versions stay
  pinned.



## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.2.0...vti-specs-vta-v0.3.0) — 2026-11-02


### Added

- **voting**: TextReleaseThreshold may be as low as 1, disclosed below 10 (VTI-VOT-065) ([#2379](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2379))

* build(specs): pin voting/election register+show 0.3, vta/pcs voter/vote/trustee next versions, vtc/elections create 0.4 + show 0.3

  The voting/_shared/0.3 manifest lets textReleaseThreshold be as low as 1
  (VTI-VOT-065); every task carrying the manifest moves a version. The old
  versions stay pinned; their bundles take the registry's deprecation note.



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.1.0...vti-specs-vta-v0.2.0) — 2026-10-30


### Added

- **vta**: Serve vta/webvh/dids/update/1.1 — list or remove an existing log's did:scid alias ([#2354](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2354))

* feat(vta)!: serve vta/webvh/dids/update/1.1 — list or remove an existing log's did:scid alias

  Every did:webvh log is also `did:scid:vh:1:<scid>`; the two forms are one
  subject only while the did:webvh document lists
  `did:scid:vh:1:<scid>?src=<source>` in `alsoKnownAs` (VTI-KEY-164).
  create/1.2 lists it at creation. update/1.1 (trustoverip/dtgwg-trust-tasks-tf#992)
  adds `scidAlsoKnownAs` so an operator can list or remove it on a log that
  already exists, without building the DID URL or sending a whole document.

  VTA (one handler serves 1.0 and 1.1; 1.1 extends 1.0):
  - `<source>` derived by `vta_sdk::did_scid::scid_forms` (`:` -> `/`,
    percent-encoding kept), applied to `document` or the current document.
    `true` appends unless listed and replaces a stale `src` in place; `false`
    removes every did:scid entry for the SCID.
  - `scidAliasRequired` when the VTA presents the identity as its did:scid
    (VTI-KEY-166): the `presented` flag create/1.2 records on the did:scid
    identity (`webvh_store::ScidIdentity`), or `vta_did` being this log's
    did:scid. Also refuses a supplied `document` that drops the alias, under
    1.0 too (as a validation error).
  - `noChange` when the resulting document and parameters equal the latest
    entry's: nothing published, no rotation.
  - Otherwise a document change: publishes and rotates the update key, so the
    task stays Destructive. The response reports `scidAlsoKnownAs` and
    `scidDidUrl`; 1.0 and rotate-keys responses are unchanged.
  - The did:scid identity record follows the published document, so the
    did:scid DID addresses the log exactly while the alias is listed.



## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-specs-vta-v0.1.0) — 2026-10-30


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


