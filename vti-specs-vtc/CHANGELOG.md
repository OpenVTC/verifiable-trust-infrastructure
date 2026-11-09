# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.6.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtc-v0.6.2...vti-specs-vtc-v0.6.3) — 2026-11-09


### Added

- **vtc**: A member can rotate onto a did:webs (VTI-MEM-041, VTI-KEY-003) ([#2517](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2517))

Member rotation accepted did:key, did:webvh and did:scid. It now accepts
  did:webs. A did:webs document has no `#key-0`: its keys are the KERI key
  state's, identified by their CESR encoding, all in `authentication`. The
  document resolves only when the key event log verifies (VTI-LNK-052), so the
  new-DID signature is accepted from any key the document authorises for
  authentication (at most 16 are tried), each through the same purpose and
  controller check as the did:webvh path (VTI-MEM-041). A ConditionalProof2022
  entry is skipped; it is not a key.

  Re-pins vtc/members/rotate/0.1, which gained `did:scid` and `did:webs` in
  its response `method` enum in place (trustoverip/dtgwg-trust-tasks-tf#1064).
  That also fixes rotation onto a did:scid, whose successful reply
  (`method: "did:scid"`) failed the published schema and reached the member
  as an internal error.

- **vtc**: Badge claim codes for events and the automatic badge counts (VTI-BDG-015, 025 – 027) ([#2494](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2494))

Phase 4 of member badges, from the chapter (dtgwg-vti-spec #108) and the wire
  (trust-tasks-tf #1059), pinned here.

  Claim codes (`vtc/badges/claims/{create,list,withdraw,redeem}/0.1`,
  `badges::claims`):
  - An owner (or `vtc.badges.admin`) issues a code for a community badge with a
    label, a time (at most 90 days ahead) and a claim limit. The code is 256 bits
    from the CSPRNG, answered once; the community keeps only its SHA-256 digest
    (`bcdig:`), the record (`bclaim:`, indexed by badge) and a marker per member
    who redeemed it.
  - A member redeeming it is admitted as on an approved request (VTI-BDG-024):
    the claim is reserved - counted and marked under the badges lock - before the
    credential is issued, and released if the key holder fails, so a limit is
    never exceeded; then `credential::issue_with_new_award` issues the badge
    credential with a new accepted award (giver = the code's issuer) as evidence,
    offers it, and records the membership. Unknown, expired, exhausted,
    withdrawn and retired-badge codes answer `codeInvalid` alike;
    `alreadyClaimed` and `alreadyHeld` refuse a second claim.
  - Withdrawing stops a code; claims made stand. Retiring a badge withdraws its
    codes. `claims/list` never answers a code.

  Rule counts (VTI-BDG-015): an automatic badge's rule may read
  `kudosReceived`, `ideasSelected` and `electionTickets` with `atLeast` and
  `count`. `groups::check_badge_rule` admits them; `check_rule` (any other group)
  refuses them. `badges::rule_counts` counts from the community's own records at
  each recompute - accepted kudos awards, selected ideas by proposer entry,
  tickets by the member's current DID (never whether a ballot was cast).
  Accepting kudos, selecting an idea and issuing a ticket kick the dynamic
  sweeper (VTI-DIR-072).

- **vtc**: A holder shows a badge award outside the community — share, unshare, the verification location and the baked picture (VTI-BDG-070, 071) ([#2489](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2489))

* feat(vtc): a holder shows a badge award outside the community — share, unshare, the verification location and the baked picture (VTI-BDG-070, 071)

  Serves `vtc/badges/awards/share/0.1` and `unshare/0.1` (pinned in #2487) and
  answers the holder's own awards on `vtc/badges/show/0.1` (`myAwards`,
  trust-tasks-tf #1057, refreshed here).

  Sharing is the holder's own choice, award by award, for a badge marked
  `shareableOutside`:

  - `badges::share`: a 256-bit token generated for the share and derived from
    nothing (`bshare:<token>` -> award, `Award.shared` with the locations and
    `since`); a repeat share answers the same locations; `unshare` discards the
    token, revokes nothing, and a later share answers new ones.
  - What is served is the holder's credential exactly as issued: each time
    `credential::issue` signs one in the outside regime it is kept at
    `bcred:<badge>:<entry>`, so a repeat award or a renewal is served at the same
    location (share item 10). A holder whose credential predates that is issued
    it again on their first share (outside the lock, as every issue is).
  - `GET /badges/shared/<token>`: the credential (`application/vc+ld+json`) to a
    verifier; to a browser, a page saying what the community verifies of it
    (issued by it, in its validity period, its slot in the community's
    revocation list clear), with its own CSP. `GET .../image.png`: the badge's
    picture as a PNG with the credential baked into an `iTXt` chunk
    (`openbadgecredential`, Open Badges 3.0 baking). Unauthenticated,
    parent-root, let through the host-surface gate; neither names another
    holder or a count (VTI-BDG-071).
  - A share ends with `unshare`, a take-back (`awards/revoke`), retiring the badge
    and the holder's departure (`badges::on_departure`); `share::resolve`
    re-checks the award, the token and the badge on every request, so a stopped
    share answers the same `404` as a token never issued.
  - Refusals as declared: `badgesOff`, `notFound` (unknown, another's and not
    accepted alike), `notShareable` (`insideOnly` | `kudos` | `retired`),
    `publicLocationUnavailable` (no `public_url`).
  - `settle_after_revoke`'s re-issue is factored out as `reissue`, which now
    re-reads each award under the badges lock before recording the credential on
    it, so it never writes back a stale award (and its share) over a newer one.

- **vti-specs-vtc**: Pin vtc/badges/awards/{share,unshare} 0.1 (badges shown outside, VTI-BDG-070) ([#2487](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2487))

* feat(vti-specs-vtc): pin vtc/badges/awards/{share,unshare} 0.1 (badges shown outside, VTI-BDG-070)

  Pins the two tasks from trust-tasks-tf #1054: a holder shows an accepted award
  of a badge marked shareableOutside at unguessable public locations (the
  credential as issued with a verification, and a baked image), and stops.

  #1054 also added `AwardShare` and the optional `Award.shared` to
  `vtc/badges/_shared/0.1`, changing eight pinned 0.1 drafts in place
  (awards/{list,offer,revoke,withdraw}, kudos/{give,list}, mine/{accept,decline,list});
  `trust-tasks update` takes their new bytes. Additive: no field VTI sends today
  changed.

  vti-mcp-common's guard census classifies `share` and `unshare` as mutating, as
  `publish` is: the holder's own reversible choice to have the community serve
  their credential; stopping revokes nothing.

  Nothing serves the two tasks yet; the handlers follow.

- **vti-specs-vtc**: Pin vtc/badges/* 0.1 (member badges, 24 tasks) ([#2473](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2473))

Pins the Trust Task family the Community Badges chapter (VTI-BDG-001 – 095)
  binds to, as trustoverip/dtgwg-trust-tasks-tf#1052 published it: settings
  (show, update), definitions (create, update, retire, promote, list, show),
  pictures (images/upload, images/get), awards (offer, withdraw, revoke, list),
  the holder's own (mine/list, accept, decline, hide, show, arrange), walls
  (wall/show, holders/list) and kudos (give, list).

  Nothing serves them yet: this is the pin phase 1 builds on
  (docs/05-design-notes/vtc-badges.md). The groups bundles are left at their
  pinned digests; the shared Group record's new optional `badgeId` arrives with
  their next update.



## [0.6.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtc-v0.6.1...vti-specs-vtc-v0.6.2) — 2026-11-05


### Added

- **vtc-service**: Preview a network before joining it — vtc/networks/preview/0.1, the console's join form and cnm networks preview ([#2464](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2464))
- **boards**: Appoint a board's facilitators (VTI-BRD-090 – 093) ([#2459](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2459))

Serves vtc/boards/facilitators/{add,remove,list}/0.1. Any facilitator of a board
  appoints an active member to facilitate it: a resource grant of vtc.boards.manage
  at board:<boardId> on the member's own entry, beside their role, delegated by and
  bounded to the signer's own holding, so a member with no administrative role can
  run one board and nothing else. A facilitator steps down; only a holder of
  vtc.boards.manage unqualified ends someone else's appointment. When the appointer
  departs or stops facilitating the board, the appointment goes to an
  acl.grants.review item (boardGrants) and is withdrawn on decline or at the
  deadline; deleting the board withdraws every appointment to it. Every change is
  audited as BoardChanged by entry, never DID.

  The grant/review/withdraw machinery of group managers moves to
  acl::appointment and now serves both kinds; ResourceGrant::confers answers
  vtc.boards.manage for the exact board only.



## [0.6.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtc-v0.6.0...vti-specs-vtc-v0.6.1) — 2026-11-05


### Added

- **elections**: Read a deleted board's election tombstone (VTI-BRD-009) ([#2455](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2455))

A deleted board's elections each keep a tombstone (VTI-BRD-007/008),
  but nothing served it, so no voter could check a receipt against the
  community's kept heads once the board was gone (VTI-VOT-053).



## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtc-v0.5.0...vti-specs-vtc-v0.6.0) — 2026-11-04


### Added

- **vtc**: Vtc/networks 0.2, and broadcasts as vtc/networks/deliver ([#2450](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2450))

A community pins vtc/networks/* 0.2 (a registration is the signed
  vtn/groups/register request; a group's endpoint is the community's Trust
  Task endpoint) and takes a network's broadcasts as
  vtc/networks/deliver/0.1 at /v1/trust-tasks, signed by the delivering
  network, instead of the REST route /v1/networks/relay/{group_id}.



## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtc-v0.4.0...vti-specs-vtc-v0.5.0) — 2026-11-04


### Added

- **boards**: Closing a board ends its voting; delete closed boards, keeping tombstones for a set retention (VTI-BRD-005 – 008) ([#2444](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2444))

Closing a board (open → closed, or straight to archived) now ends the
  voting on it (VTI-BRD-006): each idea's election open for voting is
  closed early, so its count is final; one not yet open, or not yet
  registered, is cancelled and its idea not selected; one whose manifest
  does not allow closing early runs on, and the close answers which
  (`closing.runningToClose`). The board is stored closed first; each end
  is recorded on its election (`ElectionRecord::pending_end`) before the
  ballot box is asked, asked at once in the background, and retried by
  the elections sweeper — its one retry owner — until answered. The
  facilitator's request never waits for the ballot box. A closed board
  opens no election (VTI-BRD-005). Every board election is opened with
  `allowEarlyClose: true`, and a template stating `false` is
  `templateInvalid` (VTI-BRD-030); the console and `cnm boards init`
  starter templates allow it.

  `vtc/boards/delete/0.1` (VTI-BRD-007, VTI-BRD-008): vtc.boards.manage
  unqualified and a step-up bound to the request, spent only after every
  check passed; a board that is open is `notClosed`, one with an election
  still running `electionsRunning`. Audited before anything goes. Removes
  the board, its ideas and notes, and each election's record and ticket
  rows; each election keeps a `Tombstone` — identifier, manifest digest,
  kept board heads, never title, roll or tickets — for
  `[boards] tombstone_retention` (days, default 365; 0 keeps none;
  "forever"). The sweeper removes tombstones past their retention.

  - cnm: `boards delete <id> --reason`, `boards close` prints how the
    voting ended; refusals print the fix (close first, which elections
    run, the passkey gesture).
  - console: "Close and end voting", the closing summary in the toast,
    and "Delete board" (closed boards, board managers only) with the
    title typed, a reason, and the bound passkey gesture.
  - vtc-client: `boards_delete`. vta-sdk: the delete schemas in OpenAPI.
  - Pins vtc/boards/delete/0.1 and the updated vtc/boards/update/0.1.
  - docs/03-vtc/boards.md: closing, archiving, deleting, retention.



## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtc-v0.3.0...vti-specs-vtc-v0.4.0) — 2026-11-04


### Added

- **vtc-service**: Community boards — members propose ideas and leave notes, each accepted idea is its own election (VTI-BRD-001 – VTI-BRD-080) ([#2420](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2420))

* build(vti-specs-vtc): pin vtc/boards/*/0.1

  The thirteen Community Boards tasks (VTI-BRD-001 – VTI-BRD-080): create, update, list and show a board; propose, update, withdraw, decide and select ideas; add, list, withdraw and hide notes. Resolved against a local build of dtgwg-trust-tasks-tf feat/vtc-boards — re-pin against trusttasks.org once that publishes.



## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtc-v0.2.0...vti-specs-vtc-v0.3.0) — 2026-11-03


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

- **vtc**: A community's side of Verifiable Trust Network membership ([#2399](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2399))

* feat(vti-specs-vtc): pin vtc/networks/* 0.1

  list, show, join, repudiate, leave, groups/register, notice and evidence
  (trustoverip/dtgwg-trust-tasks-tf#1014): a community's side of
  Verifiable Trust Network membership.

- **voting**: Credential rolls proven at the ticket claim, and elections shown only to whom they concern (VTI-VOT-015 – 018, VTI-VOT-025 – 029) ([#2395](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2395))

* build(specs): pin the credential-roll and election-privacy task versions

  voting/_shared/0.4 and every task carrying it (dtgwg-trust-tasks-tf #1008,
  #1010, #1011): voting/election/register/0.4, show/0.4;
  vtc/elections/create/0.5, show/0.6, list/0.5, tickets/issue/0.3;
  vta/pcs/voter/register/0.5, voter/read/0.6, vote/0.4, vote-encrypted/0.5,
  trustee/{deal,justify,keys}/0.5, enrol/0.4, read/0.4. Older versions stay
  pinned.



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtc-v0.1.1...vti-specs-vtc-v0.2.0) — 2026-11-02


### Added

- **voting**: TextReleaseThreshold may be as low as 1, disclosed below 10 (VTI-VOT-065) ([#2379](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2379))

* build(specs): pin voting/election register+show 0.3, vta/pcs voter/vote/trustee next versions, vtc/elections create 0.4 + show 0.3

  The voting/_shared/0.3 manifest lets textReleaseThreshold be as low as 1
  (VTI-VOT-065); every task carrying the manifest moves a version. The old
  versions stay pinned; their bundles take the registry's deprecation note.

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



## [0.1.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vtc-v0.1.0...vti-specs-vtc-v0.1.1) — 2026-11-01


### Added

- **vtc**: List the trusted ballot boxes, and choose one in the manifest builder ([#2370](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2370))

Pins and serves vtc/elections/ballot-boxes/list/0.1 (trustoverip/dtgwg-trust-tasks-tf#998):
  an elections manager reads the voting services the community trusts (VTI-VOT-082), each
  with the operator and sameOperator that members are told when an election names it
  (VTI-VOT-090). The answer is read from the same live [voting] configuration create checks
  ballotBox against, so the two cannot disagree; a holder without vtc.elections.manage is
  refused with permissionDenied (VTI-VOT-080).

  - vtc-service: the handler (behind `voting`), the spine registration, a conformance
    witness, and the proof census entry (the specification recommends a proof; the
    capability check refuses an unsigned caller regardless).
  - vtc-client: `elections_ballot_boxes`.
  - cnm: `cnm elections ballot-boxes`, and the ballotBoxNotTrusted fix now points at it.
  - Console: the manifest builder's ballot-box field is a choice from the list, noting when
    the community's own operator runs the box; "Another DID…" keeps typing available, and a
    VTC that does not serve the task falls back to the typed field. A typed DID the list
    does not hold is flagged before create, since create would refuse it.



## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-specs-vtc-v0.1.0) — 2026-10-30


### Added

- **vtc**: Move a community role with vtc/members/role/set/0.1 and stop serving acl/change-role/0.1 ([#2347](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2347))

* feat(vtc)!: move a community role with vtc/members/role/set/0.1 and stop serving acl/change-role/0.1

  The community-role move (member, moderator, issuer, admin, custom roles) is
  now `vtc/members/role/set/0.1`; `acl/change-role/0.1` is no longer served,
  sent or pinned. `acl/change-role/0.2` still moves the administrative role.

  The handler makes the specification's checks 1-7 in order, each with its
  declared code: vtc.roles.assign (permissionDenied), no self-move in either
  direction (VTI-OPS-050, VTI-ACL-052), notFound, roleNotRecognized
  (details.offendingRole) / roleNotAssignable (`application` onto or off),
  stateMismatch (details.currentRole), the requester covering the entry
  (VTI-ACL-050), and fromRole == toRole answered `changed: false` with no
  gesture and no write (SPEC 7.2).

  The role-change ceremony carries items 8-18: authority follows the role
  only where it is exactly the one the current role implies;
  delegationExceedsGranter (axes); lastRoleAssigner checked before the policy
  and again under the write's lock (VTI-APV-009); the policy sees whether the
  move confers or withdraws authority and may not choose a different role
  (deniedByPolicy); the bound step-up and parked consent (VTI-OPS-051,
  VTI-APV-018/019); the compare-and-swap re-checked under LAST_ADMIN_LOCK
  (item 14); the role credential returned as roleVac; and a new
  CommunityRoleSet audit event (from/to, authority before/after, approval,
  action id, reason).

  The response is the generated type: subject, role, previousRole, changed,
  approval, entry (AclEntry 0.2) and roleVac. vtc-client's acl_change_role
  becomes members_role_set; `cnm access change-role` and the admin console
  send the new task. Approver summary templates are added for the new task
  (server and console pins); the 0.1 templates stay for history.

- **vtc**: Passkey admin invites from the console, vtc/admin/invites/{create,list}/0.2 ([#2345](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2345))

vtc/admin/invites/create/0.1 required `did`, so the console could issue only
  wallet invitations; a passkey invitation needed `vtc admin invite` on the host.
  trust-tasks-tf #989 adds create and list 0.2, which VTI now serves and sends in
  place of 0.1 (nothing outside VTI sent 0.1).

  Wire changes:
  - create 0.2: `did` optional. Present → wallet invitation (claimed with
    vtc/install/claim/{start,finish}/0.3); absent → passkey invitation (claimed
    with vtc/install/claim/passkey/{start,finish}/0.1). The response gains a
    required `kind` (`wallet` | `passkey`); `aclEntryCreated` is false for a
    passkey invitation.
  - list 0.2: every entry gains a required `kind`; a passkey invitation's
    `targetDid` is absent until consumed, then the derived DID.
  - revoke stays at 0.1.

  Behaviour (create 0.2 items 3-4): a passkey invitation records an
  install::InvitedAuthority — community administrator with the full ceiling,
  delegated by the inviter, labelled with `label` — and writes nothing to the
  ACL; passkey/finish item 9 writes it for the derived DID. Since nobody is
  present to authorise it at the claim, issuing one always costs the inviter's
  bound gesture and another unrestricted administrator's consent, parked under
  the stable subject `urn:openvtc:vtc:admin-invite:passkey`. A consumed row now
  remembers it was a passkey invitation (`Consumed.passkey`) so list can report
  its kind.

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


