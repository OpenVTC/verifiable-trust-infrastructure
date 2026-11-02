# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
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


