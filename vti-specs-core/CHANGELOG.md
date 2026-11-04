# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.3.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-core-v0.3.0...vti-specs-core-v0.3.1) — 2026-11-04


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-core-v0.2.0...vti-specs-core-v0.3.0) — 2026-11-03


### Added

- **git-ns**: The VTC speaks bridge job 0.7 and event 0.6 ([#2401](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2401))

* feat(git-ns): the VTC speaks bridge job 0.7 and event 0.6

  Pin git-ns/bridge/job 0.7 and git-ns/bridge/event 0.6 in vti-specs-core
  (replacing job 0.6 and event 0.5; test deployments only, no fallback).

  - Jobs go out as git-ns/bridge/job/0.7 only, and only to a bridge that
    lists 0.7 in trust-task-discovery (vgi-bridge v0.31.0 or later). The
    schema is unchanged from 0.6.
  - The VTC serves git-ns/bridge/event/0.6 only. A bindCompleted carrying
    supersedes records it in the namespace's audit history
    (gitNs.namespace.superseded, the bridge as actor); nothing is restored
    from those ids.
  - Orphaned namespaces, VTC step 1: git-ns:unknownNamespace is answered to
    an event only when the namespace's record is positively absent. A store
    read failure, or a record that exists but cannot be read, is answered
    with the framework's unavailable, since a 0.6 bridge stops acting in a
    namespace on unknownNamespace. A bridge result whose job record cannot
    be read is likewise unavailable, never unknownJob.

  The registry also republished git-ns/bridge/job/list 0.4 with a
  description-only change (JobKind now names job 0.7); its new digest is
  locked here.

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



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-core-v0.1.0...vti-specs-core-v0.2.0) — 2026-11-02


### Added

- **voting**: TextReleaseThreshold may be as low as 1, disclosed below 10 (VTI-VOT-065) ([#2379](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2379))

* build(specs): pin voting/election register+show 0.3, vta/pcs voter/vote/trustee next versions, vtc/elections create 0.4 + show 0.3

  The voting/_shared/0.3 manifest lets textReleaseThreshold be as low as 1
  (VTI-VOT-065); every task carrying the manifest moves a version. The old
  versions stay pinned; their bundles take the registry's deprecation note.



## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-specs-core-v0.1.0) — 2026-10-30


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

- **auth**: Answer step-ups with auth/step-up/approve-response/0.7, and stop serving 0.4 and 0.6 ([#2346](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2346))

Every step-up answer moves to approve-response 0.7
  (trustoverip/dtgwg-trust-tasks-tf#983). A user-verified WebAuthn assertion
  by the approver's own registered passkey is evidence on its own, so the admin
  console answers unsigned. A delegated key's proof never counts as the
  approver's. A didSigned or approverSigned answer, and every denial, still
  needs the approver's own proof.

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


