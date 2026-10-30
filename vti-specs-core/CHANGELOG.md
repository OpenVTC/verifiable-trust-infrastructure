# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
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


