# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.20.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.20.0...vti-specs-v0.20.1) — 2026-11-28


### Added

- **hcp**: Pin the hcp/* 0.1 suite in vti-specs-hcp (A1) ([#2859](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2859))

HCP V0 task A1 (docs/05-design-notes/hcp-tasks.md): pins the seven hcp/*
  0.1 tasks V0 speaks in vti-specs-hcp: hcp/grants/{request,revoke,revoked},
  hcp/entries/{query,create}, hcp/audit/read and hcp/disclosures/summary. The
  bundles are as published at trusttasks.org, digests in the lock, and
  trust-tasks-build 0.3.0 generates every one. vti-specs re-exports the family
  as vti_specs::hcp and merges its index; the six generated tables stay
  disjoint.

  Pinned is not served: nothing dispatches an hcp/* task until A8 wires the
  handlers behind the `hcp` feature. The one census that holds every pinned
  request URI, vti-mcp-common's verb classification, gains `revoked`
  (hcp/grants/revoked, a provider's revocation notice) as mutating, beside
  `granted` and `notice`.

  The suite is `draft`, so a version may change in place upstream:
  `trust-tasks -C vti-specs-hcp check` is what says a re-pin still matches.



## [0.20.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.19.0...vti-specs-v0.20.0) — 2026-11-28


## [0.19.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.18.0...vti-specs-v0.19.0) — 2026-11-28


## [0.18.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.16.0...vti-specs-v0.18.0) — 2026-11-24


## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.15.0...vti-specs-v0.16.0) — 2026-11-18


### Added

- **vta**: Every DID the VTA holds through one method-neutral surface (vta/dids/*) ([#2763](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2763))

* feat(vta)!: every DID the VTA holds through one method-neutral surface (vta/dids/*)



## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.14.0...vti-specs-v0.15.0) — 2026-11-15


## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.13.0...vti-specs-v0.14.0) — 2026-11-14


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.12.0...vti-specs-v0.13.0) — 2026-11-12


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.11.0...vti-specs-v0.12.0) — 2026-11-10


## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.10.0...vti-specs-v0.11.0) — 2026-11-09


## [0.10.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.9.0...vti-specs-v0.10.0) — 2026-11-05


## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.8.0...vti-specs-v0.9.0) — 2026-11-05


## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.7.0...vti-specs-v0.8.0) — 2026-11-05


## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.6.0...vti-specs-v0.7.0) — 2026-11-04


## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.5.0...vti-specs-v0.6.0) — 2026-11-04


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.4.1...vti-specs-v0.5.0) — 2026-11-04


## [0.4.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.4.0...vti-specs-v0.4.1) — 2026-11-03


### Added

- **vti-specs-vtn**: Generated vtn/* 0.1 wire types, re-exported as vti_specs::vtn ([#2412](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2412))

The Verifiable Trust Network's own Trust Tasks (trustoverip/dtgwg-trust-tasks-tf#1020),
  pinned in a fifth generated crate so vti-vtn and vtn-service can depend on it alone.



## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.3.0...vti-specs-v0.4.0) — 2026-11-03


### Added

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



## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.2.0...vti-specs-v0.3.0) — 2026-11-02


## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-v0.1.0...vti-specs-v0.2.0) — 2026-10-30


## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-specs-v0.1.0) — 2026-10-30


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


