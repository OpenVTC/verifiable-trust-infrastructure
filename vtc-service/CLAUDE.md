# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust workspace for **Verifiable Trust Communities (VTC)**. A VTC manages a community of Verifiable Trust Agents. Unlike the VTA (which manages keys), the VTC handles community management, ACL, audit, policy (Rego), credentials, status lists, trust-registry sync, cross-community recognition, member relationships, endorsements, the public website, and the admin SPA. Part of the [First Person Network](https://www.firstperson.network/white-paper) project.

## Workspace Structure

`vtc-service` sits inside the wider workspace at the repo root. Key sibling crates:

- **vti-common** (`../vti-common/`) — Shared library: auth (JWT, passkey), ACL, store (local fjall + vsock), audit writer + HMAC key store, error types, config, pagination cursors.
- **vta-sdk** (`../vta-sdk/`) — Shared SDK: types, VTA HTTP client, DIDComm protocol surfaces, `sealed_transfer`, provision-integration.
- **vta-service** (`../vta-service/`) — VTA library + local/dev binary (key management, did:webvh, mediator).
- **vtc-service** (this crate) — VTC binary service. Community management, policy, audit, public website, admin SPA.

`vti-common` is the canonical home for cross-crate types; VTC-specific business logic lives here.

## Key Differences from VTA

- **VTC isn't the key authority.** The VTA mints the integration DID + signing keys; the VTC stores the bundle in `secrets` and signs locally for VMC / VAC / status-list issuance (cached-locally pattern). No BIP-32 here.
- **Audience-isolated JWTs.** `aud = "VTC"`; cross-audience tokens are rejected.
- **Default port** 8200 (VTA uses 8100).
- **Twenty-odd keyspaces**, not the original two: `acl`, `sessions`, `members`, `community`, `policies`, `active_policies`, `audit`, `audit_key`, `install`, `passkey`, `status_lists`, `relationships`, `relationships_by_did`, `endorsement_types`, `endorsements`, `join_requests`, `sync_queue`, `sync_cursor`, `registry_records`, `config`, plus the website filesystem. The full live list is the keyspace fields on `AppState` in `src/server.rs`.
- **VTC never targets TEE.** Permanent non-goal (only the VTA runs in Nitro Enclave).

## Source layout (high-level)

```
src/
├── acl/                ACL storage + role types (VtcRole)
├── audit/              (re-exports from vti-common::audit)
├── auth/               session, AuthClaims/AdminAuth/SuperAdminAuth extractors
├── ceremony/           Decision pipeline (facts → verify → decide → effect/audit);
│                       `assemble` (one Facts builder for every purpose) +
│                       `orchestrate` (role-change + leave spines, out of routes)
├── community/          CommunityProfile storage
├── credentials/        LocalSigner + VMC/VAC/status-list builders; `exchange/`
│                       (OID4VCI issuer + OID4VP/SD-JWT/DI/bbs verifier, split into
│                       issue/verify/pending/jwt) + `vm_resolver` (the single shared
│                       DID-VM → key resolver + `check_issuer_binding`)
├── endorsement_types/  Operator-registered endorsement-type registry
├── endorsements/       Community statement (VSC), vetter-grant and IDVC rows + status-list flip
├── install/            Install-token state machine + claim secret
├── join/               Join-request lifecycle + `orchestrate` (submit spine:
│                       holder-binding → decide → auto-admit → admit audit)
├── members/            Member storage + lifecycle helpers
├── policy/             regorus engine, default policy bundle, evaluators
├── recognition/        Foreign role-VAC verification (Phase 3 cross-community)
├── registry/           Trust-registry client + syncer + audit-log tail
├── relationships/      VRC publish/revoke
├── routes/             Every HTTP route handler, sub-mounted by feature
├── routing/            Security headers, CSRF, body cap, governor middleware
├── setup/              `vtc setup` wizard: `wizard.rs` (interactive) +
│                       `from_toml.rs` (`setup --from <toml>`, phase 2) +
│                       `phase1.rs` (`setup --setup-key-out`, mint the
│                       ephemeral key for headless two-phase bring-up).
│                       wizard + from_toml build one `WizardPlan` and share
│                       the `apply` effect driver.
├── status_list/        Bitstring status list allocator + storage + serve route
├── store/              Re-export of vti-common's keyspace abstractions
└── website/            Public website handler, bundle + deploy, default site
```

The admin SPA lives at `admin-ui/` (React + TS + Vite, baked into the binary at compile time by `build.rs` + `include_dir!`). The fallback public landing page lives at `website-default/` (plain HTML / CSS / JS, no build step).

## Operator docs

The reader-facing operator guides live under `/docs/03-vtc/`. Start there before touching code:

- `getting-started.md` — first-install walkthrough.
- `architecture.md` — keyspace + module map.
- `policy.md` — Rego authoring + activation discipline.
- `audit.md` — envelope shape, HMAC actor hashing, rotation.
- `cross-community.md` — Phase 3 recognition + trust-registry sync.
- `website-and-admin.md` — public website + admin SPA deployment.
- `admin-ui-plugins.md` — third-party plugin loader contract.

The Phase 0-5 spec is at `/docs/05-design-notes/vtc-mvp.md` — pinned decisions in §3, security invariants in §14. Section status notes flag which phase shipped each component.

## Build Commands

```bash
# Build entire workspace
cargo build

# Check compilation (faster, no codegen)
cargo check

# Run the service
cargo run --package vtc-service

# Skip the admin-UI npm build during cargo invocations (faster dev loop)
VTC_SKIP_ADMIN_UI_BUILD=1 cargo build -p vtc-service

# Run all tests
cargo test

# Run tests for a single crate
cargo test --package vtc-service

# Run a single test by name
cargo test test_name

# Lint
cargo clippy

# Format
cargo fmt
cargo fmt --check   # check only
```

### `build.rs` must only write under `OUT_DIR`

This crate is the workspace's only npm-in-build crate, and it has
already paid for breaking that rule once. Until #1243, `build.rs`
wrote two things into the source tree, and together they made
`cargo build -p vtc-service` **never** a no-op — every build, test,
clippy run and rust-analyzer check-on-save recompiled the crate from
scratch:

- `npm install` rewrote `admin-ui/package-lock.json`. Same bytes, new
  mtime — so `git status` stayed clean and nothing looked wrong — but
  the lockfile is one of the script's own `cargo:rerun-if-changed`
  inputs, so the script was dirty the instant it finished and re-ran
  on every build.
- `npm run build` regenerated `admin-ui/dist`, and `include_dir!`
  expands to one `include_bytes!` per file, making all 78 of them
  compile inputs of the lib. Each re-run refreshed their mtimes and
  forced a full recompile.

So: `npm install` goes through `run_npm_preserving_lockfile`, which
restores the lockfile's mtime when npm left the content identical —
that is the fix that closes the loop — and vite's `--outDir` points
at `$OUT_DIR` so the bundle isn't in the source tree at all. The
second is the Cargo rule rather than the bug fix, but it pays for
itself: `admin-ui/README.md` tells developers to run `npm run build`
by hand, which used to refresh 78 compile inputs and rebuild the
crate.

What does *not* work, in case it looks tempting: keeping the baked
files' mtimes stable across a re-run so the lib survives it. Cargo
rebuilds a build script's dependents whenever the script re-runs,
regardless of whether its output changed (measured, not assumed).
Not re-running the script is the only lever.

Before adding anything to `build.rs`, ask what it writes and where.
Guarded by `vtc-service/tests/it/no_rebuild.rs` and the "vtc-service
rebuild is a no-op" CI step — a cold-cache CI run never builds the
same tree twice, so nothing else would catch a regression here.

## Rust Configuration

- **Edition**: 2024
- **Minimum Rust version**: 1.95.0
- **Resolver**: 3
- **License**: Apache-2.0

## Integration flows

Moved here from the workspace `CLAUDE.md`, which keeps an index of every
flow. Each entry: what it does, the invariants to preserve, code, docs.
When adding a flow, add it here and a line to the root index.

### VTC first-boot setup (VTA-provisioned)
- **What**: Stands up a VTC by provisioning its DID + keys from a running
  VTA via the `vtc-host` DID template, then writing `config.toml`, the
  `did.jsonl`, the sealed key bundle, and a one-shot admin install URL.
  The VTC is **not** the key authority — the VTA mints; the VTC caches.
- **Entry point**: `vtc setup` (interactive) or, for headless bring-up, a
  **two-phase** flow mirroring mediator / did-hosting:
  1. `vtc setup --setup-key-out <path> [--context <id>]` — mint + persist
     an ephemeral `did:key` (0600) and print the `pnm contexts create …
     --admin-did` grant command. Reuses the shared SDK helper
     `vta_sdk::provision_client::driver::run_phase1_init`.
  2. *(out of band)* an operator / CI step holding VTA admin runs that
     grant — VTC deliberately never holds a VTA admin credential (no
     self-grant), same as mediator / did-hosting.
  3. `vtc setup --from <toml>` — load the now-authorised key
     (`setup_key_file`) and provision end-to-end (no TTY).
- **Secrets**: `[secrets] backend = "vault"|"k8s"|"aws"|"gcp"|"azure"|`
  `"keyring"|"config"|"plaintext"` selects the store explicitly (validated,
  fail-closed); omit for legacy implicit resolution. All backends except
  TEE-KMS (a permanent VTC non-goal) are supported. Factory:
  `vtc-service/src/keys/seed_store/mod.rs::create_secret_store`.
- **First administrators**: the install claim writes the first
  `community-admin` (passkey claim 0.2, or wallet claim 0.3 binding the
  plugin's approver as step-up factor); `co_admin_did` adds a second;
  `--single-admin` writes `[acl] single_admin_mode` (see *VTC administrator
  action list*).
- **Code**: `vtc-service/src/setup/{wizard,from_toml,phase1}.rs` (both
  front-ends build one `WizardPlan` → shared `apply`),
  `vtc-service/src/main.rs` (`setup` subcommand),
  `vtc-service/src/config.rs` (`SecretBackend`).
- **Docs**: `docs/03-vtc/non-interactive-setup.md`,
  `docs/03-vtc/getting-started.md`,
  `docs/03-vtc/examples/vtc-setup.example.toml`.

### VTC community-owned rooms (`vtc/rooms/community/*`, `vtc/rooms/offers/*`)
- **What**: Data rooms the community itself owns (design §8.4). The VTC is the
  owner (`ownerDid` = its DID) and host; **its own VTA is the key holder**,
  reached over `vta_link` (TSP > DIDComm, never inbound): it mints the room's
  DID from the `room` template, founds the group with the community as its only
  member, issues and vaults the community's own VMC + `admin` VAC, and later
  issues members' VIC/VMC/VAC (`rooms/owner/*` + `vault/credentials/receive`,
  unchanged VTA tasks, signed as the VTC's DID, which is a persona the VTA
  holds in `[rooms.community] context`). Members are offered admission and
  pull it (`offers/list`, `offers/accept` with a KeyPackage → Welcome), and read
  where each admission stands with `vtc/rooms/memberships/list` — the one record
  every surface (portal, `pnm`, OpenVTC) shows, beside the VTA's `rooms/keys/list`.
  Never give a surface its own record of acceptance: every step of accepting
  answers a repeat with its first answer (`key-package/0.2` returns the held
  KeyPackage, the kept Welcome, `alreadyJoined`) so any surface finishes another's.
- **Invariants to preserve**: the VTC holds no room key or group secret, and
  never falls back to one (`noKeyHolder`). Remote first: a create stores the
  room only after mint + group + credentials; an admission is recorded only
  after `group/add` answered; a removal only after `group/remove`. The owner's
  record (`community_rooms` keyspace, backed up) is **never read on the host
  path** (I5). `vtc.rooms.manage` (not `vtc.rooms.admin`) gates the admin
  tasks; changes take the requester's bound step-up and do not park. Offers
  answer only the proven signer, and only an active member. Never log or audit
  a Welcome, a KeyPackage or a credential. Absent `[rooms.community]` = off.
  Serverless room identities are served at `/room-dids/<id>/did.jsonl`.
- **Renewal** (`rooms::community_renewal`, create item 6's SHOULD): a sweeper
  reissues the community's own VMC + `admin` VAC within `[rooms.community]
  authority_renew_within_days` (default 30, ≤ half the life) and stores each
  **under the vault handle it replaces** — the VTA refuses to choose between
  two VACs for one persona, so never add one beside the other. Handles are
  recorded at create (`authority-renewal:<room>`), else found by
  `vault/credentials/query` + `get` (needs `vault-read`). Remote first: the
  owner's record's `ownerAuthorityValidUntil` is written last; the sweeper is
  the only retry owner (capped backoff + jitter); failures are `warn`ed,
  audited at the start of a run, and shown in `get`/`list`'s
  `ext["org.openvtc"].authorityRenewal`. No "renew now" task exists.
- **The room's profile** (create 0.3 / update 0.2, `rooms::community_profile`): the label
  and description — never the tags — go only to the community's own VTA in
  `rooms/keys/profile/write`, as the community, and into the room sealed; never the host
  record, a credential or `register`. A write that did not land is `pending`, never a failed
  request; the profile sweeper is its one retry owner and always writes the room as it is
  then. Needs `room-open` on the community's VTA entry.
- **Code**: `vtc-service/src/rooms/{community,community_profile}.rs`,
  `vtc-service/src/trust_tasks/community_room_tasks.rs`,
  `cnm-cli/src/rooms.rs` (`cnm rooms …`).
- **Docs**: `docs/03-vtc/community-rooms.md`.

### VTC room file migration (`vtc/rooms/storage/migrate`)
- **What**: Moves a hosted room's existing blobs onto the storage config it is
  assigned to (`data-rooms-files.md` §7.3; 0.2 served beside 0.1, each answered
  at its own version, one engine; `vtc/rooms/get/0.2` reports the migration through
  `vtc/_shared/0.1/room-migration`): copy, read back and verify against
  every chunk digest and the whole-blob digest of the committed manifest, switch,
  and the old copy deleted by collection after the orphan grace window. No key.
  `vtc.rooms.admin`, parked as `Act::ChangeStorage`; VTC-only (`room-host` has
  one config).
- **Invariants to preserve**: the switch is **one `Batch`** in `room_blobs` (entry,
  `moved:` row for the old copy, counters, plan row, record), applied only while
  the entry is byte-for-byte what it was when the copy began — never a sequence of
  writes. The target's bytes are reserved at start and converted per switch; the
  old copy counts against its config (so a `draining` config does not retire)
  until collected, never less (§6.1). Before writing a copy, a pending `moved:` row
  of the same blob on the target is reclaimed under the lock, so collection never
  deletes what a switch is about to name. The runner (`rooms::migration`) is the
  **one retry owner** (migrate/0.2 item 10): capped backoff + full jitter, `paused`
  only after `MIGRATION_MAX_ATTEMPTS` in a row (never earlier; `capacity` never,
  since the bytes are reserved at approval), then it tries again by itself at
  `nextAttemptAt` (`PAUSED_RETRY_SECS`, jittered, `resume_due`). Its pre-step check
  of the target (not `active` → `destination`, no usable store → `credential`) is
  a failed attempt like any other. A paused migration always carries `pausedCause`
  and a `lastError` scrubbed of URL queries, tokens, the room id/prefix/hash and the
  blob ref. Re-issuing the task — at either version — answers a `queued`, `running`
  or `paused` migration with itself, resuming a paused one at once, **without**
  parking, keeping its `toConfig` and `reason` (a request's rate is adopted), and
  audits the resumption with its requester. A copy that does not verify is
  `failed`, never retried. `toConfig` is fixed at approval and kept through a
  reassignment (item 9). Orphans are never planned or counted; one orphaned or
  collected while a migration is open is dropped at once by
  `drop_from_migration` — plan row + reservation before its switch, `mdone:` row
  (done and total counts) after — and `skip` adjusts only while the plan row
  exists, so nothing is counted twice. **Queueing is per target config**
  (item 13): a migration to a config with another `running`/`paused`/`queued` one
  is `queued` (bytes reserved at approval, nothing copied) and `promote_queued`
  starts it in approval order (`seq`) once those finish; 0.1 reports `queued` as
  `running`. A restore pauses a running one (`pause_after_restore`, cause
  `destination`, no `nextAttemptAt`), and the blob in flight is re-verified. A
  target retired under a move leaves it paused and retrying forever — the
  specification has no way out yet; don't invent one here.
- **Code**: `vti-rooms/src/blobs/migrate.rs`, `vtc-service/src/rooms/migration.rs`,
  `vtc-service/src/trust_tasks/storage_tasks.rs` (`handle_migrate`),
  `admin-ui/src/plugins/rooms/RoomDetail.tsx` (`MoveExistingFiles`).
- **Docs**: `docs/02-vta/data-rooms.md` (*Moving a room's files*).

### VTC member directory (`vtc/directory/*`)
- **What**: The community's field schema (`fields/*`), each member's card
  (`card/{show,update,assert}`), and browse/search/show (`entries/*`, plus the
  older `query/0.1`), every read a **projection** for its caller; pictures
  (`images/{upload,get}`), external cards (`card/{publish,public}`),
  administrators' notes (`notes/*`), the export, and credential-sourced fields
  (`card/present`). Groups are their own family (*VTC community groups*);
  introductions are a later phase (design §14).
- **Invariants to preserve**: a value leaves only where the member's own
  visibility, the field's ceiling **and** the `directory` policy all admit the
  viewer — intersected, and the policy can only narrow (`directory::project`,
  VTI-DIR-020/021). Withheld means absent; nothing visible is the same
  `notFound` as no such entry (VTI-DIR-110). A viewer's stars, lists and notes
  are never stored here (VTI-DIR-001). Administrators' notes
  (`directory::notes`, `vtc.directory.notes`) are the opposite case: kept here,
  never in a card or any projection, append-only (a redaction is a later note),
  and released to their member only by `notes/export` behind a bound step-up at
  Critical (VTI-DIR-030 – 033). A verified value (`directory::present`,
  `card/present`) is written only from a presentation whose holder is the member
  (their DID, or an SD-JWT key their DID lists and the key-binding `kid` names),
  bound by the presentation's signed `nonce` = the request `id` and `domain` =
  the community DID; only the named claims are kept, never the presentation, a
  lapsed one is hidden by `Subject::from_records` and withdrawn by the sweeper,
  and a refusal's reason is logged, never answered. A picture is stored only as the
  community's own re-encoding (`directory::images::reencode` — never a byte as
  sent, never metadata), goes only on its uploader's card, and is read only
  through the projection (`images/get`), never by digest alone. An external card
  is the member's signed JSContact card, stored and served exactly as received
  (`directory::external`); the community never composes or signs one, publishes
  only one that is exactly the member's public values in the fixed mapping,
  and **never serves a stale one**: every serving path calls
  `external::served`, which reconciles first, and a withdrawal stops serving
  before the registry pointer goes. Departure withdraws it before anything
  else (VTI-DIR-120). Entries are keyed by a random `entryId`,
  never a DID; a rotation moves only the `entry:<did>` index (VTI-DIR-050/122).
  A member writes only `member`-sourced values, an administrator only
  `admin`-sourced ones, and derived ones (`role`, `joinedAt`, `did`,
  `personhood`) are read from the ACL and member records, never stored
  (VTI-DIR-011/013). A card update older than the one in force is
  `superseded` (VTI-DIR-012). A field widening parks as
  `Act::ChangeDirectoryPrivacy` for the other holders of `vtc.directory.admin`
  (VTI-DIR-024); `directoryWrite` policy refuses values and is never asked about
  a change that only narrows. Search never matches a DID for a member, cursors
  are bound to caller and question, facet counts below *k* are never exact
  (VTI-DIR-044/112/113). Every write is audited by reference, never a value.
- **Code**: `vtc-service/src/directory/` (`fields`, `cards`, `values`,
  `project`, `read`, `write_policy`, `images`, `external`, `sweep`),
  `vtc-service/src/trust_tasks/directory_tasks.rs`,
  `vtc-service/policies/default/{directory,directory_write}.rego`.
- **The portal's key**: a member sign-in at `auth/oob/*/0.2` offers
  `signingScope: ["vtc/directory"]`; `redeem` records a delegation for `K_b`
  (`member_portal::delegation`), and the member directory tasks read a
  document `K_b` signs as the member's while that session is live
  (`Writer::Delegated`: never `public`, never external). Never let a
  delegation outlive its session, keep it alive, or cover `auth`, `acl`,
  `consent`, `task-consent` or `confirm`.
- **Docs**: `docs/03-vtc/member-directory.md`,
  `docs/05-design-notes/vtc-member-directory.md`.

### VTC community groups (`vtc/groups/*`)
- **What**: The community's groups, each with its own `did:webvh` that the
  community's VTA mints from the `vtc-group` template and holds, and a community →
  group DTG `AuthorityCredential` (`issue-membership`) the VTA signs **as the
  community** through `keys/sign-document`, with a slot in the community's
  revocation list and an expiry. Served: `create`, `update`, `delete`, `list`,
  `show`, `members/{add,remove,list}`, `join`, `leave`, `requests/{list,decide}`
  `managers/{add,remove}` for **static** and **dynamic** groups, and
  `bindings/{add,remove,list}` for **room**, **grants** and **role** bindings.
- **Dynamic groups** (`groups::dynamic`, VTI-DIR-011/103): members are
  whoever the rule admits over verified facts (role, `admin`/`credential`
  fields — re-checked against the schema at every evaluation — personhood,
  join date), less **opt-outs** (`gopt:<groupId>:<entryId>`, written by
  `leave`, withdrawn by `join`, never overridden). The sweeper is the one
  recompute owner (5-minute tick, kicked by `admin_events::notify` on
  `Members`/`Directory` and by create/update/join): admits with source `rule`,
  credential first, and ends rule-sourced memberships the rule no longer
  admits. `members/add|remove` refuse `dynamicGroup`; a dynamic group stores
  `closed`, answers no `joinPolicy`, and never carries authority
  (`groupNotEligible`, and `authority::rows_for` skips it).
- **Room bindings** (`groups::bindings`): a manager holding `vtc.rooms.manage`
  binds a community room, after the bound gesture `members/add` takes (never
  parked). The reconciler is the one owner of every effect: it offers each
  active group member admission through the normal offer path (recorded only
  after the VTA answered), keeps `MemberRecord::sources` (`gb_…` ids, plus
  `direct` for an administrator's admission), owes a `LeftGroup` removal
  through `rooms::departures` when no source is left — never removing a direct
  admission — and renews bound admissions into `offers/list/0.3` `renewals`
  (membership + authority, never an invitation; the renewed `validUntil` becomes
  the admission's own).
- **Group grants** (`acl::group_grant`, `groups::authority`, VTI-DIR-100 – 105):
  what a `grants`/`role` binding confers is written onto each member's entry as
  `groupGrants` rows (one per capability × binding, naming the group), and
  every gate still asks `VtcAclEntry::can`. A row counts only inside the
  member's role ceiling and while it may act — **at read time**, so a role
  change that brings one into force is a conferral `newly_conferred` sees
  (`VtcAclEntry::conferring` counts rows) — and confers nothing to approve.
  `authority::provision` is the one writer (git-ns write lock; `acl/*` writes
  keep the rows as stored); it writes only what the binding's delegator holds
  **not through a group**, nothing for a group that is not `closed`, keeps a
  suspended member's rows, and is run by the binding reconciler each pass. The
  tasks gate every change (VTI-DIR-104): binding an authority-conferring
  capability and adding a member are `Act::GroupAuthority` (subject
  `group:<id>` or the member), removing a member is `settle_reduction_as(
  Act::ReduceGroupAuthority)` (cooling-off included), removing the binding or
  deleting the group is one group-wide `Act::ReduceGroupAuthority` whose
  approvers exclude every group member (unopposed: gesture + `Critical` per
  member, no cooling-off). Their requester is the group's manager, so
  `requester_still_authorized` asks `vtc.groups.manage`, not an admin role.
  Nothing is recorded while parked; the approval re-runs the handler.
- **Where identities are published** (`did_hosting`): the runtime key
  `dids.webvh_server` (`local` or a VTA hosting-server id; `config/patch`,
  import, the Groups page) is read live at every group and community-room
  mint and overrides each kind's `webvh_server`; unset, those apply. It never
  moves an identity already minted, and is not consent-gated.
- **Renewal** (`groups::renewal`, create item 5's MUST): a sweeper renews a
  group's authority within `[groups] authority_renew_within_days` (default
  `max(30, credential_valid_days)`, ≤ half the life) **in the slot it already
  holds** (deletion's one bit revokes every authority it was issued), and each
  active member's credential within a third of its life, offered with the
  current authority. Remote first; the sweeper is the only retry owner
  (`grenew:` schedules, capped backoff + jitter); no "renew now" task.
- **Invariants to preserve**: the VTC holds no group key and never falls back to
  one (`noKeyHolder`). Remote first: a group is stored only after its DID and its
  authority exist; a served log is published before anything verifies against
  the DID and withdrawn when a later step fails. Who manages a group is
  `vtc.groups.manage` on the live ACL entry — unqualified for every group and
  creating, or a resource grant `group:<groupId>` — never the group's record. A
  group the caller may not see is `notFound` on every task, like one that does
  not exist; `memberCount` only where `showMembers` admits the caller,
  `managers`/`credentialAuthorityValidUntil` only to managers. A dynamic rule
  reads only verified facts (role, `admin`/`credential` fields, personhood, join
  date), never a `member`-sourced field. The group's DID document carries no name
  or description. The `groups` policy only refuses. Audit by reference. A
  member's group credential is a DTG `MembershipCredential` the VTA signs **as
  the group** (`keys/sign-document`, the group's own key), issued and offered
  **before** the membership is recorded, with no status list (expiry is the
  revocation). The directory's `groups` audience counts only groups both belong
  to whose member list the viewer may see (`groups::audience_groups`). Departure
  ends every membership and withdraws pending requests (`groups::on_departure`,
  before the card's own departure). Nobody decides their own request. A
  manager's appointment is a resource grant written under the git-ns write lock
  (so `acl/*` writes keep it); a granter who departs or no longer covers it
  sends it to an `acl.grants.review` item (`groupGrants`), withdrawn on decline
  or at the deadline (`groups::managers::sweep`).
- **Code**: `vtc-service/src/groups/` (`mod`, `identity`, `policy`),
  `vtc-service/src/trust_tasks/group_tasks.rs`,
  `vtc-service/policies/default/groups.rego`, `vta-sdk/templates/vtc-group.json`.
- **Docs**: `docs/03-vtc/groups.md`.

### VTC administrator action list (`vtc/admin/actions/*`)
- **What**: Second-party consent at the VTC. An operation that needs other
  administrators' agreement — an authority-conferring grant or admin invite
  (VTI-APV-018), a reduction of another administrator (APV-019), lowering the
  consent threshold (APV-020), authority policy (VTI-VTC-022), a custom role
  define/delete, a restore's commit, any change to the trusted-witness list
  (VTI-CMP-090), to a join criterion (`vtc/schemas/accepts/{register,delete}`,
  kind `join.criteria.change`; hidden vetting's `vtc/vetting/hidden/{publish,withdraw}`,
  kind `join.criteria.hiddenVetting`) or to the personhood policy (kind
  `policy.recognition.change`; VTI-APV-023) — is **parked** after the requester's
  operation-bound step-up (202 + `trust-task-next-step` naming the action) and
  **runs itself on the N-th approval**, every check re-run against the
  community as it is then (APV-017). The same list holds `coolingOff` items (a
  reduction nobody but requester and subject could approve; lands after
  `acl.removal_cooling_off`, cancellable by the requester only) and
  `acknowledge` items (each offline ACL write, VTI-VTC-023, record type
  `vtc/operator/offline-write/0.1`).
- **Invariants to preserve**: an approval is a `task-consent/decision` signed
  by the approver's **own DID** (wallet or `cnm`), never a console key;
  `webauthn` / `approverSigned` evidence rides beside it, never instead. The
  requester never approves, nor the subject of a reduction. One decline closes
  an action. Execution is crash-safe (`executing` + effect record, reconciled
  by the minute sweeper). **Single-administrator mode** (VTI-APV-022, `[acl]
  single_admin_mode`) is host-only (setup writes it; `config/patch` / import
  refuse it), waives a consent only when the approver set is **empty**, on the
  requester's bound step-up, always `Critical`-audited and bannered; it never
  skips a reduction's cooling-off. Never widen it to a non-empty set or make
  it patchable.
- **Code**: `vtc-service/src/admin_actions/`,
  `vtc-service/src/acl/{admin_consent,single_admin}.rs`,
  `vtc-service/src/trust_tasks/action_tasks.rs`, `cnm-cli/src/actions.rs`.
- **Docs**: `docs/03-vtc/admin-access.md` §2–3,
  `docs/05-design-notes/vtc-action-list.md`.

### VTC member portal (`/members`, `/v1/member/*`)
- **What**: Where a community's members sign in — a separate application from
  the console, enforced by the daemon, not by what the page shows. Sign-in is
  the **trigger-link key grant** (`auth/oob/*` on `/v1/trust-tasks`,
  `trust_tasks::oob_tasks` + `member_portal::oob`: the browser's
  non-extractable `K_b` opens a request, a wallet claims it with a throwaway
  `K_a`, proves membership and the on-screen number, and returns a grant
  signed by the member's DID naming `K_b`; only `K_b` redeems it), a portal
  passkey, or — **deprecated** (contract C7) — SIOPv2 issued by the member's
  VTA (wallet `walletProfile` + `proxyLogin`, against
  `<origin>/v1/member/wallet`). Never the extension's self-issued `login()`,
  which presents its own `did:key`. For `auth/oob`: the ACL string check comes
  before any DID resolution; every state change is a compare-and-set under one
  process lock; a failed step from the lock holder declines the request; step
  1 and 2 responses are signed for `assertionMethod`; `identify` is verified
  for `authentication`, `grant` for `assertionMethod`.
- **Invariants to preserve**: only an **active member** (live ACL entry, not
  expired/suspended/`application`, member record not removed) signs in, and
  that is re-read on every request and refresh — never trusted from the
  session. Portal tokens carry audience `VTC-member`; console extractors
  validate `aud = VTC`, so the two never cross — do not add a shared audience
  or make a console extractor accept both. Portal sessions and passkeys live in
  `member_sessions` / `member_passkeys`, never `sessions` / `passkey`: that is
  what stops a member-who-is-also-an-admin from redeeming a portal refresh
  token, or a portal passkey, at the console. Portal cookies are
  `Path=/v1/member` (`vtc_member_csrf` is `Path=/`), and the CSRF gate pairs
  them by path. Adding or removing a portal passkey requires a wallet-proven
  session (`amr` contains `did`). The bundle imports no console shell, plugins
  or API client. The console's login page uses the same `auth/oob/*` flow
  with `ext["org.openvtc.session"].audience = "admin"`: the audience is fixed
  at `request`, signed into step 1 and step 2 (so the grant's
  `contextDigest` covers it), and `redeem` issues exactly that audience's
  session — the console's (`routes::auth::mint_admin_cookie_session`, ACL
  admin role read now) or the portal's, never the other. Never let a
  member-audience request reach the console minter, and never read an
  unreadable audience as `admin`.
- **Data rooms in the portal** (`src/members/Rooms.tsx`, `wallet-rooms.ts`):
  the pages talk only to the member's wallet (`window.vtaWallet.rooms`, the
  extension's P7b channel), which acts as the member's persona through their
  VTA. Never add a `/v1/member/*` route that carries room content, a
  presentation or a key, and never import the extension's code: the wallet's
  gates (the page is the `SignInPortal` origin, rooms the member shared, each
  write confirmed) are the authorization (`data-rooms-files.md` §8.5).
- **DID self-check**: `did_self_check` resolves the VTC's own DID (boot +
  5-minute lazy cache) and warns when the published document lacks
  `TrustTaskHTTPS` / `SignInPortal`; `GET /v1/member/sign-in/config` carries
  `didDocument` (`ok` / `missing` + types / `unknown`) and the sign-in pages
  hide the code when it is `missing`. Advisory only: never blocks boot, and a
  resolution failure is `unknown`, never `missing`.
- **Code**: `vtc-service/src/member_portal/`, `vtc-service/src/routes/member_portal.rs`,
  `vtc-service/src/routing/{csrf,host_dispatch}.rs`, `vtc-service/src/admin_ui.rs`
  (`MEMBER_UI_DIR`), `vtc-service/admin-ui/src/members/` +
  `vite.members.config.ts`, `vtc-service/website-default/` (the landing page
  that links to it).
- **Docs**: `docs/03-vtc/website-and-admin.md` (*Member portal*).

### VTC direct admission (`vtc/members/admit`, `vtc/members/make-membership`)
- **What**: An administrator admits a DID without a join request — *Add a
  member* (new ACL entry + member record + VMC/role VAC, as a completed join),
  or *Make this a membership* for an ACL entry with no member record (the
  bootstrap administrator), which writes the record and credentials and leaves
  the entry untouched.
- **Invariants to preserve**: it is a ceremony (`PolicyPurpose::Admission`,
  `vtc.admission`, authority-deciding): `refer` parks it as
  `Act::DirectAdmission` for another holder of `vtc.members.manage` (never the
  requester or subject), `deny` refuses. Host checks the policy cannot widen:
  `vtc.members.manage`; a non-`member` role takes `vtc.roles.assign` and
  `granting::check_write` (the invitation rule); `admin` and
  authority-conferring roles are never seated; an administrative role takes the
  bound gesture; `application` entries and removed records are refused for
  make-membership. Wire types, document policy and error codes are the
  generated `trust_tasks_rs::specs::vtc::members::{admit, make_membership}`
  (trust-tasks-tf #784); a payload is schema-checked before it is parsed, so an
  out-of-schema `subject` / `role` is `malformedRequest`, never
  `roleNotPermitted`.
- **Code**: `vtc-service/src/ceremony/admission.rs`,
  `vtc-service/src/trust_tasks/admission_tasks.rs`,
  `vtc_client::members`, `cnm-cli/src/members.rs` (`cnm members
  {admit,make-membership}`),
  `vtc-service/policies/default/admission.rego`,
  `admin-ui/src/plugins/members/Admission.tsx`.
- **Docs**: `docs/03-vtc/community-lifecycle.md` (*Admitting a member
  directly*).

### VTC trusted witnesses (`witnesses.trusted`)
- **What**: The witnesses whose Verifiable Witness Credentials (`witnessed/1`
  statements, issued by `vti-witness`) count in a community. Community
  configuration — `[witnesses] trusted` or the runtime key `witnesses.trusted`
  via `config/patch` / `vtc/config/import` (`vtc.config.admin`, audited
  `ConfigChanged`, marked `trust_semantics`) — no Trust Task family of its own.
- **Invariants to preserve**: **every runtime change parks** — add, remove or
  relabel (only a reorder is no change) — as `Act::ChangeTrustedWitnesses`
  (kind `config.witnesses.change`) for the other holders of `vtc.config.admin`,
  pinned to the list in force; single-administrator mode waives it only on the
  requester's operation-bound step-up, at `Critical`. Never let a witness-list
  write reach `patch_config` / `import_inner` past
  `acl_tasks::settle_witness_list_gate`, and never let it share an action with
  a threshold lowering (refused). Empty (the default), unreadable or corrupt
  means **no** witness is trusted. The host settles one verdict per VWC in a fixed
  order — trusted witness (`untrustedWitness`), then outcome evidence of the
  cited session paired by the framework's four checks plus VWC identity
  (`noOutcomeEvidence` / `outcomeInvalid`, VTI-CMP-023), then the digest
  binding — so every later state implies the earlier checks passed and no
  policy can accept what the host refused (VTI-VTC-022). Evidence rides
  `outcomeEvidence` on `vtc/members/personhood/assert/0.2` only (the `evidence`
  `vta/witness/accept` returns; 0.1 and its `ext` stop-gap are not served), read
  as received, and an entry's terminal type is the one its session document's own
  version declares (`submit/0.1` for a 0.1 session, `/0.2` for 0.2, never
  crossed); the join paths carry none, so a VWC meets no criterion there. Never compare witness DIDs other than verbatim,
  never let a community list its own DID.
- **Code**: `vtc-service/src/credentials/{trusted_witnesses,witness}.rs`,
  `vtc-service/src/config_store.rs`, `vtc-service/src/routes/members/personhood.rs`,
  `vtc-service/src/join/criteria.rs`.
- **Docs**: `docs/03-vtc/trusted-witnesses.md`.

### VTC step-up: passkeys and approver devices
- **What**: Authority-changing VTC acts need a step-up bound to a digest of
  that one operation (`acl::bound_step_up`, one use within 300 s). It is
  answered by a passkey, or by a **step-up approver** — an Ed25519 `did:key`
  bound to the subject, such as the browser plugin's per-community approver
  identity (`approveStepUp`) — whose statement is carried in an
  approve-response signed by the subject's own DID (VTI-APV-015).
- **Invariants to preserve**: every enrolment rests on an anchor independent of
  the subject's signing key — install claim 0.3, another administrator's
  invite, a factor already held, or `vtc admin enrol-approver` offline — proves
  possession, and is audited with `enrolledVia` (VTI-APV-016). Nobody invites
  themselves; a revoked approver DID is never bound again. Once a subject holds
  a dedicated factor, their session passkeys stop counting. A
  console-key-signed answer is `subjectMismatch`.
- **Code**: `vtc-service/src/acl/{bound_step_up,approver}.rs`,
  `vtc-service/src/step_up_approver.rs`,
  `vtc-service/src/trust_tasks/step_up_approver_tasks.rs`.
- **Docs**: `docs/03-vtc/admin-access.md` §3.1,
  `docs/05-design-notes/vtc-approver-step-up.md`.

### VTC role-based administration (`acl/*/0.2`, `vtc/roles/*`)
- **What**: VTC authority is capabilities (optionally resource-qualified)
  bounded by an administrative role's ceiling; built-in roles plus **custom
  roles** stored in the `acl` keyspace (`role:<name>`). Every gate asks the
  live entry (`VtcAclEntry::can`); a custom role is resolved from its stored
  definition on every read, and an entry naming an undefined role confers
  nothing (VTI-ACL-011).
- **Invariants to preserve**: `vtc/roles/define|delete`, authority-conferring
  grants, reductions, threshold lowering, authority policy and a backup
  restore's commit all park in the action list; approvers are read off
  **approve scope** (`admin_consent::may_approve`), so the least-privilege
  `approver` counts. A role's ceiling is bounded by its requester's **and
  approvers'** holdings. A departed (removed, narrowed or expired) granter's
  grants become one `acl.grants.review` action; the delegation sweeper is the
  backstop. Git grants (resource grants beside the role) go to review only on
  the granter's departure from the community, never on a narrowing. `acl/swap-key/0.1` is the only self-modification: same authority,
  link proof from the new key, audited before the atomic move, delegations
  re-pointed.
- **Code**: `vtc-service/src/acl/{capability,roles,granting,delegation,admin_consent}.rs`,
  `vtc-service/src/trust_tasks/{acl_tasks,role_tasks}.rs`,
  `vtc-service/src/admin_actions/`.
- **Docs**: `docs/03-vtc/admin-access.md`, `docs/05-design-notes/vtc-admin-roles.md`.

### VTC admin console live channel (`vtc/admin/events/*`)
- **What**: An open admin console learns *when* to re-read — the action list,
  acknowledgements, join requests, members, single-administrator mode, the
  configuration, (0.2) the rooms pages, (0.3) the directory and groups
  pages, and (0.4) the community rooms pages — without polling every read on a
  timer. One stream per console session; polling stays the fallback. 0.1 – 0.4
  are served, each stream answered at its own version; the topic set is closed
  per version (`rooms` from 0.2, for `vtc.rooms.admin`; `directory` and
  `groups` from 0.3, for `vtc.directory.{admin,notes}` and
  `vtc.groups.manage`; `communityRooms` from 0.4, for `vtc.rooms.manage` —
  `vtc.rooms.admin` alone does not qualify). `groups` is fingerprinted over the
  groups the recipient manages, so a manager qualified to one group is never
  hinted about another; `directory` is coalesced to one hint per ten seconds;
  `communityRooms` is fingerprinted over what the owner's reads
  (`vtc/rooms/community/{list,get}`, `members/list`) show, so a `rooms` seam
  that moves nothing they show is no hint.
- **Transport**: HTTPS binding 0.3 §2.1 **streamed responses** — the signed
  `vtc/admin/events/subscribe/0.1` document POSTed to the ordinary
  `/v1/trust-tasks` door with `Accept: text/event-stream, application/json;q=0.5`,
  answered `200 text/event-stream` with the signed `#response` as the first
  event and `vtc/admin/events/event/0.1` documents after it (one per `data:`
  line, no `event:` field, SSE `id` = resume token, heartbeats as comments).
  Why SSE and not TSP/DIDComm: the console is a browser holding only a console
  key, and no other binding defines a streamed response — a subscribe arriving
  any other way is `streamUnavailable`. Why `fetch` and not `EventSource`:
  every (re)connection must be a freshly signed POST; resumption is in-band
  `since` only (`Last-Event-ID` is a cross-check, mismatch → `malformedRequest`).
- **Hints only — the invariant**: an event carries `topic`, `at`,
  `resumeToken` and, on `actions` / `acknowledgements` / `joinRequests`, the
  recipient's `count`. Never a record, a record id or a DID, in any member
  including `ext`. The console re-fetches the topic's own signed read, so
  authorization stays on every read and the stream needs no model of its own.
  Do not "optimise" a hint into carrying the changed row: that is the moment
  the stream needs per-record authorization and diverges from the reads.
- **Invariants to preserve**: refusals are JSON and open no stream; nothing
  but hints and heartbeats after the `#response` (never a `trust-task-error`);
  standing is re-checked on every ACL change, before every hint and once a
  heartbeat, and a shrink **ends** the stream rather than dropping a topic; the
  stream ends no later than the signer's ACL entry / console-key delegation /
  document `expiresAt`, and within an hour; caps 5 per administrator, 256 in
  all (`tooManyStreams`); the subscribe's response is never recorded for
  redelivery (a replay answers `204`); the bus is fed from storage seams
  (action save/delete, join-request store/delete, member store/delete, ACL
  store/delete, config override and profile writes, storage-config writes,
  `vti_rooms::observe`'s hook for room registration/renewal and holdings
  or limit writes, the directory's and groups' own writes, and every
  `community_rooms` write the owner's reads show — `rooms::community::changed`,
  after the record lands) and carries no row data; `rooms` is fingerprinted (rooms, lifecycle state,
  80/95/100 % bands, configs) so only rule-4 changes hint, and
  a stream wakes itself at the next clock-driven lifecycle change;
  no lock across an await (R1.3); the console's live status is derived from
  bytes arriving, never latched (R6.2).
- **Code**: `vtc-service/src/admin_events/` (bus, tokens, caps, standing,
  stream), `vtc-service/src/trust_tasks/event_tasks.rs` (the subscribe
  handler), `vtc-service/src/routes/trust_tasks.rs` (Accept negotiation, the
  stream slot), `admin-ui/src/lib/{live-events,use-live-events}.ts`,
  `admin-ui/src/components/LiveIndicator.tsx`, `cnm-cli/src/actions_watch.rs`
  (`cnm actions watch`).
- **Docs**: `docs/03-vtc/website-and-admin.md` (*Live updates, and polling as
  the fallback*).

### VTC git namespaces (`git-ns/*`)
- **What**: A VTC governs repositories on the forges it has bound — who may
  create them, who owns each, whose commits its CI check accepts — and
  publishes those rights to its Trust Registry. The VTC is the source of
  truth; the registry and the forge (through a per-community bridge) are
  projections of it.
- **Wire**: the `git-ns/*` Trust Tasks, generated types under
  `trust_tasks_rs::specs::git_ns`, served on the document dispatcher. Authority
  is the proof signer's **git rights**, read at execution time — never a bearer
  token, and never the community-admin role (whose community-wide
  `git.ns.admin` only binds, reseats a headless namespace and ratifies). **One
  authority model (VTI-VTC-020, phase C3):** a git right is a *resource grant*
  on the holder's ACL entry (`acl::resource_grant`) — `git.ns.admin`,
  `git.repo.manage` graded `create`/`own`/`maintain`, or `git.commit.sign`,
  qualified by `git-ns:<forge>/<owner>` or `git-repo:<forge>/<owner>/<repo-id>`,
  each with its own `delegatedBy`. There is no separate rights store: `git_ns::
  store::{get,put}_rights` and `Snapshot::load` read and write the entries
  (through a `git-holder:` index in the `acl` keyspace), and the fixed rules run
  over that. Grants sit beside the administrative role, never in its ceiling;
  `acl/*` writes keep them (`routes::acl::commit_grant` re-reads them under the
  git-ns lock) and must never drop them. A grant is also bounded by the
  granter's entry (`resource_grant::granter_covers`, VTI-ACL-071). A non-member
  holding a grant (the bridge, an external signer) gets an entry of community
  role `application` — never a membership, never signs in, never an elevated
  right, not assignable by any caller — removed with its last grant. Removing
  an entry tombstones its grants (`git-departed:`) for the lifecycle to record;
  a departed granter's grants go to `acl.grants.review` (`gitGrants`) and are
  withdrawn at the deadline. The old `rights:*` rows are migrated at boot and
  on backup import (`git_ns::migrate`); unmappable ones are kept inert under
  `rights-unmapped:*` with an acknowledge item. The admin REST routes (`/v1/git-ns/*`) are read-only
  console projections; the administrator's view, namespace and repository
  listings and break-glass list are signed reads (`git-ns/view/0.5`,
  `git-ns/namespace/list`, `git-ns/repo/list` in `git_ns::admin_reads`),
  answered to a namespace's administrators only, never to a bearer session.
- **Invariants to preserve**: the fixed rules of `git-ns/right/grant` live in
  `git_ns::rules` and run before the `gitNamespace` policy, which can only
  refuse; rights are keyed by repository id, not name (a rename moves them, a
  new repository at the old name inherits nothing); the projection withdraws
  before it publishes, and publishes the implied `git.commit.sign` of every
  `own`, `maintain` and `ns.admin`; a grant's `reason` is never published or
  audited. Grant and revoke are served at 0.3 only (no 0.1/0.2), repo/create
  at 0.3: an implied `repo.create` (from `ns.admin`) carries no creator
  ownership. Elevated rights go only to, and only from, ACL-backed members.
  **Separation of duties** (grant 0.3 rule 7): no elevated self-grant
  through any task; the only way is `git-ns/right/break-glass` (`git_ns::break_glass`),
  which always takes an operation-bound passkey step-up, is audited at
  `AuditSeverity::Critical`, and is announced to every other administrator —
  policy may disable, delay or tighten it, never quieten it. An unratified
  break-glass record never counts toward the last-owner/last-admin invariants.
  In single-administrator mode, where nobody else could make the grant, rule 7
  is instead waived for that one operation (`git_ns::single_admin`, a
  `Waivable` token the rules accept for exactly that self-grant), and that
  record does count.
  Each unratified one is also an action-list `queue` item for the namespace's
  other administrators (`admin_actions::queues`): Ratify/Revoke call
  `right_ratify`/`right_revoke` as the decider, it never expires into
  acceptance, nobody cancels it, and it closes however the record ends.
  A member who is no console user answers that step-up with a **step-up
  passkey** (`step_up_passkey`, `auth/passkey/enroll/invite/0.2` `purpose:
  stepUp`), served only as Trust Tasks on the spine
  (`trust_tasks::step_up_passkey_tasks`). It is enrolled only through a
  community admin's single-use invite (signed, with a bound gesture) plus its
  claim code, redeemed by a `redeem/start` **signed by the invited member**
  (`cnm git enrol-step-up-passkey`); kept in its own keyspace login never
  reads; accepted only by `acl::bound_step_up` for its own current member; and
  never instead of a proof — every approve-response is signed by its subject
  (the console hands a no-key member an answer code for `cnm` to sign).
  A namespace admin gets no forge role: role projection (`bridge::highest_repo_rights`) counts only rights held in the person's own
  name, sends an admin with none as `git.ns.admin` (no role), one entry per
  account, and never a namespace-level `projectRoles` job. Jobs are
  `git-ns/bridge/job` 0.5 to a bridge that lists 0.5 in
  `trust-task-discovery`, else 0.4 (`bridge::send_versioned`); never
  downgrade, and `closePullRequest` (the pull-request gate,
  `git_ns::pr_gate`) is never sent to a bridge without 0.5.
- **Code**: `vtc-service/src/git_ns/` (`rules`, `ops`, `tasks`, `projection`,
  `bridge`, `lifecycle`), `vtc-service/src/routes/git_ns.rs`,
  `cnm-cli/src/git.rs`, `vtc-client/src/git_ns.rs`.
- **Docs**: `docs/03-vtc/git-namespaces.md`.

### VTC capability modules (`governance/capability/*`)
- **What**: A community's pluggable governance capabilities (`git-trust`
  first) — listed by its members, enabled and disabled by its administrators.
  Not ACL capabilities (`vtc.config.admin` …): keep the two apart in names,
  types and audit text (`capability_modules`, "capability module",
  `CapabilityModuleChanged`).
- **Invariants to preserve**: the VTC is the source of truth and the Trust
  Registry a projection — a decision is persisted (community keyspace) before
  the projector tells the registry, as its admin, over the registry client's
  TSP > DIDComm selection; the projector is the only retry owner, records an
  answer only against the generation it sent, treats `alreadyEnabled` /
  `notEnabled` as success, and surfaces a refusal as `failed` + an audit row
  while still retrying at the cap. `enable`/`disable` take `vtc.config.admin`
  and a step-up bound to the document (destructive class), never the action
  list (they confer no ACL authority). `list` answers members and admins only,
  as the generated `#response` that `trust-tasks-capability-client` parses.
  The git-trust manifest is a copy of the registry's, pinned by a test.
- **Code**: `vtc-service/src/capability_modules/`,
  `vtc-service/src/trust_tasks/capability_module_tasks.rs`,
  `vtc-service/src/registry/{client,messaging}.rs`
  (`project_capability_module`).
- **Docs**: `docs/03-vtc/trust-registry.md` (*Capability modules*),
  `../design-docs/vtc-capability-modules.md`.

### VTC community elections (`vtc/elections/*`, feature `voting`)
- **What**: The community as **registrar** of its polls, surveys and elections
  (VTI-VOT-001 – 100): create from a manifest, list/show, close, cancel, and issue each party
  the roll admits one ticket, blind. The ballot box is a `vti-voting-service`, never the VTC.
- **Invariants to preserve**: the community never handles a ballot, and the ballot box never
  learns who holds a ticket — nothing here may carry one to the other. The ballot box is
  reached over TSP > DIDComm as the community (`elections::link`, `PeerTasks`), never HTTPS
  (VTI-VOT-005). Remote first: `registered` / `closed` / `cancelled` only after the ballot box
  answered; a registration it has not answered is redelivered by `elections::sweeper`, the one
  retry owner; cancel stops issuance durably **before** it asks. Tickets: one per party per
  election, recorded before answering, one critical section (`Elections::issue_lock`); the
  audit row never carries the request's identifier, commitment or pre-credential. Unknown and
  unseen are the same `electionUnknown`. A binding election parks as
  `Act::CreateBindingElection` (VTI-VOT-081). The voting key is HKDF from the signer's master
  (`vtc-voting-pcs-secret/v1`), unrelated to hidden vetting's. The trusted ballot boxes are
  host config (`[voting] trusted_ballot_boxes`, VTI-VOT-082). `certify` reads everything from
  the ballot box, never the requester, and re-verifies the board from the community's own key
  (`vti_voting::audit`); auditors' attestations are evidence beside it, never instead. A trustee
  step counts only as a `trusteeStep` entry carrying the trustee's signed request as received,
  its proof verified by the reader (`vti_voting::steps::ProvenRequests`, CONVENTIONS §9.6); the
  election key `show` carries is formed by the community from those steps alone, never taken
  from `voting/trustees/status`, which carries no proof.
- **Code**: `vtc-service/src/elections/`, `vtc-service/src/trust_tasks/election_tasks.rs`,
  `vtc-service/tests/it/election_tasks.rs`.
- **Docs**: `docs/03-vtc/elections.md`.
