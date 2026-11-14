# vtc-service decomposition — a plan, and where it stops

**Status:** plan. Nothing in it has landed. Every number below was measured on
`origin/main` at `6cf8ad034` (2026-11-14); re-measure before acting on a step,
because the crate grows by a feature a week.

`vtc-service` is the largest crate in the workspace by a factor of three. It
holds the community's whole product: membership, join and vetting, the ACL and
administrative roles, git namespaces, data rooms, groups, boards, badges,
elections, the directory, the trust-registry syncer, OID4VP, step-up, the
member portal — and the service's own spine (Trust Task dispatch, HTTP routes,
messaging, setup, the binary). Everything recompiles when anything changes, and
nearly every test runs inside one lib test binary that has to link all of it.

[vta-service decomposition](vta-service-decomposition.md) is the precedent and
the rulebook: its technique, its test for whether an extraction is worth doing
([What LOC is and isn't measuring](vta-service-decomposition.md#what-loc-is-and-isnt-measuring)),
and its stopping rule ([Where this stops](vta-service-decomposition.md#where-this-stops))
all apply here unchanged. Read it first. This note does not restate them; it
applies them to the VTC, and the honest answer it reaches is different from the
VTA's: **far less of the VTC is extractable, and the first two steps are worth
more than any extraction.**

## The crate, measured

| | Lines |
|---|---|
| `src/` (412 files) | 274,735 |
| — of which in-file test modules (lower bound) | ~71,700 |
| — non-test `src/` | ~203,000 |
| `tests/` (129 files) | 89,118 |
| **Total `.rs`** | **363,853** |

Tests: 2,286 `#[test]` / `#[tokio::test]` functions in `src/` (compiled into the
lib test binary) and 1,498 under `tests/`. The VTA was 114k when its
decomposition began.

### Modules by size, and how coupled they are

"Files on `AppState`" counts files that name `AppState` at all. "Imports from"
lists the other top-level modules a module names as `crate::<module>`, which
includes test-only and doc-link uses — so it overstates runtime coupling, and
the candidate sections below separate the two.

| Module | Lines | Files | Files on `AppState` | Imports from (other modules) |
|---|---:|---:|---:|---|
| `trust_tasks/` | 55,945 | 48 | 42 | 47 modules — effectively all |
| `routes/` | 29,653 | 62 | 56 | 50 modules — effectively all |
| `git_ns/` | 27,086 | 26 | 15 | acl, admin_actions, auth, backup, ceremony, community, config_store, credentials, hooks, join, member_portal, member_push, members, messaging, outbound, policy, registry, routes, server, status_list, store, trust_tasks |
| `rooms/` | 15,998 | 18 | 9 | acl, admin_events, ceremony, config, groups, members, outbound, policy, routes, routing, server, store, trust_tasks, vta_link |
| `acl/` | 11,719 | 19 | 8 | admin_actions, admin_events, auth, backup, ceremony, config_store, credentials, directory, elections, error, git_ns, groups, member_portal, members, policy, routes, schemas, server, step_up_*, store, trust_tasks |
| `credentials/` | 11,536 | 24 | 5 | acl, ceremony, config, config_store, member_push, policy, recognition, registry, relationships, rooms, schemas, server, setup, status_list |
| `vetting/` | 7,913 | 11 | 9 | 15 modules |
| `admin_actions/` | 7,662 | 4 | 3 | 19 modules |
| `registry/` | 7,524 | 11 | 1 | capability_modules, config, credentials, directory, hooks, members, messaging, outbound, policy, trust_tasks |
| `ceremony/` | 6,865 | 15 | 10 | 24 modules |
| `directory/` | 6,791 | 14 | 4 | 18 modules |
| `setup/` | 5,792 | 6 | 0 | config, credentials, install, keys, secure_file, server, store |
| `join/` | 4,775 | 6 | 3 | 20 modules |
| `groups/` | 4,007 | 9 | 9 | 16 modules |
| `policy/` | 3,874 | 6 | 0 | acl, ceremony, credentials (doc and test only — see below) |
| `oid4vp/` | 3,681 | 7 | 3 | 11 modules |
| `elections/` | 3,585 | 7 | 4 | 12 modules |
| `badges/` | 2,984 | 6 | 4 | 10 modules |
| `routing/` | 2,904 | 6 | 1 | 10 modules |
| `community/` | 2,420 | 6 | 0 | admin_events |
| `members/` | 2,379 | 5 | 1 | 11 modules |
| `recognition/` | 1,902 | 3 | 0 | acl, credentials, registry |
| `status_list/` | 1,256 | 4 | 0 | credentials |
| 17 smaller modules | 19,491 | — | — | — |
| top-level files (`server.rs` 3,350, `test_support.rs` 2,925, `config.rs` 2,807, `messaging.rs` 2,127, `step_up_approver.rs` 1,678, …) | 26,993 | 33 | — | — |

214 of 412 source files name `AppState`.

Two things stand out. **The spine is a third of the crate**: `trust_tasks/` and
`routes/` alone are 85,598 lines (31% of `src/`), and both import from
effectively every other module. And **almost every domain module imports
upward** — from `routes`, `trust_tasks`, `server`, `ceremony` or
`admin_actions` — which is the coupling an extraction has to cut, and why
"takes no `&AppState`" is a much weaker property than it sounds.

### `AppState`

`pub struct AppState` (`src/server.rs:52`) has **87 public fields**, of which
**52 are `*_ks: KeyspaceHandle`**. It is built as a struct literal twice
(`server.rs:1096` in `run`, `test_support.rs:769` in the fixture), so every new
keyspace is a three-site edit. `pub async fn run` (`server.rs:461`) is one
1,576-line function.

Grouped by the subsystem that owns each field:

| Subsystem | Fields |
|---|---|
| Sessions, auth, install | `sessions_ks`, `passkey_ks`, `install_ks`, `install_signer`, `install_store`, `jwt_keys`, `webauthn` |
| Members, join | `members_ks`, `member_count_cache`, `join_requests_ks`, `consumed_invitations_ks`, `invitations_ks` |
| Community, config | `community_ks`, `config_ks`, `config` |
| ACL, step-up, console | `acl_ks`, `console_keys_ks`, `step_up_marks_ks`, `step_up_passkeys_ks`, `step_up_approvers_ks` |
| Admin actions | `admin_actions_ks` |
| Policy | `policies_ks`, `active_policies_ks` |
| Credentials, status lists | `status_lists_ks`, `credential_signer`, `x509_trust_anchors` |
| Trust registry | `registry_records_ks`, `sync_queue_ks`, `sync_cursor_ks`, `registry_client`, `registry_health`, `registry_drift`, `syncer_health` |
| Capability hooks | `hooks_queue_ks`, `hooks_cursor_ks`, `pending_replies` |
| Relationships | `relationships_ks`, `relationships_by_did_ks`, `publish_rate_limiter` |
| Endorsements, schemas | `endorsement_types_ks`, `endorsements_ks`, `schemas_ks` |
| Vetting (incl. hidden) | `vetting_revocations_ks`, `vetter_profiles_ks`, `vetting_pcs_spent_ks`, `vetting_pcs_issue_ks` |
| Member portal, pushes | `member_sessions_ks`, `member_passkey_ks`, `member_pushes_ks` |
| Notifications, boards, badges | `notifications_ks`, `boards_ks`, `badges_ks`, `badge_images_ks` |
| Directory, elections | `directory`, `elections` |
| OID4VP | `oid4vp_keys_ks`, `oid4vp_signers`, `oid4vp_sessions_ks` |
| Rooms | `rooms_ks`, `room_records_ks`, `room_epoch_links_ks`, `room_revocations_ks`, `room_watches`, `room_files`, `room_storage`, `community_rooms`, `room_limiters` |
| Git namespaces | `git_ns` (already a `GitNsHandles` — see step 2) |
| Audit | `audit_ks`, `audit_key_ks`, `audit_checkpoint_ks`, `audit_writer` |
| Backup | `backup_bundles_ks` |
| Messaging, transport | `outbox_ks`, `tsp_relationships_ks`, `accepted_ids_ks`, `atm`, `didcomm`, `did_resolver`, `secrets_resolver`, `tsp_reach`, `large_document_budget` |
| Process, network | `public_url`, `shutdown_tx`, `supervisor`, `geoip`, `did_self_check` |

The pattern step 2 generalises already exists in seven places: `git_ns`
(`GitNsHandles`: three keyspaces plus the bridge client), `room_files`,
`room_storage`, `community_rooms`, `room_watches`, `directory` and `elections`
each own their keyspaces behind one field.

### The keyspace registry already exists — inside the crate

`src/store/keyspaces.rs` (606 lines) is already the VTC's `vta-keyspaces`:
**61 names** in `ALL`, partitioned into `BACKED_UP` (37) and
`EXCLUDED_FROM_BACKUP` (24), with `backup_partition_is_total` and
`all_has_no_duplicates` tests. 27 source files name `keyspaces::`. Two
weaknesses, both of which steps 1 and 2 fix:

- `all_matches_app_state_keyspace_count` claims to pin `ALL` to the `AppState`
  keyspace fields, but asserts a literal (`ALL.len() == 61`) beside a comment
  that is already stale (it says "48 top-level `*_ks` fields"; there are 52).
  Nothing ties the number to the struct.
- `backup.rs`'s `backed_up_handle` maps each `BACKED_UP` name back to an
  `AppState` field by hand (a 38-arm `match`), held to the list by a separate
  test. It is a second copy of the partition.

Seven names are re-exports of constants `vti-rooms` owns (`ROOMS`, `ROOM_RECORDS`,
`ROOM_EPOCH_LINKS`, `ROOM_REVOCATIONS`, `ROOM_WATCHES`, `ROOM_BLOBS`,
`ROOM_BLOB_TRANSFERS`).

## What an extraction has to buy

The VTA's three goals — compile-unit granularity, independent testability,
narrow dependency surfaces — apply as written. The VTC adds one specific to it:
**a crate below `vtc-service` escapes `build.rs`**, which runs `npm` for the two
web bundles unless `VTC_SKIP_ADMIN_UI_BUILD=1`, and escapes the 2,286-test lib
binary. A subsystem's tests in its own crate build and run without the admin
UI, without `vtc-service`'s feature matrix, and without linking 275k lines.
That is the strongest argument for any step below, and the one each step's PR
should quantify.

**No compile-time measurement exists yet.** The VTA note's last lesson is that
nobody measured; do not repeat it. Step 0 is a baseline.

## The plan

Each step is one PR (or a short series), behaviour-neutral, with the
VTA's techniques: pure move behind a re-export facade, enabling moves,
dependency inversion, tests move with the code.

### Step 0 — a baseline

Record, on one machine, in the PR description of step 1:

- `cargo build -p vtc-service --timings` (clean, default features), and the
  `vtc-service` unit's own time from the report;
- an incremental `cargo test -p vtc-service --lib --no-run` after touching
  `src/policy/engine.rs`, and again after touching `src/rooms/handlers.rs`.

Each later step re-runs the incremental number for the module it moved. If a
step does not move it, say so in its PR — that is the evidence the stopping rule
needs.

### Step 1 — `vtc-keyspaces`, a dependency-free leaf

Move `src/store/keyspaces.rs` to a new crate `vtc-keyspaces`, the VTC
equivalent of `vta-keyspaces`: the 61 `const` names, `ALL`, `BACKED_UP`,
`EXCLUDED_FROM_BACKUP`, and the two partition tests. `vtc-service` keeps
`pub use vtc_keyspaces as keyspaces;` in `store/mod.rs`, so the 27 call sites
do not change.

- **Blocker: the seven `vti-rooms` re-exports.** A dependency-free leaf cannot
  `pub use vti_rooms::ROOMS_KEYSPACE`. Restate them as literals in
  `vtc-keyspaces` and add a test *in `vtc-service`* (which depends on both)
  asserting each equals the `vti-rooms` constant. The names are on-disk
  partition identifiers — a wire contract — so the literal and the test are
  the right shape, not a workaround.
- **Leave `all_matches_app_state_keyspace_count` behind** in `vtc-service`; it
  is about `AppState`, not about the names. Step 2 replaces it.
- Why first: every later crate opens its own keyspaces and must name them
  without depending on `vtc-service`. This is the leaf they all sit on, as
  `vta-keyspaces` is for the VTA's subsystems.

### Step 2 — per-subsystem store structs, inside `vtc-service`

Before extracting anything that takes `&AppState`, give each subsystem its own
state. Replace the 52 `*_ks` fields with structs grouped as in the table above
— `MembersStores`, `AclStores`, `PolicyStores`, `RegistryStores`,
`VettingStores`, `RoomsStores`, `AuditStores`, `MessagingStores`, … — each:

- built by one `fn open(store: &Store) -> Result<Self, AppError>`, so `run` and
  the test fixture call the same constructor instead of repeating a literal;
- declaring `const KEYSPACES: &[&str]` (its names from `vtc-keyspaces`) and a
  `fn handle(&self, name: &str) -> Option<&KeyspaceHandle>`.

That replaces two hand-kept lists with structural checks: the census becomes
"the union of every struct's `KEYSPACES` equals `vtc_keyspaces::ALL`, with no
overlap" (replacing the literal 61), and `backed_up_handle` becomes "ask each
struct", deleting the 38-arm `match`. `GitNsHandles` is the model and stays as
it is (its `acl_ks` is a second handle on `ACL`, which the census must allow).

Then move functions, one subsystem per PR, from `&AppState` to the narrowest
struct they need (`&RoomsStores`, `&AclStores`). This is the step that makes
any later extraction possible: a function that takes `&AppState` cannot leave
the crate, and one that takes `&PolicyStores` can. It is also the step with
value even if nothing is ever extracted — a subsystem's tests can build its
stores from a template database (`vti_common::store::test_fixture`) without the
87-field fixture.

Split `run` in the same series: open stores → build clients and signers →
build `AppState` → spawn background tasks → build routers → serve. Each phase a
function, with no behaviour change.

`AppState` does not go away; it becomes the holder of the store structs and the
service-wide handles (config, messaging, signers, shutdown).

### Step 3 — the candidates, in order

#### 3a. `policy/` (3,874 lines; 2,199 of them tests; 78 tests)

The cleanest candidate. Its **runtime** imports are `regorus`, `vti_common`,
`serde`, `uuid`, `chrono`, `sha2` and its own submodules; the `crate::ceremony`
and `crate::credentials` uses are inside test modules (`default.rs:912`, `:1681`)
and `crate::acl` is a doc link. Its rego bundle is `include_str!`-ed from
`vtc-service/policies/` and moves with it (the new crate's `include` must list
it).

- **Blocker: #2577 first.** `vtc-service/src/policy/engine.rs` and
  `vta-policy/src/engine.rs` are two copies of the bounded regorus wrapper
  (the three limits, `CompiledPolicy`, `compile`, `evaluate`). Extracting the
  VTC copy into its own crate would make the duplication permanent across two
  crates. Land #2577's shared engine (generic over the id type) first; then
  `vtc-policy` is the VTC's model, storage, default bundle and evaluators on
  top of it.
- The tests that use `ceremony::Verdict` stay in `vtc-service` as integration
  tests of the two together; they are not policy-engine tests.
- Consumers: `routes`, `trust_tasks`, `ceremony`, `registry`, `join`,
  `directory`, `rooms`, `git_ns`, `admin_actions`, `acl` (`PolicyPurpose`) —
  all upward, so the facade keeps them resolving.

#### 3b. `status_list/` (1,256 lines; 19 tests) — enabling move first

One runtime dependency: `credentials::LocalSigner`. `LocalSigner`
(`credentials/signer.rs`, 778 lines) in turn reaches `setup::bundle`
(`for_own_keys(…, &OwnKeyMaterial)`). So:

- **Enabling move:** invert the signing through a small trait the status list
  needs (sign a credential as the community), implemented by `LocalSigner` in
  `vtc-service`; or move `LocalSigner` and `OwnKeyMaterial` down together if a
  second consumer below the spine appears.
- On its own, 1.3k lines is below the bar. Fold it into whichever crate takes
  the credential plumbing (3c), or leave it.

#### 3c. `recognition/` (1,902 lines; 41 tests) — needs two enabling moves

Not dependency-free. It imports `credentials::proof_set` and
`credentials::vm_resolver` (360 lines that depend only on each other) and
`registry::{TrustRegistryClient, RegistryError}`.

- **Enabling moves:** `proof_set` + `vm_resolver` to the lowest crate that
  needs them (a `vtc-credentials-core` holding them and, if 3b chose it,
  `LocalSigner`); the `TrustRegistryClient` trait and `RegistryError` to the
  registry crate of 3d.
- Do it after 3d, or not at all.

#### 3d. `registry/` — the pure half only

`registry/` names `AppState` in one file, but it is **not** a zero-coupling
module: `syncer.rs` (1,481) needs `members`, `directory`, `policy`, `config`;
`messaging.rs` (1,826) needs `messaging`, `outbound`, `hooks`, `credentials`,
`trust_tasks`; `tail.rs` (863) and `policy.rs` (401) need `policy`. Those are
service glue and stay.

The pure half — `client.rs` (718, needs only `capability_modules`), `model.rs`,
`storage.rs`, `health.rs`, `drift.rs`, `upstream.rs`, about 2,840 lines — could
form `vtc-registry` once `capability_modules`' type it reads is moved down or
inverted. It is the home for `TrustRegistryClient`, which unblocks 3c.

#### 3e. `acl/` — the data model, not the module

The AppState-taking files are operations, and stay: `admin_consent.rs`
(2,079), `bound_step_up.rs` (1,646), `approver.rs`, `appointment.rs`,
`delegation.rs`, `migrate.rs`, `single_admin.rs`.

The core — `entry`, `role`, `roles`, `capability`, `granting`,
`resource_grant`, `group_grant`, `storage`, `console_key`, `elevation`, `mod`,
about 5,600 lines, none naming `AppState` — is what every gate reads
(`VtcAclEntry::can`). Its blockers:

- `capability.rs` → `policy::PolicyPurpose`: solved by 3a (`vtc-acl` depends on
  `vtc-policy`).
- `resource_grant.rs` / `storage.rs` → `git_ns::model::{Right, BreakGlassMark,
  SingleAdminMark}`: **a cycle**, since `git_ns` imports `acl` from 18 files.
  Enabling move: those three types into `vtc-acl` (rights are resource grants
  on an ACL entry, so they belong with it), re-exported from `git_ns::model`.
- `storage.rs` → `admin_events::notify_authority()` (four calls, a global
  broadcast): dependency inversion — a notify hook the service installs.
- `roles.rs` → `routes::acl::NO_ADMIN_ROLE`: a constant in the wrong layer;
  move it into `acl` (part of #2574's direction).
- **#2580 first.** The `AdminActor` type belongs in this crate and replaces the
  synthetic `AuthClaims` that reads as super-admin. Land it inside
  `vtc-service`, then extract; the extraction must not carry a type change.

#### 3f. `git_ns/` and `rooms/` — the large self-contained domains

`git_ns/` (27,086 lines, 283 tests, 300 uses of `state.git_ns`) is big but not
self-contained: `bridge.rs` (2,809) needs messaging and outbound, `ops.rs`
(2,645) and `lifecycle.rs` need `admin_actions`, `projection.rs` needs
`registry` and `hooks`. Its pure core is `model`, `rules`, `role_map`, `wire`,
`view` and `store` (about 3,900 lines). Extracting the whole module needs
`admin_actions` inverted, which is orchestration — so the realistic target is
**the pure core into `vtc-git-ns`, after 3e** (it needs `vtc-acl`), with
`ops`/`bridge`/`projection`/`lifecycle` staying as the service's git-ns
operations. Name the incremental-build win from step 0 before doing it.

`rooms/` should **not** become a `vtc-rooms` crate. Its handler layer
(`handlers.rs` 4,013, `files.rs` 1,095) duplicates `room-host`'s, and #2575
moves the shared bodies into `vti-rooms` (or `vti-rooms-host`) behind a
`RoomHost` trait. That *is* the rooms extraction. What stays in `vtc-service`
is the `RoomHost` implementation and what only a community has:
`community*.rs`, `departures.rs`, `vta_access.rs`, `vta_storage.rs`,
`storage_configs.rs`, `migration.rs`. Step 2's `RoomsStores` is the natural
thing the VTC's `RoomHost` implementation wraps.

## How the related issues fit

In order. In-crate restructuring lands before the extraction that depends on
it, because an extraction PR must be a move.

1. **#2568 — `AuditEvent` out of `vti-common`.** Independent of everything
   here, and worth doing first for its own reason (every VTC feature
   republishes the layer-0 crate). Its destination matters to this plan: the
   VTC's variants must go to a **leaf `vtc-audit` crate**, not into
   `vtc-service`. Every subsystem emits audit events; a variant inside
   `vtc-service` would be unreachable from `vtc-policy`, `vtc-acl` or
   `vtc-git-ns`, and would block step 3 entirely. (`vta-audit` is the
   precedent.)
2. **Steps 0–2** (baseline, `vtc-keyspaces`, store structs, `run` split).
3. **#2577 — one regorus wrapper.** Before 3a.
4. **#2579 — split `trust_tasks/mod.rs`** (9,089 lines) into per-family files.
   Spine work: it never leaves `vtc-service`. Do it as a pure move first, then
   standardise routing on `AsyncDispatcher`. It goes before #2574 so the
   handlers are moved once, as files, before their bodies change.
5. **#2574 — `routes/` stops being the operations layer.** Moves the `*_inner`
   operations into their domain modules over the generated payloads and deletes
   the REST-era body/query types. This is what removes most of the upward
   `crate::routes::` imports (316 across `trust_tasks`, `admin_actions`,
   `ceremony` and `join`, plus `acl/roles.rs`, `acl/admin.rs`,
   `rooms/community_lifecycle.rs`) — a precondition for extracting any module
   that names `routes`.
6. **3a `vtc-policy`.**
7. **#2580 — `AdminActor`**, then **3e `vtc-acl`**.
8. **3d `vtc-registry`** (pure half), then **3c** if still wanted, with **3b**
   folded in.
9. **#2575 — shared rooms handlers** with `room-host`. Can run in parallel with
   6–8; it depends only on step 2's `RoomsStores` (to keep the VTC's
   `RoomHost` implementation small).
10. **3f `vtc-git-ns`** (pure core), if step 0's numbers justify it.

## Publishing

- **`vtc-service` publishes as a binary**, with the two web bundles in its
  `include` list. A published crate's whole dependency closure must be
  published, so **every crate this plan creates must publish** — exactly as the
  VTA's subsystem crates do, and for the same reason.
- Add each to `EXCLUDED` in `scripts/semver-report.sh` beside the VTA's
  subsystem crates: their APIs have no consumer, so a semver report on them is
  noise. Name the reason in the comment there.
- `vtc-service`'s `include` covers `/src/**`, `/policies/**`,
  `/website-default/**` and the bundles. `vtc-policy` takes `policies/` with it
  and needs its own `include` (or none — the default is the crate directory).
  Check every `include_str!` outside tests in a moved module against the new
  crate's package with `cargo package --list -p <crate>`.
- The `fuzz` crate is a library consumer of `vtc-service`
  (`credentials::exchange::*`). Facades keep its paths resolving; if a facade
  is later removed, re-point the fuzz targets in the same PR.
- **Each new crate is a workspace-wide edit**, checked by CI:
  - root `Cargo.toml` `members` and `default-members`;
  - a `COPY` line in `Dockerfile.nitro` (`scripts/check-nitro-copies-every-member.py`);
  - the root `CLAUDE.md` crate map (regenerate with
    `python3 scripts/check-docs.py --write`) and a row in its crate table;
  - every "**N of M crates publish**" line in `CLAUDE.md`, `RELEASING.md` and
    `docs/04-reference/workspace-engineering-notes.md`
    (`scripts/check-docs.py` fails on a stale count);
  - path-dependency version requirements
    (`scripts/check-workspace-version-reqs.py`);
  - a `CLAUDE.md` and `README.md` in the crate.
- Never edit `version =`; release-plz assigns the first version.

## Where this stops

**The spine stays, and the spine is most of the VTC.** These never leave
`vtc-service`:

| Module | Lines | Why it stays |
|---|---:|---|
| `trust_tasks/` | 55,945 | The dispatch spine. Routes to everything; #2579 splits it into files, not crates. |
| `routes/` | 29,653 | The HTTP surface, shrinking under #2574 to the declared REST exceptions. Terminal. |
| `ceremony/` | 6,865 | The decision pipeline; imports two dozen modules. Orchestration. |
| `admin_actions/` | 7,662 | The administrator action list; imports about 20 modules. Orchestration. |
| `join/`, `vetting/`, `groups/`, `directory/`, `elections/`, `boards/`, `badges/`, `notifications/`, `oid4vp/`, `member_portal/` | 37,988 | Product features over many subsystems; each would need half the crate below it. |
| `setup/` | 5,792 | First-boot wizards. A leaf-ward consumer; extract only for a named win, as the VTA note says of its own. |
| `server.rs`, `main.rs`, `messaging.rs`, `step_up_*.rs`, `*_cli.rs`, `test_support.rs` | ~14,700 | The binary, the messaging bridge, the offline CLIs, fixtures. |

Add up what step 3 can move — `vtc-policy` ~3.9k, the `acl` core ~5.6k, the
`registry` pure half ~2.8k, `recognition` + `status_list` + credential core
~3.5k, the `git_ns` pure core ~3.9k, and the ~5k of rooms handlers #2575
shares with `room-host` — and it is **about 25k lines, under 10% of `src/`**.
The VTA moved 23%. That is the honest expectation, and it is why steps 1 and 2
matter more than step 3: they give every subsystem its own state and a
testable boundary without moving a line across a crate, and they are the
precondition for anything else.

So the program stops when:

- steps 0–2 have landed;
- 3a and 3e have landed (the two with a clear consumer and a clean boundary);
- and each further candidate either names its measured incremental-build or
  test-time win from step 0, or is not done.

**Non-goals.**

- A `vtc-operations`, `vtc-trust-tasks` or `vtc-routes` crate. Moving the spine
  narrows no dependency surface; it is renaming
  ([the VTA's reasoning](vta-service-decomposition.md#where-this-stops) applies
  word for word).
- One crate per product feature (`vtc-badges`, `vtc-boards`, …). They are
  small, sit on many subsystems, and change together with the console.
- Chasing the LOC number. As with the VTA, quote non-test lines beside total
  lines: ~203k of `src/`'s 275k is implementation.
- Removing the re-export facades in the same PR as an extraction.
- Any behaviour change inside a move, including the type and wire changes of
  #2574, #2580 and #2568 — they land on their own, before the move that
  depends on them.

## Invariants to preserve

The VTA note's list ([Invariants to preserve](vta-service-decomposition.md#invariants-to-preserve))
holds as written. Two more for the VTC:

- **The keyspace partition stays total and structural.** Every keyspace is in
  exactly one of `BACKED_UP` / `EXCLUDED_FROM_BACKUP`, and (after step 2) owned
  by exactly one store struct. A new keyspace that fails either census is a
  backup that silently drops data.
- **No gate is a claims check.** Every VTC gate asks `VtcAclEntry::can`
  (`docs/05-design-notes/vtc-admin-roles.md`). An extracted crate that needs
  to authorise takes the entry (or, after #2580, an `AdminActor`), never
  `vti_common::auth::AuthClaims`.
