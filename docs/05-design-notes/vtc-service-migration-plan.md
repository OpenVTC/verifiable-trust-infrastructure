# VTC service migration — execution plan

**Status:** proposed — not started.
**Context:** issue #710. Companion to
[`vtc-trust-task-registry-migration.md`](vtc-trust-task-registry-migration.md),
which is the *what* (64 → 47, two-plane model, delegated confirm, the
reduction buckets). This note is the *how*: the sequenced, PR-by-PR plan
for the `vtc-service` consumption side.

The canonical registry side is done — the policy, audit, and config
families landed as `dtgwg-trust-tasks-tf` #126–#132. Everything below is
the work of pointing VTC (and its consumers) at them and migrating the
tasks that stay VTC-owned.

## Two facts that shape the sequencing

1. **Single-release tag.** The whole mesh tags together, so breaking
   changes are free — nothing ships until every component is back in
   sync. This is *not* a compatibility migration. The only invariant to
   hold is: **each PR leaves the workspace compiling and green.** Order
   for reviewability and risk-isolation, not for wire compatibility.
2. **The bindings are concentrated.** Real edit sites are few:
   - `vtc-service/src/routes/mod.rs` — 67 inline URI literals across 79
     `tt(...)` / `ttl(...)` route mounts. The single largest hand-edit.
   - **`vta-sdk` — 12 `pub const` task URIs** (`protocols/join_requests.rs`
     ×9, `protocols/members.rs` ×3). This is the real hub: the VTC
     dispatcher (`trust_tasks/mod.rs`) matches on these *constants*, not
     literals, and openvtc flows through them too. **Change the constant,
     retarget the dispatcher and openvtc for free.**
   - `cnm-cli` — 3 consts (`backup.rs` ×2, `audit.rs` ×1).
   - `vti-common` — 14 occurrences, **all doc-comments / test fixtures**.
     Cosmetic, no behavioural risk.

## Two tripwires

- **The census test** (`vtc-service/tests/trust_task_manifest.rs`) scrapes
  source for the `openvtc/vtc/` prefix and asserts manifest ↔ router
  agreement. It fails loudest and first. Its hardcoded `PREFIX` (:23) and
  two exception tables (`UNBOUND_OK`, `UNPUBLISHED_OK`) must be
  **generalised early** (Phase 1) to tolerate *both* prefixes during the
  migration, then updated per-family.
- **openvtc's `didcomm.rs:215` regex allowlist** matches
  `openvtc/vtc/.*` on inbound DIDComm `type`. Left unchanged it will
  *reject* migrated traffic. It is the one openvtc site that actively
  breaks, versus the SDK-constant sites that propagate automatically.

## The confirm/1.0 gate → `vti-common` (decided)

The management-plane approval gate (see the two-plane model in the
companion note) lands in **`vti-common`**, not a new crate and not a
dependency on the `did-hosting` workspace.

Rationale:
- `vti-common` already owns the auth/session foundation, with the exact
  extension points: `auth/step_up.rs`, `auth/session.rs`, and a top-level
  `consent.rs`. The delegated confirm is a consent-over-session-elevation
  flow — it belongs beside them.
- **Both `vta-service` and `vtc-service` depend on `vti-common`**, so both
  services get the gate from one implementation. That is the mesh-wide
  reuse #710 exists to produce — the same argument that put the Trust
  Tasks in the canonical registry.
- No cross-repo edge to `did-hosting-common` (whose confirm *route* isn't
  reusable anyway — it lives in `did-hosting-control`), so no coupling to
  that workspace's release cadence or transitive deps.

Implementation nuance: the confirm flow has a DIDComm round-trip (park the
op → `confirm/request` to the approver → resume on `confirm/response`).
`vti-common` stays **transport-agnostic** — the DIDComm sender is injected
via a trait, exactly as `vti-common` already injects its telemetry sink,
`Store`, and `SeedStore`. The transport-independent core (the
StepUpAuth-style extractor, session elevation, request parking +
challenge correlation) is what lives in `vti-common`; the service wires
its DIDComm transport in.

## Phases

Each phase is ≈ one green, reviewable PR unless noted. Phases 2 and 4
split into per-family PRs.

### Phase 0 — canonical tasks published ✅
Done: `dtgwg-trust-tasks-tf` #126–#132 (policy `{get,activate,active}`,
audit `{verify,list}` + `AuditEnvelope`, config
`{show,patch,reload,restart}`). Pre-existing canonical `acl/*`,
`auth/passkey/enroll/*`, `confirm/*` are also available.

### Phase 1 — deletions + census generalisation (low risk; warm-up)
- Delete the 5 A1 tasks (`acl/legacy/entry`, `acl/legacy/manage`,
  `config/legacy/manage` — empty stubs) from the manifest, on-disk, and
  their route mounts; de-list the two non-tasks (`admin-ui/build-info`,
  `status-lists/show`).
- **Generalise the census** to accept both `openvtc/vtc/*` and `spec/*`
  bound URIs so it stays a working tripwire *through* the migration
  rather than blocking it.
- Smallest surface change; proves the census-retarget mechanics before
  the big repoints.

### Phase 2 — repoint to *existing* canonical, one family per PR (medium)
For each family: swap the `routes/mod.rs` literals (and any SDK const) to
the canonical URI, reconcile the VTC handler's payload to the canonical
schema, update the census exception tables.
- **2a `policy/*`** — repoint to canonical `policy/{get,activate,active,
  upsert,list,evaluate,delete}`. **Behavioural, not mechanical:** canonical
  `policy/*` uses the *relational* purpose model (#127); VTC's handlers
  treat purpose as *intrinsic*. VTC adopts activate-binding here. The
  meatiest repoint.
- **2b `audit/*`** — repoint `audit/{list,verify}`; map VTC's envelope
  onto the canonical `AuditEnvelope`, keep the opaque cursor.
- **2c `config/*`** ✅ — split VTC's merged `admin/config/manage` mount into
  `config/show` + `config/patch`; repointed `reload`/`restart`. The PATCH
  body gained the canonical `overrides` wrapper (dropped
  `#[serde(flatten)]`). `config/legacy/manage` and `admin/config/
  {export,import}` stay on `openvtc/` — no canonical counterpart.
  **Finding that unblocks 2d:** a merged GET+PATCH mount does *not* need
  "per-method Trust-Task selectors" — `task_routes` layers the method
  router and axum merges same-path method routers per method, so each
  verb enforces its own URI. Pinned by
  `vti_common::trust_task::openapi::per_method_tasks_on_one_path_are_enforced_independently`.
- **2d `acl/*`** — repoint remaining ACL bindings to canonical
  `acl/{show,change-role,revoke,list,grant}`. The 2-mount → 5-task fan-out
  is *not* blocked (see 2c's finding); the real work is payload
  reconciliation: `did`→`subject`, `allowed_contexts`→`scopes`, `u64`
  epoch → RFC3339 `date-time`, and adding the canonical-required
  `truncated` to list responses.
- **2e `auth/*`** — collapse `auth/admin-login` → `auth/authenticate`
  (cookie behaviour to a binding/`ext`); passkey enrolment →
  `auth/passkey/enroll/*` (its inline UV is removed in Phase 3).

### Phase 3 — the confirm/1.0 management gate (highest risk; novel flow)
- Build the transport-agnostic gate in `vti-common` (see above).
- Strip the inline `uvOptions`/`uv_response` from `admin/passkeys/
  {register,revoke}` and `members/promote-to-admin`; those tasks become
  plain canonical tasks (`auth/passkey/enroll/*`, a passkey-revoke,
  `acl/change-role`) guarded by the gate.
- Wire VTC's DIDComm transport into the gate.
- Isolated because it is the one genuinely new behaviour and the one
  place a bug is a security regression rather than a wiring error.

### Phase 4 — migrate VTC-specific tasks to `spec/vtc/*` (high; the grind)
The ~36 tasks that stay VTC-owned (members, join-requests, website,
relationships, endorsement-types, community, recognition, install-claim,
the endorsement credentials).
- **4a (registry, `dtgwg-trust-tasks-tf`)** — author them under
  `specs/vtc/*` in registry format (front-matter reshape,
  `payload.schema.json`, `payload.invalid-examples.json`, ~36 hand-written
  `summary` lines). Independent of the VTI repo — **can start in parallel
  with Phases 1–3.** Ships new `vta-sdk`-consumable `spec/vtc/*` URIs.
- **4b (VTI)** — repoint the 12 `vta-sdk` constants, the `routes/mod.rs`
  literals, and `cnm-cli` to the new `spec/vtc/*` URIs.
- **4c (openvtc)** — widen the `didcomm.rs:215` regex; fix the
  `messaging.rs:1239` literal.

### Phase 5 — retire the manifest; retarget the census (low-medium)
- `trust-tasks/index.json` stops being the source of truth once specs live
  in the registry repo — delete it or demote it to a local convenience
  index. Fix its stale "CI publishes on merge" description either way.
- Retarget `trust_task_manifest.rs` to assert against `specs/vtc/*` in the
  registry repo (or its successor); update `PREFIX` + exception tables.

### Phase 6 — downstream: SDK + openvtc bumps (medium; cross-repo)
- Publish the `vta-sdk` bump carrying all URI-const changes.
- Bump `openvtc` onto it — spans `0.18 → 0.19+` (two minors of unrelated
  change), fix its one test literal, and untangle its lockfile's two
  resolved `vta-sdk` copies (`0.16.1` + `0.18.14`) first.
- Acceptance test for the whole migration: **openvtc still builds and
  completes a join.**

## Behavioural changes to watch (not string swaps)

- **Phase 2a** — VTC's policy handlers adopt the relational purpose model.
- **Phase 3** — the inline-UV → delegated-confirm shift is a real
  authorization-flow change; a bug here is a security regression.

Everything else is mechanical URI/payload reconciliation that the census
tripwire and `cargo test` will catch.

## Recommended starting point

**Phase 1.** It is the smallest change, it proves the census-retarget
mechanics that every later phase depends on, and it removes dead surface
before the real repoints. Phase 4a (registry authoring) can be started in
parallel at any time since it lives in the other repo and is additive.

## Open sub-decisions (resolve at the relevant phase, not now)

- **`credentials/*` generalisation** — folding VTC's endorsement
  credentials and `vta/credentials/*` into one canonical `credentials/*`
  touches a published VTA surface; confirm scope before Phase 4a authors
  them as `vtc/*`.
- **`config/export`/`import`** — still deferred (they embed
  `communityProfile`, which must move to `ext` before they can be a
  generic canonical task). Not in this plan's critical path.
