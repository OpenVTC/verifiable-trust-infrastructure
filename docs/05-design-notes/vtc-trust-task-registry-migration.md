# Consolidating VTC's Trust Task surface onto the registry

**Status:** proposed — not implemented.
**Context:** issue #710. The manifest census (PR #711) pinned VTC's Trust
Task surface in place; this note covers reducing and relocating it.

## Framing

Two constraints shape this work, and they point somewhere different from
a straight URI migration:

1. **Breaking changes are acceptable.** Everything here is beta and the
   components tag as a single release, so nothing ships until the whole
   mesh is back in sync. There is no dual-accept window, no deprecation
   dance on published `vta-sdk` constants, no waiting on peers to
   upgrade. Change the URI and move on.
2. **The goal is fewer, properly-defined tasks.** A Trust Task is the
   *interface*, identical over REST, DIDComm, and TSP. Every task VTC
   defines that duplicates an existing one is a second interface for the
   same operation — the cost is not the URI, it is that a client now has
   to know which service it is talking to in order to pick the right
   task. Reuse is the objective; relocation is a side effect.

So the primary question is not "where do these 64 tasks move to" but
**"how many of these 64 should exist at all?"**

That reframes the earlier draft of this note, which treated all 64 as
things to migrate. Most of the risk it worried about — the SDK constant
dance, the DIDComm peer window, staged sequencing — was an artifact of
assuming compatibility had to be preserved. With constraint 1 those
sections are moot and have been dropped.

## The precedent that settles the URI question

VTA already publishes its service-specific tasks to the **public**
registry — `https://trusttasks.org/spec/vta/credentials/issue/0.1`, on
disk at `specs/vta/credentials/issue/0.1/`. Hierarchical slugs are
explicitly permitted (SPEC §6.1) and CONTRIBUTING-SPECS recommends them
for namespacing. The `vtc` slug is unclaimed.

Whatever survives the reduction below lands at:

```
https://trusttasks.org/spec/vtc/<slug>/<MAJOR.MINOR>
```

Today VTC emits two non-conformant shapes, both under
`https://trusttasks.org/openvtc/vtc/…`: a flat form (60 of 64 live
tasks) with no `/spec/` segment, which a conforming consumer cannot parse
at all, and an interior-`/spec/` form (the 4 join-request tasks) that
parses but keeps the wrong authority. §6.5 forbids the `trusttasks.org`
domain for private specs, so the "keep it private" option is not
available without also changing authority — and doing that would isolate
VTC from the registry its own sibling service already publishes to.

## The reduction

Every row below was checked at the **payload-schema level**, not by name
or summary. That matters: an earlier draft of this note claimed
`policies/upload` = `policy/upsert` and `policies/test` =
`policy/evaluate` were exact matches on the strength of their canonical
*summaries*. The schemas do not support either claim. Names and one-line
summaries are not evidence.

The honest headline: **64 → 47 tasks in the `vtc/*` namespace**, with 17
leaving. That is less than the earlier draft's optimistic "~36", and the
work is less "delete duplicates" than "extend the canonical families so
one definition serves both services".

### A1. Delete outright — 5 tasks

Self-declared placeholders whose schemas are literally `{"type":
"object"}` with no properties, plus two routes that were never Trust
Tasks.

| Task | Disposition |
|---|---|
| `acl/legacy/entry` | → canonical `acl/{show,change-role,revoke}` |
| `acl/legacy/manage` | → canonical `acl/{list,grant}` |
| `config/legacy/manage` | strict duplicate of `admin/config/manage`; its own text names the successor, which already shipped |
| `admin-ui/build-info` | plain `.route()`, no Trust-Task layer, already `trust_task_header_exempt` |
| `status-lists/show` | header-exempt by design — external verifiers fetching a W3C BitstringStatusList do not carry our extension header |

The `acl/legacy/*` pair are the cleanest wins in the whole exercise:
zero declared fields, description "Stub — subsumed by `members/*` tasks
in M0.6+", and canonical is strictly more expressive (`fromRole`
optimistic concurrency, `scopes` partial revocation). These are the same
pattern as the seven `auth/legacy/*` tasks retired in PR #711 — nobody
had checked whether it extended past `auth`. It does.

### A2. Collapse once canonical gains a step-up envelope — 3 tasks

**This is the highest-leverage finding in the analysis.** Three VTC tasks
differ from their canonical counterparts by *exactly one thing*: a
mandatory step-up user-verification carried **inside** the privileged
request (`uvOptions` / `uv_response`, or `options` / `uvResponse`).

| VTC task | Canonical | Sole blocking delta |
|---|---|---|
| `admin/passkeys/register` | `auth/passkey/enroll/{start,finish}` | in-request UV |
| `admin/passkeys/revoke` | `vta/passkey-vms/revoke` | in-request UV (+ the `409 LastPasskeyProtected` invariant, behavioural) |
| `members/promote-to-admin` | `acl/change-role` | in-request UV |

Canonical models step-up only as a *separate* ceremony
(`auth/passkey/login/start` with `purpose: "stepUp"`), never as fields
within the privileged operation. VTC needs it atomic — its rationale is
that "a stolen session must not be able to bind a new authenticator", and
a two-ceremony flow reopens exactly that window.

**Proposal: add a shared step-up envelope to the canonical `_shared`
namespace** — a `StepUpChallenge` / `StepUpAssertion` `$def` composable
into any privileged task. That single addition collapses all three VTC
tasks into canonical ones, and is reusable by every future privileged
operation in the mesh rather than being a VTC concession. It is the
clearest instance of the "fewest total tasks" goal paying off.

Note `members/promote-to-admin`'s other deltas are narrowings, not new
capability: `toRole` hardcoded to `Admin`, `subject` carried in the URL
path, and `fromRole`'s optimistic-concurrency intent expressed
server-side via `PROMOTE_LOCK` instead of in the payload.

### A3. Generalize into a new canonical task — 1 task

`admin/passkeys/list` → propose canonical **`auth/passkey/list`**.

It does *not* match `vta/passkey-vms/list`, which enumerates published
DID-document verificationMethods (`publicKeyMultibase`, `controller`,
`type: "Multikey"`) — public key material for verifiers. VTC's enumerates
server-side credential records with operator lifecycle metadata
(`registeredAt`, `lastUsedAt`) and no key material. Different data,
different trust model.

But VTC's shape is essentially `auth/passkey/enroll/finish`'s response
replayed as a collection, which is a good sign it generalizes cleanly.
Naming needs reconciling: canonical `auth/*` uses `deviceLabel`, VTC and
`vta/*` use `label`. `lastUsedAt` is a VTC-only addition and a reasonable
canonical candidate.

### A4. Collapse on observability grounds only — 1 task

`auth/admin-login` → canonical `auth/authenticate`.

Its schema is an empty stub, so there is nothing to diff; the spec says
the wire shape is the same signed-challenge authenticate. The **only**
deliberate delta is a response side-effect — setting `vtc_admin_session`
and `csrf` cookies — and VTC's stated reason for a separate task ID is so
SIEM filters can distinguish a cookie session mint from a bearer one.

That is an audit concern, not a payload one. The cookie behaviour belongs
in a transport binding or `ext`. Worth confirming the SIEM requirement can
be met another way (the audit event type already distinguishes them)
before collapsing, but this is duplication for observability convenience.

### B. Promote to canonical generics — 7 tasks

Not community-specific; the VTA already ships parallel, independently
designed surfaces for all three areas, which is the duplicated design
effort this work exists to eliminate. Ranked by readiness:

| Rank | Task | Notes |
|---|---|---|
| 1 | `audit/verify` | Promote as-is. No payload, pure hash-chain vocabulary, zero community-specific fields. **The VTA has no chain-verify endpoint at all** — net-new capability for it. |
| 2 | `config/reload`, `config/restart` | Near as-is. Rename the `VTC_SUPERVISED` env var; supervisor detection is deployment-generic. |
| 3 | `audit/list` | Must reconcile paging: VTC uses opaque HMAC-signed cursor + limit, VTA's existing `ListAuditLogsBody` uses offset (`page`/`page_size`). That reconciliation *is* the value. Consider folding in VTA's `retention` get/update, which VTC lacks. |
| 4 | `config/manage` | Promote as split `config/show` + `config/patch` (it currently merges two HTTP methods pending per-method selectors). Open the `source` enum — `env > db > toml > default` is a VTC implementation choice. |
| 5 | `config/export`, `config/import` | Blocked until `communityProfile` moves to `ext`. Import is worse: `communityProfileDiff` / `communityProfileApplied` are structural, and the community-DID mismatch `409` routes through `CommunityProfileUpdate::apply`. |

**`health/diagnostics` is explicitly *not* promoted.** It is not a health
task — it is trust-registry reconciler telemetry (`rtbf_batched_count`,
`registry_status`, `queue_depth`, `oldest_pending_age_seconds`). Zero
field overlap with the VTA's health surface, which reports deployment and
attestation posture (`tee_status`, `sealed`, `storage_encrypted`). They
share a URL prefix and nothing else. `additionalProperties: false` blocks
extension in place. A canonical `health/*` should be designed fresh; this
task stays `vtc/*` and should probably be renamed to say what it is.

### C. Stays `vtc/*` — 47 tasks

Everything else. Three groups within it need calling out because they
were *proposed* for reduction and survived scrutiny:

**The policy family (5) — moves as a unit or not at all.** VTC's
`purpose` closed enum (nine governance lifecycle stages: `join`,
`removal`, `personhood`, `registry`, `directory`, `roleDefinitions`,
`crossCommunityRoles`, `crossCommunityRelationships`, `relationships`)
has no canonical model. It is load-bearing: it drives `upload`'s
classification, `list`'s filter, `show`'s `isActive` computation, and it
is the entire reason `activate` exists — activation is an *exclusive
per-purpose pointer* (`active_policies:<purpose>`), not canonical's
per-policy `enabled` boolean. Canonical's `appliesTo` is an open string
array that can carry the values but loses both the closed-enum validation
and the one-active-policy-per-purpose invariant.

Worse, canonical has **no `policy/get`** (no way to fetch one policy by
id — `policy/list` has no `id` filter) and **no policy-activation concept
anywhere**. And `policies/test` cannot migrate at all as written: its
`input` is schema-free and carries a membership-application shape, while
canonical `PolicyInput` is `additionalProperties: false` and requires
`request.kind ∈ {proxy_login, release, step_up_response}` — a
credential-vault model. VTC's join-application input cannot validate
against it. VTC's `query` field (probe any Rego rule, not just `allow`)
has no counterpart either.

Migrating `upload`/`list` piecemeal while `show` and `activate` have no
target would split the policy lifecycle across two registries — strictly
worse than either end state. Either extend canonical `policy/*` (add
`get`, `activate`, and a home for `purpose`) and move all five, or keep
all five. Do not do half.

**The endorsement credentials (2) are not duplicates.**
`credentials/endorsements/issue` gates on a VTC-local endorsement-type
registry (`400 endorsement-type-not-registered`) and allocates a shared
status-list slot, returning `statusListIndex`; canonical
`vta/credentials/issue` treats `credentialType` as a free string and has
no status-list concept. More sharply,
`credentials/endorsements/revoke` **contradicts** canonical: canonical
says a consumer MUST report `already_revoked` on re-revocation "so the
caller can distinguish 'I revoked it now' from 'it was already gone'",
while VTC returns `200 OK` silently idempotent. VTC as written would fail
canonical conformance.

**The install-claim pair (2) is a genuinely distinct operation.**
`install/claim/{start,finish}` carry `install_token`,
`did_binding_signature`, `setupSessionToken`, and return `adminDid` — the
bootstrap of the very first admin identity, with the passkey's Ed25519
key projected into a `did:key` and proof of single-key control demanded
across both signing paths. Canonical `auth/passkey/enroll/*` assumes an
authenticated session and has no DID-binding challenge. This is a
canonical *candidate in its own right* (`install/claim/*` or
`auth/passkey/enroll/bootstrap`), not a VTC duplicate.

### Known defects found along the way

Worth fixing regardless of what this note leads to:

- `credentials/endorsements/revoke/1.0/spec.md` has two `## Status`
  sections.
- Both `credentials/endorsements/{issue,revoke}` schemas are permissive
  stubs (`additionalProperties: true`, zero declared properties) despite
  their `spec.md` naming concrete fields — no machine-checkable contract
  exists for either.
- `members/promote-to-admin` reuses `registrationId` for what is a UV
  *authentication* handle; canonical `login/start` calls the same thing
  `authId`. It is not a registration.
- Every VTC schema uses a different envelope convention from canonical
  (sibling `request`/`response` properties, no `additionalProperties:
  false`, no `ext` extension point). All 64 need re-shaping regardless of
  semantic overlap — budget for that separately from the reduction.

## Downstream: `openvtc` is a live consumer

`~/devel/openvtc` participates in the join ceremony as the **joining
side** — the counterparty to VTC's four DIDComm-bound `join-requests/*`
tasks. It is in scope for this work and must land in the same release.

The good news is that it consumes the ceremony through **`vta-sdk`
constants and body types**, not hardcoded URI strings:

```rust
// openvtc-core/src/messaging.rs:18
use vta_sdk::protocols::join_requests::{
    JoinRequestStatusResponseBody, JoinRequestSubmitReceiptBody,
    VerdictEffect, VerdictResponse,
};
```

with `JOIN_REQUEST_SUBMIT_RECEIPT_TYPE`,
`JOIN_REQUEST_STATUS_RESPONSE_TYPE`, and
`JOIN_REQUEST_SUBMIT_RESPONSE_TYPE` used by value. So a URI change
propagates on an SDK version bump — there is no string-rewrite pass to do
in that repo. Exactly one hardcoded literal exists
(`messaging.rs:1239`), and it is a *negative* assertion in a test
("this is not a trust-task-error type"); it needs a mechanical edit only.

Two things to handle:

- **openvtc pins `vta-sdk = "0.18"` (locked `0.18.14`); VTI ships
  `0.19.13`.** The coordinated release has to bump openvtc onto the new
  SDK, and that bump spans two minors of unrelated change — it is not a
  no-op just because the URI edit is.
- **Its lockfile resolves two `vta-sdk` versions** (`0.16.1` and
  `0.18.14`), so something pulls an older copy transitively. Worth
  untangling before the bump rather than during it.

The join-requests family therefore stays `vtc/*` (group C) but is the one
cross-repo interface in the set. Sequence it so VTC and openvtc change
together, and treat "openvtc still builds and completes a join" as the
acceptance test for the whole migration.

## What has to change

1. **Verify group A.** Diff each VTC payload schema against its canonical
   counterpart. Where they differ, the question is whether VTC's variant
   is a genuine requirement or an accident — assume accident until shown
   otherwise, since the whole point is one interface per operation.
2. **Land the canonical additions** in `dtgwg-trust-tasks-tf` first —
   everything else binds against their slugs. We hold approval rights on
   the registry, so this is a sequencing constraint we control, not an
   external dependency. In dependency order:

   1. **The `_shared` step-up envelope** (`StepUpChallenge` /
      `StepUpAssertion`). Highest leverage: it alone unblocks group A2's
      three tasks, and it is reusable by every future privileged
      operation rather than being a VTC-shaped concession.
   2. **`auth/passkey/list`** (group A3) — reconcile `deviceLabel` vs
      `label` while doing it.
   3. **The group B generics** — `audit/{list,verify}`,
      `config/{show,patch,reload,restart}`, then `config/{export,import}`
      once `communityProfile` moves to `ext`.
   4. **The policy-family extensions** (`policy/get`, `policy/activate`,
      and a home for `purpose`) — only if the decision is to move all
      five; see group C.
3. **Author surviving `vtc/*` specs** into `specs/vtc/…`, in registry
   format. This is not a relocation — the on-disk shape differs:

   | | VTC today | Registry requires |
   |---|---|---|
   | Schema file | `schema.json` | `payload.schema.json` |
   | Schema `$id` | `…/openvtc/vtc/<path>/schema.json` | `https://trusttasks.org/spec/vtc/<slug>/<ver>` |
   | Front matter | `id`, `applies_to`, `authors` | `slug`, `version`, `title`, `summary`, `status`, `targetFrameworkVersion`, `category` |
   | Validation | none | `specs/spec.meta.schema.json` at build time |

   `summary` (≤280 chars) and `category` (closed enum) do not exist in
   our front matter and must be written per task — the bulk of the manual
   effort, though the reduction cuts it from 64 to ~36.
4. **Repoint the code.** `routes/mod.rs` wiring, `trust_tasks/mod.rs`
   dispatch, `vta-sdk/src/protocols/{join_requests,members}.rs` (15
   `pub const`s — change values in place, no deprecation window needed),
   `cnm-cli/src/{audit,backup}.rs`. `vti-common/src/trust_task/*` hits
   are doc comments and test fixtures only.
5. **Bump `openvtc` onto the new `vta-sdk`** and fix its one test
   literal. See the downstream section above — the URI change itself
   propagates through the SDK, but the version bump spans two minors.
6. **Retire `trust-tasks/index.json`.** Once specs live in the registry
   repo it is no longer a publication source of truth. Its `description`
   already claims a CI publication step that does not exist.

   `vtc-service/tests/trust_task_manifest.rs` is written against that
   manifest and must be retargeted, not deleted — it is the only thing
   holding the surface together. The natural successor asserts that every
   task the router binds resolves to a spec in the registry repo.

## Open questions

- **`credential-exchange/*`** — 5 task directories on disk in neither the
  manifest nor any binding. Decide publish-or-delete before they get
  migrated by accident.
- **Version numbers.** Surviving tasks stay at `1.0`; content is
  unchanged and a lower number would imply a maturity regression that did
  not happen. Group B promotions start at `0.1`, matching how the
  canonical families they join are versioned.

## Non-goals

- Changing payload shapes for their own sake. Where a group A schema
  differs from canonical, converging on canonical is in scope; redesign
  is not.
- Migrating the 7 auth tasks retired in PR #711. They are terminal per
  §5.3 and already declare `supersededBy`.
- #709 (unpublished bound tasks) as separate work — those get authored
  directly in the new shape here, which is why #710 blocks it. The
  reduction likely absorbs several of them outright.
