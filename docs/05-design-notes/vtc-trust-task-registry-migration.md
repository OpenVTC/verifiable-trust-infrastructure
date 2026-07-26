# Consolidating VTC's Trust Task surface onto the registry

**Status:** **partly implemented — the residual is much smaller than this
note assumes.** See "Where this actually stands" immediately below before
reading anything else; the reduction analysis further down is still sound,
but its headline numbers are stale. That section was itself corrected on
2026-07-26 (a router-only scan had undercounted the residual and wrongly
reported #709 as partly unblocked).
**Context:** issue #710. The manifest census (PR #711) pinned VTC's Trust
Task surface in place; this note covers reducing and relocating it.

---

## Where this actually stands (measured 2026-07-25, corrected 2026-07-26)

This note was written against a 64-task surface, all on the non-conformant
`trusttasks.org/openvtc/vtc/…` authority, and framed the work as
"**64 → 47**". That is no longer the shape of the problem: the Phase 2 + 4
migrations (#724–#729, #733, #743, openvtc#171–#173) executed most of it.

> **Correction (2026-07-26).** The counts first published here were measured
> from `vtc-service/src/routes/mod.rs` alone, which is *not* the whole binding
> surface — DIDComm wire constants live in `vta-sdk/src/protocols/`, and the
> admin SPA and `cnm-cli` carry their own literals. That scan undercounted the
> residual (26 → **30**) and, more seriously, mis-classified four tasks as
> "already conformant" when they are bound on `openvtc/vtc/` from the SDK. The
> practical consequence: **#709 is fully blocked on #710**, not partly. The
> numbers below are the corrected ones.

Counting distinct Trust-Task URIs across **every live binding site** — the
router, the `vta-sdk` protocol constants, the admin SPA, and `cnm-cli`:

| Form | Count | Meaning |
|---|---:|---|
| `trusttasks.org/spec/<slug>/<ver>` | 24 | Canonical. Group A/B promotions — **done**. |
| `trusttasks.org/spec/vtc/<slug>/<ver>` | 33 | Already in this note's target shape — **done**. |
| `trusttasks.org/openvtc/vtc/<slug>/<ver>` | **30** | **The residual. This is what #710 still means.** |

(The router alone accounts for 26 of the 30; the other 4 —
`members/self-remove-receipt`, `spec/join-requests/submit-receipt`,
`spec/members/request-vmc`, `spec/members/vmc` — are `vta-sdk` DIDComm
constants with no REST mount, which is exactly why a router-only scan missed
them.)

A further 4 appear only in `vti-common/src/trust_task/` doc comments and test
fixtures (`auth/login/1.0`, `install/claim/{1.0,1.1,start/1.0}`). Those are not
bindings and nothing on the wire depends on them, but they should be updated
with everything else so the examples do not teach the retired shape.

So the target shape is not a proposal any more — 33 tasks already use it and
work. The remaining question is narrow: **move 30 URIs**, not "reduce 64 to
47".

The manifest agrees: `trust-tasks/index.json` now carries 54 `retired`
entries (each with a `supersededBy`) and 15 `draft`.

### The residual 30, reconciled against #709

#709 ("20 bound tasks absent from the published manifest") is not a separate
backlog — it is a strict subset of this one. Cross-referencing the 30 residual
URIs against the census test's `UNPUBLISHED_OK` table:

| Bucket | Count | Work per task |
|---|---:|---|
| Non-conformant **and** unpublished | **19** | Author the spec **at** the new URI — one edit closes both issues |
| Non-conformant, already published as `draft` | **11** | URI change + re-file the existing `spec.md`/`schema.json` |
| In #709 but not a real wire task | **1** | `join-requests/submit/1.0`, the documented mount-collapse alias of `spec/join-requests/submit/1.0` — no spec to author |

**19 of #709's 20 entries are in group 1, and the twentieth is an alias.** So
#709 has no independently-executable remainder: every task it asks for either
moves URI here or is not a task at all. Author any of them at the old URI and
the work is thrown away.

**Group 1 — non-conformant *and* unpublished (19).**

```
admin/invites/manage/1.0      invitations/issue/1.0    spec/join-requests/submit-receipt/1.0
admin/invites/revoke/1.0      invitations/revoke/1.0   spec/members/request-vmc/1.0
auth/admin-session/1.0        members/purge/1.0        spec/members/vmc/1.0
auth/recognise/challenge/1.0  members/removed/1.0
backup/export/1.0             members/request-vmc/1.0
backup/import/1.0             members/self-remove-receipt/1.0
ceremonies/list/1.0           recognition/check/1.0
directory/query/1.0           relationships/graph/1.0
```

**Group 2 — published as `draft`, wrong URI (11).** Content exists; the URI
and the on-disk registry shape change:

```
admin/config/export/1.0    admin/passkeys/revoke/1.0   policies/test/1.0
admin/config/import/1.0    auth/admin-login/1.0        website/deploy/1.0
admin/passkeys/list/1.0    config/legacy/manage/1.0    website/files/show/1.0
admin/passkeys/register/1.0 members/promote-to-admin/1.0
```

Six of these are dispositions this note already argues for and which are
**not** simple relocations — `auth/admin-login` collapses into
`auth/authenticate`; `admin/passkeys/{register,revoke}` and
`members/promote-to-admin` shed their inline-UV fields for the delegated
`confirm/1.0` gate; `admin/config/{export,import}` are group-B promotions.
Those four decisions stand unchanged; only the count around them moved.

**There is no third group.** An earlier revision of this addendum claimed five
tasks were already on conformant URIs and therefore executable as #709 work
straight away. That was an artefact of scanning only the router: four of them
(`members/self-remove-receipt`, `spec/join-requests/submit-receipt`,
`spec/members/request-vmc`, `spec/members/vmc`) are bound on `openvtc/vtc/`
as `vta-sdk` DIDComm constants with no REST mount, and the fifth
(`join-requests/submit/1.0`) is the mount-collapse alias, not a task. All four
belong in group 1.

### Call sites, counted

The "Repoint the code" step below understates the blast radius in one place
and overstates it in another.

| Location | Occurrences | Note |
|---|---:|---|
| `vtc-service/src/routes/mod.rs` | 29 | The bindings |
| `vtc-service/tests/` | 21 | Test literals |
| `vti-common/src/trust_task/` | 14 | Router, OpenAPI, doc comments |
| `vta-sdk/src/protocols/{members,join_requests}.rs` | 6 | **Only 5 are `pub const`s that change value**, not the 15 this note claims — #724–#729 already repointed the rest |
| `cnm-cli/src/{audit,backup}.rs` | 2 | |
| **`vtc-service/admin-ui/src/`** | **16** | **Not mentioned anywhere in this note.** 7 TypeScript files: `lib/api.ts`, `lib/ceremony-manifest.ts`, `pages/Login.tsx`, `plugins/{acl,ceremonies,members,myPasskeys}.tsx` |
| `trust-tasks/` (`index.json` + per-task files) | 226 | Rewritten wholesale by the move |
| `docs/`, `tasks/` | 20 | Prose |

The admin SPA is the gap worth flagging: it is compiled into the binary by
`build.rs`, so it cannot lag the daemon by even one release. It sends
`Trust-Task` headers as string literals and is not covered by the Rust
type system, so nothing will catch a missed one at compile time — the
`trust_task_manifest` census test does not see TypeScript either.

### What this means for sequencing

1. **#709 stays fully blocked on #710** — 19 of its 20 entries move URI here
   and the twentieth is an alias, so there is nothing in it to start early.
   Close it as part of this work rather than sequencing it separately.
2. **The canonical additions** (`auth/passkey/list`, the group-B generics,
   the `policy/*` extensions) are still the first dependency — unchanged.
3. **Add an admin-UI step** to "What has to change" between steps 4 and 5.
4. **The `trust_task_manifest.rs` retarget** (step 6) is now the highest-value
   piece, not the cleanup — and its scope must be **every binding site, not the
   router**. A router-only census is what produced the wrong numbers this
   addendum corrects: it cannot see `vta-sdk`'s DIDComm constants (4 tasks with
   no REST mount), the admin SPA's 16 header literals, or `cnm-cli`. Whatever
   replaces the manifest test should read all four, or it will report a
   finished migration while a transport is still on the old authority.

   Good news from the recount: every admin-SPA URI is currently a subset of the
   router's, so there is no live drift to fix — only migration debt.

Everything below this line — the two-planes model, the step-up decision, the
group A/B/C dispositions, the settled decisions, the non-goals — is unchanged
and still governs. Only the counts and the sequencing above are new.

---

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

## Two planes: management vs self-management

The reduction below only makes sense against a distinction the earlier
draft missed, which turns out to govern where step-up, policy, and human
approval each belong. VTC operates on **two planes**, and a task lives on
exactly one of them.

**1. Management / administration — a human is in the loop.** Operations an
operator performs *on* the community: promoting a member to admin,
enrolling or revoking an admin passkey, editing the community profile.
These require **human approval**, and that approval follows the
**delegated ratify** pattern (DTTE — Delegated Trust-Task Execution): the
agent proposes the action, a human admin ratifies it, and only then does
it run. Four-eyes capable — the ratifying admin may differ from the
initiator.

**2. Self-management — no human, policy-gated.** The VTC acting *on
itself* through its own VTA, autonomously, when a Rego policy authorises
it. Issuing a `MembershipCredential` from the community's own keys on a
join-policy verdict is the canonical case: the VTC evaluates its own
`policy/*` rules, and if they permit, it acts with no operator present.
The `policy/*` family's `purpose`/governance-stage enum *is* this plane's
decision layer.

### Consequence for step-up

This is where an earlier assumption was wrong. VTC's current management
tasks (`admin/passkeys/{register,revoke}`, `members/promote-to-admin`)
carry an **inline self-UV** shape — `uvOptions`/`uv_response` embedded in
the task's own start/finish. An earlier draft proposed extracting that
into a shared `StepUpChallenge`/`StepUpAssertion` `$def` so the tasks
could compose it inline.

That is not the pattern the mesh actually uses. DID-hosting — the sibling
that already implements this — gates a privileged operation as a
**separate concern**, not inline: the op is guarded server-side, and the
approval runs as its own exchange. Two mechanisms exist there:

- `auth/step-up/approve-request` + `approve-response/0.2` — despite the
  name, the code converged onto **self** step-up (`issuer == subject`,
  "the VTA is no longer in the loop"): the acting principal re-signs to
  elevate their *own* session `aal1 → aal2`.
- `confirm/request` + `confirm/response/0.1` — the genuinely **delegated**
  flow: park the REST op, send the approver a DIDComm confirm, resume on
  their signed ratification. This is the literal DTTE pattern and the one
  VTC management adopts.

**Decision (confirmed): VTC management uses the delegated `confirm/1.0`
gate.** Consequences:

- The three management tasks **shed their inline UV fields entirely** and
  collapse to plain canonical tasks — `promote-to-admin` → `acl/change-role`,
  `passkey/register` → `auth/passkey/enroll/*`, `passkey/revoke` → a
  canonical passkey-revoke.
- Human approval becomes a **server-side `confirm/1.0` gate** reused from
  DID-hosting, orthogonal to each task's schema. No step-up fields on the
  privileged task at all.
- **No new canonical spec is needed** for any of this. `confirm/request`,
  `confirm/response`, `acl/change-role`, and `auth/passkey/enroll/*` all
  already exist. The `_shared` step-up envelope the earlier draft called
  the "highest-leverage finding" is **not built** — the delegated-gate
  decision removes the need for it.

Self-management operations touch none of this: no step-up, no confirm
gate. They are authorised by `policy/*` evaluation and run under the VTC's
own VTA identity.

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

> **Stale count — the dispositions below are not.** Most of this reduction
> has since shipped (#724–#729, #733, #743). 57 of the 83 currently-bound
> URIs are already canonical or already `spec/vtc/*`; **30 remain on
> `openvtc/vtc/*`** (corrected 2026-07-26 from a router-only count of 26). Read "Where this actually stands" at the top of this
> note for the current tally. The per-task reasoning in A1–A4, B, and C is
> unaffected — only the arithmetic around it is.

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

### A2. Collapse to canonical + a delegated confirm gate — 3 tasks

These three are the management-plane privileged operations (see "Two
planes" above). Each differs from a plain canonical task by *exactly one
thing*: a mandatory step-up user-verification carried **inside** the
request (`uvOptions` / `uv_response`, or `options` / `uvResponse`).

| VTC task | Canonical | Inline shape to shed |
|---|---|---|
| `admin/passkeys/register` | `auth/passkey/enroll/{start,finish}` | in-request UV |
| `admin/passkeys/revoke` | canonical passkey-revoke (see A3) | in-request UV (+ the `409 LastPasskeyProtected` invariant, behavioural) |
| `members/promote-to-admin` | `acl/change-role` | in-request UV |

An earlier draft proposed a shared `StepUpChallenge` / `StepUpAssertion`
`$def` so the tasks could keep the UV *inline*. **That is abandoned.** The
two-plane analysis showed the mesh does not gate privileged ops inline —
DID-hosting gates them as a **separate, server-side concern** and runs the
approval as its own exchange. So:

- Each task **sheds its inline UV fields** and becomes the plain canonical
  task in the middle column.
- Human approval is enforced by a **delegated `confirm/1.0` gate**
  (`confirm/request` + `confirm/response`, reused verbatim from
  DID-hosting): the server parks the op, sends the approver a DIDComm
  confirm, and resumes on their signed ratification. Four-eyes capable.
- **Nothing new is authored in the canonical registry.** All four target
  tasks plus the confirm pair already exist. This is a bigger reduction
  than the envelope plan and needs zero canonical spec work.

`members/promote-to-admin`'s remaining deltas are narrowings, not new
capability: `toRole` hardcoded to `Admin`, `subject` in the URL path, and
`fromRole`'s optimistic-concurrency intent expressed server-side via
`PROMOTE_LOCK` instead of in the payload — all fine to drop onto
`acl/change-role`.

The original "a stolen session must not bind a new authenticator"
rationale still holds: a delegated confirm is *stronger* than inline
self-UV, since it can require a second admin rather than just re-checking
the possibly-stolen session's own credential.

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
| 4 | `config/manage` | **Done (Phase 2c).** Split into canonical `config/show` + `config/patch`. The "pending per-method selectors" caveat was **mistaken**: `task_routes` layers the *method* router and axum merges same-path method routers per method, so each verb already enforces its own Trust Task — proven by `vti_common::trust_task::openapi::per_method_tasks_on_one_path_are_enforced_independently`. The same applies to any other merged-method mount (e.g. `acl/legacy/entry`). Open the `source` enum — `env > db > toml > default` is a VTC implementation choice. |
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

   1. **`auth/passkey/list`** (group A3) — reconcile `deviceLabel` vs
      `label` while doing it. Also the canonical passkey-revoke A2's
      `admin/passkeys/revoke` targets, if `vta/passkey-vms/revoke`'s
      fragment-based identifier is judged the wrong fit.
   2. **The group B generics** — `audit/{list,verify}`,
      `config/{show,patch,reload,restart}`, then `config/{export,import}`
      once `communityProfile` moves to `ext`.
   3. **The policy-family extensions** (`policy/get`, `policy/activate`,
      and a home for `purpose`) — the self-management plane's decision
      layer; move all five (decision confirmed, see group C).

   No step-up envelope appears here: the delegated `confirm/1.0` gate
   (see "Two planes") reuses tasks that already exist, so A2 needs no
   canonical addition at all — only the passkey-revoke target above,
   shared with A3.
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
   effort, though the reduction cuts it from 64 to ~47.
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

## Settled decisions

Recorded so they are not relitigated:

- **Policy family → extend canonical, move all five.** `policy/get` +
  `policy/activate` + a canonical home for `purpose` are added, and VTC
  binds canonical for the whole family. It is the self-management plane's
  decision layer (see "Two planes"); the `purpose` governance enum is
  community-specific even though the CRUD verbs are generic.
- **`auth/admin-login` → collapse into `auth/authenticate`.** The only
  delta was a cookie side-effect for SIEM distinguishability, which the
  audit event type already carries; the cookie behaviour moves to a
  transport binding / `ext`.
- **Management-plane approval → delegated `confirm/1.0`** (see "Two
  planes"). Not inline step-up, not self step-up. No `_shared` envelope.
- **`credential-exchange/*` → keep; not dead.** The five directories are
  complete Phase-3 specs whose IDs are referenced by dispatched handler
  code (`vtc-service` `messaging.rs:449-450`) via
  `vta_sdk::protocols::credential_exchange` constants. Their absence from
  `index.json` is tracked backlog (credential-architecture plan task 3.7,
  the same "unpublished bound tasks" class as #709), not abandonment.
  Publishing them is completing 3.7; deleting them would orphan live
  handlers. They migrate to `spec/vtc/credential-exchange/*` (or a shared
  `spec/credential-exchange/*` if the shape is service-agnostic — decide
  when 3.7 is done).

## Open questions

- **Version numbers.** Surviving tasks stay at `1.0`; content is
  unchanged and a lower number would imply a maturity regression that did
  not happen. Group B promotions start at `0.1`, matching how the
  canonical families they join are versioned.
- **Where `confirm/1.0` gating is enforced.** DID-hosting applies its gate
  to exactly one operation today (domain force-delete); the extractor +
  `elevate_session` helpers live in `did-hosting-common`, with no shared
  SDK. VTC either depends on that crate or reimplements the gate. Which,
  and whether the gate helper should be promoted to a shared crate, is an
  implementation decision for the management-plane work, not this note.

## Non-goals

- Changing payload shapes for their own sake. Where a group A schema
  differs from canonical, converging on canonical is in scope; redesign
  is not.
- Migrating the 7 auth tasks retired in PR #711. They are terminal per
  §5.3 and already declare `supersededBy`.
- #709 (unpublished bound tasks) as separate work — those get authored
  directly in the new shape here, which is why #710 blocks it. The
  reduction likely absorbs several of them outright.
