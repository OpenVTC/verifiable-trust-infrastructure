# Changelog

## Unreleased

### vta-sdk 0.20.8 / vta-service 0.12.43 / vtc-service 0.11.37 — credential-exchange resolves, and the registry guard covers the whole authority (#821)

The eight `credential-exchange` Trust Tasks now bind URIs the registry actually
publishes (`trust-tasks-rs` 0.2.41, authored in trust-tasks-tf#148). Five of
them previously existed **only** as files in this repo while claiming a
`trusttasks.org` ID no consumer could resolve; the other three —
`pending-list`, `pending-approve`, `pending-deny` — had no spec anywhere at all.

**Breaking wire changes** on all eight:

- Renumbered `1.0` → `0.1`, matching how the rest of the registry versions.
- `pending-list` / `pending-approve` / `pending-deny` are nested as
  `pending/{list,approve,deny}`. The family now reads as what it is: a
  party-to-party wire protocol, plus an operator surface over the consent
  backlog it generates.
- **`PendingPresentationSummary` and `RequestedCredentialSummary` serialize
  camelCase.** Every member of those two is ours, so the registry's casing
  convention applies — `verifier_did` → `verifierDid`, `created_at` →
  `createdAt`, `credential_query_id` → `credentialQueryId`. The OID4VCI /
  OID4VP bodies keep snake_case: `credential_offer`, `dcql_query`, `vp_token`
  are those specifications' own field names, not casing drift. The *stored*
  deferral record is unchanged — it is fjall-persisted internal state, not a
  wire type, and renaming it would need a migration for no benefit.

There are no external consumers of these constants, so the rename is free.
`trust-tasks/credential-exchange/` is deleted: the specs live upstream now, and
keeping a second copy is how the two drift.

### The guard that should have caught this

`every_bound_vtc_task_exists_in_the_registry` only ever checked the
`spec/vtc/` prefix, which is why eight URIs on the same authority went
unverified. It is now
`every_bound_canonical_task_exists_in_the_registry` and checks **every**
`https://trusttasks.org/spec/` URI the workspace binds. A per-family prefix is
the wrong shape for the assertion: it defends the family someone remembered to
name and silently exempts the next one. The claim being tested is about the
*authority* — binding a `trusttasks.org/spec/` URI asserts the registry serves
it.

Widening it required distinguishing a task URI from other strings sharing the
prefix, which is done by shape: a Type URI ends in a `MAJOR.MINOR` segment
(SPEC §6.1). That one rule excludes family prefixes used to build or assert
URIs (`vta-sdk`'s `ALLOWED_PREFIXES`) and shared-schema `$id`s, which are
components rather than tasks.

**It immediately found 67 more.** All pre-existing, none introduced here:

| Family | Unpublished | What |
|---|---:|---|
| `spec/vta/` | 55 | The bulk of the VTA's own Trust Task surface at 1.0 — keys, contexts, backup, seeds, acl, audit, attestation, config, discovery, management, provision-integration, webvh dids/servers/agent-name. The registry publishes 22 `vta/*` tasks; the workspace binds 77. |
| `spec/vault/` | 12 | The vault + credential-store archival lifecycle (#540), authored as local "openvtc 0.1 extensions" and never taken upstream. |

Plus `spec/trust-task-error/0.1`, which is a permanent and legitimate
exception — the framework's error *envelope* is a response type, deliberately
absent from the task index.

These are recorded in `UNPUBLISHED_CANONICAL_OK` as family-level exceptions
**with asserted counts**. Listing 68 URIs individually would be unreadable;
excluding a family without a count would let the next unpublished task in it
pass unnoticed, which is the failure this assertion exists to prevent. Pinning
the number means the debt can only shrink — publish some upstream and the count
drops, add a new unpublished one and the test fails.

Nothing here is a runtime defect: the bindings work. They reference specs no
consumer can fetch, which is a published-authority claim we are not yet
entitled to make.

### vtc-service 0.11.36 — the VTC accepts Trust Tasks over TSP

TSP frames already reached the VTC: the delivery-layer `DidCommTransport` owns the
one mediator websocket and surfaces both protocols off it, tagging each
`Inbound.message.protocol`. The dispatcher then dropped every TSP frame **silently**
at its first line, because a TSP payload is Trust-Task bytes rather than a DIDComm
plaintext and `serde_json::from_slice::<Message>(…).ok()?` simply returned `None`.

This is §6.1/§6.2 of `docs/05-design-notes/tsp-enablement.md` for the VTC, mirroring
`vta-service`'s `messaging::tsp_inbound` + `service::handle_tsp` deliberately — TSP,
DIDComm and REST all feed `dispatch_trust_task_core`, so a caller gets identical
round-trip semantics whichever transport it arrived on.

- `Protocol::TSP` frames route to a new `handle_tsp`, which dispatches on the shared
  spine and seals the response back to the proven sender over the same socket
  (`atm.tsp().send_routed([mediator_did, sender_vid])`). **No second websocket** —
  the mediator permits one per DID and evicts a second as `duplicate-channel`.
- The caller identity is the VID TSP's `unpack` authenticated, and **only** when
  `verified` is set. `tsp_sender` is factored out so that decision is unit-testable
  without a mediator; there is deliberately no plaintext-`from` fallback, since TSP
  has no public-read handler that could justify one.
- An unauthorised caller gets a Trust-Task error envelope rather than silence. The
  VID is cryptographically proven, so there is no enumeration exposure, and a
  conformant client only understands envelopes.
- `JoinTransport::Tsp` records the arrival transport.

Receive-side only. Answering over TSP is required (the caller waits on the TSP
correlation), but VTC-**initiated** sends to members stay DIDComm until the Phase B
flip (§12, §14 Q4).

Behind the `tsp` feature, still off by default, and the feature now also enables
`affinidi-tdk/tsp` for `atm.tsp()`. Both configurations build, and 695 lib tests pass
in each.

**Not yet advertised.** The VTC's DID document does not carry a `#tsp` service, and
must not until this ships — TSP is the highest-preference transport, so advertising
before accepting would have clients select it and get silence. Advertising needs no
code: it is an `update_did_webvh` service patch on the VTA-managed VTC DID.

### vtc-service 0.11.35 — the retired Trust Task authority has no bindings left (#710)

`admin/config/{export,import}` move to canonical
`spec/vtc/config/{export,import}/0.1`. They were the last two bindings on
`https://trusttasks.org/openvtc/vtc/`, and **that authority is now unbound
across the whole workspace** — router, `vta-sdk` constants, admin SPA and
`cnm-cli` alike. All 66 entries in `trust-tasks/index.json` are `retired` with
a `supersededBy`, which turns that file from a manifest into a redirect table.
Both census tables in `vtc-service/tests/trust_task_manifest.rs` are empty;
`no_new_bindings_on_the_retired_authority` is what stops it regressing one
literal at a time.

These two were the only entries whose recorded blocker was *real*: no canonical
counterpart existed — `specs/config/` published `show`, `patch`, `reload`,
`restart` and nothing to migrate to. They are now authored upstream
(trust-tasks-tf#147, `trust-tasks-rs` 0.2.40, pinned here).

**Not promoted into the generic `config/*` family.** The recorded plan was to
push `communityProfile` into `ext` and make these generic. Dropped: the profile
and its diff are roughly half the import's payload, so the "generic" task would
have been a hollow shell in its only real use. They are `vtc/`-slugged, on the
`vtc/backup/{export,import}` precedent.

**Breaking wire changes** — the repoint is not a rename:

- **`confirm` moves from the query string into the payload.** A Trust Task is
  one interface over REST, DIDComm and TSP, and only REST has a query string to
  carry a flag in. A stale client still sending `?confirm=true` now **previews**
  instead of applying — the recoverable direction, and pinned by a test.
- **Export wraps its result**: `{ "document": { … } }` rather than the bare
  document. The registry response convention needs `additionalProperties: false`
  plus an `ext` extension point, and neither attaches to a bare `$ref`.
- **Import's response is one shape with a discriminant.** `confirmed: bool` →
  `status: "preview" | "imported"`; `communityProfileDiff` → `profileChanges`;
  `configOverridesDiff` → `overrideChanges`. The `communityProfileApplied` /
  `configOverridesApplied` lists are **gone**: on `imported` the change arrays
  carry what was actually written, so a key that failed to persist is in
  `rejected` and not reported as applied.
- **`pendingRestart` is new, and is reported on the preview too** — an operator
  learns that confirming implies downtime while they are still deciding.
- Absent-vs-null is now preserved on the wire. `oldValue` / `newValue` are
  omitted when unset rather than emitted as `null`, so "leave this field alone"
  stays distinguishable from an explicit "clear it".

No SPA or CLI consumer existed for either endpoint, so the blast radius is
external callers only.

### vta-sdk 0.20.7 — `receive_next`'s poll loop no longer trips `never_loop` without the `tsp` feature

`DIDCommSession::receive_next` polls in a `loop`, but its only `continue` — the
skip for an inbound TSP frame that belongs to the TSP leg's own subscriber — is
`#[cfg(feature = "tsp")]`. Compile that out and every arm returns, so clippy
sees a loop that runs exactly once and denies `never_loop`.

Accurate, but not actionable: the iteration exists to re-poll after skipping a
frame that only exists in the `tsp` build. Annotated
`#[cfg_attr(not(feature = "tsp"), allow(clippy::never_loop))]` so the lint stays
live in the configuration where it can still catch a real regression.

**This was a latent CI break, not just a local one.** `tsp` is off by default in
`vta-service`, so `cargo clippy --workspace` builds `vta-sdk` without it too —
CI has been passing only because its `stable` toolchain predates the lint
firing here. `cargo clippy -p vtc-service` already failed hard today.

### vtc-service 0.11.34 / vti-common 0.11.28 — two of the last four bindings leave the retired authority (#710)

`POST /v1/auth/admin-login` and `GET, PATCH /v1/config` are **removed**. Both
were the last VTC surfaces enforcing a `https://trusttasks.org/openvtc/vtc/…`
Trust Task, and both turned out to be deletions rather than the folds the
design note had recorded. Two bindings remain on that authority
(`admin/config/{export,import}`), and they are blocked upstream, not here.

**`auth/admin-login` — the recorded blocker assumed the endpoint had to
survive.** It was to "collapse into `auth/authenticate` with the cookie
side-effect moved to a binding/`ext`". But the endpoint ran the same
`authenticate_and_mint` as `POST /v1/auth/` and differed only by appending
`Set-Cookie`, and that cookie half is already a canonical task of its own:
`POST /v1/auth/admin-session` (`spec/vtc/auth/admin-session/0.1`) validates an
access token the caller holds and mints the same `vtc_admin_session` + `csrf`
pair. So admin login is `spec/auth/authenticate/0.1` then that — no binding
extension needed, and the `Trust-Task` value still distinguishes a cookie mint
from a bearer one for SIEM filtering, which was the separate ID's whole
justification. It was removed rather than repointed because **nothing called
it**: the admin SPA already logs in this way (`admin-ui/src/lib/wallet.ts` →
`pages/Login.tsx`), and no test, CLI or SDK path referenced it. Passkey login
(`/v1/auth/passkey-login/finish`) mints the cookies directly and is unchanged.

**`config/legacy/manage` — the recorded reason was wrong twice over.** It read
"strict duplicate of `admin/config/manage`, which shipped": that task was
itself retired, and the two surfaces never shared a single field. `/v1/config`
carried community identity; `/v1/admin/config` carries `server.host` /
`server.port` / `log.level`. The deletion stands on a field-by-field ownership
audit instead:

| Legacy field | Canonical owner |
|---|---|
| `vtc_did` | `communityDid` on `spec/vtc/community/profile/show/0.1` — any authenticated session, the same reach the legacy `GET` had |
| `vtc_name`, `vtc_description` | `spec/vtc/community/profile/{show,update}/0.1`, already the sole write path the legacy `PATCH` delegated to |
| `public_url` | the `config_store` db-overlay, read by `spec/config/show/0.1` and written by `spec/config/patch/0.1` — the same overlay the legacy `PATCH` wrote |

The legacy handler's `409` on `vtc_did` / `vta_did` went away with it, so the
guarantee it enforced is now pinned on the successors, where it holds
structurally rather than by a runtime branch: `CommunityProfileUpdate` has no
`community_did` field, and neither identity key is in the config-store
`REGISTRY`, so a patch naming them is rejected as an unknown key. New suite
`vtc-service/tests/config_identity.rs` asserts exactly that, plus the
`public_url` overlay round-trip the retired `tests/config_legacy.rs` used to
cover. `admin_config.rs` exercises pending-restart with `server.port`; this
does it with the key the legacy PATCH actually wrote.

**The census tables are both empty now.** `UNBOUND_OK` held seven shared-mount
exceptions; five had been retired as their families moved to `spec/vtc/*`, and
the remaining two were `draft` rows on the retired authority describing routes
that had *already* migrated — `GET /v1/endorsement-types` enforces
`spec/vtc/endorsement-types/register/0.1`, `DELETE /v1/members/{did}/personhood`
enforces `spec/vtc/members/personhood/assert/0.1`. Both are retired now against
the canonical `list/0.1` / `revoke/0.1` the registry publishes. Those two mounts
still collapse a second verb onto a sibling's canonical task; the fan-out is
unblocked (Phase 2c) but is a canonical-side split, not an authority migration,
so it is left for its own change.

**What is left, and why it is not backlog.** `admin/config/{export,import}` are
blocked on an upstream spec that does not exist — `specs/config/` publishes
`show`, `patch`, `reload`, `restart` and no export/import counterpart. The
earlier plan to promote them as a generic `config/{export,import}` with
`communityProfile` pushed into `ext` is dropped: `communityProfileDiff` /
`communityProfileApplied` are roughly half the import response, so the generic
task would be a hollow shell in its only real use. `vtc/backup/{export,import}/0.1`
is the precedent for the alternative — VTC-slugged, `confirm` carried in the
payload rather than a query string, fields first-class. Target is
`spec/vtc/config/{export,import}/0.1`, to be authored in
`dtgwg-trust-tasks-tf`; the repoint here follows that release.

### vta-sdk 0.20.6 — re-export `resolve_vta_with_resolver` alongside `resolve_vta`

`provision_client` re-exports a curated list, and #813 added
`resolve_vta_with_resolver` to `resolve.rs` without adding it there. So the
function existed and was `pub`, but not at the path its sibling lives at:
`provision_client::resolve_vta` worked while
`provision_client::resolve_vta_with_resolver` did not, and a consumer had to
reach through `provision_client::resolve::` to find it.

OpenVTC hit exactly that wiring its TSP discovery tests
(OpenVTC/openvtc#198) and worked around it with the deeper path. An
asymmetric export on a pair of functions that differ only by "and here is
the resolver" is the kind of thing every future caller stubs a toe on.

Additive — the deeper path keeps working, so nothing that already compiles
breaks.

### vta-sdk 0.20.5 / vti-common 0.11.27 / vta-service 0.12.42 / vta-cli-common 0.10.16 / pnm-cli 0.11.11 / cnm-cli 0.11.10 — ACL listings can be asked which direction a context filter reads (#822)

`GET /acl?context=X` answers "who may act **in** X" — entries scoped to X or to
an ancestor of it. That is correct, and it is one of two questions a context id
raises, because a context id names a subtree. The other — "what is granted
**beneath** X" — had no way to be asked, and asking it with the act-in filter
returns precisely the entries that are *not* the answer: the ancestors keeping
their authority, with every leaf-scoped grant omitted. Short, not empty, so it
reads as complete.

That bites on revocation. Once sub-contexts exist the least-privilege layout is
a leaf per purpose (`<tenant>/<unit>/<purpose>` — partly because, absent a
per-key actor grant (#818), a context of its own is the only way to scope a
caller to one key), and a sweep of `<tenant>/<unit>` then misses *every*
principal under it. Cierge's kill switch hit exactly this
(affinidi/cierge#49): a gateway grant at `<domain>/attestation` survived the
cut and could keep signing as the killed domain while the report said success.

**An explicit direction on the filter**, defaulting to today's behaviour:

| direction | question | predicate |
|---|---|---|
| `acting-in` (default) | who may act **in** X? | entry scope `is_ancestor_or_self` of X |
| `subtree` | what is granted **beneath** X? | X `is_ancestor_or_self` of the entry scope |
| `any` | whose authority **touches** X's subtree? | either |

One enum rather than a `subtree=true` flag, because "either direction" is the
third question an auditor actually asks and a boolean cannot spell it.

Surfaces: `GET /acl?context=…&direction=…`, a `direction` member on the
`spec/vta/acl/list/1.0` payload (and the DIDComm `list-acl` body),
`pnm|cnm acl list --direction`, the offline `vta acl list --direction`, and
`VtaClient::list_acl_in_direction`. `VtaClient::list_acl` is unchanged and
stays `acting-in`; the client omits the parameter entirely at the default, so
requests that mean what an older VTA already does still reach it.

Two edges, both deliberate and tested: an **unrestricted (super-admin) entry is
not in the `subtree` answer** — it names no context, so it is not a grant *of*
the branch, and returning it would hand a caller revoking a compromised branch
its own super-admin to delete (`acting-in` and `any` report it); an entry naming
contexts inside *and* outside the branch **is** in it, because it does hold a
grant inside and omitting it would under-report.

Fail-closed: absent parameter is byte-for-byte the previous behaviour, pinned at
the scope, entry, and operation layers. An unparseable direction is refused with
the valid set rather than defaulted, and a direction with no context is refused
rather than silently answered with the whole ACL — guessing which of two
opposite questions the caller meant is the defect, one level up. The CLI prints
the question it asked beside the count, including on an empty result.

The VTC's equivalent filter deliberately did **not** follow: its listing is
bound to the canonical `acl/list/0.1` Trust Task, whose payload is
`additionalProperties: false`, so a `direction` member is an openvtc spec change
(or an `ext` member), not a local one. Recorded as a follow-up in
`docs/05-design-notes/acl-scope-semantics.md` — with the note that the VTC list
is paginated, so `direction` must also join the cursor binding or a resumed
sweep changes question mid-listing.

### VTC Trust Tasks — the unpublished-manifest backlog is closed (#709)

`vtc-service/tests/trust_task_manifest.rs` carried twenty `UNPUBLISHED_OK`
exceptions: task URIs the router enforced that `trust-tasks/index.json` never
published. The table is now empty — but **not** because twenty specs were
authored into that manifest. Every one of those tasks was resolved by the #710
migration (#806 / #809 / #811 / #812 and predecessors): they now bind canonical
`https://trusttasks.org/spec/vtc/<slug>` URIs published by the upstream
registry, verified against `trust_tasks_rs` by
`every_bound_vtc_task_exists_in_the_registry`. Nothing in the workspace binds
any of the twenty on the old authority any more.

The table stays in place, empty, because the assertion behind it still is: a
new `openvtc/vtc/` binding with no manifest row fails rather than silently
reopening the backlog.

**The manifest's own description was false and now says so.** It claimed to be
the "source of truth for trusttasks.org publication" with "CI publishes Draft
entries on every merge to main per spec §9.4". No CI job has ever read
`trust-tasks/index.json` — that pipeline was never built. The description now
records what the file actually is: a historical record of the retired
`openvtc/vtc` authority, 60 entries retired and 6 awaiting a canonical fold.
(Now 64 and 2 — see the entry above.)

### vta-sdk 0.20.4 / vta-service 0.12.41 — the signing oracle's authorization model is a documented guarantee (#805)

The VTA signs the bytes it is handed without inspecting them, so *which keys a
caller may name* is the whole of the authorization story. A companion proposal
was declined partly on the reasoning that per-key scoping already delivers the
identity property — but that reasoning was read off an SDK field comment
("must be an active key the caller has access to") rather than observed in the
service, and a multi-domain signer now depends on it.

**Confirmed: the service enforces it**, in three layers, in
`operations::keys::sign_payload` — and more strictly than the field comment
implies:

1. **Caller's context scope** — `require_context` on the key's `context_id`,
   via `ActScope`.
2. **The key's context policy** — `signable_keys` is *resource-bound*: it
   constrains the key's context **regardless of the actor, including a
   super-admin**. That is what lets a fleet- or VTC-pushed policy bind every
   signer; the owner relaxes it via policy CRUD, not by holding a bigger role.
3. **Unscoped keys are super-admin only** — no context means no policy, so the
   role floor is the only guardrail left.

All three transports (REST, DIDComm `key-management/1.0/sign-request`, and the
`keys/sign` Trust Task) funnel through that one function, so there is a single
enforcement point rather than three.

**Documented, with the caveat that matters.** Enforcement is **per context, not
per key id**: holding a context authorizes every key in it. A signer acting for
several identities therefore needs a context *each* — putting several
identities' keys in one context and scoping the caller to it authorizes all of
them. `signable_keys` gives per-key narrowing but is opt-in policy an operator
must write. New §"What authorizes a sign request" in
`docs/02-vta/integration-guide.md`; the SDK field comment now states the
guarantee and points there instead of implying it.

**Two of the three layers had no regression test** — the two the declined
proposal actually rests on. Added
`sign_payload_refuses_a_key_outside_the_callers_contexts` and
`sign_payload_restricts_unscoped_keys_to_super_admin`; both verified to fail
when their check is removed.

### vta-sdk 0.20.3 — transport discovery is testable without a live VTA

`resolve_vta_endpoint` built its `DIDCacheClient` from the environment, so a
consumer had no way to point discovery at a fixture: seeding a document into its
own cache did nothing, because the function never saw that cache. The practical
effect was that "does this VTA advertise `#tsp`" — the question #765 and #810
made answerable — could still only be *asserted* against a live deployment.
OpenVTC hit this trying to cover its TSP-enablement path (OpenVTC/openvtc#185)
and had to leave the assertion unmade.

- `resolve_vta_endpoint_with_resolver(vta_did, &DIDCacheClient)` and
  `provision_client::resolve_vta_with_resolver(...)` run the same discovery over
  a caller-supplied resolver. The env-configured entry points delegate to them,
  so behaviour is unchanged and no caller has to move.
- Follows the pattern `resolve_mediator_did_with_resolver` already set in the
  same module, for the same two reasons: reuse (no second cache per resolve) and
  testability.
- `provision_client`'s two entry points now share one `flatten`, so they cannot
  disagree about what an endpoint shape means.

Additive. Four new tests seed a document and assert what discovery makes of it,
in-process with no network: a dual `#tsp` + `#vta-didcomm` VTA (the reference
deployment's shape) reports both in preference order; a DIDComm-only VTA reports
no TSP; a TSP-only VTA does not fall back to a REST URL synthesized from its own
domain; and a `#tsp` entry carrying a URL instead of a mediator DID is ignored
rather than routed through.


### vtc-service 0.11.33 — the raw-byte website endpoints stop pretending to be Trust Tasks

Three endpoints on the website management surface move **file bytes**:
`GET`/`PUT /v1/website/files/{path}` and `POST /v1/website/deploy`. A Trust
Task's payload is a JSON document, so none of them can be one — there is no
document shape for "here are 4 MiB of PNG", and no canonical spec will ever
supersede them.

All three were nevertheless gated on a `Trust-Task` header, sharing
`openvtc/vtc/website/files/show/1.0` (or `…/deploy/1.0`) — tasks that existed
only to give the mount *a* header to check. Because the whole mount shared one
gate, the `PUT` and the `DELETE` both announced themselves as a **read**.

- The three byte-moving endpoints are **de-listed**: no header required, specs
  removed from `trust-tasks/`. They keep every authorization gate they had —
  de-listing removes a *header* check, never `AdminAuth`.
- `DELETE /v1/website/files/{path}` carries a path, not a payload, so it is a
  genuine Trust Task. It now binds the canonical
  `spec/vtc/website/files/delete/0.1` it should have had all along. This is the
  last of the four canonical website tasks to be wired.
- `openvtc/vtc/website/files/delete/1.0` moves `draft` → `retired` with a
  `supersededBy`; the on-disk spec tree now matches the manifest exactly.

Three census exceptions go away, and the retired `openvtc/vtc/` authority is
down from **6 bound URIs to 4** — all four now genuinely blocked on other work
(`admin/config/{export,import}` on `communityProfile` moving to `ext`,
`auth/admin-login` on the cookie side-effect, `config/legacy/manage` on a
field-ownership audit).

**For API clients:** stop sending a `Trust-Task` header on the three exempt
endpoints (a stale one is now ignored there rather than checked). On `DELETE`,
send `spec/vtc/website/files/delete/0.1` — the old `…/files/show/1.0` now fails
with `TrustTaskMismatch` (415). The admin SPA, `cnm-cli` and `vta-sdk` call none
of these, so nothing in-tree needed updating.

New `vtc-service/tests/website_task_gating.rs` pins all of it — including that
the de-listed routes still refuse an unauthenticated caller, which is the
distinction the change turns on.

### vti-common 0.11.26 / vtc-service 0.11.32 / vta-service 0.12.40 — step-up means *recent*, and admin promotion uses it

`StepUpAuth` gated on `acr == "aal2"` and nothing else. That reads as "this
session reached two factors at some point", not "a second factor was confirmed
for this operation" — and the two diverge badly, because a passkey sign-in is
`aal2` from its very first request and refresh preserves it for the session's
whole life. A route behind that gate would have accepted a sign-in from an hour
ago, losing the property such routes exist for: that a stolen session cannot,
by itself, authorise the next privileged operation.

Freshness already had a home — `Session.acr_expires_at`, which the VTA's
step-up ceremony stamps and the intrinsic-sender (DIDComm/TSP) resolver honours
by downgrading `acr` on read. Its own doc named the missing half: *"a later
phase wires REST into the same read-time downgrade."* This is that phase, and
it does not need a new JWT claim — the `AuthClaims` extractor already loads the
session row for the `jti` pin.

**`StepUpAuth` now requires a live elevation window** as well as `aal2`, read
straight off the session. An absent deadline is **refused**, not waved through:
an unknown elevation time must never read as a recent one. REST deliberately
does *not* copy the intrinsic path's read-time `acr` rewrite — the gate reads
the deadline directly, so a stale `acr` can never satisfy it, and a passkey
login stays honestly reported as `aal2` instead of being downgraded below the
level it logged in at. `Session::elevation_active` /
`downgrade_lapsed_elevation` put both readings in one place.

Nothing regresses: `StepUpAuth` had no call sites, and every other extractor is
untouched.

**`purpose: stepUp` is now implemented** on the VTC's passkey-login pair, which
moves from `spec/auth/passkey/login/{start,finish}/0.1` to `/0.2` (the camelCase
`stepUp` enum; the 0.1 constants in `vta-sdk` are already deprecated). A comment
in `routes/mod.rs` claimed the payload's `purpose` field already selected between
login and step-up — no handler read it.

A step-up is not a login with a flag, and the differences are the security
content:

| | `purpose: login` | `purpose: stepUp` |
|---|---|---|
| Caller | unauthenticated — the ceremony *is* the auth | must already hold the session |
| Credentials challenged | every registered passkey (discoverable) | **only the caller's own** |
| User verification | as the authenticator offers | **required** — a silent assertion is one factor |
| Result | a new session + tokens | the existing session elevated in place, **no** tokens |

The ceremony is bound at `start` to the session that asked for it and re-checked
at `finish` against both the session id and its subject, because neither of
`start`'s arrangements is load-bearing on its own: `allowCredentials` is a
client-side hint, and the token presented at `finish` need not be the one
presented at `start`. Without the subject re-check, any enrolled admin's passkey
would elevate anyone's session.

`subject` is honoured rather than noted: it narrows a login challenge, and a
step-up naming anyone but the authenticated subject is refused.

Operator-visible: the elevation lasts 15 minutes (matching the VTA's
`STEP_UP_ELEVATION_TTL_SECS`), reported to the client as
`ext["org.openvtc.step-up"].expiresAt`.

#### Breaking — `promote-to-admin` folds onto `members/update`

`POST /v1/members/{did}/promote-to-admin/{start,finish}` is **removed**. Admin
promotion is `PATCH /v1/members/{did}` with `{"role": "admin"}`
(`spec/vtc/members/update/0.1`), on a session carrying a live step-up
elevation. `openvtc/vtc/members/promote-to-admin/1.0` is `retired`,
`supersededBy` the canonical task, and leaves `AWAITING_CANONICAL_FOLD`.

The fused endpoint bundled a WebAuthn UV *ceremony* with a role-change
*operation*: one URI carrying two tasks' worth of semantics, a second
implementation of passkey UV alongside `auth/passkey/login`, and a proof of
user presence that could authorise exactly one operation and nothing else.

Every security property carried over — UV required, the caller's own passkey,
self-promotion refused, serialised under `PROMOTE_LOCK`, the already-admin
re-check inside the critical section, and still routed through
`role_change_via_pipeline(step_up = true)` so `role_change.rego` governs it
(P0.14). What changed is *when* the UV happens: recently, in its own request,
which is what makes the window mean anything.

Two deliberate differences:

- **The authorising credential id** moved off `AdminPromoted` onto a new
  `AuthSteppedUp` audit event emitted by the ceremony itself. `AdminPromoted`
  gains `authorisingSessionId`, which joins the two rows. Both new fields are
  `#[serde(default)]`, so archived envelopes from either side of the fold
  deserialise.
- **Promoting an existing admin is a `200` no-op**, not a `409`. `POST
  …/promote-to-admin` was imperative and promoting an existing admin is
  meaningless; `PATCH` is declarative — the role *should be* admin, and it
  already is — so a retried request is safe. The `409` that mattered still
  guards the concurrent-promotion race.

The recorded plan for this fold named `acl/change-role` as the target. It does
not hold: that task is bound to `PATCH /v1/acl/{did}`, a bare ACL write that
never runs `role_change.rego` and serves non-member ACL rows (integrations,
install DIDs). Routing admin promotion through it would have reintroduced the
P0.14 policy bypass. `members/update` already ran the ceremony.

The admin SPA is updated in lockstep — it steps up, then PATCHes.

### vta-sdk 0.20.2 — TSP is a per-surface leg, not a whole-client transport

A consumer holding a DIDComm session could not use TSP at all. The only way to
a Trust-Task-over-TSP client was `connect_tsp`, which opens its **own**
websocket — and the mediator permits one websocket per DID, so the second was
rejected with `duplicate-channel` and the two reconnect loops duelled. On the
reference deployment `#tsp` and `#vta-didcomm` resolve to the *same* mediator,
so that was the normal case; a split-mediator topology would have worked, which
is the worst shape available (correct on an unusual deployment, broken on the
one everyone runs). This blocked OpenVTC/openvtc#185 item 2b.

**The fix is the client-side mirror of one the VTA already shipped.**
`vta-service` deleted its standalone TSP websocket for exactly this reason and
now demuxes TSP off its single delivery-layer socket. The client can do the
same, because neither half of TSP needs a socket of its own: send is an HTTP
`POST /inbound` to the mediator, and receive already arrives on the DIDComm
pickup socket, which `live_stream_next_frame` tags by protocol.

- `DIDCommSession` gains a **TSP leg** — `send_tsp_document`, `request_tsp`,
  `receive_next_tsp` — over its existing connection. **No second socket.** The
  leg takes its own `subscribe()` receiver, so the TSP pump cannot eat a DIDComm
  push and `receive_next` cannot eat a TSP reply.
- `VtaClient::enable_tsp_trust_tasks` moves the Trust-Task surface
  (`dispatch_trust_task`, `rpc_tt`, the `device/*` and `vault/*` methods) onto
  it. **No I/O, cannot fail.** `attach_tsp_leg` covers the split-mediator
  topology, and refuses a second session for a DID on the mediator it is already
  connected to — the defect is now unrepresentable through the API.
  `connect_didcomm_with_tsp` does both in one call.
- `rpc` / `rpc_void` stay on DIDComm unconditionally. TSP carries Trust Tasks;
  the VTA has no TSP dispatcher behind `key-management/1.0/*`,
  `create_did_webvh` or `list_contexts`.

**Fixes a live regression on the `pnm`/`cnm` connect path.** Since TSP became
selectable, `TransportChoice::Auto` returned a **TSP-only** client whenever a
VTA advertised `#tsp` — so on a TSP-enabled VTA every protocol-message command
(`keys create`, `contexts list`, DID minting) failed with
`UnsupportedTransport`. `Auto` now returns a **dual** client against a VTA
advertising both: trust tasks over TSP, protocol messages over DIDComm, one
socket. A VTA advertising `#tsp` alone still yields a TSP-only client, and
`--transport tsp` is unchanged (TSP-only by request). If the DIDComm mediator is
down, `Auto` still falls back to TSP-only — loudly, naming what that client
cannot serve.

New: `SurfaceTransport` + `VtaClient::{trust_task_transport,
protocol_message_transport}`, because a client no longer has *one* transport and
an operator display that renders a single value is wrong by construction.

Also fixed: `DIDCommSession::receive_next` parsed every inbound frame as a
DIDComm `Message`, so a TSP frame on the multiplexed socket became a hard error
on the DIDComm inbox that received it. It now skips them. Latent until now,
because nothing sent TSP to an SDK DIDComm session.

Internals: reply correlation moved to a shared `tsp_demux` so `TspSession` and
the new leg cannot drift on the rule that stops a *stale* inbox frame being
returned as a reply (#749). Its parking queue is now bounded — previously
unbounded, which a long-running process that only calls `request` would grow
forever.

Verified live against the deployed VTA (a trust task dispatched over the DIDComm
session's socket, reply correlated back) and hermetically over the embedded
`TestMediator` in `tests/e2e/tests/tsp_dual_leg.rs`.


### vtc-service 0.11.31 — admin passkeys move to the canonical `auth/passkey/*` tasks

The `/v1/admin/passkeys/*` surface leaves the retired `openvtc/vtc/` authority
for the canonical tasks published in trust-tasks-tf#145 (`trust-tasks-rs`
0.2.38 → 0.2.39). Three of the eight entries in `AWAITING_CANONICAL_FOLD` are
gone; #710 and #709 shrink accordingly.

**No wire change.** The canonical specs were written *from* this
implementation, not the other way round, so request and response bodies are
byte-identical. Only the `type` URIs moved.

**One task per ceremony leg, where there used to be one per family.**
`admin/passkeys/register/1.0` covered both `register/start` and
`register/finish`; `revoke/1.0` likewise. A single schema spanning both legs
had to permit the union of their members, so a `finish` arriving without its
user-verification assertion still validated against the family task. Each leg
now names its own task:

| Endpoint | Task |
|---|---|
| `GET /v1/admin/passkeys` | `auth/passkey/list/0.1` |
| `POST …/register/start` | `auth/passkey/enroll/start/0.2` |
| `POST …/register/finish` | `auth/passkey/enroll/finish/0.2` |
| `POST …/revoke/start` | `auth/passkey/revoke/start/0.1` |
| `POST …/revoke/finish` | `auth/passkey/revoke/finish/0.1` |

Because a mount split means every caller must be audited *per leg* rather than
renamed in bulk, all four binding sites were walked individually — the router,
`tests/admin_passkeys.rs` (19 call sites), `tests/install_flow.rs` (3), and the
`myPasskeys` admin-UI plugin (4). The negative test that deliberately sends the
wrong task to `register/start` still sends a wrong one.

**The recorded blocker was wrong.** These three sat in
`AWAITING_CANONICAL_FOLD` needing "a `confirm/1.0` gate". `confirm/request` is
an *asynchronous* delegation whose response returns out of band on the
approver's own transport — appropriate when the approver is a separate party,
wrong here. This surface verifies the user *in-band, in the same request*, via
WebAuthn, and always did. `enroll/*` moves to 0.2 because that is the version
carrying the optional `uvOptions` / `uvCredential` members which describe the
re-authentication half this code already performs.

The superseded `admin/passkeys/{list,register,revoke}/1.0` are marked `retired`
with `supersededBy` in `trust-tasks/` and `index.json`, per SPEC §5.3.

### vtc-service 0.11.30 — audit checkpoints honour their own signing key

`verify_checkpoint_state` resolved every `verificationMethod` to the VTC's
*current* signing key (`|_vm| Some(current_key)`), which ignored the field
entirely. Two consequences: a checkpoint naming some other key was silently
checked against the live one, and the per-checkpoint `verificationMethod` that
#708 persists specifically to survive rotation was decorative.

The verifier now honours it. **The live signer is tried first, for its own
method only**; anything else goes to the DID resolver. That ordering matters —
resolving unconditionally would make a local integrity check depend on DID
resolution being configured and the community's DID being reachable, which
breaks verification outright on a deployment with no resolver. The common case
(a checkpoint signed by the still-current key) stays entirely local, and
resolution is reached only for a key the signer does not own — exactly the
rotated-away case the old code could not handle.

An unresolvable key is reported as **its own condition**, not as a bad
signature. "The signing key is no longer published" is expected after a
rotation; "this checkpoint was forged" is an incident, and the response must
let an operator tell them apart.

**Still not fixed, and now written down precisely:** verifying a checkpoint
signed under a key since rotated away needs the DID document *as it stood at*
`checkpointAt`. Neither `DIDCacheClient::resolve` nor `didwebvh-rs` offers
version- or time-addressed resolution — `didwebvh-rs`'s `version_time` creates
log entries rather than resolving history — so that is a resolver capability
rather than something the audit verifier should take on by replaying
`did.jsonl`. A deployment whose DID document retains prior verification methods
alongside the current one already verifies across rotation today.

Refs #708.


### vta-sdk 0.20.1 / vtc-service 0.11.29 / cnm-cli 0.11.9 / vti-common 0.11.25 — VTC Trust Tasks move to `spec/vtc/*`

The registry now publishes every VTC task (`dtgwg-trust-tasks-tf` #144,
`trust-tasks-rs` 0.2.38), so the bindings move off the non-conformant
`trusttasks.org/openvtc/vtc/...` authority they were never entitled to use.
This repoints **20 old URIs onto the 22 authored `spec/vtc/<slug>/0.1`
slugs** — 22 because two collapsed mounts split.

**All four binding sites**, in one change, because they cannot lag each
other: `routes/mod.rs`, the `vta-sdk` DIDComm constants, the admin SPA's
TypeScript `Trust-Task` headers, and `cnm-cli`. The SPA is compiled into the
binary by `build.rs`, so a partial migration would ship a UI calling URIs the
router no longer binds.

**Two mounts split per method.** `admin/invites/manage` served list *and*
create; `invitations/issue` served issue *and* list. One URI cannot state two
contracts, and the exposure differs sharply — issuing returns a bearer
credential, listing must never re-disclose one. `task_routes` layers the
method router and axum merges same-path method routers per method, so each
verb enforces its own task (pinned by
`per_method_tasks_on_one_path_are_enforced_independently`). The SPA's
`listInvitations` even carried the comment "Reuses the issue Trust Task";
it now has its own.

**The reciprocal-VMC exchange became three tasks.** `members/request-vmc`
(admin → VTC) and `spec/members/request-vmc` (VTC → member) would have
collided on one slug once the parsing-artifact `spec/` segment was dropped.
They are now `vtc/members/solicit-vmc`, `vtc/members/request-vmc`, and
`vtc/members/vmc`.

**BREAKING (wire): the VTC backup payloads are now camelCase.**
`ExportRequest`, `ImportRequest`, `BackupEnvelope`, `KdfParams`,
`EncryptionParams` and `ImportResult` carried no `serde(rename_all)` and were
snake_case on the wire, against R3.1 and against every other VTC payload.
`cnm-cli` is updated on both sides — it was sending `include_audit` and
reading `source_did` / `includes_audit` / `created_at`, all of which would
have silently returned `None` against the new server. **The VTA's backup wire
is untouched**: `vta-sdk::client::backup` targets a different service and
stays snake_case.

**De-listed, not migrated:** `website/deploy` and `website/files/show` are
raw-byte operations — a JSON Trust-Task payload cannot carry file bytes — so
the registry deliberately has no spec for them. They are removed from the
manifest rather than retired, because `supersededBy` is mandatory on a
retired entry and nothing supersedes them.

**The census test now reads every binding site**, not just the router. A
router-only scan is what produced the wrong residual count corrected in #802:
four tasks are `vta-sdk` DIDComm constants with no REST mount. Two new
guards:
- `no_new_bindings_on_the_retired_authority` — nothing may bind
  `openvtc/vtc/` outside a shrinking, reasoned allowlist of the 10 tasks
  still awaiting a canonical fold.
- `every_bound_vtc_task_exists_in_the_registry` — every bound `spec/vtc/`
  URI must resolve through `trust_tasks_rs::schema_index::schema_for`, so a
  typo or a slug that was never authored fails here rather than at runtime.

**Downstream:** `openvtc` consumes the changed `vta-sdk` constants and has a
DIDComm regex allowlist that will *reject* the new URIs until it upgrades. It
must land in the same release.

Deferred to a follow-up (tracked in `AWAITING_CANONICAL_FOLD`): the 8 tasks
that fold onto canonical specs rather than `spec/vtc/*`. Three of those are
blocked on upstream registry work, and three need the delegated `confirm/1.0`
gate.

Also updates `vti-common`'s Trust-Task doc examples and test fixtures off the
retired authority. They are not bindings — the census deliberately excludes
them — but a doc comment demonstrating `openvtc/vtc/...` teaches the shape we
just spent this change removing.

Refs #710, refs #709.


### vti-common 0.11.24 / vtc-service 0.11.28 / cnm-cli 0.11.8 — signed audit checkpoints

The `prev_hash` chain (#555) and `GET /v1/audit/verify` (#703) detect
reordering, dropping, duplication, and content edits. They do not detect the
adversary #537 tier 3 actually named — one with **write access to the `audit`
keyspace** — because `chain_digest` is an *unkeyed* SHA-256, so that adversary
holds everything needed to recompute it:

- **Restamping** — edit or insert an envelope, recompute its `entry_hash`, walk
  forward restamping every successor. Verifies cleanly. No secret required.
- **Truncation** — delete everything after some point. The remaining prefix is
  a *valid chain*, and nothing recorded how long the log should be, so a
  truncated log was indistinguishable from a community that went quiet. This is
  the cheaper attack and the more serious one: it erases an incident with no
  forgery at all.

**What ships.** A periodic `AuditCheckpoint`, signed with the **community
Ed25519 key** (the same `LocalSigner` that issues VMCs/VECs), committing to the
chain head *and* `entry_count`. That count is the load-bearing field: a log
shorter than a signed checkpoint attests to has lost entries, and that
contradiction cannot be manufactured from the store alone.

Not the audit HMAC key — it lives in the very store the adversary is assumed to
have reached, and symmetric verification means whoever can *check* a checkpoint
can also *forge* one, which reduces to the status quo. Signing with the
community key also makes checkpoints **externally** verifiable: an auditor
holding only the community DID can confirm the log has not been rewritten, with
no shared secret and no daemon access.

Checkpoints chain to each other, so deleting the checkpoint that contradicts a
truncated log is itself detectable — without that, the mechanism would protect
nothing.

**Beyond the design note**, three additions the threat model demanded:

- `entry_count` must be **monotonic** across the checkpoint chain. Otherwise an
  adversary could re-link a genuinely-signed *older* checkpoint into a later
  position and lower the attested count without forging anything.
- `emit_checkpoint` **refuses to sign** when the live log already holds fewer
  entries than the last checkpoint claims. Signing there would launder a
  truncation into a fresh "this is fine".
- Each checkpoint records the `verificationMethod` that signed it, so one
  signed under a later-retired key stays verifiable.

**Cadence** (the note left this open): time-based, default 15 minutes,
`[audit_checkpoints] interval_secs`, `0` disables with a loud `WARN`. The
interval is the attacker's free truncation window, so it sets residual risk
directly. Count-based triggering was deliberately *not* implemented — doing it
honestly needs a running entry counter in `AuditWriter`, and approximating it by
polling more often means walking the whole audit keyspace on a timer. A shorter
interval is the cheaper knob and bounds the window in *time* regardless of
traffic. A tick with no new entries emits nothing.

**`GET /v1/audit/verify`** gains a `checkpoints` block —
`consistent` / `truncated` / `headMismatch` / `chainBroken` / `noCheckpoints`,
with `attestedEntries` and `unattestedEntries`. That last one is the live
truncation window (entries written since the last checkpoint, covered by the
forgeable chain and no signature) and is reported rather than left implicit.
`cnm audit verify` prints it and now **exits non-zero on a checkpoint failure
even when the chain verifies** — that combination *is* the store-level attack,
and exiting 0 would make `cnm audit verify || alert` silent for the one thing
checkpoints exist to catch.

**Backup.** `audit_checkpoint` is in `BACKED_UP` and gated on the same
`include_audit` flag as `audit`. The pairing is not optional: either half alone
turns a legitimate restore into the truncation finding — checkpoints without
their log attest to entries that aren't there, and a log without its
checkpoints is shorter than every checkpoint claims. Pinned by two tests.

**Known limitation, recorded not hidden.** The verifier resolves every
`verificationMethod` to the VTC's *current* signing key, so checkpoints signed
before a community key rotation would stop verifying. The per-checkpoint
`verification_method` is already persisted for the fix (resolve the DID
document's key history), so it is a verifier change with no data migration.
External anchoring — publishing the head somewhere append-only to defend
against an adversary who *also* holds the signing key — remains out of scope
and is the next step.

Closes #708.

### vta-mobile-core 0.6.16 — give the phone the DID→name seam every other surface already has

The mobile agent shows DIDs where it has no choice: who is asking for a step-up,
who delivered a task-consent request, which VTA and mediator it is bound to. A
`did:webvh` in a phone caption is unreadable, and on an approval sheet
unreadable is not cosmetic — it is the operator approving something they cannot
identify.

New `vta_mobile_core::display_name`, a thin FFI skin over `vta_sdk::display_name`
— the same seam the PNM/CNM CLIs, the VTC CLI and the admin console render
through. Two exports:

* `resolve_agent_name(did) -> Option<AgentName { name, verified }>` — the
  round-tripped lookup, `display_name::agent_name::lookup` verbatim. Infallible
  by design: an unreachable name server must degrade to showing the DID, never
  fail the operator's approval.
* `shorten_did(did) -> String` — the pure abbreviation, exported rather than
  ported so the phone cannot drift from the CLIs and the console. An operator
  moves between all three looking at the same community.

**Why a skin and not an implementation.** A name is only safe to show because it
round-tripped: the DID's document claimed it *and* resolving that name led back
to the same DID. `alsoKnownAs` alone is self-asserted, so a hostile DID can claim
`mybank.com/@treasury`, and a display layer printing that bare has told the
operator they are looking at their bank — on the one screen where they are about
to approve something. That defence is already written and tested in `vta-sdk`;
re-deriving it in the engine, or across the FFI in Swift, would mean two
implementations of a spoofing check that must agree forever. So the *verdict*
crosses the boundary instead — `verified` is `vta-sdk`'s conclusion, and the
app's job is to not discard it.

Enables `vta-sdk/agent-names` for the mobile crate. Nothing in this workspace
publishes an `alsoKnownAs` entry yet, so `resolve_agent_name` returns `None` for
every DID today — the surfaces are wired so that minting names lights them up
without another mobile release.

### vtc-service 0.11.27 — a REST-only client can now refresh without a mediator

`POST /v1/auth/refresh` went straight to `atm.unpack` and — correctly, since
0.11.20 — required an authcrypt DIDComm envelope. That left the VTC's auth
surface asymmetric: a wallet could **log in** over plain REST via the SIOP
`id_token` path, but to spend the refresh token it was handed on the way out it
needed a mediator/DIDComm stack it otherwise never touched. In practice such a
client re-ran the whole SIOP round-trip on every access-token expiry instead of
refreshing. The VTA has had both halves of this loop since 0.12.x; the VTC only
had the first.

**Fix.** `refresh` now tries a canonical `auth/refresh/0.1` Trust Task document
before falling through to `atm.unpack`, mirroring the VTA's
`try_refresh_trust_task`. Refresh carries no proof — the opaque refresh token
*is* the bearer credential (RFC 6749 §10.4), verified by the canonical handler's
single-use rotating reverse index — so the REST path passes `signer_did: None`,
exactly as the VTA does. A VTC running with no `atm` at all can now serve
refresh.

The payload is `payload.refreshToken` (camelCase, per the generated spec type
and R3.1), byte-identical to the VTA's, so one document builder serves both
services. The DIDComm envelope path is untouched and still gated by
`bind_authcrypt_sender` — pinned by the existing
`plaintext_didcomm_refresh_is_rejected` regression, which still passes because a
plaintext DIDComm message has no `payload` member and so cannot be mistaken for
a Trust Task.

Also adds the header-exempt `POST /v1/wallet/auth/refresh` alias beside the
existing `/v1/wallet/auth/{challenge,}` pair. The browser wallet extension posts
with **no** `Trust-Task` header, so without this its loop was still incomplete:
it could log in header-free but not refresh. Same handler, op `type` in the body.

Closes #783.
### vta-sdk 0.20.0 — TSP is a selectable transport, not just a probe (BREAKING)

TSP has worked on the wire since #749/#750, but nothing between "the wire works"
and "a client can choose it" existed. A consumer could *ping* a TSP VTA and could
*receive* pushes; it could not transact with one. Three gaps, closed together
because each is useless without the others.

**Discovery (#765).** `session::resolve_vta_endpoint` never read the `#tsp`
service. It ran its own two-field extraction (`#vta-rest` + `DIDCommMessaging`)
even though `protocol::matching::ServiceCapabilities::from_did_document` — which
matches on service `type`, tolerates `type` as string-or-array, and had
understood `TSPTransport` all along — was sitting beside it. That duplication
*was* the bug, so discovery now routes through the shared matcher rather than
gaining a third bespoke branch.

Two consequences. A TSP-enabled VTA is no longer invisible: every SDK consumer
can see it advertises TSP. And a **TSP-only** document no longer falls through
both extractions to `url_from_did()`, which returned a REST URL synthesized from
the DID's own domain — an endpoint that need not exist. This SDK ships
`did-host-tsp` and `did-host-http-tsp` templates, so it could mint a node it
could not then resolve.

`ResolvedVta` gains `tsp_mediator_did` and `advertised()`, deliberately separate
from "the transport we connected over" — a probe needs both, independently
sourced. Conflating them is what rendered a TSP-advertising VTA as
"DIDComm (in use) · only transport offered".

**Selection (#766).** `TransportChoice` gains `Tsp` and `Didcomm`, and `Auto`
now implements the documented precedence **TSP > DIDComm > REST** (it previously
meant "DIDComm when advertised, else REST" — the precedence was documented
everywhere and implemented nowhere). `Didcomm` did not exist even implicitly:
forcing DIDComm was only available as "whatever `Auto` happens to pick".

`Auto` **falls back loudly**: an advertised-but-unanswering TSP mediator logs a
`WARN` naming the mediator and deadline, then tries DIDComm, then REST. Failing
hard would make a dual-transport VTA *less* available than before, purely for
having enabled TSP; falling back silently would make a permanently-broken TSP
deployment invisible. `--transport tsp` never falls back, for operators who want
the strict behaviour.

TSP connects are bounded (`VTA_TSP_CONNECT_TIMEOUT_SECS`, 30s default) with
their **own** ceiling rather than sharing the DIDComm one — the TSP websocket
hits the same mediator behind the same reconnect/backoff loop, so without a
deadline `Auto` preferring TSP would turn a working DIDComm fallback into an
indefinite hang. Per R6.4, "TSP advertised but the mediator went silent" and "no
TSP advertised at all" get distinct messages, the latter naming the transports
the VTA *does* offer.

**The client (#767).** `TspSession::request(vta_did, mediator_did, document,
timeout)` — correlated request/response, which is what makes TSP a transport:

- Replies match on `threadId` (fallback: echoed `nonce`), never "first frame
  that parses". The mediator inbox is durable and flushes on connect, so an
  uncorrelated read returns a reply from a *previous process run* — the fault
  that made the #749 delivery bug look intermittent. The correlation logic was
  written for `TspPingSession::ping` and welded there; it is now one shared
  `correlates` helper both paths use.
- Concurrent requests share one session. Whichever caller holds the socket
  demultiplexes for all of them (leader/followers), so a slow request cannot
  serialise a fast one and one request's read cannot consume another's reply.
  `receive_next` previously took the socket lock for its entire timeout budget.
- Frames matching no in-flight request are **parked** for `receive_next`, not
  discarded — a pushed `task-consent/request` must not be eaten by a request
  waiting on something unrelated.
- Every wait has a finite deadline (R1.2).

`VtaClient::connect_tsp` mirrors `connect_didcomm`, and `Transport::Tsp` plugs
into `dispatch_trust_task` — the single funnel — so the **whole Trust-Task
surface** works over TSP with no per-operation work. The older DIDComm
*protocol-message* surface (`key-management/1.0/*`) has no TSP dispatcher behind
it and returns `UnsupportedTransport` naming DIDComm, rather than sending a frame
the VTA cannot dispatch.

**Authentication, stated explicitly** (the issue asked for this in writing):
there is no token dance and no holder proof on the TSP path. TSP `unpack` yields
a cryptographically proven sender VID, which `tsp_inbound::dispatch_one` resolves
straight to its ACL grant before dispatching on the shared spine — the same
intrinsic-sender model as DIDComm authcrypt. The REST bearer-token flow has no
TSP analogue; `set_token` is a no-op on this transport.

New `VtaError::TspTransport`, distinct from `DidcommTransport`: the two fail for
different reasons and have different recovery flags.

**Breaking.** `VtaEndpoint` gains a `Tsp` variant. It was not `#[non_exhaustive]`
(unlike `TransportChoice`), so an exhaustive downstream match no longer compiles;
it is `#[non_exhaustive]` now, so this is the last time. Hence 0.19 → 0.20.
`ResolvedVta` gains two fields. CLIs gain `--transport tsp` and
`--transport didcomm`.

A compile-time pin (`tsp_send_assertions`) asserts every `TspSession` future is
`Send`. One `Box<dyn Error>` held across one `.await` makes the whole chain
`!Send` — including `VtaClient::dispatch_trust_task`, which `vta-mcp` puts behind
`#[tool]`. Because `vta-mcp` doesn't enable the `tsp` feature itself, that break
only surfaces once Cargo's feature unification turns TSP on for a workspace-wide
build, a long way from the edit that caused it. It bit during this change; the
private helpers are now `String`-typed so it cannot recur silently.

Closes #765, #766, #767.

### Dependent crates — `vta-sdk` 0.20 pin bump only

No behavioural change; each of these only re-pins `vta-sdk = "0.19"` → `"0.20"`,
which the version guard counts as a source change. `pnm-cli` 0.11.10 and
`cnm-cli` 0.11.7 additionally expose the new `--transport tsp` /
`--transport didcomm` flags (documented above).

- `vta-audit` 0.1.1
- `vta-backup` 0.1.1
- `vta-cli-common` 0.10.15
- `vta-keys` 0.1.2
- `vta-service` 0.12.39
- `vta-support` 0.1.2
- `vta-vault` 0.1.1
- `vta-webvh` 0.1.1
- `vtc-client` 0.1.5
- `vtc-service` 0.11.26
- `vti-common` 0.11.23
- `vti-secrets` 0.1.8

### vta-service 0.12.38 — make the wizard's scripted prompts feature-proof, and actually run them in CI

The setup wizard's two golden tests (`interactive_matches_equivalent_toml`,
`advanced_existing_keys_mode_maps_through`) failed under `--features config-seed`
and had been failing since that feature landed. CI never noticed because the
`Feature combos` job only runs `cargo check`, so nothing in CI *executed* a
wizard test under any non-default backend set.

**Cause.** `ScriptedPrompter` replayed answers **positionally**, ignoring the
prompt and its option list. The secrets-backend menu is assembled feature by
feature (`aws-secrets`, `config-seed`, `keyring`, …), so `Answer::Index(0)` meant
"OS keyring" by default but "Config file" once `config-seed` was on. That picked
the wrong backend, which meant the wizard never asked for a keyring service name,
which meant the *next* scripted answer was eaten by the wrong prompt — surfacing
as a bogus `expected Index answer for prompt: VTA DID` several prompts downstream.
A positional script cannot survive a menu whose length is a build-time property.

**Fix.** New `Answer::Label(&str)` picks a `select` option by its label, resolved
against the `items` the harness already received and previously discarded. The two
backend answers now say `Answer::Label("OS keyring")`. This is immune to options
being added, removed, or reordered, and when a label genuinely disappears it fails
at the *right* prompt with the available options listed, instead of derailing the
script.

Verified across seven feature sets — default, `config-seed`,
`config-seed,keyring`, `aws-secrets,keyring`, `vault-secrets,keyring`,
`k8s-secrets,keyring`, and `config-seed,vault-secrets,k8s-secrets,keyring` — all
green. Previously only the default set passed.

**This also fixes the two tests #795 added** (`a_pre_created_empty_data_dir_is_
never_asked_about`, `existing_store_offers_reuse_and_delete`), which reached for
the same `Answer::Index(0), // secrets backend = keyring` idiom and so were
broken under `config-seed` the moment they landed. All five wizard tests now use
`Answer::Label` for that select. The new CI step below would have caught them —
it is what flagged them here.

**CI.** `Feature combos` gained a step that *runs* these tests under
`config-seed` and under `config-seed,vault-secrets,k8s-secrets`. Every other step
in that job only compiles; the wizard is the one place a feature flag changes
behaviour rather than just what builds, so compiling it was never going to catch
this.

Pre-existing `Answer::Index` uses for fixed menus (log format, messaging kind,
VTA DID kind, advanced mode) are unchanged — those option lists don't vary by
feature.

### vti-common 0.11.22 / vta-service 0.12.37 — setup no longer treats a pre-created data directory as a conflict

`vta setup` refused to run against any `data_dir` that already existed, offering
only "delete everything" or "cancel". That made containerized first-boot
impossible: Docker volumes, bind mounts, and Kubernetes PVCs all create the
mount path *before* the container starts, so a completely fresh install always
hit the prompt — and answering "yes" then failed too, because
`remove_dir_all` removes the directory itself and `rmdir` on a mount point
returns `EBUSY` however empty it is. Reported against `/app/vta-data`.

* **The gate is store presence, not directory presence.** New
  `vti_common::store::local_store_exists` probes for fjall's own `version`
  marker — the same file `fjall::Database` uses to decide "recover" versus
  "create new", so the two cannot drift. An existing-but-storeless `data_dir`
  is initialized into silently, with no prompt.

* **`data_dir_exists = "delete"` clears the directory's contents, not the
  directory.** Same destruction, but it succeeds on a mount point.

* **New `data_dir_exists = "reuse"`** plus a matching third option in the
  interactive prompt, which is now a three-way choice (cancel / keep contents /
  wipe) instead of a yes-no with no survivable answer.

* **Setup fails closed over an initialized VTA.** Re-running setup mints a
  fresh master seed as generation 0; on top of an existing seed that orphans
  every key derived from the original. All policies — including `reuse` — now
  refuse when generation 0 is already present.

* **The wizard no longer deletes `config.toml` while it is still asking
  questions.** It used to remove the file at the config-path prompt, so an
  operator who backed out at the data-directory question a dozen prompts later
  was left with no config and a VTA that would not start. Intent is now carried
  as `overwrite_config` (new `WizardInputs` field, `--from <toml>`-settable,
  default `false`) and the file is written only once everything else has
  succeeded. `--from` callers that relied on the previous "delete it first"
  behaviour are unaffected; those that want in-place re-runs can set
  `overwrite_config = true` instead of `rm`-ing the file.

* The data-directory and config-path answers are trimmed, so a pasted path with
  stray whitespace no longer becomes a subtly different path.
### vta-cli-common 0.10.14 / pnm-cli 0.11.9 / vta-service 0.12.36 — retire the pre-Banyan CLI shims, and fix the `init` aliases they hid

Sunsets the compatibility shims left over from the `webvh` → `did-mgmt` and
`did-hosting-*` → `did-host-*` renames (both pre-Banyan, May–June 2026), each of
which documented itself as lasting "one release". Clearing them surfaced a real
bug.

* **`pnm did-templates init` was broken for seven of its nine aliases.** The
  `did-hosting-*` → `did-host-*` rename updated `BUILTIN_NAMES` and
  `load_embedded` but not the CLI's alias table, so `init control`, `daemon`,
  `hosting`, `did-hosting`, `server`, `witness`, and `watcher` all resolved to
  template names that no longer existed and failed with `builtin template
  'did-hosting-…' not found`. Only `mediator` and `agent` worked. The role words
  now map onto the canonical shape names — control →
  `did-host-http-didcomm`, daemon/hosting → `did-host-http`,
  witness/watcher/server → `did-host-didcomm`.

  The resolution moved into a testable `resolve_builtin_kind`, with a test that
  asserts **every** alias resolves to something `load_embedded` can actually
  load. That is the check whose absence let the rename half-land; a future
  rename that misses one side now fails in CI.

* **Retired the legacy `webvh-*` template aliases** from `did-templates init`,
  matching the builtin loader, which had already dropped them (its
  `legacy_template_aliases_are_removed` test pins that). A stale name now fails
  loudly instead of silently resolving.

* **Retired `vta`'s hidden `webvh` command alias** and its deprecation warning.
  `pnm`'s equivalent went in an earlier release; this finishes the pair.
  `WebvhCommands` itself stays — it is now purely internal plumbing that
  `did-mgmt` converts into, and renaming it touches every handler.

* **Dropped `pnm`'s `LEGACY_SESSION_KEY`.** Documented as load-bearing for
  operators upgrading from pre-0.4 `pnm`, it was in fact a dead constant behind
  `#[allow(dead_code)]` — the migration that used it was already gone, and the
  `#[allow]` was hiding that.

* **Docs corrected where they described removed behaviour**: `CLAUDE.md` and
  `docs/02-vta/{did-templates,provision-integration}.md` all still told
  operators the legacy aliases resolved, and two of them listed
  `did-hosting-control/daemon/server` as built-in template names. `CLAUDE.md`
  now carries the real `BUILTIN_NAMES` list. (`did-hosting-*` remains valid as
  an integration kind and as a service name — only the template names were
  retired.)

Deliberately **not** removed, since neither is migration code: the
`#[serde(default)]`/`alias` wire fields (peer interop with older VTAs, mediators,
and clients — including `ChallengeRequest`'s `alias = "did"`, which is on the
authentication path), and `vta-keys`' `seed_hex` archive migration, whose read
path is what keeps keys minted under a pre-P0.7b seed generation recoverable.


### vtc-service 0.11.25 / vta-service 0.12.35 — clear the workspace clippy warnings

`cargo clippy --workspace --all-targets` emitted twelve warnings; it is now
silent. No behaviour change.

* Test-module imports in `did_peer.rs` / `did_webvh.rs` now carry the
  `config-seed` gate their only consumer already had, instead of reading as
  unused whenever that feature is off.
* `edit_did_document` and `vtc-service`'s `as_vti_role` moved above their file's
  `mod tests` ("items after a test module"), so tests stay last.
* Two `.err().expect(..)` calls in `provision_integration/preconditions.rs`
  became `.expect_err(..)`.
* Dropped two unused `SHOW_TASK` constants from the `vtc-service` endorsement and
  removal tests, left behind by the spec/vtc Trust Task migration.

Known unrelated gap, not fixed here: `setup::interactive`'s two scripted-wizard
tests fail under `--features config-seed`, because the wizard skips its "Seed
storage backend" select when only one backend is compiled and a second one shifts
every scripted answer. CI never builds that combo.

### vta-mobile-core 0.6.15 / vta-sdk 0.19.28 / vta-service 0.12.35 — a device can submit Trust Tasks with no REST API

Completes the mobile no-REST loop: a device could already *receive* over both
DIDComm and TSP, but had no way to submit a signed document back, so every reply
path still needed the VTA's REST surface.

* **`vta-mobile-core`: `MediatorSession::send_trust_task`** (+ a
  `send_trust_task_one_way` counterpart) — submits an already-signed Trust Task
  document as the body of a `binding/didcomm/0.1/envelope` message and awaits its
  `#response`, demuxed by `thid`. No bearer token: the message is
  authcrypt-packed, so the VTA proves the sender DID and derives authorization
  from it (intrinsic-sender auth). Safe to call while a `receive_next` loop runs.

* **`vta-mobile-core`: `TspMediatorSession::send_trust_task`** — the TSP
  counterpart, making the TSP session bidirectional. Deliberately
  fire-and-forget: TSP has no `thid` demux, so the VTA's reply arrives as an
  ordinary inbound frame and the caller correlates it off the inbox on
  `threadId`. Sending takes no socket lock, so it is safe to call while
  `receive_next` holds one; an in-place wait would deadlock.

* **`vta-sdk`: a dead DIDComm session no longer looks like an idle one.**
  `DIDCommSession::receive_next` returned `Ok(None)` both when the poll window
  elapsed *and* when the inbound stream ended. A supervisor polling for work
  therefore treated "stream ended" as "nothing yet", called again, got the same
  answer instantly, and spun at full tilt forever without reconnecting. Now
  reports `Ok(None)` only for an expected teardown (`shutdown()` was called) and
  `Err(DidcommTransport)` otherwise, which is what makes a supervisor reconnect.

* **`vta-service`: inbound messaging is concurrent, bounded at 32 in flight.**
  `run_inbound_loop` awaited each `handle_inbound` inline, so the VTA processed
  exactly one inbound frame at a time — across *both* protocols, since one
  mediator websocket carries DIDComm and TSP together. A single slow handler
  stalled every other caller's traffic and a hanging one wedged inbound messaging
  entirely. Handlers now spawn under a semaphore; at the cap the loop waits for a
  permit, degrading to the old serialised behaviour under extreme load rather
  than growing tasks unboundedly. Safe because the dispatch spine was already
  concurrent — the REST route runs `dispatch_trust_task_core` under axum with no
  such serialisation.

* **Regression test: hermetic TSP routing** (`tests/e2e/tests/tsp_round_trip.rs`).
  Pins that a TSP frame routes between two local mediator accounts and is
  readable on **both** socket modes — the raw-TSP socket the device reads and the
  store-and-pickup socket the VTA's inbound loop reads — each paired with a
  DIDComm control over the same fixture, plus a 10-round burst case because the
  original failure was intermittent. Guards the silent-drop bug fixed upstream in
  `affinidi-messaging-mediator` 0.17.7 (tdk #646); the VTA drives a different
  crate (`affinidi-messaging-delivery`), so a recurrence would not be caught by
  the upstream test. No network, no deployed VTA — runs unignored in CI.

### vti-secrets 0.1.7 / vta-config 0.1.1 — `[secrets] backend` selects the seed store explicitly

Choosing "Plaintext file" in the setup wizard silently produced a
**keyring-backed** VTA. `create_seed_store` inferred the backend from whichever
selector field was populated, and plaintext has no field of its own —
`allow_plaintext` is a *permission* to fall back, not a request. With `keyring`
compiled in (the default) the keyring arm matched unconditionally, so the
plaintext arm below it was unreachable. The same shadowing hid any backend
sitting under a configured one.

* **New `secrets.backend`** (`keyring` | `config_seed` | `aws` | `gcp` |
  `azure` | `vault` | `kubernetes` | `plaintext`). When set it wins outright:
  that backend is built and its required fields are validated. Mirrors
  `vtc_service::config::SecretBackend`, so the VTA and VTC now share one
  vocabulary.

* **Fail closed.** A backend named on a binary built without its Cargo feature
  is a hard config error rather than a silent fall-through to keyring or
  plaintext — the same P0.8 stance the VTC already took.

* **The setup wizard always writes it**, so every generated `config.toml`
  states its backend instead of leaving it to inference. Plaintext now needs
  both keys: `backend = "plaintext"` (which backend) and
  `allow_plaintext = true` (accepting a cleartext master seed).

* **Backward compatible.** Omitting `secrets.backend` keeps the legacy implicit
  priority chain exactly as it was, and the field is skipped on serialize when
  unset, so existing configs neither change behaviour nor grow a key.

### vta-tee 0.1.0 / vta-policy 0.1.0 / vta-keys 0.1.1 / vti-common 0.11.21 / vta-service 0.12.34 — extract the TEE and policy subsystems

Ninth decomposition step — two subsystem extractions in one PR, each unblocked
by a small enabling move.

* **New `vta-tee`** — the TEE bootstrap subsystem (~4k lines): attestation
  providers (Nitro / SEV-SNP / simulated), KMS attest/decrypt + storage-key
  derivation + CMS unwrap, the DynamoDB anti-rollback anchor MAC, Mode-B admin
  bootstrap + carve-out, first-boot DID autogen, and the mnemonic-export guard.
  Re-exported (behind the `tee` feature) as `crate::tee`, so `vta_service::tee::…`
  keeps resolving for `vta-enclave` and every call site. Its 32 tests run in the
  new crate. The KMS/AWS dep stack (`aws-sdk-kms`, `aws-sdk-dynamodb`,
  `aws-config`, `aes`, `cbc`) moved out of `vta-service` with it.

  *Enabling move:* `derive_pre_rotation_keys` (a pure BIP-32 key operation) moved
  from `operations::did_webvh` to **`vta-keys` 0.1.1** — it was `tee`'s only
  coupling into `vta-service`, and it removed a `did_webvh` coupling too.

* **New `vta-policy`** — the policy subsystem (~2.3k lines): the regorus (Rego)
  engine, the default policy bundle, the DTTE consent model, decision
  evaluators, and policy storage. Re-exported as `crate::policy`. Its 37 tests
  run in the new crate; the `policies/default.rego` bundle moved with it.

  *Enabling move:* the `Guards` / `WebvhPathCounter` executor-precondition types
  moved from `vta-service`'s trust-task planner to **`vti-common` 0.11.21**
  (`vti_common::guards`) — the planner's only shared type with the consent model,
  re-exported from `planner` so its own references are unchanged.

* No behaviour change: 687 `vta-service` lib tests + 32 `vta-tee` + 37
  `vta-policy` tests pass; all feature combos, the enclave build, and the
  workspace build are green. `vta-service` drops ~6.3k lines (→ ~87k).

### vta-backup 0.1.0 / vta-keyspaces 0.1.1 / vta-support 0.1.1 / vta-service 0.12.33 — extract the backup subsystem (with dependency inversion) + did-template storage

Eighth decomposition step, and the first to use **dependency inversion** rather
than a pure move — bundled with two clean pure-moves to land several
extractions in a single review/release cycle.

* **New `vta-backup`** — the encrypted full-state export/import operations
  (Argon2id + AES-256-GCM), the compatibility check, the two-phase descriptor
  flow, the sealed backup-bundle store, and its TTL sweeper (~3.7k lines from
  `vta-service`). Re-exported so `crate::operations::backup::…` and
  `crate::{backup_bundle_store,backup_bundle_sweeper}::…` are unchanged. Its 59
  tests run in the new crate (with slim local test fixtures so it needs no
  dependency on `vta-service`).

  Two `vta-service`-specific glue points were **inverted** rather than moved:
  - The `AppState`-borrowing constructors (`DescriptorDeps::from_app_state`)
    became free functions in `vta-service`
    (`operations::descriptor_deps_from_app_state`); the `DescriptorDeps` struct
    itself moved to `vta-backup`.
  - The TEE KMS re-encryption step of an import is now injected through a
    `vta_backup::BootstrapReEncryptor` trait whose sole implementation
    (`vta-service`) wraps `tee::kms_bootstrap::re_encrypt_bootstrap_secrets`.

* **`vta-keyspaces` 0.1.1** — the shared `Keyspaces<'a>` handle bundle (used by
  backup + contexts + messaging) moved here from `vta-service::operations`, so a
  subsystem crate can take it without depending on `vta-service`. Its
  `AppState` / `VtaState` constructors became free functions
  (`operations::keyspaces_from_app_state` / `_from_vta_state`). Additive — every
  existing `"0.1"` pin still resolves.

* **`vta-support` 0.1.1** — the DID-template storage module (`tpl:` keyspace,
  ~0.1k lines) moved from `vta-service`, re-exported as `crate::did_templates`.
  A clean pure-move (only `crate::error` / `crate::store` → `vti_common::…`).

* **`backup_bundle_sweeper` note:** unlike the three generic sweepers extracted
  in the previous step, the backup-bundle sweeper is coupled to
  `backup_bundle_store` and moved *with* it into `vta-backup`.

* No behaviour change: 720 `vta-service` lib tests + 59 `vta-backup` tests pass;
  all feature combos, the enclave build, and the workspace build are green.
  `vta-service` drops ~3.9k lines (→ ~93k).

### vta-sweepers 0.1.0 / vta-service 0.12.32 — extract the background TTL sweepers

Seventh decomposition step, enabled by the `vta-audit` extraction (#788): with
`audit` now a foundation crate, the periodic-maintenance sweepers no longer
reach into `vta-service` at all.

* **New `vta-sweepers`** — `acl_sweeper` (expires time-limited ACL grants),
  `consent_sweeper` (expires stale pending-consent + consumed grants), and
  `vault_sweeper` (hard-purges grace-expired soft-deleted vault entries),
  ~0.4k lines. Each depends only on the foundation/leaf crates (`vti-common`,
  `vta-audit`, `vta-keyspaces`, and — for the vault sweeper — `vta-vault`).
  `vta-service` re-exports each as `crate::{acl_sweeper,consent_sweeper,
  vault_sweeper}`, so the storage-thread sweep loop in `server.rs` and the
  other call sites are unchanged.

* **Pure move, no behaviour change.** Files moved as git renames (history
  preserved); the modules' 3 tests run in the new crate. The only edits were
  repointing the back-references now that their targets are extracted crates
  (`crate::audit` → `vta_audit`, `crate::vault` → `vta_vault`, `crate::acl` /
  `crate::store` / `crate::error` → `vti_common::…`,
  `crate::keyspaces` → `vta_keyspaces`).

* `backup_bundle_sweeper` stays in `vta-service`: unlike the three above it is
  coupled to `backup_bundle_store` (the backup subsystem's sealed-bundle
  store), so the two move together with a future `vta-backup` extraction.

### vta-audit 0.1.0 / vta-service 0.12.31 — extract structured audit logging into a foundation crate

Sixth decomposition step. `audit` is the single most-depended-on leaf — every
subsystem emits `audit!(…)` events — so it belongs *below* the subsystems as a
shared foundation crate, not inside `vta-service`.

* **New `vta-audit`** — the `audit!` tracing macro plus the audit-keyspace
  persistence helpers (`record`, `record_with_detail`, `record_consent`,
  `cleanup_expired_logs`), ~0.2k lines. Depends only on `vti-common` and
  `vta-sdk`. The macro is now `#[macro_export]`ed (its body was already
  fully-qualified `::tracing::…`, so no path rewriting was needed).
  `vta-service` re-exports the crate as `crate::audit`, so all consumers —
  `crate::audit::record*` calls and `use crate::audit::{self, audit}` macro
  imports alike — are unchanged.

* **Pure move, no behaviour change.** The file moved as a git rename (history
  preserved); the only edits were repointing the two thin re-export
  back-references (`crate::error`, `crate::store` → `vti_common::…`) and the
  macro export.

* Unblocks the sweeper cluster (`acl_sweeper`, `consent_sweeper`,
  `vault_sweeper`), whose only remaining back-reference is now into this
  foundation crate rather than into `vta-service` proper.

### vta-webvh 0.1.0 / vta-service 0.12.30 — extract the WebVH hosting infrastructure

Fifth decomposition step. With the clean-leaf and mid-layer services out, the
next coherent seam is the WebVH hosting infrastructure — a self-contained
cluster that the big `operations/did_webvh` DID-lifecycle subsystem sits on top
of.

* **New `vta-webvh`** — `webvh_store` (the local `did:webvh` DID-record +
  server-record store), `webvh_client` (the HTTP client to a remote `did:webvh`
  hosting server), and `webvh_auth` (the DID-auth handshake the client uses),
  ~2.4k lines from `vta-service`. `webvh_client` and `webvh_auth` are a
  mutually-coupled pair; together with the store they depend only on
  `vti-common`, `vta-keyspaces`, `vta-sdk`, and `affinidi-tdk` — never on
  `vta-service`. Re-exported (behind the `webvh` feature) as
  `crate::{webvh_store,webvh_client,webvh_auth}`, so all 37 consumer files are
  unchanged and `vta-enclave` is unaffected.

* **Pure move, no behaviour change.** Files moved as git renames (history
  preserved); the modules' 48 tests run in the new crate. The only edits were
  repointing three thin re-export back-references (`crate::error`,
  `crate::store` → `vti_common::…`; `crate::keyspaces::WEBVH` →
  `vta_keyspaces::WEBVH`). `vta-service` drops ~2.4k lines (→ ~98k).

* `webvh_didcomm` stays in `vta-service` for now — it depends on
  `didcomm_bridge`, which is part of the messaging subsystem still to be
  untangled. Extracting it (with `operations/did_webvh`) into `vta-webvh` is a
  later step once that coupling clears.

### vta-support 0.1.0 / vta-service 0.12.29 — group the clean mid-layer services into one crate

Fourth decomposition step. The clean-leaf extractions (keyspaces, vault,
config, keys) are done; the remaining big subsystems are tightly coupled to
`AppState` and each other. Between them sit a few small, clean shared services,
grouped here into one crate rather than proliferating tiny crates.

* **New `vta-support`** — `contexts` (trust-context storage), `seal` (the
  sealed-transfer producer-side seal helper), and `sealed_nonce_store` (the
  sealed-bootstrap anti-replay nonce store), ~0.9k lines from `vta-service`.
  Each is a self-contained near-leaf depending only on `vti-common`,
  `vta-config`, `vta-keyspaces`, `vta-sdk`. `vta-service` re-exports each as
  `crate::{contexts,seal,sealed_nonce_store}`, so all call sites (25 files) are
  unchanged and `vta-enclave` is unaffected.

* **Pure move, no behaviour change.** Files moved as git renames (history
  preserved); the modules' 10 tests run in the new crate; no visibility change
  was needed. `vta-service` drops ~0.75k lines (→ ~100.5k). `audit` was left in
  `vta-service` deliberately: its `audit!` macro (not `#[macro_export]`) makes a
  cross-crate move fiddly and isn't worth it for a 218-line module.

* Removes these back-references from the coupled subsystems (`did_webvh`,
  `provision_integration`, `backup`, `tee`), an incremental step toward
  extracting them.

### vtc-service 0.11.24 — fix a broken test from #771 and republish

* **Fixes the red `Test` job on main.** #771 ("fix: auth check") added
  `tests/auth_forged_plaintext.rs`, whose `VtcAclEntry { … }` construction omits
  the `updated_at` / `updated_by` fields the struct carries — so
  `cargo test --workspace` fails to compile it
  (`E0063: missing fields updated_at and updated_by`). CI Test has been red on
  main since #771 merged; a genuine merge-integration miss, not a registry
  staleness. The two `None` fields are now set, matching every other
  `VtcAclEntry` test construction.

* Bumps the crate so the fix — and #771's earlier `routes/auth.rs` security fix,
  which #771 never bumped for — reaches crates.io. The published `0.11.23` still
  holds pre-#771 source; `0.11.24` republishes the current source.

### vti-common 0.11.20 — publish the auth-check fix that #771 left unreleased

* #771 ("fix: auth check") added `vti_common::auth::AuthcryptError` (and the
  `bind_authcrypt_sender` binding in `auth/didcomm.rs`) and used it from
  `vta-service`, but did **not** bump `vti-common`. crates.io therefore still
  held the pre-#771 `0.11.19` source, so publishing `vta-service 0.12.28`
  failed its verify build — `cannot find AuthcryptError in vti_common::auth` —
  because it resolved the stale registry copy. This bump republishes the
  crate with the symbol, unblocking the `vta-service` release. No source change
  here beyond the version.

  (The version-bump guard is meant to catch a source change with no bump; #771
  slipped through it — a guard gap worth a separate look. `vtc-service` was
  also touched by #771 without a bump; its published copy is likewise missing
  the fix, tracked separately.)

### vta-keys 0.1.0 / vta-service 0.12.28 — extract key management into its own crate

Third decomposition step (after `vta-keyspaces`+`vta-vault` in #780 and
`vta-config` in #781). With config a crate, `keys` became a clean leaf — it
reaches only into `vta-keyspaces`, `vta-config`, `vti-common`, `vti-secrets`,
`vta-sdk`, never into any `vta-service` internal.

* **New `vta-keys`** — master-seed storage, BIP-32 hierarchical key derivation,
  AES-GCM key wrapping, imported-key handling, and the seed-store backend
  selection (`create_seed_store`), ~2.8k lines extracted from
  `vta-service/src/keys/`. Security-sensitive: seed material stays in
  `zeroize`-guarded buffers. `vta-service` re-exports it as `crate::keys`, so
  every `crate::keys::…` reference (36 files) is unchanged and
  `vta_service::keys` keeps resolving for `vta-enclave`. The eight seed-store
  backend features (`aws-secrets` … `keyring`, `tee`) each chain to the
  matching `vta-keys/*` feature.

* **Pure move, verified hard.** Files moved as git renames (history preserved).
  Only two `pub(crate)` encoders (`encode_private_multibase` /
  `encode_public_multibase`, used by `operations::keys`, `provision_integration`,
  and `did_webvh`) become `pub` at the crate boundary — no other visibility or
  logic change. 36 key tests run in the new crate; `operations::keys` (12) and
  the `operations::backup` seed→derive→store→export→import→re-derive round-trip
  (39) pass unchanged in `vta-service`; `vta-enclave` builds with `tee`, which
  compiles the KMS seed-store path. `vta-service` drops ~2.8k source lines
  (→ ~101.3k).

* Unblocks the subsystem crates that need keys — `tee`, `backup`, `webvh` — for
  subsequent phases.

### vta-config 0.1.0 / vta-service 0.12.27 — extract the VTA config types into their own crate

Second step of decomposing `vta-service` into subsystem crates (after
`vta-keyspaces` + `vta-vault` in #780). Analysis of the next candidates
(`tee`, `backup`) showed they are **not** clean leaves — both reach into
`crate::config` (`AppConfig`) and `crate::keys`, which live in `vta-service`.
So does every other remaining subsystem. The genuine next step is therefore to
extract the shared core they depend on, beginning with config.

* **New `vta-config`** — the `AppConfig` TOML shape and its sub-configs
  (`PolicyConfig`; under the `tee` feature `TeeConfig` / `TeeKmsConfig` /
  `TeeMode`), composing the shared config types from `vti-common` and
  `vti-secrets`. A near-leaf: it depends only on `vti-common`, `vti-secrets`,
  `serde`/`toml`/`tracing`. `vta-service` re-exports it as `crate::config`, so
  every `crate::config::…` reference — 64 files — is unchanged, and
  `vta_service::config` keeps resolving for `vta-enclave`. The `tee` feature
  gates the same items it did before, wired to `vta-config/tee`.

* **Pure move, no behaviour change.** `config.rs` moved as a git rename
  (history preserved); its 7 tests run in the new crate. `vta-service` and
  `vta-enclave` (which consumes `vta_service::config` and the `tee` feature)
  build unchanged. `vta-service` drops by ~1k source lines.

* This unblocks the rest of the decomposition: with config a crate, `vta-keys`
  becomes extractable next (it needs only `AppConfig` from the core), and after
  that `tee` / `backup` / `webvh`.

### vta-keyspaces 0.1.0 / vta-vault 0.1.0 / vta-service 0.12.26 — begin decomposing `vta-service` into subsystem crates

`vta-service` is a 114k-line crate — 44% of the workspace and one compile unit,
so any library change recompiles all of it, with no enforced boundary between
conceptually independent subsystems. This is the first step of decomposing it
**within the workspace** into subsystem crates (we evaluated and rejected
splitting VTA from VTC into separate *repos*: the two already have zero
cross-dependency, and a repo split would tax the routinely-atomic
shared-foundation changes). Pilot-first: prove the crate mechanics and the
narrow-dependency seam on the cleanest leaf, then repeat per subsystem.

* **New `vta-keyspaces`** — the 29 keyspace-name constants + the backup
  partition (`ALL` / `BACKED_UP` / `EXCLUDED_FROM_BACKUP`), a dependency-free
  leaf so subsystem crates can name keyspaces without depending on
  `vta-service`. `vta-service::keyspaces` re-exports it, so every existing
  `crate::keyspaces::*` reference is unchanged; the `no_bare_keyspace_literals`
  guard stays in `vta-service` (it must scan that crate's source).

* **New `vta-vault`** — the holder credential vault (storage, model, query,
  receive/verify, present, status refresh, BBS, DI verify, consent), ~8.7k
  lines, extracted from `vta-service/src/vault/`. It takes narrow dependencies
  (`KeyspaceHandle`, `ActScope`, resolver args) and never `AppState`, which is
  why it was the clean pilot. Re-exported as `vta-service::vault`, so the
  dispatch handlers (`trust_tasks/vault`, `cred_vault`), the sweeper, and
  `credential_exchange` keep their `crate::vault::…` paths unchanged. `bbs` and
  `webvh` cargo features gate the same code they did before, wired through to
  `vta-vault/bbs` and `vta-vault/webvh`.

* **No behaviour change.** Pure extraction — 103 vault tests run in the new
  crate; the dispatch and credential-custody (#776) tests still run in
  `vta-service` and exercise the crate seam unchanged. `vta-enclave` (the one
  external consumer of `vta-service` internals) is unaffected. `vta-service`
  drops from ~113.9k to ~104.9k source lines.
### vta-sdk 0.19.27 / vta-cli-common 0.10.13 / pnm-cli 0.11.8 / cnm-cli 0.11.6 / vta-service 0.12.25 / vtc-service 0.11.23 — give agent names a caller

* The producer machinery for agent names was already complete — inbound
  Trust-Task handlers for all six verbs, an operations layer that edits the DID
  document's `alsoKnownAs` and republishes the signed log, and outbound calls to
  the DID-hosting control plane over both REST and DIDComm. What it had was no
  caller: no `VtaClient` methods, no CLI, so the only way to reach any of it was
  a hand-rolled Trust Task.

* **`pnm did-mgmt agent-names {set,check,list,remove,enable,disable}`**, on six
  new `VtaClient` methods. Trust-task-only, and no new REST route was needed:
  `dispatch_trust_task` posts to `/api/trust-tasks` on a REST transport and
  rides the DIDComm envelope otherwise, so both reach the same handler.

* `remove` and `disable` are deliberately distinct and the CLI says so at the
  point of use — remove frees the name for anyone to claim, disable parks it so
  it stops resolving while staying reserved to this DID. `list` reads the
  hosting registry rather than the DID document, because a parked name is
  absent from the document by design and would otherwise be invisible.

* **`--resolve-agent-names`** turns on verified name resolution in display
  output, and `pnm-cli` now enables the `agent-names` feature that backs it —
  without which the flag would have parsed and done nothing. Off by default: a
  lookup is a DID resolution plus an outbound fetch per claimed name, per DID
  on screen. Wired into `acl list` / `acl get` (including the `created_by`
  column, where an unfamiliar DID most often appears) and the hosted-DID list,
  which is where names can actually exist.

* **Fixed a real divergence**: reading a DID's names over DIDComm treated a
  missing `agentNames` field as an internal error while the REST path treated
  it as an empty list. A host predating the registry omits the field entirely,
  so the same DID appeared to have names or not depending on how the VTA
  happened to reach its host. Both are tolerant now.

* Named DIDs also reach the remaining surfaces skipped last time: the hosted
  `did:webvh` list, the DID-hosting server list, and `vtc create-did-key`,
  which was storing an operator-supplied label and never showing it. `vtc
  status`, `pnm doctor` and `cnm` report the names a resolved document claims,
  marked unverified — free, since the document is already in hand.

* **Correction.** The previous entry claimed "nothing in this workspace
  publishes `alsoKnownAs` yet". That was false: `operations::did_webvh`'s
  `edit_agent_name` has been writing the claim and republishing all along. The
  claim was true of DID *templates*, which is where it was checked, and wrongly
  generalised to the workspace. The same error was repeated in the
  `display_name` module docs; both are corrected.

* **A cross-repo contract test.** What the VTA writes into `alsoKnownAs` is
  read back by the hosting server with `agent_names::AgentName::parse`, keeping
  only entries whose authority matches the domain it serves. If our emitted
  form ever stops satisfying that parser nothing errors — the claim is simply
  never indexed and the name silently 404s. The test now uses the host's own
  parser rather than asserting our format against itself.

* `cnm` gains `--resolve-agent-names` for display parity. It has no
  `did-mgmt` surface, so it gets the flag but not the binding commands.

* CI: the Test job reclaims the runner's preinstalled Android/.NET/GHC
  toolchains before building. `cargo test --workspace` links a test binary
  per crate with full debuginfo and had begun exhausting the runner's root
  disk while linking the largest one; this is the standard headroom fix and
  helps every future PR, not just this one.

* `sealed_producer` banners are deliberately left showing bare, full DIDs —
  those DIDs are minted seconds before they are printed, so there is no name to
  show, and the operator is copying an exact identifier for handoff.


### vti-common 0.11.19 / vta-service 0.12.24 / vtc-service 0.11.22 — let a context admin create a least-privilege approver

* `validate_acl_modification` saw only the target's context list, never its
  role, so it could not tell an *acts-nowhere* entry (any non-admin role, no
  contexts) from an *unrestricted* one (admin, no contexts) — and refused both
  to a non-super-admin. That barred a context admin from creating the very
  shape the CLI recommends: a reader that acts nowhere and confers a context it
  administers via `approve_scope` (a least-privilege approver).

* The function now takes the target role and decodes it into an `ActScope`.
  `All` (unrestricted) stays super-admin-only; `None` (acts nowhere) grants no
  authority to act, so any caller who may manage the ACL may create it. The
  *conferral* half is unchanged — `validate_approve_scope_grant` still requires
  the caller to administer every context an approver confers — so a context
  admin can mint an approver for its own contexts and no others, and still
  cannot mint a super-admin.

* This is the last of the two conflations `ActScope` (#772) was introduced to
  make resolvable. It is safe now, and was not before, because the "an
  acts-nowhere entry grants nothing" premise it rests on is finally true on
  every read path — the credential-vault custody gaps that violated it silently
  were closed in #776. The two changes are related: this one should not have
  landed ahead of that one.

* Callers updated in all three services; behaviour is otherwise unchanged (the
  scoped and unrestricted cases decide exactly as before). Verified
  load-bearing: reverting the `None` arm to refuse fails both the unit test and
  the end-to-end `create_acl` test.

### vti-common 0.11.18 — make delegated-any step-up ratification ancestry-aware

* The admin path of `delegated_any_approver_covers` matched a subject's
  contexts against the approver's with exact `contains`, while the
  approve-scope path in the same function used ancestry-aware `covers`. So a
  context admin of `acme` could **not** ratify a delegated AAL2 step-up for a
  subject scoped to `acme/eng`, even though it administers that subtree — and
  an equivalent explicit `ApproveScope` grant *could*.

* That contradicted the stated ACL-gate rule — "any `allowed_contexts` entry
  `is_ancestor_or_self` of the target" (`hierarchical-contexts.md`). The helper
  landed (#257) five days before this function was written (#329) and was
  simply not reached for. The admin path now uses the same `covers`, so admin
  standing and explicit conferral agree.

* Behaviour is identical while contexts are flat — the two readings diverge
  only once sub-contexts exist, which is the case the hierarchy feature was
  built for. Resolves one of the two conflations #772 left flagged.

### vta-service 0.12.23 — enforce credential custody on the credential-vault surface

* **Security.** `StoredCredential.context_id` is documented as the **custody**
  axis — "which context in *this* VTA owns the credential" — and no path
  enforced it. Every credential-vault trust task gated on the caller's
  *capability* and then read or mutated by id, so a caller scoped to one
  context reached another's credentials. Verified with a repro before fixing:
  a `ctx-a` caller received `{"credential":{"id":"cred-in-ctx-b"}}` from
  `get`, and both contexts' rows from `query`.

* Affected: `query` and `get` (read), `archive` / `unarchive` / `restore`
  (mutate), and `delete` / `purge` (destroy). **`delete --force` was the
  worst** — it hard-deleted by id without loading the record at all, so custody
  could not be checked even in principle and a scoped caller could destroy
  another context's credential outright.

* One `caller_may_access_custody(&ActScope, Option<&str>)` predicate now backs
  every path. In `search` it sits with the existing lifecycle and status
  post-filters, where the full record is already loaded, so it costs nothing —
  the descriptor returned to callers carries no `context_id`, making a
  downstream filter impossible without re-reading every hit.

* Inaccessible credentials conflate to **not-found**, matching how archived and
  absent ones are already reported, so the gate is not an enumeration oracle.
  An absent id stays idempotent-success on `delete --force`.

* **Unscoped (`context_id: None`) credentials remain readable by any caller.**
  That is how rows written before the field existed deserialize, and how a
  multi-context or super-admin `receive` still stores today. Denying it would
  retroactively hide legacy credentials from the scoped callers using them, so
  it is a deliberate compatibility carve-out — tightening it needs a backfill
  of `context_id` first.

* The credential-**exchange** presentation path (`match_vault`) is deliberately
  unchanged and passes `ActScope::All`: that is the holder presenting its own
  store to a verifier, governed by the context-policy guardrail and consent, a
  different question from "may this caller read this context's credentials".

* Same defect class as #769, in the sibling file that fix did not cover.

### vtc-service 0.11.21 — decode ACL scope the same way the VTA does

* The VTC's ACL surface read `allowed_contexts.is_empty()` by hand in three
  places, the same idiom that produced three separate bugs on the VTA side
  (#746, #769, #770). `VtcAclEntry::act_scope()` now maps the community role
  through `as_vti_role` and calls the shared `act_scope_for`, so the two
  services cannot disagree about what an empty scope set means.

* **Revoking every scope** now says which case it refused. Emptying an *admin*
  entry's scopes silently promotes it to community-wide authority; emptying any
  other role's leaves it inert. Both are refused, as before, but the message no
  longer describes every entry as community-wide.

* **`caller_covers_admin_target`** distinguishes an unrestricted target from an
  acts-nowhere one rather than having both fall out of a single `is_empty()`.

* **The offline `vtc acl` listing** always renders the scope. Printing nothing
  for an empty list left "community-wide" and "acts nowhere" looking identical
  on an operator display.

* No behaviour change beyond the two clarified messages; `as_vti_role` moves
  from the route layer to `acl::role` so the offline CLI can reach it.

### vti-common 0.11.17 / vta-service 0.12.21 — let a context admin audit who may confer in their context
### vti-common 0.11.17 / vta-service 0.12.22 — let a context admin audit who may confer in their context

* **A least-privilege approver was invisible to the admins whose contexts it
  could confer.** It acts nowhere by design, so it names no context on the act
  axis, so it never overlapped a context admin's scope in
  `is_acl_entry_visible` — and an operator asking "who can authorize a change
  in my context?" could not see the answer. Conferral is authority, and
  authority in your context should be auditable by its admin.

* The fix is a **second predicate, not a wider first one**:

  | predicate | includes | gates |
  |---|---|---|
  | `is_acl_entry_visible` | act-scope overlap | update, delete |
  | `is_acl_entry_auditable` | that, plus approve-scope reaching the caller | list, get |

  Separate because `is_acl_entry_visible` gates *mutations* too. An entry can
  administer someone else's context while conferring into yours; folding
  conferral into one predicate would have made that entry deletable by you —
  `delete_acl`'s only other guard is `validate_role_assignment`, which a
  context admin passes — turning a read widening into privilege escalation.
  Pinned at both the predicate and operation layers, and verified by merging
  the two and watching those tests fail.

* A mutation refused on an entry the caller can nonetheless read now returns
  `Forbidden` explaining the split rather than `NotFound`: there is nothing
  left to conceal about a row they can already list. Entries the caller cannot
  read at all still conflate to `NotFound`, so the enumeration guard is intact.

* The act axis is unchanged — an unrestricted (super-admin) entry still does
  not surface to a context admin merely by being unrestricted.
### vta-sdk 0.19.26 / vta-cli-common 0.10.12 / pnm-cli 0.11.7 / cnm-cli 0.11.5 / vta-service 0.12.21 / vtc-service 0.11.20 — show names where we used to show DIDs

* Operators read DIDs constantly and cannot. Roughly ninety sites across the
  three CLIs printed raw DIDs, and each abbreviated them its own way: a
  29-*byte* slice in `audit` (which would panic on a multi-byte character),
  50- and 60-char truncations in `services`, and a fourth strategy again in the
  VTC admin console. Nothing anywhere mapped a DID to a human name at render
  time.

* New `vta_sdk::display_name`. A `NameBook` is a `DID → name` map a command
  fills from a response it has *already fetched*, then queries while
  rendering — not a resolver, and it performs no lookups of its own. That
  shape is what makes naming free: an ACL listing names every subject from its
  label and, with no extra request, the `Created By` column too, since a
  granting admin is nearly always another entry's subject.

* `shorten_did` replaces all four truncators. It abbreviates the opaque
  `did:webvh` SCID and keeps the domain/path tail — the half that actually
  identifies the agent — instead of clipping the end. Ported from the admin
  console's `shortenDid`, with a vector table pinning the two to identical
  output; an operator moving between a terminal and the console should not
  have to re-identify the same DID.

* Tables gain a `Name` column only when at least one row has a name. On a VTA
  where nothing has been labelled, a column of dashes is worse than no column.
  DIDs are never *replaced* by names — the name leads, the identifier follows,
  and `--full-display` and `--json` still carry every DID in full. A name the
  operator cannot cross-check against an identifier is a name they cannot
  audit, and these are the screens where ACL grants get approved.

* `--json` output is unchanged. No field was renamed, removed, or reshaped, so
  scripts piping `pnm acl list --json` through `jq` are unaffected.

* Named DIDs now appear in: `pnm/cnm acl list|get`, `audit` (actor), `services
  didcomm drain list`, `services report` (mediators + senders), the
  context-delete confirmation — where an operator is deciding which principals
  lose access — `vtc acl list`, and the VTC console's members, ACL, sessions,
  join-requests, invitations, audit and relationship-graph views.

* **Agent names are wired but inert.** New optional `agent-names` feature on
  `vta-sdk` reads the names a DID's document claims via `alsoKnownAs`. Those
  claims are *self-asserted* — the agent-name specification's two-sided binding
  protects the name→DID direction, not the reverse — so a hostile DID can
  claim `mybank.com/@treasury`. Every claim is round-tripped (resolve the name
  forward, require it to lead back to the same DID) before being shown
  unqualified; one that fails surfaces as unverified, ranks below every local
  source, and never renders bare. See the agent-name entry below for the
  producer side.

* `PATCH /v1/members/{did}` accepts `label`. The VTC's only human name for a
  member lives on the ACL row, which meant correcting a typo in a display name
  took a full `acl/grant` re-grant.

* Breaking, internal: `vta_cli_common::commands::contexts::render_delete_context_preview`
  takes a `&NameBook`. Both call sites (the online `pnm contexts delete` and
  the offline `vta contexts delete`) are updated.

### vta-sdk 0.19.25 / vti-common 0.11.16 / vta-cli-common 0.10.11 / vta-service 0.12.20 — decode an ACL entry's authority to act in one place

* **`allowed_contexts` means opposite things depending on the role** —
  unrestricted for `Role::Admin`, *nothing at all* for every other role — and
  call sites kept reading it without the role. That produced a display calling
  a least-privilege approver "unrestricted" (#746), two `acl list --context`
  filters that disagreed with each other and with the truth (#770), and a vault
  scope gate that handed an authorized-nowhere entry credential-vault reads in
  every context (#769). Three bugs, one cause: the decode was open-coded at
  every call site.

* **`ActScope`** (`None` / `All` / `Contexts`) is now that decode, done once.
  It sits in `vta-sdk/src/acl.rs` beside `ApproveScope`, with deliberately
  identical variants, an identical `covers()`, and the same fail-closed
  default — so "what may this DID do" and "what may it confer" read as one
  model rather than an enum and a convention.

* **Nothing is stored or sent in the new shape.** Unlike `ApproveScope`, the
  act axis stays `(role, allowed_contexts)` on disk and on the wire;
  `ActScope` is computed on read via `vti_common::acl::act_scope_for`, reached
  through `AclEntry::act_scope()` / `AuthClaims::act_scope()`. No migration, no
  wire change, existing rows untouched. The decode lives server-side because it
  needs `Role`, which `vta-sdk` cannot see — the same shape/policy split #768
  used for `ApproveScope`.

* `is_super_admin`, `has_context_access`, `can_act_in`, `is_acl_entry_visible`,
  `acl_entry_can_act_in`, `delegated_any_approver_covers` and both ACL displays
  now route through it. Behaviour is unchanged throughout — including two
  conflations preserved deliberately and flagged in place, since removing
  either is an authorization change rather than a structural one.

* `docs/05-design-notes/acl-scope-semantics.md` documents the model and what
  remains; CLAUDE.md gains the workspace rule.

### vti-common 0.11.15 / vta-service 0.12.19 — make `acl list --context` answer the same way on both surfaces

* The two implementations of the context filter disagreed on exactly one input
  class, and disagreed totally. Offline (`vta acl list --context`) matched
  `allowed_contexts.is_empty() || contains(ctx)`, so an **empty list matched
  every context**. Online (`operations::acl::list_acl`) matched
  `contains(ctx)`, so an **empty list matched none**. Same command, opposite
  answers.

* Neither was right. An empty list means unrestricted for `Role::Admin` and
  *nothing at all* for every other role, so the correct filter includes
  super-admins (offline had them, online silently dropped them — an operator
  auditing "who can reach context X" never saw the entries with the most
  authority over it) and excludes acts-nowhere entries (online had this right,
  offline listed them under every context).

* Both also compared with `contains`, missing entries scoped to an *ancestor*
  of the queried context, which do grant it. The VTC's equivalent filter has
  been hierarchy-aware all along; the VTA's now matches.

* One `acl_entry_can_act_in` predicate in `vti-common` now backs both call
  sites, so they cannot drift again.

### vta-service 0.12.18 — fix a vault scope gate that ignored the caller's role

* **Security.** `enforce_context_scope`, the gate on every vault trust task,
  treated *any* empty `allowed_contexts` as super-admin scope without checking
  the role:

  ```rust
  if auth.allowed_contexts.is_empty() {
      return Ok(()); // Super-admin (or unscoped) sees everything.
  }
  ```

  An empty list only means unrestricted for `Role::Admin` —
  `AuthClaims::is_super_admin` requires the role *and* the empty list, and
  `has_context_access` otherwise iterates the list, where empty matches
  nothing. So for every other role the entry is authorized **nowhere**, and
  this gate said the opposite.

  `Role::Reader` derives `Capability::VaultRead`, so a least-privilege approver
  — `--role reader` with no contexts, the shape the `--approve-all` help text
  recommends, whose authority is entirely `approve_scope` — passed the gate for
  every context and could read the credential vault community-wide.
  `Role::Initiator` derives `VaultWrite`, so the same shape reached
  `handle_upsert`.

  The gate now delegates to `has_context_access`, the predicate the REST routes
  already use. That also fixes a second defect in the same function: it
  compared contexts with `==`, so a context admin was denied its own subtree,
  which `has_context_access`'s segment-aware ancestry allows.

  The list handler's defence-in-depth narrowing had the identical `is_empty()`
  skip — an authorized-nowhere caller got every entry in every context — and is
  gated on `is_super_admin` now.

  Regression tests cover the reader and initiator shapes, the super-admin path
  that must keep working, and the subtree case. Verified to fail against the
  previous implementation.
### vta-sdk 0.19.24 / vti-common 0.11.14 / vta-service 0.12.17 / vta-cli-common 0.10.10 / pnm-cli 0.11.6 / cnm-cli 0.11.4 — approve scope is changeable, and the offline CLI can create

* **`approve_scope` was settable at create time only**, on every surface — REST,
  DIDComm, `pnm`, offline `vta`. Narrowing, widening or revoking an approver
  meant delete-and-recreate, which is worse than it sounds for exactly these
  entries: `ApproveScope::All` is super-admin-only to grant, so a non-super-admin
  operator whose recreate is refused has already landed the delete and left the
  DID with **no ACL entry at all**. It is also non-atomic over DIDComm, where an
  `Ok` means accepted-locally rather than applied, and it loses
  `created_at` / `created_by`. All four update paths now carry it. (#744)
* **Clearing is `Some(ApproveScope::None)`, not absence.** The update bodies
  carry the enum rather than mirroring create's `approve_all_contexts: bool` +
  `approve_contexts: Vec<String>` pair, because two independent fields cannot
  distinguish "revoke this approver" from "leave it alone" — and revoking is the
  case that matters most. On the CLIs that is an explicit `--approve-none`
  flag, for the same reason: an empty list cannot mean both.
* **`ApproveScope` moves to `vta-sdk`** (`vta_sdk::acl`), re-exported from
  `vti-common` — the arrangement already used for `context_path`. The DIDComm
  `UpdateAclBody` lives in the SDK and must be constructible by clients that
  never link the server crates. Only the shape moves; every authorization rule
  over it (`validate_approve_scope_grant`) stays in `vti-common`. The wire shape
  is unchanged and now pinned by a round-trip test.
* **`vta acl create` exists.** The offline surface had `list`/`get`/`update`/
  `delete` but no create, and the only offline entry-minting path (`vta
  import-did`) hardcodes an admin role with empty contexts behind the bootstrap
  seal — so there was no offline route to an approver entry at all. Like the
  existing offline `update`, it is **break-glass: no authorization check**,
  because the surface has no authenticated caller (it is direct store access by
  whoever holds the filesystem). The help text says so, so the absent
  super-admin check does not read as an oversight. Context-id *shape* validation
  still applies — that is not an authorization check, and the break-glass path
  should not be the one that plants a malformed id in the store. (#745)

### vti-common 0.11.13 / vta-cli-common 0.10.9 / vta-service 0.12.16 / pnm-cli 0.11.5 — ACL contexts: say what an empty list means, and stop storing a blank one

* **An empty `allowed_contexts` rendered as `(unrestricted)` for every role,
  which is the opposite of the truth for all but one.** `is_super_admin`
  requires `Role::Admin` *and* an empty list; `has_context_access` otherwise
  iterates the list, and an empty list matches nothing. So a least-privilege
  approver — the shape the `--approve-all` help text itself recommends —
  displayed as holding blanket read access while able to act nowhere, and an
  operator auditing for over-broad grants saw `(unrestricted)` on rows that were
  inert. `format_contexts` is now role-aware in both copies (`pnm` and the
  offline `vta acl`), rendering `(none — acts nowhere)` for non-admin. The test
  that asserted the old behaviour pinned the bug, not the contract. (#746)
* **`--contexts ''` stores a context named empty-string.** Verified against
  clap 4 rather than assumed: the empty value parses to `[""]`, not `[]`. That
  one-element list cleared every `is_empty()` guard while naming no context, and
  **nothing on the ACL write path validated a context id's shape at all** —
  `validate_context_path` existed and was never called there. A super admin
  reached it most easily, since its authority check returns before any
  per-context work. Both `validate_acl_modification` and
  `validate_approve_scope_grant` now validate each id, which also rejects
  `/ctx`, `ctx/`, `a//b` and ids containing spaces. The `--approve-all` help no
  longer recommends the broken invocation — omit `--contexts` instead. (#747)

### vta-service 0.12.15 — the consent decisions that reached no audit row

* Two decision paths recorded nothing, so a decision that *arrived* looked
  identical to one that never did. **Proof-verification failure** returns
  through `reject_with`, which does not log, and cannot write an audit row —
  there is no proven actor to attribute it to, and an unverified `from` is not
  an identity. It is now a `warn!`, because a broken proof (rotated key, wrong
  signer, malformed payload) and a wallet/routing failure have opposite causes
  and previously looked the same from the VTA side. The **`add_approval` race**
  (pending read, then gone before the approval lands) now records an audit row
  under the existing `denied:no_pending` outcome. (#760)
* Everything else #760 proposed was discarded deliberately: `record_consent`
  (#739) already instruments every other decision outcome and emits it to the
  `audit` target, so five of that patch's six lines would have been duplicates.

### vta-service 0.12.14 / vta-sdk 0.19.23 — `hostingPath` is retired, not reinterpreted

* **`hostingPath` never meant anything, and 0.12.12 gave it a meaning the live
  deployment contradicts.** No caller ever supplied `HOSTING_PATH`
  (`build_webvh_provision_ask` sets `URL` alone), so every document carrying the
  field carries the `did-host-http*` templates' own default, `/webvh`; and
  nothing in `affinidi-webvh-service`, `didwebvh-rs`, or the TDK ever read it
  back. A field with no producer and no consumer, in permanent signed documents.
* **`join_base` is reverted.** The REST base for a `WebVHHosting` endpoint is
  `serviceEndpoint.uri` alone. Reading the prefix as the control-plane base
  would have 404'd every REST-only server advertising one — it sat on
  `resolve_server_transport`, not just the agent-name path that motivated it,
  and that path had already moved to DIDComm, so nothing was exercising it.
  `webvh.storm.ws` answers `/api/health` with 200 and `/webvh/api/health` with
  404; `did-hosting-control` nests its whole API at `/api` off the origin root
  with no prefix setting to configure.
* **The three `did-host-http*` templates no longer emit the field**, so new
  documents stop making a claim nothing backs. Existing documents keep it
  harmlessly — the read side ignores it. `docs/02-vta/did-templates.md` replaces
  the (never-true) "where a hosting server publishes DID logs" definition with a
  retirement note carrying the evidence. (#759, #762)

### vta-service 0.12.13 — agent names over DIDComm, dropping the REST detour

* Agent-name operations had no DIDComm form, so a DIDComm-transport VTA either
  refused them or reached sideways to the hosting server's REST control plane.
  The hosting server now dispatches all six verbs itself
  (`spec/did-management/agent-name/{verb}/0.1`), so the detour is gone. (#758)

### vta-service 0.12.12 — honour the `hostingPath` a webvh server advertises — **reverted in 0.12.14**

* A hosting server may serve its control plane under a path prefix rather than
  at the origin root, and `webvh.storm.ws` advertises exactly that. The DID
  templates have emitted `hostingPath` all along; it is now actually used. (#756)
* **Superseded.** That premise was never checked against a live server and is
  wrong — `webvh.storm.ws` serves its control plane at the origin root, and the
  advertised `/webvh` was this workspace's own template default rather than
  anything the server published. Do not build on this entry; see 0.12.14. (#759)

### vta-service 0.12.11 — use the REST endpoint a server already advertises for agent names

* Managing an agent name failed on a server perfectly able to serve the request:
  agent-name operations are not supported over DIDComm, and the hosting server
  exposes them only via REST. Both true, and together the wrong conclusion —
  the advertised REST endpoint is now used. (#755)

### vta-sdk 0.19.22 — surface a trust-task error carried inside the payload

* A failed trust task still returns a `payload`, with the error envelope
  *inside* it as `{ code, message, retryable }`. `extract_trust_task_payload`
  treated the presence of a payload as success, so callers deserialised an error
  object as a result and reported whichever field their result type happened to
  be missing — while the real message was discarded. (#753)

### Release hygiene — the `vta-sdk` lockfile self-pin is gone, not refreshed

* A transitive dev-dependency (`vtc-service` → `affinidi-messaging-test-mediator`
  → `affinidi-messaging-mediator` → `vta-sdk`) pulled our own crate back in from
  crates.io, so `Cargo.lock` carried a second, registry-sourced `vta-sdk` node.
  It went stale the instant we published, and `cargo publish --locked` verifies
  dependents against it — which is how pnm-cli 0.11.2 was built against vta-sdk
  0.19.11 minutes after 0.19.12 shipped.
* Refreshing it can only happen inside the publish job, which means committing to
  a protected branch from CI; the org ruleset forbids that, so the workflow opens
  a PR instead and cannot ("GitHub Actions is not permitted to create or approve
  pull requests"). Seven consecutive releases ended with an orphaned refresh
  branch and a stale `main`, cleared by hand each time (#754 was the last of
  those); the seven orphaned branches have been deleted.
* `[patch.crates-io] vta-sdk = { path = "vta-sdk" }` removes the second node
  entirely — nothing to go stale, no refresh to run, no token or org setting
  required. Publishing is unaffected: the patch is workspace-local, so
  `cargo publish`'s verification build resolves `vta-sdk` from the registry and
  picks the newest published version, which in a release run is the one published
  moments earlier in the same loop. (#757)
* Trade-off: the published `affinidi-messaging-mediator` now compiles against the
  local `vta-sdk`. A breaking change within `0.19.x` surfaces in CI rather than
  after a release, but as a build failure inside a third-party crate.

### vta-service 0.12.10 — the consent e2e test matches #748's fail-fast contract

* #748 made an unsatisfiable elevation fail at submission instead of minting a
  consent ceremony that could never execute, but the test asserting the old
  behaviour was not updated, so `main` was red. The test now asserts the new
  contract: the task is refused up front, the refusal names the context and the
  approver set that cannot confer it, and no challenge is minted. (#752)

### vta-sdk 0.19.21 — the TSP ping measures its own reply

* `TspPingSession::ping` accepted the first frame that unpacked and parsed as
  JSON. The mediator inbox is durable, so a reply an earlier probe never
  collected is flushed onto the socket on connect — meaning the probe could
  report a healthy round trip, at an invented latency, off a pong from a previous
  run. That is what disguised a total TSP delivery outage as intermittent.
* The reply is now correlated on the Trust-Task `threadId` (falling back to the
  echoed `nonce`), so a stale frame cannot satisfy a probe. (#750)
* The underlying transport faults were upstream in `affinidi-tdk-rs`
  (affinidi/affinidi-tdk-rs#646): the mediator never marked raw-TSP websockets
  live, so anything arriving after connect was stored and never pushed, and the
  SDK separately dropped packed frames that landed between polls. Fixed and
  published in mediator 0.17.7 / messaging-sdk 0.18.62.

### vtc-service 0.11.19 / vta-sdk 0.19.20 — Phase 4: the remaining vtc families move to `spec/vtc`

* Every remaining VTC Trust Task with a canonical counterpart is repointed:
  members (list/show/renew/rotate/rotate-challenge/self-remove/personhood),
  relationships, endorsement-types, install/claim, admin/bootstrap,
  auth/recognise, website (files/list, generations/list, rollback), and
  `health/diagnostics` → `spec/vtc/registry/diagnostics/0.1`.
* **Four shared mounts are now split, one canonical task per verb**:
  `/members/{did}` (show/update/admin-remove), `/community/profile`
  (show/update), `/credentials/endorsements` (issue/list) and
  `/credentials/endorsements/{id}` (show/revoke). Seven of those tasks
  previously existed only on disk and were never enforced on the wire.
* **Breaking for clients that sent one verb's task for another.** The
  bundled admin UI was sending the *show* task on `DELETE /members/{did}`
  and on `PUT /community/profile`; both are fixed here, but any external
  client doing the same now gets a 415.
* `members/self-remove`'s SDK constant moves with the rest of the family
  (held back from the join-requests change so members migrated as a unit).
  openvtc needs one more `cargo update` after `vta-sdk 0.19.20` publishes.
* Not included: website's raw-byte ops (`files/show`, `files/write`,
  `deploy`) — Phase 4a decided those are not Trust Tasks, so they need
  de-listing rather than repointing — `website/files/delete` (its mount is
  a `ttl` chain sharing one layer across three verbs), and the families
  with no canonical counterpart.

### vta-sdk 0.19.19 / vtc-service — Phase 4: the join-requests ceremony moves to `spec/vtc`

* The nine join-requests constants move to
  `spec/vtc/join-requests/{submit,accept,status,manifest}/0.1` (and their
  `#response` forms); the four admin REST mounts move to
  `spec/vtc/join-requests/{list,show,approve,reject}/0.1`.
* **Breaking for DIDComm/document peers**: the Trust Task `type` a holder
  sends changes. `OpenVTC/openvtc#171` (merged) already teaches the
  OpenVTC router to accept both prefixes; an openvtc build must take
  vta-sdk 0.19.19 to *dispatch* the new types, since it matches on these
  constants.
* The GET list carries its own task instead of borrowing `submit`'s
  descriptor — the shared-mount workaround was never necessary (axum
  merges same-path method routers per method).
* The two `*_RECEIPT_TYPE` constants stay on the `openvtc` authority:
  a receipt is a fire-and-forget ack, not a Trust Task response, and the
  registry publishes no receipt task.
* `members/self-remove` is untouched here — moving only its DIDComm
  constant would have left its REST mount on the old authority. The
  members family moves as a unit in its own change.

### vtc-service — Phase 2a: `policy/*` repointed to the canonical registry

Completes the vtc-service Trust Task migration's Phase 2. The policy
family was the hardest of the five because canonical and VTC disagree on
what a policy *is*, not just on field names.

* `GET /v1/policies` → `spec/policy/list/0.2`, `POST /v1/policies` →
  `spec/policy/upsert/0.2`, `GET /v1/policies/{id}` →
  `spec/policy/get/0.1`, `POST /v1/policies/{id}/activate` →
  `spec/policy/activate/0.1`, plus a new `GET /v1/policies/active` →
  `spec/policy/active/0.1`. The four superseded `openvtc` tasks are
  **retired** with `supersededBy`.
* **`policies/test` deliberately stays on its `openvtc` URI.** Canonical
  `policy/evaluate` runs the *matching policy set* through the standard
  `decision` rule; `test` evaluates an operator-chosen Rego query against
  one stored module. Different verb, not a rename.
* **Purpose travels in `ext` (`org.openvtc.purpose`), and is required.**
  Canonical models purpose as a property of the *activation binding* — a
  module is purpose-agnostic and reusable. VTC cannot follow that: the
  purpose is baked into the module's own Rego package and validated at
  upload, because a module in the wrong package compiles cleanly and then
  silently denies every request for that ceremony. Inference is not an
  escape either — only 4 of the 10 purposes have an expected package, so
  6 could never be derived from source. `ext` is exactly what the
  framework reserves for ecosystem members, so the divergence is
  documented rather than hidden, and an upsert without it is refused
  rather than guessed at.
* **The package↔purpose guard is preserved** on both upsert and activate.
* **`expectedVersion` is honoured as a real compare-and-swap**: VTC's
  monotone per-purpose revision counter is the concurrency token, so two
  operators racing on the same purpose can no longer each append a
  revision over the other's read.
* **Breaking (admin API).** Entries are the canonical `PolicyModule`:
  `regoSource` → `module`, responses wrap in `{policy}` / `{policies,
  truncated, cursor}` / `{bindings}`, and `limit` → `pageSize`. `sha256`,
  `authorDid` and `purpose` move under `ext` (the canonical type is
  `additionalProperties: false`). `isActive` is **gone** — activeness is
  a binding, read from `policy/active`. The bundled admin UI is updated
  in step.
* Canonical members this maintainer cannot honour — `appliesTo`,
  `priority`, `enabled` on upsert; `contextId`, `enabledOnly` on list;
  `contextId` on active — are **refused with an error naming them**
  rather than accepted and ignored. A caller setting `enabled: false`
  must never have it silently dropped.

### vtc-service — Phase 2d: `acl/*` repointed, with the canonical semantics implemented

* The two combined mounts (`acl/legacy/{manage,entry}/1.0`) fan out to the five
  canonical tasks — `spec/acl/{list,grant,show,change-role,revoke}/0.1` — one per
  verb. Both legacy tasks are **retired** with `supersededBy`.
* **Breaking (admin API).** Entries are now the canonical `AclEntry`:
  `did` → `subject`, `allowed_contexts` → `scopes`, and every timestamp is an
  RFC3339 string rather than a unix epoch (canonical types them
  `format: date-time`, so an integer would be a silent contract break). List
  responses gain the canonical-required `truncated` plus an optional `cursor`.
  The bundled admin UI is updated in step.
* **`PATCH /v1/acl/{did}` is now `acl/change-role`, and role-only.** It takes
  `{fromRole, toRole}` and **enforces `fromRole` as a compare-and-swap**,
  returning 409 when the subject's current role differs. That closes the
  read-modify-write race the old partial update had: two admins demoting the
  same subject concurrently could each read `admin`, write different results,
  and last-writer-wins with no signal. The old body (`role`/`label`/
  `allowed_contexts`, all optional) is rejected outright rather than being
  read as a subset of the new one.
* **Label and scope edits move to `acl/grant`**, which canonical defines as
  "the entry the maintainer should hold". Re-granting the *same* role rewrites
  the entry; granting a *different* role to an existing subject is refused with
  a pointer to `acl/change-role`, so grant cannot be used to bypass the CAS
  guard. Server-owned provenance (`createdAt`/`createdBy`/`updatedAt`/
  `updatedBy`) is not accepted from callers.
* **`DELETE` implements canonical revoke's two modes.** With `?scopes=`, the
  entry is *scope-reduced* and survives; only an omitted `scopes` removes it.
  Conflating the two would have stripped far more authority than an operator
  asked for. Revoking *every* scope is refused rather than executed, because an
  empty scope set is how a community-wide (super) grant is spelled — revocation
  must never widen authority. A scope reduction revokes the subject's live
  sessions, since their tokens still carry the old scopes.
* `acl/list` gains the canonical `role` / `scope` / `subjectPrefix` filters and
  `pageSize`/`cursor` paging, with the filters bound into the cursor's HMAC so a
  page cannot be resumed under a different filter set. The `scope` filter keeps
  the hierarchy-aware matching the old `context` filter had (an ancestor scope
  does carry a descendant). Paging degrades gracefully when the audit writer is
  absent: cursors are signed with the audit key, so without one the full visible
  set is returned as a single page rather than the endpoint failing — listing the
  ACL must not depend on audit being configured.
* `VtcAclEntry` gains `updated_at`/`updated_by` (`#[serde(default)]`, so existing
  rows decode unchanged and report `None` rather than pretending creation was an
  update).

### vtc-service — Phase 2b(ii): `audit/list` repointed, with filters actually implemented

* `GET /v1/audit` now carries `https://trusttasks.org/spec/audit/list/0.1`;
  `openvtc/vtc/audit/list/1.0` is **retired** with `supersededBy`.
* **Breaking (admin API).** The response is the canonical envelope —
  `{entries, truncated, cursor}` replaces `{items, next_cursor,
  total_estimate}` — and each entry is a canonical `AuditEnvelope`:
  `eventId` / `recordedAt` / `action` / `actor` / `target` / `detail`,
  camelCase throughout. `limit` is renamed `pageSize`. The bundled
  admin UI is updated in step.
* Because the canonical envelope is `additionalProperties: false`,
  VTC's maintainer-specific fields (`actorDidHash`, `targetDidHash`,
  `auditKeyId`, `eventVersion`) move under `ext.vtc` rather than being
  dropped. `action` is the serde tag already stored on the envelope
  (e.g. `MemberRemoved`) and `detail` is that variant's payload.
* `prevHash` / `entryHash` are emitted as **hex**, matching the encoding
  `audit/verify` already uses for `head`. They are base64 in storage, so
  a caller comparing `verify.head` with the newest entry's `entryHash`
  would otherwise see a spurious mismatch; a test now pins the two
  together.
* **Filters are implemented, not accepted-and-ignored.** `from`, `to`,
  `action` and `actor` filter server-side. `outcome` and `contextId` —
  which this maintainer has no data for (there is no envelope-level
  outcome, and a VTC is a single community, so the log is not
  context-partitioned) — are **refused with an error naming them**.
  Returning an unfiltered page to a caller who asked for
  `actor=X&outcome=denied` would invite exactly the wrong conclusion.
* `truncated` reports whether more *matching* entries remain, not
  whether more rows remain, so a filtered query can't hand back a cursor
  that leads only to an empty tail.
* Cursors are bound to their filter set: `Cursor::{encode,decode}_bound`
  fold the active filters into the HMAC without putting them on the
  wire, so resuming a page under different filters fails as a tampered
  cursor. Canonical requires filters not change mid-pagination; unbound
  `encode`/`decode` stay byte-compatible, so other paginated endpoints
  are unaffected.

### vtc-service / cnm-cli — Phase 2b(i): `audit/verify` repointed to the canonical registry

* `POST /v1/audit/verify` now carries
  `https://trusttasks.org/spec/audit/verify/0.1`; the
  `openvtc/vtc/audit/verify/1.0` task is **retired** with `supersededBy`.
* **No payload change.** The canonical schema was derived from VTC's
  `VerifyResponse`: the request is parameterless and every response field
  (`verified`, `entriesExamined`, `entriesVerified`, `legacySkipped`,
  `unparseableSkipped`, optional `head` / `chainBreak`) already matched,
  including `chainBreak.kind`, which VTC already emits as the canonical
  `tamperedEntry` / `brokenLink` rather than a snake_case variant.
* `audit/list` is **not** repointed here — it needs a genuine response
  projection (`{items,next_cursor,total_estimate}` →
  `{entries,truncated,cursor}`, snake_case envelope → canonical
  `AuditEnvelope`) plus a rewrite of the `vtc-service/admin-ui` audit
  plugin that consumes the current shape. It follows as its own change.

### vta-sdk 0.19.18 — a failed DIDComm connect no longer leaks a live socket

* `DIDCommSession::connect_with_secrets` created an `ATM` and then ran several
  fallible steps against it — profile creation, the 15s-bounded
  `profile_enable_websocket`, binding `DidCommTransport`. Every one of those
  error paths returned without calling `graceful_shutdown()`. Dropping the
  handles does **not** stop the ATM's background tasks: the websocket transport
  survives, reconnects on its own timer, and goes on holding the mediator's
  one-socket-per-DID slot for `client_did` for the life of the process. The
  `LeakGuard` only catches a *successfully built* session that is dropped
  without `shutdown()` — it never saw these, because the session was never
  built.
* Why it bit: a service that opens a session per refresh cycle accumulates one
  ghost socket per failed connect. Several of them, all authenticated as the
  same DID, then duel over that DID's slot — each eviction triggering an
  immediate reconnect. A mediator was observed taking ~40 connects/sec from its
  own admin DID this way.
* Fix: the fallible tail moved into `finish_connect`, with a single error path
  that shuts the ATM down. The outcome is stringified before the shutdown await
  because `Box<dyn Error>` is not `Send` and would otherwise make the connect
  future non-`Send`.
* The same omission is fixed in the three probe paths in `session.rs`
  (`ping_over_didcomm`, `TrustPingSession::connect`, the TSP probe): each now
  tears its ATM down when setup fails, not only when it succeeds.
* Pairs with `affinidi-messaging-sdk` 0.18.61 (client backoff no longer resets
  on an immediately-closed socket) and `affinidi-messaging-mediator` 0.17.6
  (refresh over REST when self-mediated; server-side duel damper).

### vtc-service — Phase 2c: config Trust Tasks repointed to the canonical registry

* `GET /v1/admin/config` now carries `https://trusttasks.org/spec/config/show/0.1`,
  `PATCH` carries `spec/config/patch/0.1`, and reload / restart carry
  `spec/config/{reload,restart}/0.1`. The `openvtc/vtc/admin/config/
  {manage,reload,restart}/1.0` tasks are **retired** with `supersededBy`
  (SPEC §5.3). `config/legacy/manage` and `admin/config/{export,import}` keep
  their `openvtc/` URIs — they have no canonical counterpart.
* **Breaking (admin API):** the PATCH body now wraps its key→value map in an
  `overrides` object — `{"overrides":{"log.level":"debug"}}` — to match
  canonical `config/patch/0.1`, whose envelope is `additionalProperties:
  false`. Previously the map was flattened to the top level. Unknown top-level
  members are now rejected rather than treated as config keys.
* The merged GET+PATCH mount was split into two separately-enforced tasks.
  A long-standing comment claimed this had to wait for `TrustTaskRouter` to
  gain per-method task selectors; that was **mistaken**. `task_routes` layers
  the *method* router and axum merges same-path method routers per method, so
  each verb already enforces its own URI. Now pinned by
  `vti_common::trust_task::openapi::per_method_tasks_on_one_path_are_enforced_independently`,
  which also unblocks the ACL fan-out in Phase 2d.

### vta-sdk 0.19.14 — republish on didwebvh-rs 0.6

* Dependency-only release, but a necessary one: the published `vta-sdk 0.19.13`
  has `didwebvh-rs = "0.5.6"` baked into its manifest, because a crate freezes
  its workspace-inherited dependency versions at publish time. #712 moved this
  workspace to `didwebvh-rs 0.6`, and that only reaches consumers once vta-sdk
  is republished.
* Why it matters: `didwebvh-rs 0.6` requires `affinidi-did-common "0.4"` while
  0.5.x required `"0.3"`. Any consumer resolving both the published vta-sdk and
  a current Affinidi crate therefore pulls **two copies of
  `affinidi-did-common`** — which compiles only while no `Document` crosses the
  boundary, and becomes a hard `E0308` the moment one does. The Affinidi TDK
  carries exactly this duplicate today, allowlisted in its
  `scripts/workspace-duplicates-allow.txt` pending this release.
* No source changes. Verified by packaging: the 0.19.14 manifest carries
  `didwebvh-rs = "0.6"`.

### vta-sdk — REST discovery matches a set of service types

* `ServiceCapabilities` matched REST on `"VTARest"` and nothing else. That
  type is correct for a VTA — it says a VTA's REST API is behind the URL — but
  it made the type unusable as a generic "this peer speaks REST" marker: any
  non-VTA service either had to claim to be a VTA or stay undiscoverable. A
  Trust Registry advertising its own type was invisible, so `select_protocol`
  returned `NoMatchingProtocol` for a peer that plainly spoke REST.
  `REST_SERVICE_TYPES` now holds both `VTARest` and `TRQPRest` (a Trust
  Registry's TRQP-over-REST surface) and matching walks the set. VTAs are
  unaffected; adding a REST-speaking service type is a one-line change.
* `vta-mobile-core`'s resolver matched services with
  `id.ends_with("#vta-rest") || ty == "VTARest"`. Matching on the `#id`
  fragment violates R4.4 — the fragment is an arbitrary label — so the check
  both missed valid services (a registry uses `#rest`) and could match the
  wrong one: a DIDComm entry fragmented `#vta-rest` would have been read as
  the REST endpoint. It now matches on `type` alone.

### vta-service — CMS `encryptedContent` unwrap no longer misreads raw ciphertext

* `decrypt_cms_envelope` decided whether KMS had used EXPLICIT tagging on
  `encryptedContent [0]` by testing a single byte — `ct_value[0] == 0x04`.
  Under the normal IMPLICIT tagging that slice is raw AES-GCM ciphertext, i.e.
  uniformly random bytes, so roughly 1 envelope in 256 was mistaken for an
  EXPLICIT OCTET STRING wrapper. The misfire either raised a bogus
  `CMS: truncated length bytes for inner encryptedContent` on a perfectly valid
  envelope, or — worse — parsed successfully and returned a *truncated*
  ciphertext, surfacing as a GCM tag mismatch indistinguishable from the KMS
  ciphertext tampering the JWT-fingerprint guard exists to flag. Both land on
  the enclave's first-boot path. The check is now structural: the slice is
  unwrapped only when it is a well-formed OCTET STRING TLV spanning it
  *exactly*, which random ciphertext cannot satisfy by accident. Measured over
  500 runs of the wrong-key test: 2 failures before, 0 after (issue #685, filed
  as CI flake — the flake was this bug).
* The `encryptedContent` length parse also sliced without bounds checks, so a
  truncated or malformed envelope panicked instead of returning `AppError`;
  over-wide long-form lengths are now rejected before they can overflow the
  shift. Every other parse in this module already returned typed errors.

### pnm-cli — `bootstrap open --out` writes the credential bundle

* `pnm bootstrap open` decrypted a sealed bundle, printed a summary and exited
  without writing anything, and had no flag to do otherwise. File-based
  consumers of a `CredentialBundle` — notably the trust registry's
  `TR_VTA_CREDENTIAL`, documented as a `file://` URI — therefore had no
  supported way to obtain one: `extract_admin_credential` existed but was
  reachable only from `cnm-cli`, which feeds it straight into the keyring.
  `--out <PATH>` now writes the extracted bundle as JSON, opened at `0600` so
  the private key is never briefly world-readable. Serde renames on
  `CredentialBundle` mean the output is already the documented wire shape
  (`privateKeyMultibase` / `vtaDid` / `vtaUrl`). Accepts `AdminCredential` and
  `ContextProvision` payloads; other variants keep their existing per-variant
  rejection. Because opening consumes the single-use bootstrap secret, the
  omit-`--out` path now says plainly that nothing was written and how to get a
  file, rather than pointing only at the online `connect` flow.

### vta-mobile-core — task-consent approver FFI (mobile as a 2nd device, phase 1)

* New `consent.rs` exposes the FFI the mobile agent needs to act as a
  task-consent approver, mirroring the existing step-up approver: parse an
  inbound `task-consent/request/0.1` for display (`parse_task_consent_request` —
  lenient, tolerating the VTA's extra wire fields, and surfacing effects, the
  side-effect/exposure class, and a digest-prefix match code), and build a
  DID-signed `task-consent/decision/0.1` approval or denial
  (`build_task_consent_decision_did_signed` / `_denied`) via the shared
  `eddsa-jcs-2022` proof path. DIDComm transport only; the on-device DI-proof
  verify of the request is a hardening follow-up. The Swift approval UI is the
  next slice.

### vta-service — notify the requester when a task-consent grant is minted

* A requester had no way to learn that its task had been approved except to
  re-submit and see whether the grant existed — which meant the caller polled.
  On reaching the approval threshold, the VTA now pushes a lightweight
  `task-consent/granted/0.1` notice (carrying the salted `payloadDigest` the
  requester already holds) to the requester's DID over the mediator, using the
  same Guaranteed delivery + doorbell as the consent-request push. It is
  best-effort and non-load-bearing — the single-use grant check remains the real
  gate, so a lost or spurious notice costs at most one re-submit — and it lets a
  requester act the instant an approval lands (same browser or another device)
  instead of polling.

### vta-sdk / vta-service / CLI — surface an entry's approve-authority in output

* The ACL create/get/list echo carried no `approve_scope`, so after
  `acl create --approve-contexts …` the one field that makes an entry an approver
  was invisible — you couldn't confirm it was set. The result body
  (`CreateAclResultBody`) and the client `AclEntryResponse` now echo it as
  `approve_all_contexts` / `approve_contexts` (both `#[serde(default)]` for
  pre-approver servers), and `pnm acl create` / `acl get` / `acl list
  --full-display` print an `Approve:` line (`all contexts` or `contexts [ … ]`),
  shown only when the entry actually confers something.

### vti-common / vta-service — least-privilege approvers: separate "may approve" from "may act"

* An approval only *conferred* delegated authority (task-consent
  `compute_delegated_contexts`, step-up `delegated_any_approver_covers`) if the
  approver was `Role::Admin` of the subject's context — which is also the power
  to change DIDs in it directly, and approving across all contexts required a
  super-admin. The reviewer had to hold the maximal power to make the very change
  it was meant to check.
* **Fix 1** — new `ApproveScope` (`none` | `all` | `contexts([...])`) on the ACL
  entry, read only by the two conferral paths and never by
  `require_admin`/`has_context_access`. An approver can now be `role: reader`,
  `allowed_contexts: []` (acts nowhere) with `approve_scope: all` (authorizes
  anywhere). Both conferral paths honour it in addition to the existing admin
  path (backward compatible; pre-existing rows deserialise as `none`,
  fail-closed). Granting it is privilege-checked: `all` is super-admin-only, a
  scoped grant requires the caller to hold each context. Exposed on the ACL
  create surface (trust-task / DIDComm / REST) and the CLI (`--approve-all` /
  `--approve-contexts`).
* **Fix 2** — new `AuthClaims::with_delegated_authority`: a consumed consent
  grant now lifts the ephemeral role to `Admin` (not just the context) for the
  single bound dispatch, so a purely unprivileged requester can execute a task an
  approver blessed. The webvh update guard is relaxed to match: Plan mode needs
  only `require_read` (a dry-run reveals just the public DID-document diff), and
  Execute is satisfied by the delegated grant. The requester (e.g. the browser
  plugin) can therefore hold no standing admin — every cross-context edit is
  gated on a live approval. The widening stays single-dispatch and is never
  persisted to the session, JWT, or ACL.
### vtc-service 0.11.11 — follow vti-common capability_client dedup

* The hook writer drops one `?` now that the shared capability document builders
  are infallible (they return the document, not `Result`). No behaviour change.

### vti-common 0.11.8 — capability_client is now the shared crate

* `vti_common::capability_client` is re-exported from the new published
  `trust-tasks-capability-client` crate instead of an inlined copy, so the hook
  producer here and out-of-repo consumers (management UIs) share one
  contract-tested wire implementation. The builders are now infallible (they
  return the document directly); `vtc-service`'s hook writer drops the
  corresponding `?`.


### vtc-service 0.11.10 — membership hooks: production DIDComm writer + wiring

* Completes the membership hook relay (`design-docs/vtc-membership-hooks.md`): the
  `DidcommCapabilityWriter` signs `git-trust/grant|revoke` documents with the VTC's
  credential signer (the community is the authority its grants are issued under; the
  signer's canonical form matches the trust registry verifier's exactly) and sends them
  to the registry over the delivery-layer messaging, correlating the reply by `threadId`
  through a shared pending-reply map completed in the inbound demux.
* New config: `registry.did` (the registry's DIDComm DID — required for the relay) and a
  `[hooks.git-trust]` section (`grant_on_role`, `revoke_with_membership`). `serve()`
  spawns the relay under a panic-restart supervisor **only** when git-trust hooks, the
  registry DID, and the VTC credential signer are all present — absent any, no relay.
* New keyspaces `hooks_queue` / `hooks_cursor`.


### vti-common 0.11.7 — `capability_client`: shared capability Trust Task primitives

* New `capability_client` module: transport-free document builders, `eddsa-jcs-2022`
  Data-Integrity signing (canonical form matching the trust registry's verifier),
  DIDComm envelope parsing, and reply classification for the capability Trust Task
  families (`governance/capability/*`, `git-trust/*`). `WriteOutcome::IdempotentSuccess`
  classifies the registry's `already_granted`/`not_granted` answers as success, making
  redelivered capability writes safe. First consumer: the vtc-service membership hooks;
  the openvtc TUI's duplicate copy migrates in a follow-up.

### vtc-service 0.11.9 — membership lifecycle hooks (capability grant relay)

* New `hooks` module (`design-docs/vtc-membership-hooks.md`): membership audit events
  (`MemberAdded`/`MemberRemoved`/`RoleChanged`) map through the operator's
  `[hooks.git-trust] grant_on_role` configuration into `git-trust/grant|revoke`
  capability writes, drained by `HookRelay` — a second audit-tail consumer with its own
  cursor and queue, modeled on the `MembershipSyncer` so crash-replay is inherited.
  Exactly-once-effective (idempotency root = the audit row key), FIFO-ordered including
  within one event's revoke→grant pair, revocation retries indefinitely on transient
  failures (delivery-critical), grants carry a bounded retry budget, and registry
  rejections are terminal and loud. Absent `[hooks]` config, the relay is not spawned.
  The production DIDComm `CapabilityWriter` plus server wiring land in the follow-up.


### vta-service — recover from a wedged mediator listener (drain-on-start + clearer logging)

* The mediator enforces one live-delivery websocket per DID, and the VTA's single
  DIDComm listener carries **both DIDComm and TSP**. So an undeliverable/poison
  message queued for the VTA's DID — or an active websocket left by a prior
  process that wasn't cleanly stopped — can stall the live-delivery handshake and
  wedge the listener indefinitely, taking both inbound paths down while REST stays
  up. Diagnosing it previously meant dropping to `RUST_LOG` debug.
* The `not connected after 30s` warning now explains this in the default log:
  that auth+websocket likely connected but live-delivery didn't complete, that the
  one listener carries DIDComm *and* TSP, the two usual causes (a lingering active
  websocket for this DID, or a queued poison message), that the VTA keeps serving
  REST and retrying, and how to recover.
* New opt-in `messaging.drain_inbox_on_start` (default **false**). Because REST
  auth + message-pickup keep working even when the websocket stalls, when set the
  VTA drains its own mediator inbox over REST **before** enabling the live
  listener: it fetches queued messages in bounded batches and deletes them,
  logging each (and loudly logging + stopping if a batch can't be fetched), so a
  mediator-side backlog can't keep startup wedged. Off by default because it
  deletes queued messages; turn it on to recover a stuck boot without touching the
  mediator.

### vta-service — per-task delegated capability for cross-context trust tasks

* A delegated webvh update failed with `forbidden: caller has no admin role in
  context` whenever the requester wasn't an admin of the DID's context. The only
  ways to make it pass were to grant the (agent) requester standing admin in
  every context it touches, or make it a super-admin — both put durable, broad
  authority on a long-lived credential. Authority was a standing property of the
  requester, checked at both plan and execute; consent was collected but never
  load-bearing (the approver's authority was never consulted).
* Authority can now flow **per task** from an approver who holds it. When a
  requester can't self-authorize the DID's context, the plan dry-run still runs
  (its only output is the public DID-document diff, so an approver can be shown
  the effects), and the task is executable only via consent. At the approval
  threshold, `task-consent/decision` resolves each approver against the live ACL
  and — attenuation only — confers the DID's context **iff** enough approvers are
  admins of it (`Role::Admin` + context access; set membership alone is not
  authority). The consumed grant then widens the requester's `AuthClaims` for
  that single dispatch via `AuthClaims::with_delegated_contexts`; the widening is
  payload-bound, state-pinned, single-use, short-lived, and never written back to
  the session. The agent holds no standing context authority.
* An approval from a set member who is *not* an admin of the context confers
  nothing, so the re-submit still can't execute. Same-context consent is
  unchanged. New fields carry the delegation through: `UpdatePlan` /
  `TaskPlan.{subject_context, requester_authorized}`,
  `PendingTaskConsent.{subject_context, requester_authorized}`, and
  `TaskConsentGrant.delegated_contexts` (all `#[serde(default)]`, so older stored
  pendings/grants read as non-delegated). Covered by unit tests for the
  attenuation rule and two `mocks-nothing` e2e flows (a context-admin approval
  lets a cross-context requester execute; a non-context-admin approval does not).

### vtc-service (0.11.5) — foreign status-list fetch delegates to the shared SSRF chokepoint (D2)

* The recognise/present path's SSRF guard, hardened HTTP client, and
  response-body cap were a verbatim copy of the shared `vta_sdk::http` helpers.
  `verify.rs` now delegates `guard_status_list_url` → `vta_sdk::http::guard_public_url`,
  `foreign_fetch_client` → `vta_sdk::http::foreign_fetch_client`, and
  `read_body_capped` → `vta_sdk::http::read_body_capped` (mapping
  `ForeignFetchError` → `RecognitionError::StatusListFailed`), so the VTA
  vault-present and VTC recognise paths share one CWE-918 guard implementation
  instead of two that could drift. Behaviour and error surface are unchanged;
  the local `FOREIGN_FETCH_CLIENT` / timeout const / body-cap const were removed.

### vta-enclave — retry the vsock storage-proxy connect on boot (D9)

* On a cold boot the enclave and the parent-side vsock storage proxy start
  concurrently; a single `VsockStore::connect` that lost the race would
  `exit(1)`, and Nitro does not restart the enclave — so a benign ordering race
  became an outage on every unattended host reboot. The connect now retries with
  bounded backoff (~80s wait-for-dependency) before giving up. (`publish = false`;
  no version bump.)

### vtc-service (0.11.4) — website file-list is off-runtime and hashes only the page (D9)

* `GET /v1/website/files` walked the whole site tree and `std::fs::read` +
  SHA-256'd every file **on the async runtime**, even though the response is
  paginated to ≤200 entries — pinning a tokio worker with O(total-site-bytes)
  work on large media bundles, and `TimeoutLayer` couldn't cancel the blocking
  code. It now walks metadata off the runtime (`spawn_blocking`, O(files), no
  reads), paginates on that cheap metadata, and hashes **only the returned
  window** off the runtime.

### vta-service (0.11.5) — final-mode create fails fast when it can't succeed

* Final-mode `create-did-webvh` (a client-provided, pre-signed `did_log`) is
  serverless-only. Combined with a hosting `server_id` it published using the
  base58 SCID as the mnemonic path with no prior slot reservation, which the
  host always rejects (mixed-case mnemonic + unreserved slot) — so it could
  never succeed. No first-party flow uses that combination (`vta setup`'s
  advanced `did_log` path is always serverless). The VTA now rejects it up front
  with an actionable error ("…only supported serverless… use template or
  did_document mode") instead of a confusing downstream host failure. (D4-F2)

### vta-service (0.11.4) — webvh update keys off the canonical SCID

* Fixed a keyspace bifurcation (#659 regression): `run_update` accepted a full
  `did:webvh:…` (delegated path) or a bare SCID (CLI) but then keyed the
  `webvh_keys` handle store off the raw argument. A DID updated via one path
  installed its key handles under a prefix the other path couldn't find, so a
  delegated update left the DID un-updatable from the CLI ("no active update key
  … restore from backup"). `run_update` now canonicalizes the identifier to the
  record's bare SCID before any key-handle op. Adds a regression test that both
  identifier forms resolve to the same canonical SCID.

### vta-sdk (0.19.6) — shared hardened foreign-fetch helper

* New `http::{foreign_fetch_client, read_body_capped, guard_public_url,
  DEFAULT_MAX_FOREIGN_BODY, ForeignFetchError}`: the single hardened chokepoint
  for fetching attacker-influenceable URLs — `redirect(none)` (blocks
  SSRF-via-redirect), bounded timeouts, a chunked response-body cap, and an
  SSRF URL guard (https-only, no userinfo, rejects loopback/private/link-local/
  multicast/ULA and cloud-metadata IP targets). Ported from vtc-service's
  reference implementation so consumers share one guard instead of each rolling
  their own.

### vta-service (0.11.3) — status-list fetch is SSRF/DoS-hardened

* `HttpStatusListResolver` (the issuer-supplied status-list fetch on the
  credential-present path) previously used `reqwest::Client::new()`: no timeout,
  default redirect-following, and `.json()` buffering an unbounded body — a
  tarpit / SSRF-via-redirect / OOM surface on a hot path. It now guards the URL
  (`vta_sdk::http::guard_public_url`) before dialing, fetches through the shared
  hardened client, and reads the body under `DEFAULT_MAX_FOREIGN_BODY`.

### vta-sdk (0.19.5) — finite timeouts on all REST clients

* Every SDK REST client is now built with request + connect timeouts (new
  internal `http::rest_client`, overridable via `VTA_REST_TIMEOUT_SECS` /
  `VTA_REST_CONNECT_TIMEOUT_SECS`) instead of `reqwest::Client::new()`, which
  has no default timeout. A hung or blackholed VTA now surfaces as a timeout
  error rather than hanging the caller (vtc setup, vta-mcp, the CLIs) forever.

### vta-service (0.11.2) — webvh client timeout bounds the per-server auth mutex

* `WebvhClient` is built with request + connect timeouts. A wedged hosting
  daemon now fails with a timeout instead of an unbounded hang, which also
  bounds how long `auth_cache::ensure_fresh_access_token` holds the per-server
  auth mutex — so one dead daemon can no longer freeze all publishing for that
  server.

### vta-service (0.11.1) — consent rejects carry a machine-readable reason

* The consent-required rejection (`policy_gate`) now includes an explicit
  `"reason": "auth:consent_required"` in the trust-task-error `details`, so a
  consumer keys on a stable structured field instead of the standard top-level
  `code` (`taskFailed`) or the free-text `message`. Additive and
  backward-compatible — existing `details` fields (`payloadDigest`, `challenge`,
  `approverSet`, `minApprovals`, `consentRequests`) are unchanged.

### vta-sdk (0.19.4) — acl/create body reads camelCase, rejects unknown fields

* `CreateAclBody` (the `spec/vta/acl/create/1.0` Trust Task payload) now
  deserializes **camelCase** as its canonical wire form, matching the published
  spec convention and the sibling `acl/swap-key` body. Snake_case is still
  accepted via per-field aliases (non-breaking for the REST client and legacy
  senders), and unknown fields are now rejected (`deny_unknown_fields`).
* Fixes a silent-drop hazard: a spec-conventional camelCase caller previously
  had `allowedContexts`/`expiresAt` dropped to defaults. Because an empty
  `allowed_contexts` on an `Admin` entry is a super-admin, a super-admin caller
  intending a scoped, expiring grant could instead mint a permanent,
  unrestricted admin.

### vti-common (0.11.5)

* Added `setup_acl: bool` (default `false`) to `MessagingConfig`.

### vtc-service (0.11.3)

* Fixed `MessagingConfig` initialisers to include the new `setup_acl` field.

### vta-service (0.11.0) — automatic ACL provisioning on startup

* Enabled the SDK's `acl-setup` feature and integrated automatic
  mediator ACL provisioning into VTA startup.
* VTA now provisions the required DID-level mediator ACL immediately
  after establishing its DIDComm listener connection, eliminating the
  need for manual ACL setup.
* Reuses the shared ACL provisioning implementation provided by
  `vta-sdk`.
* Allows VTA deployments to operate correctly with mediators with
  stricter ACL enforcement policies.
* ACL provisioning is performed transparently during startup and does
  not alter existing DIDComm workflows beyond automatically ensuring
  the required mediator access rules are present.
* Added `setup_acl` boolean to `[messaging]` in `config.toml` and the
  `vta setup` wizard / `--from <toml>` schema. When `true`, the VTA
  automatically provisions its per-DID allow-all ACL on the mediator
  after connecting (required for mediators using `ExplicitAllow` mode).
  Defaults to `false`; existing configs are unaffected.

### cnm-cli (0.11.0) / pnm-cli (0.11.0) — automatic ACL setup on DIDComm connect

* Enabled the SDK's `acl-setup` feature by default in the CLIs.
* DIDComm connections now automatically provision mediator ACLs during
  connection establishment.
* Improves interoperability with mediators enforcing DID-level ACL
  policies by removing the manual ACL setup requirement.
* Keeps CLIs workflows unchanged while ensuring ACL provisioning is
  performed transparently in the background.

### vta-sdk (0.19.3) — automatic mediator ACL provisioning for DIDComm connections

- Added an optional `acl-setup` feature that automatically provisions
  DID-level mediator ACLs when a DIDComm connection is established.
  The implementation hashes the client DID (SHA-256), creates an
  allow-all `MediatorAcl`, and submits it via
  `atm.trust_tasks().acl_set()` in a non-blocking background task.
- `connect_with_secrets()` now invokes ACL provisioning after DIDComm
  transport initialization when the `acl-setup` feature is enabled.
  Existing behavior is unchanged when the feature is not enabled.
- Introduced a shared `acl_setup` module containing reusable ACL
  provisioning logic for SDK consumers.
- New feature dependencies:
  `trust-tasks-rs`, `sha2`, `tracing`, and `tokio`
  (all gated behind `acl-setup`).
- This change enables SDK consumers to operate against mediators with
  stricter ACL enforcement policies without requiring manual DID-level
  ACL configuration.

### vta-sdk (0.19.2) — declare the `task-consent` Trust Task family

`task-consent/decision/1.0` (PR #645) introduced a new Trust Task family, but
the `every_uri_in_canonical_namespace` census — which exists to force exactly
that declaration — was never updated, so it has been failing on `main` since.
Declares `https://trusttasks.org/spec/task-consent/` with the rationale for it
being its own family rather than a member of messaging `consent/*` (different
subject, authority, and grant lifetime), and refreshes the census preamble,
which had drifted (it claimed five families and omitted `spec/device/`).

Test-only change; no wire or API surface moves.

### pnm-cli (0.10.7) / cnm-cli (0.10.7) — `--transport rest` recovery flag

Adds a global `--transport <auto|rest>` flag to both CLIs. `rest` forces the
REST transport, skipping DIDComm even when the VTA advertises it and even when
the local config pins a `mediator_did` — the recovery path when a VTA's mediator
is unreachable and auto-selection would keep dialling it. Example: `pnm
--transport rest services didcomm disable` recovers a VTA that enabled DIDComm
against a mediator it can't reach.

`pnm` also reconciles a pinned `mediator_did` after a successful `services
didcomm enable|update|disable` (repoint on enable/update, clear on disable). The
pin is priority 1 of transport selection and never re-reads the DID document, so
a stale one would keep forcing DIDComm at a mediator that is gone.

Docs: `docs/02-vta/runtime-service-management.md` gains a "Recovery: the mediator
is unreachable" section.

### vta-sdk (0.19.1) — force-REST connect path + bounded DIDComm connect

- `SessionStore::connect_with_transport` + `TransportChoice { Auto, Rest }`:
  force REST regardless of advertised DIDComm. The existing `connect` is
  unchanged and delegates with `Auto`. Purely additive. `TransportChoice` is
  `#[non_exhaustive]` — TSP will land as a variant.
- Auto-selected DIDComm connects are now bounded (30s default, override with
  `VTA_DIDCOMM_CONNECT_TIMEOUT_SECS`). The mediator client owns a
  reconnect/backoff loop, so an unreachable mediator previously hung the CLI
  indefinitely instead of failing; the timeout error now names
  `--transport rest`, which is what makes the flag above discoverable.
- Forced REST resolves `url_override`, else the `#vta-rest` service on the VTA's
  DID document, and errors asking for `--url` if it finds neither. It
  deliberately does not fall back to a URL synthesized from the DID's own domain
  (`resolve_vta_url`'s last resort): for a hosted `did:webvh` that is the DID
  host, not the VTA, and authenticating against it fails undiagnosably.

### vta-sdk (0.18.18) — did-host TSP-only DID templates

Two new built-in `did-host-*` templates let a VTA provision a node whose DID
advertises **TSP without DIDComm**, closing the gap where the only
mediator-carrying `did-host-*` templates advertised both transports
unconditionally.

Highlights:
- Added `did-host-http-tsp` (WebVHHosting + TSPTransport, no DIDComm) and
  `did-host-tsp` (TSPTransport only — no HTTP, no DIDComm), the TSP-only
  siblings of `did-host-http-didcomm` / `did-host-didcomm`.
- Registered both as built-ins (`BUILTIN_NAMES`, `load_embedded`) and exposed
  curated `ProvisionAsk::did_host_http_tsp` / `did_host_tsp` builders plus
  `BUILTIN_DID_HOST_HTTP_TSP_TEMPLATE` / `BUILTIN_DID_HOST_TSP_TEMPLATE`
  constants.
- The `#tsp` `TSPTransport` service points at the shared mediator, matching the
  existing dual-transport templates; a rendered-shape fixture
  (`did-host-tsp.rendered.json`) and per-template tests lock the document shape.
- Purely additive — existing templates, names, and rendered shapes are
  unchanged.

### vta-service (0.10.22) — self DID resolver refresh after runtime DID-log mutations

`vta-service` now keeps its in-process resolver cache for the VTA's own DID in
sync after runtime DID-log mutations, including protocol `services {…}`
operations and did-webvh create/update paths.

Highlights:
- Centralized the post-mutation refresh at the DID-log write site: every runtime
  mutation (did-webvh create/update and all protocol `services {…}` ops, which
  funnel through `update_did_webvh`) reseeds the shared resolver cache once, from
  the freshly-built log, right after it is persisted.
- Fail-safe refresh: on did-log read/parse/decode failure the last-known-good
  cache entry is kept (never evicted). For the VTA's own DID `verificationMethod`
  stays byte-identical across service mutations, so a stale-but-present self-doc
  still carries the exact keys pack/unpack needs — strictly safer than dropping
  the entry, which would strand a serverless / network-unreachable `did:webvh`.
- Kept startup preload + listener resolver reuse behavior aligned with runtime
  refresh semantics.
- Added coverage for refresh success and the fail-safe (preserve-on-error) path.

### vta-sdk (0.18.15) — didcomm-mediator template: make the TSPTransport service opt-in

The `didcomm-mediator` built-in template previously advertised a `#tsp`
`TSPTransport` service **unconditionally**, so every mediator minted from it
(VTA-managed or self-hosted webvh) published a TSP endpoint even on
DIDComm-only deployments — misleading peers into routing TSP the mediator can't
serve.

The `#tsp` service is now an optional slot: a new `SERVICE_TSP` optional var
(default `null`) rendered as the whole-string array element `"{SERVICE_TSP}"`,
pruned when unset (the same mechanism as the P-256 verification-method slots).
Callers that want TSP advertised supply `SERVICE_TSP` as the fully-resolved
service object, e.g.:

```json
{ "id": "{DID}#tsp", "type": "TSPTransport", "serviceEndpoint": "https://mediator.example.com" }
```

The renderer does not recurse into injected values, so the caller resolves the
endpoint URL itself; `{DID}` stays a sentinel for the did-method layer.

**Breaking for the mint path:** a caller that does not supply `SERVICE_TSP` now
gets a document without `#tsp`. Provisioning callers that want TSP advertised
must pass `SERVICE_TSP` in `integration_template_vars` (it flows through the VTA
provisioning render unchanged). Other built-in templates that advertise TSP
(`ai-agent`, `did-host-didcomm`, `did-host-http-didcomm`) are unchanged.

### vta-service — reliability: preload VTA self DID into resolver cache

`vta-service` now preloads its own `did:webvh` DID document into the
`DIDCacheClient` during auth/resolver initialization, using the locally stored
`did.jsonl` log (`WEBVH` keyspace) as the source of truth.

This avoids self-resolution network round-trips (and related startup/runtime
failures) when a VTA cannot reach its own public domain from inside private
network environments.

Behavior is best-effort and non-fatal: if local log state is missing or
malformed, the service logs a warning and falls back to normal resolver
behavior.

### vti-common — security: keyspace values bound to their location (AAD); breaking on-disk format

AES-256-GCM keyspace encryption now authenticates every value against its
`(keyspace, key)` location via associated data (AAD), and prefixes a 4-byte
format magic (`VAE1`). Previously a value's ciphertext was bound to nothing: an
attacker who controls the storage medium — in the Nitro model the **untrusted
parent EC2 instance owns the fjall database** — could cut-and-paste a ciphertext
from one key to another (e.g. resurrect a revoked admin ACL row, or move a value
across keyspaces that share the single storage key) without breaking any crypto.
Binding `(keyspace, key)` into the AAD makes any such relocation fail
authentication. The `sealed_nonces` and `cache` keyspaces, previously stored in
plaintext, are now encrypted alongside the rest.

**Breaking — encrypted stores only.** The new format is intentionally **not**
backward-compatible with the previous AAD-less layout: a legacy read-fallback
would reintroduce the cut-and-paste hole via downgrade. A stale value yields a
clear "incompatible store format — re-bootstrap or restore from backup" error
rather than a confusing decryption failure.

- **Affected:** TEE/Nitro deployments, and any non-TEE VTA configured with an
  explicit `storage_encryption_key`. These must **re-bootstrap a fresh enclave**
  or **restore from a backup** taken with this build (backup export/import is
  format-independent — it re-encrypts on import).
- **Not affected:** deployments with no encryption key configured (the default
  local/dev path) never encrypted and are byte-for-byte unchanged.

This is the integrity half of the TEE storage threat model; anti-rollback of a
whole keyspace (replay/delete of records) is tracked separately.

### vta-sdk 0.11.0 → 0.11.1 — fix: never trust a key's label as its DIDComm kid

Patch release cutting the publish boundary for the fix in #337. The published
`0.11.0` `VtaClient::fetch_did_secrets_bundle` adopted a key's human-readable
`label` as the bundle `key_id` whenever the label merely started with `did:` or
contained `#`. A decorative label such as `"did:key:z6Mk… key-agreement key"`
therefore silently overwrote the authoritative store `key_id`
(`{did}#key-1`). A VTA-managed mediator registers its operating secrets under
that clobbered kid, so a peer encrypting to the `keyAgreement` verification-method
id published in the mediator's DID document matches no local secret — every
inbound unpack (including `/authenticate`) fails with `No local secret matches
any JWE recipient`, and the mediator boots clean but can never read a message.

`select_secret_kid` now uses the authoritative store `key_id` when it is a
verification-method id of the context DID, falls back to the `label` only when
the label is *itself* a strict VM id (correct `{did}#` prefix, no embedded
whitespace), and otherwise excludes the secret (e.g. an admin `did:key` minted
into the context, or a free-text-labelled key) rather than corrupting the
operating-secret set. The `label` is treated as human-readable metadata only.

Patch bump — no public API change. Consumers pin `vta-sdk = "0.11"`, which
`0.11.1` satisfies, so no dependent pin changes are required.

### Version bumps — delegatedAny + step-up + legacy-strip release

Cuts the publish boundary for the accumulated breaking work documented below
(delegatedAny + per-entry `stepUp.require`; the `atm/1.0`, passkey-vms `/1.0`,
DID-template name-alias, and `pnm webvh` strips). Each is breaking — removed
public API or message-type acceptance — so every changed crate takes a **minor**
bump (each lands at exactly +1 minor over its published baseline):

- `vta-sdk` 0.10.0 → **0.11.0** — dropped the deprecated passkey-vms `/1.0` and
  `BUILTIN_{WEBVH,DID_HOSTING}_*` consts + `ProvisionAsk::{webvh,did_hosting}_*`
  builders; DIDComm auth emits canonical `auth/{authenticate,refresh}/0.1`;
  `acl` request/response types gain `step_up_require`.
- `vti-common` 0.9.1 → **0.10.0** — `AclEntry.step_up_require` +
  `delegated_any_approver_covers`; `new_pending_step_up` gained `approver_any`.
- `vta-cli-common` 0.8.2 → **0.9.0** — `cmd_acl_{create,update}` gained a
  `step_up_require` parameter.
- `vta-service` **0.9.0** (publishes over 0.8.1) — delegatedAny + per-entry
  override enforcement; `atm/1.0` and passkey-vms `/1.0` acceptance dropped.
- `vtc-service` 0.8.1 → **0.9.0** — `atm/1.0` (DIDComm + SIOP) acceptance dropped.
- `pnm-cli` / `cnm-cli` 0.8.1 → **0.9.0** — `--step-up-require` flag; the
  `pnm webvh` alias removed.

Internal `major.minor` pins updated across the workspace; the non-published
consumers (`vta-mobile-core`, `didcomm-test`, `vta-enclave`) had their pins
bumped to match. Publish order: `vta-sdk` → `vti-common` → `vta-cli-common`
→ `vta-service` / `vtc-service` → `pnm-cli` / `cnm-cli`.

### Removed: vtc-service legacy `affinidi.com/atm/1.0` auth aliases (legacy strip)

Completes the `atm/1.0` removal across both services (the VTA side landed
earlier). `vtc-service/routes/auth.rs` now accepts only the canonical
`auth/authenticate/0.1` / `auth/refresh/0.1` types — on the DIDComm
authenticate + refresh paths **and** the SIOP `id_token` envelope path. All
VTC clients already emit canonical: the browser plugin's SIOP login client
(`siop/login-client.ts`) and vta-sdk / cnm-cli DIDComm auth.

### Removed: `pnm webvh …` CLI alias (legacy strip)

The hidden `pnm webvh …` command alias (superseded by `pnm did-mgmt {servers,dids} …`)
is removed — invoking it now errors as an unknown command. The internal
`WebvhCommands` dispatch type stays; the new `did-mgmt` surface still converts
into it (`DidMgmtCommands → WebvhCommands → commands::webvh::run`), so the
command implementations are unchanged. Stale `pnm webvh …` hints in operator
output / `--help` updated to the `pnm did-mgmt …` forms.

### Removed: legacy DID-template name aliases `webvh-*` / `did-hosting-*` (legacy strip)

Both prior template-name generations are dropped; only the capability-named
`did-host-*` built-ins remain. This completes the rename noted earlier in this
changelog ("both prior generations resolve for one release").

- **vta-sdk**: `load_embedded` no longer resolves the `webvh-*` /
  `did-hosting-*` aliases (the `LEGACY_ALIASES` table + `resolve_alias` are
  gone) — an old name now returns `BuiltinNotFound`. The deprecated
  `BUILTIN_{WEBVH,DID_HOSTING}_*` constants and the `ProvisionAsk::{webvh,did_hosting}_*`
  builder methods are removed. **Breaking** — minor bump at next release.
- **Operator action:** update any on-disk template config still referencing
  `webvh-*` / `did-hosting-*` to the canonical `did-host-http-didcomm` /
  `did-host-http` / `did-host-didcomm` names.

### Removed: legacy `affinidi.com/atm/1.0` auth aliases (legacy strip)

The VTA's DIDComm auth path no longer accepts the legacy
`affinidi.com/atm/1.0/authenticate` and `…/authenticate/refresh` message
types — only the canonical `auth/authenticate/0.1` / `auth/refresh/0.1`
Trust-Task URIs. In the same change the **vta-sdk** DIDComm auth path
(`session.rs`, `auth_light.rs`) now *emits* the canonical types, so SDK
clients move to canonical automatically.

- **Deployment note (breaking):** a client still on the pre-canonical SDK
  (emitting `atm/1.0`) fails auth against an upgraded VTA with
  `unexpected message type`. Roll clients onto this SDK with/before the VTA.
- **Follow-up:** `vtc-service` still dual-accepts `atm/1.0` (incl. its SIOP
  envelope path); the SDK switch doesn't break it. Its `atm/1.0` removal is a
  separate change (its SIOP path may have other clients).

### Removed: pre-spec `vta/passkey-vms/*/1.0` URIs (legacy strip)

The pre-spec `…/1.0` passkey-vms task URIs — kept dual-accepted alongside the
canonical `…/0.1` during the browser plugin's migration — are removed. The
plugin has been on `…/0.1` since vta-sdk 0.10, so the alias is no longer
needed. A `…/1.0` document now falls through to `UnsupportedType`.

- **vta-sdk**: dropped `TASK_PASSKEY_VMS_{ENROLL_CHALLENGE,ENROLL_SUBMIT,LIST,REVOKE}_1_0`
  constants and their `ALL_URIS` entries. **Breaking** — bump at next release.
- **vta-service**: the dispatcher matches only the `…/0.1` arms; the parity
  harness now asserts the 0.1 URIs are dispatched.

### Built-in DID templates renamed `did-hosting-*` → `did-host-*` (capability-named)

The three did-hosting built-in templates are renamed from service-named to
capability-named, so the name describes the DID-document shape the template
mints rather than a particular binary. The suffix names the endpoints the
DID advertises: `http` = a `WebVHHosting` (HTTP resolution) endpoint,
`didcomm` = a `DIDCommMessaging` endpoint.

- **Renames**: `did-hosting-control` → `did-host-http-didcomm`,
  `did-hosting-daemon` → `did-host-http`, `did-hosting-server` →
  `did-host-didcomm`. The on-disk JSON files, the embedded loader, the
  `BUILTIN_DID_HOST_*_TEMPLATE` constants, and the `ProvisionAsk::did_host_*`
  builders all carry the new names.
- **Back-compat**: both prior generations resolve for one release.
  `load_embedded` silently maps `webvh-*` **and** `did-hosting-*` to the
  `did-host-*` templates; the returned `DidTemplate.name` carries the
  canonical name. The `BUILTIN_DID_HOSTING_*_TEMPLATE` constants and
  `ProvisionAsk::did_hosting_*` builders remain as `#[deprecated]` shims
  (the `webvh_*` shims now delegate to the new names too). Update configs
  to the `did-host-*` names before the aliases are dropped.
- **Method lock unchanged**: these templates stay `did:webvh`-specific (the
  `WebVHHosting` service type and `methods` field are baked into the
  template body, not caller-set) — the rename is naming only.
- `vta-sdk` 0.9.5 → 0.9.6 (additive: new canonical names, old names
  deprecated but functional).

### DIDComm session: receive unsolicited inbound messages

`vta-sdk`'s `DIDCommSession` gains `receive_next(timeout_secs)` — polls the
mediator's live stream and returns the next **unsolicited** inbound message
(unpacked, as JSON), not bound to a sent request's thread id. This is the
foundation for the mobile approver receiving a VTA-pushed
`auth/step-up/approve-request/0.1` over the mediator (the engine FFI for the
iOS proxied step-up wraps it). Reuses the proven `message_pickup().live_stream_next`
path. `vta-sdk` 0.9.4 → 0.9.5 (additive).

### Set a delegated step-up approver at grant *and update* time

The ACL create/grant and update bodies gain an optional `step_up_approver`
— the VID a delegated AAL2 step-up's approve-request is addressed to (the
holder's mobile/browser approver). It's stored on the entry and read by the
step-up gate's delegated mode. Makes delegated step-up operable end-to-end:
previously the gate could route to an approver but there was no way to set
one outside tests. `update` follows the existing set-if-`Some`/leave-if-
`None` semantics (clearing isn't expressible, matching `label`).

- `vta-sdk` `CreateAclBody` + `CreateAclResultBody` gain
  `step_up_approver: Option<String>` (additive, `serde(default)`); the REST
  `POST /acl` request + the `vta/acl/create/1.0` trust task accept it and
  the result reflects it. `UpdateAclBody` + the REST `PATCH /acl/{did}` +
  the `vta/acl/update/1.0` trust task likewise accept it. `vta-sdk`
  0.9.2 → 0.9.4.
- Still pending (optional): the wire `auth/step-up/policy/0.1` handler for
  *remote* policy management — the `vta step-up` CLI already covers local
  management.

### Key rotation goes through `acl/swap-key`

The SDK's first-auth key rotation (`session::rotate_key`, REST path) now
uses the atomic `POST /acl/swap` (`acl/swap-key`) instead of the
create-then-delete sequence on `POST /acl`. The VTA moves the temp DID's
ACL entry (same role + contexts) onto the freshly-minted DID and removes
the temp in one transaction — no transient over-privilege window, and the
rotation travels the structurally non-escalating swap-key path, so an
*enabled* step-up policy carrying the rotation carve-out still admits it
at AAL1.

- `vta-sdk` gains `protocols::acl_management::swap::build_swap_presentation`
  (client feature) — builds the Ed25519 VP-JWT the swap verifier accepts;
  round-trip-tested against `AclSwapPresentation::verify`.
- `vta-sdk` 0.9.1 → 0.9.2 (additive public API). The DIDComm rotation path
  still uses create-then-delete; migrating it onto swap-key is a follow-up.

### Fix: server-managed provisioning drops the DID path (`e.p.did.path-invalid`)

When a consumer (e.g. the did-hosting-daemon) provisions an integration
against a VTA that has **exactly one** registered webvh server, the SDK
auto-selects that server and runs the server-managed path. In that mode
the hosting server reads `WEBVH_PATH` and ignores the path folded into
the `URL` template var — but `run_provision` passed `webvh_path = None`,
so `WEBVH_PATH` was never injected and the hosting server received an
empty path, rejecting with `e.p.did.path-invalid: path must not be
empty` (HTTP 500 at the gateway).

Fixed at two layers (defense-in-depth):

- **SDK (vta-sdk, the fix):** `run_provision`'s `PreflightDone` handler
  now derives the path from the ask's `URL` var (via the new
  `runner::webvh_path_from_url`) when it auto-selects a server, and
  passes it as `webvh_path` to `run_provision_flight`. The var-injection
  is factored into `runner_didcomm::inject_webvh_vars` and unit-tested.
  Serverless mode (no server selected) is unchanged — it reads the path
  straight from `URL`.
- **VTA service (vta-service, safety net):** `provision_integration`
  falls back to the path parsed from the `URL` var
  (`webvh::webvh_path_from_url_var`) when a `WEBVH_SERVER` is set but no
  explicit `WEBVH_PATH` was provided. Read-only; never overrides an
  explicit `WEBVH_PATH`.

Derivation is conservative on both sides: bare origins, empty paths and
`.well-known` (the webvh log marker, never a DID path) yield no path,
letting the server run its own allocation; `…/webvh` → `webvh`,
`…/dids/daemon` → `dids/daemon`, query/fragment stripped.

### Dependencies: DIDComm 0.15 across the affinidi-messaging stack

Moved the whole workspace to `affinidi-messaging-didcomm 0.15`, now that
the affinidi side published the releases that close the previous split:

- `affinidi-tdk` 0.7.2 → **0.7.3** (`didcomm ^0.15`) — the production
  unblock. tdk re-exports didcomm and our `DIDCommSession` passes
  `Message` values into its transport, so tdk and our direct didcomm dep
  must share one version. While tdk capped at `^0.14`, 0.15 was
  unreachable (two incompatible `Message` types).
- `affinidi-messaging-mediator` 0.15.11 → **0.15.12** (`^0.15`) +
  `affinidi-messaging-test-mediator` 0.2.3 → **0.2.4** (the embedded test
  fixture).
- `affinidi-messaging-sdk` 0.18.4 → **0.18.6** and
  `affinidi-messaging-didcomm-service` 0.3.2 → **0.3.3** (both already on
  `^0.15`, now selected).
- `affinidi-crypto` 0.1.10, `affinidi-status-list` 0.1.3 (latest).

Code migration for the 0.15 API:

- didcomm 0.15 removed its own `crypto` module; `Curve` /
  `PrivateKeyAgreement` / `PublicKeyAgreement` now live in
  `affinidi_crypto::jose::key_agreement`. Updated the imports in
  `vta-sdk` (`didcomm_light`) and `vta-mobile-core` (`didcomm`), and added
  `affinidi-crypto` to vta-sdk's `client` feature (it now names that type
  in its own right). `anoncrypt`'s shape is otherwise unchanged; the
  `pack_anoncrypt` JWE round-trip test still passes.
- `affinidi-messaging-sdk` 0.18.5 added
  `WebSocketResponses::Disconnected`; handled it in `didcomm-test`'s
  listen loop (logs and stops — the socket is gone).

Resolution note: the dev-only test tree still pulls a second
`didcomm 0.14.1` transitively through the **published** `vta-sdk 0.9.0`
that `affinidi-messaging-mediator` depends on. The mediator pins
`vta-sdk = "^0.9"`, so this self-heals the moment `vta-sdk 0.9.1` (this
release, on didcomm 0.15) is published — the resolver then selects it for
the mediator too and the duplicate disappears. `cargo deny` treats the
transient duplicate as a warning, consistent with the other accepted
build-graph duplicates.

### Version bumps

This cycle's bumps for the provision-path fix + the didcomm 0.15 move
(the publish boundary already advanced to `vta-sdk` 0.9.0 /
`vta-service` 0.8.0 in the #183 release bump):

- `vta-sdk` 0.9.0 → 0.9.1 — provision bugfix (crate-internal helpers, no
  API change) **plus** the `affinidi-messaging-didcomm` 0.14 → 0.15 dep
  bump. Kept in the `0.9.x` line on purpose: `affinidi-messaging-mediator`
  0.15.12 pins `vta-sdk = "^0.9"` *and* `didcomm = "^0.15"` at the same
  time, so the affinidi side explicitly expects a `0.9.x` of vta-sdk that
  carries didcomm 0.15. A `0.10.0` bump would fall outside their `^0.9`
  pin and lock them on the old didcomm-0.14 `vta-sdk 0.9.0` — defeating
  the unification. (Strict semver would call a public-dep major bump
  breaking; here it's deliberate ecosystem coordination, not an
  accident.) External consumers pinned at `"0.9"` pick it up with no pin
  change.
- `vta-service` 0.8.0 → 0.8.1 — patch: carries the Option B safety net +
  the didcomm 0.15 pin; bumped so it can be republished. `vta-enclave`'s
  `"0.8"` pin is unaffected.

Historical (0.7 → 0.8 cycle, retained for context):

Only the two crates external repos (did-hosting-common,
webvh-witness, rp-sdk, …) consume are bumped:

- `vta-sdk` 0.7.0 → 0.8.0
- `vti-common` 0.7.0 → 0.8.0

Minor bump (not patch) is required by the additive public API + the
const-value change on `BUILTIN_WEBVH_*_TEMPLATE` (now resolves to
`"did-hosting-control"` etc.) + the manual `Debug` redaction on
secret-bearing wire types + the REST `import_key` hardening. Each
of those is detailed in its own section below. Consumer repos pull
the changes by updating their pin from `"0.7"` to `"0.8"`.

The other workspace crates (`vta-service`, `vta-enclave`,
`vta-cli-common`, `pnm-cli`, `cnm-cli`, `vtc-service`,
`didcomm-test`) stay at their current versions — they're
binaries / CLI tools, not libraries consumed externally, so their
Cargo.toml version is cosmetic for the install-the-binary use case.
Their internal `vta-sdk` / `vti-common` dep pinnings are updated
`"0.7"` → `"0.8"` to point at the bumped crates.

### Built-in DID templates renamed `webvh-*` → `did-hosting-*`

Aligns the SDK's built-in template names with the broader OpenVTC
service-role terminology already in `auth-architecture.md` and
`trust-task-uri-registry.md`.

- **Renames**: `webvh-control` → `did-hosting-control`,
  `webvh-daemon` → `did-hosting-daemon`,
  `webvh-server` → `did-hosting-server`. The on-disk JSON files,
  `name` + `kind` fields, builtin-loader constants, and curated
  `ProvisionAsk` builders (`did_hosting_control` / `did_hosting_daemon`
  / `did_hosting_server`) all flip to the new names.
- **Back-compat alias for one release.**
  `load_embedded("webvh-control")` still resolves to
  `did-hosting-control` (same for daemon and server); the returned
  `DidTemplate.name` carries the canonical name. The
  `BUILTIN_WEBVH_*_TEMPLATE` constants and `ProvisionAsk::webvh_*`
  builders are marked `#[deprecated(since = "0.8.0")]` and forward
  to the new names. Operator configs should switch to
  `did-hosting-*` before the alias is dropped in the next minor.
- **Doc cross-refs.** Tracker mentions of `webvh-witness` (a service
  role in the webvh-service repo) follow the same rename to
  `did-hosting-witness`. Protocol URIs and module names that refer
  to the `did:webvh` DID-method itself are unchanged.

### CLI restructure: `pnm webvh` / `vta webvh` → `did-mgmt {servers,dids}`

The operator CLI surface restructured to match the SDK umbrella
module `vta_sdk::protocols::did_management`. Two intermediate verbs
split the noun:

- `pnm webvh add-server` → `pnm did-mgmt servers add`
- `pnm webvh list-servers` → `pnm did-mgmt servers list`
- `pnm webvh update-server <id>` → `pnm did-mgmt servers update <id>`
- `pnm webvh remove-server <id>` → `pnm did-mgmt servers remove <id>`
- `pnm webvh create-did` → `pnm did-mgmt dids create`
- `pnm webvh edit-did` → `pnm did-mgmt dids edit`
- `pnm webvh register-did` → `pnm did-mgmt dids register`
- `pnm webvh list-dids` → `pnm did-mgmt dids list`
- `pnm webvh get-did` → `pnm did-mgmt dids get`
- `pnm webvh delete-did` → `pnm did-mgmt dids delete`
- `pnm webvh did-log` → `pnm did-mgmt dids get-log`

Same rename applies to the offline `vta` binary (no `get-did`
variant). The `webvh` cargo feature is **not** renamed — it gates
`didwebvh-rs`, which refers to the DID *method*, not the operator
UX.

**Back-compat alias for one release.** The old `pnm webvh …` /
`vta webvh …` paths still dispatch through the same handlers
(`Webvh` variant is `#[command(hide = true)]` — absent from `--help`
but invocable). Each call prints a yellow stderr deprecation note
pointing at the new path; alias removed in the next minor.

Operator-facing docs (`docs/02-vta/{cold-start,
runtime-service-management,provision-integration,did-templates,
did-webvh-update}.md`, `docs/03-vtc/getting-started.md`,
`docs/04-reference/cli-style.md`, `CLAUDE.md`) updated to the new
command shapes. Prose mentions of "WebVH server" are now
"DID-hosting server" where they refer to the hosting role;
references to `did:webvh` the DID method itself are intentionally
unchanged.

Rationale: `did-management` is the right umbrella because half the
surface isn't hosting at all (DID lifecycle: create/edit/delete/
get/get-log/register) and the SDK module of the same name already
groups both halves. `did-hosting` is reserved by
`trust-task-uri-registry.md` for the host-side trust-task namespace
(`spec/did-hosting/*`), a distinct concern.

### Adopt `did-management/0.1` Trust-Task surface + per-DID domain selection

Pairs with [`affinidi/affinidi-webvh-service` PR #15](https://github.com/affinidi/affinidi-webvh-service/pull/15)
and the draft spec category in
[`trustoverip/dtgwg-trust-tasks-tf` PR #40](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/40).
The VTA's webvh client now speaks the v0.1 `did-management/...`
surface and lets operators direct DID provisioning at a specific
hosting domain when the remote backplane serves multiple tenants.

#### Outbound Trust-Task URIs migrated to v0.1

- **`vta-service/src/webvh_didcomm.rs`** stops emitting the legacy
  `https://affinidi.com/webvh/1.0/did/...` constants. Every outbound
  DIDComm message now carries a v0.1 `did-management/...` type URI:
  `did/check-name/0.1` (with `reserve: true`) replaces
  `did/request/1.0` for slot reservations; `did/register/0.1`,
  `did/publish/0.1`, and `did/delete/0.1` replace their 1.0
  siblings. Response sides use the framework's `#response`
  fragment rather than a paired URI.
- **`vta-service/src/webvh_client.rs`** (REST) sends the same v0.1
  payload shape on `POST /api/dids` and `POST /api/dids/register`:
  `method` discriminator + `didData` field (replacing the legacy
  `did_log`). The remote `did-hosting-control` accepts both
  shapes through its alias map during the v0.7 deprecation window,
  but moving outbound traffic to the canonical surface keeps the
  VTA off the runtime deprecation warn lines those hosts now
  emit (`legacy_task=... successor=... sunset=v0.8.0`).
- **`POST /api/dids/check`** payload gains a `reserve: bool` flag.
  When set + path available, the host atomically commits a
  reservation under the caller and returns `{ available, reserved,
  mnemonic, didUrl }` in one round-trip — absorbs the legacy
  request_uri call for the common "check, then claim" flow.

#### Per-DID domain selection threaded through the stack

A VTA managing slots across multiple tenant domains on one shared
`did-hosting-control` backplane can now name the target domain on
every relevant call. Every layer carries the field optionally;
omitted means "let the server resolve via the caller's ACL
default → its system default."

- **Data model**:
  `CreateDidWebvhBody` / `CreateDidWebvhRequest` /
  `CreateDidWebvhParams` gain `domain: Option<String>`.
  `RegisterDidWithServerBody` / `RegisterDidWithServerParams` ditto.
  All five wire shapes serialise with `skip_serializing_if =
  "Option::is_none"` so v0.7 callers and hosts that don't yet
  understand the field are unaffected.
- **Outbound calls**:
  `WebvhClient::{request_uri, register_did_atomic, publish_did,
  delete_did, check_path}` and the parallel `WebvhDIDCommClient`
  all take `Option<&str>` domain. The transport enum and the
  `_authenticated` wrappers thread it through.
- **End-to-end**: explicit `--domain` (CLI) → `CreateDidWebvhRequest`
  body → vta-service handler → `WebvhTransport` → DIDComm/REST
  payload → did-hosting-control resolves it. An unknown domain on
  the remote comes back as the spec-level error
  `did-management:unknown_domain` (per the category conventions in
  the trust-tasks PR), which the CLI surfaces unchanged so
  operators can correlate.

#### Operator CLI gains domain UX

- **`pnm did-mgmt dids create --domain <name>`** and
  **`pnm did-mgmt dids register --domain <name>`** are new optional
  flags. When omitted the server resolves through the standard
  chain.
- **Interactive prompt** when stdin is a TTY, the operator targeted
  a specific hosting server, and `--domain` was omitted: the CLI
  fetches the server's available domains (caller-scoped view) and
  asks the operator to pick — single-domain servers, non-TTY
  invocations (CI / scripts), and servers that fail the
  domain-list call all skip the prompt and let the server resolve.
- **`pnm did-mgmt dids list-domains --server <id>`** is a new
  top-level subcommand. Walks the server's `/api/me/domains`
  (proxied through the VTA, authenticated with the VTA's
  credentials) and prints the caller-scoped subset, flagging the
  system default. Use this to discover legitimate `--domain`
  values before the first call.

#### Supporting plumbing

- New SDK protocol message id
  `https://firstperson.network/protocols/did-management/1.0/list-webvh-server-domains`
  + result variant. `VtaClient::list_webvh_server_domains()`
  exposes it.
- New `vta-service` REST route `GET /webvh/servers/:id/domains`
  authenticates the VTA to the named hosting server through the
  existing `WebvhTransport` / `auth_cache` machinery and forwards
  the response. DIDComm-only servers return an empty list (the
  v0.1 `me/domains` task is REST-only on the hosting-control
  side); the CLI then falls back to the server-side resolution
  chain rather than blocking the operator.
- All call sites updated: `operations/did_webvh/mod.rs`,
  `update/orchestrator.rs`, `provision_integration/mod.rs`,
  `setup/{from_toml,interactive}.rs`, `webvh_cli.rs`,
  `messaging/handlers.rs`, `routes/{did_webvh,trust_tasks/webvh}.rs`,
  and the SDK tests under `vta-sdk/tests/client_rest.rs`.

Out of scope for this change — to land separately:

- The DID-method extension shape
  (`ext.vnd.trusttasks.did-method-webvh.*` carrying SCID, witness
  URLs, update-key multibase) is sketched in the trust-tasks PR
  but the VTA's outbound payloads don't emit it yet. The
  framework's ignore-unknown rule keeps current hosts accepting
  our absence and our consumers accepting hosts that include
  theirs.

### Security review follow-ups (external patches 02, 03, 04, 05, 07, 08, 09, 10)

Eight findings from the April 2026 external security review.
Patches 01 + 06 (DIDComm sender-DID binding on `/auth/refresh`) were
already closed by the prior auth-handler consolidation. Each fix
below ships with a focused regression test. Tracker file at
`~/Downloads/patches/verifiable-trust-infrastructure/REVIEW_2026-04_TRACKER.md`
maps each patch to the commit that addressed it.

- **#4 (Critical) — BIP-32 `allocate_path` race.**
  `vta-service/src/keys/paths.rs`: the read-increment-write of the
  per-base path counter was a TOCTOU race. Two concurrent
  `allocate_path` calls could be handed identical derivation paths,
  producing two `KeyRecord`s that share a private key. Serialised
  with a process-wide `tokio::sync::Mutex`. Regression test launches
  64 concurrent allocations against one base and asserts all paths
  are distinct.
- **#10 (High) — `delete_did_webvh` cross-context.**
  `vta-service/src/operations/did_webvh/mod.rs`: only checked
  `require_admin`, never `require_context(record.context_id)`, so a
  context-scoped admin could trigger remote deletion (via the stored
  mnemonic) and local key cleanup of did:webvh records owned by
  other contexts on the same VTA. Now mirrors the scoping that
  create / get / get_log / list already enforce.
- **#7 (High) — `AuthConfig` / `SecretsConfig` Debug leak.**
  `vti-common/src/config.rs`: replace `#[derive(Debug)]` with manual
  impls that print `<redacted>` for `jwt_signing_key` (Ed25519
  access-token signer) and `inline_secret` (master seed / HMAC).
  Serialize is intact — config files still round-trip. Enclave-mode
  logs forward over vsock to the host, where a stray `{:?}` would
  otherwise be a near-total compromise.
- **#8 (High) — vta-sdk protocol message Debug leaks.**
  Manual `Debug` impls across `vta-sdk/src/protocols/{auth,
  backup_management/types, did_management/create, key_management/
  {create,secret}, seed_management/rotate}.rs`. Mnemonics, seeds,
  private keys, access / refresh tokens, backup passwords no longer
  appear in `{:?}` output. Wire formats and sealed-transfer payloads
  unchanged. Note the original audit named `AuthenticateData` — that
  type was replaced by `TokenBundle` during the auth consolidation;
  the fix applies to the current shape.
- **#9 (High) — REST `POST /keys/import` no longer accepts plaintext
  `private_key_multibase`.** Posting raw key material over a
  session-bearer-authenticated REST call relies entirely on TLS for
  confidentiality — on Nitro Enclave the TLS terminator is on the
  host, which means the host network stack reads plaintext private
  keys out of memory. The handler now uses
  `#[serde(deny_unknown_fields)]` so any client posting the legacy
  field gets a specific `unknown field private_key_multibase` 422
  pointing them at the migration path. Use one of:
  - `private_key_sealed` — armored sealed-transfer bundle. Fetch
    the ephemeral wrapping pubkey via
    `GET /keys/import/wrapping-key`, then seal locally and POST.
  - `private_key_jwe` — legacy ECDH-ES + A256GCM compact JWE,
    wrapped against the same ephemeral key.

  The DIDComm transport (no server-side handler yet) keeps the
  multibase field on its SDK shape because authcrypt already
  provides end-to-end confidentiality. **Operator-facing side
  effect**: the `pnm/cnm import-key` CLI's fall-back-to-multibase
  branch (active when the wrapping-key fetch failed) is removed —
  the CLI now surfaces the wrapping-key-fetch error directly with a
  clear message ("the VTA must support sealed-transfer key import —
  `vta-sdk ≥ 0.8`"). The mediator-setup and did-hosting-setup flows
  are **not** affected: they use `provision-integration` (the VTA
  mints keys via BIP-32 from the master seed and returns a sealed
  bundle to the consumer), never `POST /keys/import`.
- **#3 (Medium) — `delete_acl` role floor.**
  `vta-service/src/operations/acl.rs`: an Initiator whose
  `allowed_contexts` overlapped an Admin entry could delete that
  Admin. `update_acl` was already protected by an admin-only floor;
  the delete path now also calls `validate_role_assignment(auth,
  &entry.role)` after the visibility check.
- **#5 (Medium) — `get_key` / `list_keys` Reader-role floor.**
  `vta-service/src/operations/keys.rs`: `Monitor`-role principals
  (intended for metrics/health only) could read key records when
  context scope happened to overlap. Both operations now call
  `auth.require_read()` at the top so the floor fires before any
  per-record filter and covers REST + DIDComm equally.
- **#2 (Medium DoS) — backup nonce/salt length validation.**
  `vta-service/src/operations/backup/mod.rs`: `Nonce::from_slice`
  panics on wrong-length input, so a crafted backup envelope with a
  non-12-byte nonce (or non-32-byte salt) would take the import
  handler down. The KDF-parameter bounds half of the patch was
  already in; the length checks complete the fix.

### Auth-architecture consolidation (S1+S2+S3)

A cross-repo consolidation of the `/auth/*` surface. Five
near-duplicate implementations (VTA REST + DIDComm, VTC REST +
DIDComm, did-hosting control SIOPv2, did-hosting server
DIDComm, webvh-witness DIDComm) collapse into thin route
dispatchers around a canonical handler in `vti_common::auth::
handlers`. Closes the structural follow-ups from the May 2026
cross-system security review.

#### Added

- **Canonical `Session` superset** — `vti_common::auth::Session`
  is now the single source of truth for the wallet/holder
  session row across both repos. Adds `token_id` (per-token
  rotation pin) and `session_pubkey_b58btc` (ephemeral
  Ed25519 multikey for Data-Integrity-proof binding) on top
  of the existing `tee_attested` + `amr` + `acr`. did-hosting's
  `Session` is deleted; the type re-exports from vti-common via
  a cross-repo dep.
- **`vti_common::auth::backend::AuthBackend` trait + canonical
  `/auth/*` handlers**. Five services (VTA, VTC,
  did-hosting-control, did-hosting-server, webvh-witness) now
  share challenge / authenticate / refresh flow logic. The
  trait abstracts over associated `Store`, `Error`, `Role`
  types so each backend keeps its own storage layer + AppError;
  default-method policy hooks (`validate_did`,
  `attest_challenge`, `max_pending_challenges_per_did`,
  `audit`, `didcomm_freshness_window`) carry safe defaults.
  The canonical handlers enforce the load-bearing invariants
  — signer-DID-binds-to-session-DID, constant-time challenge
  compare, atomic refresh-token claim, AAL preservation across
  rotation, ACL re-look-up at every step — once, not five
  times. ~500 lines of duplicated flow logic removed across
  the callers.
- **`KeyspaceHandle::take_raw`** — atomic GET+DELETE on the
  Local (fjall) variant via a single `blocking_with_timeout`
  closure. Vsock backend falls back to `get_raw` + `remove`
  with a per-call `warn!()` and a doc note flagging the
  cross-replica TOCTOU window; single-replica TEE deployments
  are unaffected. Backs the canonical
  `take_session_id_by_refresh` helper.
- **`SessionStore` adapters** — `KeyspaceSessionStore` (vti-
  common's KeyspaceHandle) and `DidHostingSessionStore`
  (did-hosting's). VTA + VTC use the first directly; did-hosting
  implements its own to honour its separate storage + error
  primitives.
- **`@openvtc/rp-sdk` (`rp-sdk-js`, new repo)** — server-side
  TypeScript SDK for Relying Parties consuming SIOPv2
  `id_token`s from the OpenVTC browser plugin. `verifyIdToken`
  enforces the OIDC Core §3.1.3.7 + SIOPv2 §6 checks (alg
  pinning, self-issued constraint, audience + nonce match, iat
  / exp window, DID-resolved JWS verification). Closes the
  gap where the browser-plugin demo accepted POSTs without
  verifying the signature.

#### H/M/L security review follow-ups

Numbering matches the May 2026 cross-system auth review (`H`igh
/ `M`edium / `L`ow).

- **L1** — JWT `iat` claim. Standard OIDC/RFC 7519 §4.1.6.
  `#[serde(default)]` so legacy tokens deserialise as `iat=0`.
- **L4** — `/auth/` + `/auth/refresh` handlers accept both the
  legacy `affinidi.com/atm/1.0/...` / `affinidi.com/webvh/1.0/...`
  URIs and the canonical
  `trusttasks.org/spec/auth/{authenticate,refresh}/0.1`. Drop
  the legacy alias one minor release after every client
  upgrades.
- **L2** — `server.trust_xff: bool` config flag (default `false`)
  on both VTA and VTC. Selects `PeerIpKeyExtractor` (safe for
  direct-binding deployments; not bypassable by header spoofing)
  vs. `SmartIpKeyExtractor` (honours `X-Forwarded-For` /
  `Forwarded`; only safe behind a trust-boundary reverse proxy
  that overwrites these headers). Closes a silent rate-limit
  bypass.
- **M3** — DIDComm `created_time` freshness window. VTA + VTC
  authenticate handlers now thread `msg.created_time` into the
  canonical handler instead of `None`; 60s default window
  against `session.created_at` bounds replay risk.
- **M1** — `vti_common::auth::StepUpAuth` extractor. Axum
  extractor that requires the JWT's `acr == "aal2"`; rejection
  returns 403 with body
  `{ "error": "step_up_required", "requiredAcr": "aal2" }` —
  a distinct signal the wallet uses to trigger a step-up
  ceremony. Mirrors did-hosting-common's existing impl.
- **M2** — `AuthBackend::access_token_ttl_for_aal2()`. Default
  1/3 of base TTL with a 60s floor; canonical handlers pick
  TTL by `acr`. A leaked aal2 token now has a ~5-minute
  window (default) instead of 15.
- **M6** — `AclEntry.version: u32` + `update_acl_entry_versioned`
  helper. Optimistic-concurrency-checked write that refuses to
  overwrite if the stored row has moved ahead; raises
  `AppError::Conflict` on stale write. Closes "two admins
  silently lose one update" on concurrent ACL edits.
- **H2** — RP-side `id_token` verification — see `@openvtc/rp-sdk`
  under Added.
- **H3 + H4 + H5** — closed as side-effects of the canonical-
  handler migration:
  - per-DID challenge rate limit now uniform across all five
    services (was missing on VTA/VTC, O(N) prefix-scan on
    did-hosting-server/witness, O(1) tracker on
    did-hosting-control);
  - `allowed_did_methods` rejection error collapsed to a
    generic `Forbidden` so the operator-configured allowlist
    isn't echoed to callers.
- **M4** — `chrome.runtime.onMessage` sender check in the
  browser plugin's background + offscreen listeners. Rejects
  messages whose `sender.id !== chrome.runtime.id`. MV3
  isolation enforces this at the manifest layer already;
  belt-to-the-braces defence-in-depth.
- **M5** — origin → RP-DID pinning in the browser plugin. New
  `origin-pin.ts` module persists `chrome.storage.local`
  mappings; the consent prompt renders a loud red warning
  ("⚠ Relying-party identity changed") when a site asks for
  a different `rpDid` than the previously-approved one. Both
  SIOP and DIDComm login flows wired.
- **H1 (foundation)** — pluggable `SecretWrap` trait in
  `@pnm/core` + a working `WebAuthnPrfSecretWrap` impl in the
  extension. The wallet's Ed25519 root secret can be persisted
  through an encryption wrap (WebAuthn PRF → HKDF →
  non-extractable AES-256-GCM key) rather than plaintext
  base64url in IndexedDB. **Not yet auto-enabled**; the
  operator-visible UX (settings toggle, first-enroll
  ceremony, lock/unlock, migration of existing plaintext
  wallets) is the second half.

#### Behaviour / wire changes worth flagging

- **VTC `/auth/refresh` response shape** is now the canonical
  `{ session, tokens }` body (was the legacy `{ sessionId,
  data: { accessToken, accessExpiresAt } }`). Matches VTA and
  the cross-cutting `spec/auth/refresh/0.1` schema; no
  in-tree callers consumed the legacy shape. External clients
  of VTC's `/auth/refresh` need to migrate.
- The 2^-256 nonce-collision check on VTA's `/auth/challenge`
  is dropped during the canonical-handler migration — defence
  in depth that wasn't anchored by anything else, and the
  canonical handler doesn't carry it for the four other
  backends. Random 32 bytes is sufficient.

#### Deferred

- **H1 (operator-visible flow)** — settings toggle, first-
  enroll UX, migration UX for existing plaintext wallets,
  lock/unlock UX from the popup. The encryption infrastructure
  is in (`SecretWrap` trait + `WebAuthnPrfSecretWrap` impl);
  not yet auto-enabled in `holder.ts` so existing users aren't
  locked out.
- **L5** — workspace lint for trust-task `recipient`
  enforcement. Tooling-heavy; needs design.

### Added

- **Runtime service management** — operators can now enable, update,
  disable, or roll back the VTA's advertised REST and DIDComm
  service entries on a running VTA without rebuilding. Twelve
  commands across two transport kinds (`pnm services {rest,didcomm}
  {enable,update,disable,rollback}` plus `pnm services list`,
  `pnm services didcomm drain {list,cancel}`, `pnm services
  report`). Each mutation publishes a new WebVH LogEntry;
  `verificationMethod` is byte-identical before and after. At least
  one transport must remain advertised at all times — disabling
  the last one is refused with `LastServiceRefused`, no `--force`.
  Rollback is fail-forward (appends a new LogEntry that re-applies
  the prior config; never rewinds the chain). Default drain TTL
  raised from 1h to 24h, hard cap 30d, 1h floor over DIDComm
  transport. Reachable from both `pnm` (over REST or DIDComm) and
  the offline `vta services …` binary on a stopped VTA.
  See `docs/02-vta/runtime-service-management.md` for the
  operator guide and
  `docs/05-design-notes/runtime-service-management.md` for the
  spec.
- **`pnm bootstrap provision-integration --create-context`** —
  PNM matches the offline `vta` flag. Creates the target context
  inline if it doesn't exist, instead of failing the whole call
  with "context not registered." **Requires super-admin** —
  context-admin callers get `Forbidden` against a missing
  context (the super-admin gate sits inside
  `operations::contexts::create_context`, the one place context
  creation is authorised). Idempotent when the context already
  exists. The response carries a new `context_created: bool`
  field so operators see whether their flag actually did
  something — the CLI prints `Context: <id> (created inline …)`
  on first run and `Context: <id> (already existed; --create-context
  was a no-op)` on idempotent retries. Same wire field is honoured
  on REST and DIDComm; old senders continue to work because
  `create_context` defaults to `false` on the wire.
- **`pnm bootstrap provision-integration` works over DIDComm** —
  the SDK's `VtaClient::provision_integration` now dispatches to
  the existing `provision-integration/1.0` DIDComm handler when
  the client is in DIDComm transport mode, instead of returning
  `UnsupportedTransport`. Whichever transport the client opened
  carries the VP and the sealed bundle.

  Both REST and DIDComm support the **operator-as-relayer** flow
  needed for air-gap onboarding: a third-party integration signs
  a BootstrapRequest with its own ephemeral did:key, transfers
  the request to the operator's host, the operator's PNM relays
  it to the VTA, and the operator carries the encrypted bundle
  back. The auth model is layered the same on both transports —
  outer transport authenticates the relayer (bearer token or
  authcrypt sender, ACL-gated), inner VP authenticates the
  holder (the bundle is HPKE-sealed to the holder's X25519). The
  relayer can't decrypt the bundle and can't forge the VP
  signature, so relaying is safe.

  Adds a workspace-specific `e.p.msg.forbidden` problem-report
  code so genuine permission failures don't collapse into the
  SDK's `Auth` variant — fixes a misleading "Token may be
  expired" CLI hint that fired for `Forbidden` errors over
  DIDComm. SDK clients that predate this code fall back to
  `DidcommRemote { code, comment }` cleanly.
- **Promote a serverless WebVH DID to a server-managed one** —
  `pnm webvh register-did --did <did> --server <server-id>` (and
  the offline `vta webvh register-did …`) push an existing local
  `did.jsonl` to a registered host and flip `server_id` so future
  `pnm services …` mutations auto-publish there. Use this when a
  VTA was set up serverless and a webvh host became available
  later — the DID identifier is unchanged so existing integrations
  keep working. Refused if the DID is already server-managed
  (re-pointing a hosted DID at a different host is a separate
  operation, out of scope).

### Breaking

- **`pnm mediator …` subcommand surface retired** in favour of
  the unified `pnm services …` tree. Calling `pnm mediator
  migrate|rollback|drain|report` prints a copy-pasteable redirect
  to the equivalent `pnm services …` command and exits 2.
  Migration map: `pnm mediator migrate --to X` → `pnm services
  didcomm update --mediator-did X`; `pnm mediator rollback` →
  `pnm services didcomm rollback`; `pnm mediator drain cancel
  --mediator-did X` → `pnm services didcomm drain cancel
  --mediator-did X`; `pnm mediator report` → `pnm services
  report`. Likewise `pnm services {enable,disable} didcomm` →
  `pnm services didcomm {enable,disable}`. The `--to` muscle
  memory is preserved as a clap `visible_alias` on `update`.
- **DIDComm message-type rename for symmetry**:
  `services-management/1.0/disable` → `services-management/1.0/
  didcomm-disable`. Other DIDComm-side ops already followed the
  `didcomm-{verb}` shape; this aligns the laggard.
- **Default drain TTL raised from 1h to 24h** when the operator
  omits `--drain-ttl`. The 1h floor over DIDComm transport is
  unchanged. Operators who relied on the prior default need to
  pass `--drain-ttl 3600` explicitly.

## vta-service 0.5.1 — 2026-05-05

### Fixed

- `vta bootstrap provision-integration` now produces an actionable error
  when the target context is missing and `--create-context` wasn't
  passed. The error names both the flag the operator can pass to
  provision the context inline and the `vta contexts create --id <id>`
  command they can run first. Previously the failure surfaced as a
  generic precondition error from inside the library fn, with no hint
  at the missing flag — operators pasting wizard-generated commands
  against fresh VTAs had to grep the docs to recover. CLI-only behavior
  change; library API and wire formats unchanged.

## 0.5.0 — 2026-05-04

The `sealed-bootstrap` release: every secret-bearing transfer between
VTA, integrations, and CLIs now moves as an HPKE-sealed bundle, DID
minting is template-driven, and the DIDComm protocol surface can be
enabled, disabled, or migrated on a running VTA without rebuilding it.

### Added

- **DIDComm protocol management** — enable, disable, and migrate
  the DIDComm protocol surface on a running VTA without rebuilding
  it, re-issuing admin credentials, or rotating the VTA's
  verification keys. Six new operator commands:
  `pnm services {enable,disable} didcomm`, `pnm mediator {migrate,
  rollback,drain cancel,report}`. Each protocol change publishes a
  new WebVH LogEntry; `verificationMethod` is byte-identical
  before and after. Mediator changes go through a drain set
  (persisted to fjall, restart-resilient, 30-day TTL cap) so
  in-flight messages from senders with stale DID-doc caches keep
  landing while the new mediator picks up traffic. Telemetry sink
  is pluggable behind a trait — default impl is a 10k-event ring
  buffer; the `mediator report` command queries it for
  per-mediator inbound counts and per-sender last-seen mediator.

  The full pre-promotion handshake fires end-to-end:
  `migrate`/`rollback` use a live `DIDCommServiceProver` against
  the running service; first-enable spins up a transient
  `DIDCommService` just for the round-trip (lifecycle managed
  by `messaging::transient_handshake`). Drain TTLs fire
  end-to-end via the per-mediator `JoinSet` sweeper + boot-time
  replay. All five admin operations are available over both REST
  and DIDComm transport (`enable` is REST-only by nature).

  See `docs/02-vta/didcomm-protocol-management.md` and
  `docs/05-design-notes/didcomm-protocol-management.md`. New
  modules: `vti_common::telemetry`,
  `vta_service::messaging::{registry, drain_store, drain_sweeper,
  handshake, live_prover, transient_handshake, handlers_protocol}`,
  `vta_service::operations::protocol::*`, `vta_sdk::protocol`,
  `vta_sdk::protocols::protocol_management`,
  `vta_cli_common::commands::{services, mediator}`.

### Breaking

- **WebVH built-in templates renamed by deployment role.**
  `webvh-hosting-server` → `webvh-daemon`, `webvh-service` → `webvh-server`,
  and a new `webvh-control` joins them. Three fixed shapes, one per role:
  `webvh-control` exposes both `WebVHHosting` and `DIDCommMessaging`
  (hosting + DIDComm); `webvh-daemon` exposes `WebVHHosting` only (no
  DIDComm); `webvh-server` exposes `DIDCommMessaging` only (witness,
  watcher, server consumed via DIDComm). The renderer stays declarative —
  no conditionals — so the template name is a 1:1 promise of what comes
  out. See `docs/02-vta/provision-integration.md` for the
  comparison matrix.
- **`ProvisionAsk` builders renamed to match.** `ProvisionAsk::webvh_service`
  → `ProvisionAsk::webvh_server`, `ProvisionAsk::webvh_hosting_server` →
  `ProvisionAsk::webvh_daemon`, plus a new `ProvisionAsk::webvh_control`.
  Constants follow: `BUILTIN_WEBVH_SERVICE_TEMPLATE` →
  `BUILTIN_WEBVH_SERVER_TEMPLATE`, `BUILTIN_WEBVH_HOSTING_TEMPLATE` →
  `BUILTIN_WEBVH_DAEMON_TEMPLATE`, plus `BUILTIN_WEBVH_CONTROL_TEMPLATE`.
  `WebvhServiceMessages` → `WebvhServerMessages`.
- **`webvh-daemon` document shape normalized to `key-0`/`key-1`** (was
  `key-1`/`key-2`). Matches the other webvh templates. Existing
  `webvh-hosting-server` deployments must re-provision against
  `webvh-daemon`.
- **`webvh-server`/`webvh-control` declare `URL` and `WEBVH_SERVER` in
  `optionalVars`** for discoverability. The runtime check that "URL or
  WEBVH_SERVER must be set for any webvh-method template" is unchanged
  — declaring them in the template just makes the contract visible to
  consumers.

### Changed

- **Provisioning error message** when neither `URL` nor `WEBVH_SERVER` is
  supplied now names the satisfying built-in templates explicitly and
  shows the exact `--var` flags to pass.

---

### Publish-readiness review

A multi-agent review across software design, security, test coverage,
and consumer ergonomics produced a punch-list of pre-publish items.
The entries below are the actionable changes that landed.

### Breaking

- **`VtaError` tightened — lossy auto-conversions removed.**
  `impl From<String>`, `impl From<&str>`, and `impl From<Box<dyn Error>>`
  for `VtaError` are gone; every conversion path now picks a typed
  variant explicitly. `from_http` is now `pub` (consumers wiring their
  own HTTP transport produce typed errors directly), and a new
  `VtaError::from_problem_report(code, comment)` mirrors the REST
  mapping for DIDComm so callers `match` on the same variants
  regardless of transport.
- **`verify_vta_authorization_credential` returns a typestate.** Was
  `Result<(), _>`; now `Result<VerifiedAuthorizationCredential, _>`
  carrying the eagerly-parsed claim. Forgetting the `parse_claim`
  follow-up is now a compile error. `parse_claim` itself is `pub(crate)`.
- **Refresh tokens rotate on every `/auth/refresh`** (RFC 6749 §10.4).
  A presented refresh token is single-use; replay surfaces as
  "refresh token not found". Response shape unified with `POST /auth/`:
  refresh now returns the same `AuthenticateResponse`. The bespoke
  `RefreshResponse`/`RefreshData` types are removed.
- **`server_internal_super_admin` removed.** Replaced with a sealed
  `operations::internal_authority::InternalAuthority` marker whose
  constructor is `pub(super)` to the operations module — route
  handlers cannot reach it. `operations::keys::get_key_secret_internal`
  is the parallel `InternalAuthority`-gated entry point. Closes a
  type-system gap where any code path could synthesize a fake
  super-admin claim.
- **`SessionBackend::save` error type bound** in the trait stays sync
  for now; the AzureBackend runtime panic that motivated an async
  migration is fixed via `block_on_isolated` (a side-thread dedicated
  runtime). The full async-trait migration is deferred to a later
  cycle.

### Added

- **`VtaError::suggested_fix(&self) -> Option<&'static str>`** — lifts
  the CLI's "did you mean…" hint into the SDK so non-CLI consumers
  (web UIs, GUIs, custom dashboards) get the same operator-actionable
  guidance without forking the dispatch logic.
- **CLI `--json` flag** (`pnm`, `cnm`) — global flag wired into
  `acl list`, `contexts list`, `keys list`, `did-templates list`. Empty
  results emit the canonical empty shape so `jq` pipelines have a stable
  contract. Uses a new `vta_cli_common::render::OutputFormat` /
  `is_json_output` / `print_json` infrastructure that other commands
  can opt into with a one-line guard.
- **Two runnable examples** under `vta-sdk/examples/`:
  `sealed_transfer_round_trip` (HPKE round-trip end-to-end) and
  `bootstrap_request` (provision-integration request build + sign +
  verify). Each has `required-features = […]`; both double as compile-
  time API-surface locks.
- **`vtc-service` library surface + integration tests.** New `lib.rs`
  exposes the module tree so `tests/` can drive the route stack
  end-to-end. First test file is `tests/auth_audience.rs` (3 cases:
  VTA-audience, unknown-audience, no-token rejection through the full
  router).
- **`pnm did-templates list`, `pnm acl list`, etc. now respect global
  `--json`** — emits the canonical wire shape ready for automation.

### Security

- **Backup KDF parameter clamps on import.** `decrypt_backup` rejects
  `m_cost` outside `[8 MiB, 1 GiB]`, `t_cost` outside `[1, 10]`, and
  any non-`argon2id`/`aes-256-gcm` algorithm. Closes a Nitro-fatal
  memory-bomb vector where a hostile envelope could force `m_cost =
  u32::MAX`.
- **Per-route body caps on unauth endpoints** — `/bootstrap/request`
  and the three `/auth/*` routes now share a 64 KiB cap (vs the global
  1 MiB) so an attacker can't drive expensive crypto with 1 MiB blobs
  ahead of any auth check.
- **`BootstrapRequestBody.label` capped at 256 bytes** via
  `serde(deserialize_with = ...)`. Prevents an MB-scale free-form
  string from spilling into audit logs.
- **`tee_attested` JWT claim is per-session.** Was sourced from
  `state.tee.is_some()` (compile-time TEE feature on); now read from
  the `Session` record set at challenge issue time. A TEE binary in
  `Optional` mode that fell through to an unattested challenge writes
  `false` here; older session JSON deserializes as `false` via
  `#[serde(default)]`.
- **`Session::Debug` redacts `refresh_token`.** Hand-implemented
  `Debug` so a stray `tracing::debug!("{session:?}")` or panic
  backtrace can't surface a bearer-equivalent secret.
- **`SessionInfo` and `TokenResult`** also redact private-key /
  access-token fields in `Debug`.
- **`vta did-webvh create-did --print-mnemonic`** is now opt-in. The
  generated mnemonic is no longer printed to stderr by default —
  protects against shell history, scrollback, CI log collectors, and
  tmux/screen buffers.
- **Auth nonce GC.** `cleanup_expired_sessions` collects live
  `session_id`s in the same pass and removes orphan `nonce:` reverse-
  index rows. The keyspace no longer grows linearly with every
  challenge ever issued — relevant in long-running TEEs.
- **Reject unknown armor headers.** `vta-sdk/src/sealed_transfer/armor.rs`
  used to silently drop unknown headers for forward compatibility;
  now returns `SealedTransferError::Armor("unknown header: …")`. New
  test cases mutate `Bundle-Id`/`Chunk i/N`/`Digest-Algo` through the
  textual armor wire form and assert open fails.
- **`AzureBackend` runtime panic isolated.** The Azure Key Vault
  session backend used `tokio::runtime::Handle::current().block_on(…)`
  inside a sync trait method; that panics under the current-thread
  runtime most CLIs use. New `block_on_isolated` helper spawns a
  dedicated OS thread with its own runtime. Cost is one thread per
  call — acceptable for human-rate session ops.

### Tests

- **`MODE_B_LOCK` concurrency contract** — 16 concurrent
  `mint_mode_b`-style "lock → check → ... await ... → write" tasks
  race against the actual `MODE_B_LOCK` static and the actual
  `BOOTSTRAP_CARVEOUT_CLOSED_KEY` constant. Asserts exactly one task
  writes the sentinel.
- **`KeyspaceHandle` behavioural conformance suite** — 14 cases that
  define the observable contract every `KeyspaceHandle` backend must
  satisfy (round-trip, prefix scan, large-value, binary-safe keys,
  empty values, approximate_len). Today exercises `Local`; harness is
  parameterised on `&KeyspaceHandle` so a future Linux-only fake
  vsock proxy runs the same suite against `Vsock`.
- **Nitro attestation negative-path suite** — 8 cases covering wrong
  proof variant, unknown format, case-insensitive Nitro-format
  matching, malformed base64, empty/random quote bytes, BadProducerDid.
  Documents that the cryptographic-signature path requires a
  fixture-bearing on-host harness.
- **KMS CMS-envelope failure paths** — 5 cases (wrong RSA key,
  corrupted CEK, tampered AES-GCM ciphertext, empty envelope,
  malformed PKCS#8) covering the unwrap path the security review
  flagged as fixture-only.
- **JWT audience isolation through the full route stack** — VTA-side
  in `vta-service/tests/api_integration.rs`, VTC-side in the new
  `vtc-service/tests/auth_audience.rs`. Cross-audience tokens return
  401, unknown audiences return 401.
- **Backup KDF parameter clamps** — 5 unit tests covering each
  out-of-bounds class.
- **`Session::Debug` redaction regression test** — guards against a
  future derive-`Debug` regression re-leaking refresh tokens.
- **Refresh-rotation contract tests** — `delete_refresh_index`
  isolation + idempotence.
- **Sealed-transfer armor tampering** — 4 new cases through the
  textual wire form.

### Refactored

- **`client.rs` → `client/types.rs` + `client.rs`.** The 2269-line
  `client.rs` had request/response DTOs (~36 of them, plus their
  builder impls) inline. Types now live in `client/types.rs` and are
  re-exported via `mod types; pub use types::*;`. `client.rs` shrinks
  to 1858 lines and is mostly methods.
- **`session.rs` → `session/backends/{file,keyring,azure}.rs`.** Each
  backend gets its own focused file (~80 lines apiece); a sibling
  `mod.rs` keeps the `default_backend` selection and the `pub(super)`
  re-exports. `session.rs` drops 260 lines.
- **Shared seal helper for provision-integration.** The end-of-flow
  block (`pick assertion → seal_payload → armor → digest`) was
  copy-pasted between the `TemplateBootstrap` and `AdminRotation`
  paths in `operations/provision_integration/`. Extracted into a
  `pub(super)` `seal_provision_payload` helper in
  `provision_integration/seal.rs`. New payload variants pick up the
  same sealing contract by default.

### Polish

- **`#[must_use]` on every builder** — `CreateKeyRequest`,
  `CreateContextRequest`, `CreateAclRequest`, `EnableDidcommRequest`,
  `MigrateMediatorRequest`, `ProvisionRequestBuilder`,
  `VtaAuthorizationParams`. Catches dropped builder chains at
  compile time.
- **Missing derives.** `SessionInfo`, `SessionStatus`, `LoginResult`,
  `TokenResult`, `TokenStatus` now carry `Debug + Clone` (and
  `Copy + PartialEq + Eq` where appropriate). `SessionInfo` and
  `TokenResult` use a hand-implemented `Debug` that redacts
  bearer-equivalent fields.
- **CLI flag consistency.** `pnm keys create/import` now accept
  `--context` (keeps `--context-id` as a hidden alias for backward
  compat) — matches the rest of the CLI surface.
- **`vta-enclave` `publish = false`.** Linux-only Nitro Enclave
  binary; consumed via the deploy pipeline, not `cargo install`.
- **Crate-level doc on `vta-sdk/src/lib.rs`.** First page of
  `cargo doc` is no longer empty — covers Quick Start, sealed-transfer
  pointer, feature-flag table, module map.
- **README + integration-guide fixes.** Workspace `README.md`,
  `pnm-cli/README.md`, and `docs/02-vta/integration-guide.md`
  no longer document non-existent flags or missing API methods.
  Version pins bumped from `0.4` to `0.5`.
- **Stale CLAUDE.md notes struck.** The "backup `vta_did` cross-check
  not implemented" warning was already false (implemented at
  `backup.rs:286-307`); removed.

### Dependencies

- **`keyring-core` 1.0** replaces the legacy `keyring` v3. Each
  binary registers a platform store at startup via
  `vta_sdk::keyring_init::install_default_store()`; per-target
  stores: `apple-native-keyring-store` (macOS Keychain),
  `windows-native-keyring-store` (Windows Credential Manager),
  `dbus-secret-service-keyring-store` (Linux Secret Service —
  matches prior behaviour and survives reboot, vs `linux-keyutils`
  which doesn't).
- **`affinidi-tdk` 0.6 → 0.7**, **`affinidi-messaging-didcomm-service`
  0.2 → 0.3**, **`affinidi-tdk-common` 0.5 → 0.6**.
  `TDKSharedState::default()` is removed; all 5 call sites switched
  to `TDKSharedState::new(TDKConfig::builder().build()?).await?`.
  The `secrets_resolver` field is now private; uses now go through
  the `secrets_resolver()` accessor.
- **`metrics-exporter-prometheus`** patch-bumped 0.18.2 → 0.18.3.

### Deferred

The following items are real but cascade beyond a focused commit
and don't gate publish. Queued for the next breaking-change cycle:

- **`SessionBackend` async trait migration.** Trait shape stays sync
  for now; AzureBackend uses `block_on_isolated`. Native-async would
  ripple through ~30 SessionStore call sites + both CLIs.
- **`VtaClient<T: Transport>` god-object split.** Same shape of
  cascade as SessionBackend.
- **Hot-spot file split for `did_webvh/update.rs`** — the
  recommended boundaries (update/rotate/state/keys_helper) share
  helpers more entangled than the agent's recommendation suggested,
  needs its own design pass.
- **Provision-integration mid-sequence failure test** — needs a
  fault-injecting `KeyspaceHandle` wrapper. Existing happy-path +
  ACL-gate tests cover the externally-visible contract.
- **Generic `--json` rollout** — wired into 4 high-value list
  commands; remaining list commands (audit logs, services, mediator,
  webvh) keep their human renderers and can opt in with a one-line
  guard when needed.

### Added (sealed-transfer foundation)

- **Sealed-transfer wire format** (`vta-sdk::sealed_transfer`) —
  HPKE-AEAD envelope (X25519-HKDF-SHA256 + ChaCha20-Poly1305),
  OpenPGP-style ASCII armor with CRC24 line checksums, and a tagged
  `SealedPayloadV1` enum covering admin credentials, context
  provision bundles, DID secrets, admin key sets, raw private keys,
  and template-bootstrap payloads. One format, one seal/open path,
  one set of tamper tests for every secret we move.
- **Provision-integration flow** — a holder posts a VP-framed
  `BootstrapRequest` naming a DID template + variables; the VTA
  mints keys, renders the template, registers the holder in the
  ACL, issues a `VtaAuthorizationCredential` (W3C VC + Data
  Integrity), seals the whole bundle to the holder's X25519, and
  returns armored output. Works over three transports (offline
  file, PNM REST bridge, DIDComm) through the same library function.
- **DID templates feature** — declarative JSON describing the shape
  of a DID document with `{TOKEN}` placeholders. Four built-ins ship
  with the SDK (`didcomm-mediator`, `vta-admin`,
  `webvh-hosting-server`, `webvh-service`). Operators can upload
  global or context-scoped custom templates via REST / DIDComm. See
  `docs/did-templates.md`.
- **`webvh-service` built-in template** — generic webvh DID for
  control plane, DID-hosting server, witness, and watcher services
  that route DIDComm through a shared mediator DID.
- **TEE Mode B bootstrap** — `pnm bootstrap connect --vta-url`
  performs a one-command attested first-boot against a fresh Nitro
  enclave. The `/bootstrap/request` carve-out closes permanently on
  first success. Full Nitro attestation verification (COSE_Sign1 +
  cert chain + PCR match) in `pnm-cli` via the `attest-verify`
  feature.
- **Cold-start admin credential flow** — unified temp-did:key flow
  with auto-rotation to a fresh did:key on first authenticated call.
  `vta import-did` seeds the temp DID into the ACL offline; PNM
  completes the handshake + rotation in one `pnm setup` run.
- **Non-interactive VTA setup** — `vta setup --from <file>` for
  CI / sealed images / unattended bootstrap. See
  `docs/non-interactive-setup.md`.
- **Persistent bundle-id anti-replay store** — sealed-transfer nonce
  reuse rejected via fjall-backed `PersistentNonceStore`.
- **Rate limiting** on unauth routes (`/bootstrap/request`,
  `/auth/*`, public `/did/{did}/log`): 5 rps + 10 burst per IP via
  `tower-governor`.
- **Deferred-VTA-DID `pnm setup` flow** (non-TEE) — operators can now
  mint the PNM admin `did:key` **before** the VTA exists, paste it
  into the VTA's `admin_did` input, boot the VTA, then finish PNM
  with `pnm setup continue <slug>`. Unblocks automated VTA hosting:
  Terraform / scripted provisioners no longer hit the chicken-and-egg
  where PNM wanted the VTA DID first and VTA wanted the admin DID
  first. Interactive (`pnm setup` → prompt VTA DID blank to defer)
  and non-interactive (`pnm setup --name <n>` phase 1 with JSON on
  stdout, `pnm setup continue <slug> --vta-did <did>` phase 2) modes.
  Same ephemeral `did:key` preserved across both phases. Multiple
  concurrent pending VTAs allowed (distinct slugs). Spec:
  `docs/design/pnm-setup-deferred-vta-did.md`.
- **`vta-sdk` `test-support` feature** — exposes
  `vta_sdk::session::testing::InMemorySessionBackend` for consumer
  integration tests. Avoids OS-keyring prompts / Secret-Service
  availability in CI. Additive, zero-cost when off.

### Changed

- **MSRV bumped to Rust 1.94.0.**
- **Replaced `rsa` crate with `aws-lc-rs`** for the KMS CMS envelope
  unwrap in the Nitro attested bootstrap path. Drops RUSTSEC-2023-0071
  exposure; constant-time OAEP via BoringSSL heritage. Also dropped
  the SHA-1 MGF1 OAEP fallback (AWS KMS always uses symmetric
  `RSAES_OAEP_SHA_256`).
- **Replaced plaintext credential / DID-secret transfer** with sealed
  bundles everywhere. Plaintext `encode/decode` helpers on bundle
  types are gone — the only way to move secrets is through
  `sealed_transfer::seal_payload` + `open_bundle`.
- **`VtaError::Protocol(String)`** split into typed DIDComm variants
  (`UnsupportedTransport`, `DidcommTransport`, `DidcommRemote`)
  so the CLI can emit operator-specific remediation.
- **Client-side keygen for admin credential issuance** — the VTA no
  longer returns raw secret material. Clients mint their Ed25519
  locally and register the public DID via ACL.
- **`TemplateBootstrap` payload** is now the canonical integration
  bundle shape; replaces ad-hoc `ContextProvisionBundle` exports.
- **Coordinated RustCrypto 0.11 ecosystem bump**: `sha2` 0.10→0.11,
  `hmac` 0.12→0.13, `hkdf` 0.12→0.13, `aes` 0.8→0.9, `cbc` 0.1→0.2.
- **Azure crates bumped**: `azure_identity` 0.33→0.35,
  `azure_security_keyvault_secrets` 0.12→0.14.
- **[breaking] `vta-sdk::session` public-type `vta_did`** is now
  `Option<String>` on `Session` (internal), `SessionInfo`,
  `SessionStatus`, and `LoginResult`. `None` encodes the new
  `PendingVtaBinding` state used by deferred-VTA-DID `pnm setup`.
  `SessionStore` gains `store_pending_vta_binding`, `bind_vta_did`,
  and `has_pending_vta_binding`. Existing session JSON still
  deserializes (serde default). No external `SessionBackend`
  implementors exist outside the in-tree built-ins.

### Security

Design-review hardening pass (see CLAUDE.md for the full write-up):

- **S-1** KMS attested-only on real Nitro hardware. Previously a
  transient NSM hiccup silently downgraded to an IAM-only KMS call,
  bypassing PCR-enforced policy. Now terminal unless
  `tee.kms.allow_unattested_fallback = true`.
- **S-2** JWT key fingerprint no longer silently re-baselines on
  missing record. Operators migrating from a pre-fingerprint VTA
  opt in explicitly via `tee.kms.allow_fingerprint_init`.
- **S-3** Constant-time challenge + DID compare on `/auth/`.
- **S-4** `AuthClaims::local_cli` renamed to
  `unsafe_local_cli_super_admin` and feature-gated behind
  `cli-synthesis`. Enclave builds cannot compile a call to it.
  Added a separate `server_internal_super_admin` for the library-
  internal privilege-elevation case.
- **S-5** `verify_producer_assertion_with_pubkey` now returns a
  `VerifiedAssertion` typestate (`DidSignedVerified` /
  `PinnedOnlyAcknowledged` / `AttestedNeedsNitroCheck`). Callers
  must match exhaustively — no more silent `Ok(())` for Attested.
- **S-6** `TeeProvider::verify(report) -> bool` renamed to
  `smoke_check_structure(report) -> StructuralCheckOutcome` with
  doc comments spelling out that this is structural only, not
  cryptographic verification.
- **S-7** Refresh tokens keyed by SHA-256 in the session reverse-
  index. A storage dump now yields hashes, not live credentials.
- **S-8** `validate_identifier` on context-id and template-name at
  the DID-template operations boundary. Guards against
  `{context}:{name}` → `tpl:ctx:a:b:c` keyspace injection.
- **S-9** Backup import rejects mismatched `vta_did`. Fresh installs
  accept any backup (disaster recovery); running VTAs refuse to
  overwrite their identity with a foreign backup.
- **S-10** `open_bundle` couples `PinnedOnly` producer assertions to
  an OOB digest at the type level via `PinnedOnlyPolicy`.
- **Backup encryption** uses Argon2id (m=64 MiB, t=3, p=4) +
  AES-256-GCM with 12-char minimum password and AEAD tag check.

### Tests

Reference-quality coverage across foundation crates:

- **T-1** vsock-store wire-format tests (25) — protocol constants,
  encode/decode tamper cases, request payload shape.
- **T-2** ACL unit tests (26) — CRUD, role assignment matrix,
  context-scope visibility, expiration boundary, serde
  forward-compat with pre-`expires_at` entries.
- **T-3** JWT rejection tests (7) — expired, tampered signature,
  `alg=none`, foreign signer, missing required claims, empty,
  malformed shape.
- **T-4** Session lifecycle tests (17) — CRUD, refresh-token S-7
  regression guard, cleanup of expired sessions.
- **T-5** vtc-service wire-shape + config parse tests (18).
- **Mutation-coverage suite** for VP verify in
  `provision_integration/request.rs` — bit-flip in nonce, ask,
  `validUntil`, admin template, type arrays.
- **Sealed-transfer adversarial suite** — armor CRC24 tamper, AAD
  tamper caught by AEAD, missing chunk, nonce replay, wrong
  recipient, PinnedOnly-without-digest rejection.

### Refactored

- `vta-service/src/operations/provision_integration.rs` (1942 lines)
  split into `mod.rs` + `mint` + `preconditions` + `templates` +
  `vta_keys` + `webvh` submodules.
- `vta-service/src/operations/did_webvh.rs` (1444 lines) split into
  `mod.rs` + `document` + `lifecycle` + `servers`.
- `vta-service/src/setup/` split into `interactive` + `from_toml`.
- New `vta-service/src/test_support` for the shared test harness.

### Removed

- **`/auth/credentials` endpoint and `VtaClient::auth_credential_*`
  client methods** — clients mint did:key locally and register the
  DID in the ACL; the VTA never holds the private key.
- **Plaintext `encode/decode` helpers** on `CredentialBundle`,
  `ContextProvisionBundle`, `DidSecretsBundle`, `AdminKeySet`,
  `RawPrivateKey` — the only way to move these is via
  `sealed_transfer`.
- **`rsa` and `sha1` crates** from direct dependencies.

## 0.4.1 — 2026-04-15

### Added

- **`VtaClient` and `DIDCommSession` are now `Clone`** — Cloning a
  `VtaClient` is cheap; clones share the underlying HTTP connection pool
  and authentication state via `Arc<Mutex>`, avoiding redundant auth
  round-trips.
- **Cold-start bootstrap guide** (`docs/cold-start-guide.md`) —
  Step-by-step walkthrough for bootstrapping a VTA + Mediator + WebVH
  environment from scratch.

### Changed

- **Consolidated security documentation** — Merged `threat-model.md`
  and `security-architecture.md` into a single `docs/security.md`.
  Removed stale `docs/VTA_Service_Overview.md` and
  `docs/store-migration.md`.

## 0.4.0 — 2026-04-13

### Changed

- **Upgrade to `affinidi-messaging-didcomm-service` v0.2** — Both VTA
  and VTC now use the v0.2 DIDComm service framework, which provides
  production-ready lifecycle management for mediator connections.
- **VTA DIDComm bridge simplified** — The bridge no longer captures the
  listener's ATM from handler context. Instead, it uses
  `DIDCommService::send_message_with_retry()` for resilient delivery
  with exponential backoff across mediator reconnects, and
  `listener_did()` for dynamic DID lookup.
- **VTA startup blocks until mediator is ready** — The server now calls
  `wait_connected()` after starting the DIDComm service, ensuring the
  mediator connection is established before accepting REST traffic.
- **VTC migrated to DIDComm service framework** — Replaced the manual
  ATM/WebSocket dispatch loop with `DIDCommService` + `Router`. VTC
  now gets automatic reconnection, typed message routing, and lifecycle
  event logging for free.

### Added

- **DIDComm lifecycle event logging** — Both VTA and VTC log mediator
  connection events (`Connected`, `Disconnected`, `Restarting`) via
  the service's `subscribe()` broadcast channel.

### Removed

- **`vta-sdk::didcomm_init`** — Manual ATM/WebSocket/profile setup
  module removed. All DIDComm connection management is now handled by
  `DIDCommService`.
- **`vta-sdk::didcomm_transport`** — The `send_and_wait_raw` function
  and `DIDCommSendParams` struct removed. The `PendingMap` type has
  moved into the VTA service's `DIDCommBridge`.

## 0.3.3 — 2026-04-13

### Fixed

- **DIDComm message expiry** — Outbound DIDComm messages now include
  `created_time` and `expires_time` fields, preventing stale messages
  from accumulating at the mediator between sessions. Expiry matches
  the caller's timeout (30 seconds for WebVH operations).
- **Problem-report logging** — Unhandled problem-report messages (e.g.,
  protocol-specific types from WebVH servers) now log `code`, `comment`,
  `from`, and `msg_type` instead of just "unknown message type". The
  standard problem-report handler also includes `msg_type` to
  distinguish between protocol-specific and standard problem reports.
- **Stale message detection** — The DIDComm bridge now logs unmatched
  responses (messages with a `thid` that don't match any pending
  request) at DEBUG level, identifying them as likely stale messages
  from a previous session.

## 0.3.2 — 2026-04-12

### Fixed

- **DIDComm outbound response routing** — The `DIDCommBridge` now
  correctly receives responses to outbound request-response messages
  (e.g., WebVH DID creation via DIDComm transport). Previously,
  `try_complete()` was never called on inbound messages, so
  `send_and_wait` would always time out.
- **Single mediator connection** — Replaced the dual-ATM architecture
  (one for the listener, one for the bridge) with a single shared
  connection. The new `BridgeHandler` wrapper captures the listener's
  ATM from `HandlerContext` and intercepts response messages before
  normal handler dispatch. This eliminates the
  `w.websocket.duplicate-channel` error loop that occurred when two
  connections used the same DID.

## 0.3.1 — 2026-04-11

### Client-Provided DID Documents for WebVH Creation

- **Three DID creation modes** — `POST /webvh/dids` now supports three
  mutually exclusive modes:
  - **VTA-built** (default) — VTA derives keys and builds the DID
    Document internally (existing behavior, unchanged).
  - **Template mode** (`did_document` field) — Client provides a DID
    Document template with `{DID}` placeholders. VTA derives keys,
    signs the log entry, and resolves placeholders via `didwebvh-rs`.
    `add_mediator_service` and `additional_services` are ignored.
  - **Final mode** (`did_log` field) — Client provides a complete,
    pre-signed `did.jsonl` log entry. VTA publishes it as-is without
    deriving keys or creating a log entry. No key records are stored.
- **`set_primary` flag** — Optional boolean (default `true`). When
  `false`, the context's primary DID (`ctx.did`) is not updated,
  allowing multiple DIDs per context without overwriting the primary.
- **CLI support** — `pnm webvh create-did` gains `--did-document <FILE>`,
  `--did-log <FILE>`, and `--no-primary` flags.
- **5 new integration tests** — Mutual exclusivity validation, template
  mode with custom keys, final mode storage, and `set_primary`
  true/false behavior.

### User-Specified Keys for DID Creation

- **`signing_key_id` / `ka_key_id` fields** — Optionally specify
  existing VTA-managed keys (imported or derived) for DID creation
  instead of having the VTA derive fresh keys. The signing key must
  be Ed25519; the KA key must be X25519.
- **Signing-only DIDs** — When only `signing_key_id` is provided, the
  DID Document is created with authentication/assertion but no
  keyAgreement, suitable for non-DIDComm use cases.
- **DIDComm validation** — If the DID Document includes
  `DIDCommMessaging` services (via `add_mediator_service`,
  `additional_services`, or a template), `ka_key_id` is required.
- **CLI support** — `pnm webvh create-did` gains `--signing-key` and
  `--ka-key` flags.
- **5 new integration tests** — Signing-only, both keys, KA-without-
  signing rejection, DIDComm-requires-KA, wrong key type rejection.

### Setup Wizard Improvements

- **Simple/advanced toggle** — VTA DID creation now offers a simple
  path (VTA creates everything) and an advanced path that reveals
  template mode, pre-signed log import, and user-specified key options.
- **Consolidated DID creation** — `did_webvh.rs` standalone CLI
  rewritten as a thin interactive wrapper around `operations::create_did_webvh()`,
  removing ~200 lines of duplicate key derivation and document building.
- **VTA DID via operations layer** — `create_vta_did()` in the setup
  wizard now uses `build_wizard_did()` → `operations::create_did_webvh()`
  instead of direct `didwebvh-rs` calls.
- **Pre-rotation UX** — Replaced interactive loop ("Generate another?")
  with a count prompt ("Number of pre-rotation keys", default: 1).
- **Post-creation hosting instructions** — After saving `did.jsonl`,
  the wizard now shows the URL where it should be uploaded.

### Capabilities Discovery

- **`GET /capabilities`** — New authenticated endpoint reporting VTA
  features (webvh, didcomm, tee, rest), enabled services, configured
  WebVH servers, and supported DID creation modes. Allows 3rd party
  apps using `vta-sdk` to probe what the VTA supports before attempting
  operations.
- **DIDComm discovery protocol** — `discover-capabilities` message type
  returns the same information via DIDComm.
- **`VtaClient::capabilities()`** — SDK client method for discovery.

### Infrastructure & Bug Fixes

- **Unified `build_did_document`** — merged `build_did_document` and
  `build_did_document_from_keys` into a single function with `include_ka`
  parameter.
- **DID deletion cleans up key records** — `delete_did_webvh` now removes
  associated signing, KA, and pre-rotation key records.
- **DIDComm bridge wired in handler path** — WebVH server communication
  via DIDComm now uses the real bridge instead of a dummy.
- **Pre-rotation keys in TEE autogen** — TEE auto-generated DIDs now
  include 1 pre-rotation key by default.
- **Mediator DID format validation** — Setup wizard validates `did:`
  prefix when entering an existing mediator DID.

### Code Consolidation

- **Eliminated `CreateDidRequest`** — REST route now uses
  `CreateDidWebvhBody` from SDK protocol types directly.
- **`From<CreateDidWebvhBody> for CreateDidWebvhParams`** —
  Centralizes default value logic, replacing boilerplate conversions
  in REST and DIDComm handlers.
- **Removed ~316 lines of duplicate code** — Deleted `create_webvh_did()`
  and `prompt_pre_rotation_keys()` from `setup.rs` after migrating
  all callers to `build_wizard_did()`.
- **Cleaned up unused imports** — Removed `didwebvh-rs` direct
  dependencies from `setup.rs` now that it uses the operations layer.

## 0.3.0 — 2026-04-01

### Reader Role & Action Classification

- **New `Reader` role** — Context-scoped read-only access to keys,
  contexts, DIDs, and configuration. Sits between Application and
  Monitor in the hierarchy. Readers can observe all business data
  within their allowed contexts but cannot sign, write to cache,
  create keys, or perform any mutating operation.
- **Action classification** — Every endpoint is now classified as
  read, write, or manage:
  - **Read** (Reader+): list/get keys, contexts, DIDs, config, cache
  - **Write** (Application+): sign, cache write/delete
  - **Admin**: key create/delete/import, seeds, audit, DID management
  - **Manage** (Initiator+): ACL operations, credential generation
  - **Super Admin**: config update, context CRUD, backup, restart
- **`require_read()` / `require_write()`** — New methods on
  `AuthClaims` for action-level authorization checks.
- **`WriteAuth` extractor** — Route-level extractor requiring at
  least Application role. Applied to sign and cache write endpoints.
- **Tightened auth on sign and cache** — `POST /keys/{id}/sign`,
  `PUT /cache/{key}`, and `DELETE /cache/{key}` now require
  Application role or higher (previously any authenticated user).
- **Backup export route** — Changed from `AuthClaims` to
  `SuperAdminAuth` extractor, matching the operations layer.
- **DIDComm handler auth fixes** — 17 handlers now have explicit
  role checks matching their REST counterparts (defense-in-depth).
  Fixed `handle_update_retention` from `require_admin()` to
  `require_super_admin()` to match REST.

### Role Hierarchy (updated)

```
Super Admin  (Admin + unrestricted)
  Admin      — key mgmt, DID ops, audit, seeds
    Initiator  — ACL management, credential generation
      Application — sign, cache write, standard API
        Reader     — read-only business data access
          Monitor  — metrics and health only
```

### Version Bumps

All crates bumped from 0.2.1 to **0.3.0**.

### Testing

- **18 new tests** — Reader role parsing, `require_read`/`require_write`
  enforcement across all roles, ACL validation (Reader cannot assign
  roles, Initiator/Admin can create Reader), integration tests (Reader
  can list keys, cannot sign, cannot create keys).
- **Total: 263 tests** (up from 245).

### VTA SDK Integration Module

- **`vta_sdk::integration::startup()`** — Unified startup pattern for
  any service that manages its DID and secrets through a VTA. Handles
  authentication, secret fetching, local caching, and offline fallback
  in a single call. Returns a `StartupResult` with the service DID,
  secrets bundle, source indicator, and an optional `VtaClient` for
  follow-up calls.
- **`SecretCache` trait** — Pluggable local cache for VTA secrets.
  Services implement `store()` and `load()` using their preferred
  backend (keyring, AWS Secrets Manager, filesystem, etc.) to enable
  offline resilience.
- **`authenticate()`** — Two-tier authentication strategy: lightweight
  REST auth first (`VtaClient::from_credential`), with session-based
  DIDComm fallback for non-`did:key` VTAs. Network errors propagate
  immediately without fallback.
- **`integration` feature flag** — New opt-in feature on `vta-sdk`
  (implies `client` + `session`) that enables the integration module.

### Key Labels as Verification Method IDs

- **`fetch_did_secrets_bundle()`** — When a key has a label, it is now
  used as the verification method fragment (e.g., `did:example#my-label`)
  instead of the raw key ID. This produces cleaner, human-readable DID
  documents for services that use labeled keys.

### Workspace Dependency Consolidation

- **`ed25519-dalek`** — Moved to `workspace.dependencies`, updated 6
  crates to use `workspace = true`.
- **`dialoguer`** — Moved to `workspace.dependencies`, updated 4
  crates to use `workspace = true`.
- **`chrono` in `vta-cli-common`** — Now uses workspace definition
  (gains `serde` feature that was previously missing).

### HTTP Client Improvements

- **`auth_light` client reuse** — `challenge_response_light()` and
  `refresh_token_light()` now accept a `&reqwest::Client` parameter
  instead of creating a new client per call, enabling connection
  pooling across authentication flows.
- **`authenticate_with_credential()`** — Returns the HTTP client
  alongside the auth result, which `VtaClient::from_credential()`
  now reuses directly (eliminating a redundant client allocation).
- **`WebvhClient` refactor** — Extracted `send()` and `with_auth()`
  helpers to eliminate repeated request/error-handling boilerplate
  across 4 methods.

### Code Quality

- **Zero clippy warnings** — Resolved all clippy warnings across the
  workspace: collapsible ifs, `.is_multiple_of()`, needless `Ok(?)`,
  `Default` impl for `WrappingKeyCache`, type alias for complex KMS
  return type.
- **`Keyspaces` struct** — New `operations::Keyspaces` bundles keyspace
  handles with `from_app_state()` and `from_vta_state()` constructors.
  Reduces argument counts for `export_backup` (11→6), `apply_import`
  (10→5), `delete_context` (8→5).
- **`DIDCommSendParams`** — New params struct for `send_and_wait_raw`,
  replacing 10 positional arguments.
- **`cargo fmt`** — Full workspace formatting pass.

### Security

- **VTC key material zeroization** — Added `zeroize` dependency to
  `vtc-service`. Replaced `.unwrap()` on key material slices with
  proper error propagation. Secrets bundle now written to file
  instead of stdout (preventing key leakage to logs).
- **Session error visibility** — Replaced `.ok()?` chains in keyring,
  file, and Azure session backends with explicit error logging via
  `tracing::warn`. Users can now diagnose auth failures from logs.

### Architecture

- **Shared `SeedStore` trait** — Extracted seed/secret store trait
  from `vta-service` into `vti-common/src/seed_store.rs`. Both VTA
  (`SeedStore`) and VTC (`SecretStore`) now implement the shared
  interface. Cloud backend implementations remain in each service crate.

### Testing

- **Operation-level unit tests** — New tests for `create_key` (Ed25519,
  P256), `sign_payload` (EdDSA roundtrip), and `rotate_seed` (archive
  + generation increment). Uses mock `SeedStore` and temp fjall stores.
- **Total: 245 tests** (up from 241).

### CI/CD

- **GitHub Actions pipeline** (`.github/workflows/ci.yml`) — Four
  parallel jobs: `cargo check`, `cargo test`, `cargo clippy -D warnings`,
  `cargo fmt --check`. Triggers on push to main/nightly and PRs to main.
  Cargo registry and target caching via `actions/cache`.

### Documentation

- **Integration Guide** (`docs/integration-guide.md`) — Comprehensive
  guide for 3rd-party developers integrating applications and services
  with the VTA. Covers credential provisioning, authentication patterns,
  key management, the SDK integration module, offline resilience, and
  security best practices.

---

## 0.3.0 — 2026-03-31

### Imported Secrets

- **Import external private keys** — New `POST /keys/import` endpoint
  and `pnm keys import` command allow importing externally-created
  private keys (Ed25519, X25519, P-256) into the VTA. Imported keys
  are stored encrypted at rest and participate in signing, secret
  export, backup/restore, and revocation alongside BIP-32-derived keys.
- **Ephemeral wrapping keys (REST)** — REST key import uses
  ECDH-ES + AES-256-GCM key wrapping via ephemeral X25519 keypairs
  (`GET /keys/import/wrapping-key`). Each wrapping key is single-use
  with a 60-second TTL. DIDComm transport sends keys directly inside
  the end-to-end encrypted envelope.
- **Encrypted storage layer** — Imported secrets are encrypted with
  AES-256-GCM using a KEK derived from the BIP-32 master seed via
  HKDF-SHA256 with a random 32-byte salt. Each ciphertext is bound
  to its `key_id:key_type` via authenticated associated data (AAD),
  preventing blob-swap attacks.
- **Secure deletion on revoke** — Revoking an imported key overwrites
  the encrypted blob with zeros and deletes it from the keyspace.
  The `KeyRecord` is retained for audit trail.
- **Seed rotation re-encryption** — When the BIP-32 seed is rotated,
  all imported secrets are automatically re-encrypted with the new
  seed-derived KEK.
- **Backup & restore** — Imported secrets are included in the
  encrypted backup payload (plaintext inside the Argon2id+AES-256-GCM
  envelope) and restored on import. The KEK salt is also backed up
  for deterministic KEK reconstruction.

### Data Model

- **`KeyOrigin` enum** — New `origin` field on `KeyRecord`:
  `derived` (default, BIP-32) or `imported` (external). Backward
  compatible via `#[serde(default)]`.
- **`ImportedSecretBackup`** — New type in `BackupPayload` for
  portable imported secret backup.
- **`imported_secret_count`** — Added to `ImportResult` for
  visibility during backup preview/import.

### Security

- **Zeroize** — All private key buffers are zeroized after use
  via the `zeroize` crate (import, signing, backup export/import,
  seed rotation re-encryption).
- **AAD binding** — AES-GCM encryption of imported secrets includes
  `key_id:key_type` as additional authenticated data, preventing
  ciphertext swapping between key entries.
- **Independent KEK salt** — A random 32-byte salt is generated
  per VTA instance and stored alongside the keyspace, ensuring
  two VTAs with the same seed produce different KEKs.
- **Admin-only import** — The import endpoint requires Admin role
  (stricter than key creation which allows Initiator).

### CLI

- **`pnm keys import`** — Import a private key from multibase
  string (`--private-key`) or file (`--private-key-file`).
  Supports `--key-type ed25519|x25519|p256`, `--label`, and
  `--context-id`. Prints a secure-deletion warning on success.

### Testing

- **6 new unit tests** — Imported secret encrypt/decrypt roundtrip,
  wrong-AAD rejection, secure deletion, seed rotation re-encryption,
  ephemeral wrapping key generation + unwrap, single-use enforcement.
- **Total: 234 tests** (up from 228).

### Breaking Changes

- **Operation signatures** — `get_key_secret()`, `sign_payload()`,
  `revoke_key()`, `rotate_seed()`, `export_backup()`, and
  `apply_import()` now accept an `imported_ks` parameter.
- **`AppState`** — Added `imported_ks: KeyspaceHandle` and
  `wrapping_cache: WrappingKeyCache` fields.
- **`VtaState` (DIDComm)** — Added `imported_ks: KeyspaceHandle`.
- **Workspace version bumped to 0.3.0** — All crates updated.

### Dependency Updates

- `hkdf` 0.12 (new — KEK derivation for imported secrets)

### VTA SDK Improvements for Service Integration

- **Lightweight DIDComm auth (`auth_light`)** — New
  `challenge_response_light()` and `refresh_token_light()`
  functions perform DIDComm challenge-response authentication
  without requiring ATM/TDK runtime initialization. Uses a
  hand-rolled JWE packer (`didcomm_light`) with
  ECDH-ES+A256KW key agreement and A256GCM content
  encryption. Available behind the `client` feature (not
  `session`).
- **`VtaClient::from_credential()`** — One-line constructor
  that decodes a base64 credential bundle, authenticates via
  lightweight auth, and returns a ready-to-use client with
  auto-refresh enabled.
- **Automatic token refresh** — `VtaClient` now stores
  credential material and automatically refreshes expired
  tokens before each API call. Tries the `/auth/refresh`
  endpoint first (cheap), falls back to full
  challenge-response if the refresh token is expired.
  Token expiry is checked with a 30-second buffer.
- **`fetch_context_secrets()`** — Convenience method that
  paginates through all active keys in a context and returns
  TDK `Secret` objects ready for DIDComm or signing. Pages
  in batches of 100 to handle large key sets.
- **`check_auth()`** — Verifies the current token is valid
  by calling `GET /health/details`. Returns `true`/`false`
  for readiness checks.
- **`token_expires_at()`** — Exposes token expiry for health
  monitoring in long-running services.
- **`set_token()` is now `&self`** — No longer requires
  `&mut self`, simplifying usage in shared contexts.

### Lightweight DIDComm Packer (`didcomm_light`)

- **DIDComm v2 anoncrypt** — Minimal JWE (General JSON)
  packer producing messages compatible with any DIDComm v2
  unpacker (including `affinidi-tdk`'s `ATM::unpack()`).
- **ECDH-ES+A256KW** key agreement with ephemeral X25519.
- **A256GCM** content encryption (simpler than A256CBC-HS512).
- **Concat KDF** (NIST SP 800-56A) for key derivation.
- **AES-256 Key Wrap** (RFC 3394) for CEK wrapping.
- **`did:key` → X25519** conversion (Edwards→Montgomery).
- **8 unit tests** — Key wrap roundtrip, KDF determinism,
  did:key parsing, Ed25519→X25519 conversion, JWE structure
  validation.

### VTA SDK Ergonomics

- **`vta_sdk::prelude`** — Re-exports the most commonly used
  types (`VtaClient`, `VtaError`, `KeyRecord`, `KeyType`,
  `CredentialBundle`, request/response types) for single-line
  imports.
- **Builder patterns** — `CreateKeyRequest::new(KeyType::Ed25519)
.label("my-key").context("app")` replaces verbose struct
  construction with many `None` fields. Builders added for
  `CreateKeyRequest`, `CreateContextRequest`, `CreateAclRequest`,
  and `GenerateCredentialsRequest`. All accept `impl Into<String>`.
- **`fetch_did_secrets_bundle()`** — One-call replacement for the
  4-step pattern (get context → list keys → get secrets → build
  bundle). Returns a portable `DidSecretsBundle`.
- **`From<GetKeySecretResponse> for SecretEntry`** — Eliminates
  manual field-by-field mapping when building secret bundles.

---

## 0.2.1 — 2026-03-30

### Bug Fixes

- **Health check deserialization** — Made `version` field optional
  in `vta-sdk::HealthResponse` so the unauthenticated `GET /health`
  endpoint (which returns only `{"status": "ok"}`) deserializes
  correctly. Previously `pnm health` and `cnm health` reported
  "error decoding response body".

### Improvements

- **Audit log levels** — Audit events now use `INFO` for successful
  outcomes and `ERROR` for failures (e.g. `denied:*`). Previously
  all audit events were emitted at `ERROR` level regardless of
  outcome.

## 0.2.0 — 2026-03-29

### Observability

- **Prometheus metrics endpoint** — `GET /metrics` serves
  request count and latency histograms in Prometheus text
  format. Requires authentication (any role including the
  new Monitor role).
- **Monitor role** — New lowest-privilege role for
  observability-only access. Can read `/metrics` and
  `/health` but nothing else. Create with
  `pnm acl create --role monitor`.

### Hardening

- **Admin credential delete-after-read** — The
  `/attestation/admin-credential` endpoint now deletes the
  credential from the store after first retrieval.
  Subsequent calls return 404.
- **Server-side backup password minimum** — The backup
  export API enforces a 12-character minimum password.
- **Super admin for backup/restart** — Backup export,
  import, and VTA restart now require super admin (admin
  with no context restrictions).
- **Enclave bootstrap error handling** — Replaced all
  `.expect()` calls in `vta-enclave/src/main.rs` with
  proper error handling and `tracing::error` before exit.
- **Clippy clean** — Fixed all actionable warnings:
  `Role::from_str` → `Role::parse`, `.clamp()`, needless
  borrows, collapsed ifs.

### Testing

- **31 REST API integration tests** — Full axum server
  with temp fjall store, programmatic JWT tokens, and
  pre-inserted sessions. Covers auth enforcement (6),
  role hierarchy (4), CRUD operations (5), backup (3),
  cache (1), audit (2), context scoping (1), key
  lifecycle (3), P-256 keys (1), seed list (1),
  wrong password (1), ACL lifecycle (1), context
  lifecycle (1), audit retention (1).
- **20 security-focused unit tests** — Auth role
  enforcement, ACL privilege escalation prevention,
  context access scoping, backup crypto validation.
- **Total: 226 tests** (up from 175 at start of release).

### Documentation

- **6 Mermaid diagrams** — Crate dependencies, REST vs
  DIDComm request flow, auth challenge-response sequence,
  BIP-32 derivation tree, TEE bootstrap sequence, enclave
  proxy architecture.
- **Consolidated docs** — Removed ~170 lines of
  duplicated content from README.md (feature flags, CLI
  reference). Cross-references to canonical sources.
- **Doc comments** on 35 public route handler functions.
- **Expanded CONTRIBUTING.md** — Development setup, test
  commands, PR checklist, coding guidelines.

### Architecture

- **vta-service / vta-enclave split** — `vta-service` is
  now a library crate exporting all business logic.
  `vta-enclave` is a separate binary crate for Nitro
  Enclave deployments with TEE-specific bootstrap (KMS,
  vsock-store, attestation). Future front-ends (SGX,
  serverless) follow the same pattern.
- **Soft restart** — The VTA server can now restart
  in-process without a process restart. Service threads
  shut down gracefully, auth/crypto re-initialize, and
  threads restart. Exposed via `POST /vta/restart`,
  DIDComm protocol, and `pnm vta restart`.
- **Patched affinidi-messaging-didcomm-service** — Local
  patch adds `tdk_config` field to `ListenerConfig` so
  the VTA can pass its network-mode DID resolver to the
  DIDComm service listener.

### TEE / Nitro Enclave

- **KMS-based secret bootstrap** — First boot generates
  BIP-39 seed and JWT key inside the enclave, encrypts
  with KMS `GenerateDataKey` (with Nitro attestation),
  stores ciphertext. Subsequent boots decrypt via KMS
  `Decrypt` with PCR enforcement.
- **Encrypted storage** — AES-256-GCM encryption of all
  sensitive keyspaces. Key derived from seed via HKDF.
- **Auto-generated VTA identity** — `did:webvh` DID
  created automatically on first boot from a template.
- **Admin credential bootstrap** — Operator-provided
  admin DID or auto-generated `did:key` with credential
  bundle stored for retrieval.
- **Seal mechanism** — Ed25519 challenge-response seal
  prevents offline CLI modification after bootstrap.
- **Nitro deployment infrastructure** — Dockerfile,
  enclave entrypoint, KMS setup scripts, IAM policies,
  full deployment guide (1,200+ lines).

### DIDComm

- **Migrated to affinidi-messaging-didcomm-service** —
  Replaced manual message dispatch with typed Router,
  handler functions, MessagePolicy middleware, and
  RequestLogging. Handlers use `Extension<Arc<VtaState>>`
  for shared state injection.
- **WebSocket-based DIDComm session** — PNM CLI now uses
  WebSocket streaming for response delivery, fixing
  reliability issues with REST-only polling.
- **Backup management protocol** —
  `backup-management/1.0/export` and
  `backup-management/1.0/import` DIDComm message types.
- **VTA restart protocol** —
  `vta-management/1.0/restart` DIDComm message type.

### P-256 Key Support

- **P-256 (secp256r1) key derivation** — New key type
  with BIP-32 derivation using domain-separated paths
  (`m/13'/256'/...`).
- **Signing oracle endpoint** — `POST /keys/{key_id}/sign`
  (REST) and `key-management/1.0/sign` (DIDComm) for
  server-side signing with managed keys.
- **Token cache API** — `GET/PUT/DELETE /cache/{key}` for
  ephemeral key-value storage with TTL support.

### Backup & Restore

- **Export** — `POST /backup/export` and DIDComm protocol
  serialize all VTA state (seed, keys, ACL, contexts,
  WebVH, config, optional audit logs) into a
  password-protected `.vtabak` file.
- **Encryption** — Argon2id (64 MiB, 3 iterations, 4
  parallel) derives AES-256-GCM key from user password.
- **Import** — `POST /backup/import` decrypts, validates,
  replaces all state, and triggers soft restart. Preview
  mode (`confirm=false`) shows what would change.
- **TEE re-encryption** — On import in TEE mode,
  `re_encrypt_bootstrap_secrets()` re-encrypts the
  imported seed and JWT key with the enclave's KMS key.
- **PNM CLI** — `pnm backup export [--include-audit]`
  and `pnm backup import <file> [--preview]`.

### Performance

- **DIDComm service DID resolver fix** — The DIDComm
  service listener was creating a local-mode DID resolver
  (ignoring network-mode config), causing ~1s of uncached
  HTTP DID resolution per message through the HTTPS proxy.
  Fixed via patched crate with `tdk_config` passthrough.
- **Reusable TrustPingSession** — PNM health command now
  creates one ATM + WebSocket connection for both mediator
  and VTA pings, eliminating ~4s of duplicate setup.
- **Shared DID resolver** — Single `DIDCacheClient` across
  all health check operations.

### CLI

- **DIDComm-only mode** — PNM CLI works without a REST
  URL, using DIDComm through the mediator for all
  operations.
- **Multi-VTA support** — `pnm vta list/use/remove/info`
  for managing connections to multiple VTAs.
- **`pnm vta restart`** — Trigger soft restart remotely.
- **`pnm backup export/import`** — Remote backup and
  restore with password protection.
- **Trust-ping in health** — `pnm health` now pings both
  the mediator and VTA through DIDComm with latency
  display.

### Enclave Proxy

- **Rust rewrite** — Replaced shell-based parent proxy
  with a Rust binary (`enclave-proxy`).
- **7-channel multiplexer** — Inbound REST, outbound
  mediator (TLS), HTTPS CONNECT proxy, IMDS credential
  proxy, persistent storage (fjall), DID resolver bridge,
  log forwarding.
- **Embedded Affinidi DID resolver** — Resolves mediator
  DID locally without external resolver service.
- **Connection limit** — Semaphore-based limit (256) per
  channel to prevent resource exhaustion.

### Breaking Changes

- **`vta-service` is now a library** — The local/dev
  binary is still included, but TEE deployments use
  `vta-enclave` which depends on `vta-service` as a
  library.
- **DIDComm handler signatures changed** — Handlers now
  use `(HandlerContext, Message, Extension<Arc<VtaState>>)`
  pattern from `affinidi-messaging-didcomm-service`.
- **Workspace version bumped to 0.2.0** — All crates
  updated.

### Dependency Updates

- `affinidi-messaging-didcomm-service` 0.1.2 (patched
  locally for TDK config passthrough)
- `didwebvh-rs` 0.3 → 0.4
- `tokio-vsock` 0.5 → 0.7
- `argon2` 0.5 (new — backup encryption)
- `aes-gcm` 0.10
- `hmac` 0.12

---

## 2026-03-21

### vti-common `0.1.1` (new crate)

- **Shared foundation crate** — Extracts common code
  from `vta-service` and `vtc-service` into a shared
  library: auth (JWT, sessions, extractors), ACL, error
  types, config types, and the fjall key-value store.
- **Key-only prefix scan** — New `prefix_keys()` method
  on `KeyspaceHandle` for efficient iteration when only
  keys are needed (no value decryption overhead).

### vta-service `0.1.3`

- **Audit logging system** — New structured audit log
  with persistence to fjall keyspace. Includes REST
  endpoints (`GET /audit/logs`, `GET /audit/retention`,
  `PATCH /audit/retention`) and DIDComm protocol
  support. Audit events emitted via tracing at the
  `audit` target and persisted for API retrieval.
- **Connection rate limiting** — Enclave proxy now
  enforces a configurable maximum concurrent connection
  limit (default 256) per proxy channel to prevent
  resource exhaustion.
- **Refactored to use vti-common** — Auth, ACL, store,
  error, and config modules now delegate to the shared
  `vti-common` crate, reducing duplication with
  `vtc-service`.
- **Code quality cleanup** — Eliminated unnecessary
  `KeyspaceHandle::clone()` calls in auth routes,
  combined redundant config lock acquisitions, removed
  duplicate `AuditLogQuery` struct in favor of SDK's
  `ListAuditLogsBody`, and optimized audit cleanup to
  use key-only iteration.

### vtc-service `0.1.2`

- **Refactored to use vti-common** — Auth, ACL, store,
  error, and config modules now delegate to the shared
  `vti-common` crate.

### vta-sdk `0.1.2`

- **Audit management protocol** — New
  `audit_management` module with types and client
  methods for listing audit logs
  (`list_audit_logs`), querying retention
  (`get_audit_retention`), and updating retention
  (`update_audit_retention`).

### vta-cli-common `0.1.2`

- **Audit commands** — New `cmd_list_audit_logs` (with
  colored table output), `cmd_get_retention`, and
  `cmd_update_retention` commands.
- **Simplified `cmd_list_audit_logs` API** — Accepts
  `&ListAuditLogsBody` directly instead of 8 individual
  parameters.

### pnm-cli `0.1.2`

- **`pnm audit list`** — List audit logs with filtering
  by time range, action, actor, outcome, and context.
- **`pnm audit retention get/set`** — View and update
  audit log retention period.

### Security Documentation

- **Security architecture** (`docs/security-architecture.md`)
  — Comprehensive security architecture document.
- **Threat model** (`docs/threat-model.md`) — Detailed
  threat model analysis.

---

## 2026-03-16

### vta-sdk `0.1.1`

- **Context provision bundle** — New
  `ContextProvisionBundle` type for encoding/decoding
  portable application onboarding bundles (context
  credentials, VTA config, and optional DID material).
- **Pluggable session storage (`SessionBackend` trait)**
  — `SessionStore` now uses a `SessionBackend` trait
  instead of compile-time feature flags. Consumers can
  provide their own storage implementation via
  `SessionStore::with_backend()`. Built-in backends
  (keyring, file, Azure) remain available as trait
  implementations.
- **DID log retrieval** — New `get_did_webvh_log()`
  client method and `GET_DID_WEBVH_LOG` protocol
  constant for retrieving stored DID logs.
- **Context deletion preview** — New
  `preview_delete_context()` and `delete_context()`
  client methods with cascading resource cleanup.
- **Serverless DID creation** —
  `CreateDidWebvhRequest` now supports an optional
  `url` field for serverless DID creation. Response
  includes `did_document` and `log_entry` for
  self-hosting.

### vta-service `0.1.2`

- **Serverless WebVH DID creation (`--did-url`)** —
  Create a DID document and log entry locally without
  a pre-registered WebVH server. Keys are derived and
  stored, and the DID document and log entry are
  returned for self-hosting.
- **Cascading context deletion** — Deleting a context
  removes all associated keys, WebVH DIDs (and logs),
  and cleans up ACL entries. A preview endpoint lets
  callers inspect what will be removed before
  committing.
- **DID log retrieval API** — New
  `GET /webvh/dids/{did}/log` endpoint (REST and
  DIDComm) to retrieve the stored DID log for a given
  WebVH DID.
- **Serverless DIDs now persist data** — Serverless
  DID creation stores the `WebvhDidRecord`, DID log,
  and updates the context DID field, matching
  server-managed behavior.
- **Upgraded to didwebvh-rs 0.3 `create_did()` API**
  — Replaced manual `DIDWebVHState` +
  `create_log_entry` + SCID/DID extraction with the
  high-level `CreateDIDConfig` builder and
  `create_did()`. DID documents now use `{DID}`
  placeholders.

### vta-cli-common `0.1.1`

- **`cmd_context_provision`** — Creates a context,
  generates admin credentials, and optionally creates
  a WebVH DID. Outputs a portable base64 bundle for
  application onboarding.
- **`cmd_context_reprovision`** — Regenerates a
  provision bundle for an existing context. Supports
  selecting an existing VTA-stored key interactively
  or via `--key`, or creating a new admin key.
  Includes full DID material (document, log entry,
  secrets).
- **`cmd_context_delete`** — Cascading delete with
  preview and interactive confirmation.
- **Serverless DID support** in
  `cmd_webvh_did_create` via `--did-url`.

### pnm-cli `0.1.1`

- **`pnm context provision`** — Single command for
  application onboarding with optional DID creation.
- **`pnm context reprovision`** — Regenerate provision
  bundles for existing contexts.
- **`pnm context delete`** — Cascading delete with
  preview and `--force` flag.
- **`pnm webvh create-did --did-url`** — Serverless
  DID creation.

### cnm-cli `0.1.1`

- **`cnm context delete`** — Cascading delete with
  preview and `--force` flag.

### vtc-service `0.1.1`

- **Upgraded to didwebvh-rs 0.3 `create_did()` API**
  — Same refactoring as vta-service for DID creation
  flows.

### Dependency Updates (all crates)

- `didwebvh-rs` 0.2 → 0.3
- `affinidi-tdk` 0.5 → 0.6
- `azure_security_keyvault_secrets` 0.11 → 0.12
- `azure_identity` 0.32 → 0.33
- All compatible transitive dependencies updated to
  latest versions
