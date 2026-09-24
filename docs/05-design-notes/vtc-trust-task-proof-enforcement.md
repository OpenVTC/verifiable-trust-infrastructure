# The VTC and the proof its tasks declare

*Design note for [#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/issues/1641).
Covers the second of the two divergences the VTI specification's Appendix F.2
records against `vtc-service` (trustoverip/dtgwg-vti-spec#35): the document
dispatcher accepts a document with no `proof` for a task whose own
specification declares one **REQUIRED**, and applies no acceptance window to
`issuedAt`.*

The first divergence — 49 tasks that declare a proof REQUIRED but are served
only as flat-payload REST behind a bearer JWT — is **not** closed here, and
§6 says why closing it depends on this one.

---

## 1. What the specifications actually require

Four documents bear on this and they agree with each other. None of them is
ambiguous.

**VTI `08-operations.md`.**

- **VTI-OPS-020** — "An operation document MUST identify the operation, the
  issuer, the intended recipient, and the time of issue, and MUST carry a proof
  by the issuer."
- **VTI-OPS-021** — "A node MUST apply the same document requirements on every
  transport. A transport that authenticates its sender MUST NOT be treated as
  relieving a producer of addressing or signing the document it sends."
- **VTI-OPS-024** — "A node MUST refuse a document whose time of issue lies
  outside its acceptance window."
- **VTI-OPS-025 … 027** — every document carries a unique identifier; the
  record of accepted identifiers is kept for the acceptance window and is
  **shared across every binding the node exposes**.
- **VTI-OPS-093** — "A binding MUST NOT weaken the document requirements of
  this chapter on the basis of a property of the transport."

VTI-OPS-021's own rationale states the reason in one sentence: transport-level
sender authentication says *who opened this connection*; a document proof says
*who authored this document, what it covers, and to whom it was addressed*, and
"only the second survives the message being stored, forwarded, replayed on
another transport, or produced in evidence afterwards."

**Trust Tasks SPEC §7.2 item 7.** "If the *Trust Task specification* identified
by `type` declares `proof` as **REQUIRED** … and no `proof` is present, reject
the document with `proofRequired`." The clause is unconditional and names no
transport.

**Trust Tasks SPEC §9.1.1.** A transport binding *may* permit `proof` to be
omitted, but only by publishing a security profile addressing eight named
properties — and "**Silence is not permission.**" A binding that does not
address omission "**MUST NOT** be read as permitting it".

**The DIDComm binding (`bindings/didcomm/0.2`), §5.** This is the one that
settles it, because it is the binding the lenient path was resting on:

> A *Trust Task specification* that declares `proof` as **REQUIRED** overrides
> this binding-level allowance: the in-band `proof` is mandatory regardless of
> transport, because such specifications produce documents intended to be
> replayable past the original transport hop.

And §6, on where the transport's guarantee stops:

> At the message. The envelope is discarded on unwrap, and the guarantee does
> not travel with the document.

That is the whole argument, stated by the transport's own binding: authcrypt
tells this service who handed it the bytes. It leaves nothing behind that a
third party — an auditor, a registry, the member themselves — could check
afterwards.

### 1a. What transport attribution *is* permitted to substitute for

SPEC §4.8.1 is precise about this, and it is narrower than the lenient path
assumed.

1. **Where an in-band member is present**, it is authoritative, and the
   transport-derived identity is *only a cross-check*. Where both exist they
   MUST be consistent, and a mismatch is a validation failure (§7.2 item 6).
2. **Where an in-band member is absent**, the consumer MAY derive the party
   identity from the transport and treat the derived value as if it had been
   carried in-band.

So transport attribution substitutes for **an absent `issuer` or `recipient`
member** — nothing else. A `proof` is not a party identity; it is an integrity
and attributability artefact over the document's bytes. §4.8.1 offers no rule
under which an authenticated transport peer stands in for one, and §7.2 item 7
resolves the proof requirement from the *specification*, with no transport term
in it at all.

The lenient rule this note replaces read §4.8.1's clause 2 as though it covered
`proof`. It does not, and the two clauses it does cover are enforced here
unchanged.

---

## 2. What the VTC actually binds — re-derived

`vtc-service/src/routes/mod.rs` is the single mount site for REST task routes
(`tt()` / `ttl()`; no other module calls `task_routes` / `task_layer`), and it
names its Type URIs as literals. Joining those against
`trust_tasks_rs::schema_index::spec_policy_for` (trust-tasks-rs 0.21.17):

| | count |
|---|---|
| distinct task URIs mounted on REST routes | **95** |
| of those, declaring `proof` REQUIRED | **51** |
| of those, declaring `issuedAt` REQUIRED | 52 |
| of those, declaring `recipient` REQUIRED | 94 |
| with no published spec policy in this build | 1 — `vtc/relationships/persona/0.1` |

Two of the 51 already verify a document proof on their REST route
(`auth/authenticate/0.1` and `vtc/relationships/publish/0.2`) and are the model
the migration follows. **That leaves 49 proof-REQUIRED tasks served on a bearer
token** — divergence 1.

Of those 49, eleven now have a signed-document binding (§6b, batches 1–5). The
divergence closes per task when the bearer route goes, not when the signed door
opens, and for two of the eleven it has: batch 3 removed the bearer routes of
`vtc/config/{export,import}/0.1` in the same change, because nothing called
them. **47 remain**, nine of them with a signed door beside a still-mounted
bearer route.

### Drift against the recorded entry

The Appendix F.2 entry and #1641 record **48** (30 community + 17 canonical +
`vtc/auth/admin-session/0.1`). Re-deriving gives 49. The difference is exactly
one task, added after the entry was written:

- **`vtc/invitations/deliver/0.1`** — bound by #1648.

No other drift: all 48 recorded URIs are still mounted, still declare `proof`
REQUIRED, and still carry no document proof. The count is a **floor that grows
with each new admin route**, which is itself the argument for closing the
divergence at the dispatcher rather than route by route.

### The dispatched set

`DISPATCHED_URIS` plus `vti_rooms::wire::ROOMS_DISPATCHED_URIS` — 26 URIs:

| URI | proof | issuedAt | recipient |
|---|---|---|---|
| `vtc/join-requests/submit/0.2` | **REQ** | REQ | REQ |
| `vtc/join-requests/status/0.1` | **REQ** | – | REQ |
| `vtc/join-requests/withdraw/0.1` | **REQ** | REQ | REQ |
| `vtc/join-requests/supplement/0.1` | **REQ** | REQ | REQ |
| `vtc/members/self-remove/0.1` | **REQ** | REQ | REQ |
| `vtc/members/vmc/0.1` | **REQ** | REQ | REQ |
| `vtc/members/personhood/assert/0.1` | **REQ** | REQ | REQ |
| `vtc/vetting/revoke-statement/0.1` | **REQ** | REQ | REQ |
| `vtc/vetting/vetters/grant/0.1` | **REQ** | REQ | REQ |
| `rooms/*` (11 tasks) | **REQ** | REQ | REQ |
| `vtc/join-requests/manifest/{0.1,0.2}` | – | – | REQ |
| `vtc/vetting/vetters/{profile,list,resend}` | – | profile only | REQ |
| `vtc/members/personhood/challenge/0.1` | – | – | REQ |

Twenty of the twenty-six declare `proof` REQUIRED. The eleven `rooms/*` arms
already refused without a verified signer, each handler having done so for
itself before the spine took over verification. **The nine `vtc/*` rows above
are the ones the spine was lenient about.**

Since then the set has grown by the tasks §6b's batches move onto this binding
— four in batch 1, two in batch 2 (`vtc/join-requests/decide/0.1`,
`vtc/community/profile/update/0.1`), two in batch 3
(`vtc/config/{export,import}/0.1`), two in batch 4
(`vtc/endorsement-types/{register,delete}/0.1`) and one in batch 5
(`vtc/backup/export/0.1`), making thirty-one proof-REQUIRED. The
count is asserted by
`the_dispatched_set_declares_the_proofs_the_design_note_records`, so a batch
that lands without updating this note fails a test.

---

## 3. Which producers sign, and which do not

The question that decides whether enforcement is a tightening or an outage.

| Producer | Tasks | signs? | `issuedAt`/`issuer`/`recipient` | transport |
|---|---|---|---|---|
| `vta-sdk` `VtaClient::dispatch_trust_task` | any | **yes**, always (`signed_task_document`); an identity-less client is refused before it sends | yes | REST, DIDComm, TSP |
| `vtc-client` `submit_join_as` | submit | **yes** (`build_signed_with`), and on the session path too — it delegates to the SDK above | yes | REST + session |
| `pnm-browser-plugin` `@pnm/core` | submit, status, vmc, self-remove | **yes**, on all three channels; a channel cannot be constructed without a signer | yes | REST, DIDComm, TSP |
| `openvtc-core` **vetting** | `vetting/revoke-statement` | **yes** (`capabilities::sign_document`, eddsa-jcs-2022) | yes | DIDComm |
| `openvtc-core` **join / members / personhood** | submit, status, self-remove, vmc, personhood/assert | **now yes** — openvtc#371, via `trust_task_doc::build_signed_value`. Before it: deliberately unsigned, the builder's own comment saying "no `proof` is attached", relying on the authcrypt sender or the TSP sender VID | yes | DIDComm, TSP |

Two findings fall out of the table.

**It is not a specification problem.** The brief asked whether any task requires
a proof that no client can produce. None does: `openvtc-core` already signs
Trust Task documents — `capabilities::sign_document` is the same
`eddsa-jcs-2022` primitive, used on the vetting path in the same crate. The
five unsigned producers are a deliberate choice made under the older reading of
the DIDComm binding, not a missing capability. **No upstream change is needed.**

**`join-requests/{withdraw,supplement}` have no client producer at all** —
only handlers, tests and generated bindings reference them. Enforcing on those
two costs nothing today.

So the break was precisely: `openvtc-core`'s join, status, self-remove, VMC and
personhood-assert paths. Everything else already sent what the specification
asks for. **openvtc#371 closed it**, which is what let #1672 remove the switch
§4 describes; a community still serving an `openvtc` build older than that has
those five paths refused and must upgrade the client.

---

## 4. What this change enforces

In `dispatch_trust_task_core`, in order, before any handler runs:

1. **`validate_freshness`** against a policy of `max_age = 10 min`,
   `skew = 60 s` (SPEC §4.2's own "typically ≤ 60s"), `issuedAt` required.
   Refuses a future-dated `issuedAt` and an `expiresAt` at or before it as
   `malformedRequest` (§7.2 item 13 — neither was *ever* acceptable, so
   `expired` would misdescribe them), and a document older than the window as
   `expired`. **VTI-OPS-024.**
2. **`validate_basic`** — expiry and the recipient binding, as before.
3. **`spec_policy_for(type_uri).enforce(doc)`** — the flag-driven rules the
   *specification* declares: `recipient` REQUIRED (item 5b), `proof` REQUIRED
   (item 7a), audience binding (item 8), `issuedAt` REQUIRED (§7.3 item 17).
   Read off the generated bindings by URI; there is no list of task URIs in
   this repository to drift from the registry.
4. **Proof verification**, when a proof is present, now additionally bound to
   the document's `issuer` — §4.7 requires the `verificationMethod` to resolve
   to material controlled by the issuer, and without the check a valid proof by
   *any* DID satisfied the requirement. This closes a real hole rather than
   restating one: `verified_signer` is what the `rooms/*` arms authorize
   against.
5. **The replay record**, unchanged in mechanism but now *bounded*. It was
   claimed under a policy whose own documentation said "retention only — this
   is not an acceptance policy and must not become one". §7.2 (*Bounding the
   record*) makes that separation unavailable: acceptance and retention are one
   bound. `retain_until` now caps a producer-chosen `expiresAt` at
   `issuedAt + max_age + skew`, so a document stamped `expiresAt = now + 10
   years` can no longer pin an id for ten years. **VTI-OPS-025 … 027.**
   *(Step 1a replaced the mechanism: the record is now store-backed and
   shared across bindings, which is what -027 requires. The cap is
   unchanged. See §6a.)*

All five steps are **unconditional**. There is no configuration that relaxes
any of them.

### The gate that used to be here, and how it went away

#1641 shipped step 3's `proof`-REQUIRED refusal behind `[trust_tasks]
require_declared_proof`, default `false`. It governed exactly that one refusal,
it applied only where the transport had authenticated the sender (so a REST
document with no proof was refused whatever the setting), and every waiver
logged at `warn!` naming `VTI-OPS-021` and the task URI.

It existed because this repository could not land the `openvtc-core` change in
the same pull request, and turning it on with such a client in the field would
have refused every join, every status poll and every VMC collection on that
community. Its removal condition was written down and exact: *when
`openvtc-core` signs the five documents in §3, the default flips and the field
goes with it.*

**openvtc#371 signs them** — all five now go through
`trust_task_doc::build_signed_value` — so #1672 did both: the default flipped
and the field is gone. Divergence 2 is closed rather than merely visible.

Nothing should put a switch back. VTI-OPS-093 forbids a binding weakening a
document requirement on the strength of a transport property; a per-deployment
setting that lets an operator do it is the same weakening reached by a longer
path.

### What a config still carrying the key does

The key is retired, not ignored — the two values were different intents and are
answered differently:

| in `config.toml` | what happens |
|---|---|
| `require_declared_proof = true` | a warning at load naming the retired key, then a normal start. It asked for the behaviour that is now the only behaviour, so nothing is lost; the line should be deleted. |
| `require_declared_proof = false` | **the config fails to load**, with an error naming openvtc#371 and saying the client must be upgraded. That intent cannot be honoured, and starting anyway would enforce the opposite of what the file says. |
| absent | nothing. This is the state to arrive at. |

The refusal lives in the deserializer (`refuse_disabling_declared_proof`), so it
holds on every path that parses an `AppConfig`. The warning lives in
`AppConfig::load` and goes to stderr rather than `warn!`, because config loads
before `init_tracing` and a `warn!` with no subscriber is exactly the silence
this is meant to avoid.

### Rollout

A deployment running an `openvtc` build older than openvtc#371 sends those five
documents unsigned, so after this change its joins, status polls,
self-removals, VMC collection and personhood assertions are refused with
`proofRequired` — correctly, but abruptly, and there is no setting that will
accept them. **The fix is to upgrade the client.** A deployment that already
set the flag to `true` has been running this behaviour since #1641 and is
unaffected; it has one line to delete.

---

## 5. What is deliberately *not* enforced at the spine

**The transport cross-check (§7.2 item 6, §4.8.1 clause 1)** — comparing the
in-band `issuer` against the transport-derived sender — stays in the handlers
(`resolve_holder`), not the spine. A spine-level comparison would refuse the
**relayer ≠ holder** shape this workspace supports deliberately: in
provision-integration the outer transport authenticates a relayer while the
inner proof authenticates the holder, and they may legitimately differ. The
handlers that need the two to be the same party say so, and do.

**Divergence 1's 49 REST routes.** Untouched. See §6.

---

## 6. The migration path for divergence 1

Divergence 1's resolution is "bind each of these tasks in the document
dispatcher". That closes nothing while the dispatcher does not enforce — the
tasks would simply arrive somewhere else and still be accepted unsigned. This
change is therefore its precondition, and the order is:

1. **(#1641)** the spine can enforce, and does, for everything but the gated
   case. ✅
1a. **(#1674)** the accepted-id record moves into the store, so any binding can
   consult it — the precondition step 3 would otherwise defeat. See §6a.
2. **(openvtc#371 + #1672)** `openvtc-core` signs; the default flipped and the
   field is deleted. Divergence 2 closes. ✅
3. Bind the 49 tasks in `DISPATCHED_URIS` / `dispatch_typed`, taking
   authorization from the verified signer's ACL entry rather than from a bearer
   token. `auth/authenticate/0.1` and `vtc/relationships/publish/0.2` are the
   two routes that already do this and are the model. **In batches — see §6b.**
4. Keep each bearer route as a **documented transitional path** with a stated
   removal point, said so in its OpenAPI description — the clients that call
   them today (the admin SPA, `cnm`, `vtc-client`) need the signed path before
   the bearer route can go. The admin SPA is the one with no path at all, and
   it blocks 34 of the 49; how it gets one is
   [`vtc-console-signing.md`](vtc-console-signing.md).
5. Remove them, and close the Appendix F.2 entry.

Steps 3 and 4 are the large ones: 49 routes, three client surfaces, and an
admin SPA that has broken silently on response reshapes before. They are not
one pull request.

### 6a. Why the record had to move first (step 1a)

**VTI-OPS-027** requires the accepted-identifier record to be shared across
every binding a node exposes. The `REPLAY_GUARD` #1659 left in place was an
in-process `InMemoryReplayGuard` reachable only from
`dispatch_trust_task_core`, which is adequate while the dispatcher is the only
door and stops being adequate the moment step 3 makes a task reachable through
two. A task bound in the dispatcher *and* still served on its bearer route
would keep a record on one and none on the other, and the specification's own
rationale says what that is worth: "the node's replay protection is exactly as
good as its least-used transport."

So this is **not** something to carry into step 3 — doing it in the same pull
request as the first batch means the migration itself opens the hole. It is
step 1a, and it is done:

- The record is `crate::trust_tasks::accepted_ids`, backed by the
  `accepted_ids` keyspace, and any binding reaches it as
  `state.accepted_ids()`. `AcceptedIds::claim` returns `Acceptance::{Fresh,
  Duplicate, Conflict}`; a `Fresh` claim is settled with
  `AcceptedClaim::{completed, release}`. Each phase-2 call site is that
  match, not a redesign.
- It is bounded by the acceptance window (`retain_until` still caps a
  producer-chosen `expiresAt` at `issuedAt + max_age + skew`) and swept on the
  retention sweeper's tick, because a keyspace has no capacity eviction to
  bound it the way the in-memory map did.
- Claim-and-insert is atomic **within the process**, which is the whole scope
  in which two claims can race: fjall holds an exclusive lock on the store
  directory, so a second process cannot open it. It is *not* cross-replica, and
  no shared store backend exists for the VTC to make it so. A replicated VTC
  would double-execute; closing that needs a native conditional write at the
  store layer (Redis `SET NX`, DynamoDB `ConditionExpression`) behind a new
  `KeyspaceHandle` primitive, at which point `claim` becomes one call to it.

What step 3 must then do at each site: take the claim **before** the effect,
settle it after, and refuse `Conflict` as `idConflict` — not "check whether the
id was seen". A check-then-act at the route is the TOCTOU the claim exists to
close.

---

### 6b. Step 3, batch by batch

**Batch 1 — the admin-facing member verbs.** `vtc/members/credentials/0.1`,
`vtc/members/update/0.1`, `vtc/members/admin-remove/0.1` and
`vtc/members/purge/0.1` are bound in `DISPATCHED_URIS` / `dispatch_typed`.
Authority is `admin_signer`'s read of the verified signer's ACL row
(`crate::acl::resolve_auth_role`) at execution time. `purge` additionally
demands an unrestricted `ActScope` — `AuthClaims::require_super_admin`, the
same question `SuperAdminAuth` asks — because its bearer route demanded a
super-admin and a gate copied one notch loose is the failure mode this whole
migration risks.

The batch is four rather than more because the work is not the binding: it is
lifting each route handler's body into a transport-free inner that both doors
call, so the two cannot answer differently. `members/update` was kept in
despite #1645's reshaping of it: the `adminRoleForbidden` refusal happens
before anything is read, and it is the *promotion* path — the only part that
consults a session — that the refusal makes unreachable, so a session-less
caller has nothing to lose.

**Both doors stay open, and that does not open a replay hole.** §6a's concern
is a document accepted on one binding being acceptable on another. It does not
arise here, and the reason is worth writing down rather than re-deriving: the
bearer routes take a **flat payload and a JWT**, not a document. They have no
`id` to claim, and a captured signed document cannot be presented at them at
all — there is no body shape that would carry it. The two doors are disjoint in
credential type, so there is nothing for them to share. A batch that moved a
task onto a *second document* binding would be a different matter, and would
have to claim through `state.accepted_ids()` like the spine does.

**The signed door is the governed unauth chain**, so every task moved onto it
inherits that chain's per-IP rate limit (5/s, burst 10) and its 64 KiB body cap
rather than the authenticated chain's 1 MB. That is the right place for a
document whose authentication is in the document, but it is a real difference:
an admin operation carrying a large payload — `members/update`'s `extensions`
bag is the one in this batch — can fit on one door and not the other. Each
batch should check its verbs against 64 KiB rather than assume.

**The removal point for the bearer routes** is stated in each one's OpenAPI
description and is the same: the admin console cannot sign. `vtc-service/
admin-ui/src` has no signing primitive of any kind — no `eddsa-jcs-2022`, no
Ed25519, no `crypto.subtle.sign` — and its second factor is a passkey, which is
WebAuthn and cannot produce the Data-Integrity proof these documents need. So
the console holds no key with which to author a Trust Task document, and
retiring its routes before it has one would take the member surface out of the
admin UI entirely. `cnm`/`vtc-client` reach the same four routes with a bearer
session and are in the same position.

**Batch 2 — the join decision and the community profile.**
`vtc/join-requests/decide/0.1` and `vtc/community/profile/update/0.1`, on the
same terms: bound in `DISPATCHED_URIS` / `dispatch_typed`, each route body
lifted into a transport-free inner both doors call, authority from
`admin_signer`'s read of the verified signer's ACL row. Two batch-specific
findings are worth keeping:

- **Neither task's bearer route applies a gate beyond `AdminAuth`.** No
  super-admin bar, no context scoping, no vetter/admin split — a VTC community
  is one scope, and `resolve_auth_role` admits only `VtcRole::Admin` in any
  case, so `admin_signer` returning at all *is* `AdminAuth`. The difference is
  the same one batch 1 found and no other: the ACL row is read at execution
  time rather than copied into a token at login, so an expired or removed row
  refuses here and would not have refused there.
- **`decide` is the first migrated verb whose second execution would be
  materially wrong**, rather than merely redundant: approving issues a
  membership credential and a role endorsement, so a replayed decision would
  issue two of each. Nothing was added at the handler for it. The spine's claim
  already covers it — claim before dispatch, settle after, and a `Duplicate`
  answered with the recorded response without re-entering the arm — and a
  handler-level "have I seen this?" would be exactly the check-then-act the
  claim exists to replace. The `notPending` refusal stays what it was: the
  answer to a *different* decision aimed at an already-decided request.
  `vti_ops_025_a_replayed_decision_does_not_issue_a_second_credential` drives
  it through the issuance path and counts the credentials.
- **One divergence surfaced, pinned rather than fixed.**
  `vtc/community/profile/update/0.1` says its nullable members may be set to
  `null` to clear them; they cannot be, because `CommunityProfileUpdate` types
  them `Option<Option<String>>` with no double-option deserializer and serde
  folds `null` onto the outer `None`. It is the store's behaviour rather than
  the transport's, so it predates this binding and holds identically on the
  bearer route — what this batch owes is that the two doors agree, and they
  do. `an_explicit_null_does_not_yet_clear_a_nullable_member` pins it.

**The 64 KiB body cap, checked for `community/profile/update`.** It is the one
verb moved so far that carries operator-authored content, so §6b's instruction
to check rather than assume applies. Every field the operation accepts is
capped by `CommunityProfileUpdate::apply` before anything is written — `name`
200 characters, `description` 4 000, `logoUrl` 2 048 and constrained to
`http(s)` so a `data:` image cannot ride in it at all, `contactEmail` 320, and
the `extensions` bag 16 KiB **measured serialised**. Their sum, taken at the
worst UTF-8/escape expansion, is about 44 KiB, and a realistic maximal profile
is nearer 25 KiB; the document envelope and its proof add roughly 1.5 KiB. So
64 KiB is enough, with room, and the cap refuses with 413 rather than
truncating — a large-but-valid update is never silently shortened. Three
members are *not* capped (`publicUrl`, `personhood.governanceFrameworkUrl`,
`personhood.acceptedIdvps`), so the payload is unbounded in principle although
no legitimate value approaches the cap; all three are published on the
unauthenticated public-profile endpoint, which is the same stored-payload
argument the existing caps were added for, and capping them belongs in a change
about that rather than in a transport migration.

**Batch 3 — the portable-configuration pair, and the first bearer routes
removed.** `vtc/config/export/0.1` and `vtc/config/import/0.1` are bound in
`DISPATCHED_URIS` / `dispatch_typed` on batch 2's terms: authority from
`admin_signer`, and the bearer routes applied exactly `AdminAuth`, so a
context-scoped admin is admitted and a member refused. What differs:

- **The bearer routes are gone, not transitional.** Batches 1 and 2 kept theirs
  because the admin console reaches them. It does not reach this pair — there
  is no screen for either (`vtc-console-signing.md` §7) — and neither
  `vtc-client`, `cnm` nor openvtc calls them. A route with no client has no
  removal point to wait for, so `POST /v1/admin/config/{export,import}` were
  deleted in the same change and the divergence is closed for both tasks. The
  REST integration suite (`tests/admin_config.rs`) was ported to signed
  documents rather than dropped; the one test not ported held that a stale
  `?confirm=true` query parameter does not apply, and a document has no query
  string.
- **`ext` was refused on both levels.** The route's hand-written
  `ImportRequest` and `ConfigExportDocument` were `deny_unknown_fields`
  without the `ext` members the published schema gives the payload and the
  document, so a schema-valid import carrying either was refused as malformed.
  Both now accept and ignore it. The bearer route also accepted documents the
  schema refuses (`"communityProfile": null`, `"extensions": null`); the signed
  door validates the payload against the schema first, so those are refused
  now, as the specification says they should be.
- **64 KiB is enough.** The payload is a community profile and at most five
  small config overrides, and the profile is batch 2's, measured above at
  about 44 KiB worst case. An import whose profile is over those caps would
  have been refused by `CommunityProfileUpdate::apply` anyway — with one
  exception, below.
- **One pre-existing gap recorded here, fixed separately.** When no profile was
  stored, `apply_profile_import` wrote the imported one verbatim instead of
  through `CommunityProfileUpdate::apply`, so none of that function's caps
  applied — including the `http(s)`-only `logoUrl`. Boot heals a missing
  profile whenever `vtc_did` is configured (`server.rs`), so the path was
  reachable only on a VTC with no identity yet. It was a validation gap in the
  import rather than the transport, so it was fixed in its own change: every
  import now applies the patch, to a default profile when none is stored
  (`an_import_with_no_stored_profile_meets_the_edit_caps`).

**Batch 4 — the endorsement-type writes, and the console's first signed
calls.** `vtc/endorsement-types/register/0.1` and
`vtc/endorsement-types/delete/0.1` are bound on the same terms; `list` declares
no proof and stays on its bearer route. The console's statement-types card
calls both, so here the bearer routes stay — but the card now sends each write
through `signedOrBearer`, the first console call site to do so: a browser with
a console key uses the signed door, and one without falls back. Findings:

- **`claimSchema` had no bound at all**, in the task or the route, so a schema
  between ~63 KiB and 1 MB registered over bearer and could not fit a signed
  document — and `signedOrBearer` deliberately does not fall back on a
  refusal. The operation now caps it at 32 KiB serialised on both doors
  (`CLAIM_SCHEMA_MAX_BYTES`), refused as `malformedRequest`.
- **`description`'s published `maxLength: 1024` was not enforced** on the
  bearer route; the signed door's schema check already held it. Both enforce
  it now.
- **A declared framework code panicked the dispatcher.** `register` refuses a
  `claimSchema` that is not a JSON Schema with `malformedRequest`, carried as a
  `TaskError::declared` so the bearer route can put the code in its body. The
  spine's `task_error_to_reject` read every declared code as `<slug>:<local>`
  and panicked on it. It now parses the code as the framework does
  (`declared_code`), so a standard code goes out as itself. Nothing had bound
  such an operation on the signed door before, which is why it had not fired.
- **An absent `claimSchema` stays absent.** The generated payload folds absent
  into an empty map; the arm reads the raw payload as the route's
  `RegisterBody` so the stored row records what was sent.

**Batch 5 — the backup export, without its import.** `vtc/backup/export/0.1`
is bound on the same terms, with the one gate batch 1 introduced for `purge`:
the bearer route took `SuperAdminAuth`, so the signer's entry must be an
unrestricted admin (`require_super_admin`) and a context-scoped admin is
refused. Its bearer route stays, because `vtc-client` calls it; the console
has no backup screen. Findings:

- **The request fits; the reply is recorded.** The payload is a password and a
  flag. The reply is the whole encrypted envelope, and the spine records a
  successful reply against the document's `id` — so a redelivery is answered
  with the same envelope rather than a second export under a fresh salt and
  nonce (`vti_ops_025_a_redelivered_export_answers_with_the_same_envelope`), at
  the cost of a second, password-encrypted copy of the backup in
  `accepted_ids` for the acceptance window. That keyspace is excluded from
  backup, so a copy cannot end up inside a later export.
- **The password is in a signed, unencrypted document**, which is no worse
  than the bearer route's body: REST is TLS, DIDComm and TSP encrypt end to
  end, and the spine records a document's identifier and digest, never its
  payload.

**`vtc/backup/import/0.1` stays on bearer, and the fix is a chunked transfer.**
Its request carries the whole envelope inline, which a 64 KiB document cannot
hold for any real community, and raising the cap is not the answer: the signed
door is the unauthenticated chain until the proof is checked, so a large cap
there is a lever for anyone. The shape that fits the binding is a transfer
session of several documents, each small, each signed and replay-recorded:

1. `…/import/begin` — the envelope's metadata (`version`, `format`,
   `sourceDid`, KDF and cipher parameters), the ciphertext's total length, the
   chunk count and its SHA-256. Answers a session id; stages nothing yet.
2. `…/import/chunk` × *n* — session id, index and a slice of the ciphertext,
   each document well under 64 KiB after encoding (≈ 40 KiB of ciphertext per
   chunk leaves room for base64 and the envelope). Staged server-side under a
   TTL; a chunk out of range, repeated with different bytes, or for an
   expired session is refused.
3. `…/import/commit` — session id, password and `confirm`. Reassembles,
   checks the digest named at `begin`, then runs today's preview-or-apply
   unchanged.

Every document in the session must come from the same signer, and the
super-admin bar is checked at `begin` and again at `commit`, where the effect
happens. `export` has the mirror problem on the messaging transports, where a
reply the size of the backup may exceed what a mediator carries; a chunked
export is the same design read backwards. This is a new task family, so it is
proposed in dtgwg-trust-tasks-tf first and reaches this workspace through a
`trust-tasks-rs` bump — the dispatcher cannot bind a family whose schema is not
published.

**Next batch.** `vtc/admin/invites/{create,revoke}` are the same admin-from-ACL
shape, and become available once the `vtc/invitations/*` work owned elsewhere
lands. Before keeping a batch's bearer routes, check who calls them — batch 3
found nobody did — and where the console does, move its call sites to
`signedOrBearer` in the same batch, as batch 4 did. The bearer routes kept for
`vtc-client` (batch 5's `backup/export`, and the members verbs it reaches) go
once that client signs.

---

## 7. Requirement → where it is held

| Requirement | Held by |
|---|---|
| VTI-OPS-020 (proof by the issuer) | `spec_policy_for(..).enforce` + the issuer/signer binding in `dispatch_trust_task_core`; tests `vti_ops_020_*` in `spine_proof_tests` and `members_admin_tests`. For a migrated task the issuer is also the *authorization*: `admin_signer` reads their ACL entry — §6b |
| VTI-OPS-021 / -093 (same requirements on every transport) | the same call, reached identically from REST, DIDComm and TSP, and unconditional since #1672; test `vti_ops_021_a_missing_proof_is_refused_on_every_transport` drives one document over all three |
| VTI-OPS-023 (intended recipient) | `validate_basic` + `is_recipient_required` |
| VTI-OPS-024 (acceptance window) | `freshness_policy()`; tests `vti_ops_024_*` |
| VTI-OPS-025 / -026 (replay record, bounded) | `trust_tasks::accepted_ids::AcceptedIds` + `retain_until`; tests `vti_ops_025_*` / `vti_ops_026_*` in `accepted_ids`, `spine_proof_tests` and `members_admin_tests` — the last drives them through a verb with a real effect |
| VTI-OPS-027 (record shared across bindings) | the same type, backed by the `accepted_ids` keyspace rather than a process-local map, reachable from any binding as `AppState::accepted_ids`; test `vti_ops_027_a_second_binding_sees_what_the_first_accepted`. Atomic within the process, **not** across replicas — see §6a |
