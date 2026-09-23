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
2. **(openvtc#371 + #1672)** `openvtc-core` signs; the default flipped and the
   field is deleted. Divergence 2 closes. ✅
3. Bind the 49 tasks in `DISPATCHED_URIS` / `dispatch_typed`, taking
   authorization from the verified signer's ACL entry rather than from a bearer
   token. `auth/authenticate/0.1` and `vtc/relationships/publish/0.2` are the
   two routes that already do this and are the model.
4. Keep each bearer route as a **documented transitional path** with a stated
   removal point, said so in its OpenAPI description — the clients that call
   them today (the admin SPA, `cnm`, `vtc-client`) need the signed path before
   the bearer route can go.
5. Remove them, and close the Appendix F.2 entry.

Steps 3 and 4 are the large ones: 49 routes, three client surfaces, and an
admin SPA that has broken silently on response reshapes before. They are not
one pull request.

One thing to carry into step 3: **VTI-OPS-027** requires the accepted-identifier
record to be shared across every binding. Today's `REPLAY_GUARD` is
process-local and covers only the document dispatcher, so a task served on both
the bearer route and the dispatcher would have a record on one binding and none
on the other. Binding a task in the dispatcher must retire its bearer route, or
the two bindings must share the record.

---

## 7. Requirement → where it is held

| Requirement | Held by |
|---|---|
| VTI-OPS-020 (proof by the issuer) | `spec_policy_for(..).enforce` + the issuer/signer binding in `dispatch_trust_task_core`; tests `vti_ops_020_*` |
| VTI-OPS-021 / -093 (same requirements on every transport) | the same call, reached identically from REST, DIDComm and TSP, and unconditional since #1672; test `vti_ops_021_a_missing_proof_is_refused_on_every_transport` drives one document over all three |
| VTI-OPS-023 (intended recipient) | `validate_basic` + `is_recipient_required` |
| VTI-OPS-024 (acceptance window) | `freshness_policy()`; tests `vti_ops_024_*` |
| VTI-OPS-025 … 027 (replay record) | `REPLAY_GUARD` + `retain_until`; test `vti_ops_020_and_025_a_replayed_document_id_is_refused`. **-027 is not met across bindings** — see §6 |
