# Multi-tenant signing — what per-key scoping can and cannot do

**Status:** design review. Recommendations R1–R4 are proposals, not
implemented. Written against #805, having read the VTA's authorization path
and the Cierge gateway that motivated the question.

## The question

The VTA signs the bytes it is handed without inspecting them, so *which keys a
caller may name* is the whole of the authorization story. #805 asked whether
the service actually enforces that. A declined proposal (V1 — have the VTA
*issue* attestations rather than blind-sign, setting `sub` from the caller's
authorized domain) rested partly on the answer being yes.

The concrete worry: **a compromised multi-domain signer signing as any domain
it can name.**

## Finding 1 — the VTA enforces, in three layers

`operations::keys::sign_payload` (`vta-service/src/operations/keys.rs:839-861`),
reached identically by REST, DIDComm `key-management/1.0/sign-request`, and the
`keys/sign` Trust Task:

| # | Gate | Bound to |
|---|---|---|
| 1 | `auth.require_context(ctx)` on the key's `context_id` | the **actor** |
| 2 | `signable_keys` / `quota_for("sign")` on the context policy | the **resource** — applies regardless of actor, *including super-admin* |
| 3 | unscoped keys (`context_id: None`) are super-admin only | the **actor** |

Gate 2 being resource-bound is the load-bearing one for fleet governance: a
VTC- or fleet-pushed policy binds every signer in the context, and the owner
relaxes it through policy CRUD rather than by holding a bigger role.

Confirmed and pinned by three regression tests (#814).

## Finding 2 — authorization cannot solve the stated threat

This is the part that reframes the issue, so it is worth stating plainly.

**A process that legitimately signs for N identities holds authority for N
identities.** Every gate above sits *downstream* of that credential, and none
of them can distinguish "the gateway signing for domain A because a domain-A
request arrived" from "the gateway signing for domain A because it was
compromised". The decision that a given request belongs to domain A is made
*inside* the process, before the VTA is ever called.

So no refinement of the VTA's authorization model — not per-key grants, not
tighter policy, not V1 — prevents a compromised shared signer from signing as
any identity it holds. Only two things do:

- **(i) Don't give one process that credential.** Split, so each process holds
  one identity's authority.
- **(ii) Require a factor the attacker cannot supply** — end-user consent,
  out-of-band ratification. The VTA has these (`vta-policy/src/consent.rs`,
  step-up, `confirm/1.0`), and they are appropriate for high-value discrete
  operations. They are not appropriate per-request on a gateway attesting every
  proxied LLM call.

**(i) is the answer.** Everything below is about making it affordable, and
about fixing a *different*, real gap that surfaced on the way.

## Finding 3 — the VTA's model is already one-principal-per-process

The architecture is consistent about this, and Cierge is the deviation:

- `provision_integration` gives each integration its own DID, ACL entry and
  context. That is the designed unit.
- `vta-mcp` documents itself as "a dedicated, context-scoped vta-mcp (the
  agent's ACL bounds it to its context)" (`vta-mcp/src/main.rs:21`).
- `docs/02-vta/personal-ai-agents.md` provisions each agent its own isolation
  context and ACL grant.

The Cierge gateway shares **one** VTA session across every domain
(`crates/cierge-gateway/src/main.rs:236`), each domain naming its own
`vp_key_id`. Its `[vta]` config carries no context; authority comes from one
bundle DID's single ACL entry. Cross-domain separation there is the in-process
`domain → DomainSigner` map — a process boundary, not an authorization one.

Cierge does not overclaim this. Its threat model says the fix yields "the
ability to **request** signatures while it lasts… revocable by **one** ACL
entry", and §10.7 states that cross-domain separation, structural everywhere
else in cierge, is "only as strong as one process boundary" in the gateway.

**The gap is not that anyone lied. It is that #805's V1 reasoning assumed a
property this deployment's shape does not provide.**

## Why the deviation happened — the cost of doing it right

Worth naming, because it is the thing to fix:

The gateway's session is `connect_didcomm_bundle` — a **DIDComm** session, so
one mediator websocket per identity, and the mediator permits one websocket per
DID. Per-domain sessions therefore mean per-domain DIDs *and* per-domain
websockets. The gateway's own comment justifies the sharing: "Built once, so a
per-request signature is a round trip, not a handshake."

That is a reasonable engineering call given the options available. The correct
pattern was expensive, so a consumer took the cheap one. **Lower the cost and
the correct pattern becomes the easy one** — that is the design lever.

## Recommendations

### R1 — Split the signing path per tenant *(solves #805's threat; Cierge-side)*

Only R1 addresses the stated threat. Two shapes, cheapest first:

**R1a — per-domain REST sessions.** Signing does not need DIDComm. Over REST a
session is a bearer token, not a websocket, so the per-DID websocket ceiling
disappears and N sessions cost N JWTs. Each domain authenticates as **its own**
DID (which it already has — `vp_did`), so gate 1 becomes a real boundary: a
domain-A session physically cannot name domain-B's key.

This is a large improvement for a small change, but note honestly what it does
*not* fix: the gateway process still holds all N credentials, so a full host
compromise still reaches all of them. What it buys is that every path *short of*
full credential theft — a confused-deputy bug, a routing error, a request-
handling flaw that reaches the signer with the wrong domain in hand — is
refused by the VTA instead of served.

**R1b — a signer sidecar per domain.** The credential lives in a separate
process (or container, matching the isolation cierge already applies elsewhere
per B1/§10.6); the gateway holds none. This is what actually closes the
compromise path, at the cost of a process per domain.

R1a is the pragmatic step; R1b is the one that makes the threat-model entry go
away. They compose — do R1a now, R1b if the gateway's attestation surface is
judged worth it.

### R2 — Per-key actor grants in the VTA *(fixes a real gap; needed regardless)*

Today the resource dimension of a grant is expressible **only** as a context.
`AclEntry.capabilities` is a flat `Vec<Capability>` — `Capability::Sign` is
unparameterized — so "this caller may sign with exactly key K" cannot be said.
The only way to scope a caller to one key is to give that key a context of its
own.

That is a genuine least-privilege gap independent of Cierge: any consumer that
needs one key out of a shared context must today be handed the whole context.

The `signable_keys` policy is **not** the answer and should not be reached for:
it is resource-bound by design, constraining the key's context for *every*
actor uniformly. It cannot express "this caller, this key".

Proposal: an optional actor-scoped key filter on the ACL entry, intersected
with — never widening — the existing context scope:

```rust
/// Key ids this entry may invoke the signing oracle on. `None` = every key
/// in `allowed_contexts` (today's behaviour). Intersects with the context
/// scope; it can only narrow, never widen, so an entry naming a key outside
/// its contexts still cannot use it.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub allowed_keys: Option<BTreeSet<String>>,
```

Fail-closed and additive: `None` on every existing row preserves behaviour
exactly, matching how `capabilities` was introduced. Enforced in
`sign_payload` as a fourth gate, after gate 1 so a caller can never name a key
outside its contexts.

### R3 — Token attenuation, if multi-tenant front doors recur *(general primitive)*

The VTA has **no** way to exchange a broad token for a narrower one. Attenuation
exists as a concept in `trust_tasks/task_consent.rs` (an approver cannot
delegate authority it lacks) but not as a session primitive.

For the general shape — one component terminates requests for N tenants and
must act as each — the standard answer is a broker: the broad credential stays
in a small, rarely-changing component, which mints short-lived tokens scoped to
one tenant and hands them to the worker doing the request. It is R1b without a
process per tenant.

**Do not build this for Cierge alone.** R1a solves Cierge. Build it when a
*second* consumer needs the shape — at which point the shape is proven and the
design can be driven by two real call sites instead of one hypothetical. Recorded
here so the next person meeting this does not re-derive it.

### R4 — Write down the architectural rule

"One principal = one DID = one context = one process" is enforced by
convention and by three consistent implementations, but is stated nowhere. A
consumer reading only `docs/02-vta/integration-guide.md` cannot tell that
sharing a session across identities forfeits gate 1. §"What authorizes a sign
request" (added in #814) now documents the per-context granularity; the rule
itself should sit next to it.

## What this does *not* argue

**It is not an argument to reopen V1.** V1 was declined partly on per-key
scoping, and this review shows per-key scoping does not deliver for a shared
signer — but V1 does not either, for the same Finding-2 reason: a compromised
process authenticated as a multi-domain principal would have the VTA issue the
attestation it asks for. The residual V1 *did* address — timestamp and
claim-shape control (backdating, TTL extension) — is untouched by any of this
and still stands on its own merits.

## Summary

| | Solves #805's threat | Effort | Owner |
|---|---|---|---|
| **R1a** per-domain REST sessions | Partly — everything short of credential theft | Low | Cierge |
| **R1b** signer sidecar per domain | Yes | Medium | Cierge |
| **R2** `allowed_keys` actor grants | No — fixes a different, real gap | Low | VTA |
| **R3** token attenuation | Enables R1b cheaply | Medium | VTA, when a 2nd consumer appears |
| **R4** document the rule | No — prevents recurrence | Trivial | VTA |

Related: `docs/02-vta/integration-guide.md` §"What authorizes a sign request",
[`acl-scope-semantics.md`](acl-scope-semantics.md),
[`hierarchical-contexts.md`](hierarchical-contexts.md).
