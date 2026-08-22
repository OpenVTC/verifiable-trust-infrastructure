# Trust Task version negotiation, and the versioning contract it needs

Status: **Design — not implemented.** Tracked by
[#1045](https://github.com/OpenVTC/verifiable-trust-infrastructure/issues/1045).

Two peers can be built against different versions of the same Trust Task. They
should find a common version and use it, rather than one side guessing and
failing on arrival.

This note covers both halves, because they are one decision: **negotiation is
tractable if and only if versions carry a compatibility contract.** Without one,
"negotiate" can only mean "match exactly or fail" — which is what happens today,
except without the negotiating.

Much of §2 is a proposal for the shared registry
(`trustoverip/dtgwg-trust-tasks-tf`) rather than for this workspace; §5 says
which parts are ours to decide.

---

## 1. What is actually broken

A client hardcodes the version it was compiled against:

```rust
self.dispatch_trust_task(trust_tasks::TASK_VAULT_LIST_0_1, filters, VAULT_TT_TIMEOUT)
```

`vault/list` is published at **0.1, 0.2 and 0.3**. This VTA serves 0.1 and 0.2.
A client built against 0.3 gets `unsupported_type`; over DIDComm that surfaces as
a 30-second timeout with no explanation, which is the failure mode recorded in
`didhosting-083-retired-task-uris`.

The materials to fix it exist and are unused:

| Piece | State |
|---|---|
| Ask a peer what it serves | **exists** — `trust-task-discovery/0.1` (#1042) |
| Parse a URI into `(slug, major, minor)` | **exists** — `TypeUri::{slug, major, minor}` |
| Serve two versions of one family | **exists** — `wire_v0_2`, for one specific shape of change |
| **Choose a version at run time** | **missing** |

## 2. The versioning contract

### 2.1 The problem is 0.x, not the notation

The URI already carries `MAJOR.MINOR` (SPEC §6.1). What it does not carry is a
promise.

`vault/list` 0.1 and 0.3 have **identical payload shapes**. What changed is enum
*values*:

| 0.1 | 0.3 |
|---|---|
| `oauth-tokens` | `oauthTokens` |
| `did-self-issued` | `didSelfIssued` |
| `bearer-token` | `bearerToken` |

That is a breaking wire change shipped as a minor bump, twice — and under semver
it is **not a violation**, because `0.x` explicitly guarantees nothing. The
registry is following semver correctly. Semver at 0.x simply promises nothing,
so nothing is what we can build on.

### 2.2 Proposed: 1.0 is unremarkable

**Drop the 0.x exemption.** A breaking change bumps MAJOR, whatever number that
lands on. A family at `7.2` is fine and honest.

| | rule |
|---|---|
| **MAJOR** | any wire-visible change that is not purely additive |
| **MINOR** | additive only — new **optional** members, new enum variants nothing is required to send |

No grammar change, no flag day: the rule binds the *next* change. A family's next
breaking bump goes to `1.0` rather than `0.4`; existing URIs stay where they are.

### 2.3 Why not `MAJOR.MINOR.PATCH`

Considered and rejected, for two reasons — the second is the substantive one.

**It is a framework grammar change.** `TypeUri::parse_version` does
`split_once('.')` and parses the remainder as `u32`, so `1.2.3` fails to parse.
Changing that means changing SPEC §6.1 for every task in the registry and every
implementation of it.

**A PATCH component carries no negotiation value, and costs identity.** If PATCH
is by definition invisible on the wire, then `1.2.3` and `1.2.4` are
byte-identical — but any matcher comparing Type URIs sees two different tasks.
The URI *is* the wire identity; putting non-wire-visible change into it fragments
that identity for no interop benefit.

And under the variant where MINOR is breaking and MAJOR means "substantial
redesign", both are breaking, so a negotiator must match `MAJOR.MINOR` exactly —
which is today's behaviour. The third component would buy nothing.

### 2.4 The rule needs teeth

Every invariant in this workspace that matters is guarded by a census, and this
one is mechanically checkable from the published schemas: for a MINOR bump,
**every added member is optional, no member is removed, no enum value changes,
and nothing optional becomes required.**

That check belongs upstream, next to the schemas — a minor bump that breaks the
wire is exactly the failure this contract exists to prevent, and a contract
enforced by review is a contract that lapses. Compare
`vta-sdk/tests/inert_alias_census.rs`, which found a third instance of its defect
class on first run.

## 3. Negotiation

### 3.1 The algorithm

Same shape as transport selection, which CLAUDE.md already defines:

> The protocol used is the **highest-preference one present in both parties' DID
> documents**. If the intersection is empty, raise a typed **"no matching
> protocol"** error — never silently downgrade past what a peer advertises.

For task versions:

1. Ask the peer via `trust-task-discovery/0.1` (optionally narrowed by slug glob).
2. Group both sides' URIs by `(slug, major)`.
3. For each slug, take the **highest major present on both sides**; within it,
   the **lower of the two minors**.
4. Empty intersection for a slug the caller needs → **typed error naming the
   slug and both sides' versions**. Never silently fall back.

### 3.2 Why the sender speaks down

The negotiated minor is the **lower** of the two, and the sender encodes at it.
That is what makes the contract work against the schemas as they stand:

- **Old client → new server.** The server accepts the older minor, because
  everything it added since was optional. ✓
- **New client → old server.** Would break — the schemas are
  `additionalProperties: false` and the generated types carry
  `deny_unknown_fields`. **But it never happens**, because the sender negotiated
  down first. ✓

This resolves what looks like a conflict. `deny_unknown_fields` is a security
requirement here — CLAUDE.md mandates it for wire bodies, and #656/#658 are the
scar, where a silently-accepted unknown member minted a super-admin. Tolerating
unknown members to buy forward compatibility would give that up.

**Negotiation removes the need for forward tolerance entirely.** Nobody ever
sends up-version, so nothing ever has to ignore what it does not understand.

### 3.3 The cost, stated plainly

Negotiating down to 1.1 means the client must be able to *encode* 1.1. That is
the real expense, and the additive-only rule is what keeps it bounded: bridging
an additive-only minor is **dropping members**, not rewriting them.

Contrast `wire_v0_2`, which bridges the enum-casing change — and which has to
carve out signed payloads, because rewriting bytes voids the proof. Under §2.2
that change would have been a MAJOR, and majors are not bridged: they are
separate tasks a peer either serves or does not.

### 3.4 Where the negotiated set lives

Per peer, on the client, refreshed when the peer's advertised set could have
changed (reconnect, or on an `unsupported_type` that contradicts the cache).

Two invariants to respect:

- **Nothing on the startup path.** `server::run` must reach its shutdown select
  for a signal to be honoured — negotiation is lazy or backgrounded, never a
  boot-blocking round trip.
- **No latched state** (R6.2). A cached negotiation must be able to go stale and
  be re-derived; `didcomm_websocket_status` reporting "connected" forever after
  boot is the counterexample the guide names.

## 4. What this does not solve

Negotiation answers *"do we both know this task, at this version"*. It does not
answer *"do we agree how the payload is spelled"* — that is #1033, where two
peers both served `contexts/create/1.0` and disagreed about `basePath` versus
`base_path`. A wire change still has to move through the published schema. The
same caveat is already on `VtaClient::supported_trust_tasks`.

## 5. What is ours to decide

- **§3 (negotiation)** is entirely ours. It is client behaviour over an
  already-published discovery task.
- **§2 (the contract)** is a registry decision. `vault/*`, `acl/*`, `keys/*` are
  canonical families in `trustoverip/dtgwg-trust-tasks-tf`, and the deliberate
  direction of #840 and after has been to fold onto them — which means
  inheriting their versioning rules. We can adopt §2.2 unilaterally for
  `spec/vta/*`, our own authority, but the proposal belongs upstream.

Worth checking before proposing: whether the framework already defines
versioning semantics beyond `frameworkVersion`'s "forward-minor compatibility"
note (SPEC §5.2), which concerns the *framework* version rather than a task's.
Twice now the answer to "should we build this?" has been "it already exists
upstream and we were not using it" — `trust-task-discovery/0.1` most recently.

## 6. Open questions

1. **Sequencing.** §3 is implementable today against exact-match semantics and
   gets strictly better once §2 lands. Ship negotiation first, or wait for the
   contract?
2. **Scope of the first cut.** Negotiate every family, or only those published at
   more than one version? Five are today (`vault/{list,get,upsert}`,
   `provision/integration`, `policy/evaluate`).
3. **What a client does with an empty intersection at startup** — refuse to
   connect, or degrade to the subset of operations that did negotiate? The
   transport precedent refuses; a task surface is more granular and may not want
   to.
4. **Whether `spec/vta/*` adopts §2.2 ahead of the registry**, and what it means
   to be stricter than the families we fold onto.
