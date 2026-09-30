# VTC Ceremony Catalog — Instances of the Pipeline

**Status:** Design proposal (for review) · **Parent:** [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md)
**Purpose:** Prove the one pipeline generalizes by running four maximally-different ceremonies through it, then
map the remaining purposes. If the abstraction only ever served *join*, it would be over-engineering. These four
exercise it along every axis that matters.

> **Notation.** Bare `§N` references are to [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md). MVP
> references are written `vtc-mvp.md §N`.

---

## 1. The validation matrix

The four ceremonies are chosen to differ on *every* axis — if one pipeline handles all four, it handles the rest.

| Ceremony | Trigger / `actor` | `actor` = `subject`? | Evidence | Effects | Hard invariant | Threaded? | Direction |
|---|---|---|---|---|---|---|---|
| **Join** | applicant (unauth) | **yes** | VP (invitation? / credentials?) | issue VMC + VAC, write ACL+Member | privilege ceiling | yes | constructive |
| **Leave** | member (self) **or** admin | **no** (admin case) | disposition choice / removal reason | revoke VMC, apply disposition, registry departure | no-last-admin | optional | **destructive** |
| **Role-change** | admin | **no** | target + desired role (+ step-up) | re-issue VAC, update ACL role | privilege ceiling + step-up | optional | **mutating** |
| **Directory** | any member (a query) | **no** | the query (fields requested) | return a **field projection** (no write) | PII boundary | **no** (sync) | **read-only** |

Join is constructive/self/threaded; Leave inverts it (destructive/other/one-shot); Role-change is in-place
mutation with an escalation guard; Directory is a stateless read that returns a *filter*, not a boolean. All four
are the **same** `verify → facts → evaluate → verdict → effects` pipeline with different plug-ins.

---

## 2. Join (onboarding)

The canonical evidence-bearing ceremony. Full treatment because it exercises all four verdicts.

- **Trigger:** applicant, unauthenticated, rate-limited. `actor` = `subject` = the applicant.
- **Evidence:** a VP — optionally an `InvitationCredential` (VIC) and/or other credentials.
- **Routes (policy):** first-match over `evidence`. e.g. `has_valid_invitation → allow(role from invitation)`;
  `statement_trusted("https://registry.trustoverip.org/dtg/vsc/witnessed/1") AND agreed("code-of-conduct") → allow(member)`;
  `statement_trusted("https://registry.trustoverip.org/dtg/vsc/witnessed/1") → request_more(code-of-conduct)`; else `refer(moderator)`.
- **Verdict realization:** `allow` ⇒ admit; `request_more` ⇒ return a PD; `refer` ⇒ moderator queue;
  `deny` ⇒ reject.
- **Effects (allow):** allocate status-list index → mint VMC + role VAC → write ACL + Member → sealed-transfer →
  audit. Obligation `reciprocate_vmc` (the member counter-signs → bidirectional DTG edge).
- **Invariant:** privilege ceiling — join never grants `admin`.

**Worked example (request_more → allow), facts round 1:**

```jsonc
{ "purpose":"join", "now":"…",
  "actor":   { "did":"did:key:z6MkHuman", "authenticated":true },
  "subject": { "did":"did:key:z6MkHuman" },
  "context": { "community_did":"did:webvh:acme.example", "channel":"rest", "member_count":1421 },
  "evidence":{ "invitation":null,
    "presentation":{ "verified":true, "holder":"did:key:z6MkHuman",
      "credentials":[ { "type":"StatementCredential", "predicate":"https://registry.trustoverip.org/dtg/vsc/witnessed/1", "issuer":"did:webvh:notary.example",
                        "issuer_trusted":true, "status":"valid", "claims":{"kind":"proximity"} } ] } },
  "state":   { "subject_member":null } }
```

A DTG statement's `type` fact is `StatementCredential` whatever it says; its
meaning is the `predicate` fact (`credentialSubject.predicate`), so a policy
matches a witness with `statement_trusted("https://registry.trustoverip.org/dtg/vsc/witnessed/1")`,
never with a type string. The host refuses a presented statement under a
predicate the community does not accept before policy runs.

Witness present, agreement absent → first-match yields `{"effect":"request_more","with":{"needs":["agreed:code-of-conduct"],
"presentation_definition":{…}}}`. Round 2 (same thread) carries the agreement → `{"effect":"allow","with":{"role":"member",
"obligations":["reciprocate_vmc"]}}`.

---

## 3. Leave / Exit (offboarding) — *the inverse of join*

The second ceremony, chosen to invert join. Maps to MVP `removal` (`vtc-mvp.md` §10.2).

- **Trigger:** the **member** (voluntary self-exit) **or** an **admin** (involuntary removal). So `actor` may be
  the subject or a third party — the pipeline carries both in `actor`/`subject`.
- **Evidence:**
  - self → a `request: { disposition: Purge | Tombstone | Historical | PolicyDefault }` (`vtc-mvp.md` §10.2).
  - admin → a `request: { reason }` + the target as `subject`.
- **Routes (policy `leave.rego`):** e.g. `actor_is_self → allow(disposition from request | policy default)`;
  `actor_is_admin AND not subject_is_admin → allow(disposition default)`;
  `actor_is_admin AND subject_is_admin → refer(second-admin)`; else `deny`.
- **Verdict realization:** `allow.with.disposition` carries the departure disposition (the policy *decides* it,
  generalizing join's `role`). `refer` ⇒ a second admin must co-sign. `request_more` ⇒ e.g. require a
  documented-reason credential. `deny` ⇒ refuse (policy protects certain roles).
- **Effects (allow):** revoke VMC (flip status-list bit, immediate) → delete/anonymize the Member record per
  disposition → enqueue registry departure → audit `MemberRemoved`. **Destructive — issues nothing.**
- **Invariant:** **no-last-admin** — host refuses any leave/removal that would zero the admin set
  (`vtc-mvp.md` §10.2), regardless of policy.

**What this proves:** `actor ≠ subject`, destructive effects, a *different* hard invariant, and that the
`allow` payload is purpose-shaped (`disposition`, not `role`) — all on the same pipeline, with the same verify
stage and the same four verdicts.

**Worked example (admin removing a member):**

```jsonc
{ "purpose":"leave", "now":"…",
  "actor":   { "did":"did:key:z6MkAdmin", "role":"admin", "authenticated":true },
  "subject": { "did":"did:key:z6MkLeaver" },
  "context": { "community_did":"did:webvh:acme.example", "channel":"rest", "member_count":1421 },
  "evidence":{ "request":{ "reason":"code-of-conduct-violation" } },
  "state":   { "subject_member":{ "role":"member", "status":"active", "joined_at":"…" } } }
```

`actor_is_admin AND not subject_is_admin` → `{"effect":"allow","with":{"disposition":"Tombstone"}}`. Host runs
the destructive effects; the no-last-admin guard is moot here (subject isn't an admin) but would have refused
had `subject.role == "admin"` and the set would empty.

---

## 4. Role-change / promotion — *in-place mutation + escalation*

- **Trigger:** admin. `actor ≠ subject`.
- **Evidence:** `request: { target_role }`; for promotion-to-admin, a fresh **step-up** user-verification.
- **Routes (`role-change.rego`):** `target_role in {member,moderator,custom:*} → allow(target_role)`;
  `target_role == "admin" → refer(step-up)` *(or quorum)*; demotion guarded by no-last-admin.
- **Verdict realization:** `allow.with.role` ⇒ re-issue the role VAC + update the ACL role (mutation, not
  issuance-from-scratch). `refer` ⇒ the step-up / M-of-N path.
- **Effects (allow):** re-issue role VAC → update ACL role → audit `RoleChanged`. No new membership.
- **Invariants:** privilege ceiling (policy can't grant admin directly) **and** step-up reauth for admin
  promotion (`vtc-mvp.md` §9.7, §10.4) **and** no-last-admin on demotion.

**What this proves:** the pipeline handles *mutation of an existing member*, and that `refer` cleanly models an
**escalation** (step-up / quorum), not just human moderation. Two invariants stack on one ceremony.

---

## 5. Directory access — *read-time, synchronous, returns a filter (the stress test)*

Deliberately included because it's the ceremony most likely to break a naïve "verdict + effects + thread" model.

- **Trigger:** any member issues a query. `actor` = viewer, `subject` = the member being looked up.
- **Evidence:** `request: { fields_requested }`.
- **Routes (`directory.rego`):** `allow(fields: <subset visible to actor.role>)` — the policy returns a **field
  projection**, not a yes/no. e.g. members see `{did, role}`; admins see more.
- **Verdict realization:** `allow.with.fields` is the *permitted projection*. `deny` ⇒ empty result.
  `refer`/`request_more` are unused.
- **Effects (allow):** **return the projection in the same response — no state write, no thread.**
- **Invariant:** PII boundary (`vtc-mvp.md` §8.1) — fields outside the projection never leave.

**What this proves — the important one:** the pipeline **degrades to a stateless, synchronous read filter**.
There is no thread, no issuance, no mutation; `allow` carries a *projection* rather than an obligation. If one
abstraction spans a multi-day onboarding negotiation (join) *and* a sub-millisecond field filter (directory)
without special-casing, the pipeline is the right shape — and threads/effects are correctly modelled as
*optional, purpose-specific* rather than mandatory.

---

## 6. The remaining purposes map cleanly

The other `vtc-mvp.md` §7.1 purposes are further instances — listed to show coverage, not specified here:

| Purpose | `actor` / `subject` | Evidence | `allow` effect | Notes |
|---|---|---|---|---|
| **Personhood** | member self | VP w/ a `witnessed/1` statement or the community's IDVC | set `personhood` flag, re-mint VMC | minimal-allow default (`vtc-mvp.md` §6.4) |
| **Relationship** (VRC) | member → other member | self-issued VRC | store edge if both are members | `vtc-mvp.md` §12.3 |
| **Renewal** | member self | none | re-mint VMC + VAC | today unconditional; pipeline lets it be policy-gated |
| **Registry / departure** | system | the departing member | choose disposition + publish | runs inside Leave's effects |
| **Cross-community recognition** | foreign issuer | foreign role VAC | honor external role | federation; TRQP-resolved |
| **Directory** | member viewer | query | field projection | §5 |

Every one is `verify → facts → evaluate → verdict → effects` with a different policy module, evidence slot, and
effect handler. None needs a bespoke flow.

---

## 7. Why this matters for the build

Because the catalog is *instances*, the expensive machinery is built once and inherited:

- one **verify** stage (all ceremonies),
- one **Verdict** type + **request_more/refer** machinery (all),
- one **versioning / rollback / governance** mechanism (all purposes),
- one **IR + compiler** (per-purpose vocabulary, shared codegen),
- one **Trust Task protocol** shape (see [`vtc-ceremony-protocol.md`](./vtc-ceremony-protocol.md)).

Adding the *sixth* ceremony is writing a policy module, an evidence slot, an effect handler, and a vocabulary —
not a new subsystem.

Runnable policies for all four ceremonies above — the Rule IR, the compiled `.rego`, and sample `input` facts
with expected verdicts — are in [`examples/`](./examples/) (`join`, `leave`, `role-change`, `directory`). The
authoring vocabulary and compile mapping are in [`vtc-ceremony-rule-ir.md`](./vtc-ceremony-rule-ir.md).
