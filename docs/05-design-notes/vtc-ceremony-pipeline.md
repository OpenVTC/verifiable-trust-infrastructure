# VTC Ceremony Decision Pipeline — Architecture (greenfield)

**Status:** Design proposal (for review) · **Audience:** VTC planners / architects
**Position:** Target architecture. Treats community state transitions as a clean-slate design and maps, in §10,
which existing `vtc-service` code is **reused** vs **rebuilt**. Where it cites the MVP it is for grounding, not
as a constraint — this is the shape we'd build if starting fresh.

**Companions:** [`vtc-ceremony-catalog.md`](./vtc-ceremony-catalog.md) (the ceremonies that validate this
pipeline — join, leave, role-change, directory), [`vtc-ceremony-rule-ir.md`](./vtc-ceremony-rule-ir.md) (the
authoring vocabulary + compiler) with runnable [`examples/`](./examples/),
[`vtc-ceremony-protocol.md`](./vtc-ceremony-protocol.md) (the Trust Task wire protocol), and
[`vtc-ceremony-visual-guide.html`](./vtc-ceremony-visual-guide.html) (interactive — switch between join / leave /
directory). Start at [`vtc-ceremonies-exec-summary.md`](./vtc-ceremonies-exec-summary.md).

> **Notation.** Bare `§N` references are to *this* document. References to the MVP spec are written
> `vtc-mvp.md §N`.

---

## 1. The thesis

Don't build a join ceremony. **Build one decision pipeline and make every community ceremony an instance of
it.** A community has many governed state transitions — joining, leaving, role changes, directory queries,
personhood assertions, relationship publishing. They look different, but they have the *identical* shape:

> *something triggers a transition → evidence is gathered → the host verifies it → policy decides over verified
> facts → effects are applied.*

The MVP already hints at this: `vtc-mvp.md` §7 lists **nine policy purposes**, each with its own `input`
contract, and §10 shows join / removal / personhood all doing verify → policy → effect — but each wired
bespoke. The greenfield move is to **factor that into one pipeline**, parameterized by *purpose*. Everything
expensive to build once — verification, the verdict model, versioning, rollback, governance, the visual
authoring compiler — is then built **once** and inherited by every ceremony.

The catalog ([`vtc-ceremony-catalog.md`](./vtc-ceremony-catalog.md)) proves it by running four maximally
different ceremonies through this single pipeline.

---

## 2. The pipeline

```
            ┌─────────────────────────── one pipeline, parameterized by `purpose` ──────────────────────────┐
 TRIGGER ─▶ GATHER ─▶ VERIFY (host) ─▶ FACTS ─▶ EVALUATE (<purpose>.rego) ─▶ VERDICT ─▶ EFFECTS (<purpose>) ─▶ done
 actor/      evidence   crypto, binding,  typed,    policy over verified       allow|deny|   purpose-specific
 subject                status, trust     verified  facts only                 refer|        handler keyed by
                                          facts                                 request_more  the verdict
                            │                                                        │
                            └── identity/authenticity failure → abort (never reach policy)
                                                                                     └── request_more / refer → THREAD continues
```

| Stage | Generic responsibility | Purpose-specific part |
|---|---|---|
| **Trigger** | identifies `actor` (authenticated initiator) and `subject` (who the transition is about; may differ) | who is allowed to trigger |
| **Gather** | collect evidence (client-side / local) | what evidence the ceremony needs |
| **Verify** | crypto, holder-binding, freshness, revocation status, issuer-trust (TRQP) → `VerifiedFacts` | which evidence kinds apply |
| **Facts** | the typed, purpose-agnostic policy input (§3) | the `evidence`/`state` slots populated |
| **Evaluate** | run `<purpose>.rego` over facts; never touches crypto | the policy module |
| **Verdict** | one of four effects + a `with` payload (§4) | how each effect is realized |
| **Effects** | apply the decision; emit audit | the effect handler (issue / revoke / mutate / project) |
| **Thread** | optional: persists for async (`refer`) or multi-round (`request_more`) ceremonies | whether the ceremony is threaded |

**Two invariants make this safe and generic:** (1) crypto lives entirely in *Verify*, so policy reasons only
over a `Verified*` view (typestate discipline — a call site that skips verification doesn't compile); (2)
*Effects* are the only stage that mutates state, driven solely by the verdict.

---

## 3. The Facts contract (purpose-agnostic policy input)

One input shape for every ceremony. No lossy projections — policy sees structured, pre-verified facts.

```jsonc
input = {
  "purpose":  "join" | "leave" | "role-change" | "directory" | "personhood" | "relationship" | …,
  "now":      "2026-05-30T12:00:00Z",

  "actor":    { "did", "role", "authenticated": true },   // who initiated; role from ACL if a member
  "subject":  { "did" },                                   // who the transition is about (may == actor.did)

  "context":  { "community_did", "channel", "member_count" },

  // What the actor presented. Ceremonies populate the slots they use; the rest are absent.
  "evidence": {
    "invitation":   null | { "verified", "issuer", "issuer_role", "scopes", "consumed" },
    "presentation": null | { "verified", "holder",
                             "credentials": [ { "type", "issuer", "issuer_trusted", "status", "claims", "valid_until" } ] },
    "request":      null | { /* ceremony params: disposition | target_role | fields_requested | … */ }
  },

  // Current authoritative state relevant to the decision (read from the ACL/Member keyspaces).
  "state":    { "subject_member": null | { "role", "status", "joined_at", "personhood" } }
}
```

The compiler emits helper rules over this (`cred_trusted(t)`, `has_valid_invitation`, `actor_is_admin`,
`subject_is_self`, …) so authors never hand-write traversals. Per-purpose worked instances live in the catalog.

---

## 4. The Verdict (four-valued, generic)

`<purpose>.rego` returns one `decision` object, discriminated by `effect`:

```jsonc
{ "effect": "allow" | "deny" | "refer" | "request_more",
  "with": {
    // allow        → ceremony payload: { role } | { disposition } | { fields } | { obligations }
    // deny         → { code, reason }
    // refer        → { queue, reason }                       // needs a human / quorum
    // request_more → { needs, presentation_definition }      // needs more evidence (threaded continuation)
  } }
```

The four effects generalize cleanly:

| Effect | Meaning (any ceremony) | Join realizes as | Leave realizes as |
|---|---|---|---|
| `allow` | the transition proceeds | admit + issue VMC | execute departure + disposition |
| `deny` | refused | reject request | refuse removal |
| `refer` | needs a human / quorum | moderator queue | second-admin / appeal |
| `request_more` | needs more evidence | return a Presentation Definition | require a reason credential |

`allow` is the only effect with a purpose-specific *payload* (`with`). `deny` / `refer` / `request_more` are
identical across ceremonies. This is why one pipeline suffices.

---

## 5. Effects & host-enforced invariants

**Effects** are a per-purpose handler keyed by the verdict — the only stage that writes state. Examples:
join-`allow` issues + writes ACL; leave-`allow` revokes + applies disposition; role-`allow` re-issues a VEC +
updates ACL; directory-`allow` returns a field projection (no write).

**Invariants** are hard guards the host enforces *around* the policy — a policy can never override them. They
are per-purpose:

| Invariant | Applies to | Rule |
|---|---|---|
| **Structural totality** | all | the compiler appends `default decision := {"effect":"deny", …}` — every evaluation yields a decision |
| **Privilege ceiling** | join, role-change | policy may grant `member/moderator/custom`, never `admin`; admin promotion is a separate step-up path |
| **No-last-admin** | leave, role-change | the transition is refused if it would leave the community with zero admins |
| **Step-up reauth** | role-change (to admin), high-risk | a fresh WebAuthn user-verification ceremony is required before effects run |
| **PII boundary** | directory, registry | only whitelisted fields cross a trust boundary |

Invariants are checked by the host before/after evaluation, not encoded in Rego — so an operator's policy edit
can never disable them.

---

## 6. Threads — async and multi-round are opt-in

Not every ceremony is a conversation. A **thread** (a correlated, persisted exchange) exists only when the
ceremony can go async (`refer`) or multi-round (`request_more`):

- **Threaded** — join (request_more negotiation, async moderator review), leave-with-appeal, role-change with
  step-up or quorum.
- **One-shot synchronous** — directory access: the actor queries, the policy decides, the host returns a
  filtered projection in the same response. No thread, no persistence.

The pipeline treats "threaded" as a property of the *purpose*, not a mandatory stage. This is the abstraction's
key flex — it degrades gracefully from a multi-day onboarding negotiation to a sub-millisecond read filter
without special-casing.

---

## 7. Authoring — visual Rule IR → compiler (per purpose)

Operators do **not** write raw Rego (a footgun, and a security surface). For every purpose, the visual builder
edits a constrained **Rule IR** (a JSON AST over a fixed vocabulary of conditions and effects). A deterministic
compiler emits, per policy:

1. the **Rego** module (enforcement),
2. a **DIF Presentation Definition** (so software clients self-assemble the evidence — for evidence-bearing
   ceremonies),
3. a **plain-English** rendering (admin review + public manifest), and
4. **static invariant checks** ("every path terminates", "no `allow{role:admin}`", purpose-specific rules).

Raw Rego is an expert-only, validated escape hatch — not the front door. A **policy simulator** dry-runs sample
facts against a *draft* before activation. The condition/effect vocabulary is per purpose (join speaks
credentials + invitations; leave speaks disposition + tenure; directory speaks viewer-role + fields) but the
*compiler and IR machinery are shared*.

Full grammar, the per-purpose condition/effect vocabulary, and the deterministic compile-to-Rego mapping live in
[`vtc-ceremony-rule-ir.md`](./vtc-ceremony-rule-ir.md); runnable compiled policies (IR + `.rego` + sample facts)
for join / leave / directory are in [`examples/`](./examples/).

---

## 8. Versioning, rollback, governance (shared across purposes)

Per-purpose, but one mechanism:

- **Append-only, hash-chained, DID-signed policy log** (one per purpose) — the governance record. The active
  policy is the log head; prior versions are navigable, not just "archived".
- **Fail-forward rollback** — rolling back to v3 *appends* a new v6 carrying v3's content (`parent: v5,
  kind: rollback`); the chain never rewinds. (Same discipline as WebVH `did.jsonl` and runtime-service-management
  rollback.)
- **Semantic diffs** — because the Rule IR is structured JSON, diffs are "route X added / priority raised", not
  Rego text diffs.
- **Optional M-of-N governance** — `propose → approve (DID-signed proofs accumulate into a proof set) →
  activate at quorum`. The proposal thread *is* the governance record. Per-community, per-purpose opt-in.

Because this is purpose-generic, every ceremony gets versioning, rollback, and governance for free.

---

## 9. Safety rails

- Crypto only in *Verify*; policy sees booleans/facts, never signatures.
- Invariants (§5) host-enforced, not policy-encoded.
- Default posture is **deny** (see §10 — a clean-slate change from the MVP's accept-any), with an install-time
  forced choice of posture per purpose.
- Atomic activation (CAS on the per-purpose log head); rollback re-validates the old IR compiles under the
  current vocabulary; both are signed + audited.
- Unauthenticated triggers (e.g. join over DIDComm) are rate-limited *before* evaluation.

---

## 10. Relationship to current code — build vs reuse (honest)

Greenfield does **not** mean rewrite-everything. The `vtc-mvp.md` §3 cornerstones are good; the rework is
concentrated in the ceremony/policy *modelling*.

**Reuse as-is:**

| Keep | Why |
|---|---|
| `regorus` embedded engine (`vtc-mvp.md` §3-D) | single artifact, low latency — right call |
| VTA mints keys / VTC caches + signs locally (§3-A) | clean custody boundary |
| **VC-as-projection; VTC never reads its own VCs for authz** (§3-B) | excellent, rare clarity — keep loudly |
| DTG-catalog-only credentials (§3-C), status-list privacy design, HMAC-actor audit envelope | sound |
| The `Verified*` typestate (`vtc-mvp.md` §10.1) | generalize from `VerifiedJoinRequest` → `VerifiedFacts` |
| Trust Task wire discipline (§3-L), JWT audience isolation, install/passkey flows | keep |

**Rebuild (cheap now, painful later):**

| Replace | With |
|---|---|
| 9 bespoke per-purpose flows | **one pipeline** parameterized by purpose (this doc) |
| `vp_claims` lossy projection (`vtc-mvp.md` §7.3) | **structured `evidence.presentation.credentials[]`** (§3); drop `vp_claims` |
| boolean allow/deny (§10.1) | **four-valued Verdict object** (§4) |
| active-pointer + archived priors (§5.4/§7.2) | **append-only signed policy log + fail-forward rollback** (§8) |
| `policies.open` accept-any default (§7.1) | **default-deny + install-time posture choice** (§9) |
| raw-Rego upload as primary door | **Rule IR + compiler primary**; raw Rego expert-only (§7) |
| flat `JoinStatus` enum | **ceremony thread / state machine** for async purposes (§6) |
| `VerifiableMembershipCredential` vs DTG `MembershipCredential` naming drift | **align type strings to DTG exactly** — settle while cheap |

**Reconsider (lower confidence):** the `acl:<did>` / `members:<did>` split may be premature optimization at
community scale — consider unifying with an in-memory auth index. The Trust Task router should be method-aware
and expose `/capabilities` for discovery.

---

## 11. Staged plan

| Stage | Deliverable | Depends on |
|---|---|---|
| **A · Pipeline core** | `VerifiedFacts` contract (§3), four-valued Verdict (§4), the verify→evaluate→effects spine parameterized by purpose, host-enforced invariants (§5). | — |
| **B · Two ceremonies** | **Join** and **Leave** as the first two instances (catalog) — proves actor≠subject + constructive vs destructive on one pipeline. | A |
| **C · request_more + discovery** | the `request_more` verdict + Presentation Definition generation + the ceremony manifest. | A |
| **D · Rule IR + compiler** | the IR, the shared compiler (Rego + PD + English + invariant checks), the simulator. | A |
| **E · Versioning / rollback / governance** | per-purpose append-only signed log, fail-forward rollback, M-of-N. | D |
| **F · Protocol breadth** | role-change + directory instances; the generalized `<ceremony>/*` Trust Task families. | A, B |

**Critical path:** A is the spine; B proves it; C/D/E/F broaden. Build the pipeline before the second ceremony,
not after the fifth.

---

## 12. Open decisions

| # | Decision | Recommendation |
|---|---|---|
| 1 | Default posture per purpose | **Deny**, with a forced install-time choice (change from MVP accept-any) |
| 2 | First-match vs scored route resolution | Ordered first-match (deterministic, legible) |
| 3 | Membership topology — star (paired VMCs) vs proof-set circles | Start star; leave circles open |
| 4 | Invitation delegation — community-only vs members with `can_invite` | Allow, with depth/scope bounds |
| 5 | Governance quorum — single-admin vs opt-in M-of-N | Per-community, per-purpose opt-in |
| 6 | `acl`/`members` keyspace split — keep vs unify | Revisit; likely unify at community scale |
| 7 | Credential `type` strings — `Verifiable…` prefix vs bare DTG names | Settle now to avoid a translation layer |

---

## References

- [`vtc-ceremony-catalog.md`](./vtc-ceremony-catalog.md) · [`vtc-ceremony-rule-ir.md`](./vtc-ceremony-rule-ir.md)
  · [`examples/`](./examples/) · [`vtc-ceremony-protocol.md`](./vtc-ceremony-protocol.md)
  · [`vtc-ceremonies-exec-summary.md`](./vtc-ceremonies-exec-summary.md) ·
  [`vtc-ceremony-visual-guide.html`](./vtc-ceremony-visual-guide.html)
- MVP grounding: [`vtc-mvp.md`](./vtc-mvp.md) · Rollback pattern:
  [`runtime-service-management.md`](./runtime-service-management.md)
- DTG credentials: <https://github.com/OpenVTC/dtg-credentials> · DIF Presentation Exchange:
  <https://identity.foundation/presentation-exchange/> · ToIP TRQP:
  <https://github.com/trustoverip/tswg-trust-registry-protocol> · Rego:
  <https://www.openpolicyagent.org/docs/policy-language>
