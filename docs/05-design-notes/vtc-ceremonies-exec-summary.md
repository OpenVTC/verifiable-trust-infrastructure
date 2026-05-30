# VTC Community Ceremonies — Executive Summary

> **Start here.** Fronts a five-document design bundle (+ runnable examples and an interactive guide). Read in
> the order in §5.

**Status:** Design proposal for review · **Scope:** target architecture (greenfield), with an honest build-vs-reuse map

---

## 1. The question

A community has many **governed state transitions** — joining, leaving, role changes, directory lookups,
personhood assertions, relationship publishing. Each must be **configurable, policy-driven, auditable, and
followable by software unattended**. How do we build them without a bespoke subsystem per ceremony?

## 2. The core idea

**One decision pipeline; every ceremony is an instance of it.**

```
TRIGGER → GATHER → VERIFY (host) → FACTS → EVALUATE (<purpose>.rego) → VERDICT → EFFECTS (<purpose>)
```

The expensive parts — verification, the four-valued verdict, versioning/rollback, governance, the visual
policy compiler — are built **once** and inherited by every ceremony. Adding a new ceremony is a policy module
+ an evidence slot + an effect handler, not a new subsystem.

## 3. Proven by a catalog, not asserted

Four maximally-different ceremonies run through the *same* pipeline:

| Ceremony | `actor`=`subject`? | Effects | Invariant | Threaded? |
|---|---|---|---|---|
| **Join** | yes | issue (constructive) | privilege ceiling | yes |
| **Leave** | no | revoke (destructive) | no-last-admin | optional |
| **Role-change** | no | re-issue (mutating) | ceiling + step-up | optional |
| **Directory** | no | return a filter (read-only) | PII boundary | **no (sync)** |

Join and Leave invert each other (constructive/self vs destructive/other); Directory is the stress test — a
synchronous read returning a *projection*, proving threads and effects are optional, purpose-specific stages.

## 4. The design in seven decisions

1. **One pipeline, parameterized by purpose** — not nine bespoke flows.
2. **Crypto only in Verify** — policy reasons over a `Verified*` view; skipping verification doesn't compile.
3. **Four-valued verdict** — `allow / deny / refer / request_more` (the last enables negotiation + async review).
4. **Structured Facts** — policy sees verified, typed credentials; no lossy `vp_claims` projection.
5. **Dual artifact** — one policy compiles to Rego (enforce) + a DIF Presentation Definition (so clients
   self-assemble evidence) + plain English.
6. **Visual Rule IR → compiler** — operators don't write raw Rego; the compiler also checks invariants.
7. **Append-only signed policy log** with **fail-forward rollback** and **optional M-of-N governance** — per
   purpose, one mechanism.

## 5. Suggested reading order

| # | Document | What it gives you |
|---|---|---|
| 1 | **(this page)** | the frame |
| 2 | [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md) | the architecture — pipeline, Facts, Verdict, invariants, versioning, **build-vs-reuse (§10)**, staged plan |
| 3 | [`vtc-ceremony-catalog.md`](./vtc-ceremony-catalog.md) | the proof — join / leave / role-change / directory as instances, with worked examples |
| 4 | [`vtc-ceremony-rule-ir.md`](./vtc-ceremony-rule-ir.md) | the authoring vocabulary — Rule IR grammar + compile-to-Rego mapping (the canonical source the examples & guide derive from) |
| 5 | [`vtc-ceremony-protocol.md`](./vtc-ceremony-protocol.md) | the generalized `{family}/*` Trust Task wire protocol |
| ▸ | [`examples/`](./examples/) | runnable IR + `.rego` + sample facts for join / leave / role-change / directory |
| ▶ | [`vtc-ceremony-visual-guide.html`](./vtc-ceremony-visual-guide.html) | **interactive** — switch between join / leave / role-change / directory: edit routes, simulate, version & roll back, read the live-compiled Rego/PD |

*Read 2 for the whole picture; 3 proves it generalizes; 4 is the canonical vocabulary; 5 is the wire detail;
open the guide alongside 2 and the examples alongside 4.*

## 6. Greenfield, but not rewrite-everything

The `vtc-mvp.md` §3 cornerstones are **kept**: embedded `regorus`, VTA-mints/VTC-caches keys, VC-as-projection,
status-list privacy, audit, the `Verified*` typestate, Trust Task discipline. The rework is concentrated in the
ceremony/policy *modelling*: one pipeline (vs nine flows), structured Facts (vs `vp_claims`), a verdict object
(vs boolean), a signed policy log (vs pointer+archive), default-deny (vs accept-any), the IR compiler (vs
raw-Rego upload), and ceremony threads (vs a flat status enum). Full map in pipeline §10.

## 7. What reviewers should decide

(Full list in pipeline §12.) The genuine forks: **default posture** (deny vs the MVP's accept-any),
**`acl`/`members` keyspace split** (keep vs unify), **invitation delegation** (community-only vs `can_invite`),
**governance quorum** (single-admin vs opt-in M-of-N), **credential type strings** (settle the `Verifiable…`
prefix now).

## 8. Status & caveats

- **Design, not implementation** — nothing here is compiled or tested.
- Code-grounded claims (engine, key model, keyspaces, defaults) were **verified against the tree**; this doc
  proposes replacing several of those — see the build-vs-reuse map, which is explicit about what changes.
- Presentation Definition examples are **illustrative**, not schema-validated. New Trust Task families
  (`departures`, `role-changes`, `directory`, and join's `manifest`/`present`/`status`/`accept`) are **proposed**.
