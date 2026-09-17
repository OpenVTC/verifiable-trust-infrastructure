# TSP vs DIDComm for the Trust-Task surface — a deliberate decision

**Status:** **Decided — multi-hop TSP is a requirement.** The decision below was
open; it is now settled. This note is kept as the record of *why*, and of what
the decision commits us to. Not a proposal to change direction — a framing so the
choice was made on the *benefit*, not on the friction of a bug series.

## Decision (confirmed)

The mesh **must** support multi-hop TSP: Trust Tasks carried over routing where
intermediaries do not learn the final recipient. That is exactly the benefit the
relationship layer pays for, so it is a benefit we **will** collect — which
resolves everything below in favour of TSP and makes the D1–D9 recovery work
**justified investment, not speculative rent.** The consequences (what this now
commits us to) are in "What the decision commits us to" at the end.

## Why this note exists

The §7.2.2 relationship layer has cost a visible run of work: the client-relate
fixes (#1527, #1537, #1540), the client-side self-repair (#1544), and the whole
D1–D9 recovery design (`tsp-relationship-recovery.md`). Each was a real fix, and
none was wrong. But the accumulation invites a fair question: **for the PNM↔VTA
Trust-Task surface specifically, is the relationship layer buying something we
use?** This note answers it deliberately rather than by inertia in either
direction.

## First, what the relationship layer is — and is not

A recurring confusion, worth killing up front. The §7.2.2 relationship is **not**:

- **authentication** — the sender VID is proven intrinsically by the envelope
  (authcrypt / TSP), same as DIDComm; and a Trust Task also carries its own
  signed proof.
- **authorization** — that is the ACL, the standing source of truth for what a
  peer may do.

It is **admission**: "will I accept traffic from this VID at all." That is the
only thing it decides, and it is the only thing at stake in this decision.

## The cost ledger (what TSP's relationship layer actually costs us)

- A handshake before the first Trust Task (one invite; self-suppressed once
  related).
- Symmetric, silent drops: a lost half shows up only as a timeout, which is why
  it needed detection + recovery machinery (D1 durable store, D2 reconcile, D3
  send-readiness, D4 self-repair, D5–D9).
- The bug surface that machinery implies — four fixes and counting, each in a
  code path that had no test until it broke.

## The benefit (what TSP buys over DIDComm), and the nuance that decides it

TSP's differentiators over DIDComm are **metadata-private routing** — intermediaries
don't learn the final recipient — at **bounded** message size (CESR + HPKE add
roughly additively per hop, versus DIDComm-nested's multiplicative base64 growth).
Sender authentication is *not* a differentiator; both stacks have it intrinsically.

The nuance that actually decides this: **routing privacy pays off across multiple
hops.** On the reference topology PNM and the VTA share **one** mediator. That
mediator is the delivery point — it must know the VTA to route to it — so in a
single-hop path it already sees both VIDs, and TSP's "intermediaries don't learn
the recipient" buys almost nothing over DIDComm there. The benefit materialises
when there are intermediaries *before* the recipient's mediator: multi-mediator
routing, relays that should not learn the endpoint. That is a real future, but it
is not today's single-mediator reference deployment.

So the honest statement is: **on the topology we run now, TSP's privacy benefit
for Trust Tasks is marginal and the relationship layer is mostly cost; the benefit
is realised only in the multi-hop routing TSP is being adopted *for*.**

## The strategic frame (don't decide this surface in isolation)

Two constraints from the existing direction bound the answer:

1. **TSP is the stated preference and the long-term direction** (TSP > DIDComm >
   REST; the goal is to deprecate DIDComm eventually). This note does not
   relitigate that.
2. **Do not fork transport per-surface within one deployment.** TSP already
   carries only Trust Tasks while DIDComm carries protocol messages on the same
   socket; that split is load-bearing and understood. Adding "…except Trust
   Tasks go back to DIDComm when the mediator count is one" is a third rule that
   fragments the stack and is exactly the kind of special-case that breeds the
   next silent-drop bug.

## The decision hinged on one question — now answered

> **Will this mesh carry Trust Tasks over multi-hop / intermediary routing where
> the final recipient must be hidden from intermediaries?**

**Answer: yes — it is a requirement.** So the relationship layer is the price of a
benefit we will use; keep TSP for the surface, and the D1–D9 recovery work is
justified investment to be **finished**, not second-guessed.

## What the decision commits us to

Grounded in the current code and `tsp-enablement.md` (which already sets the
stance: *use upstream `send_nested` / mediator routing — we do **not** build onion
routing ourselves*):

1. **Exercise the multi-hop privacy we just committed to.** Today the send seams
   call `send_routed(&[mediator, recipient])` — a **single** intermediary. That
   is routed delivery, not the metadata-private multi-hop wrap. The benefit is
   *designed* (upstream `send_nested`; §3 route discovery drives routed-vs-nested
   arm selection — `tsp-enablement.md` §3/§7) but not yet *exercised*. The
   concrete next feature is wiring the send seams to select `send_nested` /
   multi-intermediary routes from DID-doc discovery, still behind the existing
   seams. **This is what "support multi-hop" means in code, and it is now on the
   roadmap rather than deferred.**
2. **D6 recovery becomes non-optional, and moves up.** Multi-hop makes a lost
   relationship both more likely (more hops, more relays, more state to lose) and
   more disruptive (a mediator/VTA restart times out every peer at once). The
   per-call self-repair (#1544) covers the single-mediator case; the
   coordinator-grade recovery — single-flight, backoff, herd control (D4's
   `RecoveryState` wired into the outbox, D6) — is required at fleet/multi-hop
   scale so a fleet-wide restart cannot self-DoS.
3. **§7.2.2 recovery hardening is warranted** (D7 invite rate-limit, D8 drop
   metrics, D9 startup reconcile), for the same reason: more relationships across
   more relays raise the cost of losing and re-forming them.

## Sequencing (given the decision)

1. **Done:** #1540 (Auto-path relate), #1544 (per-call self-repair).
2. **Next:** the multi-hop send-seam wiring (`send_nested` / route discovery) —
   the feature that actually delivers the benefit; and **D6** (coordinator
   recovery) — which multi-hop makes non-optional. Order between them is a
   scoping call; D6 protects what multi-hop stresses, and the send-seam work is
   the benefit itself.
3. **Then:** D7–D9 hardening.

## What this note is *not* proposing

- Not ripping out TSP, and not disabling §7.2.2 (that is a spec divergence, and
  it would land us with a transport that is neither private nor simple).
- Not a per-surface DIDComm carve-out.

The requirement is now named — **multi-hop is required** — so it, not the bug
count, sets how hard we invest in the relationship layer: finish the recovery
machinery (D6 next) and exercise the multi-hop send path (`send_nested` / route
discovery).
