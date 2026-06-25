# Design note: VTC↔member messaging routing, and TSP

> **SUPERSEDED (2026-06-25) by `tsp-enablement.md`.** This note's §6 decision to
> *defer* TSP ("stay on lazy DIDComm; treat TSP as watch-and-wait") was reversed
> once the published mediator gained TSP routing + TSP↔DIDComm bridging and
> `affinidi-tsp` became usable. TSP is now being enabled across VTI as the
> preferred transport (TSP > DIDComm > REST). The routing-model analysis
> (§3–§5) remains accurate and is the background for that decision. See
> `tsp-enablement.md` for the active plan.

Status: **Research / decision record** — **superseded** (see banner above)
Owner: Glenn Gore
Last updated: 2026-06-22

## 1. Why this note exists

When the VTC sends a message to a member, the message may have to cross
one or more DIDComm mediators (the member can be on a different mediator
than the VTC, and that mediator may itself route via another). This note
records:

- how outbound VTC→member messaging works **today** (verified against the
  code),
- the two DIDComm routing models and their size / privacy / speed
  trade-offs,
- whether the **Trust Spanning Protocol (TSP)** would change the picture,
- the feasibility of a **hybrid TSP/DIDComm** environment, and
- the **decision**: stay on lazy DIDComm for now; treat TSP as
  watch-and-wait, because the dependency *and* the mediator are not ready.

It is a decision record so the trade-off and the current state are not
re-derived from scratch each time.

## 2. What runs today

- **Transport-neutral application layer.** Every holder-facing verb is a
  `trust_tasks_rs::TrustTask` document dispatched through one spine
  (`vtc-service::trust_tasks::dispatch_trust_task_core`). REST and DIDComm
  already feed the same spine; the document doesn't care which transport
  delivered it. **The payload is protocol-agnostic by construction.**
- **One inbound DIDComm connection.** `messaging::run_didcomm_service`
  runs a single `DIDCommService` listener (`VTC_LISTENER_ID = "vtc-main"`)
  holding one websocket to the VTC's mediator.
- **One outbound seam.** `AppState::send_to_member(recipient, message)`
  (PR #551) sends through that **same** listener connection via
  `DIDCommService::send_message_with_retry`. All outbound funnels —
  credential delivery, credential-exchange query, member-VMC request —
  go through `credentials::delivery::push_to_holder` → `send_to_member`.
  The mediator permits one websocket per DID, so reusing the listener's
  connection (rather than opening a second) is what stopped the
  `w.websocket.duplicate-channel` flapping (#550 → #551).

### How a send is actually routed today (verified)

`DIDCommService::send_message` → `transport::send_message` →
`atm.pack_encrypted(msg, recipient)` then
`forward_and_send_message(target = our own mediator, next = recipient)`.

- `pack_encrypted` (affinidi-messaging-sdk `messages/pack.rs`) encrypts
  **directly to the final recipient's** key-agreement keys. It does **not**
  resolve the recipient's `routingKeys` and does **not** wrap forwards.
- `routing.rs::forward_message` builds **one** `routing/2.0/forward`
  message (`{"next": recipient}`) addressed to **our own mediator**.

So the VTC emits a **single forward to its own mediator with
`next = member`**, over the existing websocket, and **delegates all
onward routing to the mediator mesh.** This is "lazy routing" (below).

## 3. The two DIDComm routing models

Both keep the **content** end-to-end encrypted to the final recipient — no
mediator can read the payload in either model. They differ on routing
metadata, message size, and where the work happens.

### 3a. Lazy / mediator-resolved (what we do)

Sender wraps one `forward(next = recipient)` to its own mediator. Each
mediator that doesn't host the recipient resolves the recipient's DID and
relays onward (the affinidi mediator's `processors.forwarding.external_forwarding`).
Each hop strips its one forward layer and re-wraps one new layer.

- **Pros:** trivial sender (no topology knowledge), late-bound (adapts if
  the recipient's mediators change), and **size stays ~constant** at any
  hop depth (only ever one forward layer on the wire).
- **Cons:** the `next` field carries the final recipient, so **the
  mediators learn who the final recipient is** (weak metadata privacy);
  it depends on every mediator in the path enabling external forwarding
  (non-standard, mesh-only); per-hop cost is heavier (resolve + re-wrap);
  it is effectively open relay and needs blocklists + rate limits (which
  the affinidi mediator has).

### 3b. Sender-controlled / nested onion (the DIDComm-spec model)

Sender resolves the recipient's `routingKeys` and builds nested forwards:
innermost encrypted to the recipient, then a forward layer encrypted to
each mediator outward. Each mediator peels exactly one layer and sees only
the next hop.

- **Pros:** strong metadata privacy (each mediator sees only the next box;
  the first mediator does **not** learn the final recipient);
  standards-compliant / interoperable; no reliance on external-forwarding;
  light per-hop work (strip + forward).
- **Cons:** **message size explodes with depth** (below); sender must
  resolve the whole path up front; brittle to topology change (early
  bound); more sender complexity.

### 3c. Size — 10 hops, 100 KB payload

The blow-up is an **encoding** artifact: each DIDComm forward layer
base64's the prior message as an attachment *and* base64's again inside the
JWE → roughly **×1.6–1.8 per hop**.

| | size at ~10 hops | metadata privacy |
|---|---|---|
| **Lazy DIDComm (today)** | ✅ ~constant (~200–250 KB) | ❌ mediators learn final recipient |
| Nested DIDComm | ❌ ~1.7¹⁰ ≈ 100–300× → **tens of MB** peak at the sender, shrinking per hop | ✅ next-hop only |

At realistic depths of 1–2 hops the onion overhead is only ~1.8–3×, so the
explosion only bites past a few hops.

**Speed:** lazy is lighter on the wire (constant size) but pays a DID
resolution + re-encrypt per hop, serially. Sender-controlled is heavy
up-front (resolve + build the onion) then cheap per hop, but transmitting
tens of MB dominates at depth.

### 3d. Does the code exist for both?

- **Lazy: yes, and it's what runs** (VTC `send_to_member` + the mediator's
  `external_forwarding`).
- **Sender-controlled nested: no.** The SDK's `forward_message` is
  single-hop and `pack_encrypted` doesn't auto-resolve `routingKeys`; you'd
  have to build the onion by looping `forward_message` over a resolved
  path. Nothing does this today.

## 4. Multi-mediator routing — does it "just work"?

For the homogeneous affinidi mediator mesh (VTC→Mediator-A→Mediator-B→…→member):

- The VTC hands `forward(next = member)` to **its own** mediator. The
  affinidi mediator's `external_forwarding` resolves the next DID, finds
  its endpoint (`deliver_forward` → `service_endpoint_for_remote`), and
  relays onward; each mediator repeats it. **Arbitrary hops are handled by
  the mediator chain, not the VTC.** Forward loop-detection (hop count) is
  built in.
- **Condition:** every mediator in the path must have external forwarding
  enabled and be able to resolve + reach the next. If some mediator only
  delivers to its own registered clients, the message stops there — and
  *then* the sender would need client-side `routingKeys` resolution +
  nested forwards, which we do not do.

So "get it to our own mediator" **is** enough for the trusted mesh.

## 5. TSP (Trust Spanning Protocol)

### 5a. Would TSP solve the size issue?

Conceptually yes — the size blow-up is a DIDComm encoding problem, not a
law of routing. TSP uses **CESR** (composable encoding — primitives
concatenate without re-base64'ing the whole payload per layer) and
**HPKE** (size-preserving). Nested/routed TSP adds roughly **additive**
per-hop overhead, not multiplicative — so 10 hops + 100 KB stays ~100 KB,
versus DIDComm-nested's tens of MB. Crucially it keeps the **privacy** of
sender-controlled onion routing *without* the size penalty.

But note the reframe: **lazy DIDComm already gives us bounded size.** What
TSP uniquely adds over what we run is **metadata privacy at bounded size**
(intermediaries can't learn the final recipient). So adopting TSP is a
**privacy** upgrade, not a size rescue.

### 5b. Status of the dependency and the spec (as of 2026-06)

- **`affinidi-tsp` crate:** v0.1.0 (2026-03-26) → v0.1.3 (2026-06-14).
  **Pre-1.0 and fast-moving** (4 releases in ~3 months; latest ~a week
  before this note). The `tsp` feature lives in `affinidi-tdk` 0.8.x
  (`tsp = [dep:affinidi-tsp]`), **not** the messaging SDK.
- **TSP spec:** First Implementers Draft (Rev 1) Apr 2024 →
  **v1.0 Experimental Implementer's Draft Rev 2** (~Nov 2025). Still
  *experimental*, not ratified.
- **Drift:** none to catch up on — `affinidi-tsp` was written *after*
  Rev 2 and tracks it. The risk is forward-looking: a young library
  against a draft-but-current spec.

### 5c. The hybrid TSP/DIDComm idea

Goal: use TSP where possible; if a node only speaks DIDComm, route TSP as
far as possible and use DIDComm for the last hop; deploy TSP in parallel,
switch per-recipient. The Trust Task payload is already transport-agnostic,
which makes this clean in principle:

- **Capability discovery** = resolve the recipient's DID document: a TSP
  service endpoint → TSP; only `DIDCommMessaging` → DIDComm. DIDs double as
  TSP VIDs (`affinidi-tsp` has a `did-resolver` feature), so one identity
  works in both stacks.
- **Transport selection** belongs at the `send_to_member` seam.
- **Inbound** would add a TSP listener alongside the DIDComm one, both
  feeding `dispatch_trust_task_core`.
- **End-to-end security across the bridge:** the DIDComm-only node can only
  open a DIDComm (JWE) envelope, so the *final* envelope must be DIDComm.
  To avoid the bridge becoming a plaintext-seeing trust break, the
  **sender pre-packs the DIDComm envelope encrypted to the final node** and
  carries that **opaque blob** inside TSP to the boundary; the bridge
  forwards the opaque DIDComm blob without seeing plaintext (exactly how a
  DIDComm `forward` carries an opaque inner JWE). Content stays E2E; the
  bridge only learns routing metadata.

### 5d. Mediator reality check — the blocker

The hybrid's "DIDComm last hop" depends on the mediator **bridging**
TSP↔DIDComm by message type. **It does not, in the version we have
(`affinidi-messaging-mediator` 0.16.3, also the latest published):**

- The crate's module tree has **no `tsp` module**; `find -iname "*tsp*"`
  and `grep "fn .*tsp"` find nothing. The `tsp` feature is only a Cargo
  flag (gates the `affinidi-tsp` dep + a `compile_error!` guard).
- The forward/delivery path is **DIDComm-only**: `deliver_forward`
  (`messages/protocols/routing.rs`) parses the forwarded attachment as a
  DIDComm `MetaEnvelope` ("Couldn't read forward attached **DIDComm**
  envelope") and delivers via DIDComm live-stream / local store / remote
  DIDComm endpoint. **No branch inspects message type and emits the other
  protocol.**
- Inbound is "Try DIDComm first," and the TSP-only branch says
  *"If only TSP is enabled, we don't support text-based inbound yet"*
  (`messages/inbound.rs`).

So cross-protocol bridging is **not present**; the `tsp` feature is
scaffolding at this version.

## 6. Decision

1. **Stay on lazy DIDComm over the mediator mesh.** It is what runs, keeps
   message size constant at any hop depth, and is sufficient for the
   trusted mesh. The accepted cost is routing-metadata exposure to the
   mediators (content remains E2E encrypted).
2. **Do not build a hybrid TSP/DIDComm framework yet.** Our side is ready
   (transport-agnostic Trust Task spine + the single `send_to_member`
   seam), but:
   - the value TSP adds over lazy DIDComm is **privacy**, not size, and we
     have no current requirement for intermediary-blind routing;
   - `affinidi-tsp` is 0.1.x and churning; and
   - the **mediator does not implement TSP routing or TSP↔DIDComm
     bridging** in 0.16.3, so a hybrid today would mean building the bridge
     ourselves — premature and large.
3. **Preserve optionality cheaply:**
   - keep all outbound behind `send_to_member` (don't scatter sends), so a
     future TSP transport is a swap-in behind that method;
   - watch the mediator + `affinidi-tdk-rs` TSP releases (the
     `weekly-tdk-report` already tracks the workspace);
   - a time-boxed throwaway spike (enable the `tsp` feature; measure real
     TSP envelope sizes; see the integration shape) is worth doing *once
     the mediator implements TSP routing*.

**Revisit when** either (a) a concrete requirement lands — untrusted
intermediaries, a metadata-privacy mandate, or genuinely deep cross-domain
paths — **or** (b) a mediator release implements TSP routing + DIDComm
bridging and `affinidi-tsp` reaches ≥1.0 / the spec is ratified.

## 7. References

- DIDComm routing: `protocols/routing.rs::forward_message`,
  `transports/mod.rs::{send_message, forward_and_send_message}`,
  `messages/pack.rs::pack_encrypted` (affinidi-messaging-sdk 0.18.12);
  `service/mod.rs::send_message` (affinidi-messaging-didcomm-service 0.3.4).
- VTC seam: `vtc-service::server::AppState::send_to_member`,
  `messaging::run_didcomm_service`, `credentials::delivery::push_to_holder`
  (PRs #550, #551).
- Mediator: `affinidi-messaging-mediator` 0.16.3 —
  `messages/inbound.rs`, `messages/protocols/routing.rs::deliver_forward`,
  `processors.forwarding.{external_forwarding, blocked_forwarding_dids}`.
- TSP: [`affinidi-tsp` on crates.io](https://crates.io/crates/affinidi-tsp)
  (0.1.0 2026-03-26 → 0.1.3 2026-06-14);
  [TSP Specification (Rev 2)](https://trustoverip.github.io/tswg-tsp-specification/);
  [ToIP First Implementers Draft, Apr 2024](https://trustoverip.org/blog/2024/04/11/toip-announces-the-first-implementers-draft-of-the-trust-spanning-protocol-specification/);
  [TSP Rev 2 deck, Nov 19 2025](https://www.lfdecentralizedtrust.org/hubfs/TSP_%20Trust%20Spanning%20Protocol%20(Rev2).pdf?hsLang=en).
