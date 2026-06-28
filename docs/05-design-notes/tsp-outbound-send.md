# Design note: how a VTA/VTC sends TSP outbound

**Status:** DRAFT for review — scopes SDD PR 7 (outbound seams). No code until
the §3 relationship question is decided.
**Owner:** Glenn Gore
**Created:** 2026-06-28
**Context:** `tsp-enablement.md` §7 ("outbound seams behind `send_to_member`")
and `tsp-inbound-receive.md` (the inbound counterpart, merged #591/#592). Inbound
turned out to need a design pass before code; outbound has a sharper open
question (TSP relationships), so it gets the same treatment.

---

## 1. What runs today (verified)

The VTC's single outbound funnel is
`vtc_service::server::AppState::send_to_member(recipient_did, message:
affinidi_messaging_didcomm::Message)`:

- It pulls the running `DIDCommService` listener (`self.didcomm` OnceCell) and
  calls `send_message_with_retry(VTC_LISTENER_ID, message, recipient_did, …)` —
  the SDK authcrypt-packs and forwards through the VTC's mediator over the
  listener's single websocket. **Always DIDComm.**
- One real consumer path: `credentials::delivery::push_to_holder` →
  `send_to_member` (credential delivery, credential-exchange query,
  reciprocal-VMC request all funnel here).
- The argument is an **already-built `didcomm::Message`** — the seam is
  DIDComm-shaped, not protocol-agnostic.

The VTA has an equivalent send path; PR 7 should make both protocol-aware, but
the VTC `send_to_member` is the canonical seam this note works through.

## 2. The send API (TDK 0.18.39)

- `atm.tsp().send(profile, to_did, payload)` — packs a TSP **Direct** message and
  POSTs it to the mediator `/inbound` (Content-Type `application/tsp`), reusing
  the profile's existing authenticated session. The mediator sniffs + routes it.
- `atm.tsp().send_routed(profile, route, payload)` — `route` is the ordered hop
  list ending at the final recipient, e.g. `[member_mediator_did, member_did]`;
  sealed end-to-end to `route.last()`, wrapped to `route[0]` (must be a
  TSP-routing mediator). This is the **mediator-indirection** case from
  `tsp-enablement.md` §2: VTC → member-behind-their-mediator.
- `atm.tsp().send_nested` — adds a metadata-private outer wrap.

All post to the VTC's own mediator `/inbound`; no second socket. Good — mirrors
how DIDComm `send_to_member` reuses the listener connection.

## 3. The load-bearing open question — TSP relationships

`affinidi_tsp`'s Direct/Routed send is defined against a **Bidirectional TSP
relationship** with the recipient (the RFI/RFA lifecycle: invite → accept). The
SDK exposes the FSM — `atm.tsp().{form_relationship, accept_relationship,
relationship_state, record_incoming_control}` (#529) — backed by a pluggable
store. **Whether `atm.tsp().send` hard-fails without a `Bidirectional` state, or
sends opportunistically, must be confirmed** (the SDK wrapper's doc comment
doesn't restate the library's relationship precondition; a live test resolves
it).

This gates the design. Options:

- **3a. Establish-on-first-send (lazy).** Before the first TSP send to a member,
  the VTC runs `form_relationship` (and processes the member's accept via the
  inbound loop's Control-message path) and persists the state, then sends. Needs
  a relationship store keyed by `(vtc_vid, member_vid)` and an inbound
  Control-message handler in the PR-6b loop.
- **3b. Establish-at-admit.** Form the TSP relationship when a member is admitted
  (alongside the existing DIDComm onboarding), so steady-state sends find a
  ready relationship.
- **3c. Relationship-free Direct (if the SDK allows it).** If `send` does *not*
  require Bidirectional, skip relationships for v1 and treat TSP like DIDComm
  (intrinsic per-message auth). Simplest — **verify first.**

**Recommendation:** confirm 3c against a live mediator; if relationships are
mandatory, adopt 3a (lazy, least coupling to the admit flow) with the
relationship store + the Control-message handler wired into the PR-6b inbound
loop. Either way this is the decision to lock before the send path is coded.

## 4. Protocol selection (reuse PR 3)

`send_to_member` becomes protocol-aware:

1. Resolve the recipient's DID document →
   `vta_sdk::protocol::matching::ServiceCapabilities::from_did_document`.
2. Build *our* capabilities from the VTC's advertised services.
3. `select_protocol(ours, theirs, recipient_did)` → TSP > DIDComm > REST.
4. Dispatch: TSP arm (§2/§3) or the existing DIDComm arm; empty intersection →
   the typed `NoMatchingProtocol` error (already exists). The **opaque-carry
   TSP→DIDComm bridge is the mediator's job**, not the VTC's: if the member only
   advertises DIDComm, the matcher simply picks DIDComm — the VTC never builds a
   bridge envelope.

## 5. The abstraction change

The seam takes a built `didcomm::Message` today; TSP needs the **raw payload**
(the Trust Task / credential bytes) to pack itself. So PR 7 either:

- **5a.** changes `send_to_member` (and `push_to_holder`) to take the
  protocol-agnostic payload + recipient, packing per the selected protocol; or
- **5b.** keeps the DIDComm `Message` arg and, for the TSP arm, extracts the
  inner body to re-pack — lossy and awkward.

**Recommendation 5a:** thread the payload (already available at
`push_to_holder` before it builds the `Message`) down to a protocol-aware seam.
The DIDComm arm builds the `Message` as today; the TSP arm packs the payload.

## 6. VTC TSP foundation (prerequisite, mirrors 6a/6b)

The VTC `tsp` feature is only `["vta-sdk/tsp"]` — it does **not** enable
`affinidi-messaging-sdk/tsp`, so `atm.tsp()` isn't reachable yet (the same gap
6a found for the VTA). And the VTC has `AppState.atm` but no mediator-bearing TSP
profile. So PR 7 needs, mirroring 6a/6b:

- Cargo: VTC `tsp` → `["vta-sdk/tsp", "dep:affinidi-messaging-sdk",
  "affinidi-messaging-sdk/tsp"]` (+ the optional direct dep).
- A mediator-bearing `Arc<ATMProfile>` in the VTC `AppState` (built where the
  messaging config is in scope, like the VTA's PR-6b mount).

## 7. Resulting PR plan

- **PR 7a — VTC TSP foundation** (§6): Cargo wiring + mediator-bearing profile in
  `AppState`. Mechanical mirror of 6a/6b; feature-gated off; testable (builds).
- **PR 7b — protocol-aware `send_to_member`** (§4 + §5): selection via the
  matching engine + the TSP send arm, after §3 is decided. The relationship
  handling (if needed) lands here or in a 7c.
- **PR 7c — TSP relationships** (only if §3 says they're required): the
  `(vtc_vid, member_vid)` relationship store + the inbound Control-message
  handler in the PR-6b loop + establish-on-first-send.

## 8. Verification boundary

Like 6a/6b, the live send + relationship behaviour can't be verified without a
mediator. The selection logic (§4) and the foundation (§6) are testable; the
actual `atm.tsp().send` round-trip is the live smoke test (the same one that
validates 6a/6b inbound). **§3 in particular should be answered by that live
test before 7b/7c are coded.**

---

### Note: SDD PR 6c (auth over TSP) is already covered

`tsp-inbound-receive.md` §4 anticipated a separate "auth over TSP" PR. It needs
no new code: a TSP-delivered `auth/authenticate` Trust Task arrives through the
PR-6b inbound loop, is dispatched by `dispatch_one` → `dispatch_trust_task_core`
→ `handle_authenticate` — the **same audience-checked path** REST and DIDComm
use. The proven signer is supplied by `auth_from_did` (PR 6b, tested). There is
no TSP-specific auth surface and therefore no TSP-specific audience-isolation
gap to test beyond the existing `handle_authenticate` coverage. **6c is complete
by construction once 6b merged.**
