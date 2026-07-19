# Design note: how a VTA/VTC sends TSP outbound

**Status:** DRAFT for review — scopes SDD PR 7 (outbound seams). No send-path
code until the §3 relationship question is decided; the probe that decides it
already ships in `pnm health` (see §3.1) — run it against a live TSP-enabled VTA.
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

### 3.0 DECIDED: 3c (relationship-free routed send)

Confirmed against a live mediator (2026-07-19): `pnm health`'s TSP Trust-ping
returns `pong` — an `atm.tsp().send_routed` to the VTA, with no `form_relationship`
first, succeeds. **§3 resolves to 3c.** PR 7 carries no relationship store / FSM;
**PR 7c is dropped**. Outbound TSP is treated like DIDComm (intrinsic per-message
auth, routed through the mediator).

*Is the ping cold?* Yes, by construction: `TspPingSession::new` builds a fresh
in-memory ATM/TDK each run (no relationship-store path is configured anywhere in
the SDK) and `pnm` is a short-lived process, so every run starts from an empty
relationship store. And 3c holds even if `affinidi_tsp` forms a relationship
*transparently* on first send — our code still just calls `send_routed`; only a
hard "no relationship" send failure would refute 3c. To remove all doubt about a
persisted external store, `pnm health --fresh` (§3.1) probes from a throwaway
`did:key` minted at probe time, which can hold no prior relationship at all.

Consequence for device push: routing a TSP frame to a `did:key` device works
via the shared mediator exactly as DIDComm does (`send_routed(&[mediator, dev]`).
The remaining gate is **not** routing or relationships — it is a *capability
signal*: a `did:key` device can't advertise `#tsp` in a document, so the VTA
needs another way to know a device can **receive** TSP before it prefers TSP for
that device. See the outbound-send tracks below / the Phase-2 plan.

### 3.1 The probe already exists — how to decide

No new probe is needed. `pnm-cli`'s `health::tsp_probe` (compiled by default —
`tsp` is in the crate's `default` features) already performs the load-bearing
test: it opens the client's TSP websocket to the mediator and does a **cold
`atm.tsp().send_routed`** of a `messaging/ping/0.1` Trust Task to the VTA with
**no `form_relationship` call first**, then awaits the routed reply. `pnm health`
runs it automatically whenever the target VTA's DID document advertises a
`#tsp` (`TSPTransport`) service. Run against a live TSP-enabled VTA:

```
pnm health          # (default build already has `tsp`) — round-trip from your session DID
pnm health --fresh  # cold SEND probe from a throwaway did:key minted at probe time
```

`--fresh` mints a never-before-seen `did:key` and runs the routed send from it,
judging success on the **send alone** (`✓ cold send accepted`) — it does *not*
wait for a reply. Two facts about a throwaway VID make the round-trip impossible
but are irrelevant to §3: it has no ACL entry — so the VTA's TSP dispatch
(`dispatch_one` gates *every* task, `messaging/ping` included, on `auth_from_did`)
answers `403` — and it isn't a registered mediator account, so that reply can't
route back to it. §3 asks only whether a cold `send_routed` **hard-fails**
without a relationship; the send being accepted answers it (3c). Plain
`pnm health` (session DID — registered + ACL'd) does the full pong round-trip.

**Confirmed live (2026-07-19):** plain `pnm health` → `VTA TSP ✓ pong (250ms)`,
and a `--fresh` cold send reached the VTA (`TSP trust-task dispatched … 403`) —
both prove the relationship-free routed send. 3c holds on real infrastructure.

Read the **"VTA TSP → Trust-ping"** line:

- **`✓ pong (Nms)`** → a cold routed TSP send to a peer we have no relationship
  with *did not* hard-fail → **§3 resolves to 3c** for the routed path. PR 7
  proceeds with no relationship store / FSM (drop PR 7c); treat TSP like DIDComm.
- **`✗ TSP ping failed: <error>`** → capture the error. If it names a
  relationship / not-authorized / VID-unknown precondition, relationships are
  required → adopt **3a** (lazy establish-on-first-send) and keep PR 7c.

**Scope of the test — be precise:** the probe exercises the **routed** send
(`send_routed`, through the mediator bridge), which is exactly the path VTA→device
push uses (the device is a mediator account). It is a genuine *cold* send — the
client VID has no prior relationship with the VTA, so if the SDK required a
`Bidirectional` state the **send itself** would fail before any reply. It does
**not** exercise Direct (non-routed) `send`; the ecosystem routes everything
through the mediator (ADR 0008), so Direct isn't on the design path and needs no
separate probe here.

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

### 4.1 IMPLEMENTED — device push: learn-from-inbound (not document selection)

Document-based `select_protocol` (§4) works for **node peers** that advertise a
`#tsp` service. It does **not** work for the immediate outbound consumer — the
device push to a `did:key` approver/requester — because a `did:key` has no
service block to advertise `#tsp`, and the device picks its inbox transport at
*runtime* (the mobile app's DIDComm/TSP toggle). So the document can never carry
the answer. Instead the VTA **learns from inbound**:

- `messaging::tsp_reach::TspReachability` — an in-memory, self-expiring map of
  DIDs last seen sending over TSP (TTL-bounded; never persisted).
- `messaging::tsp_inbound::dispatch_one` records the **proven** `sender_vid` on
  every inbound TSP frame — cryptographic proof that DID is on TSP right now.
- The device-push sites (`consent_request::push_one` and
  `step_up::maybe_push_step_up`) call `step_up::try_push_over_tsp`: if the
  recipient is fresh in the map, route the **bare** Trust-Task doc over TSP via
  `atm.tsp().send_routed([mediator, recipient])` (§3 = 3c, no relationship);
  otherwise fall through to the existing DIDComm `send_guaranteed`. A TSP send
  error also falls back to DIDComm.

`push_granted` stays DIDComm-only: it targets the browser **requester** (which
doesn't speak TSP), and its notice body isn't a full Trust-Task envelope, so the
device's TSP inbox — which classifies by the doc's own `type` — would ignore it.

The device announces its TSP-reachability by sending the VTA a TSP frame; that
"announce on connect" is a small mobile follow-up (the iOS TSP session in
vta-mobile-agent-ios #21 is receive-only for now), so until it lands the first
contact is DIDComm and this arm activates for any DID that has sent inbound TSP
(e.g. exercised via `pnm`).

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
