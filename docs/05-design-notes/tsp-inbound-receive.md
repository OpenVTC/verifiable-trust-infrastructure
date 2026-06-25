# Design note: how a VTA receives TSP inbound

**Status:** DRAFT for review — gates SDD PR 6 (inbound listener + auth) and
informs PR 7 (outbound). No code until approved.
**Owner:** Glenn Gore
**Created:** 2026-06-26
**Context:** `docs/05-design-notes/tsp-enablement.md` §6 assumed "add a TSP
listener alongside the DIDComm one." This note records why that's not a drop-in
and specifies the actual receive path.

---

## 1. The problem

PR 6 needs the VTA to *receive* TSP messages and feed them into the same
`dispatch_trust_task_core` spine that REST and DIDComm already feed. The SDD
hand-waved "a TSP listener alongside the DIDComm one." Investigation shows there
is **no turn-key TSP listener** to stand up, so the path has to be designed.

### 1.1 What runs today (DIDComm inbound) — verified

```
mediator ws ──► DIDCommService (affinidi-messaging-didcomm-service)
                  │  unpacks the DIDComm JWE  ► authenticated `Message`
                  ▼
                Router  (routes by msg.type via handler_fn / MessageHandler)
                  ▼
                handler  ──► crate::trust_tasks::dispatch_trust_task_core
```

`DIDCommService` is a **router that unpacks DIDComm before dispatch**
(`vta-service/src/messaging/{router,handlers}.rs`; the service's `Router` +
`handler_fn`). The VTA only ever sees an already-unpacked DIDComm `Message`. The
service exposes middleware (`MiddlewareHandler`/`Next`) but **no pre-unpack raw-bytes
hook**. A TSP message (CESR/qb2, not a JWE) pushed through this path would fail
DIDComm unpack inside the service.

### 1.2 What the TSP SDK gives us — verified

`affinidi-messaging-sdk`'s TSP surface (`protocols/tsp.rs`) is **fetch/unpack**,
not a service runner:
- `atm.tsp().is_tsp(stored)` — detect that a fetched/stored message is TSP
  (base64url-decode + CESR magic-byte sniff).
- `atm.tsp().unpack(stored, our_vid)` — decode → resolve sender → decrypt+verify
  → `(payload, sender, receiver, message_type)`.

And the **mediator stores TSP to the mailbox for pickup** — verified in
`affinidi-messaging-mediator` `messages/inbound.rs`: `handle_inbound_tsp` →
`deliver_tsp_local` → `deliver_opaque`, described as "stores it for pickup —
reusing the protocol-neutral store path that DIDComm direct delivery uses." So a
recipient VTA's TSP messages land in the **same mailbox** as its DIDComm
messages; the client retrieves them with message-pickup and unpacks per-message.

---

## 2. Options

### Option A — a separate TSP fetch/pickup loop (RECOMMENDED for v1)

A background task (`messaging::tsp_inbound`, mirroring how the DIDComm listener is
owned by `AppState`) that:

1. Registers the VTA's **TSP VID** with the ATM's TSP agent — the VID is the
   VTA's DID; the keys are its existing Ed25519 (auth/sign) + X25519
   (keyAgreement/decrypt). No new key material (tsp-enablement.md D5).
2. Pickup-loops the mediator mailbox for the VTA's DID, **filtering with
   `is_tsp`** so only TSP messages are taken on this path (DIDComm messages stay
   with `DIDCommService`).
3. `atm.tsp().unpack(stored, vta_vid)` → the inner payload is a `trust_tasks_rs`
   document (the protocol-agnostic Trust Task — same shape DIDComm/REST carry).
   The unpacked TSP **sender VID is the proven signer** (intrinsic auth, like
   DIDComm's `msg.from`).
4. Hand `(payload, sender)` to **`dispatch_trust_task_core`** — the existing
   spine. Auth (§4) and every holder verb flow through unchanged.

- **Pros:** zero upstream dependency — uses only published SDK APIs; no
  `DIDCommService` changes; clean coexistence (the two paths partition the
  mailbox by `is_tsp`); restart-resilient the same way the drain sweeper is.
- **Cons:** pickup-poll latency vs. a live websocket push; a second mailbox
  consumer to reason about (must not double-consume vs. the DIDComm pickup —
  see §3).

### Option B — pre-unpack sniff hook in `DIDCommService` (upstream change)

Add a middleware/hook in `affinidi-messaging-didcomm-service` that sniffs the
CESR magic on raw inbound bytes and routes TSP out *before* DIDComm unpack, into
a VTI-supplied TSP handler.

- **Pros:** live (websocket-push) latency; one inbound connection.
- **Cons:** requires an **upstream change** to the messaging-service crate;
  couples our rollout to their release cadence. Defer to a v2 optimization.

### Option C — mediator bridges all TSP→DIDComm at the recipient

The VTA only ever receives DIDComm; the recipient's mediator bridges inbound TSP
into a DIDComm `forward`.

- **Rejected:** that's the bridge for **DIDComm-only** recipients. A
  TSP-native VTA wants the TSP envelope end-to-end (the whole point — metadata
  privacy + bounded size); bridging at its own mediator throws that away.

---

## 3. Recommendation & open questions

**Adopt Option A (TSP fetch/pickup loop) for PR 6**, with Option B as a future
live-delivery optimization once (and if) the upstream hook lands.

Resolve before/while implementing:

1. **Mailbox partition (the load-bearing one).** Does the existing DIDComm
   live-stream / pickup also surface the stored **TSP** blobs (which
   `DIDCommService` cannot unpack and would error/drop)? Two sub-cases:
   - If the mediator's live-stream only pushes DIDComm and TSP is pickup-only →
     clean: Option A's loop owns TSP, `DIDCommService` owns DIDComm.
   - If the live-stream pushes TSP blobs too → we must ensure `DIDCommService`
     **ignores** non-DIDComm bytes (an `ignore`/error-handler tweak) rather than
     erroring, and that pickup doesn't double-consume. **Verify against the
     running mediator before coding the loop.**
2. **TSP client auth to the mediator.** Per the upstream dual-protocol mediator
   SDD (D1), a TSP client performs a TSP handshake that mints the **same** EdDSA
   `SessionClaims` JWT used by DIDComm. Confirm the VTA establishes that session
   (and the relationship/`is_tsp` pickup auth) at listener start.
3. **VID registration.** Confirm the ATM `tsp()` agent accepts the VTA's
   existing DID + secrets as a `PrivateVid` (it should — `affinidi-tsp` has a
   `did-resolver` feature and the keys are standard Ed25519/X25519).

---

## 4. Auth third path (rides §2 Option A)

`vti_common::auth::handlers::handle_authenticate` already content-negotiates
(DI-signed Trust Task / DIDComm envelope). TSP adds **no new auth shape** — a
TSP-delivered `auth/authenticate/0.1` Trust Task arrives via the §2 loop, is
unpacked (proven sender VID), and is handed to `dispatch_trust_task_core` →
`handle_authenticate` exactly as the DIDComm path is. The only requirement:
audience isolation (VTA vs VTC) must reject cross-audience TSP-minted tokens
identically. So "auth over TSP" is a *consequence* of Option A, not separate
code — modulo confirming the proven-signer plumbing carries through the TSP
unpack the same way `msg.from` does for DIDComm.

---

## 5. Sealed-envelope unseal is independent (can land first)

The vault `SealedEnvelope::TspMessage` unseal (`trust_tasks/vault.rs`,
`operations/vault/upsert.rs`) does **not** depend on the inbound listener. It's a
request-scoped unpack: when a `vault/upsert` Trust Task carries a `tsp-message`
sealed secret, add a `TspMessage` arm beside `DidcommAuthcrypt` that calls a
`unseal_tsp_secret(atm, caller_did, message)` (mirroring `unseal_secret`):
`atm.tsp().unpack` with the VTA's VID + the sender-vs-caller cross-check, then
the existing cleartext deserialize. This is a clean, self-contained, testable PR
that can land **before** the listener — recommend doing it as the first concrete
PR 6 increment while the §3 mailbox question is verified.

---

## 6. Resulting PR plan (supersedes the single "PR 6" in tsp-enablement.md §13)

- **PR 6a — sealed-envelope TSP unseal** (§5). Self-contained; no listener dep.
- **PR 6b — TSP inbound fetch/pickup loop** (§2 Option A) feeding
  `dispatch_trust_task_core`, after the §3.1 mailbox question is verified.
- **PR 6c — auth over TSP** (§4): mostly a consequence of 6b; the delta is the
  proven-signer plumbing + an audience-isolation test. May fold into 6b.
- Option B (live pre-unpack hook) is a later optimization, gated on upstream.
