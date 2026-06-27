# Design note: how a VTA receives TSP inbound

**Status:** Decision record — gates SDD PR 6 (inbound listener + auth) and
informs PR 7 (outbound).
**Owner:** Glenn Gore
**Created:** 2026-06-26
**Updated:** 2026-06-26 — **the TDK gained native TSP support that resolves both
load-bearing open questions** (see §0 + §3). `affinidi-messaging-sdk` 0.18.37
graduated TSP from experimental to supported (TDK #528) and added turn-key
client auth + live-stream CESR sniffing. The recommendation (Option A) stands
but is now much closer to turn-key.
**Context:** `docs/05-design-notes/tsp-enablement.md` §6 assumed "add a TSP
listener alongside the DIDComm one." This note records why that's not a drop-in
and specifies the actual receive path.

---

## 0. Update (2026-06-26): native TDK TSP support landed

Two TDK capabilities resolve the open questions this note originally flagged:

- **Turn-key TSP client auth** — `affinidi_messaging_sdk::TspAuthHandler` (TDK
  #533): a pure-TSP `CustomAuthHandler` that signs a challenge to the mediator's
  `POST /tsp/authenticate`; afterwards the usual `atm.tsp()` ops authenticate
  transparently. **Resolves §3 open-Q2.**
- **Live-stream CESR sniffing** — the SDK websocket transport
  (`transports/websockets/websocket.rs::process_inbound_didcomm_message`) now
  sniffs `atm.tsp().is_tsp(frame)` and, for a TSP frame, surfaces it as
  `WebSocketResponses::PackedMessageReceived` (un-unpacked) instead of failing
  the DIDComm unpack and dropping it. **Resolves §3 open-Q1 (the load-bearing
  one): the live-stream *does* surface TSP, gracefully, as a packed frame the
  consumer unpacks via `atm.tsp()`.**

**Net effect on the plan:** Option A (below) is unchanged in shape but no longer
needs a bespoke pickup loop *or* an upstream change — the VTA already holds a
mediator websocket via its DIDComm listener, and that stream now carries TSP
frames. The **only** remaining seam is whether the VTA's `DIDCommService`-based
listener exposes those `PackedMessageReceived` TSP frames to a VTI handler (vs.
only routing unpacked DIDComm `Message`s). If `DIDCommService` doesn't surface
packed frames, the fallback is a `direct_channel` / pickup consumer on the same
authenticated session — still no upstream change. Verify which against the
0.18.37 `DIDCommService` API when implementing PR 6b.

### 0a. Update (2026-06-26, later): raw-TSP WebSocket delivery mode (mediator)

TDK #534 (`affinidi-messaging-mediator` **0.16.31**) adds a **second, cleaner
inbound mode** — but **mediator-side only for now**:

- A WebSocket client opts in by offering the **`tsp` subprotocol** (alongside
  `bearer.{token}`). The socket then carries **raw TSP `Message::Binary`
  frames**, with a **flush-on-connect + delete-on-successful-send** contract
  (queued TSP is drained on connect; a frame is deleted from the inbox only once
  its send succeeds → **at-least-once** delivery). This is a dedicated TSP
  channel, separate from the DIDComm-text websocket of §0/Mode 1.
- **The `affinidi-messaging-sdk` client was NOT changed by #534** (it's
  mediator + test-mediator only; the e2e test drives it with a raw
  tokio-tungstenite socket). So there is **no turn-key ATM API to *open* this
  raw-TSP websocket yet** — using it means a raw-ws client or a future SDK
  helper.

### 0b. Update (2026-06-27): SDK client consumer for Mode 2 landed (#536) — this is now the plan

TDK #536 (`affinidi-messaging-sdk` **0.18.39**) adds the turn-key **client
consumer** for the raw-TSP WebSocket mode that #534 added server-side. **Mode 2
is now fully available client-side, so PR 6b adopts it** (superseding the Mode 1
sniff path):

- `atm.tsp().connect_websocket(profile) -> TspWebSocket` — opens the raw-TSP WS
  to the mediator; **authenticates internally** (calls the TDK authentication →
  `TspAuthHandler` path) and the server runs flush-on-connect + delete-on-send.
- `TspWebSocket::recv()` → `Option<Vec<u8>>` next **raw qb2 TSP** message (`None`
  on close; skips ping/pong); `.send(&[u8])` for outbound.
- `atm.tsp().unpack_bytes(profile, qb2)` → `(payload, sender_vid)` — `payload`
  is the inner Trust Task doc; `sender_vid` is the **proven signer**.

**PR 6b inbound loop (turn-key):**

```rust
let ws = atm.tsp().connect_websocket(&profile).await?;
while let Some(qb2) = ws.recv().await? {
    let (payload, sender_vid) = atm.tsp().unpack_bytes(&profile, &qb2).await?;
    // sender_vid = intrinsic proven signer (like DIDComm msg.from)
    dispatch_trust_task_core(&app_state, sender_vid, payload).await;
}
// recv() == None → reconnect with backoff (mirror the DIDComm RestartPolicy)
```

So PR 6b is: own this loop as a background task in `AppState` (gated on the
`tsp` feature + a configured TSP mediator), with reconnect/backoff, feeding the
existing spine. **No DIDComm-stream sniffing, no mailbox-partition concern, no
`DIDCommService` hook question** — those are all moot under Mode 2. Both
`connect_websocket` and `unpack_bytes` take `Arc<ATMProfile>`, confirming the
profile-into-`AppState` plumbing (§5) serves 6a, 6b, **and** outbound (PR 7).

**Dependency floor rises to `affinidi-messaging-sdk` ≥ 0.18.39** for PR 6b
(6a/unseal only needs ≥ 0.18.37 + `unpack`/`unpack_bytes`).

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

### Option B — live websocket delivery (now largely shipped upstream)

Originally framed as "needs an upstream pre-unpack hook." **Update (§0): the
sniff already shipped** — the SDK websocket transport detects TSP frames and
surfaces them as `PackedMessageReceived` rather than dropping them. So live
delivery is available *if* the VTA's listener exposes packed frames to a VTI
consumer. This collapses Option A and Option B into one approach over the
existing authenticated websocket; the choice is now just *where* the VTA taps
the packed TSP frames (DIDCommService handler surface vs. a `direct_channel`
consumer), not push-vs-poll.

### Option C — mediator bridges all TSP→DIDComm at the recipient

The VTA only ever receives DIDComm; the recipient's mediator bridges inbound TSP
into a DIDComm `forward`.

- **Rejected:** that's the bridge for **DIDComm-only** recipients. A
  TSP-native VTA wants the TSP envelope end-to-end (the whole point — metadata
  privacy + bounded size); bridging at its own mediator throws that away.

---

## 3. Recommendation & open questions

**Adopt Option A** — receive TSP off the VTA's existing authenticated mediator
connection (no bespoke pickup loop, no upstream change), filter `is_tsp`, unpack
via `atm.tsp()`, and feed `dispatch_trust_task_core`.

Original open questions — status after the §0 TDK update:

1. ~~Mailbox partition (the load-bearing one)~~ **RESOLVED (§0).** The SDK
   websocket sniffs `is_tsp` and surfaces TSP frames as `PackedMessageReceived`
   instead of failing the DIDComm unpack — so the live-stream carries TSP
   *and* DIDComm without dropping or double-unpacking. No mediator-behavior
   verification needed; the SDK handles the partition.
2. ~~TSP client auth to the mediator~~ **RESOLVED (§0).** `TspAuthHandler`
   (`POST /tsp/authenticate`) is turn-key; `atm.tsp()` authenticates
   transparently afterwards.
3. ~~VID registration~~ **Effectively resolved.** `atm.tsp().unpack(profile,
   stored)` extracts the profile's Ed25519+X25519 keys from the secrets resolver
   directly — no separate `PrivateVid` registration. The VTA's existing DID
   profile is the VID.

**The one remaining seam** (narrow, no upstream dep): does the VTA's
`DIDCommService`-based listener (0.18.37) expose `PackedMessageReceived` TSP
frames to a VTI handler, or must the VTA tap a `direct_channel` on the same
session? Determine this against the live `DIDCommService` API when coding PR 6b —
it's a "where do we attach the consumer" question, not a design risk.

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
`unseal_tsp_secret(atm, profile, caller_did, message)` (mirroring
`unseal_secret`): `atm.tsp().unpack(profile, message)` → `(payload, sender_vid)`,
sender-vs-caller cross-check, then `serde_json::from_slice(&payload)` into the
cleartext `VaultSecret`.

**One plumbing wrinkle to resolve in PR 6a (found while scoping):** unlike the
DIDComm `atm.unpack(jwe)` (no profile arg), `atm.tsp().unpack` requires an
`Arc<ATMProfile>`, and the VTA's profile is **not** currently held in `AppState`
— it's created inline for the DIDComm listener (`server.rs`) and the vault-context
ATM (`state.atm`) is built separately without a registered profile (no
`profile_add` in `vta-service` today). So PR 6a must either (a) thread the VTA's
`Arc<ATMProfile>` into `AppState`, or (b) construct it on demand in
`unseal_tsp_secret` from the VTA DID + secrets resolver. (a) is cleaner and also
serves PR 6b/7. This makes 6a slightly more than a pure mirror of
`unseal_secret`, but it's still self-contained and listener-independent.

---

## 6. Resulting PR plan (supersedes the single "PR 6" in tsp-enablement.md §13)

- **PR 6a — sealed-envelope TSP unseal** (§5). Self-contained; no listener dep.
  Includes the `Arc<ATMProfile>`-into-`AppState` plumbing (§5).
- **PR 6b — TSP inbound via `atm.tsp().connect_websocket`** (§0b — Mode 2, the
  current plan): a background task in `AppState` (gated on `tsp` + a configured
  TSP mediator) that runs the `recv()` → `unpack_bytes` → `dispatch_trust_task_core`
  loop with reconnect/backoff. No DIDComm-stream sniffing, no
  `DIDCommService`-hook question — Mode 2 is a dedicated channel. `connect_websocket`
  handles TSP auth internally (`TspAuthHandler`).
- **PR 6c — auth over TSP** (§4): mostly a consequence of 6b; the delta is the
  proven-signer plumbing + an audience-isolation test. May fold into 6b.

**Dependency floor:** PR 6a (unseal) needs `affinidi-messaging-sdk` ≥ 0.18.37
(`atm.tsp().unpack`); **PR 6b needs ≥ 0.18.39** (`connect_websocket` /
`unpack_bytes`, #536). The workspace pins `affinidi-tdk = "0.8"`; verify the
resolved messaging-sdk patch (or bump) when starting each.
