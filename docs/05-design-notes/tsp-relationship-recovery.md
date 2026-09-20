# TSP relationship recovery — surviving restarts and asymmetric state loss

**Status:** decision cores prototyped (D1–D5), on branch `feat/inbound-kind` of
`affinidi-tdk-rs` plus the VTA wiring here. Depends on the Rev 3 flag day (see
`tsp-rev3-migration.md`); the gating rule this note recovers from is live only
once `affinidi-tsp` 0.2.0 is in place, and the VTA wiring compiles only once an
SDK release carries D1–D5. Runtime integration (D6) and hardening (D7–D9) remain.
Client-side send-path self-repair — the first consumer of `reset_relationship` —
is now wired into `vta-sdk`'s `VtaClient::dispatch_trust_task` (see D4 below).

| Item | What | Status |
| --- | --- | --- |
| D1 | Durable `RelationshipStore` | core in SDK + VTA wiring (gated on SDK publish) |
| D2 | Idempotent re-establish transition | done in `affinidi-tsp` |
| D3 | Recovery-aware send readiness | core in SDK |
| D4 | Bounded, single-flight, jittered recovery | core in SDK; client-side reply-timeout self-repair wired in `vta-sdk` (per-call, no coordinator yet) |
| D5 | Idle eviction (7-day) | core in SDK |
| D6 | Single-flight coordinator + eviction sweep + enumerate | core in SDK (`RecoveryCoordinator`, `evict_idle`, `scan_prefix`); service wiring pending |
| D7 | Inbound-invite rate limit (re-resolve keys / ACL still pending) | limiter core in SDK (`InviteRateLimiter`) |
| D8 | Recovery metrics (§7.2.2 drop counter pending) | `RecoveryMetrics` in SDK; drop counter is service-side |
| D9 | Enumerate established relationships for startup reconcile | core in SDK (`established_relationships`); service wiring pending |

## The problem

Rev 3 §7.2.2 has an endpoint **drop** an application message from a VID it
holds no relationship with. Dropped, not refused — nothing goes back to the
sender. The gate is enforced in
`affinidi-messaging-sdk/src/protocols/tsp.rs` (the `tsp_relationship_gating()`
check before both `unpack_bytes` at ~L1971 and `unpack_message` at ~L2056),
and `affinidi-tsp/src/relationship.rs` defaults `RelationshipPolicy` to
`Gated`. The receiving adapter deletes the frame from the mediator so it stops
being redelivered (`transport_adapter.rs` — this is the line that logged the
incident that started this note).

That is fine when both endpoints agree on the relationship. It fails the moment
they **disagree**, and today they disagree routinely, because the default store
is ephemeral:

> `InMemoryRelationshipStore` … is **wiped on process restart**
> — `protocols/tsp.rs` L284.

The concrete failure we hit: a client held `Bidirectional` with `glenn-vta`,
the VTA restarted onto Rev 3 with an empty store, and every subsequent
application message from the client was dropped at the gate. The client never
learns why — §7.2.2's silent drop means it just sees a `TspPingSession::ping`
(`vta-sdk/src/session.rs` L2900, which calls `send_routed` with no prior
`relate`) time out. From the client's side an unresponsive VTA and a VTA that
forgot the relationship are indistinguishable.

This note specifies how each service **recovers** — detects that a relationship
has been lost and re-establishes it — without operator intervention.

## What exists today

| Piece | Where | State |
| --- | --- | --- |
| Relationship state machine | `affinidi-tsp/src/relationship.rs` | `None → Pending → Bidirectional`; `admits_application_message()` = *not `None`*; `can_send()` = *only `Bidirectional`* |
| The §7.2.2 gate | `messaging-sdk/protocols/tsp.rs` L1971, L2056 | live when `tsp_relationship_gating()` (default true) |
| Store seam | `RelationshipStore` trait, `protocols/tsp.rs` L191 | `get`/`set` state, plus capability, thread-digest and reply-path caches |
| Default store | `InMemoryRelationshipStore`, L284 | ephemeral, wiped on restart |
| Persistence injection | `ATMConfigBuilder::with_relationship_store`, `config.rs` L545 | exists; **nobody injects a durable impl** — `config.rs` L667 falls back to the in-memory default |
| Form a relationship | `TspOps::form_relationship_routed`, `protocols/tsp.rs` L1312; `TspPingSession::relate`, `session.rs` L2758 | send-only invite; guarded by a prior `relationship_state()` read |

Two facts from that table drive everything below:

1. **The persistence seam already exists** — `RelationshipStore` +
   `with_relationship_store`. Nobody has implemented a durable one. That is the
   single biggest lever and it needs no protocol change.
2. **The state machine has no re-establish path.** This is the trap.

## The three constraints

### C1 — The state machine deadlocks a naïve re-invite

Recovery is reconciling two independently-held halves after one side loses
its. The obvious move — "just re-invite" — is broken in both directions by
the transition table in `relationship.rs`:

- The side that **lost** state can re-invite (`None → SendInvite → Pending`),
  fine.
- The side that **lost** state but whose *local* view still says
  `Bidirectional` (asymmetric loss detected by the *other* peer) cannot:
  `SendInvite` is only valid from `None`, so `form_relationship_routed` returns
  `InvalidTransition`. `session.rs` already works around this by reading
  `relationship_state()` first and skipping the invite — which is exactly the
  wrong thing for recovery.
- The side that **kept** state rejects the peer's re-invite:
  `Bidirectional + ReceiveInvite` is **not in the table**, so it falls to the
  catch-all `Err(InvalidTransition)`.

So an unmodified state machine cannot recover: whoever re-invites, someone
raises `InvalidTransition`. **Recovery requires a new, idempotent transition**
(D2). This is not optional polish — without it the rest of the design cannot
complete a handshake.

### C2 — Detection is timeout-based and ambiguous

§7.2.2 mandates a *silent* drop; it is a security property (an unrelated VID
must not be able to confirm that a target VID is legitimate). So the peer will
never signal "I lost our relationship." The only local signal is **no reply**,
which also means "peer down" and "network partition." Recovery therefore must
be driven by the **sender's own state and timers**, never by a message from the
peer, and must not treat every timeout as a lost relationship (D4).

### C3 — There is exactly one durable seam, and it forgets time

`RelationshipStore` is the only place state lives, and its `get`/`set` carry no
timestamp — there is no notion of "last used." The 7-day idle-eviction policy
needs one. Either the trait grows activity tracking or the durable impl records
it out of band (D5).

## Design

### D1 — A durable `RelationshipStore` (the real fix) — **core prototyped**

Implement `RelationshipStore` against durable storage and inject it via
`with_relationship_store`. This alone converts "every restart drops every peer"
into "restart is transparent." The 7-day cache in the original proposal is an
**eviction policy on top of this store**, not a substitute for it; if the store
isn't durable, recovery fires on every bounce for every peer and we have built a
thundering-herd generator instead of a recovery mechanism.

Persist the full pair record, not just the state enum: the trait already
carries capability, `thread_digests` (needed for the §7.2.3 invite-race
tiebreak) and `reply_path` (§7.2.4 — a MUST, not an optimisation). A durable
store that drops those reintroduces conformance losses the in-memory store's
docstrings already call out.

**Prototype (in `affinidi-tdk-rs`, branch `feat/inbound-kind`):** rather than a
bespoke store per service — five chances at the same persistence bug — the
serialisation, key layout and per-facet defaults live once in the SDK:

- `ThreadDigests` gained `Serialize`/`Deserialize` (it was the one stored facet
  that lacked them; `RelationshipState`, `PeerCapability`, `CapabilitySource`
  already had them).
- New `PersistentRelationshipStore<B: RelationshipKv>` in
  `affinidi-messaging-sdk` implements the whole `RelationshipStore` trait over a
  three-method backend trait, `RelationshipKv` (`get`/`put`/`delete`). Each
  facet (state, digests, reply-path, capability) is a separate length-prefixed
  key per `(our_vid, their_vid)` pair — mirroring `InMemoryRelationshipStore`'s
  independent maps, so setters never read-modify-write a shared record.
- Five tests, incl. `persistent_store_survives_a_restart` (drop the store,
  rebuild over the same backend, assert `Bidirectional` and the digests are
  still there) and a key-collision test for the length-prefix encoding. Full SDK
  suite green (184); both new public types re-exported from the crate root.

A service now supplies only a thin `RelationshipKv` adapter over the store it
already runs, and injects `PersistentRelationshipStore::new(adapter)` at its ATM
build site.

**VTA wiring (written; gated on an SDK release):** done in `vta-service` /
`vta-keyspaces`, on the same branch as the SDK work:

- A `relationships` keyspace (`vta-keyspaces`): added to `ALL`,
  `EXCLUDED_FROM_BACKUP` (re-establishable and DID-scoped, like `sessions`) and
  classified `Cascade` for DID deletion (protocol state keyed by the VID, like
  `cache`/`outbox`). Both census tests (`backup_partition_is_total`,
  `did_delete_census`) pass.
- `KeyspaceRelationshipKv` (`vta-service/src/messaging/tsp_relationship_store.rs`):
  a `RelationshipKv` over one `KeyspaceHandle`. Encryption-at-rest comes for free
  — the handle is opened through the same `apply_encryption(store.keyspace(…))`
  as every other keyspace, so there was no separate encryption bootstrap to
  navigate after all.
- Injected in `build_messaging` — the long-lived TSP-serving listener — as
  `.with_relationship_store(Arc::new(PersistentRelationshipStore::new(KeyspaceRelationshipKv::new(relationships_ks))))`,
  `#[cfg(feature = "tsp")]`. The keyspace is opened beside `outbox_ks` in
  `server.rs` and threaded through `MessagingConnect`; the two `build_messaging`
  callers (`server.rs`, `test_support.rs`) pass it.

`cargo check -p vta-service --features tsp` fails on **exactly two** symbols —
`affinidi_messaging_sdk::{RelationshipKv, PersistentRelationshipStore}` — because
the workspace pins `affinidi-messaging-sdk` from crates.io (0.26.4) and there is
deliberately no `[patch]`. Everything else type-checks against the published API.
So the wiring is complete and correct; it compiles the moment an SDK release
carries D1 — the same publish gate the whole Rev 3 migration sits behind
(`tsp-rev3-migration.md`).

The other `ATM::new` sites (`transient_handshake.rs`, `server.rs` status probe)
are short-lived DIDComm handshakes that don't serve TSP application traffic, so
they keep the ephemeral default deliberately; only the persistent listener needs
the durable store.

### D2 — An idempotent re-establish transition (protocol change) — **prototyped**

Make **`ReceiveInvite` total over the established states** in
`affinidi-tsp/src/relationship.rs`:

| From | Event | To | Why |
| --- | --- | --- | --- |
| `Bidirectional` | `ReceiveInvite` | `InviteReceived` | peer lost its half and re-invited; we reopen to re-accept |
| `InviteReceived` | `ReceiveInvite` | `InviteReceived` | retransmitted RFI; idempotent |
| `None` | `ReceiveInvite` | `InviteReceived` | unchanged (fresh invite) |
| `Pending` | `ReceiveInvite` | — | unchanged: the §7.2.3 digest tiebreak owns this (crossed invites) |

**No new `Reestablish` event.** There is no separate re-establish control
message in TSP — a re-invite over a live relationship *is* the signal — so
overloading `ReceiveInvite` is the faithful, minimal change. The peer that kept
the relationship drops to `InviteReceived` and re-accepts; its RFA is what
repairs the peer's lost inbound half, so there is no shorter path back to
`Bidirectional`. The window is safe: `can_send()` is briefly false, but those
sends were already being dropped at the peer's §7.2.2 gate, and
`admits_application_message()` stays true so a §3.6-bundled payload still lands.

This is the load-bearing change and it lives in `affinidi-tsp`, so it ships in a
TDK release and every consumer inherits it. Verified: the SDK does
`pub use affinidi_tsp::relationship::RelationshipState` and its inbound-invite
path (`protocols/tsp.rs` ~L1507) special-cases only `prior == Pending` before
calling `transition(ReceiveInvite)` — identical to `affinidi-tsp`'s
`handle_control` — so the VTA/mediator gate picks up reconcile with no
SDK-side change.

**Prototype status:** landed on branch `feat/inbound-kind` in `affinidi-tdk-rs`.
Three FSM unit tests plus two end-to-end two-agent tests with real crypto:
`a_lost_half_is_recovered_by_re_inviting_the_peer_that_kept_it` (the deadlock
case, now resolved) and `a_reconcile_invite_delivers_its_bundled_payload_immediately`
(§3.6 one-round-trip recovery). Full `affinidi-tsp` suite green (178 tests);
`affinidi-messaging-sdk` compiles unchanged.

### D3 — `ensure_relationship` on the send path, with §3.6 bundling — **core prototyped**

**Prototype (in `affinidi-messaging-sdk`, branch `feat/inbound-kind`):** the
send-decision is a pure, total function plus a store-reading check and a
ready-made send:

- `SendReadiness` (`Ready` / `Reestablish` / `HandshakeInFlight`) and
  `readiness_for(state)` — a pure, total map over the four relationship states,
  so a new state cannot silently fall through to "send anyway". Tested exhaustively.
- `TspOps::send_readiness(profile, their)` reads the (durable) store and reports
  which case a send is in — the local, unambiguous half of recovery.
- `TspOps::send_reestablishing(profile, their, route, payload)`: on
  `Reestablish` it sends an invite (`form_relationship_routed`, valid only from
  `None`) then the payload immediately after (§3.6); on `Ready`/`HandshakeInFlight`
  it sends directly. This is what a service calls instead of `send_routed`.
- A D1×D3 test proves readiness is read off the store, so after a restart a send
  takes the `Ready` path (no needless re-invite) — `readiness_follows_the_durable_store_across_a_restart`.
  Full SDK suite green (187); clippy clean.

Scope of the prototype is the **local-knowledge** cases (our half missing or a
handshake mid-flight). It deliberately does **not** cover the peer having lost
*its* half while we still read `Bidirectional` — that surfaces only as a
round-trip timeout (§7.2.2's drop is silent, C2) and is D4's job. `Ready` sends
once and returns; the timeout-driven reset-and-retry is not in this primitive.

The eventual full shape (the network orchestration, timeout detection and retry
folded into the outbox rather than a bolt-on loop — see D4/D6, and the "retry
has one owner per failure domain" rule in the workspace CLAUDE.md):

```
send_app(peer, payload):
    st = store.get(me, peer)              # durable
    if st.can_send():                     # Bidirectional
        send(payload)
        on gated-drop signal / round-trip timeout → recover(peer, payload)
    else:                                  # None or expired
        recover(peer, payload)

recover(peer, payload):                    # single-flight per (me, peer)
    re-resolve peer DID + keys             # D7
    reset local half to None if stale      # D2
    invite = build_invite(reply_path)
    send_routed(invite WITH payload)       # §3.6: one round trip, not two
    backoff + cap; on exhaustion → surface error, stop
```

The §3.6 bundling matters: a sender may pack application data *alongside* the
invite, and `admits_application_message()` already returns true for
`InviteReceived`. So recovery re-sends the original payload bundled with the
fresh invite — the peer records the inbound half and accepts the payload in the
same frame. Recovery costs one round trip, not an invite/accept/resend three.

### D4 — Single-flight, backoff, cap (herd control) — **core prototyped**

Because a mediator or VTA restart makes *every* peer time out at once, and
because a timeout is ambiguous (C2):

- **Single-flight** per `(me, peer)`: one recovery attempt in flight; concurrent
  sends coalesce onto it.
- **Jittered exponential backoff** between attempts; a **retry cap**, after
  which the send fails up to the caller / outbox rather than looping. A VTA that
  is genuinely down must not be invite-flooded, and a real outage must not be
  masked as "recovering."
- Recovery is idempotent (D2), so a duplicate attempt that races is harmless.

**Prototype (in `affinidi-messaging-sdk`, branch `feat/inbound-kind`):** the
policy is pure and clock-injected, matching the rest of the module's tested
cores:

- `BackoffPolicy { base, max, max_attempts }` with `capped_delay(attempt)` —
  `base·2^attempt` saturating, capped at `max`, `None` at the cap on attempts —
  and `full_jitter(delay, frac)` (AWS full jitter over `[0, delay)`, `frac`
  clamped). Tested for exponential growth, the cap, overflow-saturation
  (`2^500` doesn't panic) and jitter bounds.
- `RecoveryState` + `RecoveryAction` (`Start` / `InFlight` / `Backoff(d)` /
  `GiveUp`): the single-flight state machine. `begin(now_ms, policy)` returns one
  `Start` and coalesces every concurrent caller to `InFlight`; `fail` holds the
  peer off for the backoff; `succeed` clears it; `GiveUp` past the cap. Tested
  for single-flight, backoff timing, give-up, and success-reset.
- `TspOps::reset_relationship(profile, their)` — the "stale local half" reset:
  set state `None` + clear digests so a subsequent `send_reestablishing` sees
  `Reestablish` and re-invites. **This is where D4 leans on D2**: a timeout is
  ambiguous, so the reset may be unnecessary, but if the peer *did* keep the
  relationship the fresh invite lands on its live half and D2's reconcile
  transition has it re-accept rather than error — so acting on a false-positive
  timeout self-heals. Without D2, D4 could not safely reset on an ambiguous
  signal at all.

Full SDK suite green (193); clippy clean. Scope is the **decision core** — what
to do and when. The runtime that fires it (a round-trip timeout on a correlated
send feeds `begin`; a background task holds the per-peer `RecoveryState` behind a
lock and runs `reset_relationship` → `send_reestablishing` on `Start`) is the
outbox integration below (D6), kept out of the unit-tested surface exactly as
the D3 network orchestration was.

**Wired in `vta-sdk` (client-side self-repair) — done.** `VtaClient::dispatch_trust_task`
is the first consumer of `reset_relationship` in this workspace. On a TSP
reply-timeout (`VtaError::is_tsp_reply_timeout`) it re-forms the relationship —
reset the local half to `None`, then re-invite through the existing `relate`,
leaning on D2's reconcile for the false-positive case — and, for a Trust Task
classified blind-retry-safe in `vta_sdk::retry_safety`, resends once. A
`Keyed`/`KeyedSecret`/unknown task is healed but its resend is left to
`VtaClient::idempotent`, the one retry owner that holds a stable key, so this
never double-executes a mutation and never stacks a second retry loop on the
idempotency one. This is the **synchronous, per-call** form — a single inline
retry across all three TSP leg shapes (pure, multiplexed, separate) via
`force_relate` / `force_relate_tsp` — so it does not yet use the single-flight /
backoff `RecoveryState` above; that stays for the outbox integration (D6).
Regression test: `tests/e2e/tests/tsp_self_repair_on_drop.rs` — a client whose
VTA has forgotten its half recovers a `RetrySafe` grant in one call (non-vacuous:
neutering the self-repair reproduces the bare timeout).

### D5 — Idle eviction (the 7-day cache) — **core prototyped**

Add `last_active` to the durable pair record, updated on **successful
round-trip** (not on send-attempt — a broken relationship must age out, not
refresh itself on every failed retry). A sweep evicts pairs idle > 7 days
(configurable). Eviction is purely local and needs no coordination: if we evict
but the peer kept the relationship, the next send takes the `None` branch,
re-invites, and D2 lets the peer accept the re-invite it didn't strictly need.

**Prototype (in `affinidi-messaging-sdk`, branch `feat/inbound-kind`):**

- `EvictionPolicy { ttl }`, defaulting to **7 days** — the interval from the
  original proposal — with `is_idle(last_active_ms, now_ms)`, a saturating age
  comparison (a backwards clock reads as not-idle, never underflows to a huge
  age). Pure and tested across the boundary.
- `PersistentRelationshipStore::{touch, last_active}` — a fifth facet key, so the
  durable store records activity while the ephemeral one carries nothing to evict
  (the C3 decision: `last_active` lives on the durable store, not the
  `RelationshipStore` trait). Tested that it round-trips and **survives a
  restart** — the idle clock must not reset on a bounce, or nothing ages out.

Full SDK suite green (195); clippy clean. Remaining wiring: stamp `touch` on a
successful round-trip, and a sweep that scans idle pairs and evicts them — the
scan needs a `RelationshipKv` iterate method, so it lands with the outbox/runtime
work (D6).
Correctness holds; the only cost is one extra handshake. Expose the TTL as
config; 7 days is the default, not a constant.

### D6 — Single-flight coordinator + eviction sweep — **cores prototyped**

The D1 delivery layer (`affinidi-messaging-delivery`) already has
outbox-drain and escalate-on-expiry. A gated/timed-out send should **feed the
outbox and let it retry** once the relationship is up, rather than spawning a
second, competing retry loop. `ensure_relationship` raises the relationship;
the outbox owns redelivery and the expiry escalation. One retry system, not
two.

**Prototype (in `affinidi-messaging-sdk`):** the two pieces that are pure/testable:

- `RecoveryCoordinator` — async single-flight over `RecoveryState` + a
  `BackoffPolicy`, clock-injected: `begin` gives one caller `Start` and coalesces
  the rest to `InFlight`; `settle_success`/`settle_failure` advance the backoff;
  `metrics()` exposes D8's counters. This is the object the timeout runtime calls.
- The eviction sweep: `RelationshipKv::scan_prefix` (default no-op),
  `PersistentRelationshipStore::evict_idle` (sweep idle pairs, `forget` the whole
  record) and `established_relationships` (D9's candidates).

**Service wiring (pending), and where it lives:** the timeout→recovery loop
belongs where correlated sends *originate* — the **client** (`vta-sdk` /
`pnm-cli`), which is exactly where the original bug appeared (a `pnm health` TSP
ping timing out). A responder VTA rarely initiates a correlated TSP round-trip,
so its recovery is mostly D1 (durable store, done) + D2 (auto re-accept on a
re-invite, done). The VTA's own D6 wiring is the **eviction sweep** — and it must
be spawned **once at server startup, not inside `build_messaging`**, which
re-runs on every mediator reconnect: a sweep task holds the store `Arc` and does
not depend on the socket, so spawning it per-reconnect would leak one sweep per
reconnect (the same task-lifecycle trap the mediator-connection note warns
about). It needs a **concrete** `Arc<PersistentRelationshipStore<..>>` handle
kept beside the `Arc<dyn RelationshipStore>` handed to the ATM (the sweep/
enumerate methods are on the concrete type, not the trait).

### D6a — A refused invite is not a failed recovery

The re-establishing send is three steps — read the send readiness, invite if it
says `Reestablish`, send the payload behind it (§3.6) — and the first two are
**separate awaits on the relationship store**. The peer can move our half in
between: its own invite arrives, `None` + `ReceiveInvite` leaves us
`InviteReceived`, and `SendInvite` is legal only from `None`. The invite is then
refused with

```text
invalid transition: SendInvite in state InviteReceived
```

and the SDK's combined `send_reestablishing` returns that error **with the
payload unsent**.

Treating that as a failure is wrong twice over. It is the outcome the invite
existed to produce, reached from the other side — a relationship is on record,
and `admits_application_message()` is true for every state but `None`, so the
payload could have gone. And it is worst exactly where it matters most: two
endpoints repairing the same broken relationship at once is what a mediator
restart or a VTA redeploy produces, so the collision is common precisely when
recovery is.

**The fix lives in the SDK, from `affinidi-messaging-sdk` 0.26.12**
(affinidi-tdk-rs #838). `TspOps::send_reestablishing` answers a refused invite by
**re-reading the store** — not by matching on the error's text, which is not a
contract. Our half no longer `None` means carry on to the payload; still `None`
means the invite failed for its own reasons and that error stands. The decision
is the pure `invite_refusal_is_benign(SendReadiness) -> bool`, exported beside
`readiness_for` and unit-tested with it: the race lives between two awaits, so
no test can place the peer's invite, and the decision is what can be pinned.

`vta-service` carried a local copy of that sequence for one release (#1582) and
now delegates again (#1586). Two consequences worth keeping in view:

- **The floor is `0.26.12`, not `0.26`.** Every `affinidi-messaging-sdk`
  requirement in this workspace names the patch. On `^0.26` a lockfile resolving
  0.26.11 would put the race back with nothing local left to catch it — the
  failure mode that makes a version floor load-bearing rather than tidy.
- **`vtc-service` is covered by the same bump.** Its registry client
  (`registry::messaging::send_tsp`) calls the SDK's form directly. Before 0.26.12
  the collision surfaced there as a transient `Unreachable` that the syncer's
  backoff — the one retry owner on that path — re-sent through, so it self-healed
  on the next attempt; that is why it was left alone rather than given a second
  copy of the workaround. A one-shot recovery has no such owner, which is why the
  VTA's arm could not wait.

One thing this exposed on the VTA side, fixed with it: `recover_send_tsp`
collapsed `Timeout`, `Cancelled` and `SendFailed(reason)` into one message,
"`<peer>` did not answer over TSP after re-establishing the relationship" — so a
frame that never left this VTA was reported as a silent peer, and every reader
was sent to the wrong endpoint. The steady-state `send_tsp` beside it already
told the three apart; the recovery arm now does too. That is what made the
upstream defect readable, and it stays whatever the SDK does.

### D7 — Security invariants for re-establishment

Recovery is the moment an attacker would try a key-swap or downgrade, so:

- **Re-resolve the peer's DID document and keys on every re-establish.** Never
  re-invite against cached keys — re-resolution is also what legitimately fixes
  the case where the peer rotated keys (often *why* the relationship broke).
- **Recovery re-runs admission / ACL.** A peer that lost authorization must not
  silently re-form a relationship. The throwaway-VID probe already shows the VTA
  403s unknown VIDs; recovery respects that, it does not bypass it.
- **Rate-limit inbound invites**, not just outbound — an invite flood is a DoS
  and D2 makes invites cheap to accept. **Prototyped:** `InviteRateLimiter`
  (SDK) — one accepted invite per interval per peer; the receiver's invite
  handler consults `allow` before acting on a fresh invite. Re-resolve-keys and
  ACL-re-run remain to wire into the SDK recovery path and the VTA admission.
- **Do not add a "relationship required" signal back to the sender.** It would
  defeat §7.2.2's silent-drop security property. Detection stays sender-local
  (C2).

### D8 — Observability — **recovery metrics prototyped**

The failure that started this note was invisible except in one log line. Add:

- A **§7.2.2 drop counter** on the receiving side, labelled by peer. A spike
  *is* "a peer lost its state" — this is the alarm. **Service-side** — the drop
  happens at the VTA's inbound TSP handler / transport adapter, so the counter is
  wired there to the telemetry sink; no SDK change needed.
- Recovery metrics: attempts, successes, exhaustions. **Prototyped** as
  `RecoveryMetrics { attempts, successes, give_ups }` on `RecoveryCoordinator`;
  a service reads `metrics()` on an interval into its sink. A **give-up spike**
  is the "peer durably unreachable" alarm; an **attempt storm** (many peers at
  once) means a service lost its store, e.g. a durable store misconfigured back
  to in-memory.

### D9 — Proactive reconcile on startup — **enumerate prototyped**

With a durable store (D1), a service can on startup **re-assert** its stored
relationships — a lightweight keepalive/refresh — instead of waiting for the
first real message to fail. Turns a user-visible timeout into a background
reconcile. Cheap given D2/D3 already exist; gate it behind the same herd
controls (D4) so a fleet-wide restart doesn't self-DoS.

**Prototyped:** `PersistentRelationshipStore::established_relationships` returns
the `Bidirectional` pairs to re-assert (a half-open handshake is excluded — it is
already in flight). The re-assertion itself is a keepalive round-trip per pair,
so it is the client-side timeout-loop work (D6) applied proactively at boot
rather than reactively on first failure.

## Where the changes land

| Change | Crate / file | Kind |
| --- | --- | --- |
| D2 re-establish transition | `affinidi-tdk-rs` · `affinidi-tsp/src/relationship.rs` | protocol; needs TDK release |
| D3 `ensure_relationship` + §3.6 bundling | `affinidi-tdk-rs` · `affinidi-messaging-sdk` (near `transport_adapter.rs` / `protocols/tsp.rs`) | SDK; inherited by all services |
| D4 single-flight / backoff | same as D3 | SDK |
| D1 durable store impl | per service — VTA (`vta-service`/`vta-sdk`), webvh host, VTC | wiring + a store impl each |
| D5 `last_active` + eviction | `RelationshipStore` trait (add activity) + durable impls | trait touch (C3) |
| D6 outbox integration | `affinidi-messaging-delivery` + service send paths | wiring |
| D7 re-resolve / ACL / rate-limit | SDK recovery path + each service's admission | SDK + service |
| D8 metrics | receiving adapter + service telemetry | additive |
| D9 startup reconcile | each service's boot | additive |

## Sequencing

1. **D1 durable store** first — biggest win, no protocol change, testable today
   by killing and restarting one endpoint and watching a ping survive.
2. **D2 transition** next — unblocks every reconcile; ships in a TDK bump. Prove
   it with a two-store reconcile test before any service wiring (kill one half,
   re-invite, assert `Bidirectional` on both).
3. **D3 + D4** — the send-path primitive and herd control, in the SDK.
4. **D6** — fold into the outbox so there's one retry system.
5. **D5 / D7 / D8 / D9** — eviction, security hardening, metrics, proactive
   reconcile.

## Open decisions

- **Durable store backend per service** — reuse each service's existing state
  store, or a shared crate implementing `RelationshipStore` once? A shared crate
  avoids five subtly-different persistence bugs but couples the services to one
  storage choice.
- **`last_active` in the trait vs. out of band** (C3). Adding it to the trait is
  cleaner but touches every impl including the in-memory default; recording it
  beside the state in the durable impl only is less invasive.
- **Startup reconcile (D9) default on or off?** On is safer for correctness, but
  a synchronized fleet restart needs D4's jitter to not become a self-inflicted
  invite storm.
- **Where the round-trip timeout that triggers recovery is set** — per send, per
  session, or adaptive from observed latency. Too low and healthy-but-slow peers
  trigger needless re-invites; too high and recovery is sluggish.

## Testing

- **Two-store reconcile** (unit, `affinidi-tsp`): kill one half, re-invite,
  assert both reach `Bidirectional`; assert `Bidirectional + ReceiveInvite`
  no longer errors (D2).
- **Restart survival** (integration): durable store, restart the receiver
  mid-conversation, assert the next application message is *not* dropped (D1).
- **Cold recovery** (integration): receiver with an empty store, sender with
  `Bidirectional`; assert one gated drop, then automatic re-establish via §3.6
  bundling, then delivery — no operator action (D3).
- **Herd** (load): restart a VTA with N connected peers; assert bounded invite
  rate, single-flight per peer, and no unbounded retries on dead peers (D4).
- **Eviction** (unit): a pair idle > TTL is evicted; a failed retry does **not**
  refresh `last_active` (D5).
- **Downgrade** (security): a re-establish against rotated/attacker keys
  re-resolves and rejects the stale key (D7).
