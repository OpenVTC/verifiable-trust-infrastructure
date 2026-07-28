# One ATM per process, not per identity

**Status:** implemented (vta-sdk 0.20.11). Closes #830.
**Related:** `multi-tenant-signing.md` (R1b, R4), `tsp-enablement.md` §3.3a
(one socket per DID).

## The problem

Every session constructor in `vta-sdk` built its own `TDKSharedState` **and**
its own `ATM`, then attached exactly one identity to it —
`DIDCommSession::connect_with_secrets`, `TrustPingSession::new`,
`TspPingSession::new`, `TspSession::connect`, and the free function
`send_trust_ping`. A process authenticating as N DIDs therefore held N ATMs, N
secrets resolvers, N deletion handlers, and N sets of background tasks.

The transport never required that shape. `ATM` already models many identities:
`Profiles` is a map keyed by alias with `find_by_did`, and
`profile_add(profile, live_stream)` attaches each one with **its own** websocket.
The mediator's real ceiling is *one websocket per DID*, which N profiles on one
ATM satisfies exactly as well as N ATMs do — each DID still gets one socket.
What N ATMs bought was duplicated per-process machinery.

## What was actually broken

Chasing this surfaced a live defect. **No session in the SDK ever called
`atm.profile_add`** — each built an `ATMProfile` and went straight to
`profile_enable_websocket`. But `ATM::graceful_shutdown` stops websockets by
iterating the ATM's profile map, and that map was empty. So `shutdown()` stopped
the deletion handler and **left the socket running**.

Nothing else could stop it either. The websocket task transitively owns the only
`Sender` for its own command channel (task → `Arc<ATMProfile>` → `Mediator
.ws_channel_tx`), so the channel never closes on its own; upstream's
`cleanup_failed_websocket` documents that exact Arc cycle. `stop_websocket` had
zero callers anywhere in this workspace.

Net: every "cleanly shut down" client session left an orphaned,
auto-reconnecting socket holding the mediator's one-socket-per-DID slot for the
life of the process. That is demonstrated, not inferred —
`tests/e2e/tests/session_hub.rs::shutdown_stops_the_mediator_websocket` fails
when the pre-#830 shape is restored.

## The shape

`vta_sdk::session_hub::SessionHub` holds one TDK + one ATM. Identities attach to
it; each gets a registered `ATMProfile` and its own socket.

```rust
let hub = SessionHub::new().await?;
let finance = VtaClient::connect_didcomm_on(&hub, fin_did, key, vta, med, rest).await?;
let legal   = VtaClient::connect_didcomm_on(&hub, leg_did, key, vta, med, rest).await?;
// ...
finance.shutdown().await;   // detaches this identity only
legal.shutdown().await;
hub.shutdown().await;       // tears the shared ATM down
```

| Shared across identities | Per identity |
|---|---|
| `TDKSharedState` (DID resolver cache, secrets resolver) | `ATMProfile` |
| `ATM` + its deletion handler | mediator websocket |
| `ATMConfig` | delivery-layer `MessagingService` + subscribers |

Every legacy constructor still works unchanged — it now builds a **private**
hub for its one identity. `*_on` variants take a caller-owned hub:
`DIDCommSession::{connect_on, connect_with_secrets_on}`,
`TspSession::connect_on`, `TrustPingSession::new_on`, `TspPingSession::new_on`,
`VtaClient::{connect_didcomm_on, connect_didcomm_bundle_on, connect_tsp_on}`.

### Ownership is explicit

`HubOwnership::{Exclusive, Shared}` decides what `shutdown()` does:

- **Exclusive** (legacy constructors): detach the identity, then shut the hub
  down. Nothing else is on it.
- **Shared** (`*_on`): detach the identity and leave the hub running. A
  sibling's socket must survive — sharing an ATM must not mean sharing a
  failure domain, and the e2e suite pins that.

### Detach is the teardown

`SessionHub::detach` is `profile_remove` (which sends the transport its `Stop`)
plus eviction of that identity's secrets from the shared resolver. Both halves
matter: the first is what actually ends the socket, the second is what stops a
torn-down tenant's keys from staying reachable to whatever else runs on the hub.
It is idempotent, so `shutdown()` remains safe on any session clone.

### One DID, one attachment

Attaching a DID that already has a session on the hub is **refused**
(`HubError::AlreadyAttached`). The mediator would evict the older socket as
`duplicate-channel` and the two reconnect loops would duel, so failing the
second connect is strictly better than letting both exist. The claim is taken in
one locked step and released on detach (and on a failed attach), so a
reconnecting identity is never locked out. The lock is *not* held across the
mediator resolution — that would serialise every unrelated identity's attach
behind one DID-document fetch (R1.3).

## The TSP question

#830 asked whether the TSP legs want the same treatment. They already have it,
in the sense that matters: `TspLeg::Multiplexed` exists so a DID that holds a
DIDComm session never opens a second socket for TSP (#803), and that is
unchanged here — the leg rides the same profile the hub attached. `TspSession`
and `TspPingSession` are hub-hosted like everything else, so a process that is
TSP-only across N identities pays one ATM rather than N.

The standing rule is unchanged and is a *mediator* rule, not an ATM one: **a DID
that already holds a `DIDCommSession` must use that session's TSP leg**
(`request_tsp`), not a `TspSession` beside it. Same hub or not, the mediator is
what permits only one socket per DID.

## What this does not change

The architectural rule is still **one principal per process**
(`multi-tenant-signing.md` R4). A hub makes holding N identities *cheap*; it
does not make it *safe*. It exists for the front door that legitimately
terminates requests for N tenants and has not yet split into a process per
tenant (R1b) — the cost of that intermediate step should not be N of everything.

A REST-only consumer should still prefer `auth_light::challenge_response_light`,
which needs no ATM at all. (`session::challenge_response` built an ATM purely to
pack one message and never shut it down — one leaked deletion-handler task per
login and per re-authentication. That is fixed here too, but the light path
remains the right one.)
