# Mediator connection: readiness gate and reconnect

How a VTA establishes and keeps its outbound DIDComm connection to its mediator,
and the `[mediator_readiness]` settings that tune it.

Audience: operators deploying a VTA behind a load balancer, in Kubernetes, or
anywhere the VTA's DID document becomes resolvable *after* the process starts.

## The problem this solves

The mediator authenticates a VTA by **resolving the VTA's DID itself** — it
fetches the DID document to get the key that decrypts the authcrypt handshake.
That creates a cold-start ordering hazard:

1. The VTA boots and publishes its `did:webvh`.
2. The VTA immediately opens the mediator websocket.
3. The mediator tries to resolve the VTA's DID — but the document isn't served
   yet (the DID host hasn't published it, or the LB target fronting it isn't
   healthy).
4. The resolution fails, the mediator rejects the handshake with a 403, and —
   worse — the mediator's resolver **negative-caches** the failure, so the next
   several attempts fail even after the document goes live.

Before the readiness gate, the VTA burned a short retry burst against that and
then gave up until an operator restarted it.

## What the VTA does now

A single background supervisor owns the whole mediator lifecycle. Nothing below
runs on the startup path, so `/health` is live throughout and a `SIGTERM` is
honoured immediately — including mid-gate.

### 1. Self-readiness gate

Before the first connect, the VTA waits until **its own DID fully resolves over
the network**, through the configured resolver (`resolver_url` when set, local
resolution otherwise). A pass means the mediator can do the same lookup and
authenticate us.

Resolution — not an HTTP probe of the `did.jsonl` URL — is deliberately the whole
check:

- A bare `200` on `did.jsonl` doesn't imply resolvability; a `200` serving a
  partial or malformed log still fails resolution.
- A direct HTTP probe would test *the VTA's own egress to the DID host*, which is
  the wrong path when egress is restricted to a resolver sidecar — there the VTA
  cannot reach the DID host directly at all, so the probe could never succeed.

Only network-resolved methods are gated (`did:webvh`, `did:web`). A `did:key` VTA
resolves from its own identifier with no network fetch, so it skips the wait
entirely. An unrecognised method is also not gated — DIDComm is not withheld on
the strength of a probe we can't reason about.

The gate retries with capped exponential backoff and full jitter up to
`max_wait_secs`, then applies `on_timeout`.

### 2. Connect, with retry

The connect itself retries on the same backoff scheme. The classic failure here
is the mediator's *own* negative cache from step 4 above: it clears on its own
timer, so retrying means the VTA **self-heals with no restart**.

Every attempt re-confirms self-resolution first, so a VTA that can't resolve
itself never storms the mediator with unauthenticatable handshakes.

### 3. Session supervision

Once connected, the supervisor watches the session. If the inbound loop ends, it
tears the session down — unpublishing the outbound wiring, then stopping the
websocket — and reconnects. Without this the VTA would go silently deaf for the
rest of the process while still looking healthy.

The teardown is not optional: the mediator permits **one socket per DID**, so
reconnecting while the old socket is still auto-reconnecting would have the two
duel over the slot (each evicting the other as `duplicate-channel`).

A session must stay up for at least 60s to count as healthy and reset the
backoff. A connect that succeeds and instantly drops is treated as a failed
attempt, so a flapping mediator escalates the backoff instead of being retried at
full rate.

## Configuration

All optional, under `[mediator_readiness]` in the VTA's `config.toml`. The
defaults are intended to be correct for a normal LB/Kubernetes deployment —
most operators need none of this.

```toml
[mediator_readiness]
enabled                     = true   # run the gate at all
retry_secs                  = 5      # base backoff interval
backoff_cap_secs            = 30     # cap on the gate's backoff
max_wait_secs               = 300    # how long the gate waits
on_timeout                  = "skip" # skip | proceed | fail
reconnect                   = true   # retry the connect, and reconnect dropped sessions
reconnect_backoff_cap_secs  = 60     # cap on the reconnect backoff
reconnect_max_elapsed_secs  = 0      # 0 = retry forever
```

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Run the self-readiness gate. `false` connects immediately — only sensible where the DID is known-published before boot. |
| `retry_secs` | `5` | Base interval. Attempt `n` sleeps a uniform random duration in `[0, min(cap, retry_secs * 2^n)]` (full jitter), so a fleet coming up together doesn't probe in lock-step. |
| `backoff_cap_secs` | `30` | Upper bound on the gate's per-attempt interval. |
| `max_wait_secs` | `300` | How long the gate waits before applying `on_timeout`. Cancellable — a shutdown signal abandons the wait immediately. |
| `on_timeout` | `"skip"` | See below. |
| `reconnect` | `true` | Retry a failed connect, and reconnect a dropped session. `false` restores the legacy single-shot behaviour. |
| `reconnect_backoff_cap_secs` | `60` | Upper bound on the reconnect interval. Larger than `backoff_cap_secs` because it must outlast a resolver negative-cache TTL. |
| `reconnect_max_elapsed_secs` | `0` | Give up after this many seconds of *continuous* failure; `0` never gives up. Measured from the start of the current failure run and reset by any healthy session — a VTA that ran for a week then dropped gets the full budget. |

### `on_timeout` policies

| Value | Behaviour |
|---|---|
| `"skip"` (default) | Don't start DIDComm this boot. REST stays fully live, so the LB target turns healthy and the DID can finish publishing; a later restart reconnects. |
| `"proceed"` | Connect anyway, best-effort, accepting that the handshake may be rejected. The reconnect loop still applies. |
| `"fail"` | Treat it as fatal and shut the process down. Use where an orchestrator should recreate the pod rather than run it without DIDComm. |

## Operating notes

- **`/health` is never gated.** The REST listener starts before the supervisor,
  so a VTA waiting on its DID is healthy from the LB's point of view — which is
  what lets the DID become resolvable in the first place.
- **A gate timeout under `skip` is not an error state.** The VTA runs
  REST-only. If that is unacceptable for your deployment, use `fail`.
- **`did:key` VTAs are unaffected** by every setting here.
- **What to check when the gate times out.** The log names the DID and, for
  `did:webvh`, where its document is expected to be published. Fetch that URL and
  confirm it returns a complete log; if the VTA uses a resolver sidecar, check the
  sidecar can reach the DID host.

## Code

- `vta-service/src/messaging/readiness.rs` — the gate, the resolution probe, and
  the shared backoff/jitter helpers.
- `vta-service/src/server.rs` — `MessagingConnect`, the supervisor.
- `vta-service/src/messaging/service.rs` — `build_messaging` /
  `connect_transport`, including the socket teardown every error path takes.
- `vta-config/src/lib.rs` — `MediatorReadinessConfig`, `ReadinessTimeoutPolicy`.
