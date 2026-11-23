# Health probes: `/livez`, `/readyz` and `/health`

The VTA and the VTC each serve three unauthenticated probe routes at the root
of their REST listener. They are outside authentication, rate limiting, the
request trace, and the VTC's host and surface gating, so they answer the same
on every host the service is reached on.

| Route | Answers | Fails when | Use it for |
|---|---|---|---|
| `GET /livez` | `200 {"status":"ok"}` | never, while the process serves HTTP | Kubernetes `livenessProbe` |
| `GET /readyz` | `200 {"status":"ready","storage":"ok"}` | `503 {"status":"notReady","storage":"unavailable"}` while the store is unavailable | Kubernetes `readinessProbe`, load-balancer target health |
| `GET /health` | `200 {"status":"ok"}` (the VTC adds `version` and `vtc_did`) | never | existing monitors; unchanged |

## What each one checks

**`/livez` checks nothing but the HTTP server.** Storage trouble, an
unreachable mediator or an unpublished DID never fail it. A restart would cure
none of them and would throw away the state that might, so a liveness probe
that failed on them would turn a dependency problem into a restart loop.

**`/readyz` checks the store**, because every request needs it:

- **Local store (fjall)**: the data directory still holds the database (an
  open database goes on answering from memory after its volume is detached or
  its directory deleted), and the database still accepts a journal flush to
  OS buffers, which fails once fjall has stopped writing after an I/O error.
  Neither check writes data or fsyncs.
- **Enclave (vsock) store**: one read round trip through the parent's storage
  proxy.

A check that takes longer than 800 ms counts as a failure, so a stalled disk
or proxy gets the instance drained instead of holding the probe open. One
result answers for one second: however many callers probe, the store is
checked at most once a second. The cause of a failure is logged (`readiness:
store check failed`) and never put in the body.

**`/readyz` does not check the mediator.** DIDComm and TSP have their own
reconnect supervisor ([Mediator connection](../02-vta/mediator-connection.md)),
and REST callers are served without them, so draining the instance would turn
a degraded transport into an outage.

## Kubernetes

```yaml
livenessProbe:
  httpGet: { path: /livez, port: 8100 }
  periodSeconds: 10
  failureThreshold: 3
readinessProbe:
  httpGet: { path: /readyz, port: 8100 }
  periodSeconds: 5
  failureThreshold: 2
```

Use the service's own listen port (the VTC defaults to `8200`). A VTA built
without REST serves no probes; use an exec probe or the mediator-side signals
instead.
