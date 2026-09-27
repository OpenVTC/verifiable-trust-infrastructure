# Runtime Service Management

Operator guide for the unified `pnm services …` command surface
that manages the VTA's advertised transport services (REST and
DIDComm) at runtime, without rebuilding the VTA, re-issuing admin
credentials, or rotating verification keys. Every service change
publishes a new WebVH LogEntry; external resolvers see each
change as an authentic, signed update.

Spec: `docs/05-design-notes/runtime-service-management.md`.

This page replaces the older `didcomm-protocol-management.md`
guide. The DIDComm-specific surface is now part of a unified
`services {kind} {verb}` tree alongside REST.

## Migration from the legacy `pnm mediator …` surface

If you have scripts targeting the pre-P5 commands, here's the
direct mapping. Old commands have been **retired** (no aliases).
Calling `pnm mediator …` prints a friendly redirect with the
equivalent `pnm services didcomm …` command and exits 2 — the
clap-default "unknown subcommand" message is intercepted in
`pnm-cli/src/main.rs` so operators with stale scripts get a
copy-pasteable suggestion instead of a generic parse error.

| Old | New |
|---|---|
| `pnm services enable didcomm --mediator-did X` | `pnm services didcomm enable --mediator-did X` |
| `pnm services disable didcomm --drain-ttl 3600` | `pnm services didcomm disable --drain-ttl 86400` |
| `pnm mediator migrate --to X --drain-ttl 3600` | `pnm services didcomm update --mediator-did X --drain-ttl 86400` |
| `pnm mediator rollback --to X` | `pnm services didcomm rollback` |
| `pnm mediator drain cancel --mediator-did X` | `pnm services didcomm drain cancel --mediator-did X` |
| `pnm mediator report` | `pnm services report` |
| (no equivalent) | `pnm services list` |
| (no equivalent) | `pnm services didcomm drain list` |
| (no equivalent) | `pnm services rest {enable,update,disable,rollback}` |
| (no equivalent) | `pnm services tsp {enable,update,disable,rollback}` |

**Default `--drain-ttl` is now 24h** (was 1h). The 1h floor for
DIDComm-transport delivery is unchanged.

**Rollback semantics changed.** The old `pnm mediator rollback
--to <did>` took an explicit target DID. The new `pnm services
didcomm rollback` is **snapshot-driven** — it reads the per-kind
snapshot store and fail-forwards into whichever forward operation
re-applies the prior config. No `--to` argument; the rollback
target is whatever was in effect before the most recent forward
mutation.

The `--to` muscle memory is partially preserved on `update`:
`pnm services didcomm update --to <did>` works (clap
`visible_alias` on `--mediator-did`).

## Operations at a glance

All commands require **super-admin** privileges on the target VTA.
The operations are reachable over both REST and DIDComm transports,
except `services didcomm enable` which is REST-only by nature (DIDComm
isn't running yet at first-enable). `services tsp enable` — unlike
`services didcomm enable` — is reachable over **either** transport, since
enabling TSP doesn't depend on TSP already running.

### Inspect

| Task | Command |
|---|---|
| Show currently-advertised services | `pnm services list` |
| Show in-flight drain entries | `pnm services didcomm drain list` |
| Per-mediator traffic + sender attribution | `pnm services report [--since <rfc3339>] [--until <rfc3339>] [--format json|table]` |

#### DIDComm status (`vta/services/get`, `service: didcomm`)

`pnm services list` reports the advertised service array from the VTA's
DID document. For DID methods with no resolvable service block (e.g.
`did:key`), the mediator can't be discovered that way, so `pnm health` asks
`vta/services/get` for `didcomm`, which answers `{ enabled, mediatorDid }`
from runtime config. Like every operation here it is **super-admin** gated.
The live websocket state is not part of the published state; read it from
`GET /health/details`.

`pnm services report` queries the same telemetry sink and renders
per-mediator inbound counts plus per-sender last-seen attribution.

## Wire-form details

These are the on-the-wire shapes the SDK exposes. Most operators
won't need them; the `pnm` CLI is the canonical interface.

**Trust Tasks** (super-admin; over TSP, DIDComm, or HTTPS on `/trust-tasks`):
- `vta/services/list/1.0`, `vta/services/get/1.0` — what is advertised
- `vta/services/{enable,disable,rollback}/1.0` and `vta/services/update/1.1`
  — `{ service, config }`, one task per verb across `rest`, `didcomm`, `tsp`
  and `webauthn`; `update/1.1` adds `drainTtlSecs` for the mediated
  transports
- `vta/services/drain/{list,cancel}/1.0` — the drain set
- `vta/services/report/0.1` — per-mediator traffic and sender attribution

The `/services/*` and `/mediators/*` REST routes, and the
`services-management/1.0` / `mediator-management/1.0` DIDComm messages, are
removed: every client, the `pnm` CLI included, dispatches the tasks.

## Recovery: the mediator is unreachable

DIDComm is the preferred transport, so `pnm` picks it whenever the
VTA's DID document advertises it. If that mediator then goes away —
wrong DID at enable time, mediator decommissioned, network partition —
every `pnm` command against that VTA tries to reach it. That includes
the very commands you would use to fix the situation (`services list`,
`services didcomm disable`), so the VTA looks bricked when it is only
unreachable *over DIDComm*. Its REST surface is still up.

Two things break the loop.

**The connect is bounded.** An auto-selected DIDComm connect gives the
mediator 30 seconds and then fails with the recovery command rather than
retrying forever. Raise the ceiling on slow links with
`VTA_DIDCOMM_CONNECT_TIMEOUT_SECS`.

**`--transport rest` forces REST.** A global flag on both `pnm` and
`cnm`. It skips DIDComm even when the DID document advertises it, and
even when the local config pins a `mediator_did`:

```bash
# Confirm what the VTA currently advertises.
pnm --transport rest services list

# Point DIDComm at a mediator that answers …
pnm --transport rest services didcomm update --to did:web:new-mediator.example.com

# … or stop advertising DIDComm altogether.
pnm --transport rest services didcomm disable --drain-ttl 0
```

`--drain-ttl 0` (immediate teardown) is only accepted over REST — which
is exactly the transport you are on. Over DIDComm the server enforces a
1h minimum so the response doesn't die with the listener carrying it.

Notes:

- Forcing REST needs a REST endpoint to force. `pnm` uses `--url` if
  given, else the `#vta-rest` service on the VTA's DID document. If the
  VTA advertises neither, the command errors and asks for `--url` — it
  will not guess a URL from the DID's domain, which for a hosted
  `did:webvh` is the DID host, not the VTA.
- If your config pins a `mediator_did` (`pnm vta add --mediator-did …`),
  that pin is priority 1 of transport selection and never re-reads the
  DID document. A successful `services didcomm enable|update|disable`
  reconciles the pin for you — disable clears it, enable/update repoint
  it — so the next command doesn't dial a mediator that is gone.
- Once DIDComm is disabled, plain `pnm services list` works again; the
  DID document no longer advertises a mediator, so auto-selection lands
  on REST on its own.

## Failure modes

The CLI's error renderer surfaces the typed `VtaError` variant
along with a suggested-fix string per CLAUDE.md "operator errors
should suggest the fix":

| Error | Status | Suggested fix |
|---|---|---|
| `ServiceAlreadyEnabled` | 409 | "Use `services <kind> update …` to change the configuration." |
| `ServiceNotPresent` | 409 | "Run `services <kind> enable …` first." |
| `LastServiceRefused` | 409 | "Enable the other transport first via `services <other> enable …`." |
| `MediatorHandshakeFailed` | 502 | "Confirm the mediator DID is correct and the mediator is reachable." |
| `DrainTtlOutOfBounds` | 400 | "Pick a value within [3600s, 30 days]." |
| `NoPriorMutation` | 409 | "No prior mutation to roll back; use the direct command instead." |

## Offline `vta services …` — operator-host alternative

Every command above has an offline counterpart on the local
`vta` binary. The shape is identical (`vta services list`,
`vta services rest enable --url …`, `vta services didcomm
update --to <did>`, etc.) but the execution model differs:

- **No HTTP**, no operator authentication ceremony.
- **Direct fjall access** — opens the local data directory and
  calls the operation functions in-process.
- **Filesystem access is the security boundary** — same model
  as `vta acl …`, `vta keys …`, `vta contexts …`. Anyone with
  read/write access to the data dir can run these.

### Don't run while the VTA daemon is running

fjall takes an exclusive file lock when the running VTA opens
its data directory. Offline `vta services` will fail to open
the store with a clear error pointing the operator at `pnm
services` against the live VTA. This protects against
split-brain corruption on disk; the cost is that `vta services`
mutations require stopping the daemon first (which most
operators won't want to do — `pnm services` is the canonical
path for live-VTA changes).

### Not for TEE deployments

Inside a Nitro Enclave the VTA's fjall store lives behind a
vsock proxy; the offline `vta` binary on the parent host has no
access to it. Same constraint applies to every other `vta`
offline command (acl, keys, contexts, webvh) — operators
running TEE always use `pnm services …` against the VTA's
HTTPS endpoint.

### When `vta services` is useful

- Cold-start setup before the daemon ever runs (e.g. publishing
  a REST URL for an air-gapped VTA before it boots).
- Recovery / forensics on a stopped VTA.
- Test environments where spinning up the full daemon is
  overkill.

For day-to-day service management against a running VTA, prefer
`pnm services …`.

## Spec references

- §3.2 — at-least-one-service brick-prevention invariant
- §3.3 — DIDComm-preferred ordering in the `service[]` array
- §3.4 — REST-specific operations and the `#vta-rest` shape
- §3.5 — DIDComm-specific operations and the drain machinery
- §3.5a — fail-forward rollback semantics
- §3.6 — 24h default drain TTL
- §5.1 — final CLI surface (this guide is the operator-facing
  rendering of that section)
- §7a — end-to-end test matrix

## See also

- `docs/05-design-notes/runtime-service-management.md` — the
  approved spec
- `docs/05-design-notes/runtime-service-management-plan.md` —
  the dependency-ordered implementation plan
- `docs/05-design-notes/runtime-service-management-tasks.md` —
  the 33-task breakdown
- `docs/02-vta/didcomm-protocol-management.md` —
  redirects here (legacy DIDComm-only guide superseded in P5)
