# Spec: Runtime service-endpoint management

Status: **Implemented**
Owner: Glenn Gore
Last updated: 2026-05-06

## 1. Objective

Allow a super-admin to add, update, or remove service entries on a
**running VTA's DID document** without rebuilding the binary or
re-running setup. Each mutation publishes a new WebVH LogEntry that
re-uses the existing verification methods. The mutation is reachable
from both the VTA local CLI (`vta`) and PNM (`pnm`), over both REST
and DIDComm transports — except where a transport must necessarily be
absent (you cannot enable DIDComm over DIDComm).

This generalizes the DIDComm-specific protocol-management work that
shipped on `sealed-bootstrap` (commits up to 88dab00) into a unified
service-management surface that also handles REST. The DIDComm-only
operator surface (`pnm services enable|disable didcomm`,
`pnm mediator …`) is **retired** and replaced by the new unified shape.

### Why this matters

* Operators today must rebuild and re-deploy a VTA to change its
  published REST URL (e.g., domain migration).
* "DIDComm-only" and "REST-only" deployments are valid topologies but
  the only way to reach them today is editing config files at boot.
* The DIDComm migrate-with-drain machinery is already well-tested;
  exposing it through a generic service-management surface makes the
  REST equivalent (URL update, on/off) a thin extension instead of a
  parallel system.

### Non-goals

* Hot-swapping the Axum listener bind address, port, or TLS cert.
  Those remain process-config and are set at boot. This spec only
  changes what the DID document **advertises**.
* Adding service kinds beyond REST and DIDComm. Operator-defined
  service types are a separate, larger design (extensible kinds need
  schema, validation, telemetry hooks).
* REST drain/replay. REST is request/response; removing a URL from
  the DID document means clients resolve a 410 and retry. There is
  no buffered-message concept on the REST side.
* Multi-service atomic transactions. Each mutation is one LogEntry,
  one transport, one service. See §6.

## 2. Tech Stack & Codebase Context

* Rust workspace, edition 2024, MSRV 1.94.0
* Existing modules to extend (do **not** fork):
  * `vta-service/src/operations/protocol/` — operation handlers
  * `vta-service/src/messaging/{registry,drain_store,drain_sweeper,handshake,live_prover,transient_handshake}.rs` — DIDComm mediator state machinery
  * `vta-service/src/operations/did_webvh/mod.rs` — LogEntry publication
  * `vta-service/src/trust_tasks/services.rs` — transport-neutral service handlers
  * `vta-sdk/src/protocol/` — wire types (`vta_sdk::protocol::*`)
  * `vta-cli-common/src/commands/{services,mediator}.rs` — CLI commands
  * `vti-common/src/telemetry/` — pluggable telemetry sink
* Existing invariants that must continue to hold:
  * `verificationMethod` is byte-identical across LogEntries
  * Each service mutation publishes exactly one LogEntry
  * Drain set is fjall-persisted, restart-resilient, capped at
    30 days (`MAX_DRAIN_TTL`)
  * `MIN_DRAIN_TTL_OVER_DIDCOMM = 3600s` floor when the disable
    command is *itself* delivered over DIDComm (so the operator
    isn't cut off mid-command)

## 3. Functional Requirements

### 3.1 Service kinds and operations

Two transport kinds are managed: `rest` and `didcomm`.

| Kind | enable | update | disable | rollback | drain |
|------|:------:|:------:|:-------:|:--------:|:-----:|
| rest | ✓ | ✓ | ✓ | ✓ | — |
| didcomm | ✓ | ✓ | ✓ | ✓ | ✓ |

REST mutations are immediate (publication-only; no in-flight state).
DIDComm mutations route through the existing handshake / drain /
sweeper machinery unchanged.

**Rollback is fail-forward** for both kinds — see §3.5a.

### 3.2 Brick-prevention invariant

**At least one service kind must be enabled at all times.**

The operation layer rejects any mutation that would leave the DID
document with zero advertised services. Specifically:

* `services rest disable` is rejected with `409 LastServiceRefused`
  if DIDComm is currently disabled.
* `services didcomm disable` is rejected with `409 LastServiceRefused`
  if REST is currently disabled.

There is **no `--force` escape hatch.** If an operator genuinely
wants a totally-unreachable VTA they can rotate it out and replace
it via setup; the CLI will not provide a foot-gun.

### 3.3 DIDComm-preferred ordering

When both services are advertised, the DID document MUST signal
DIDComm as the preferred transport for clients that support it.
Encoding mechanism is finalized in Phase 2 (Plan); candidates:

* DIDComm v2 `priority` key on the DIDComm service entry
  (lower number = higher priority)
* Array ordering convention (DIDComm before REST)

Whichever is chosen, the rendering is centralized in the WebVH
operation layer so REST clients see consistent ordering.

### 3.4 REST-specific behavior

* `services rest enable --url <url>` adds a service entry of
  type `LinkedDomains` (or our REST-specific type — to be confirmed
  in Plan against the existing DID template's REST shape) with
  the supplied URL.
* `services rest update --url <url>` replaces the URL on the
  existing REST service entry. Errors with `409 ServiceNotPresent`
  if REST isn't currently advertised.
* `services rest disable` removes the REST service entry.

The Axum listener itself is **not** torn down — it stays running so
local CLI traffic and management endpoints remain reachable. Only
the *advertisement* changes.

URL validation: must be `https://` (TLS-only), parsable by `url::Url`,
no fragment, no userinfo. Enforced in `vta-sdk` so both transports
share the rule.

### 3.5 DIDComm-specific behavior

`services didcomm enable --mediator-did <did> [--setup-acl]` is carried by the
`vta/services/enable/1.0` Trust Task over any transport already available to the
VTA (normally HTTPS on a REST-only VTA). Internally it calls `enable_didcomm`:

1. Transient `DIDCommService` spun up
2. If `--setup-acl` is set, provision the VTA's allow-all account ACL over the
  transient profile
3. Handshake trust-ping against the candidate mediator
4. On success, mediator pinned, transient teardown
5. LogEntry published with DIDComm service entry

ACL provisioning happens after the candidate websocket authenticates and
before the forwarded self trust-ping. This ordering lets a VTA join a mediator
whose global default is `ExplicitAllow` without a restart or out-of-band ACL
grant. The same profile is reused so no second websocket competes for the
mediator's one-socket-per-DID slot.

`services didcomm update --mediator-did <new-did> [--drain-ttl <dur>]
[--setup-acl]` replaces today's `pnm mediator migrate`:

1. Live `DIDCommServiceProver` connects to the new mediator
2. If `--setup-acl` is set, provision the VTA's account ACL on that candidate
  profile before trust-ping
3. Complete the pre-promotion trust-ping
4. New mediator becomes primary; old mediator moved to the drain set
5. Drain TTL = `--drain-ttl` arg, else **24h default** (see §3.6)
6. LogEntry published with the updated DIDComm service entry

For both operations, a successful explicit request persists
`messaging.setup_acl = true`; later requests that omit the flag do not turn it
off, so startup can repair the mediator ACL after restart. `--setup-acl` and
`--force` are mutually exclusive: force bypasses creation of the live profile
that ACL provisioning requires. Until the shared task schema gains a native
member, the option is carried as `ext["org.openvtc"].setupAcl`.

`services didcomm disable [--drain-ttl <dur>]` replaces today's
`disable_didcomm`. Removes DIDComm service entry; pins drain TTL on
the previously-active mediator. Refused if REST is also disabled
(see §3.2).

`services didcomm rollback` is described in §3.5a (transport-agnostic
fail-forward semantic).

`services didcomm drain list` shows current drain set.
`services didcomm drain cancel <mediator-did>` removes a mediator
from the drain set immediately. Both already exist; only renamed.

### 3.5a Rollback semantic — fail-forward

WebVH is an append-only ledger. We never rewind the chain; we never
mark an entry "reverted." `rollback` is operator-friendly
terminology for **"publish a new LogEntry that re-applies the
previous service configuration for this kind."**

Mechanics:

1. The operation layer looks up the kind's *prior* config — the
   service-entry shape that was in effect immediately before the
   most recent mutation of that kind.
2. It runs the equivalent forward operation:
   * Most recent mutation was `update X→Y` → rollback runs an
     `update Y→X`.
   * Most recent mutation was `disable` (from config X) → rollback
     runs an `enable X`.
   * Most recent mutation was `enable X` → rollback runs `disable`
     (subject to §3.2 brick-prevention).
3. A new LogEntry is published with the resulting service[].
4. For DIDComm, the drain set is updated by the same path the
   forward operation would use — e.g., rolling back an `update
   A→B` puts mediator B into the drain set with the supplied
   `--drain-ttl` (default 24h).

Properties:

* **Single-step only.** Rollback reverts exactly one prior
  mutation per kind. Rolling back twice in a row first undoes the
  most recent mutation, then would undo the *next* most recent
  mutation — which is two distinct user actions, not one.
* **Independent per kind.** REST rollback ignores DIDComm history
  and vice versa. Each kind tracks its own "previous-config"
  pointer.
* **Subject to §3.2.** A rollback that would leave zero advertised
  services is rejected with `LastServiceRefused`, identical to a
  direct `disable`.
* **Subject to TTL bounds.** A DIDComm rollback that would put a
  mediator into the drain set obeys the same `MIN_DRAIN_TTL_OVER_
  DIDCOMM` / `MAX_DRAIN_TTL` bounds as a direct `update`.
* **No special "reverted" telemetry.** The emitted event is the
  forward operation's event (`service.didcomm.updated`,
  `service.rest.enabled`, etc.) with a `triggered_by: "rollback"`
  field, so operators see in telemetry what actually changed.

Implementation note: each successful mutation persists its
"previous-config" snapshot in fjall, replacing the one from before.
Rollback consumes the snapshot. After rollback, the snapshot
reflects the state from *before* the rollback (so a second
consecutive rollback would revert the rollback — a no-op cycle the
operator can avoid by checking `services list` first).

### 3.6 Default drain TTL

* New default: **24 hours** when the operator omits `--drain-ttl`
  on `update` or `disable`.
* Floor: existing `MIN_DRAIN_TTL_OVER_DIDCOMM = 3600s` retained
  (only when the command is delivered over DIDComm).
* Cap: existing `MAX_DRAIN_TTL = 30 days` retained.
* Per the user's input, this default is applied retroactively — no
  feature flag or migration period (no production users yet).

### 3.7 Audit & telemetry

Each successful mutation emits a telemetry event via
`vti_common::telemetry::TelemetrySink`. Event-kind wire form is
the snake-case `TelemetryKind` discriminant (serialized via
`#[serde(rename_all = "snake_case")]`):

* `services_rest_enable` / `services_rest_update` / `services_rest_disable`
* `services_didcomm_enable` / `services_didcomm_update` /
  `services_didcomm_disable`
* Drain events: `mediator_drain_start`, `mediator_drain_cancel`,
  `mediator_drain_expire`

**No separate rollback events.** Per §3.5a, rollback dispatches into
the equivalent forward operation, so the emitted event is the
forward op's event with a `triggered_by: "rollback"` field. An
external verifier filtering on `triggered_by` distinguishes rolled-
back mutations from direct ones without needing a parallel event
namespace.

Each event carries the new LogEntry version-id so an external
verifier can join telemetry to WebVH history.

### 3.8 Authorization

Super-admin only on every operation. No context-admin path.
Implementation reuses the existing JWT role check from
`routes/protocol.rs`; no new claim shapes.

## 4. Wire Types (additions to vta-sdk)

New module: `vta_sdk::protocol::services` (existing
`vta_sdk::protocol` houses DIDComm-specific types; we extend it).

```rust
// Request shapes — exact field names finalized in Plan
pub struct EnableRestRequest { pub url: Url }
pub struct UpdateRestRequest { pub url: Url }
pub struct DisableRestRequest;

pub struct EnableDidcommRequest {
    pub mediator_did: String,
    pub routing_keys: Option<Vec<String>>,
}
pub struct UpdateDidcommRequest {
    pub mediator_did: String,
    pub routing_keys: Option<Vec<String>>,
    pub drain_ttl: Option<Duration>,
}
pub struct DisableDidcommRequest {
    pub drain_ttl: Option<Duration>,
}

// Rollback (per §3.5a, fail-forward — the new LogEntry is just a
// re-application of the prior config, no special chain marker).
pub struct RollbackRestRequest;
pub struct RollbackDidcommRequest {
    // Used only when the rollback target is the previous mediator
    // and that target had a drain TTL set; lets the operator
    // override the 24h default.
    pub drain_ttl: Option<Duration>,
}

// Response (unified)
pub struct ServiceMutationResponse {
    pub log_entry_version_id: String,
    pub effective_at: DateTime<Utc>,
    pub drain_until: Option<DateTime<Utc>>,  // didcomm only
}
```

`VtaError` gains typed variants so the CLI can emit guidance
(per CLAUDE.md "Operator errors should suggest the fix"):

* `LastServiceRefused` — would leave the VTA unreachable
* `ServiceNotPresent` — `update`/`disable` on a kind that's already off
* `ServiceAlreadyEnabled` — `enable` on a kind that's already on
* `MediatorHandshakeFailed { reason }` — DIDComm handshake refused
* `DrainTtlOutOfBounds { min, max, requested }`
* `NoPriorMutation` — `rollback` with no eligible prior mutation
* `UnsupportedTransport` — command delivered over a transport that
  cannot serve it (e.g., `services didcomm enable` over DIDComm)

## 5. CLI Surface

### 5.1 Final shape

```
pnm services list
pnm services rest enable      --url <url>
pnm services rest update      --url <url>
pnm services rest disable
pnm services rest rollback
pnm services didcomm enable   --mediator-did <did> [--routing-keys <k1,k2>]
pnm services didcomm update   --mediator-did <did> [--drain-ttl 24h]
pnm services didcomm disable  [--drain-ttl 24h]
pnm services didcomm rollback [--drain-ttl 24h]
pnm services didcomm drain list
pnm services didcomm drain cancel <mediator-did>
pnm services report
```

The `vta` local CLI mirrors the same shape (`vta services …`).

### 5.2 Removed commands

These are **deleted** (breaking change per user direction):

* `pnm services enable didcomm`
* `pnm services disable didcomm`
* `pnm mediator migrate`
* `pnm mediator rollback`
* `pnm mediator drain cancel`
* `pnm mediator report`

The `mediator` subcommand namespace is removed entirely from `pnm`
and `cnm`. `vta-cli-common/src/commands/mediator.rs` is deleted;
`services.rs` is rewritten.

### 5.3 CLI surface — design rationale

I considered four shapes and picked Option B. Recording the rejected
alternatives so future contributors know why we didn't go that way:

* **Option A — keep separate.** `pnm services enable|disable rest`
  alongside `pnm mediator migrate`. Asymmetric: DIDComm gets a
  privileged top-level namespace, REST doesn't. Rejected.
* **Option B — unify under `pnm services`. ✓ chosen.** One namespace;
  `<kind>` is the dispatch axis. Verbs like `update`, `rollback`,
  `drain` slot under the kind they apply to. Adding a future
  protocol kind is purely additive.
* **Option C — move under `pnm setup`.** `pnm setup services rest …`.
  Rejected: `setup` today is a *cold-start* lifecycle (mints initial
  DID, establishes operator-VTA relationship). Service mutation is
  steady-state. Conflating one-shot bootstrap with everyday
  reconfiguration in muscle memory invites mistakes — operators run
  setup once but may run service mutations many times.
* **Option D — flat verbs with `--kind` flag.** `pnm services add
  --kind rest --url …`. Shallow tree but every command needs the
  flag, and DIDComm-only verbs (`drain`, `rollback`) read awkwardly.
  Rejected.

## 6. Atomicity Model

* **One LogEntry per mutation. One mutation per command.**
* No multi-service atomic ops. Per user direction in clarifying Q6,
  the CLI deliberately does not offer "change REST and DIDComm at
  the same time" — that's how operators brick themselves.
* Sequence: validate → mutate runtime state (e.g., mediator pin,
  drain set) → publish LogEntry → emit telemetry. If LogEntry
  publication fails, runtime state must roll back. Tested in
  `migrate_mediator.rs` today; reuse that pattern for REST.

## 7. Acceptance Criteria

A criterion is met when there's a passing test (unit, integration,
or e2e against the test mediator) demonstrating it. Manual checks
are not sufficient.

### Functional
- [ ] `pnm services list` returns current services with their config
      (URL for REST; mediator DID + drain set for DIDComm).
- [ ] `pnm services rest enable --url https://x.example` adds a REST
      service entry and publishes one LogEntry; `verificationMethod`
      unchanged.
- [ ] `pnm services rest update --url …` replaces the URL on the
      existing entry; one new LogEntry.
- [ ] `pnm services rest disable` removes the REST entry; one new
      LogEntry; rejected with `LastServiceRefused` if DIDComm is off.
- [ ] `pnm services didcomm enable --mediator-did did:…` mints DIDComm
      service entry via existing `enable_didcomm` flow; one LogEntry.
- [ ] `pnm services didcomm update --mediator-did did:new` migrates;
      old mediator joins drain set with default 24h TTL.
- [ ] `pnm services didcomm disable` removes DIDComm entry; previous
      mediator drains for 24h by default; rejected with
      `LastServiceRefused` if REST is off.
- [ ] `pnm services didcomm rollback` fail-forwards the most
      recent DIDComm mutation (update, disable, *or* enable),
      publishing a new LogEntry that re-applies the prior config.
- [ ] `pnm services rest rollback` fail-forwards the most recent
      REST mutation symmetrically (update, disable, *or* enable),
      publishing a new LogEntry.
- [ ] `pnm services didcomm drain list` shows currently-draining
      mediators with TTL countdown.
- [ ] `pnm services didcomm drain cancel <did>` removes mediator
      from drain set.

### Invariant
- [ ] No mutation produces a DID document with zero advertised
      services. Verified by property test over all command sequences.
- [ ] Every mutation publishes exactly one new WebVH LogEntry whose
      `verificationMethod` is byte-identical to the prior entry's.
- [ ] Drain TTL clamped to `[3600s over DIDComm | 0 over REST,
      30 days]`; out-of-range requests return
      `DrainTtlOutOfBounds`.
- [ ] DIDComm service entry, when present alongside REST, is
      ordered/priorityed such that a v2-aware client picks DIDComm.

### Transport coverage
- [ ] Every command (except `services didcomm enable`) is reachable
      over both REST and DIDComm. `services didcomm enable` is
      REST-only and rejects DIDComm delivery.
- [ ] REST and DIDComm handlers share the same operation layer —
      no duplicated business logic.

### CLI surface
- [ ] `pnm` and `vta` expose the §5.1 surface; `pnm mediator` and
      `pnm services {enable,disable} didcomm` are gone (no
      deprecation alias).
- [ ] Operator errors print suggested commands per CLAUDE.md
      ("operator errors should suggest the fix").

### Telemetry
- [ ] Each mutation emits a `service.<kind>.<verb>` event carrying
      the new LogEntry version-id.
- [ ] Existing `RingBufferTelemetry` swappability test still passes
      with the new event types.

### Tests
- [ ] Unit tests in each `operations/protocol/*` file cover happy
      path + each rejection variant.
- [ ] Integration tests in `tests/e2e` cover the full coverage
      matrix in §7a against the test mediator.
- [ ] Restart-resilience: drain set survives a process restart
      (existing test extended for the new defaults).

## 7a. End-to-End Coverage Matrix

This section is **part of the acceptance criteria**, not an
appendix. The implementation is not done until every cell below has
a passing test in `tests/e2e`.

### 7a.1 State model

The VTA's published service surface has exactly three valid states
under the §3.2 invariant:

| State | REST | DIDComm |
|:-----:|:----:|:-------:|
| **S1** | on   | off     |
| **S2** | off  | on      |
| **S3** | on   | on      |

`(off, off)` is invariant-violating and is itself a test target —
every command that *would* produce it must be rejected.

### 7a.2 State × Operation matrix

Every cell is a separate e2e test. "✓ → Sn" means accepted and the
state transitions to Sn (or stays). Error cells assert the typed
`VtaError` variant fires; no implementation may collapse them to a
generic string.

| From | rest enable | rest update | rest disable | rest rollback | didcomm enable | didcomm update | didcomm disable | didcomm rollback |
|:----:|:-----------:|:-----------:|:------------:|:-------------:|:--------------:|:--------------:|:---------------:|:----------------:|
| **S1** | `ServiceAlreadyEnabled` | ✓ → S1 | `LastServiceRefused` | history-dependent (§7a.5) | ✓ → S3 | `ServiceNotPresent` | `ServiceNotPresent` | `NoPriorMutation` |
| **S2** | ✓ → S3 | `ServiceNotPresent` | `ServiceNotPresent` | history-dependent (§7a.5) | `ServiceAlreadyEnabled` | ✓ → S2 | `LastServiceRefused` | history-dependent (§7a.5) |
| **S3** | `ServiceAlreadyEnabled` | ✓ → S3 | ✓ → S2 | history-dependent (§7a.5) | `ServiceAlreadyEnabled` | ✓ → S3 | ✓ → S1 | history-dependent (§7a.5) |

`NoPriorMutation` is a new typed error variant — added to the §4
list. It fires when `rollback` is called on a service kind that has
no recorded prior mutation to fail-forward from.

Rollback cells say "history-dependent" because, per §3.5a, the
result depends on what the most recent mutation of that kind *was*
— the cell can resolve to any other ✓ outcome or to
`NoPriorMutation` / `LastServiceRefused`.

Total: **24 cells.** All must have an e2e test.

### 7a.3 Transport coverage

Each accepted (✓) cell above is run **twice**: once delivered over
REST, once over DIDComm. Exception: `services didcomm enable` is
REST-only by nature and the DIDComm-transport variant is replaced
by an `UnsupportedTransport` rejection test.

For S2 (REST off), REST-transport variants of the operations are
delivered against the still-bound local Axum listener — recall
§3.4: the listener stays running, only its DID-doc advertisement is
removed. The test fixture asserts this distinction.

Total: **2× the accepted cells, plus the `UnsupportedTransport`
test.**

### 7a.4 Drain interaction matrix

Drain semantics are DIDComm-only. These are *additional* scenarios
on top of §7a.2:

| Scenario | Expected |
|---|---|
| `didcomm update` from S2 → drain set has 1 entry, 24h default TTL | drain entry exists; drain countdown visible in `drain list` |
| `didcomm update` while a previous drain is still active | drain set has 2 entries; sticky outbound routing per §3.5 |
| `didcomm disable` from S3 → drain entry created with default 24h | drain entry exists; LogEntry has no DIDComm service |
| `didcomm rollback` while drain active for the prior `update` | drain canceled, prior mediator restored, no new LogEntry chain branching |
| `didcomm rollback` of a `disable` while drain still active | DIDComm re-advertised, drain entry removed atomically |
| Drain TTL expiry → `DIDCommService::remove_listener` called | listener removed; mediator no longer in registry |
| Process restart mid-drain → drain set replayed with remaining TTL | sweeper resumes, no double-counting |
| `drain cancel <did>` on an active drain | drain entry removed immediately; listener removed |
| `--drain-ttl 0` on `disable` | no drain set; immediate listener removal (allowed only over REST transport) |
| `--drain-ttl 30s` over DIDComm transport | rejected with `DrainTtlOutOfBounds` (below `MIN_DRAIN_TTL_OVER_DIDCOMM`) |
| `--drain-ttl 31d` | rejected with `DrainTtlOutOfBounds` (above `MAX_DRAIN_TTL`) |

Total: **11 drain scenarios.**

### 7a.5 Rollback history scenarios

Rollback is history-sensitive, so it gets its own enumerated set
rather than a single state×op cell. Per §3.5a, every rollback
publishes a new LogEntry — the chain only grows.

#### DIDComm rollback

| History | Then `didcomm rollback` | Expected |
|---|---|---|
| S1 (no DIDComm history) | | `NoPriorMutation` |
| S1 → S3 (didcomm enable X) → rollback | | new LogEntry → S1 (DIDComm absent again) |
| S2 → S2 (didcomm update A→B, B draining never started since A→B drains A) → rollback | | new LogEntry → S2 with mediator A primary; B enters drain set with default 24h |
| S3 → S1 (didcomm disable from mediator A, A draining) → rollback | | new LogEntry → S3; mediator A re-pinned as primary; A's drain entry removed |
| Two consecutive didcomm updates A→B→C, then rollback | | new LogEntry → B primary; C enters drain set; A continues draining on its existing schedule (single-step rollback only) |
| S2 (no DIDComm history at all — VTA was set up REST-first then `didcomm enable`) | rollback after the enable → S2 with no DIDComm | rejected `LastServiceRefused` (would brick) |

#### REST rollback

| History | Then `rest rollback` | Expected |
|---|---|---|
| S2 (no REST history at all) | | `NoPriorMutation` |
| S2 → S3 (rest enable X) → rollback | | new LogEntry → S2 (REST absent again) |
| S3 → S3 (rest update X→Y) → rollback | | new LogEntry → S3 with REST URL X |
| S3 → S2 (rest disable from URL X) → rollback | | new LogEntry → S3 with REST URL X re-advertised |
| S1 (REST-only, no DIDComm) → rollback the most recent rest enable | | rejected `LastServiceRefused` (would brick) |

Total: **11 rollback histories** (6 DIDComm + 5 REST).

### 7a.6 Sequencing / soak paths

A handful of multi-step "operator day-in-the-life" paths to catch
state-leak bugs the cell-by-cell tests miss:

1. **Domain migration**: S3 → `rest update` → S3 (different URL) →
   verify both transports still functional, LogEntry chain has
   exactly one new entry.
2. **DIDComm-only deployment**: setup-S3 → `rest disable` → S2 →
   `didcomm update` → S2 (new mediator) → operate over DIDComm
   only for the rest of the test.
3. **REST-only deployment**: setup-S3 → `didcomm disable` → drain
   to expiry → S1 → operate over REST only.
4. **Mediator failover with rollback**: S3 → `didcomm update` to
   broken mediator → handshake fails → state still S3 with
   original mediator → `didcomm update` to good mediator →
   rollback → original restored.
5. **Restart-during-drain**: S3 → `didcomm update` → kill VTA
   process during drain window → restart → drain timers replayed
   → drain expires on schedule.
6. **Brick attempt**: S2 → `didcomm disable` → rejected
   `LastServiceRefused` → state still S2 → `rest enable` → S3 →
   `didcomm disable` → S1.

Total: **6 sequencing paths.**

### 7a.7 Test infrastructure

* All e2e tests live in `tests/e2e/` (existing crate from PR #36).
* `affinidi-messaging-test-mediator` is the DIDComm test peer
  (already on crates.io as of c0bfc30).
* Each test starts from a fresh fjall store + a freshly-set-up
  VTA in a known state — no shared state between tests.
* WebVH LogEntry chain assertions use the existing did_webvh
  helpers in `vta-service/src/operations/did_webvh/`.
* Telemetry assertions read from `RingBufferTelemetry`.

### 7a.8 Counting

Approximate test count for this matrix:

| Category | Count |
|---|---|
| §7a.2 cells × ~2 transports | ~36 |
| §7a.4 drain scenarios | 11 |
| §7a.5 rollback histories | 11 |
| §7a.6 sequencing paths | 6 |
| **Total** | **~64 e2e tests** |

This is large but tractable; the harness is shared, so most tests
are short. The matrix is the gate for shipping.

## 8. Boundaries

**Always:**
* Run `cargo fmt` before committing
* DCO-sign every commit (`git commit -s`)
* Reuse `affinidi-vc` / `affinidi-data-integrity` for any
  signed-envelope work — no hand-rolled JSON signing
* Apply `Verified*` typestate pattern to any new wire form that
  carries a signature (per CLAUDE.md)
* Update `docs/02-vta/didcomm-protocol-management.md` and
  add a new `docs/02-vta/runtime-service-management.md`
  operator guide

**Ask first:**
* Adding a third service kind beyond REST/DIDComm
* Changing `MAX_DRAIN_TTL` or `MIN_DRAIN_TTL_OVER_DIDCOMM`
* Adding a `--force` flag to bypass `LastServiceRefused`
* Changing the JWT audience model or adding a new claim
* Adding a new `SealedPayloadV1` variant (touch the seal helper in
  `provision_integration/seal.rs`)

**Never:**
* Provide a multi-service atomic mutation API (foot-gun)
* Allow zero advertised services
* Re-issue or rotate `verificationMethod` as a side effect of a
  service mutation
* Re-introduce `pnm mediator …` as an alias
* Bypass the existing `MODE_B_LOCK` / carve-out gating in
  TEE bootstrap
* Skip telemetry emission "because the operation is fast"

## 9. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Operator removes the only reachable transport | `LastServiceRefused` invariant; no `--force` |
| Mediator migration races with in-flight inbound | Existing drain set, sticky outbound routing |
| LogEntry publication fails after runtime mutation | Transactional rollback (existing pattern in `migrate_mediator.rs`) |
| Operator scripts break on CLI rename | Documented breaking change; user confirmed acceptable |
| 24h default surprises an operator who relied on whatever-it-was-before | No production users; one-line note in upgrade guide |
| WebVH LogEntry chain grows unbounded with frequent service mutations | Out of scope — existing chain-pruning concerns apply equally |

## 10. Resolved Questions

All previously-open questions are resolved. Audit performed on
2026-05-06 against `main` at 88dab00.

1. **DIDComm-preferred ordering:** array-ordering convention.
   The VTA DID-doc rendering function
   (`vta-service/src/operations/did_webvh/document.rs:79`) builds
   `service[]` in a fixed order. Today's order is
   mediator-didcomm → additional_services → tee-attestation.
   When REST joins the array, it goes **after** the
   DIDComm entry, preserving "DIDComm-first." No `priority` key
   is used; resolvers that walk the array in order will pick
   DIDComm first.
2. **URL reachability probing on `rest enable`:** **don't probe.**
   Trust the operator, consistent with mediator DID handling.
3. **`routing_keys` for DIDComm:** the field is already
   well-established in the mediator template
   (`vta-sdk/templates/didcomm-mediator.json:49`,
   `routingKeys`) and in
   `EnableDidcommRequest`. The current VTA `#vta-didcomm` service
   entry omits it; we'll add it as an optional pass-through when
   the operator supplies `--routing-keys`. No SDK extension
   required.
4. **`services list` JSON shape:** minimal —
   `{ kind, enabled, config: Option<…> }` per kind. Reusing
   `services report`'s telemetry-heavy shape is rejected; report
   is a different operation (per-mediator counters, sender
   last-seen).
5. **Rollback scope:** per-kind and fail-forward (§3.5a).
   `services rest rollback` and `services didcomm rollback` are
   symmetric — each publishes a new LogEntry that re-applies
   its kind's prior config.

### Implementation note — REST service entry already exists

The VTA's own DID document **already advertises** a REST service
entry today. The rendering goes through the
`additional_services` extension point of `build_did_document_inner`
rather than being baked into the inner function directly:

* `vta-service/src/setup.rs:86` — `build_vta_additional_services`
  produces a single entry:
  ```json
  {
    "id":   "{DID}#vta-rest",
    "type": "VTARest",
    "serviceEndpoint": "<public_url>"
  }
  ```
* Emitted iff REST is enabled in runtime state AND `public_url` is set. At
  setup time this is gated by the `[services] rest` seed value (matrix test in
  `setup.rs:175`); at runtime it's gated by the
  `operations::protocol::runtime_state` fjall record, mutated by
  `services rest enable/disable`.
* SDK resolves it via `find_service("vta-rest")` at
  `vta-sdk/src/session.rs:1100`. The resolve path is
  load-bearing for the SDK's own routing.

This **constrains** the runtime-mutation work in P1.3 / T2.4:

* **Wire shape is fixed.** Keep `id: "{DID}#vta-rest"`, keep
  `type: "VTARest"`. SDK consumers depend on these strings.
* **Rendering is moved, not invented.** P1.3 lifts the rendering
  out of `setup::build_vta_additional_services` and into the
  shared service-rendering layer, so the same JSON is emitted
  whether it comes from setup or from a runtime
  `services rest enable/update`. The setup path delegates to the
  shared layer.
* **§3.3 ordering note:** today the array is
  `[#vta-didcomm (if mediator), #vta-rest, #tee-attestation
  (if tee)]`. To honor "DIDComm preferred," the existing order is
  already correct — DIDComm is first. Confirmed in T0.1 audit
  against `document.rs:79` + `setup.rs:86`. T2.4 just locks this
  in via a render-layer test.

**Initial state post-upgrade.** Runtime enable/disable state lives in the
`service_state` fjall keyspace (`operations::protocol::runtime_state`), not in
`config.toml`. On first boot post-upgrade,
`runtime_state::migrate_from_config` seeds that keyspace from the legacy
`[services]` block — so an upgraded VTA with `services.rest = true` +
`public_url` set + `services.didcomm = true` boots in **S3** (both advertised)
with no implicit state change. Subsequent boots ignore the legacy block; the
runtime commands are the only path that mutates state. A VTA configured today
with `services.rest = false` + `services.didcomm = false` is already
unreachable (its DID doc has no transport service entries) — that's a
pre-existing config foot-gun, not something this spec introduces. Per §3.2,
the runtime commands enforce the "at-least-one" invariant going forward;
existing misconfigured VTAs are not auto-repaired.

## 11. Lifecycle

* Phase 1 (this doc) — review and sign-off
* Phase 2 — Plan: component breakdown, dependency order, parallelism
* Phase 3 — Tasks: discrete units with acceptance criteria each
* Phase 4 — Implement: incremental, TDD, each task lands behind
  green CI before the next starts
