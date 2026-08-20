# Retry and idempotency — who owns what

**Status:** implemented (VTA + SDK). Closes the retry-safety half of #1009.

A client's request times out. Usually it never arrived, so retrying is correct.
Sometimes the VTA processed it and **only the reply was lost** — and there, a
retry produces a second durable effect that the party responsible for it never
learns about.

That asymmetry is the whole subject of this note. Everything below exists to
make the second case safe without making the first case slower.

---

## 1. The three layers, and which one owns retry

Three layers can independently decide to send a request again. Left
uncoordinated they multiply: three attempts at the application layer over three
at the transport layer is nine executions of an operation the server dedups at
neither.

| Layer | Retries? | Owns |
|---|---|---|
| **Messaging delivery** (`affinidi-messaging-delivery`) | yes — durable outbox, exponential backoff | *Delivery* of a message. Dedups at the receiver. |
| **`vta-sdk` client** | yes — `VtaClient::idempotent` | *One logical operation*, under one idempotency key. **This is the application-layer owner.** |
| **Application code** (OpenVTC, CLIs, integrations) | **no** | Nothing. Call `idempotent`; do not wrap it in a loop. |

**The rule: exactly one owner per failure domain.** The delivery layer owns
message delivery. `VtaClient::idempotent` owns operation completion. Application
code owns neither and must not add a third.

A hand-rolled application loop is not merely redundant — it is *actively worse
than nothing*, because it cannot hold a key stable. It re-invokes a client
method, which builds a fresh document, which means the VTA sees an unrelated
request. It converts "one operation, retried" into "two operations", which is
the exact failure the key exists to prevent.

### Migrating off a hand-rolled loop

```rust
// Before — bounded and well-intentioned, but every attempt is a new operation.
let resp = my_retry("create key", || client.create_key(build())).await?;

// After — one key across every attempt.
let resp = client.idempotent(|| client.create_key(build())).await?;
```

`op` is re-invoked from scratch per attempt, so it must rebuild any by-value
request — the same contract the hand-rolled loop had. The difference is that all
attempts now share one key.

---

## 2. What a lost reply costs each operation

`vta_sdk::retry_safety` classifies **every** URI in `ALL_URIS`. A census test
fails if a task joins the catalog unclassified, so this cannot silently drift.

| Class | Meaning | Needs a key? |
|---|---|---|
| `ReadOnly` | No durable effect. | no |
| `RetrySafe` | Mutating, but a repeat is harmless — it converges, or leaves an inert self-expiring duplicate. | no |
| `Keyed` | A repeat leaves a second durable artefact that persists and matters. | **yes** |
| `KeyedSecret` | As `Keyed`, but the response carries secret material. | **yes** |

`RetrySafe` is deliberately **not** called "idempotent", because half its members
are not. A second `auth/challenge` mints a second challenge. They are grouped
because the only question a retry layer asks is *"does a repeat do harm"*, and
for both members the answer is no.

**When adding a task, classify it.** Where convergence is not obvious from the
contract, choose `Keyed`. The asymmetry is nearly free: over-classifying costs
one dedup record, under-classifying loses the protection in exactly the rare case
the table exists for.

### The motivating example

`webvh/dids/create` is `Keyed` because production callers use
`WebvhPathMode::AutoAssign`. A retried create is assigned a **different** path,
so the first DID stays published in the log with nobody holding a reference to
it. With an explicit path the retry would collide and surface as a `Conflict` —
visible and recoverable. Auto-assign orphans silently, which is why it needed a
key rather than a convention.

---

## 3. The key

A top-level `idempotencyKey` member on the Trust Task document.

- It lands in `TrustTask::extra` (`#[serde(flatten)]`), so the upstream
  `trust-tasks-rs` document type needs no change.
- A Data-Integrity proof covers every member except `proof`, so **the key is
  signed**. A relayer cannot rewrite it to split one operation into two, or merge
  two into one.
- The request hash binds the **type URI as well as the payload**, so one key
  cannot carry a `keys/create` answer to a `dids/create` retry.
- Scoped per **principal** (`Principal::Did`), so callers can neither collide
  with nor probe each other's keys.

`Principal::Did` rather than the bearer token, for two reasons: a token rotation
mid-retry would otherwise start a fresh namespace and re-run the operation, and
DIDComm and TSP carry no bearer token at all.

### Absence is not an error

A request with **no** key, or with an unusable one (empty, or over 255 chars), is
dispatched exactly as it always was. Nothing that worked before this feature can
begin failing because of it. Rejecting a malformed key would break callers to
enforce a convenience.

---

## 4. Server-side semantics

Claimed **before** dispatch, via `insert_if_absent`. That ordering is the point:
`get` then `put` leaves a window where two concurrent attempts both read nothing
and both run.

| Found | Answer |
|---|---|
| nothing | claim it, run the handler, record the outcome |
| in flight, fresh | `unavailable` (503) + `retryAfter` — the first attempt is still running |
| in flight, stale (>10 min) | the process died mid-request; reclaim and run |
| completed, same request, replayable | the original response, verbatim |
| completed, same request, not replayable | `taskFailed` naming the first outcome |
| completed, **different** request | `taskFailed` — one key, two different requests |

Two orderings worth knowing:

- **Conflict is reported ahead of in-flight.** A mismatched body under a live
  claim gets `Conflict`, not "try again" — telling that caller to retry would
  loop it forever on a request that can never be accepted.
- **A failed task releases its claim** rather than recording it. The effect never
  happened, so the retry should actually run. Caching failures would turn one
  transient error into a sticky one for the record's whole lifetime.

### Retention window

**24 hours** (`IdempotencyClass::NonDestructive`), swept by
`vta_sweepers::idempotency_sweeper`. Records are also read-through-expiry, so a
stale one is never served even between sweeps.

Sized for the two real retry shapes: an automated backoff loop finishes within
seconds, and an operator re-running a failed provisioning step comes back within
minutes to hours. Every keyed Trust Task uses `NonDestructive`, including tasks
that destroy something — the `Destructive` 60s class exists for HTTP routes whose
key *is* the target's UUID, where a long TTL would silently no-op a later
intentional re-create. A Trust-Task key is per-attempt-group and carries no
resource identity, so that hazard cannot arise.

### Why some responses are never replayed

`seeds/export-mnemonic`, `backup/complete-export` and `provision/integration`
return a mnemonic, the whole VTA under a passphrase, and a sealed bundle
respectively. Caching those to serve a retry would persist the secret a second
time, indefinitely, in a keyspace that exists for retry bookkeeping — and would
break the standing invariant that the mnemonic plaintext is never cached
anywhere.

Those tasks record the **fact** of completion without the body. The duplicate
effect is still prevented; only the replay is refused, with an error saying so
and naming the read operation that can fetch the result. Responses over 64 KiB
take the same path, so one large listing cannot let a caller size a dedup record
with whatever it asked for.

### Failure is not fatal

A store error **logs and dispatches unguarded**. Idempotency is an improvement on
the status quo, not a precondition for it: failing closed would turn a storage
blip into an outage of every keyed operation, in order to prevent a duplicate
that only matters when a reply is *also* lost.

---

## 5. Retry hints

The VTA emits `retryAfter` in the rejection **document** when it answers
`unavailable`. `VtaClient::idempotent` honours it, **capped at 30 seconds** — an
unbounded wait on a server-chosen value is a stall the server can trigger at
will. A hint already in the past retries promptly rather than being treated as a
reason to wait.

Two deliberate limits:

- **The hint is in the document, not an HTTP `Retry-After` header.** DIDComm and
  TSP drop HTTP status entirely, so a header would serve one transport of three.
  The document is the transport-agnostic answer. Adding the header as well is a
  reasonable follow-up for HTTP intermediaries; it is not a correctness gap.
- **No outbound client in this repo currently retries HTTP at all** —
  `webvh_client` and the foreign-fetch path make a single attempt. So DRARM
  `RLA-029` (Retry-After non-compliance) has nothing to remediate here today. The
  rule below is what keeps it that way.

---

## 6. Rules for new code

1. **Classify every new Trust Task** in `vta_sdk::retry_safety`. The census test
   will fail otherwise. When unsure, `Keyed`.
2. **Never add an application-level retry loop over a `VtaClient` call.** Use
   `VtaClient::idempotent`. If you believe you need your own, you are adding a
   second owner to a failure domain that has one.
3. **Any new outbound HTTP client that retries must honour and cap
   `Retry-After`.** Cap it; an uncapped hint is a server-triggered stall.
4. **A new secret-bearing response must be `KeyedSecret`**, never `Keyed`. Ask
   what the dedup record would hold if the response were cached.
5. **Do not cache a failure.** Release the claim; let the retry run.

---

## Where the code lives

| Concern | Location |
|---|---|
| Classification + census | `vta-sdk/src/retry_safety.rs` |
| Client key scope + retry owner | `vta-sdk/src/idempotency.rs`, `VtaClient::idempotent` |
| Wire `retryAfter` → typed error | `VtaError::Unavailable` |
| Store (shared with the VTC's HTTP path) | `vti-common/src/idempotency/` |
| Dispatch policy | `vta-service/src/trust_tasks/idempotency.rs` |
| Envelope-id replay dedup (the *other* layer) | `vta-service/src/trust_tasks/replay.rs` |
| TTL sweep | `vta-sweepers/src/idempotency_sweeper.rs` |
| Acceptance tests | `vta-service/tests/idempotency_trust_task.rs` |

### The two dedup layers are not the same thing

`replay.rs` keys on `(actor, envelope-id)` and refuses a byte-identical
resubmission — the cross-transport fallback case. It **cannot** catch a genuine
retry, because every dispatch mints a fresh envelope id. `idempotency.rs` keys on
`(actor, idempotency-key)`, which is stable across attempts of one operation.
Both stay; they answer different questions.
