# Application-state store

Status: **Implemented.** Specifications published upstream as
`vta/app-state/{get,put,list,delete,get-many,put-many}/1.0`
(trustoverip/dtgwg-trust-tasks-tf#252, #253); served by this workspace per
[#1029](https://github.com/OpenVTC/verifiable-trust-infrastructure/issues/1029).

Two things in this note were changed by building it, and both are corrected
in place below rather than left for a reader to trip over: the version counter
is per **namespace**, not per record (§2), and the family is named
`app-state`, not `appstate` (§8.5). The rest stood.

A third store on the VTA, beside the secrets vault and the credential vault, for
**application state**: versioned, namespaced, per-context JSON that an
application owns and the VTA does not interpret.

This note exists because #1029 cannot be built first and specified afterwards.
The dispatcher refuses to serve a Trust Task URI the published registry has no
schema for, and says so in the assertion itself: *"Author the spec upstream in
trustoverip/dtgwg-trust-tasks-tf and bump trust-tasks-rs — growing the allowlist
is the wrong fix."* So the first deliverable is a schema in another repository,
and this note is its input. §7 sets out the sequence.

---

## 1. Why a third store

OpenVTC needs somewhere to keep the metadata that makes an account recoverable
from its Trust Context — labels, relationships, contacts, join history. Three
existing stores were considered and each is wrong for a reason worth writing
down, because the reasons are what keep the boundary from eroding later.

**Agent memory** (`vta/memory/{put,list,delete}/0.1`) is the closest fit and the
most dangerous. Verified against `vta-sdk/src/protocols/memory.rs`:

- `MemoryItem` is `{key, value}` — no version, no timestamp, nothing to hang a
  precondition on. Two writers overwrite each other and neither can detect it
  afterwards.
- `MemoryListResponse` returns *"every entry in the context, in ascending key
  order"*. No prefix, no cursor. Application state and agent memory grow
  independently, so every application read pays for the agent's memory.
- And the settling argument: **"forget everything" is a reasonable thing for a
  user to ask an agent, and it must not delete their community memberships.**
  Clearing memory has to stay safe, which it cannot be if account state lives
  there.

**The secrets vault** is shaped as a password manager — `secret_kind` of
`password`/`passkey`/`oauth-tokens`, site-oriented `targets`. Application records
are not site credentials and would surface in a user-facing vault UI as noise.

**The credential vault** is right for verifiable credentials, and OpenVTC already
uses it. Application metadata is *about* credentials rather than being one.

Three stores, three jobs: secrets, verifiable credentials, application state.

---

## 2. Shape

Records are addressed by `(contextId, namespace, key)`.

The **namespace** scopes an application — `openvtc`, `cnm`, a future agent
runtime — so several tools can share one context without colliding. It is also
the natural seam for per-namespace ACLs later; nothing here needs them yet, but
choosing an address that cannot express the grant would make that a migration.

The store is **schema-agnostic**. It manipulates generic JSON structure on
request (see merge-patch, §4) but never validates, migrates, or interprets what
a record means. A dumb store needs no migration when a consumer's model changes,
and every store that grew opinions about its records eventually blocked its
consumer's release.

**Not for secrets.** Stated in the protocol documentation, not merely implied by
the existence of a vault next door. A boundary that is not written down erodes.

### The properties that do not exist today

| Property | Behaviour |
|---|---|
| `version` | Server-assigned, monotonic per `(contextId, namespace)`; returned by `get`, `list`, `put` |
| `expectedVersion` on `put` | Optional precondition. On mismatch, a typed conflict **carrying the current version and value** |
| `expectedVersion: 0` | "Create only — fail if it exists" |
| `prefix` + pagination on `list` | Scoped enumeration |
| `sinceVersion` on `list` | Only records changed since a watermark |
| Tombstones on `delete` | Versioned, reaped after a retention window |
| Stated size limit | A per-record cap, and an explicit error on exceeding it |

Three of these carry more weight than their row suggests.

**The counter is per namespace, not per record — and this note originally got
that wrong.** Implementing it surfaced the problem: `sinceVersion` compares a
consumer's watermark against record versions, and *per-record* counters are not
comparable to each other, so no single number can mean "everything changed after
this point". A per-record counter would have forced a second sequence alongside
it, and the two would have had to be kept consistent by hand.

Making the counter per `(contextId, namespace)` collapses both jobs into one
number: a record's `version` is the counter value its most recent write took, so
it is simultaneously the optimistic-concurrency token and the sync watermark. The
cost is that a record's version jumps by however many values its neighbours
consumed, which is why the published contract states that versions are opaque and
monotonic and never an edit count. That cost is real but bounded; the alternative
was two counters and a consistency invariant between them.

**Returning the current value with a conflict** is not a convenience. A caller
that receives a bare rejection must re-read, and between the rejection and the
re-read the record can change again; the pattern has no fixed point under
contention. Returning the winner's view with the rejection removes the race
rather than narrowing it.

**Tombstones are what make incremental sync converge.** Without them a peer
pulling `sinceVersion` learns about every create and update and never learns
about a delete, so deleted records resurrect on the next full rebuild and
disagree with peers that saw the delete live. This is the property most often
omitted from a store like this and most expensive to add afterwards, because
retrofitting it means every existing consumer's watermark is silently wrong.

**A stated size limit** because OpenVTC has already lost a join to a limit that
dropped a write silently. Refusing loudly at a documented cap is the whole
requirement; the number matters less than its being knowable and enforced.

---

## 3. What to reuse rather than invent

Three pieces of this already exist in the workspace and should not be rebuilt.

**Cursor pagination.** `vti_common::pagination` is the workspace-wide standard —
opaque base64url cursors, HMAC-SHA256-signed so one maintainer's cursor cannot be
replayed against another, `(last_key, snapshot_id)` payload, and a shared
`paginate()` helper. The VTA has no audit hash chain to sign under, so it uses
`CursorKey`, which persists a random key for nothing but cursor MACs. `list`
takes `cursor` + `limit` through that helper. A bespoke offset or a raw
`last_key` would be both a regression and a second thing to get wrong.

**Idempotency.** Consequential Trust Tasks are deduped generically at the
dispatch spine on a client-supplied key, driven by the classification in
`vta_sdk::retry_safety`. Every new task must appear there — a census test
(`every_uri_is_classified`) means a task cannot join the catalogue without
someone deciding what a lost reply costs it. §6 proposes the classifications.

**The keyspace registry.** A new keyspace is a `const` in `vta-keyspaces` and a
deliberate placement in the `BACKED_UP` / `EXCLUDED_FROM_BACKUP` partition,
pinned by a census test. Application state is the user's account: it belongs in
`BACKED_UP`. Getting that wrong means a restored VTA comes back without the
metadata that made the account recoverable, which is the entire point of the
feature.

`MEMORY` is the precedent to copy for everything except the semantics — a
per-context store, keyed `mem:<contextId>:<key>`, `list` as a prefix scan, and
`BACKED_UP` because it is *"durable user data"*. `appstate` differs only in
carrying a namespace segment and a version, so the key is
`app:<contextId>:<namespace>:<key>`. Keeping the same prefix-scan shape means
`list` with a `prefix` is a narrowing of the scan rather than a new access
pattern.

---

## 4. Batching, and the shapes that make it safe

A rebuild or a write-behind flush is N records. Round-tripping each one is the
difference between a usable reconnect and an unusable one, so the surface needs
`getMany` / `putMany` with **per-record results**.

`putMany` takes an explicit **mode**, and the default matters:

- **`independent`** (default) — each write applies on its own merits, so one
  conflicted record does not block the other nine. This is what a flush of
  unrelated edits wants.
- **`atomic`** — available for records carrying a joint invariant.

An atomic default would let one stale record silently wedge an entire flush, and
the caller would have no way to tell a wedged flush from a slow one.

**`includeValues` on `list`** so a prefix scan is one call rather than a scan
plus N gets.

**JSON merge-patch on `put`** (RFC 7386) cuts payload, and more usefully cuts
*conflicts*: two instances editing different fields of one record stop colliding
entirely rather than serialising behind `expectedVersion`.

---

## 5. Blobs — and a constraint the issue got half right

A record may carry an attached blob, versioned with it but **never returned by
`list`** — only a `blobRef` with size and digest, so a prefix scan cannot
accidentally drag megabytes through a Trust-Task envelope. The existing
`backup_export_via_descriptor` → `download_blob` pattern is the right shape.

#1029 flags a caveat — *"that path is documented REST-only, and OpenVTC speaks
DIDComm"* — and the code says something more precise. From
`vta-sdk/src/client/backup_descriptors.rs`, `download_blob` matches on the
transport and a DIDComm or TSP client **can** use it, via an optional
`rest_client` side-channel:

```rust
Transport::DIDComm { rest_client, .. } => rest_client.as_ref().ok_or_else(|| {
    VtaError::Validation("DIDComm transport has no REST client for blob download".into())
})?,
```

So blobs are not closed to DIDComm clients. They are closed to clients that do
not know a REST URL — `rest_client` is `Some` exactly when `rest_url` is
(`client/mod.rs:457`).

**That is the real constraint, and it is sharper than the issue's.** A VTA may
legitimately stop advertising REST: runtime service management allows disabling
a transport provided one remains, so a DIDComm-or-TSP-only VTA is a supported
deployment. On such a VTA the blob path is unreachable, and an appstate design
that assumes it would make blobs work on some VTAs and not others with no
signal.

Three ways out, and this note does not pick one because it is a protocol
decision rather than an implementation detail:

1. **Blobs require an advertised REST endpoint**, stated plainly, with a typed
   error when it is absent. Honest and cheap; leaves a capability gap that
   varies by deployment.
2. **Chunked transfer over the Trust-Task surface.** No REST dependency, and it
   puts large payloads back inside the envelope this design deliberately keeps
   them out of.
3. **Defer blobs.** Ship `appstate` without them and let the first real consumer
   requirement decide. Nothing in OpenVTC's stated need — labels, relationships,
   contacts, join history — obviously wants a blob.

**Recommendation: (3), then (1) if a consumer needs it.** The rest of this
design is sound without blobs and blocked on nothing; blobs are the only part
that forces a decision about REST advertisement, and deferring them keeps that
decision out of the critical path for OpenVTC recovery.

**Decided: (3).** 1.0 has no blob member at all. Adding a `blobRef` later is a
MINOR addition rather than a breaking change, so nothing is foreclosed, and the
REST-advertisement question stays unanswered until a consumer actually forces
it. The published `put` spec instead states a per-record cap and requires the
maintainer to refuse loudly at it, which is what keeps a consumer from quietly
treating `value` as a blob store in the meantime.

---

## 6. Retry safety

Every task must be classified in `vta_sdk::retry_safety` before it can be
dispatched. Proposed:

| Task | Class | Why |
|---|---|---|
| `appstate/get/1.0` | `ReadOnly` | No durable effect |
| `appstate/list/1.0` | `ReadOnly` | No durable effect |
| `appstate/put/1.0` | `RetrySafe` **when** `expectedVersion` is supplied | The precondition makes a replay converge: the second attempt fails the version check and leaves one record |
| `appstate/put/1.0` | `Keyed` when it is not | Without a precondition a replay writes twice and bumps the version twice, so a watcher sees a change that never happened |
| `appstate/delete/1.0` | `RetrySafe` | Converges — a second delete finds a tombstone |
| `appstate/put-many/1.0` | `Keyed` | Same as `put`, and partial application makes a blind replay worse |
| `appstate/get-many/1.0` | `ReadOnly` | |

The `put` split is the interesting one and the classification table cannot
express it — the class is per-URI, not per-payload. The conservative reading is
what that module already prescribes (*"where an operation's convergence is not
obvious from its contract, it is classified `Keyed`"*), so **`put` should be
`Keyed`** and the `expectedVersion` path simply benefits twice. Worth stating
explicitly in the spec so a future reader does not "optimise" it to `RetrySafe`
on the strength of the precondition alone.

**As shipped**, in `vta_sdk::retry_safety`: `get` / `list` / `get-many` are
`ReadOnly`, `delete` is `RetrySafe`, and `put` / `put-many` are `Keyed`. The
reasoning above is recorded as a comment beside the entries, because the
temptation to "fix" the `put` classification is exactly the kind of change that
looks like a cleanup and is not.

The `delete` classification earns its `RetrySafe` from a specific
implementation choice rather than from the shape of the task: a repeat delete
finds a tombstone, returns `existed: false`, and **deliberately does not take a
new counter value**. Had it taken one, every consumer watching the namespace
would see a change that did not happen, and delete would have had to be `Keyed`
like the writes.

---

## 7. Sequence

The upstream dependency is load-bearing and determines the order:

1. **Author the schemas upstream** in `trustoverip/dtgwg-trust-tasks-tf` —
   `spec/vta/appstate/{get,put,list,delete,get-many,put-many}/1.0`. This note is
   the input.
2. **Bump `trust-tasks-rs`** so `schema_index::schema_for` resolves them.
   Until this lands, step 3 cannot pass its own test suite.
3. **Implement in this repo** — keyspace, storage, operations, dispatch,
   `retry_safety` entries, conformance witnesses, SDK client methods.
4. **OpenVTC adopts.**

Steps 1–2 are in another repository and on another team's cadence. That is worth
knowing before this is scheduled: the implementation is a few days and the
sequencing is not.

**Steps 1–3 are done.** The schemas are published upstream (#252, with #253
correcting the error taxonomy), and this workspace serves all six URIs with
conformance witnesses, so nothing entered `UNSPECCED_DISPATCHED_URIS`. Step 4 —
OpenVTC adoption — is the remaining work and belongs to that repository.

The sequencing prediction held, and in one respect it was optimistic: the
implementation is what found the per-namespace counter problem (§2) and the two
error-taxonomy defects (#253). Specifying first was still right — the dispatcher
gives no other option — but "specify, then implement, then correct the spec" is
the honest shape of it, and the second correction round should be budgeted.

**Do not** shortcut by adding the URIs to `UNSPECCED_DISPATCHED_URIS`. That list
is acknowledged debt from before the registry existed, it shrinks monotonically
by test, and the harness's own message calls growing it the wrong fix.

---

## 8. Resolved questions

Each of these was open when the note was written and is settled now. The
reasoning is kept because the answers constrain what a later change may do.

1. **Blobs — deferred.** §5. No blob member in 1.0; adding a `blobRef` is a
   MINOR addition, so the REST-advertisement question stays unanswered until a
   consumer forces it.

2. **Per-namespace ACLs — not yet, and the address is ready for them.** A
   namespace in 1.0 is collision avoidance, **not** a trust boundary. Both the
   `put` and `delete` specifications say so normatively in their
   `## Authorization` sections, and say what to do instead: mutually distrusting
   applications go in separate **contexts**.

   The important half is that the *address* already carries the namespace, so
   granting on it later is a new grant type rather than a migration of every
   stored record. That was the point of answering the question now — the answer
   "not yet" was only safe because the address did not foreclose it.

   `delete` is where the coarseness has teeth, and its spec says that too: a
   compromised application sharing a context can remove another's records, with
   only the tombstone retention window between that and permanent loss.

3. **Tombstone retention — configurable, default 30 days, and swept.**
   `config.app_state.tombstone_retention_days`, matching the vault's
   `grace_days` precedent: a destructive retention window is an operator's
   choice, not a constant. The configured value — not a constant — is what the
   `list` change-feed response advertises as `tombstoneRetentionSeconds`, since
   a consumer schedules against that number and advertising 30 days while
   reaping at 7 would strand exactly the clients that trusted it.

   `sweep_expired_tombstones` runs from the storage thread's interval loop
   beside the ACL / consent / vault sweepers, and lives in `vta-service` rather
   than `vta-sweepers` for the reason the backup-bundle sweeper does: it is
   coupled to this module's key layout, and a second copy of that in a lower
   crate is a second thing to keep in step.

   Two properties are worth knowing before changing it:

   - **It reaps a prefix, not a set.** Each namespace walks its tombstones in
     version order and stops at the first still inside the window. Reaping a
     later tombstone while leaving an earlier one would make `appt:`
     unstateable — no single watermark would describe what survives, which is
     the one thing `watermarkTooOld` needs to be able to say. An expired
     tombstone sitting behind a younger one waits for the next sweep.
   - **`0` days disables it**, and that is enforced at the call site rather than
     as a zero cutoff, because a zero cutoff means the opposite (everything is
     expired). Disabled means tombstones are kept forever, no watermark ever
     expires, and the keyspace grows unbounded — a legitimate trade for a
     deployment that would rather spend disk than force a rebuild.

   `reap_tombstones_through` writes the reap watermark **before** removing
   anything: a crash mid-reap then refuses a resumable sync, where the opposite
   order would serve an incomplete feed as though it were whole.

4. **Size cap — 65536 bytes per record**, measured over the value's compact JSON
   encoding, with `limitBytes` and `actualBytes` both returned on refusal. The
   number matters less than the loudness; the batch surfaces carry their own
   aggregate budgets (`get-many` defers past 512 KiB of response, `put-many`
   refuses past 768 KiB of request), because the per-record cap times the item
   ceiling exceeds any sane request or response limit.

5. **The name is `app-state`.** Hyphenated, matching `did-management`,
   `credential-exchange` and `task-consent`. `appstate` — the noun the issue
   used — would have been the only unhyphenated multiword family in the
   registry. Settled before publication, which was the whole reason to ask.

## 9. Concurrency: why a lock and not a compare-and-swap

The read-modify-write sequences are serialised by a process-local lock per
`(contextId, namespace)`, plus a durable, fsynced version reservation. A
compare-and-swap in the store layer was considered as the more robust starting
point and rejected, because on inspection it does not protect anything the lock
leaves exposed.

**There is no reachable multi-writer topology.** fjall — the local backend —
takes an exclusive file lock on the database directory, so two processes cannot
open one store at all. The vsock backend proxies to a single store from a single
enclave; `insert_if_absent` and `swap` there are already *non-atomic* get+insert
fallbacks that log a warning, and the wire protocol has six opcodes, none
atomic. A genuine CAS would need a seventh opcode implemented in
`deploy/nitro/enclave-proxy` — a separate, non-workspace crate deployed to the
parent EC2 instance — plus version negotiation between two independently
deployed artifacts. That is a TEE-protocol decision, and it would still leave
the fallback non-atomic on any proxy that had not been upgraded.

So a CAS added today would be atomic exactly where the lock already suffices,
and a warn-and-fallback exactly where it would need to be real. It would read as
multi-writer safety while providing none.

**What the CAS question did surface was a real bug**, and that is fixed: the
version counter was written without an fsync. `vti_common::store::counter` makes
the argument for BIP-32 path counters and it transfers exactly — a counter
surviving only in the journal buffer can be re-derived after a crash and hand
out a value already used. Here a reused *version* means two records collide on
one `appv:` index key, so one of them disappears from the change feed and every
incremental consumer misses that change permanently, with nothing to signal it.
`reserve_versions` now fsyncs the reservation and re-seals the TEE integrity
manifest before returning, and reserves a whole block for a batch so `put_many`
pays one fsync rather than N.

The residual exposure is a second VTA process against one store, which nothing
can currently do. If that ever becomes reachable, the fix is a compare-and-swap
in the store layer — not a bigger lock here — and it should land with the vsock
opcode, not before it.

## 10. Still open

1. **OpenVTC adoption** (§7 step 4), in that repository.
