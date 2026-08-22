# Application-state store

Status: **Design — not implemented.** Tracked by
[#1029](https://github.com/OpenVTC/verifiable-trust-infrastructure/issues/1029).

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
| `version` | Server-assigned, monotonic per record; returned by `get`, `list`, `put` |
| `expectedVersion` on `put` | Optional precondition. On mismatch, a typed conflict **carrying the current version and value** |
| `expectedVersion: 0` | "Create only — fail if it exists" |
| `prefix` + pagination on `list` | Scoped enumeration |
| `sinceVersion` on `list` | Only records changed since a watermark |
| Tombstones on `delete` | Versioned, reaped after a retention window |
| Stated size limit | A per-record cap, and an explicit error on exceeding it |

Two of these carry more weight than their row suggests.

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

**Do not** shortcut by adding the URIs to `UNSPECCED_DISPATCHED_URIS`. That list
is acknowledged debt from before the registry existed, it shrinks monotonically
by test, and the harness's own message calls growing it the wrong fix.

---

## 8. Open questions

1. **Blobs** — §5. Recommend deferring; needs a decision either way.
2. **Per-namespace ACLs.** The address supports them; nothing grants them. Is a
   namespace a trust boundary between applications on one context, or only a
   collision-avoidance convention? Answering "trust boundary" later is a
   migration, so it is worth answering now even if the answer is "not yet".
3. **Tombstone retention window.** Long enough that a peer offline for a
   plausible interval still converges; short enough that deletes are real.
   Suggest starting at the vault's 30-day grace and revisiting with evidence.
4. **Size cap.** Needs a number. The cap interacts with the 1 MB global request
   body limit, which is the ceiling for anything on the REST binding.
5. **Is `appstate` the right name?** It is the noun the issue uses. `app-state`
   or `application-state` would match the hyphenation of neighbouring task
   families more closely; worth settling before the URIs are published, because
   afterwards it is a new family rather than a rename.
