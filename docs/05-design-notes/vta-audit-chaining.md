# VTA audit chaining and actor hashing

**Status:** plan. No code yet — the middle of it cannot be landed alone, and
one stage changes what an operator sees.

**Closes:** VTI-AUD-004 (the audit trail is tamper-evident) and VTI-AUD-005 (an
audit record refers to personal data rather than embedding it) of the
[VTI specification](https://trustoverip.github.io/dtgwg-vti-spec/), both
recorded against this workspace in the specification's divergence register
(Appendix F).

## Where we are

The VTC satisfies both requirements. The VTA satisfies neither. The machinery
that would close the gap is in `vti-common`, which the VTA already depends on:

| Module | What it provides |
|---|---|
| `vti_common::audit::envelope` | the stored envelope with `prev_hash` / `entry_hash` / `schema_version`, `GENESIS_HASH`, and `verify_chain` |
| `vti_common::audit::writer` | `AuditWriter` — a process-wide chain head guarded by an async mutex, so read-head → stamp → insert → update-head is atomic; HMAC-hashes actor and target under the active audit key |
| `vti_common::audit::key_store` | `AuditKeyStore::ensure_initial(master_seed)`, key history, and `verify_actor` — "does this DID match this hash?" |
| `vti_common::audit::checkpoint` | anchors a point in the chain so verification survives retention |

The VTA's own sink is deliberately none of this. `vta-audit/src/sink.rs` says
so: the log "cannot prove it", the canonical envelope "already names the
members that would change that … and says why this maintainer omits them", and
the module adds "the seam" rather than the scheme (#1031). That was a defensible
call when the alternative was inventing a scheme. It is not one now: the scheme
exists, another node type in this workspace runs it, and the specification
requires it.

## The trap

Two types are called `AuditEnvelope`, and the wrong one is the one you reach
for first:

- `vta_sdk::protocols::audit_management::list::AuditEnvelope` — the canonical
  **wire** form the VTA renders on read. It has no hash members, and its doc
  comment explains that they are absent *because this log is flat*.
- `vti_common::audit::envelope::AuditEnvelope` — the **stored** form, with the
  hashes.

Stage 2 below is a change to the second. The first stays the wire form, and
what it carries is the subject of the decision in stage 3.

## Stages

**1 — Provision.** Add an `audit_key` keyspace to the VTA, construct
`AuditKeyStore`, and call `ensure_initial(master_seed)` on boot. Mirrors
`vtc-service/src/server.rs`. Inert on its own: nothing reads the key yet.

**2 — Write.** `KeyspaceAuditSink` writes through `AuditWriter` instead of
inserting a flat row. **This cannot land alone.** The storage key becomes
`<rfc3339-timestamp>:<event_id>` and the value becomes an envelope, so the
existing list query stops finding rows it can parse. Stage 2 and stage 3 are
one change.

**3 — Read.** `audit/list` and `cleanup_expired_logs` read both forms. The
shared code already carries the legacy path: a `schema_version` 1 row with no
hashes chains from `GENESIS_HASH`, and the verifier counts it as
`skipped_legacy` rather than reporting a break. Existing rows therefore stay
readable and the chain starts from the first new envelope.

**4 — Verify.** Expose `verify_chain` — a Trust Task and a `pnm audit verify`
subcommand, matching the VTC's `/v1/audit/verify` and `cnm audit verify`.
Chaining that nobody can check is not tamper-evidence; it is a hash column.

## The decision this needs before stage 3

**Today `pnm audit list` shows actor DIDs. Under the shared writer it cannot.**

`AuditWriter` HMACs the actor under the active audit key, which is precisely
what makes VTI-AUD-005 work — the row commits to who acted without embedding an
identifier that a later erasure would have to remove. The cost is that the list
can no longer answer *who did this*; it can answer *was it this DID?* through
`verify_actor`.

| Option | Effect |
|---|---|
| **(a) Hash, and filter by `verify_actor`** | Operators query `pnm audit list --actor <did>` and get their answer. Browsing without a candidate DID shows hashes. Satisfies AUD-005. **Recommended.** |
| (b) Hash, and keep a reversible mapping | The list looks unchanged and the property is gone: the mapping is the personal data, in the same deployment, one join away. |
| (c) Hash only actors that are personal identifiers | Requires classifying every actor as personal or not, at write time, correctly, forever. The first misclassification is silent and permanent. |

Option (a) is a real change to an operator surface and belongs to whoever owns
that surface, not to the person doing the wiring. It is the only reason this
note exists rather than a pull request.

## Retention versus the chain

`cleanup_expired_logs` deletes rows older than the retention period. Deleting
the tail of a hash chain leaves the remainder unverifiable — the first
surviving row's `prev_hash` points at something that is gone, which is
indistinguishable from tampering.

The VTC solved this with `audit_checkpoint.rs`: an anchor that lets
verification start from a known-good point rather than from genesis. Stage 3
adopts it, or retention quietly converts a tamper-evident log into a broken
one — and the first person to run `verify` after a retention sweep gets a
failure that means nothing.

This is the part of the work most likely to be skipped, because it only breaks
after the retention period has elapsed once.
