# VTA audit chaining and actor hashing

**Status:** plan. No code yet — the middle of it cannot be landed alone.
Nothing in it changes what an operator sees; an earlier revision said otherwise
and was wrong, which the section on the operator surface records.

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

## What happens to the operator surface: nothing

An earlier revision of this note claimed that stage 3 forces a choice between
showing operators an actor DID and satisfying VTI-AUD-005, and recommended
hashing with `--actor <did>` filtering. **That was wrong, and the mistake was
reading `AuditWriter::write` without reading the envelope it writes.**

The envelope carries both:

- `actor_did_hash` — always present, the durable correlation handle;
- `actor_did_plain` — the plaintext, `None` only after a redaction.

`AuditWriter::write` populates the plaintext on every write
(`writer.rs`), and the VTC's audit list renders exactly that field
(`vtc-service/src/routes/audit.rs`). So `pnm audit list` keeps showing actor
DIDs, and no operator-facing decision is required.

The property in VTI-AUD-005 comes from the third piece: **the chain digest
excludes the plaintext members**. `envelope.rs` says so, and two tests pin it —
`rtbf_redaction_preserves_hashes` and
`rtbf_redaction_does_not_break_the_chain`. An erasure nulls
`actor_did_plain`, the row keeps its hash, and the chain still verifies.

That is a better answer than any of the three options this note previously
offered, and it is what the design already does. `verify_actor` remains the way
to ask "was this redacted row's actor this DID?", which is the question that
survives an erasure — not a substitute for showing the actor while it is still
there.

## Where the audit key comes from

Stage 1 says "derive the audit key from the master seed on boot, mirroring
`vtc-service/src/server.rs`". A VTA can do that — the server holds the seed
store and already reaches it during boot — but it is worth asking whether it
should, because the seed is not the only source available and it is not
obviously the best one.

**A randomly generated key is the better default here.** The key's whole job is
to be a stable HMAC handle for actor and target identifiers: it needs to exist
before the first write, to be retrievable for as long as any envelope
references it, and to be rotatable. It does not need to be derivable from
anything. The key store already stores keys, keeps their history and rotates
them, so a random initial key fits the model it already has.

What derivation buys, and what it costs:

| | Derived from the seed | Randomly generated |
|---|---|---|
| Availability at first write | Not an issue either way — see *The first entry* below | Not an issue either way |
| Recovery when the `audit_key` keyspace is lost | Regenerable from the mnemonic, which matters if envelopes were shipped off-node (a fan-out sink to a SIEM) and only the local key store was lost | Gone. Mitigated by keeping `audit_key` in the backup set, which leaves the gap at "backups lost, mnemonic survives" |
| Who can recompute an actor hash | Anyone who holds the mnemonic, forever. A redaction that nulls the plaintext is then reversible by brute force for the seed holder, and the candidate space is small — the identifiers this node has seen | Whoever holds the key material |

The third row is the one that decides it. VTI-AUD-005 exists so that an erasure
removes personal data while the record stays verifiable. Deriving the audit key
from the master seed means the mnemonic is also an audit-key backup, so the
erasure is undone by whoever holds the recovery phrase — which, for a stack
whose recovery story *is* the mnemonic, is a wide set.

This makes a VTA's key source differ from a VTC's. That is a deliberate
difference rather than an inconsistency, and the reasoning above applies to a
VTC equally; moving it is a separate change, and its rotation machinery is the
path if the working group wants to.

**What this needs:** an `ensure_initial_random` beside `ensure_initial_with_info`
on the key store, and `audit_key` in the VTA's backed-up keyspaces.

## The first entry

There is no window before the key exists that needs auditing, because there is
nothing a VTA can do before its seed is loaded. It holds no keys, can sign
nothing, has no ACL to consult and no context to act in. The audit surface
begins where the seed does.

So **the first entry in the chain is the creation of the key that chains it.**
Written the moment the key exists, committing to its id, it is a genesis that
describes itself: a verifier reading the log from the start learns which key
the following entries are hashed under, from an entry hashed under that same
key.

The same shape covers rotation. A rotation is an audited event, and the natural
place for it is the first entry of the new key's era, so that each key's
segment of the chain opens with the record of why the key changed.

One class of event stays outside the chain: a failure to obtain the seed at
all. It cannot be chained, because the key that would chain it does not exist —
and this is the one moment where that is acceptable, since a node that cannot
load its seed is a node that is not serving. It belongs in the log stream,
which the `audit!` macro already writes to, and a reader should understand the
chained log as beginning at the first moment the node could act.

*Recorded from a review question: what would we even be auditing before the
seed is there?*

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
