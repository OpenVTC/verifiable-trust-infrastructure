# VTA audit chaining and actor hashing

**Status:** implemented, with bounded TEE storage recovery and paged readers.
Nothing in it changes what an operator sees; an earlier revision said otherwise
and was wrong, which the section on the operator surface records.

**Closes:** VTI-AUD-004 (the audit trail is tamper-evident) and VTI-AUD-005 (an
audit record refers to personal data rather than embedding it) of the
[VTI specification](https://trustoverip.github.io/dtgwg-vti-spec/), both
recorded against this workspace in the specification's divergence register
(Appendix F).

## Where we are

The VTC and the chained VTA audit sink use the same stored-envelope machinery.
The VTA keeps the older flat rows readable while new rows are chained:

| Module | What it provides |
|---|---|
| `vti_common::audit::envelope` | the stored envelope with `prev_hash` / `entry_hash` / `schema_version`, `GENESIS_HASH`, and `verify_chain` |
| `vti_common::audit::writer` | `AuditWriter` — a process-wide chain head guarded by an async mutex, so read-head → stamp → insert → update-head is atomic; the head is `Unknown` / `Known` / `Failed`, so a recovery that fails is reported and backed off rather than retried per write (stage 5); HMAC-hashes actor and target under the active audit key |
| `vti_common::audit::key_store` | `AuditKeyStore` initial random key, key history, rotation, and `verify_actor` — "does this DID match this hash?" |
| `vti_common::audit::checkpoint` | anchors a point in the chain so verification survives retention |

`vta-audit/src/sink.rs` now writes chained envelopes through `AuditWriter`.
The VTA's `log:` prefix keeps pre-chain and chained rows in the same ordered
keyspace, while `prune:watermark` remains outside that prefix.

## The trap

Two types are called `AuditEnvelope`, and the wrong one is the one you reach
for first:

- `vta_sdk::protocols::audit_management::list::AuditEnvelope` — the canonical
  **wire** form the VTA renders on read. It has no hash members, and its doc
  comment explains that they are absent *because this log is flat*.
- `vti_common::audit::envelope::AuditEnvelope` — the **stored** form, with the
  hashes.

The stored form is used for chaining and verification; the wire form remains
the operator-facing representation.

## Stages

**1 — Provision.** The VTA creates an `audit_key` keyspace and establishes a
random initial audit key lazily when the chained sink opens. Key history is
retained for actor verification and rotation.

**2 — Write.** `ChainedKeyspaceAuditSink` writes through `AuditWriter`. VTA
envelopes use `log:<seconds>:<nanos>:<uuid>` keys; pre-chain rows use
`log:<seconds>:<uuid>`. The shared `log:` prefix preserves both formats for
recovery and reads.

**3 — Read.** `audit/list` and `cleanup_expired_logs` read both forms. The
wire reader accepts flat legacy rows and stored envelopes; verification counts
legacy rows before the chain opens and reports non-envelope rows after it as
findings. Existing rows therefore remain readable and the chain starts from
the first new envelope.

Listing pages newest-first and stops as soon as it holds a full page **plus**
one further match, so `truncated` means "more *matching* entries remain" and
never "more rows remain" — a cursor whose next page turns out empty reads as
results being withheld. The cost of that guarantee is accepted, not overlooked:
a filter the log cannot satisfy `limit + 1` times is answered by reading every
remaining row, because "there is nothing further" is a claim about everything
the call does not return. It applies to successful queries too — a filter
matching three rows returns three entries and still scans to the end to
establish the rest of that answer — and it is worst for the most selective
filters. An unfiltered list exits after one page.

A row budget would bound the work but would have to report `truncated: true`
at its cut-off without knowing whether anything further matches, which is the
behaviour the ordering above exists to prevent. The two cannot both be had, so
the scan stays unbounded and the guarantee stays strict; revisit the pair
together or not at all. Each *page*, by contrast, is bounded on every backend:
both readers walk through `KeyspaceHandle::scan_pager`, which reads the range
once per walk rather than once per page on a proxy with no native bounded scan.

**4 — Verify.** `audit/verify/0.1` and the CLI verification path stream the
ordered log through `KeyspaceHandle::scan_pager` into `ChainVerifier`. They
still verify the complete retained log; paging only bounds each storage read.

**5 — Chain-head recovery.** On the first write after a restart, `AuditWriter`
re-reads the head of its chain from storage. The read is bounded because in a
TEE the whole result has to cross vsock in one frame: reading the newest row of
a 19 MB log must not mean shipping 19 MB.

The fast path is a reverse scan of the newest `HEAD_LOOKBACK` (20) rows under
the writer's own key prefix — `log:` on a VTA, which is what keeps
`prune:watermark` from being read as the newest audit row; the VTC keeps the
empty default. The newest row that deserializes as an envelope is the head, and
deserialization rather than the key is the test, because the key format belongs
to the caller. That window is all a prefix which has ever anchored a chain
needs: the anchoring envelope is permanent, so it sits inside every later
restart's window.

Fewer rows than the window, none an envelope, means there is nothing older to
find — the prefix is empty or entirely pre-chain, and the first chained write
anchors at `GENESIS_HASH`.

A *full* window of non-envelope rows is the ambiguous case, and both obvious
answers are wrong. Anchoring at genesis would fork the chain if an envelope
sits just below the window. Failing closed would brick the prefix permanently,
because no write can then succeed to clear the condition. So recovery pages
further back — `DEEP_SCAN_PAGE` (500) rows per request, still one bounded read
at a time — until an envelope turns up, or a short page proves the prefix holds
nothing older. There is no cap on the rows walked in total: stopping early is
one of the two wrong answers again, and a pre-chain log larger than any fixed
cap is ordinary (one row per audited operation over the retention window), so a
cap would turn an upgrade into every audit write failing closed. This deep scan
belongs to the one-time legacy-to-chained migration window and runs at most
once: the first envelope written anchors the chain for good, and every later
restart resolves the question again in the fast path.

Recovery fails only when a read fails — storage unreachable, a response too
large for one frame, a value that would not decrypt. A failed recovery is
reported once at `ERROR` and counted once in
`audit_chain_recovery_failures_total`; every audit write to that prefix is
failing closed meanwhile, and nothing else makes that visible from outside the
log. For the next 60 seconds
writes are refused without touching storage or repeating the log; after it, one
recovery is retried.

**6 — TEE compatibility.** Scan joins the capability negotiation PR#2003 built
for the atomic ops (`take` / `insert-if-absent` / `swap-if-absent` /
`move-if-equal`): at connect the enclave sends one `OP_HELLO` and caches the
bitmask the proxy returns (`CAP_SCAN`, bit 5, alongside the atomic-op and
batch bits), so recovery's bounded reads add no extra round trip on a proxy that
serves them. An old proxy answers `OP_HELLO`'s probe itself with "unknown
opcode" (read as "none", not an error), and recovery falls back to one legacy
`prefix_iter_raw` request, filtered and bounded client-side to the same
`ScanOpts`; if that unbounded response exceeds 16 MiB, it is not retried and
the caller gets a proxy-upgrade error instead. A proxy downgraded mid-session
is caught the same way the atomic ops catch it — an "unknown opcode" on a call
the enclave believed was supported clears the cached bit and schedules a
re-probe 60 seconds out — so a brief swap back to an older build costs one
fallback read, not a restart.

That fallback is per *request*, which is fine for recovery (one or two reads)
and wrong for anything paging: a reader looping on `scan_raw` would ask an old
proxy for the whole prefix again on every page, so a walk of `n` pages would
transfer and decrypt the range `n` times. The paged readers therefore go
through `KeyspaceHandle::scan_pager`, which decides once per walk — one bounded
read per page where the proxy serves them, otherwise one bulk read whose
remainder is served from memory. It re-checks per page, so a proxy downgraded
mid-walk buffers the rest rather than reverting to a full read each time.

Both sides compute the same range, and they are separate implementations in
separate cargo workspaces — the enclave's `vti_common::store::scan_bounds` and
the parent's `enclave_proxy::storage::scan_bounds`. A caller must get the same
rows whichever serves the scan, so the two are pinned to one table of
conformance vectors (`vti-common/src/store/scan_range_vectors.json`), which
each side runs through its own production path. A change to either needs the
same change to the other, and a new edge case needs a new vector.

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

The VTA establishes its audit key with `ensure_initial_random` when the
chained sink opens. It stores the key and its history in `audit_key`, which is
included in the VTA backup set. The VTC uses its own key-source path; the
shared writer does not require the VTA key to be seed-derived.

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

The random-key choice is deliberate: the audit key is a stable, rotatable HMAC
handle, not a derivation input. Losing both the key store and its backup still
loses the ability to recompute actor hashes, so preserving `audit_key` remains
part of the VTA backup requirement.

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

The VTA retention sweep records `prune:watermark` in the `audit` keyspace. It
contains the hash of the newest chained row removed and the cumulative number
of pruned entries. `audit/verify` resumes `ChainVerifier` from that watermark,
so an honest retention sweep does not look like tampering. The watermark is
stored alongside the log and is therefore not an external trust anchor: an
attacker who can rewrite the store can rewrite it too. It is specifically a
retention continuity marker, not protection against a compromised store.

The watermark is outside the `log:` prefix so the retention sweep does not
delete it and chain-head recovery does not mistake it for an audit envelope.
