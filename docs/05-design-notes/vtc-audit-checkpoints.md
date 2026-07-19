# Signed audit checkpoints

**Status:** proposed — not implemented.
**Context:** issue #537 tier 3. The `prev_hash` chain shipped in #555;
`GET /v1/audit/verify` (this PR) exposes it. This note covers what is
still missing and why it matters.

## The problem the chain does not solve

Each audit envelope carries `prev_hash` (its predecessor's
`entry_hash`) and `entry_hash` (a SHA-256 over its own immutable
content). `verify_chain` walks the log and checks both. That detects
reordering, dropping, duplication, and content edits.

It does not detect a competent adversary, because **`chain_digest` is
unkeyed**. From `vti-common/src/audit/envelope.rs`:

```rust
pub fn chain_digest(&self) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHAIN_DOMAIN);
    h.update(self.prev_hash);
    // ... no key material anywhere ...
}
```

An attacker who can write to the `audit` keyspace holds everything
needed to recompute it. Two attacks follow directly:

1. **Restamping.** Edit or insert an envelope, recompute its
   `entry_hash`, then walk forward restamping every subsequent
   envelope's `prev_hash`/`entry_hash`. The result verifies cleanly.
   Cost is O(entries after the edit) and needs no secret.
2. **Truncation.** Delete every envelope after some point. The
   remaining prefix is a valid chain. Nothing records how long the log
   *should* be, so a truncated log is indistinguishable from a
   community that went quiet.

Truncation is the more serious one: it is the cheapest way to erase an
incident, and it requires no forgery at all.

The HMAC over actor/target DIDs does not help here. It protects
attribution (and enables RTBF via key rotation), not sequence
integrity — and the writer holds that key anyway.

## Proposal

Periodically persist a **checkpoint**: the chain head at a point in
time, signed by a key the store-level adversary does not hold.

```rust
struct AuditCheckpoint {
    /// entry_hash of the newest envelope at checkpoint time.
    head: [u8; 32],
    /// Total chainable envelopes written up to `head`. This is what
    /// makes truncation detectable — a shorter log contradicts it.
    entry_count: u64,
    /// event_id of the envelope at `head`, so a verifier can locate
    /// the anchor point without recomputing the whole chain.
    head_event_id: Uuid,
    checkpoint_at: DateTime<Utc>,
    /// Previous checkpoint's own hash — checkpoints chain too, so
    /// deleting one is itself detectable.
    prev_checkpoint: Option<[u8; 32]>,
    /// Ed25519 signature by the community signing key over a
    /// domain-tagged encoding of every field above.
    signature: Vec<u8>,
}
```

Stored in a dedicated `audit_checkpoint` keyspace keyed by
`<rfc3339>:<uuid>`, matching the audit keyspace's convention.

### Signer: the community Ed25519 key

Two candidates were considered.

| | Audit HMAC key | Community Ed25519 key |
|---|---|---|
| New key handling | none — reuses `audit_key` | reuses `LocalSigner` |
| Verifiable by | the daemon only | anyone with the community DID |
| Forgeable by store-adversary | **yes** — key is in the same store | no |

The audit HMAC key is rejected: it lives in the same store the
adversary is assumed to have reached, and symmetric verification means
whoever can check a checkpoint can also forge one. That reduces to the
status quo.

**Decision: sign with the community Ed25519 signing key** — the same
`LocalSigner` that issues VMCs and VECs. It gives externally-verifiable
checkpoints: an auditor holding only the community's DID can confirm
the log has not been truncated or rewritten, with no shared secret and
no access to the daemon. That is the property worth having, and it
matches the workspace's existing preference for VC/VP-shaped,
independently-verifiable claims over bespoke internal assertions.

Consequence to accept: checkpoint verification depends on the community
DID resolving, and on key rotation being handled (a checkpoint signed
under a retired key must stay verifiable — the DID document history
already provides this for `did:webvh`).

### Verification

`verify_chain` gains a checkpoint-aware mode:

1. Load checkpoints, verify each signature, verify the checkpoint chain.
2. For the newest checkpoint, confirm the audit log still contains an
   envelope with `head_event_id` whose `entry_hash` equals `head`.
3. Confirm the log's chainable count is **>=** `entry_count`. Fewer
   means truncation — the finding this whole mechanism exists for.
4. Verify the envelope chain as today.

Step 3 is the one that cannot be spoofed without the signing key.

## Open questions

- **Cadence.** Time-based (hourly), count-based (every N envelopes), or
  both? Both, probably: a low-traffic community should still checkpoint
  daily so a truncation window stays bounded, and a busy one should not
  wait an hour. The window between checkpoints is the attacker's free
  truncation range, so it directly sets the residual risk.
- **External anchoring.** Checkpoints protect against a store-level
  adversary but not one who also holds the signing key. Publishing the
  head somewhere append-only (the community's own `did.jsonl`, a
  transparency log, a peer VTC) would close that. Out of scope here;
  the signature is the prerequisite.
- **Backup interaction.** `vtc-service/src/backup.rs` backs up the
  `audit` keyspace. Checkpoints must be included, or a restore looks
  like mass truncation.
- **Chain head durability.** `load_chain_head` currently recovers the
  head by scanning the whole keyspace and taking the last row — O(n) at
  first write after restart, and it re-derives trust from the same
  store an adversary may control. A checkpoint keyspace gives a cheap
  persisted head pointer as a side effect.

## Prerequisite already handled

Pre-v2 envelopes are skipped by `verify_chain` (`schema_version < 2`),
which makes them an insertion point: a forged row marked
`schemaVersion: 1` passes untouched. `GET /v1/audit/verify` reports
`legacySkipped` so this is at least visible. Before checkpoints are
worth much, confirm deployed stores hold no v1 rows — otherwise a
signed checkpoint attests to a chain with holes in it.
