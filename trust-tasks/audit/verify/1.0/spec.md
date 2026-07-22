---
id: https://trusttasks.org/openvtc/vtc/audit/verify/1.0
title: VTC — Verify the audit hash chain
status: retired
supersededBy: https://trusttasks.org/spec/audit/verify/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/audit/verify
inputs:
  - Authenticated request — caller MUST be super-admin
    (Admin role with empty `allowed_contexts`). No request body,
    no query parameters.
outputs:
  - >-
    HTTP 200 with a `VerifyResponse` body: `verified`,
    `entriesExamined`, `entriesVerified`, `legacySkipped`,
    `unparseableSkipped`, optional `head` (hex), and optional
    `chainBreak` (`{kind, index, eventId}`).
trust_assumptions:
  - >-
    A `verified: true` proves internal consistency of the chain,
    NOT authenticity. `chain_digest` is an unkeyed SHA-256, so an
    adversary with write access to the audit keyspace can forge a
    suffix and restamp every subsequent envelope, and a truncation
    to a valid prefix is indistinguishable from a quiet period.
    Treat this endpoint as detecting accident and careless tampering,
    not a determined adversary.
  - >-
    `legacySkipped > 0` is itself a finding on any store that should
    hold no pre-v2 rows. Verification skips those envelopes rather
    than checking them, so they are an insertion point.
  - >-
    The result reflects the store the daemon is reading. An adversary
    who can rewrite the store can also rewrite what this endpoint
    reads; an independent copy verified out-of-band is the stronger
    check.
related:
  - https://trusttasks.org/openvtc/vtc/audit/list/1.0
---

# VTC — Verify the audit hash chain

Every audit envelope from schema version 2 onward carries
`prevHash` (its predecessor's `entryHash`) and `entryHash` (a
SHA-256 commitment over its own immutable content). This endpoint
walks the whole audit keyspace in ascending — i.e. chronological —
key order and checks both properties for every envelope.

It detects:

- **Tampering** — an envelope whose content changed after writing,
  since `entryHash` no longer re-derives (`kind: "tamperedEntry"`).
- **Reorder, drop, or insertion** — an envelope whose `prevHash`
  does not point at its predecessor's `entryHash`
  (`kind: "brokenLink"`). Duplication is caught by the same check:
  a repeated envelope's `prevHash` cannot equal the preceding
  copy's own `entryHash`.

## What it does not detect

The chain is unsigned. An adversary with write access to the audit
keyspace holds no secret they need — `chain_digest` takes no key,
so they can recompute it for a forged suffix and restamp every
envelope after their edit, and the result verifies cleanly.
Truncating the log to any valid prefix is likewise undetectable.

Closing that gap requires periodically signing the chain head with
a key the store-level adversary does not hold. See
`docs/05-design-notes/vtc-audit-checkpoints.md`.

## Cost

The walk is O(n) over the audit keyspace and reads every row. The
verifier itself folds in constant memory (`ChainVerifier`), but the
keyspace scan currently materialises the row set, matching
`GET /v1/audit`. On a large log, prefer running this on a schedule
rather than per-request.

## Interpreting the counters

| Field | Meaning |
|---|---|
| `entriesExamined` | Rows walked, chainable or not |
| `entriesVerified` | v2+ rows that verified |
| `legacySkipped` | Pre-v2 rows skipped — non-zero is a finding |
| `unparseableSkipped` | Rows that would not deserialize — also a finding |

`entriesExamined` will exceed `entriesVerified` exactly when
`legacySkipped` or `unparseableSkipped` is non-zero. On a store
written entirely by a v2+ daemon they should be equal.
