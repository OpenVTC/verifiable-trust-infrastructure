---
id: https://trusttasks.org/openvtc/vtc/audit/list/1.0
title: VTC — List audit log entries
status: retired
supersededBy: https://trusttasks.org/spec/audit/list/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/audit
inputs:
  - Authenticated request — caller MUST be super-admin
    (Admin role with empty `allowed_contexts`). Pagination via
    `?cursor=<opaque>&limit=<1..=200>` query parameters.
outputs:
  - >-
    HTTP 200 with a `Paginated<AuditEnvelope>` body: `items`,
    `next_cursor`, and an optional `total_estimate` (currently
    always omitted).
trust_assumptions:
  - Envelopes carry plaintext actor + target DIDs unless an RTBF
    override has redacted them. This is the same sensitivity tier
    as the underlying `audit` keyspace — gating on super-admin
    only is intentional (a context admin can manage their own
    context's ACL but should not see the community-wide audit
    tail).
  - The cursor is HMAC-signed under the active audit key. Cursor
    minted before a key rotation will fail to verify; SPAs should
    reset to first page on `InvalidCursor` rather than retry.
  - Order is newest-first. The cursor's opaque `last_key`
    references the **oldest** entry on the page just returned;
    the next page returns entries strictly older than that key.
related:
  - https://trusttasks.org/openvtc/vtc/auth/whoami/1.0
---

# VTC — List audit log entries

Phase 5 admin UX surface. The admin SPA's "Audit" plugin uses
this endpoint to render a "what just happened" tail for the
operator: every audit envelope written by the daemon, newest
first, with paging via the standard signed cursor.

## Why super-admin only

Audit envelopes are the wire form of the daemon's tamper-evident
operations log. They include:

- Plaintext actor + target DIDs (the HMAC hash stays even after
  RTBF redaction, but a fresh envelope carries the plaintext).
- Full event payload — for `MemberRemoved` that includes the
  disposition; for `RegistrySyncFailed` that includes the error
  message; etc.

A context admin scoping their view to one community-internal
context shouldn't be able to enumerate cross-context activity.
The audit log is the daemon's god view, not a per-context tail.
Wiring a per-context filtered surface would mean adding a
`context_id` field to every envelope variant, which is a Phase-6
direction, not a Phase 5 one.

## Pagination semantics

Page size defaults to 50, max 200 (the workspace-wide
`MAX_LIMIT`). The `next_cursor` field is present iff more
entries remain. Operators reading the audit tail typically only
scroll the most-recent 100 or so before drilling into a specific
event — heavier consumers should pull the audit keyspace
directly (offline backup tooling, M0.10).
