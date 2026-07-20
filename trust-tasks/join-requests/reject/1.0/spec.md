---
id: https://trusttasks.org/openvtc/vtc/join-requests/reject/1.0
title: VTC Join Requests — Reject
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/join-requests/{id}/reject
---

# VTC Join Requests — Reject

Rejects a `Pending` join request. The body may carry an optional
`reason` (capped at 1024 chars). No ACL or Member rows written.

Audit envelope: `JoinRequestRejected { requestId, reason }`.

The row stays in the keyspace until the retention sweeper purges
it (default 30 days, configurable via
`config.join_requests.retention_days`).

## Authentication

`AdminAuth`.

## Errors

- `400 Bad Request` — `reason` exceeds 1024 chars.
- `404 Not Found` — request id unknown.
- `409 Conflict` — request is not in `Pending` status.
