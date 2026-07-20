---
id: https://trusttasks.org/openvtc/vtc/members/admin-remove/1.0
title: VTC Members — Admin Remove
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: DELETE /v1/members/{did}
---

# VTC Members — Admin Remove

Spec §10.2. An admin removes another member. Distinct path from
self-remove so `MemberRemoved` audit envelopes carry the
admin's DID as the actor and the target as the resource — SIEM
rules can tell self-departures and admin actions apart.

## Authentication

`AdminAuth`. The caller MUST NOT be the target — use
`DELETE /v1/members/me` for that. Phase 2 may grant
`Moderator` callers a policy-gated path; Phase 1 keeps the
gate on `Admin` only.

## Body

```text
{
  "disposition": ? "purge" | "tombstone" | "historical" | "policydefault",
  "reason":      ? string (≤ 1024 chars)
}
```

`reason` is operator-supplied and lands in the audit envelope.
May be empty.

## No-last-admin invariant

Refused with **409 `LastAdminProtected`** if the target is the
last `Admin` in the ACL. Promote another member to admin
before removing the current sole admin.

## Refusals

- `400 Bad Request` — caller is the target.
- `404 Not Found` — target has no ACL row.
- `409 Conflict` — last-admin invariant.

## Audit

`MemberRemoved { disposition, reason }` with the admin DID as
`actor` and the target DID as `resource`.
