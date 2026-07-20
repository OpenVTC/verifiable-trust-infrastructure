---
id: https://trusttasks.org/openvtc/vtc/join-requests/approve/1.0
title: VTC Join Requests — Approve
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/join-requests/{id}/approve
---

# VTC Join Requests — Approve

Approves a `Pending` join request. Atomic write of:

1. `acl:<applicant_did>` with `role = Member`.
2. `members:<applicant_did>` row.
3. `JoinRequest.status = Approved`.

Audit envelopes emitted: `JoinRequestApproved`, `MemberAdded`.
The two events share the same admin actor + applicant target so
SIEM rules can correlate them via timestamp / target DID.

## Authentication

`AdminAuth`.

## Errors

- `404 Not Found` — request id unknown.
- `409 Conflict` — request is not in `Pending` status, **or**
  the applicant DID already has an ACL row (defence against a
  double-admit race).
