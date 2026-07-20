---
id: https://trusttasks.org/openvtc/vtc/auth/legacy/sessions/manage/1.0
title: VTC Legacy — Sessions Management
status: retired
supersededBy: https://trusttasks.org/spec/auth/sessions/list/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/auth/sessions
  - rest: DELETE /v1/auth/sessions
---

# VTC Legacy — Sessions Management

Placeholder Trust Task for the pre-MVP collection-level sessions
endpoints (list + bulk revoke-by-DID) inherited from the
`vtc-service` skeleton. Two HTTP methods share this task because
they target the same resource collection.

The shape of this Trust Task will be revised in Phase 1+ when the
auth surface gets re-aligned with the new install + passkey flows.
At that point, GET and DELETE will likely split into separate
Trust Tasks.
