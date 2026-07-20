---
id: https://trusttasks.org/openvtc/vtc/acl/legacy/manage/1.0
title: VTC Legacy — ACL Collection
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/acl
  - rest: POST /v1/acl
---

# VTC Legacy — ACL Collection

Placeholder Trust Task for the pre-MVP ACL collection endpoints
(list + create) inherited from the `vtc-service` skeleton. Two
HTTP methods share this task because they target the same
resource collection.

The shape of this Trust Task will be revised in M0.6+ when the
member-lifecycle endpoints land. The legacy ACL surface will
eventually be subsumed by `members/list/1.0` and the
provision-integration / passkey flows.
