---
id: https://trusttasks.org/openvtc/vtc/acl/legacy/entry/1.0
title: VTC Legacy — ACL Entry
status: retired
supersededBy: https://trusttasks.org/spec/acl/show/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/acl/{did}
  - rest: PATCH /v1/acl/{did}
  - rest: DELETE /v1/acl/{did}
---

# VTC Legacy — ACL Entry

Placeholder Trust Task for the pre-MVP per-entry ACL endpoints
(show + update + delete) inherited from the `vtc-service`
skeleton. Three HTTP methods share this task because they target
the same resource.

The shape of this Trust Task will be revised in M0.6+ when the
member-lifecycle endpoints land. The legacy per-DID ACL surface
will eventually be subsumed by `members/show/1.0` /
`members/role/update/1.0` / `members/remove-admin/1.0` /
`members/remove-self/1.0` per spec §16.4.
