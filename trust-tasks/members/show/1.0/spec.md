---
id: https://trusttasks.org/openvtc/vtc/members/show/1.0
title: VTC Members — Show
status: retired
supersededBy: https://trusttasks.org/spec/vtc/members/show/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/members/{did}
---

# VTC Members — Show

Returns one member record joined with its ACL row. Spec §5.2.

## Authentication

`AdminAuth`.

## Errors

- `401 Unauthorized` — missing / invalid session.
- `403 Forbidden` — caller is not Admin.
- `404 Not Found` — member or matching ACL row absent.
