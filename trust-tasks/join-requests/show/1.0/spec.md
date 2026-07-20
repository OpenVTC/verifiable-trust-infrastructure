---
id: https://trusttasks.org/openvtc/vtc/join-requests/show/1.0
title: VTC Join Requests — Show
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/join-requests/{id}
---

# VTC Join Requests — Show

Returns the full `JoinRequest` including the opaque VP.

## Authentication

`AdminAuth`.

## Errors

- `404 Not Found` — unknown id.
