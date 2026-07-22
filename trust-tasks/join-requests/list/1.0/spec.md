---
id: https://trusttasks.org/openvtc/vtc/join-requests/list/1.0
title: VTC Join Requests — List
status: retired
supersededBy: https://trusttasks.org/spec/vtc/join-requests/list/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/join-requests
---

# VTC Join Requests — List

Paginated list of join requests. Default status filter is
`pending`.

## Authentication

`AdminAuth`.

## Query parameters

- `status` (optional, default `pending`) — `pending` /
  `approved` / `rejected` / `withdrawn` / `deferred`.
- `cursor` / `limit` — standard pagination.
