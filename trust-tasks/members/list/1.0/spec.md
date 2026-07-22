---
id: https://trusttasks.org/openvtc/vtc/members/list/1.0
title: VTC Members — List
status: retired
supersededBy: https://trusttasks.org/spec/vtc/members/list/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/members
---

# VTC Members — List

Returns a paginated list of community members. The response joins
each `members:<did>` row with its `acl:<did>` ACL entry so callers
get the role + label inline.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`. Phase 1 has no
privacy gating beyond the admin role; spec §12.3 PMF lands in
Phase 2+.

## Query parameters

- `role` (optional) — filter by VtcRole wire form (e.g.
  `"admin"`, `"moderator"`, `"custom:editor"`).
- `cursor` (optional) — pagination cursor from a prior page.
- `limit` (optional) — page size; clamped to `1..=200`. Default
  50.

## Errors

- `401 Unauthorized` — missing / invalid session token.
- `403 Forbidden` — caller is not Admin.
- `500 Internal Server Error` — audit writer / cursor signing
  unavailable (the daemon hasn't completed `init_auth`).
