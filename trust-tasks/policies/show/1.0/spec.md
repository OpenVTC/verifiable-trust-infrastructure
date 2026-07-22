---
id: https://trusttasks.org/openvtc/vtc/policies/show/1.0
title: VTC Policies — Show
status: retired
supersededBy: https://trusttasks.org/spec/policy/get/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/policies/{id}
---

# VTC Policies — Show

Returns the full Policy row including Rego source and an
`isActive` flag against the current `active_policies:<purpose>`
pointer. Spec §7.1.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Request

```
GET /v1/policies/{id}
```

`{id}` is the UUID returned by `POST /v1/policies`.

## Response (`200 OK`)

```
{
  "id": "1a2b…",
  "purpose": "join",
  "regoSource": "package vtc.join\nimport rego.v1\n…",
  "sha256": "abcd…",
  "activatedAt": "2026-03-21T18:42:00Z" | null,
  "authorDid": "did:key:zAdmin",
  "createdAt": "2026-03-21T18:40:00Z",
  "version": 4,
  "isActive": true
}
```

`isActive` is `true` iff `active_policies:<purpose>` points at
this id at request time.

## Errors

- `401 Unauthorized` — missing / invalid session token.
- `403 Forbidden` — caller is not Admin.
- `404 Not Found` — no policy with this id.
