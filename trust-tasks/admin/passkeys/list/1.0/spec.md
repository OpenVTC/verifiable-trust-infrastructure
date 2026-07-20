---
id: https://trusttasks.org/openvtc/vtc/admin/passkeys/list/1.0
title: VTC Admin — List Passkeys
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/admin/passkeys
---

# VTC Admin — List Passkeys

Returns every passkey registered to the caller (admin) DID. Read-
only — no step-up UV required (a stolen session leaks the
operator-friendly metadata but cannot bind a new authenticator).

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Errors

- `401 Unauthorized` — missing / invalid session token.
- `403 Forbidden` — caller is not Admin.
- `404 Not Found` — caller has no `admin:<did>` record (shouldn't
  happen post-bootstrap).
