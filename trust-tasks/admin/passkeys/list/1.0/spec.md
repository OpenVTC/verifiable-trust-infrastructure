---
id: https://trusttasks.org/openvtc/vtc/admin/passkeys/list/1.0
title: VTC Admin — List Passkeys
status: retired
supersededBy: https://trusttasks.org/spec/auth/passkey/list/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/admin/passkeys
---

# VTC Admin — List Passkeys

> **Retired.** Folded onto the canonical `auth/passkey/*` tasks
> (trust-tasks-tf#145); each ceremony leg now carries its own task,
> where this one covered a whole family:
>
>   - `GET /v1/admin/passkeys` -> `https://trusttasks.org/spec/auth/passkey/list/0.1`
>
> No wire change — the canonical specs were written from this
> implementation. Only the task URIs moved.

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
