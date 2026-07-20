---
id: https://trusttasks.org/openvtc/vtc/members/promote-to-admin/1.0
title: VTC Members — Promote to Admin
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/members/{did}/promote-to-admin/start
  - rest: POST /v1/members/{did}/promote-to-admin/finish
---

# VTC Members — Promote to Admin

Two-phase ceremony that promotes an existing member to
`VtcRole::Admin`. Spec §10.4 keeps this path distinct from the
generic `PATCH /v1/members/{did}` so admin elevation is the
highest-privilege grant the community emits — SIEM rules target
the `AdminPromoted` audit variant specifically.

## Authentication

`AdminAuth` on both endpoints. The `finish` step adds a step-up
WebAuthn user-verification (UV) ceremony against the caller's
already-registered passkeys.

## /start

Mints a UV challenge against the caller's passkeys. Returns:

```
{ "registrationId": "<uuid>", "options": <PublicKeyCredentialRequestOptions> }
```

Pre-flight refusals (no UV ceremony issued):

- `400 Bad Request` — caller is the target DID.
- `404 Not Found` — target is not a current member.
- `409 Conflict` — target is already an admin.

## /finish

Verifies the UV response, then atomically:

1. Sets `acl:<target>.role = Admin`.
2. Creates `admin:<target>` sister record (empty passkey list —
   the new admin enrols devices via the existing passkey routes).
3. Emits `AdminPromoted` audit envelope with the authorising
   credential id.

Re-checks the "already-admin" invariant under
`PROMOTE_LOCK` so a concurrent PATCH cannot smuggle in an
out-of-band role mutation between start + finish.

## Errors

- `400 Bad Request` — self-promotion.
- `401 Unauthorized` — UV state expired / failed.
- `403 Forbidden` — caller has no enrolled passkey to perform UV.
- `404 Not Found` — target removed between start + finish.
- `409 Conflict` — target became admin between start + finish.
