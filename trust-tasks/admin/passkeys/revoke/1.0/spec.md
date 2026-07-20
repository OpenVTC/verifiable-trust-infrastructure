---
id: https://trusttasks.org/openvtc/vtc/admin/passkeys/revoke/1.0
title: VTC Admin — Revoke Passkey
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/admin/passkeys/revoke/start
  - rest: POST /v1/admin/passkeys/revoke/finish
---

# VTC Admin — Revoke Passkey

Two-phase ceremony that removes a registered WebAuthn passkey from
the caller's admin DID. Spec §4.3:

- **Reauth invariant** — fresh UV required in the same request.
- **Concurrency invariant** — refuses to leave zero passkeys; CAS-
  protected by an in-process mutex.

## Flow

- `POST /v1/admin/passkeys/revoke/start` accepts `{ credentialId }`,
  pins it under a fresh `revocationId`, returns `uvOptions`. Refuses
  with 404 if `credentialId` isn't currently registered.
- `POST /v1/admin/passkeys/revoke/finish` accepts `{ revocationId,
  uvResponse }`. Verifies UV, then under the
  `ADMIN_PASSKEY_LOCK` mutex re-reads the admin entry, asserts
  `passkeys.len() > 1`, removes the pinned credential, mirrors into
  the PasskeyUser + credential-mapping records, emits
  `AdminPasskeyRevoked`.

## Authentication

`AdminAuth` for both phases.

## Errors

- `401 Unauthorized` — missing session, UV fails, revocation_id
  unknown / consumed.
- `403 Forbidden` — caller is not Admin.
- `404 Not Found` — credential_id not registered.
- `409 Conflict` — `LastPasskeyProtected`: revoke would leave zero
  passkeys.
- `503 Service Unavailable` — WebAuthn or audit writer not
  configured.
