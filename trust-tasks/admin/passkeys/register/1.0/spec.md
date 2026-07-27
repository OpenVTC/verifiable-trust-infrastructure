---
id: https://trusttasks.org/openvtc/vtc/admin/passkeys/register/1.0
title: VTC Admin — Register Passkey
status: retired
supersededBy: https://trusttasks.org/spec/auth/passkey/enroll/start/0.2
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/admin/passkeys/register/start
  - rest: POST /v1/admin/passkeys/register/finish
---

# VTC Admin — Register Passkey

> **Retired.** Folded onto the canonical `auth/passkey/*` tasks
> (trust-tasks-tf#145); each ceremony leg now carries its own task,
> where this one covered a whole family:
>
>   - `POST /v1/admin/passkeys/register/start` -> `https://trusttasks.org/spec/auth/passkey/enroll/start/0.2`
>   - `POST /v1/admin/passkeys/register/finish` -> `https://trusttasks.org/spec/auth/passkey/enroll/finish/0.2`
>
> No wire change — the canonical specs were written from this
> implementation. Only the task URIs moved.

Two-phase ceremony that enrols an additional WebAuthn passkey on
the caller's admin DID. The spec (§4.3) requires a **fresh
WebAuthn user-verification** in the same request — a stolen session
must not be able to bind a new authenticator. This implementation
combines two ceremonies:

1. **Step-up UV** — a `navigator.credentials.get()` assertion
   against an *existing* passkey, signed by the operator's current
   authenticator. Proves the current operator is physically present.
2. **New device registration** — a `navigator.credentials.create()`
   assertion that mints the new credential.

## Flow

- `POST /v1/admin/passkeys/register/start` returns `registrationId`,
  `registerOptions` (EdDSA-restricted creation challenge), and
  `uvOptions` (authentication challenge against existing passkeys).
- `POST /v1/admin/passkeys/register/finish` accepts both responses
  plus operator label + transports. Verifies UV first (a failed UV
  leaves the new-device registration state intact for retry).
  Persists the new passkey, mirrors into the `AdminEntry` sister
  record, emits `AdminPasskeyRegistered`.

## Authentication

`AdminAuth` for both phases.

## Errors

- `401 Unauthorized` — missing session, UV assertion fails,
  registration_id unknown / consumed.
- `403 Forbidden` — caller is not Admin.
- `404 Not Found` — caller has no existing passkey user record.
- `503 Service Unavailable` — WebAuthn or audit writer not
  configured.
