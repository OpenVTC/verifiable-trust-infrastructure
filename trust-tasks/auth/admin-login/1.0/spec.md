---
id: https://trusttasks.org/openvtc/vtc/auth/admin-login/1.0
title: VTC — Admin SPA cookie session mint
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/auth/admin-login
inputs:
  - DIDComm-packed authenticate message (same shape as
    `auth/legacy/authenticate/1.0`)
outputs:
  - HTTP 200 with `AuthenticateResponse` JSON body
  - "`Set-Cookie: vtc_admin_session=<jwt>; Path=/admin; SameSite=Strict; Secure; HttpOnly`"
  - "`Set-Cookie: csrf=<random-32-byte-hex>; Path=/; SameSite=Strict; Secure`"
trust_assumptions:
  - The DIDComm authenticate message carries the same signed
    challenge required by `auth/legacy/authenticate/1.0`. The
    cookie-session flow is **identical** at the credential layer
    — it just delivers the JWT via a cookie scope appropriate
    for browser-based SPA usage.
  - Cookie `Path=/admin` constrains the session to the admin UX
    surface; public-website JS on the same origin cannot read it.
  - Companion CSRF cookie is JS-readable so the SPA can echo its
    value into an `X-CSRF-Token` header for the double-submit
    check in `routing::csrf`.
related:
  - https://trusttasks.org/openvtc/vtc/auth/legacy/authenticate/1.0
  - https://trusttasks.org/openvtc/vtc/auth/legacy/challenge/1.0
---

# VTC — Admin SPA cookie session mint

Phase 5 M5.2.3. Companion to the existing DIDComm authenticate
flow (`auth/legacy/authenticate/1.0`). Same wire shape, same
session/JWT machinery — the only difference is the response
side-effect: this endpoint additionally returns `Set-Cookie`
headers carrying the access-token JWT and a CSRF double-submit
token.

The admin SPA built by `vtc-admin-ui` (Phase 5 M5.6+) calls this
endpoint at admin login. Subsequent SPA requests carry:

- The session cookie automatically (browser attaches it on
  same-origin fetches under `/admin/*` — the cookie's `Path`
  scope ensures public-website JS cannot read or send it).
- The CSRF cookie's value mirrored into an `X-CSRF-Token`
  header on every mutating request.

Programmatic clients (cnm-cli, DIDComm bridges) keep using
`POST /v1/auth/` for the bearer-JWT flow. No cookie side effects
there.

## Why a separate Trust Task

The cookie side-effect is the only deliberate observable
difference from `auth/legacy/authenticate/1.0`. Operators
choosing between the two flows need to know which side effects
they're opting into; separating the Trust Task IDs makes that
choice explicit at the SIEM and audit-tail layers (filters on
`Trust-Task` value distinguish bearer vs cookie session mints).
