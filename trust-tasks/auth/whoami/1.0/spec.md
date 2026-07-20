---
id: https://trusttasks.org/openvtc/vtc/auth/whoami/1.0
title: VTC — Inspect access-token claims
status: retired
supersededBy: https://trusttasks.org/spec/auth/whoami/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/auth/whoami
inputs:
  - Authenticated request (bearer JWT or `vtc_admin_session` cookie)
outputs:
  - HTTP 200 with `WhoamiResponse` JSON body — `did`, `role`,
    `session_id`, `access_expires_at` (Unix seconds), and
    `allowed_contexts` (possibly empty).
trust_assumptions:
  - The handler does not re-validate the JWT signature beyond the
    standard `AuthClaims` extractor — its job is to surface the
    claims already validated by the auth chain so a browser SPA
    can render a "Signed in as …" indicator without parsing the
    HttpOnly session cookie.
  - The response intentionally omits the JWT itself; the cookie
    keeps the token out of reach of JavaScript on purpose.
related:
  - https://trusttasks.org/openvtc/vtc/auth/admin-login/1.0
  - https://trusttasks.org/openvtc/vtc/auth/sign-out/1.0
---

# VTC — Inspect access-token claims

Phase 5 admin UX quality-of-life surface. The admin SPA fires this
at boot to learn who the cookie is bound to, what role they hold,
and which contexts they're allowed to touch. The shell can then:

- Render the navbar's "Signed in as …" indicator.
- Hide nav entries the caller's role wouldn't be allowed to use.
- Set up a near-expiry timer based on `access_expires_at` so the
  SPA can prompt the operator before the cookie silently expires.

No mutating behaviour — purely a read of the auth-chain output.
Programmatic clients can also call it but typically derive the
same information by decoding the bearer JWT directly.
