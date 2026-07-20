---
id: https://trusttasks.org/openvtc/vtc/auth/sign-out/1.0
title: VTC — Revoke session and clear browser cookies
status: retired
supersededBy: https://trusttasks.org/spec/auth/revoke-session/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/auth/sign-out
inputs:
  - Authenticated request (bearer JWT or `vtc_admin_session` cookie)
outputs:
  - HTTP 204 (No Content)
  - "`Set-Cookie: vtc_admin_session=; Path=/; Max-Age=0; SameSite=Strict; Secure; HttpOnly`"
  - "`Set-Cookie: csrf=; Path=/; Max-Age=0; SameSite=Strict; Secure`"
trust_assumptions:
  - >-
    Sign-out is **best effort** server-side: the session row may
    already have been deleted from another tab or expired, and
    that's fine. The cookie expiry header is the user-visible
    side effect — once the browser drops it, the SPA can no
    longer authenticate with this server.
  - >-
    JavaScript on the SPA can't clear the HttpOnly session
    cookie itself; only the server's `Set-Cookie: Max-Age=0`
    response can. This endpoint exists for exactly that reason.
  - Idempotent — repeated POSTs against an already-revoked
    session still return 204 with cookie-clear headers.
related:
  - https://trusttasks.org/openvtc/vtc/auth/whoami/1.0
  - https://trusttasks.org/openvtc/vtc/auth/admin-login/1.0
  - https://trusttasks.org/openvtc/vtc/auth/legacy/sessions/revoke/1.0
---

# VTC — Revoke session and clear browser cookies

Phase 5 admin UX surface. Bound to the admin SPA's "Sign out"
control. Two effects in one round-trip:

1. **Server side:** revoke the caller's session row so any
   replay of the JWT (e.g. from another open tab) is rejected
   by the auth extractor — `session not found` / `session not
   authenticated`. This stops the cookie working even before
   the JWT exp.

2. **Browser side:** clear the `vtc_admin_session` and `csrf`
   cookies by re-issuing them with `Max-Age=0`. Without this
   the browser would keep sending the stale JWT until it
   expired naturally (15 minutes by default).

Programmatic bearer-JWT clients (cnm-cli, DIDComm bridges) can
call this too. They get the same server-side session revocation;
the Set-Cookie headers are simply ignored.
