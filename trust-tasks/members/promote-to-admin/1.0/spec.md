---
id: https://trusttasks.org/openvtc/vtc/members/promote-to-admin/1.0
title: VTC Members — Promote to Admin (retired)
status: retired
version: "1.0"
supersededBy: https://trusttasks.org/spec/vtc/members/update/0.1
authors:
  - did:webvh:openvtc.org
applies_to: []
---

# VTC Members — Promote to Admin (retired)

**Retired.** `POST /v1/members/{did}/promote-to-admin/{start,finish}` no
longer exists. Admin promotion is
[`spec/vtc/members/update/0.1`](https://trusttasks.org/spec/vtc/members/update/0.1)
— `PATCH /v1/members/{did}` with `{"role": "admin"}` — on a session carrying a
live step-up elevation.

## Why it was retired

This task fused two things that are separately meaningful: a WebAuthn
user-verification *ceremony* and a role-change *operation*. That gave one URI
two tasks' worth of semantics, and put a second implementation of passkey UV
alongside `auth/passkey/login`. It also meant the proof of user presence could
authorise exactly one operation and nothing else.

Splitting them makes the elevation a first-class, reusable property of the
session:

1. **Step up** — `auth/passkey/login/{start,finish}/0.2` with
   `purpose: stepUp`. Verifies the caller's own passkey with UV and stamps a
   bounded elevation window on their session.
2. **Promote** — `spec/vtc/members/update/0.1` with `{"role": "admin"}`, which
   requires that window to still be open.

## What carried over

Every security property of the fused ceremony:

| Property | Where it lives now |
|---|---|
| User verification required | the step-up ceremony (`purpose: stepUp`) |
| UV is the caller's *own* passkey | step-up binds the ceremony to the session and re-checks the subject |
| Self-promotion refused | `PATCH /v1/members/{did}` |
| Serialised against concurrent role writes | `PROMOTE_LOCK` in the PATCH handler |
| Already-admin re-check under the lock | same — raised as `409` on the race |
| Governed by `role_change.rego` | `role_change_via_pipeline(step_up = true)` (P0.14) |
| Admin sister record created | the PATCH handler |
| `AdminPromoted` audit variant | the PATCH handler |

## What changed

- **The authorising credential id** moved off `AdminPromoted` and onto its own
  `AuthSteppedUp` audit row, emitted by the step-up ceremony. `AdminPromoted`
  now carries `authorisingSessionId`, which joins the two. Archived envelopes
  from before the fold still deserialise.
- **Promoting an existing admin is a `200` no-op**, not a `409`. `PATCH` is
  declarative — the role *should be* admin, and it already is — so a retried
  request is safe. The `409` still guards the concurrent-promotion race.
