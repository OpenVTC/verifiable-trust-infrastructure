---
id: https://trusttasks.org/openvtc/vtc/members/renew/1.0
title: VTC Members — Renew
status: retired
supersededBy: https://trusttasks.org/spec/vtc/members/renew/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/members/me/renew
---

# VTC Members — Renew

Re-mints the caller's VMC + role VEC. Spec §6.3.

## Authentication

Bearer-token JWT for the member. No expiry or grace-window
check on the caller's session is added beyond the standard
session validation — the spec calls renewal "unconditional on
ACL membership", and an expired session is a different issue.

## Side-effects

1. Verifies the caller has an active ACL row (404 if not a
   member).
2. Re-evaluates `personhood.rego` (spec §6.3 step 3). Phase 2
   ships the deny-all stub so the new VMC's `personhood` flag
   is always `false`.
3. Re-uses the same status-list slot the member was allocated
   at join time. A member without a slot (a grandfathered
   pre-M2.12 row) gets a fresh allocation as a one-time
   reconcile.
4. Mints a fresh VMC + role VEC (`validFrom = now`,
   `validUntil = now + community.membership.validity`).
5. Updates `Member.current_vmc_id` + `current_role_vec_id`
   to the new ids.
6. Emits `MembershipRenewed` audit envelope with
   `personhood_changed` set when the new flag differs from
   the prior VMC's.

## Response (`200 OK`)

```
{
  "did": "did:key:zMember",
  "vmc": { ... signed VC ... },
  "roleVec": { ... signed VC ... },
  "personhood": false,
  "personhoodChanged": false
}
```

## Errors

- `401 Unauthorized` — missing / invalid session token.
- `404 Not Found` — caller has no ACL or Member row.
- `500 Internal Server Error` — credential signer unavailable,
  status list not provisioned, etc.

## Idempotency

Phase 2 plan §D6 classifies renewal as non-destructive: the
ACL row is unchanged, only fresh VC ids are minted. Repeated
renewal calls within a 24h window are safe; the workspace's
idempotency cache lands separately as part of the M0.1.3
plumbing.
