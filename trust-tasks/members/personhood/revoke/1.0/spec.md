---
id: https://trusttasks.org/openvtc/vtc/members/personhood/revoke/1.0
title: VTC — Personhood Revoke
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: DELETE /v1/members/{did}/personhood
---

# VTC — Personhood Revoke

Flips a member's `personhood` flag to `false`. Phase 4 M4.4;
spec §6.3.

## Semantics

- **Auth**: Admin role **OR** the caller's session DID
  matches the path-DID (self-revoke). Self-revoke is the
  canonical RTBF-style path: "I no longer want this claim
  asserted about me."
- **Idempotent no-op** when the flag is already `false`. The
  response returns `200 OK` with `personhood: false` but
  doesn't re-mint a VMC or emit an audit envelope.
- **On revoke**:
  1. Load Member row (404 if absent).
  2. Flip `Member.personhood = false`,
     `personhood_asserted_at = None`.
  3. Re-mint VMC + role VEC with `personhood: false`. Reuses
     the existing status-list slot.
  4. Emit `PersonhoodRevoked { vmcId, reason: <"admin" | "self"> }`.
     The renewal-time `reason: "renewal-policy"` flavour
     comes from the renewal path (M4.2.2), not this endpoint.

## Trust assumptions

- Caller holds a valid VTC-audience JWT.
- For admin revokes, the JWT's `role` claim is `admin`.
- For self-revokes, the JWT's `sub` matches the path-DID.

## Outputs

`200 OK` with:

```
{
  "did": "<member-did>",
  "personhood": false,
  "vmc": <vmc>,         // omitted on idempotent no-op
  "roleVec": <role_vec> // omitted on idempotent no-op
}
```

`403` when neither admin nor self. `404` when the member
doesn't exist.

## Status

Draft. Per-method Trust Task selectors aren't yet supported
by `TrustTaskRouter`, so the route mount shares the
`personhood/assert/1.0` Trust Task at the router layer. This
file exists on disk + in `index.json` so the soft-gate
surface stays complete.

## Idempotency

Cache TTL: 60s (destructive op per §9.1). Re-revokes within
the window return the cached response; outside the window
they no-op cleanly.
