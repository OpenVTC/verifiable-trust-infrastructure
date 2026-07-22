---
id: https://trusttasks.org/openvtc/vtc/members/personhood/assert/1.0
title: VTC — Personhood Assert
status: retired
supersededBy: https://trusttasks.org/spec/vtc/members/personhood/assert/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/members/{did}/personhood
---

# VTC — Personhood Assert

Flips a member's `personhood` flag to `true` after the
caller presents a Verifiable Presentation that satisfies the
active `personhood.rego`. Phase 4 M4.3; spec §6.3 +
planning-review D2 (VP-only assert).

## Semantics

- **Auth**: any authenticated session. Admin, issuer, or
  subject member can mint a challenge + submit the assert.
  Operators wanting stricter "only admin can assert" semantics
  layer this in `personhood.rego`.
- **Body** (D2 review):
  ```json
  {
    "presentation": { /* W3C VP, holder == path-did,
                          proof signed by member's #key-0 */ }
  }
  ```
  Cap: 16 KiB.
- **Replay protection**: the VP's `proof.challenge` must
  equal a fresh nonce from
  `POST /v1/members/{did}/personhood/challenge` (10-min TTL,
  single-use).

## Flow

1. Consume the challenge (single-use; refuses on missing /
   expired / wrong-DID).
2. Verify the VP's `holder` matches the path-DID.
3. Verify the VP's `DataIntegrityProof` against the member's
   resolved `#key-0` (via the workspace DID resolver).
4. Run `extract_vp_claims` (Phase 2 M2.6) → policy input.
5. Eval `personhood.rego`. On `deny` → `403
   personhood-policy-denied`.
6. Write `Member.personhood = true`,
   `personhood_asserted_at = now`. **Evidence is not
   persisted** (D2 review — VPs are verify-then-discard).
7. Re-mint VMC + role VEC with `personhood: true`. Reuses the
   member's existing status-list slot.
8. Emit `PersonhoodAsserted { vmcId, assertedAt }`.

## Trust assumptions

- The DID resolver returns the member's current `#key-0`.
- The active `personhood.rego` reflects the operator's
  current admission policy.
- The challenge mint endpoint hasn't been bypassed (the route
  layer refuses missing / expired / wrong-DID challenges
  cleanly with `422 Validation`).

## Outputs

`200 OK` with the new VMC + role VEC. `403` on policy denial
or proof failure. `422` on challenge / shape errors. `500`
when the DID resolver is unwired (daemon misconfigured).

Every successful assert emits a `PersonhoodAsserted` audit
envelope; the renewal-time `personhood_changed` flag becomes
precise on the next renewal call.

## Status

Draft.
