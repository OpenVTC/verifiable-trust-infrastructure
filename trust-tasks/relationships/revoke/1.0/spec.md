---
id: https://trusttasks.org/openvtc/vtc/relationships/revoke/1.0
title: VTC — VRC Revoke
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: DELETE /v1/relationships/{id}
---

# VTC — VRC Revoke

Revokes a previously-published VRC. Phase 4 M4.6.3; spec
§6.1; planning-review D7 (no `credentialStatus`, revocation
= row deletion).

## Semantics

- **Auth**: the caller's session DID **must equal** the
  row's `issuerDid` (issuer self-retraction) OR the caller
  is an admin (moderation). Subject-only revocation is
  explicitly **not** allowed — the subject can't unilaterally
  drop a claim someone else made about them; they can ask
  an admin to moderate.
- **Effect**: deletes the primary row + both secondary-index
  entries. Idempotent: re-revoking a missing row returns
  `404`.
- **Audit**: emits `VrcRevoked { vrc_id, revoked_by:
  "issuer"|"admin" }`.

## Trust assumptions

- Caller holds a valid VTC-audience JWT.
- For admin revoke, the JWT's `role` claim is `admin`.

## Outputs

`200 OK` with `{ "id": "<uuid>" }`. `403` on auth failure;
`404` on missing row.

## Idempotency

Cache TTL: 60s (destructive op per §9.1).

## Status

Draft.
