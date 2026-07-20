---
id: https://trusttasks.org/openvtc/vtc/members/rotate/1.0
title: VTC Members — DID Rotation
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/members/me/rotate
---

# VTC Members — DID Rotation

Step 2 of the two-step DID-rotation ceremony. Atomically
swaps the member's DID with both keys co-signing. Spec §10.5;
Phase 2 M2.15.1 ships `did:key` only; M2.15.2 layers in
`did:webvh` resolution.

## Authentication

Bearer-token JWT for the **old** DID's session. (The
milestone bullet says "new DID's session", but the new DID
has no ACL row yet — the standard `AuthClaims` extractor
wouldn't accept it. The body's `newSignature` field provides
the equivalent "new key holder is in control" guarantee. The
deviation is documented for M2.16's spec-clarification
pass.)

## Challenge request (optional body)

```
POST /v1/members/me/rotate/challenge
Content-Type: application/json

{
  "reason": "routine" | "compromise" | "deviceLoss" | "migration" | "unspecified"
}
```

The body is optional; omitting it means `unspecified`. The reason
is recorded on the resulting `DidRotated` audit envelope.

It is deliberately collected **here** rather than on the finish
request: the rotation signatures cover only `{rotationId, oldDid,
newDid, expiresAt}`, so a reason submitted at finish would be
unauthenticated and alterable by whoever relays that request.
Captured at challenge time it is bound to the authenticated
session that opened the ceremony. It remains **self-asserted** —
the member's own claim about their motive, never evidence of it.

## Request

```
POST /v1/members/me/rotate
Content-Type: application/json

{
  "rotationId": "<uuid from challenge>",
  "oldDid": "<caller's current DID>",
  "newDid": "<member's chosen new DID, must be did:key in M2.15.1>",
  "oldSignature": "<hex Ed25519 signature>",
  "newSignature": "<hex Ed25519 signature>"
}
```

Both signatures cover the same canonical payload bytes:

```
vtc-did-rotation/v1\0 || canonical_json({
  rotationId, oldDid, newDid, expiresAt
})
```

where `expiresAt` is the **epoch-seconds integer** from the
challenge response.

## Side-effects (all-or-nothing)

1. Consume the `rotation_id` (single-use).
2. Verify both signatures against the respective DID's
   Ed25519 pubkey.
3. Move the ACL row: delete `acl:<old>`, write `acl:<new>`
   with the same role + metadata.
4. Move the Member row (same DID transition).
5. Revoke every session keyed on the old DID.
6. Re-mint VMC + role VEC to the new DID, **reusing the
   existing status-list slot** (spec §6.2 — no new slot
   allocation on rotation).
7. Emit `DidRotated { oldDid, newDid, method, vmcId,
   roleVecId, priorRole, rotationReason }` audit envelope.
   Actor is the **new** DID (future principal).

## Response (`200 OK`)

```
{
  "newDid": "<new DID>",
  "method": "did:key",
  "vmc": { ... freshly-signed VMC ... },
  "roleVec": { ... freshly-signed VEC ... }
}
```

## Errors

- `400 Bad Request` — DID method unsupported (currently any
  non-`did:key` value), `rotationId` not found / expired /
  already consumed, malformed signatures, same-DID
  rotation, signature verification failure.
- `401 Unauthorized` — missing / invalid session token.
- `403 Forbidden` — session DID doesn't match `oldDid`, or
  the rotation challenge was issued for a different DID.
- `409 Conflict` — `newDid` already has an ACL row.

## Notes

- `did:webvh` rotation (M2.15.2) extends this endpoint by
  detecting the method and walking the `did.jsonl` log via
  `affinidi-did-resolver-cache-sdk` to verify the prior-key
  signature on the latest log entry. Until that lands,
  non-`did:key` new-DID values are 400'd with a pointer to
  the follow-up milestone.
