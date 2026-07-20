---
id: https://trusttasks.org/openvtc/vtc/members/rotate-challenge/1.0
title: VTC Members — DID Rotation Challenge
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/members/me/rotate/challenge
---

# VTC Members — DID Rotation Challenge

Step 1 of the two-step DID-rotation ceremony (spec §10.5,
Phase 2 M2.15.1). Mints a single-use `rotation_id` + 10-minute
TTL the caller binds into the co-signed payload in step 2.

## Authentication

Bearer-token JWT for the member's current DID. Must
correspond to an active ACL row — non-members are 404'd.

## Request

```
POST /v1/members/me/rotate/challenge
```

Empty body.

## Response (`200 OK`)

```
{
  "rotationId": "<uuid>",
  "expiresAt": "<rfc3339>",
  "signingPayloadHex": "<hex of vtc-did-rotation/v1\0 domain tag>",
  "canonicalTemplate": {
    "rotationId": "<uuid>",
    "oldDid": "<caller's DID>",
    "newDid": "<fill in>",
    "expiresAt": <epoch seconds>
  }
}
```

The signing payload the caller hashes over is:

```
vtc-did-rotation/v1\0 || canonical_json({
  rotationId, oldDid, newDid, expiresAt
})
```

`canonicalTemplate` is a convenience — the caller substitutes
`newDid` and serializes the JSON with key-ordered fields to
reproduce the exact bytes step 2 verifies against.

## Errors

- `401 Unauthorized` — missing / invalid session token.
- `404 Not Found` — caller is not a current member.
