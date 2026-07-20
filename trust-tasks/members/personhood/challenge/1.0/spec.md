---
id: https://trusttasks.org/openvtc/vtc/members/personhood/challenge/1.0
title: VTC — Personhood Assert Challenge
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/members/{did}/personhood/challenge
---

# VTC — Personhood Assert Challenge

Mints a single-use replay-protection nonce for the paired
`POST /v1/members/{did}/personhood/assert` endpoint. Phase 4
M4.3; spec §6.3 + planning-review D2 (VP-only assert body).

## Semantics

- **Auth**: any authenticated session. The challenge is
  bound to the path-DID — the assert handler refuses if the
  presented VP's `holder` doesn't match.
- **TTL**: 10 minutes from mint. Single-use: consumed on
  successful assert. Expired challenges are accepted by the
  store but rejected by the assert handler.
- **Storage**: rows live in the `passkey` keyspace under the
  `personhood_chal:` prefix (co-tenanting with the rotation
  challenge surface to avoid a dedicated keyspace for short-
  lived state).

## Trust assumptions

- Caller holds a valid VTC-audience JWT.
- The path-DID resolves to a current ACL row (404 otherwise).

## Outputs

`200 OK` with:

```
{
  "challengeId": "<uuid>",
  "expiresAt": "<rfc3339>"
}
```

The caller embeds `challengeId` into their VP's
`proof.challenge` field, then submits the VP to the assert
endpoint within the TTL window.

## Status

Draft.
