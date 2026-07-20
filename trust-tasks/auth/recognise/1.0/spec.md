---
id: https://trusttasks.org/openvtc/vtc/auth/recognise/1.0
title: VTC — Cross-Community Session Mint
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/auth/recognise
---

# VTC — Cross-Community Session Mint

Mints a session JWT for a holder presenting a foreign
community's `VerifiableEndorsementCredential` + `Verifiable
MembershipCredential` pair. Phase 3 M3.10; spec §8.4.

## Semantics

- **No prior session** required — the foreign credentials *are*
  the authentication proof. Replaces the
  challenge/response/authenticate dance used by local-member
  flows.
- **Fail-closed.** Four hardening checks run in order, each
  short-circuiting on failure:
  1. Both VEC + VMC proofs verify against the foreign issuer's
     `#key-0`.
  2. Each credential's `credentialStatus.statusListCredential`
     fetches; the bit at `statusListIndex` must be `0`.
  3. The foreign issuer DID is present in the trust-registry
     recognition graph (live `recognise` query).
  4. Both `validFrom <= now <= validUntil`.
- **Role mapping** via `cross_community_roles.rego` (spec
  §7.1). The default policy denies every cross-community
  mapping; operators must upload an allowlist before any
  foreign role confers local access.
- **TTL clamp.** Session expires at
  `now + min(jwt_default, earliest(vec.validUntil,
  vmc.validUntil) - now)`. Per spec §8.4.
- **No refresh.** Cross-community sessions never refresh. The
  standard `POST /v1/auth/refresh` route would re-issue
  without re-running recognition — defeating the "peer
  community removed mid-session loses access" invariant. The
  session simply expires.

## Trust assumptions

- The trust registry's `recognise` query is the source of
  truth for "is this peer community recognised?". A registry
  outage during the call surfaces as `503 Service
  Unavailable`, never as a silent accept.
- The DID resolver returns the foreign issuer's current
  `#key-0`. A peer community rotating their key without
  updating their `did:webvh` log invalidates every outstanding
  foreign-issued credential — by design.

## Outputs

`200 OK` with:

```
{
  "sessionId": "xc-<uuid>",
  "data": {
    "accessToken": "<jwt>",
    "accessExpiresAt": <unix-seconds>,
    "foreignIssuerDid": "<did>",
    "mappedRole": "<local-role-string>"
  }
}
```

`403 Forbidden` on any verification failure or policy denial.
`500/503` only when the registry / DID resolver is
unreachable.

Every call (allow or deny) emits a
`CrossCommunitySessionMinted` audit envelope with a stable
`reason` discriminator.

## Status

Draft.
