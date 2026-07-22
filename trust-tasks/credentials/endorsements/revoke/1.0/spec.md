---
id: https://trusttasks.org/openvtc/vtc/credentials/endorsements/revoke/1.0
title: VTC — Custom Endorsement Revoke
status: retired
supersededBy: https://trusttasks.org/spec/vtc/endorsements/revoke/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: DELETE /v1/credentials/endorsements/{id}
---

# VTC — Custom Endorsement Revoke

## Semantics

- **Auth**: Admin OR Issuer role member.
- Idempotent: re-revoking an already-revoked row returns `200 OK` without re-flipping the bit or re-emitting audit envelopes.
- Flips the `Revocation` status-list bit at the row's `statusListIndex` (immediate).
- Emits paired envelopes:
  - `CustomEndorsementRevoked { endorsementId, endorsementType }` (semantic).
  - `StatusListFlipped { purpose: "revocation", index, revoked: true }` (bit-flip accounting).

## Status

Draft. Per-method `TrustTaskRouter` selectors aren't yet supported; route mount shares `show/1.0`. File exists on disk + index.json so the soft-gate surface stays complete.

## Status

Draft.
