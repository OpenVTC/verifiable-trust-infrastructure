---
id: https://trusttasks.org/openvtc/vtc/credentials/endorsements/issue/1.0
title: VTC — Custom Endorsement Issue
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/credentials/endorsements
---

# VTC — Custom Endorsement Issue

## Semantics

- **Auth**: Admin OR Issuer role member (live ACL check; JWT role degrades to Reader for Issuer, so the handler reads the VTC ACL row directly).
- **Body**: `{ subjectDid, type, claim, validitySeconds? }`.
- **Type registry consultation**: refuses unknown types with `400 endorsement-type-not-registered`.
- **Claim cap**: 8 KiB JSON object.
- Allocates a slot on the shared `Revocation` status list (D8 review), builds + signs the VEC, persists the row.
- Emits both `CustomEndorsementIssued { endorsementId, endorsementType, statusListIndex }` and `VecIssued { credentialId, ... }` so credential-issuance accounting stays uniform.

## Outputs

`201 Created` with the signed VEC body + the row id.

## Status

Draft.
