---
id: https://trusttasks.org/openvtc/vtc/credentials/endorsements/list/1.0
title: VTC — Custom Endorsement List
status: retired
supersededBy: https://trusttasks.org/spec/vtc/endorsements/list/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/credentials/endorsements
---

# VTC — Custom Endorsement List

## Semantics

- **Auth**: Admin OR Issuer role member.
- Cursor pagination per §9.1.
- Both live and revoked rows surface; consumers filter on `revokedAt`.

## Status

Draft.
