---
id: https://trusttasks.org/openvtc/vtc/endorsement-types/register/1.0
title: VTC — Endorsement Type Register
status: retired
supersededBy: https://trusttasks.org/spec/vtc/endorsement-types/register/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/endorsement-types
---

# VTC — Endorsement Type Register

## Semantics

- **Auth**: Admin role.
- **Body**: `{ typeUri, claimSchema?, description? }`.
- Refuses the workspace-reserved URI `role:vetter` with `409 endorsement-type-reserved`; a registered `typeUri` is a predicate IRI.
- Refuses duplicates with `409 endorsement-type-exists`.
- Refuses empty / oversized URIs (> 512 bytes) with `400`.
- Emits `EndorsementTypeRegistered { typeUri, description }`.

## Outputs

`201 Created` with the full `EndorsementType` row.

## Status

Draft.
