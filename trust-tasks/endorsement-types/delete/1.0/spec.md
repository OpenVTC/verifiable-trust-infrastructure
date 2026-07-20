---
id: https://trusttasks.org/openvtc/vtc/endorsement-types/delete/1.0
title: VTC — Endorsement Type Delete
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: DELETE /v1/endorsement-types/{type_uri}
---

# VTC — Endorsement Type Delete

## Semantics

- **Auth**: Admin role.
- Refuses with `409 endorsement-type-in-use` while at least one live endorsement of the type still exists. Operators must revoke all live endorsements first.
- `404` when the type isn't registered.
- Emits `EndorsementTypeDeleted { typeUri }`.

## Outputs

`200 OK` with `{ typeUri }`.

## Status

Draft.
