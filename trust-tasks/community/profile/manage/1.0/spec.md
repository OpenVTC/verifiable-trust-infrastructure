---
id: https://trusttasks.org/openvtc/vtc/community/profile/manage/1.0
title: VTC — Community Profile (Show + Update)
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/community/profile
  - rest: PUT /v1/community/profile
---

# VTC — Community Profile (Show + Update)

The Phase-0 read + write surface for the community's singleton
profile (`name`, `description`, `logoUrl`, `publicUrl`,
`contactEmail`, `language`, `extensions`). Two HTTP methods share
this task because they target the same resource; a future Phase-1+
revision will split them into `community/profile/show/1.0` and
`community/profile/update/1.0` (per spec §16.4) once
`TrustTaskRouter` gains per-method task selectors.

## Semantics

- **GET** — any authenticated session may read. Returns 404 with
  `community_not_initialised` when no profile has been written yet
  (pre-bootstrap state).
- **PUT** — requires `Admin` role. Accepts a partial
  [`CommunityProfileUpdate`](https://github.com/OpenVTC/verifiable-trust-infrastructure/blob/main/vtc-service/src/community/profile.rs)
  patch — every field is optional; omitted fields are left
  unchanged. The immutable `communityDid` cannot be supplied. The
  `extensions` blob is capped at 16 KiB (plan **D4**).

## Trust assumptions

- Caller holds a valid VTC-audience JWT.
- For PUT, the JWT's `role` claim is `admin`.

## Outputs

- GET → the full `CommunityProfile` record.
- PUT → `{ profile, fieldsChanged: [field, ...] }`. An empty
  `fieldsChanged` means no value actually changed (idempotent
  no-op).
- PUT also emits a `CommunityProfileUpdated` audit event once the
  audit writer is wired into `AppState` (post-M0.9).

## Status

Draft. Will split into show + update tasks when `TrustTaskRouter`
supports per-method task selectors.
