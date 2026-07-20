---
id: https://trusttasks.org/openvtc/vtc/admin/config/import/1.0
title: VTC Admin — Import Config
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/admin/config/import
---

# VTC Admin — Import Config

Diff-and-confirm import of the `ConfigExport` shape produced by
`POST /v1/admin/config/export`. Default `?confirm=false` returns
the diff without persisting anything; `?confirm=true` applies.

## Diff phase (`?confirm=false`, default)

Computes per-field diffs:

- **`communityProfileDiff`** — every profile field that would
  change (`oldValue` is `null` when no profile exists yet;
  `community_did` is included so the operator can spot a mismatched
  source).
- **`configOverridesDiff`** — every db-layer key that would change.
- **`rejected`** — keys the import carries that aren't in the
  registry, or whose values fail validation.

## Apply phase (`?confirm=true`)

Persists:
1. The community profile (if `communityProfile` is present in the
   import). Goes through the existing `CommunityProfileUpdate::apply`
   path, including the 16 KiB `extensions` cap.
2. Each validated config override (`ConfigStore::put`).

Emits `CommunityProfileUpdated { fieldsChanged }` and `ConfigChanged
{ changes, requiresRestart }` to the audit log (sensitive values
redacted via `ConfigChange::redact_if`).

## Community-DID safety

Refuses (`409 Conflict`) when the existing profile's
`community_did` differs from the import's — protects against
clobbering a different community's profile by mistake. A
freshly-installed VTC with no profile accepts any `community_did`.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Errors

- `400 Bad Request` — wrong `schemaVersion`.
- `401 Unauthorized` / `403 Forbidden` — auth + role gates.
- `409 Conflict` — `community_did` mismatch.
- `503 Service Unavailable` — audit writer not configured (apply
  path only; dry-run works without audit).
