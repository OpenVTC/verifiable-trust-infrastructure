---
id: https://trusttasks.org/openvtc/vtc/policies/upload/1.0
title: VTC Policies — Upload
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/policies
---

# VTC Policies — Upload

Compiles and persists a new Rego policy revision. Spec §7.1. The
upload does **not** activate the policy — `POST
/v1/policies/{id}/activate` is a separate call so operators can
inspect a candidate (and run dry-runs via `POST
/v1/policies/{id}/test`) before flipping the live pointer.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Request

```
POST /v1/policies
Content-Type: application/json

{
  "purpose": "join",
  "regoSource": "package vtc.join\nimport rego.v1\n\ndefault allow := false\n"
}
```

- `purpose` (required) — one of `join`, `removal`, `personhood`,
  `registry`, `directory`, `roleDefinitions`,
  `crossCommunityRoles`, `crossCommunityRelationships`,
  `relationships`. Spec §7.1.
- `regoSource` (required) — the Rego module body. Bounded at
  64 KiB; larger uploads are refused with 400. Rego v1 syntax is
  the default (regorus 0.10).

## Response (`201 Created`)

```
{
  "id": "1a2b3c…",
  "sha256": "abcd…<64 hex>",
  "purpose": "join",
  "version": 7
}
```

- `id` — the new Policy row's UUID. Stable identifier.
- `sha256` — lowercase-hex SHA-256 of the source bytes. Matches
  `sha256sum policy.rego`. Used by audit + the operator-side
  verification echo.
- `version` — per-purpose monotone counter, incremented at every
  upload for the same purpose.

The audit envelope `PolicyUploaded` records the same id +
purpose + sha256 + version.

## Errors

- `400 Bad Request` — malformed JSON, missing fields, Rego
  source exceeds 64 KiB, or unknown `purpose` value.
- `400 Bad Request` (compile failure) — Rego parse / type error.
  The message names the policy id + the regorus diagnostic
  position (`policy.rego:line:col`).
- `401 Unauthorized` — missing / invalid session token.
- `403 Forbidden` — caller is not Admin.
- `500 Internal Server Error` — audit writer unavailable.

## Notes

- The upload does not affect the active pointer for any purpose.
  Existing community traffic continues to evaluate against the
  pre-existing active policy.
- Historical revisions are retained — there is no implicit
  "supersede the previous version" semantic. M2.4's
  `GET /v1/policies?status=archived` will surface them.
