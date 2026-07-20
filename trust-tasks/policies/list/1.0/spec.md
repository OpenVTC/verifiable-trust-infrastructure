---
id: https://trusttasks.org/openvtc/vtc/policies/list/1.0
title: VTC Policies — List
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/policies
---

# VTC Policies — List

Returns a paginated list of stored policies. Spec §7.1. Each
entry carries the full Policy row (including Rego source) plus
an `isActive` flag indicating whether this revision is the
currently-active policy for its purpose.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Query parameters

- `purpose` (optional) — exact-match filter on the policy
  purpose. Wire-form camelCase (`"join"`, `"removal"`,
  `"crossCommunityRoles"`, …). Unknown values surface as 400.
- `status` (optional) — `"active"` returns only rows currently
  pointed at by `active_policies:<purpose>`; `"archived"`
  returns only rows that are not pointed at. Omitted returns
  every row.
- `cursor` (optional) — pagination cursor from a prior page.
- `limit` (optional) — page size; clamped to `1..=200`.
  Default 50.

Filters are applied **after** pagination, so a page can be
smaller than `limit` when rows are filtered out. The cursor
remains valid; just call again with the same cursor + filter to
walk further.

## Response (`200 OK`)

```
{
  "items": [
    {
      "id": "1a2b…",
      "purpose": "join",
      "regoSource": "package vtc.join\nimport rego.v1\n…",
      "sha256": "abcd…",
      "activatedAt": "2026-03-21T18:42:00Z" | null,
      "authorDid": "did:key:zAdmin",
      "createdAt": "2026-03-21T18:40:00Z",
      "version": 4,
      "isActive": true
    }
  ],
  "nextCursor": "…" | null,
  "totalEstimate": null
}
```

## Errors

- `401 Unauthorized` — missing / invalid session token.
- `403 Forbidden` — caller is not Admin.
- `500 Internal Server Error` — audit writer / cursor signing
  unavailable.

## Notes

- The full Rego source ships in the response. Phase 2 doesn't
  separate "summary" from "detail" — operators usually want the
  source anyway, and pagination caps total payload size.
- `activatedAt` is `null` for revisions that have never been
  active and `non-null` for the latest activation timestamp on
  rows that were once or are currently active.
