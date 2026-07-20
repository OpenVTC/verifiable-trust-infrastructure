---
id: https://trusttasks.org/openvtc/vtc/admin/config/export/1.0
title: VTC Admin — Export Config
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/admin/config/export
---

# VTC Admin — Export Config

Returns the portable subset of a VTC's configuration: the community
profile + the db-layer config overrides. Env-layer and toml-layer
values are deliberately excluded — those carry per-host secrets
(JWT signing key, secret-store credentials, TLS cert paths) that
must not travel with an export.

The result is plain JSON shaped as `ConfigExport`:

```json
{
  "schemaVersion": 1,
  "exportedAt": "2026-05-12T03:42:00Z",
  "communityProfile": { ... },
  "configOverrides": { "log.level": "debug" }
}
```

A subsequent `POST /v1/admin/config/import` of this payload against
a fresh VTC (or the same one, idempotently) restores both.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Errors

- `401 Unauthorized` / `403 Forbidden` — auth + role gates.
