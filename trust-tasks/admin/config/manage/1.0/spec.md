---
id: https://trusttasks.org/openvtc/vtc/admin/config/manage/1.0
title: VTC — Admin Runtime Configuration (Show + Patch)
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/admin/config
  - rest: PATCH /v1/admin/config
---

# VTC — Admin Runtime Configuration (Show + Patch)

The Phase-0 admin surface for runtime configuration. Covers reading
the four-layer-merged effective view and patching per-key
overrides into the db layer.

The reload + restart half of the spec §14.6 surface
(`POST /v1/admin/config/reload`, `POST /v1/admin/config/restart`)
lands in a follow-up alongside its own Trust Task. Export/import
(spec §14.2 + plan M0.8.4) is the third follow-up.

Two HTTP methods share this task because they target the same
resource collection; a future Phase-1+ revision will split them
into `admin/config/show/1.0` and `admin/config/patch/1.0` when
`TrustTaskRouter` gains per-method task selectors.

## Semantics

### GET

- Requires `Admin` role.
- Returns `{ fields: [{ key, value, source, requiresRestart }, …] }`
  for every registry key (currently `server.host`, `server.port`,
  `log.level`).
- `source ∈ {"env", "db", "toml", "default"}` mirrors the four-layer
  overlay precedence (env > db > toml > default).

### PATCH

- Requires `Admin` role.
- Body is an arbitrary `key → value` map.
- Unknown keys (not in the registry) are returned under `rejected`
  with a reason; the rest of the patch still applies.
- Invalid values (wrong type, out-of-range, allowlist mismatch)
  are similarly returned under `rejected`.
- Each successful write is reported as either `applied` (the new
  value is already in effect) or `pendingRestart` (the value is
  stored but takes effect on next daemon restart). A future Phase
  will tighten this with `admin/config/reload/1.0` so hot-reloadable
  values can be re-applied without restarting.
- Sensitive keys (none in Phase 0; TLS paths and storage path
  arrive later) will be redacted in the audit log via
  `vti_common::audit::ConfigChange::redact_if` before persistence.

## Trust assumptions

- Caller holds a valid VTC-audience JWT with `role` claim `admin`.
- The session referenced by `session_id` is in `Authenticated`
  state in the sessions keyspace.

## Outputs

- GET → `EffectiveConfig { fields: Vec<EffectiveField> }`.
- PATCH → `{ applied: [...], pendingRestart: [...], rejected: [...] }`.
- PATCH also emits a `ConfigChanged` audit event once
  `AuditWriter` is wired into `AppState` (post-M0.9).
