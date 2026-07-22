---
id: https://trusttasks.org/openvtc/vtc/admin/config/reload/1.0
title: VTC Admin — Reload Config
status: retired
supersededBy: https://trusttasks.org/spec/config/reload/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/admin/config/reload
---

# VTC Admin — Reload Config

Re-applies hot-reloadable settings to the running daemon without a
process restart. Diffs the four-layer `EffectiveConfig` against the
live in-memory `AppConfig`; for every key flagged
`requires_restart = false` whose effective value differs, the
in-memory config is updated and the key name is added to
`keysReloaded`. Keys whose new value already equals the live value
(no-op) are absent.

Emits `ConfigReloaded { keysReloaded }` to the audit log.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Phase 0 limitation

The Phase-0 config registry covers `server.host`, `server.port`
(both `requires_restart = true`) and `log.level` (hot-reloadable).
`log.level` updates land in the in-memory `AppConfig` but do not
yet propagate to the running `tracing-subscriber` filter — a
Phase-1 follow-up wires the subscriber's reload handle. Restart-
gated keys re-apply on the next daemon start regardless.

## Errors

- `401 Unauthorized` / `403 Forbidden` — auth + role gates.
- `503 Service Unavailable` — audit writer not configured.
