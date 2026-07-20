---
id: https://trusttasks.org/openvtc/vtc/admin/config/restart/1.0
title: VTC Admin — Restart Daemon
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/admin/config/restart
---

# VTC Admin — Restart Daemon

Triggers a graceful shutdown so a process supervisor can bring the
daemon back up with `requires_restart`-flagged config changes
applied. Refuses unless a supervisor is detected — without one,
"restart" is just "kill the process".

## Supervisor detection

Probed in priority order (`crate::supervisor`):

1. **`VTC_SUPERVISED=1`** env var — explicit operator opt-in.
2. **`NOTIFY_SOCKET`** — set by systemd `Type=notify` units.
3. **`KUBERNETES_SERVICE_HOST`** — running inside a pod; kubelet
   honours `restartPolicy`.

The detected kind is echoed back on the response so the admin UX
can render "restarting under systemd…" or similar.

## Flow

1. Validate supervisor detection — `412 PRECONDITION_FAILED` with
   `SupervisorRequired` if none found.
2. Emit `RestartRequested { drainTimeoutSeconds }` to the audit
   log *before* signalling shutdown — guarantees the row survives a
   wedged drain.
3. Flip the daemon's shared graceful-shutdown channel
   (`AppState.shutdown_tx`). The REST thread stops accepting new
   connections via `axum::serve::with_graceful_shutdown`; the
   storage thread flushes; supervisor brings the process back.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Errors

- `401 Unauthorized` / `403 Forbidden` — auth + role gates.
- `412 Precondition Failed` — `SupervisorRequired`.
- `503 Service Unavailable` — audit writer not configured.
