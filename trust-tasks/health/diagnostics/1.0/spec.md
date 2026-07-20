---
id: https://trusttasks.org/openvtc/vtc/health/diagnostics/1.0
title: VTC — Trust-Registry Reconciler Diagnostics
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/health/diagnostics
---

# VTC — Trust-Registry Reconciler Diagnostics

Admin-gated view of the `MembershipSyncer` task's internal state.
Lets operators answer "is registry sync stuck?" without shelling
onto the host. Pairs with the `registry_status` field on
`GET /v1/community/profile`: the profile says *whether* the
registry looks reachable; this endpoint says *how stuck* the
reconciler is. Spec §8.3.

## Semantics

- **GET** — requires `Admin` role.
- Reads:
  - `registry_status` — `"active"` or `"degraded"`. Mirrors
    the `RegistryHealth` state machine (M3.2).
  - `queue_depth` — count of jobs in `Pending` + `InFlight`.
    A monotonically rising number means the registry is
    refusing dispatch.
  - `oldest_pending_age_seconds` — staleness of the
    longest-waiting *dispatchable* job (excludes
    `rtbf_batched` rows whose `next_attempt_at` is still
    future-dated). Drives the "≥1h behind → degraded" SLI.
  - `rtbf_batched_count` — pending jobs parked behind the
    RTBF batch window (M3.7). Confirms batch protection is
    active without inspecting fjall.
  - `failed_count` — terminal-failure rows. Need operator
    triage; the syncer won't retry them.
  - `last_success_at` / `last_failure_at` / `last_error` —
    the most recent registry probe state.

## Trust assumptions

- Caller holds a valid VTC-audience JWT.
- JWT's `role` claim is `admin` (super-admin is not required —
  this endpoint is intended for on-call ops without privileged
  permissions).

## Outputs

`200 OK` with [`DiagnosticsResponse`](https://github.com/OpenVTC/verifiable-trust-infrastructure/blob/main/vtc-service/src/routes/health.rs).
No state changes — read-only.

## Privacy

The endpoint exposes **aggregate counts only**. Individual
member DIDs are not surfaced; `rtbf_batched_count` discloses how
many RTBF jobs are in-flight but not which members they refer
to. The `last_error` field carries a string from the upstream
registry — operators reviewing diagnostics should treat it as
potentially sensitive (it may include URLs or error codes that
identify the upstream).

## Status

Draft.
