---
id: https://trusttasks.org/openvtc/vtc/auth/legacy/sessions/revoke/1.0
title: VTC Legacy — Revoke Single Session
status: retired
supersededBy: https://trusttasks.org/spec/auth/revoke-session/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: DELETE /v1/auth/sessions/{session_id}
---

# VTC Legacy — Revoke Single Session

Placeholder Trust Task for the pre-MVP single-session revocation
endpoint inherited from the `vtc-service` skeleton. The endpoint's
behaviour is unchanged in M0.3; this stub registers a stable Trust
Task ID so the wire surface is self-describing from day one (spec
§9.4 soft gate).

The shape of this Trust Task will be revised in Phase 1+ when the
auth surface gets re-aligned with the new install + passkey flows.
