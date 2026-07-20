---
id: https://trusttasks.org/openvtc/vtc/auth/legacy/authenticate/1.0
title: VTC Legacy — Authenticate
status: retired
supersededBy: https://trusttasks.org/spec/auth/authenticate/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/auth/
---

# VTC Legacy — Authenticate

Placeholder Trust Task for the pre-MVP authenticate endpoint
inherited from the `vtc-service` skeleton. The endpoint's
behaviour is unchanged in M0.3; this stub registers a stable Trust
Task ID so the wire surface is self-describing from day one (spec
§9.4 soft gate).

The shape of this Trust Task will be revised in Phase 1+ when the
auth surface gets re-aligned with the new install + passkey flows.
