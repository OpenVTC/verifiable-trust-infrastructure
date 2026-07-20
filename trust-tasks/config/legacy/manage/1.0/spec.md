---
id: https://trusttasks.org/openvtc/vtc/config/legacy/manage/1.0
title: VTC Legacy — Config Management
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/config
  - rest: PATCH /v1/config
---

# VTC Legacy — Config Management

Placeholder Trust Task for the pre-MVP config endpoints (read +
patch) inherited from the `vtc-service` skeleton. Two HTTP methods
share this task because they operate on the same resource.

The shape of this Trust Task will be revised in M0.8 when the
config endpoints get split into `admin/config/show/1.0` /
`admin/config/patch/1.0` / `admin/config/reload/1.0` /
`admin/config/restart/1.0` per spec §14.6.
