---
id: https://trusttasks.org/openvtc/vtc/website/files/delete/1.0
title: VTC — Website file delete
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: DELETE /v1/website/files/{*path}
---

# VTC — Website file delete

Phase 5 M5.5.2. Admin-gated single-file delete under `website.root_dir`. Live mode only. Emits `WebsiteFileDeleted` audit envelope on success.
