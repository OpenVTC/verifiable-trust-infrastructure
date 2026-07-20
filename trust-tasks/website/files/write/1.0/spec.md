---
id: https://trusttasks.org/openvtc/vtc/website/files/write/1.0
title: VTC — Website file write
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: PUT /v1/website/files/{*path}
---

# VTC — Website file write

Phase 5 M5.5.2. Admin-gated single-file write into `website.root_dir`. Live mode only — managed mode refuses single-file writes and requires `POST /v1/website/deploy` for content changes.

Per-file body cap from `website.max_file_size_mb` (default 10). Optional `If-Match: <etag>` header for optimistic concurrency; mismatch returns 409 (cookie-mismatch semantics). Emits `WebsiteFileWritten` audit envelope on success.
