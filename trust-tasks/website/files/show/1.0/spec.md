---
id: https://trusttasks.org/openvtc/vtc/website/files/show/1.0
title: VTC — Website file show
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/website/files/{*path}
---

# VTC — Website file show

Phase 5 M5.5.1. Admin-gated read of a single file under `website.root_dir`. Returns the file body with `Content-Type` (via `mime_guess`), `ETag` (SHA-256 of contents), and `X-Website-Etag` echo.
