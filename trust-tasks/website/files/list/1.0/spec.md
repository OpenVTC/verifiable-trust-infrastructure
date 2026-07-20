---
id: https://trusttasks.org/openvtc/vtc/website/files/list/1.0
title: VTC — Website files list
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/website/files
---

# VTC — Website files list

Phase 5 M5.5.1. Admin-gated cursor-paginated listing of files under `website.root_dir` (live mode) or `website.root_dir/current/` (managed mode). Hidden files + blocklisted extensions are excluded from listings to match the public read handler's behaviour.
