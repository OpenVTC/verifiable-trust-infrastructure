---
id: https://trusttasks.org/openvtc/vtc/website/generations/list/1.0
title: VTC — Website generations list
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/website/generations
---

# VTC — Website generations list

Phase 5 M5.5.4. Admin-gated. Managed mode only — returns 400 in live mode. Enumerates every `gen-N` directory under `website.root_dir`, marking the one `current` resolves to.
