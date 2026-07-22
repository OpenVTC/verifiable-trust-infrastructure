---
id: https://trusttasks.org/openvtc/vtc/website/rollback/1.0
title: VTC — Website generation rollback
status: retired
supersededBy: https://trusttasks.org/spec/vtc/website/rollback/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/website/rollback/{gen}
---

# VTC — Website generation rollback

Phase 5 M5.5.4. Admin-gated. Managed mode only. Flips the `current` symlink to the requested past generation via the `symlink + rename` atomic-swap idiom. Rollback to the currently-active generation is a 200 no-op. Emits `WebsiteGenerationRolledBack` audit envelope on success.
