---
id: https://trusttasks.org/openvtc/vtc/website/deploy/1.0
title: VTC — Website bundle deploy
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/website/deploy
---

# VTC — Website bundle deploy

Phase 5 M5.5.3. Admin-gated. Accepts a `tar.gz` bundle containing the website's static content; per-bundle body cap from `website.max_bundle_size_mb` (default 50).

Pre-extract path safety rejects bundles containing `..` segments, absolute paths, symlinks / hardlinks, hidden top-level paths, blocklisted extensions, or executable bits on regular files. Survivors extract to a fresh staging directory; the staging dir is then atomically swapped into place:

- **Live mode**: rename the staging directory over `root_dir`; the previous content moves to a temp `.previous.*` dir which is best-effort removed.
- **Managed mode**: extract under `gen-N` (N = highest existing + 1), flip the `current` symlink atomically (symlink + rename), prune generations beyond `managed_generations_keep`.

Emits `WebsiteBundleDeployed` audit envelope on success.
