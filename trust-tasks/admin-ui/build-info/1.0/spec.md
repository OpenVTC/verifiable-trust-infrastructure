---
id: https://trusttasks.org/openvtc/vtc/admin-ui/build-info/1.0
title: VTC — Admin UX build info
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /admin/build-info.json
---

# VTC — Admin UX build info

Phase 5 M5.7.2. Unauthenticated GET endpoint returning the baked admin SPA's release metadata:

```json
{
  "version": "<cargo-pkg-version>",
  "indexSha256": "<sha256 of index.html>",
  "fileCount": <u32>,
  "mode": "embedded" | "external"
}
```

The `indexSha256` doubles as the audit envelope's `AdminUiServed.indexSha256` so operators can pin which build is running. The endpoint is unauthenticated because the release metadata is public; the audit log + WebAuthn ceremony cover any sensitive operations.

External-mode deployments still serve this endpoint (returning `mode: "external"`) so monitoring tools have a uniform probe regardless of how the SPA reaches users.
