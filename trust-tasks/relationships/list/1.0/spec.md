---
id: https://trusttasks.org/openvtc/vtc/relationships/list/1.0
title: VTC — VRC List per Member
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/members/{did}/relationships
---

# VTC — VRC List per Member

Paginated list of VRCs naming `{did}` as either issuer or
subject. Phase 4 M4.6.2; spec §6.1 + §12.3.

## Semantics

- **Auth**: any authenticated session. Operators wanting
  stricter visibility (e.g. issuer-only listing) layer
  `directory.rego` (Phase 4 follow-up).
- **Pagination**: cursor-based per §9.1.
  `?cursor=&limit=` clamped to `1..=200`. The cursor is
  HMAC-signed under the audit key; replay rejects with `400
  invalid cursor`.
- **§12.3 departure strip**: rows where the *other* party
  (not the path-DID) is **Purge**-removed are stripped
  from the response. `Tombstone` + `Historical` members
  remain visible — they keep their Member row and the
  trust edge remains a legitimate historical claim.

## Trust assumptions

- Caller holds a valid VTC-audience JWT.

## Outputs

```
{
  "items": [
    {
      "id": "<uuid>",
      "issuerDid": "<did>",
      "subjectDid": "<did>",
      "vrcJsonld": { ... full VC body ... },
      "vrcSha256": "<hex>",
      "createdAt": "<rfc3339>"
    },
    ...
  ],
  "nextCursor": "<base64-signed>" | null,
  "totalEstimate": null
}
```

## Status

Draft.
