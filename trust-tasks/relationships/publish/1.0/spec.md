---
id: https://trusttasks.org/openvtc/vtc/relationships/publish/1.0
title: VTC — VRC Publish
status: retired
supersededBy: https://trusttasks.org/spec/vtc/relationships/publish/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/relationships
---

# VTC — VRC Publish

Publishes a member-issued Verifiable Recognition Credential
(VRC) — a self-asserted trust edge from the caller to another
member. Phase 4 M4.6; spec §5.4 + §6.1; planning-review D1
(issuer is the *member*, not the community).

## Semantics

- **Auth**: any authenticated session. The caller's session
  DID **must equal** the VC's `issuer` field — VRCs are
  self-issued by construction. The VTC never mints VRCs.
- **Body**: `{ vrc: <signed VC body> }`. The VC must include:
  - `issuer` (string or `{ id, ... }`) matching the caller.
  - `credentialSubject.id` naming the subject member.
  - A `DataIntegrityProof` signed by the issuer's `#key-0`.
- **Idempotent re-publish**: a second publish of the same
  canonicalised VRC body returns `200 OK` with the existing
  row's id (vs a fresh `201 Created`).

## Flow

1. Parse `issuer` + `subject_did`.
2. Caller == issuer (else `403`).
3. Resolve the issuer's `#key-0` via the DID resolver +
   verify the data-integrity proof. Failure → `422
   VrcProofInvalid`.
4. Enrich both parties with `is_current` (live ACL + non-
   tombstoned Member). Subject absent → `422`.
5. Evaluate `relationships.rego`. Default policy: allow iff
   both parties are current members. Deny → `403
   RelationshipPolicyDenied`.
6. Compute SHA-256 of the canonicalised VRC. If a row with
   that hash exists, return its id (`200 OK`).
7. Allocate a new UUID, persist the row + secondary-index
   entries, emit `VrcPublished { vrc_id, subject_did,
   edge_type }`.

Per D7, VRCs carry **no `credentialStatus`** — revocation is
row deletion, not a status-list bit flip.

## Trust assumptions

- DID resolver returns the issuer's current `#key-0`.
- `relationships.rego` reflects the operator's current
  publishing policy.

## Outputs

`201 Created` on first publish, `200 OK` on idempotent
re-publish, with:

```
{
  "id": "<uuid>",
  "issuerDid": "<did>",
  "subjectDid": "<did>",
  "vrcSha256": "<hex>"
}
```

`403` on auth / policy failure. `422` on proof / shape
errors. `500` on misconfigured daemon (resolver absent).

## Status

Draft.
