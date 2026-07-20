---
id: https://trusttasks.org/openvtc/vtc/status-lists/show/1.0
title: VTC Status Lists — Show
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/status-lists/{purpose}
trust_task_header_exempt: true
---

# VTC Status Lists — Show

Returns the freshly-signed `BitstringStatusListCredential` for
one of the two status purposes the VTC maintains. Verifier-
facing — external verifiers fetch this endpoint as part of the
standard W3C status-list-v1 resolution flow.

## Trust-Task-exempt

This endpoint **does not** require the `Trust-Task` header.
W3C status-list resolution is the standard verification flow
external verifiers follow; carrying our extension header would
break interoperability. The exemption mirrors
`/v1/{scid}/did.jsonl` (DID resolver fetches).

## Path parameters

- `purpose` (required) — `revocation` or `suspension`. Other
  values surface as 404.

## Response (`200 OK`)

The response body is a signed `BitstringStatusListCredential`
per W3C Bitstring Status List v1.0:

```
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "<canonical list URL>",
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "<vtc_did>",
  "validFrom": "<rfc3339>",
  "credentialSubject": {
    "id": "<list URL>#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "<gzip + base64url>"
  },
  "proof": { … data-integrity proof … }
}
```

The proof is signed by the VTC's `#key-0` Ed25519
(`eddsa-jcs-2022` data integrity). The encoded list is
GZIP+base64url per W3C.

### `Cache-Control: no-store`

Status-list flips land in real time on the local fjall row.
Caching the response between the VTC and a verifier would mask
recent revocations, so the response carries `Cache-Control:
no-store`. Operators who deploy a CDN in front of the VTC must
preserve this header.

## Errors

- `404 Not Found` — `{purpose}` is neither `revocation` nor
  `suspension`, or the daemon hasn't provisioned this purpose
  yet (pre-`public_url` deployment).
- `503 Service Unavailable` — credential signer not initialised
  (the VTC has no key material).

## Notes

- The VC's `validFrom` is `now()` at every request — the VC is
  signed fresh per request. This is intentional: stale flips
  cannot linger in a CDN.
- Index allocation is random with decoys per spec §6.2. The
  encoded bitstring leaks neither the active member count nor
  any specific member's slot.
