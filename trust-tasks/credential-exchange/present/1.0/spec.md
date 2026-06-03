---
id: https://trusttasks.org/spec/credential-exchange/present/1.0
title: Credential Exchange — Present
status: Draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - didcomm: https://trusttasks.org/spec/credential-exchange/present/1.0
---

# Credential Exchange — Present

`holder → verifier`. The holder answers a [`query/1.0`](../../query/1.0)
with a presentation. The body is an **OID4VP `vp_token`** — a
selectively-disclosed, holder-bound presentation of the matched
credential.

## Body

`{ vp_token }` — **format-agnostic**:

- a JSON **string** → an SD-JWT-VC presentation: exactly the consented
  disclosures + a mandatory **kb-jwt** holder binding over the
  verifier `nonce` + `aud`.
- a JSON **object** → a W3C Data-Integrity VP. Plain `eddsa-jcs-2022`
  has no claim-level selective disclosure, so the whole credential is
  disclosed — and the present gate refuses unless the credential's
  claims are a **subset of the consented reveal set** (never
  over-discloses). The holder signs the VP (carrying `nonce` +
  `domain`) with its `eddsa-jcs-2022` key.

## Consent gate

Every disclosure is gated by a persisted, signed
[consent record](../../../../docs/05-design-notes/vti-credential-architecture.md)
(ISO/IEC 27560 + W3C DPV). The gate discloses exactly the consented
claims and refuses a revoked / expired credential or an over-broad
request.

## Holder binding & freshness

Holder binding is mandatory. The verifier `nonce` (freshness) and
audience are bound by the holder proof (the kb-jwt for SD-JWT-VC, the
DI proof's `nonce` + `domain` for W3C), so replay and audience
substitution are cryptographically prevented.

## Threading

Replies on the [`query/1.0`](../../query/1.0) thread (`thid`). For a
deferred query, the holder re-presents on the same thread once the
out-of-band approval lands.
