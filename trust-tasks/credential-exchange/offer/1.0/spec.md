---
id: https://trusttasks.org/spec/credential-exchange/offer/1.0
title: Credential Exchange — Offer
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - didcomm: https://trusttasks.org/spec/credential-exchange/offer/1.0
---

# Credential Exchange — Offer

`issuer → holder`. The first step of the issuance leg: the issuer
offers a credential. The Trust Task is the transport / auth /
threading envelope; the body is an **OID4VCI Credential Offer**.

## Body

`{ credential_offer }` — an OID4VCI Credential Offer object. The
holder reads the offer to learn which credential(s) are on offer and
which grant / authorization flow to use, then replies with
[`request/1.0`](../../request/1.0).

## Authentication

The DIDComm authcrypt envelope authenticates the **issuer** (the
`from` DID is the proven sender). No in-body signature.

## Format-agnostic

Nothing here is format-specific. The credential format (SD-JWT-VC,
W3C Data-Integrity, BBS+) is negotiated by the credential
configuration referenced in the offer and finalised by the DCQL
`format` selector at presentation time.

## Threading

The offer opens a thread; `request/1.0` and `issue/1.0` reply on it
(`thid`). Relayer ≠ holder is permitted (the air-gap onboarding
pattern): the envelope sender may relay on the holder's behalf.
