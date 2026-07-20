---
id: https://trusttasks.org/spec/credential-exchange/issue/1.0
title: Credential Exchange — Issue
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - didcomm: https://trusttasks.org/spec/credential-exchange/issue/1.0
---

# Credential Exchange — Issue

`issuer → holder`. The issuer delivers the credential. The body
carries **exactly one** of two shapes:

- `credential_response` — the cleartext OID4VCI Credential Response,
  for a **known** holder over an authenticated channel.
- `sealed` — an armored [sealed-transfer](../../../../docs/02-vta/provision-integration.md)
  bundle, for a **secret-bearing** credential or an **unknown holder**
  (the invite / air-gap case). Only the holder can open it.

## Cleartext path

The `credential` inside `credential_response` is **format-agnostic**:

- a JSON **string** → SD-JWT-VC compact serialization;
- a JSON **object** with a `proof` → a W3C Data-Integrity VC.

The holder infers the format from the value shape and receives it
into its vault (`receive_issued_credential`). The issuer `did:key` is
resolved locally for the Data-Integrity path; a `did:webvh` / `did:web`
issuer needs resolver-based key resolution (a follow-up slice).

## Sealed path (invite / unknown holder)

`sealed` is an armored `SealedPayloadV1::IssuedCredential` bundle
(HPKE X25519-HKDF-SHA256 + ChaCha20-Poly1305) sealed to the holder's
X25519 derivation — derived from the `did:key` the invite pinned. The
holder opens it with `receive_sealed_issued_credential`, supplying the
matching X25519 secret and the **out-of-band SHA-256 digest** (digest
pinning is mandatory — there is no TOFU). The bundle's producer
assertion (`DidSigned` / `Attested` / `PinnedOnly`) is verified per
the sealed-transfer contract.

## Authentication

DIDComm authcrypt authenticates the **issuer**. For the sealed path,
the bundle additionally binds to the holder's key: a relayer that
forwards the bundle cannot open it.

## Threading

Replies on the [`request/1.0`](../../request/1.0) /
[`offer/1.0`](../../offer/1.0) thread (`thid`).
