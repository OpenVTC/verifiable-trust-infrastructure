---
id: https://trusttasks.org/spec/credential-exchange/request/1.0
title: Credential Exchange — Request
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - didcomm: https://trusttasks.org/spec/credential-exchange/request/1.0
---

# Credential Exchange — Request

`holder → issuer`. The holder asks for the offered credential. The
body is an **OID4VCI Credential Request** carrying the holder's
**key-binding proof**.

## Body

`{ credential_request }` — an OID4VCI Credential Request. The
embedded proof (`openid4vci-proof+jwt`) binds the credential to a key
the holder controls; the issuer mints the credential against that
key (the `cnf` for SD-JWT-VC, the `credentialSubject.id` for W3C DI).

## Authentication

DIDComm authcrypt authenticates the **holder** (the `from` DID is the
proven sender). The key-binding proof is an additional, credential-
level binding — distinct from the envelope sender authentication.

## Threading

Replies on the [`offer/1.0`](../../offer/1.0) thread (`thid`). The
issuer answers with [`issue/1.0`](../../issue/1.0).
