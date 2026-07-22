---
id: https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0
title: VTC Install — Claim (Finish)
status: retired
supersededBy: https://trusttasks.org/spec/vtc/install/claim/finish/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/install/claim/finish
---

# VTC Install — Claim (Finish)

Phase 2 of the WebAuthn install ceremony (spec §4.2). The operator's
UA submits:

1. The same install-token JWT used at `start`.
2. The `registration_id` echoed from `start`.
3. The WebAuthn `RegisterPublicKeyCredential` returned by
   `navigator.credentials.create()`.
4. The Ed25519 signature (base64url-no-pad, 64 bytes) over the
   server-issued DID-binding challenge.

The VTC:

- Verifies the WebAuthn registration via the EdDSA-restricting
  wrapper (`webauthn-rs` finish + `cred_algorithm() == EDDSA`).
- Projects the credential's Ed25519 public key into a `did:key`
  (multicodec `0xed01` + base58btc).
- Verifies the DID-binding signature with the same public key,
  proving single-key control over both signing paths.
- Marks the install token `Consumed` in the claim-window state
  machine.
- Persists the passkey + `did:key → user UUID` mapping in the
  `passkey` keyspace.
- Mints a setup-session JWT (`aud = vtc-install-session`, TTL 5
  minutes) consumed by `POST /v1/admin/bootstrap` (M0.6).

The install carve-out **stays open** after `finish` — only the
bootstrap call closes it. Until then no other ceremony can re-use
the same install token (state is `Consumed`).

## Errors

- `401 Unauthorized` — install token invalid; `registration_id`
  doesn't match `jti`; WebAuthn ceremony rejected; DID-binding
  signature doesn't verify; token already consumed.
- `503 Service Unavailable` — WebAuthn or install signer not
  configured.
