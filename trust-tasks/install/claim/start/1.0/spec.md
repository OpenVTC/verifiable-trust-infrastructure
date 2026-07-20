---
id: https://trusttasks.org/openvtc/vtc/install/claim/start/1.0
title: VTC Install — Claim (Start)
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/install/claim/start
---

# VTC Install — Claim (Start)

Phase 1 of the WebAuthn install ceremony (spec §4.2). The
operator's UA submits the install-token JWT printed by `vtc setup`;
the VTC verifies the token, locks the claim window (300 s) for the
token's `jti`, and returns:

- A WebAuthn `PublicKeyCredentialCreationOptions` restricted to
  Ed25519 (`COSEAlgorithmIdentifier = -8`). The UA passes this to
  `navigator.credentials.create()`.
- A 32-byte server-issued "DID-binding challenge" (base64url-no-pad).
  The operator must sign this challenge with the Ed25519 private
  key materialised inside their authenticator and present the
  signature to `POST /v1/install/claim/finish`. Proves single-key
  control over both the WebAuthn assertion path and the
  `did:key` signing path.

## Errors

- `401 Unauthorized` — install token signature invalid, expired,
  unknown `jti`, audience mismatch, or carve-out closed.
- `409 Conflict` — a previous `start` for this token is still
  inside the 300-second claim window. Retrying after the window
  succeeds (the previous ceremony is presumed abandoned).
- `503 Service Unavailable` — VTC was started without a
  `public_url` (no WebAuthn relying party) or before key
  material was loaded (no install signer).
