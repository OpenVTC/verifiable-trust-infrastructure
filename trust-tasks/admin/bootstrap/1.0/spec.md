---
id: https://trusttasks.org/openvtc/vtc/admin/bootstrap/1.0
title: VTC Admin — Bootstrap
status: retired
supersededBy: https://trusttasks.org/spec/vtc/admin/bootstrap/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/admin/bootstrap
---

# VTC Admin — Bootstrap

Closes the install ceremony. The operator submits the
**setup-session JWT** issued by `POST /v1/install/claim/finish`
(M0.5.2) which carries:

- `sub` — the candidate admin `did:key`
- `install_jti` — the originating install token's `jti`

On success the VTC atomically:

1. Confirms no `Admin` ACL entry exists (defence-in-depth against
   double-bootstrap; the install carve-out should already block this).
2. Writes an `AdminEntry` (with one `RegisteredPasskey` lifted from
   the passkey persisted at `claim/finish`) under
   `admin:<did>` in the `passkey` keyspace.
3. Writes an `AclEntry { role: Admin }` under `acl:<did>` in the
   `acl` keyspace.
4. Closes the install carve-out — no further install token can be
   minted or claimed without an `emergency-bootstrap` action.
5. Emits `CommunityInstalled` to the audit log, carrying the
   community DID and the `install_jti` so forensics can correlate
   the install URL → bootstrap → carve-out-close chain.

## Authentication

**Unauthenticated** — the setup-session JWT is the auth credential.
The endpoint sits behind the install carve-out, which gates against
replay (the JWT's `install_jti` keys a `Consumed` install-token row).

## Errors

- `401 Unauthorized` — setup-session JWT invalid, expired, or
  references an unknown install token; the corresponding
  passkey user record is missing (claim/finish wasn't run).
- `409 Conflict` — an admin ACL entry already exists.
- `503 Service Unavailable` — install signer or audit writer not
  configured (run `vtc setup` first).
