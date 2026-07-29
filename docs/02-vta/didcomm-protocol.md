# VTA DIDComm Protocol

The VTA exposes all administrative operations over DIDComm v2 messages, providing
protocol parity with the REST API. This document specifies the message types,
body schemas, authorization model, and error handling for the DIDComm interface.

## Overview

The VTA connects to a DIDComm mediator over WebSocket and processes inbound
messages on a dedicated thread. Each message is unpacked (decrypted + verified),
dispatched to a handler based on its `type` URI, and a response is packed and
sent back to the sender via the mediator.

```
Client                     Mediator                    VTA
  |                           |                         |
  |  pack_encrypted(msg)      |                         |
  |  send to mediator ------->|  forward via WS ------->|
  |                           |                         |  unpack(msg)
  |                           |                         |  dispatch by type
  |                           |                         |  execute handler
  |                           |                         |  pack_encrypted(response)
  |                           |<------- send response   |
  |<------- deliver           |                         |
  |                           |                         |
```

## Authentication

DIDComm messages are inherently authenticated: the sender's DID is verified
during the unpack operation (signature verification + DID resolution). This
replaces the JWT-based auth flow used by the REST API.

**Authorization** works by looking up the sender DID in the ACL:

1. Extract the `from` field from the unpacked message.
2. Strip any DID fragment (e.g. `did:key:z6Mk...#z6Mk...` becomes `did:key:z6Mk...`).
3. Look up the ACL entry for that DID.
4. If the DID is not in the ACL, reject with a `Forbidden` error.
5. Apply role-based authorization (Admin, Manage, SuperAdmin) based on the
   operation being performed.

The same role hierarchy and context-scoping rules apply as in the REST API.
See the [Authorization Model](../01-concepts/overview.md#roles-and-authorization) section of the
design doc for details.

### REST-Only Endpoints

The following REST endpoints have **no DIDComm equivalents** because they are
specific to the HTTP/JWT authentication flow:

- `GET /health` — infrastructure endpoint
- `POST /auth/challenge` — JWT challenge request
- `POST /auth/` — JWT token issuance
- `POST /auth/refresh` — JWT token refresh
- `GET /auth/sessions` — JWT session listing
- `DELETE /auth/sessions/{id}` — JWT session revocation
- `DELETE /auth/sessions?did=X` — JWT session bulk revocation

## Message Format

All DIDComm messages follow the standard DIDComm v2 envelope:

```json
{
  "id": "<uuid>",
  "type": "<protocol-type-uri>",
  "from": "<sender-did>",
  "to": ["<vta-did>"],
  "body": { ... }
}
```

Response messages include a `thid` (thread ID) that references the original
message `id`, allowing request-response correlation:

```json
{
  "id": "<uuid>",
  "type": "<protocol-type-uri>-result",
  "from": "<vta-did>",
  "to": ["<sender-did>"],
  "thid": "<original-message-id>",
  "body": { ... }
}
```

## Protocol Families

All protocol URIs are under `https://firstperson.network/protocols/`.

### Key Management (`key-management/1.0`)

| Request Type | Response Type | Auth | Description |
|---|---|---|---|
| `.../create-key` | `.../create-key-result` | Admin | Create a new key |
| `.../get-key` | `.../get-key-result` | Auth + context | Get key details |
| `.../list-keys` | `.../list-keys-result` | Auth | List keys (filtered by context) |
| `.../rename-key` | `.../rename-key-result` | Admin | Rename a key |
| `.../revoke-key` | `.../revoke-key-result` | Admin | Revoke a key |
| `.../get-key-secret` | `.../get-key-secret-result` | Admin | Export secret key material |
| `.../sign-request` | `.../sign-result` | Auth + context | Sign payload (signing oracle) |
| `.../import-key` | `.../import-key-result` | Admin | Import an external private key |
| `.../get-wrapping-key` | `.../get-wrapping-key-result` | Admin | Get ephemeral wrapping key (REST only) |

#### create-key

Request body:

```json
{
  "key_type": "ed25519",
  "derivation_path": "m/26'/2'/0'/5'",
  "mnemonic": null,
  "label": "My signing key"
}
```

Response body:

```json
{
  "key_id": "m/26'/2'/0'/5'",
  "key_type": "ed25519",
  "derivation_path": "m/26'/2'/0'/5'",
  "public_key": "z6Mk...",
  "status": "active",
  "label": "My signing key",
  "created_at": "2026-02-23T12:00:00Z"
}
```

#### get-key

Request body:

```json
{
  "key_id": "did:webvh:example.com#key-0"
}
```

Response body: a full `KeyRecord` object.

#### list-keys

Request body (all fields optional):

```json
{
  "offset": 0,
  "limit": 50,
  "status": "active",
  "context_id": "vta"
}
```

Response body:

```json
{
  "keys": [ ... ],
  "total": 42,
  "offset": 0,
  "limit": 50
}
```

#### rename-key

Request body:

```json
{
  "key_id": "old-key-id",
  "new_key_id": "new-key-id"
}
```

Response body:

```json
{
  "key_id": "new-key-id",
  "updated_at": "2026-02-23T12:00:00Z"
}
```

#### revoke-key

Request body:

```json
{
  "key_id": "did:webvh:example.com#key-0"
}
```

Response body:

```json
{
  "key_id": "did:webvh:example.com#key-0",
  "status": "revoked",
  "updated_at": "2026-02-23T12:00:00Z"
}
```

#### get-key-secret

Request body:

```json
{
  "key_id": "did:webvh:example.com#key-0"
}
```

Response body:

```json
{
  "key_id": "did:webvh:example.com#key-0",
  "key_type": "ed25519",
  "public_key_multibase": "z6Mk...",
  "private_key_multibase": "z..."
}
```

#### sign-request

Request body:

```json
{
  "key_id": "did:webvh:example.com#key-0",
  "payload": "<base64url-encoded-bytes>",
  "algorithm": "es256"
}
```

The `algorithm` field must match the key type: `"eddsa"` for Ed25519 keys,
`"es256"` for P-256 keys.

Response body:

```json
{
  "key_id": "did:webvh:example.com#key-0",
  "signature": "<base64url-encoded-signature>",
  "algorithm": "es256"
}
```

### Seed Management (`seed-management/1.0`)

| Request Type | Response Type | Auth | Description |
|---|---|---|---|
| `.../list-seeds` | `.../list-seeds-result` | Admin | List seed generations |
| `.../rotate-seed` | `.../rotate-seed-result` | Admin | Rotate to a new seed |

#### list-seeds

Request body: `{}` (empty)

Response body:

```json
{
  "seeds": [
    {
      "id": 0,
      "status": "retired",
      "created_at": "2026-01-01T00:00:00Z",
      "retired_at": "2026-02-15T00:00:00Z"
    },
    {
      "id": 1,
      "status": "active",
      "created_at": "2026-02-15T00:00:00Z",
      "retired_at": null
    }
  ],
  "active_seed_id": 1
}
```

#### rotate-seed

Request body:

```json
{
  "mnemonic": null
}
```

Pass a BIP-39 mnemonic string to import a specific seed, or `null`/omit to
generate a random one.

Response body:

```json
{
  "previous_seed_id": 0,
  "new_seed_id": 1
}
```

### Context Management (`context-management/1.0`)

| Request Type | Response Type | Auth | Description |
|---|---|---|---|
| `.../create-context` | `.../create-context-result` | Super Admin | Create a context |
| `.../get-context` | `.../get-context-result` | Auth + context | Get context details |
| `.../list-contexts` | `.../list-contexts-result` | Auth | List contexts (filtered) |
| `.../update-context` | `.../update-context-result` | Super Admin | Update a context |
| `.../delete-context` | `.../delete-context-result` | Super Admin | Delete a context |

#### create-context

Request body:

```json
{
  "id": "my-app",
  "name": "My Application",
  "description": "Optional description"
}
```

Response body:

```json
{
  "id": "my-app",
  "name": "My Application",
  "did": null,
  "description": "Optional description",
  "base_path": "m/26'/2'/3'",
  "created_at": "2026-02-23T12:00:00Z",
  "updated_at": "2026-02-23T12:00:00Z"
}
```

#### get-context

Request body:

```json
{
  "id": "my-app"
}
```

Response body: same format as `create-context-result`.

#### list-contexts

Request body: `{}` (empty)

Response body:

```json
{
  "contexts": [ ... ]
}
```

Results are filtered by the caller's context access.

#### update-context

Request body:

```json
{
  "id": "my-app",
  "name": "Updated Name",
  "did": "did:webvh:...",
  "description": "New description"
}
```

All fields except `id` are optional; only provided fields are updated.

Response body: same format as `create-context-result`.

#### delete-context

Request body:

```json
{
  "id": "my-app"
}
```

Response body:

```json
{
  "id": "my-app",
  "deleted": true
}
```

### ACL Management (`acl-management/1.0`)

| Request Type | Response Type | Auth | Description |
|---|---|---|---|
| `.../create-acl` | `.../create-acl-result` | Manage | Create an ACL entry |
| `.../get-acl` | `.../get-acl-result` | Manage | Get an ACL entry |
| `.../list-acl` | `.../list-acl-result` | Manage | List ACL entries |
| `.../update-acl` | `.../update-acl-result` | Manage | Update an ACL entry |
| `.../delete-acl` | `.../delete-acl-result` | Manage | Delete an ACL entry |

#### create-acl

Request body:

```json
{
  "did": "did:key:z6Mk...",
  "role": "admin",
  "label": "Alice",
  "allowed_contexts": ["vta"]
}
```

Response body:

```json
{
  "did": "did:key:z6Mk...",
  "role": "admin",
  "label": "Alice",
  "allowed_contexts": ["vta"],
  "created_at": 1740000000,
  "created_by": "did:key:z6MkCaller..."
}
```

#### get-acl

Request body:

```json
{
  "did": "did:key:z6Mk..."
}
```

Response body: same format as `create-acl-result`.

#### list-acl

Request body (all fields optional):

```json
{
  "context": "vta"
}
```

Response body:

```json
{
  "entries": [ ... ]
}
```

Results are filtered by the caller's context visibility.

#### update-acl

Request body:

```json
{
  "did": "did:key:z6Mk...",
  "role": "initiator",
  "label": "Updated label",
  "allowed_contexts": ["vta"]
}
```

All fields except `did` are optional; only provided fields are updated.

Response body: same format as `create-acl-result`.

#### delete-acl

Request body:

```json
{
  "did": "did:key:z6Mk..."
}
```

Self-deletion is not allowed.

Response body:

```json
{
  "did": "did:key:z6Mk...",
  "deleted": true
}
```

### VTA Management (`vta-management/1.0`)

| Request Type | Response Type | Auth | Description |
|---|---|---|---|
| `.../get-config` | `.../get-config-result` | Auth | Read VTA config |
| `.../update-config` | `.../update-config-result` | Super Admin | Update VTA config |

#### get-config

Request body: `{}` (empty)

Response body:

```json
{
  "vta_did": "did:webvh:...",
  "vta_name": "My Community",
  "public_url": "https://vta.example.com"
}
```

#### update-config

Request body:

```json
{
  "vta_did": "did:webvh:...",
  "vta_name": "Updated Name",
  "public_url": "https://new-url.example.com"
}
```

All fields are optional; only provided fields are updated. Changes are
persisted to the config file.

Response body: same format as `get-config-result`.

### VTA Management — Restart (`vta-management/1.0`)

| Request Type | Response Type | Auth | Description |
|---|---|---|---|
| `.../restart` | `.../restart-result` | Admin | Trigger a soft restart |

#### restart

Request body: `{}` (empty)

Response body:

```json
{
  "status": "restarting"
}
```

The VTA sends the response before restarting. Service threads shut down,
auth/crypto re-initialize, and threads restart without a process restart.

### Backup Management (`backup-management/1.0`)

| Request Type | Response Type | Auth | Description |
|---|---|---|---|
| `.../export` | `.../export-result` | Admin | Export encrypted backup |
| `.../import` | `.../import-result` | Admin | Import encrypted backup |

#### export

Request body:

```json
{
  "password": "at-least-fifteen-characters",
  "include_audit": false
}
```

Response body: A `BackupEnvelope` JSON object containing the Argon2id KDF
parameters, AES-256-GCM encryption parameters, and the base64url-encoded
ciphertext of all VTA state.

#### import

Request body:

```json
{
  "backup": { "...BackupEnvelope..." },
  "password": "the-export-password",
  "confirm": true
}
```

With `confirm: false`, returns a preview without modifying state.
With `confirm: true`, replaces all VTA state and triggers a soft restart.

Response body:

```json
{
  "status": "imported",
  "source_did": "did:webvh:...",
  "key_count": 5,
  "acl_count": 2,
  "context_count": 3,
  "audit_count": 0,
  "message": "Import complete. VTA will restart with new identity."
}
```

### Credential Management (`credential-management/1.0`)

| Request Type | Response Type | Auth | Description |
|---|---|---|---|
| `.../generate` | `.../generate-result` | Manage | Generate a new credential |

#### generate

Request body:

```json
{
  "role": "admin",
  "label": "New admin credential",
  "allowed_contexts": ["vta"]
}
```

This creates a new `did:key` identity, adds it to the ACL with the specified
role and contexts, and returns an encoded credential bundle.

Response body:

```json
{
  "did": "did:key:z6Mk...",
  "credential": "<base64url-encoded-credential-bundle>",
  "role": "admin"
}
```

The credential string is a base64url-encoded JSON object containing the DID,
private key, VTA DID, and VTA URL. It can be imported into a CLI client with
`cnm auth login <credential>`.

## Error Handling

When a handler encounters an error, the VTA sends a
[DIDComm problem-report](https://identity.foundation/didcomm-messaging/spec/#problem-reports)
message:

```json
{
  "type": "https://didcomm.org/report-problem/2.0/problem-report",
  "thid": "<original-message-id>",
  "body": {
    "code": "e.p.processing",
    "comment": "key not found: did:webvh:example.com#key-0"
  }
}
```

Common error codes:

| Code | Meaning |
|---|---|
| `e.p.processing` | General processing error (includes the error detail in `comment`) |

The `comment` field contains a human-readable description of the error, matching
the same error messages returned by the REST API (e.g. "admin role required",
"DID not in ACL", "context not found", etc.).

## Authorization Reference

| Auth Level | Required Role | Description |
|---|---|---|
| **Auth** | Any role | DID must be in the ACL |
| **Manage** | Admin or Initiator | Can manage ACL entries and credentials |
| **Admin** | Admin | Can create/modify keys and seeds |
| **Super Admin** | Admin with empty `allowed_contexts` | Can manage contexts and global config |

## Protocol Type URIs

Full list of all protocol type URIs:

```
# Key Management
https://firstperson.network/protocols/key-management/1.0/create-key
https://firstperson.network/protocols/key-management/1.0/create-key-result
https://firstperson.network/protocols/key-management/1.0/get-key
https://firstperson.network/protocols/key-management/1.0/get-key-result
https://firstperson.network/protocols/key-management/1.0/list-keys
https://firstperson.network/protocols/key-management/1.0/list-keys-result
https://firstperson.network/protocols/key-management/1.0/rename-key
https://firstperson.network/protocols/key-management/1.0/rename-key-result
https://firstperson.network/protocols/key-management/1.0/revoke-key
https://firstperson.network/protocols/key-management/1.0/revoke-key-result
https://firstperson.network/protocols/key-management/1.0/get-key-secret
https://firstperson.network/protocols/key-management/1.0/get-key-secret-result
https://firstperson.network/protocols/key-management/1.0/sign-request
https://firstperson.network/protocols/key-management/1.0/sign-result
https://firstperson.network/protocols/key-management/1.0/import-key
https://firstperson.network/protocols/key-management/1.0/import-key-result
https://firstperson.network/protocols/key-management/1.0/get-wrapping-key
https://firstperson.network/protocols/key-management/1.0/get-wrapping-key-result

# Seed Management
https://firstperson.network/protocols/seed-management/1.0/list-seeds
https://firstperson.network/protocols/seed-management/1.0/list-seeds-result
https://firstperson.network/protocols/seed-management/1.0/rotate-seed
https://firstperson.network/protocols/seed-management/1.0/rotate-seed-result

# Context Management
https://firstperson.network/protocols/context-management/1.0/create-context
https://firstperson.network/protocols/context-management/1.0/create-context-result
https://firstperson.network/protocols/context-management/1.0/get-context
https://firstperson.network/protocols/context-management/1.0/get-context-result
https://firstperson.network/protocols/context-management/1.0/list-contexts
https://firstperson.network/protocols/context-management/1.0/list-contexts-result
https://firstperson.network/protocols/context-management/1.0/update-context
https://firstperson.network/protocols/context-management/1.0/update-context-result
https://firstperson.network/protocols/context-management/1.0/delete-context
https://firstperson.network/protocols/context-management/1.0/delete-context-result

# ACL Management
https://firstperson.network/protocols/acl-management/1.0/create-acl
https://firstperson.network/protocols/acl-management/1.0/create-acl-result
https://firstperson.network/protocols/acl-management/1.0/get-acl
https://firstperson.network/protocols/acl-management/1.0/get-acl-result
https://firstperson.network/protocols/acl-management/1.0/list-acl
https://firstperson.network/protocols/acl-management/1.0/list-acl-result
https://firstperson.network/protocols/acl-management/1.0/update-acl
https://firstperson.network/protocols/acl-management/1.0/update-acl-result
https://firstperson.network/protocols/acl-management/1.0/delete-acl
https://firstperson.network/protocols/acl-management/1.0/delete-acl-result

# VTA Management
https://firstperson.network/protocols/vta-management/1.0/get-config
https://firstperson.network/protocols/vta-management/1.0/get-config-result
https://firstperson.network/protocols/vta-management/1.0/update-config
https://firstperson.network/protocols/vta-management/1.0/update-config-result

# Credential Management
https://firstperson.network/protocols/credential-management/1.0/generate
https://firstperson.network/protocols/credential-management/1.0/generate-result
```

## Source

- Protocol type definitions: [`vta-sdk/src/protocols/`](../vta-sdk/src/protocols/)
- DIDComm handlers: [`vta-service/src/messaging/handlers/`](../vta-service/src/messaging/handlers/)
- Authorization helper: [`vta-service/src/messaging/auth.rs`](../vta-service/src/messaging/auth.rs)
- Response helper: [`vta-service/src/messaging/response.rs`](../vta-service/src/messaging/response.rs)
- Message dispatch: [`vta-service/src/messaging/mod.rs`](../vta-service/src/messaging/mod.rs)
