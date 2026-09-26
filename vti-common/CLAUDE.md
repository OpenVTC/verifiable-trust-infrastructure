# CLAUDE.md — vti-common

## Purpose

`vti-common` is the **shared foundation crate** for the Verifiable Trust
Infrastructure (VTI) workspace. It provides types and implementations used
by both `vta-service` (VTA) and `vtc-service` (VTC).

## What belongs in vti-common

- **Store abstraction** — `Store`, `KeyspaceHandle` (enum dispatch to local
  fjall or vsock-proxied backends), `VsockStore`, encryption layer
- **Auth infrastructure** — JWT encoding/decoding, session management,
  auth extractors (axum `FromRequestParts` implementations)
- **ACL** — `AclEntry`, `Role`, CRUD operations, validation
- **Error types** — `AppError` enum used across all services
- **Config types** — `AuthConfig`, `LogConfig`, `StoreConfig`,
  `MessagingConfig`, `AuditConfig` (shared config shapes)
- **Backup transfer** (`backup_transfer`) — the node-neutral half of moving a
  backup bundle: the bundle store and its state machine, the `chunkedTrustTask`
  staging/serving/accepting and finalize checks, and the sweeper. Shared by the
  VTA (`vta-backup`) and the VTC for the `backup/*` family. What a bundle
  *contains* — serializing a node's state, applying one — stays with the node.
- **Task consent** (`task_consent`) — the node-neutral data layer of the DTTE
  ceremony: the payload and wire digests, pending requests, grants and their
  single-use consume. Shared by the VTA's policy gate (re-exported as
  `vta_policy::consent`) and the VTC's unrestricted-admin gate (VTI-APV-014).
  What a node gates on, who its approvers are and how it pushes a request stay
  with the node.
- **Trust Task push** (`trust_task_push`) — pushing a signed Trust Task to a
  peer over TSP > DIDComm > REST by what its DID document advertises: a durable
  record per push, one outbox attempt per transport, evidence-based settlement
  and escalation (VTI-TRN-030/-040/-041/-042). The node lends its keyspace,
  outbox, resolver and messaging through a `PushContext`. What a node pushes,
  and when, stay with the node.
- **Cryptographic primitives with no service-specific policy** — the HMAC
  pagination tokens, the audit-checkpoint signatures, and `slip10` (SLIP-0010
  Ed25519 derivation). See the note below on where the line falls.

## What does NOT belong here

- VTA-specific business logic (the key *hierarchy* — path allocation, context
  base paths, seed storage and rotation — plus DID operations and credentials).
  Note the distinction from `slip10`: the **algorithm** (seed + path → key) is a
  spec-frozen primitive and lives here; **which path means what**, who allocates
  it, and where the seed is stored are VTA policy and live in `vta-keys`. If you
  are adding something that needs to know what `m/26'/2'/…` *means*, it does not
  belong here.
- VTC-specific logic (community management)
- CLI commands
- TEE bootstrap code (KMS, mnemonic guard)
- Route handlers

## Feature flags

| Feature | Purpose |
|---------|---------|
| `encryption` | AES-256-GCM encryption for `KeyspaceHandle.with_encryption()` |
| `vsock-store` | `VsockStore` + `VsockKeyspaceHandle` (Linux only — requires `tokio-vsock`) |
| `tsp` | `relationship_store` — the durable TSP relationship store (`KeyspaceRelationshipKv` + `maintenance_loop`) shared by the VTA and VTC for Rev 3 §7.2.2 recovery. Pulls `affinidi-messaging-sdk`, so only the TSP-speaking services enable it. Also enables `trust_task_push::TspPushTransport` (`affinidi-tdk/tsp`, `vta-sdk/tsp`). |

## Key modules

```
src/
├── lib.rs              Module declarations
├── acl/mod.rs          ACL types, CRUD, validation
├── auth/
│   ├── extractor.rs    AuthClaims, ManageAuth, AdminAuth, SuperAdminAuth
│   ├── jwt.rs          JWT encode/decode
│   ├── mod.rs          Re-exports
│   └── session.rs      Session state, cleanup
├── config.rs           Shared config types
├── error.rs            AppError enum + IntoResponse
└── store/
    ├── mod.rs          Store/KeyspaceHandle enums, LocalStore, LocalKeyspaceHandle
    ├── encryption.rs   AES-256-GCM encrypt/decrypt helpers
    └── vsock.rs        VsockStore, VsockKeyspaceHandle, file I/O (vsock-store feature)
```

## Store architecture

`Store` and `KeyspaceHandle` are **enums** that dispatch to either:
- `Local` — fjall embedded database (standard mode)
- `Vsock` — vsock-proxied store on the parent EC2 instance (enclave mode)

Both variants support `.with_encryption()` for transparent AES-256-GCM
encryption of values (keys remain plaintext for prefix scans).

See `docs/02-vta/feature-flags.md` for the `vsock-store` feature chain.
