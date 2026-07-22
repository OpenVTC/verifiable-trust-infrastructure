# VTA Security Architecture

## Overview

The VTA implements a defense-in-depth security model with eight layers of
protection when deployed in TEE mode. Non-TEE deployments use the
identity/access, seal, and audit layers (5, 6, 8); TEE deployments add
hardware isolation, KMS-backed secrets, encrypted storage, config locking,
and the vsock network controls (layers 1-4, 7).

For TEE implementation details (KMS bootstrap code, encrypted store layer,
config changes), see [TEE Enclave Security Design](tee-architecture.md).

## Security Layers

### Layer 1: Hardware Isolation (Nitro Enclave)
- Enclave runs in isolated memory -- parent EC2 cannot read enclave RAM
- No direct network access -- all I/O through vsock channels
- `/dev/nsm` provides hardware-backed attestation and entropy
- Hypervisor enforces isolation (not software-based)

### Layer 2: KMS-Backed Secrets
- Master seed generated inside enclave using NSM-backed random
- Encrypted with AWS KMS before leaving enclave memory
- KMS key policy requires PCR0 (image hash) + PCR8 (signing cert)
- Only the exact enclave image + signing cert can decrypt secrets
- JWT signing key also KMS-encrypted with fingerprint verification
- KMS calls are **attestation-gated**: `GenerateDataKey` and `Decrypt` pass a
  `Recipient` carrying an NSM attestation document, and KMS returns
  `CiphertextForRecipient` wrapped (RSAES-OAEP-SHA256) to an ephemeral RSA-2048
  key generated inside the enclave. The seed / data-key plaintext is therefore
  never exposed to the parent, even on the vsock + TLS path to KMS.

### Layer 3: Encrypted Storage
- All fjall keyspace values encrypted with AES-256-GCM
- Storage key derived from master seed via HKDF-SHA256
- Deterministic derivation -- same seed produces same key across restarts
- Keys stored in plaintext for prefix scans; values always encrypted
- Each value: `[4-byte magic "VAE1"][12-byte random nonce][ciphertext + 16-byte GCM tag]`, AEAD-bound (AAD) to its `(keyspace, key)` location

### Layer 4: Configuration Locking
- When KMS bootstrap is active, environment variable overrides are blocked
- Only `VTA_LOG_LEVEL` and `VTA_LOG_FORMAT` remain configurable
- Prevents parent-side attacker from injecting `VTA_DID`, `VTA_AUTH_JWT_SIGNING_KEY`, etc.
- Config baked into EIF at build time -- immutable after signing

### Layer 5: Identity & Access Control
- DID-based authentication via challenge-response (Ed25519 signatures)
- Role hierarchy: super-admin > admin > initiator > application > reader > monitor
- Action classification: every endpoint is classified as read, write, or manage
  - **Reader**: read-only access to business data (keys, contexts, DIDs) within allowed contexts
  - **Application**: can sign and write to cache (write actions)
  - **Initiator**: can manage ACL entries and credentials (manage actions)
  - **Admin**: full key/DID/audit management within contexts
  - **Monitor**: infrastructure-only (metrics, health)
- Context scoping restricts access to assigned application contexts
- Optional DID-method allowlist (`tee.allowed_did_methods`, TEE-only, off by default) can restrict which DID methods may authenticate
- Session state machine prevents challenge replay

### Layer 6: VTA Seal
- After initial admin bootstrap, VTA is "sealed"
- All offline CLI commands (key management, ACL changes) disabled
- Management only via authenticated REST/DIDComm
- Unsealing requires challenge-response proof of admin key ownership
- In TEE mode, seal marker is AES-256-GCM encrypted in storage

Operator-facing detail (when the seal is set, when it gets in the way,
how to unseal, and the bootstrap-then-seal-last pattern that avoids
the unseal dance) lives in
[`02-vta/seal-and-unseal.md`](../02-vta/seal-and-unseal.md).

### Layer 7: Network Controls
- Seven vsock channels with strict purpose separation (all network I/O is
  brokered by the parent-side proxy -- the enclave has no direct network):
  - Inbound REST (port 5100): client requests to VTA
  - Outbound mediator (port 5200): DIDComm messaging with TLS
  - Outbound HTTPS (port 5300): allowlisted destinations only (KMS, etc.)
  - IMDS credential proxy (port 5400): IMDSv2, hop-limited
  - Storage proxy (port 5500): fjall keyspace I/O -- ciphertext only
  - DID resolver bridge (port 5600): resolver sidecar on the parent
  - Log forwarding (port 5700): enclave logs forwarded to parent stdout
- HTTPS CONNECT proxy validates every request against allowlist
- Non-CONNECT requests rejected with 405 Method Not Allowed
- Connection limits prevent resource exhaustion
- Request body size limits protect enclave memory

#### Enclave Proxy Architecture

```mermaid
graph LR
    subgraph Enclave
        VTA[VTA Service]
    end
    subgraph Parent EC2
        Proxy[Enclave Proxy]
        Store[(fjall Store)]
        Resolver[DID Resolver Sidecar]
    end
    subgraph External
        Mediator[Mediator]
        KMS[AWS KMS]
        IMDS[IMDS 169.254.169.254]
    end
    Client -->|TCP :8443| Proxy
    Proxy -->|vsock :5100| VTA
    VTA -->|vsock :5200| Proxy -->|TLS| Mediator
    VTA -->|vsock :5300| Proxy -->|HTTPS CONNECT| KMS
    VTA -->|vsock :5400| Proxy --> IMDS
    VTA -->|vsock :5500| Proxy --> Store
    VTA -->|vsock :5600| Proxy --> Resolver
    VTA -->|vsock :5700| Proxy --> Logs[Parent stdout]
```

### Layer 8: Audit & Observability
- Structured audit events at target "audit" -- never suppressed by log level
- All security operations logged: auth, ACL changes, key operations, exports
- Health endpoint split: minimal (public) vs. detailed (authenticated)
- Graceful shutdown with store persistence guarantees

## Key Lifecycle

```
1. First Boot (inside enclave):
   ┌─────────────────────────────────────────┐
   │ Generate 256-bit entropy (/dev/nsm)     │
   │ → BIP-39 mnemonic (24 words)            │
   │ → BIP-32 master seed (512 bits)         │
   │ → KMS Encrypt(seed) → seed.enc          │
   │ → Generate JWT key (256 bits)            │
   │ → KMS Encrypt(jwt) → jwt.enc            │
   │ → HKDF(seed, salt) → storage key        │
   │ → Start mnemonic export window           │
   └─────────────────────────────────────────┘

2. Key Derivation (BIP-32 hierarchy):
   m/26'/2'/N'/K'
   │       │  │
   │       │  └── Key counter (sequential)
   │       └───── Context index (sequential)
   └────────────── FPN reserved prefix

3. Subsequent Boot:
   ┌─────────────────────────────────────────┐
   │ Read seed.enc + jwt.enc from EBS        │
   │ → KMS Decrypt(seed.enc) → seed          │
   │ → KMS Decrypt(jwt.enc) → jwt key        │
   │ → Verify JWT fingerprint (SHA-256)       │
   │ → HKDF(seed, salt) → same storage key   │
   │ → Open encrypted fjall store             │
   │ → Resume operations                      │
   └─────────────────────────────────────────┘

4. Key Rotation:
   ┌─────────────────────────────────────────┐
   │ Generate new seed (or import mnemonic)   │
   │ → Mark old seed generation as "retired"  │
   │ → New keys derived from new seed         │
   │ → Old keys remain readable (old seed)    │
   │ → Re-encrypt imported secrets with new   │
   │   seed-derived KEK                       │
   └─────────────────────────────────────────┘

5. Imported Key (external, non-BIP-32):
   ┌─────────────────────────────────────────┐
   │ Receive private key via REST (JWE-      │
   │   wrapped with ephemeral ECDH-ES) or    │
   │   DIDComm (E2E encrypted)               │
   │ → Validate key type + length            │
   │ → Derive public key, verify consistency │
   │ → HKDF(seed, salt) → KEK               │
   │ → AES-256-GCM(KEK, nonce, key,         │
   │     AAD=key_id:key_type)                │
   │ → Store ciphertext in imported_secrets  │
   │ → KeyRecord with origin=imported        │
   │                                          │
   │ On revoke: overwrite blob → delete       │
   │ On seed rotation: re-encrypt all         │
   │ On backup: plaintext inside encrypted    │
   │   envelope (Argon2id + AES-256-GCM)      │
   └─────────────────────────────────────────┘
```

**Boot with a KMS decrypt failure (fail-closed).** On a subsequent boot, if
`KMS Decrypt` of the stored `seed.enc` / `jwt.enc` fails, the VTA does **not**
blindly regenerate its identity. Only an `AccessDenied` result -- the expected
signal after an image rebuild changes PCR0 -- or an explicit
`tee.kms.allow_kms_reinit = true` clears the bootstrap keyspace and mints a
fresh identity. Every other error class (KMS internal, network, invalid
ciphertext, unknown) is treated as a transient outage or possible tampering:
the VTA refuses to start rather than silently reset its DID and keys. Resetting
a live identity is thus always a deliberate, logged action.

## Authentication Flow

```
Client                          VTA (in enclave)
  │                                  │
  │  POST /auth/challenge {did}      │
  │ ─────────────────────────────►   │
  │                                  │ ← Check DID whitelist
  │                                  │ ← Check DID in ACL
  │                                  │ ← Generate 32-byte nonce
  │                                  │ ← Store nonce (replay detection)
  │                                  │ ← Generate attestation report
  │  {sessionId, challenge,          │
  │   tee_attestation}               │
  │ ◄─────────────────────────────   │
  │                                  │
  │  (client verifies attestation)   │
  │  (client signs challenge)        │
  │                                  │
  │  POST /auth/ (DIDComm packed)    │
  │ ─────────────────────────────►   │
  │                                  │ ← Unpack DIDComm (verify sig)
  │                                  │ ← Validate session state
  │                                  │ ← Verify challenge match
  │                                  │ ← Check challenge TTL
  │                                  │ ← Issue JWT (EdDSA signed)
  │  {accessToken, refreshToken}     │
  │ ◄─────────────────────────────   │
  │                                  │
  │  GET /keys (Bearer token)        │
  │ ─────────────────────────────►   │
  │                                  │ ← Validate JWT signature
  │                                  │ ← Check expiry, role, contexts
  │  {keys: [...]}                   │
  │ ◄─────────────────────────────   │
```

## Threat Model

### Trust Boundaries

```
┌──────────────────────────────────┐
│        Untrusted Zone            │
│  (Internet, external clients)    │
└──────────────┬───────────────────┘
               │ HTTPS (TLS)
┌──────────────┴───────────────────┐
│     Semi-Trusted Zone            │
│  (Parent EC2 instance)           │
│  - enclave-proxy                 │
│  - EBS (fjall, ciphertext only)  │
│  - IAM role (limited)            │
└──────────────┬───────────────────┘
               │ vsock (no network)
┌──────────────┴───────────────────┐
│       Trusted Zone               │
│  (Nitro Enclave)                 │
│  - VTA service                   │
│  - Plaintext secrets (memory)    │
│  - Storage encryption key (mem)  │
│  - /dev/nsm (attestation)        │
└──────────────────────────────────┘
```

### Adversary Model

#### A1: Network Attacker
**Capabilities:** Intercept/modify network traffic between clients and the VTA.
**Mitigations:**
- TLS termination on parent proxy (inbound)
- DIDComm authenticated encryption (end-to-end)
- HTTPS CONNECT proxy with allowlist (outbound)

#### A2: Compromised Parent Instance
**Capabilities:** Root access to the EC2 host. Can read or roll back EBS, modify the proxy, inject env vars.
**Mitigations:**
- Nitro Enclave memory isolation (hypervisor-enforced)
- KMS key policy with PCR pinning (PCR0 + PCR8)
- Environment variable locking when KMS bootstrap active
- Storage encrypted with AES-256-GCM (key only in enclave memory)
- Attestation reports prove enclave identity to clients
- KMS `Decrypt` / `GenerateDataKey` responses are attestation-encrypted
  (`Recipient` -> `CiphertextForRecipient`), so a root parent cannot read the
  seed / data-key plaintext even by MITM'ing the vsock or TLS path to KMS
- Anti-rollback anchor: an external monotonic counter (DynamoDB, attestation-gated
  writer) detects EBS snapshot rollback / state replay when configured (`tee.kms.anchor`)
- Optional DID-method allowlist (`tee.allowed_did_methods`) restricts which DID methods may authenticate, enforced at auth time (off unless configured)

#### A3: Supply Chain Attacker
**Capabilities:** Modify the enclave image or signing certificate.
**Mitigations:**
- PCR0 (image hash) pinned in KMS key policy
- PCR8 (signing cert hash) pinned in KMS key policy
- EIF signing with P-384 key (stored offline)
- KMS Decrypt fails if PCRs don't match -- secrets inaccessible

#### A4: Insider with Admin Access
**Capabilities:** Valid admin DID credentials. Can manage keys, ACL, config.
**Mitigations:**
- Role-based access control (admin, initiator, application)
- Context scoping limits admin to assigned contexts
- Structured audit logging (target: "audit") for all admin operations
- VTA seal prevents offline CLI manipulation after deployment
- Mnemonic export is time-limited and one-time only

#### A5: Denial of Service
**Capabilities:** Flood endpoints with requests.
**Mitigations:**
- Request body size limits (1MB default)
- Connection limits on proxy (semaphore-based)
- Store operation timeouts (30s)
- Rate limiting on auth endpoints (recommended via reverse proxy)

### Attack Trees

#### AT1: Steal Master Seed
```
Steal master seed
├── Read enclave memory → BLOCKED (Nitro hypervisor)
├── Decrypt seed.enc from EBS
│   ├── Obtain KMS Decrypt access
│   │   ├── Modify KMS key policy → requires admin MFA
│   │   └── Spoof PCR values → BLOCKED (hardware-measured)
│   └── Brute-force AES-256 → computationally infeasible
├── Export mnemonic via API
│   ├── Obtain super-admin JWT
│   │   ├── Steal JWT signing key → only in enclave memory
│   │   └── Brute-force Ed25519 → computationally infeasible
│   └── Bypass time window → entropy zeroed after window
└── Intercept during KMS Decrypt
    ├── MITM vsock proxy → end-to-end TLS enclave↔KMS (CONNECT tunnel,
    │   not terminated by the parent; system CA bundle in-enclave)
    └── Read KMS response → attestation-encrypted to enclave
        (CiphertextForRecipient, RSAES-OAEP to in-enclave RSA-2048)
```

#### AT2: Impersonate VTA
```
Impersonate VTA
├── Forge attestation report → requires /dev/nsm (enclave-only)
├── Replace enclave image
│   └── KMS Decrypt fails (PCR0 mismatch) → no secrets
├── Run VTA outside enclave
│   └── tee.mode = "required" → refuses to start
└── Inject config via env vars
    └── KMS lock blocks all security-relevant env overrides
```

#### AT3: Privilege Escalation
```
Escalate privileges
├── Modify ACL via CLI → BLOCKED by VTA seal
├── Tamper with fjall store directly
│   └── AES-256-GCM encrypted → requires storage key
├── Forge JWT token
│   └── Ed25519 signing key only in enclave memory
├── Replay auth challenge
│   └── Nonce stored in session KS, state machine prevents replay
├── Roll back EBS to pre-revocation state
│   └── Anti-rollback anchor (monotonic counter) detects stale state
└── Create admin via API
    └── Requires existing admin/initiator JWT with Manage role
```

### Residual Risks

| Risk | Severity | Status | Notes |
|------|----------|--------|-------|
| KMS Recipient parameter | n/a | Implemented | `GenerateDataKey`/`Decrypt` use an attestation-bound `Recipient`; KMS returns `CiphertextForRecipient` (RSAES-OAEP-SHA256) to an ephemeral in-enclave RSA-2048 key, so the parent never sees plaintext |
| EBS snapshot rollback / state replay | Medium | Mitigated (config-gated) | Anti-rollback anchor (external monotonic counter, DynamoDB, attestation-gated writer) detects replayed state when `tee.kms.anchor` is set; manifest-only if unset |
| No per-IP rate limiting in VTA | Low | Mitigated | Deploy behind reverse proxy with rate limiting |
| Health endpoint information disclosure | Low | Fixed | Split into minimal (public) and detailed (auth required) |
| DID resolver through parent | Low | Mitigated | Whitelist blocks `did:web`; `did:key` and `did:webvh` are self-certifying |

## Cryptographic Inventory

| Algorithm | Purpose | Key Size | Standard |
|-----------|---------|----------|----------|
| Ed25519 | Signing, authentication | 256-bit | RFC 8032 |
| X25519 | Key agreement (DIDComm) | 256-bit | RFC 7748 |
| AES-256-GCM | Storage encryption | 256-bit | NIST SP 800-38D |
| HKDF-SHA256 | Storage key derivation | 256-bit | RFC 5869 |
| BIP-39 | Mnemonic seed generation | 256-bit entropy | BIP-39 |
| BIP-32 | Hierarchical key derivation | Ed25519 | BIP-32/SLIP-0010 |
| SHA-256 | JWT fingerprint, nonce hashing | 256-bit | FIPS 180-4 |
| ECDSA P-384 | EIF signing (Nitro) | 384-bit | FIPS 186-4 |
| COSE_Sign1 | Attestation reports (Nitro) | ES384 | RFC 8152 |
| RSAES-OAEP-SHA256 | KMS attested `Recipient` (data-key unwrap) | RSA-2048 (ephemeral) | PKCS#1 v2.2 |
| AES-256-CBC | KMS `CiphertextForRecipient` CMS content encryption | 256-bit | RFC 5652 / NIST SP 800-38A |

## Deployment Security Checklist

- [ ] TEE mode set to `required` (not `optional` or `simulated`)
- [ ] Parent instance is enclave-eligible (Graviton `.large`+ / x86 `.xlarge`+; T-family is not enclave-capable)
- [ ] KMS key policy pinned to PCR0 + PCR8
- [ ] EIF signed with offline P-384 key
- [ ] IAM role limited to `kms:GenerateDataKey` + `kms:Decrypt` (both attestation-gated)
- [ ] KMS admin requires MFA for policy changes
- [ ] Anti-rollback anchor configured (`tee.kms.anchor`) if rollback protection is required
- [ ] DID method whitelist: `["did:key", "did:webvh"]`
- [ ] Reverse proxy with TLS, rate limiting, CORS policy
- [ ] Mnemonic exported and stored securely offline
- [ ] VTA sealed after admin bootstrap
- [ ] Audit logs shipped to SIEM
- [ ] CloudTrail alerts on KMS policy changes
- [ ] Health endpoint accessible only to monitoring systems
