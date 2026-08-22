# Sealed Bootstrap: Unified Secret Transfer Design

Status: **Implemented.** Retained as the design record — the rationale below is
still the reason the code is shaped as it is, but do not read the phase plan in
§"Phased rollout" as outstanding work. Spot-checked against the tree: the
`vta_sdk::sealed_transfer` module and the `vta bootstrap` / `pnm bootstrap`
surfaces (phases 1–2), the unified `POST /bootstrap/request` with its single-use
`BOOTSTRAP_CARVEOUT_CLOSED_KEY` and the retired
`GET /attestation/admin-credential` (phase 3), `keys/wrapping.rs` built on
`sealed_transfer` (phase 4), and no plaintext bundle encode paths left in
`vta-sdk` (phase 5).

The stale header cost at least one reader a wrong assumption in a downstream
design doc (#1030), which is the cost of a status line nobody owns: it is
written once, at the moment it is least likely to be true for long.

Scope: workspace-wide (`openvtc`, `verifiable-trust-infrastructure`)

## Problem

Multiple tools across the workspace move sensitive material (BIP-39 mnemonics, admin credentials, context provision bundles, DID secret exports) across trust boundaries via copy/paste, CLI arguments, or unauthenticated REST endpoints:

- `openvtc-cli2` — TUI paste field for base64url `CredentialBundle` (`src/ui/pages/setup_flow/vta_credential.rs`)
- `did-git-sign` — `--credential <base64>` on argv, visible in `ps` (`src/main.rs:46`)
- `pnm-cli` — stdin paste in `setup.rs:39-50`
- `openvtc-cli` legacy — 24-word mnemonic word-by-word, armored PGP paste
- `vta-service` — hex seed prompt into plaintext `config.toml`
- `vta-service` (TEE mode) — `GET /attestation/admin-credential`: unauthenticated, unattested, one-time fetch. Credential sits in `bootstrap:tee:admin_credential` keyspace in plaintext until retrieved.

`CredentialBundle`, `ContextProvisionBundle`, and `DidSecretsBundle` are JSON-in-base64 with no encryption envelope — any time they cross a boundary, plaintext is exposed.

## Goals

1. Zero secrets on argv, env, clipboard, or terminal paste.
2. Every sensitive bundle encrypted end-to-end to a recipient-chosen ephemeral key.
3. Single-use, replay-resistant transport with mandatory integrity verification.
4. Attestation-bound sessions for TEE VTAs (strictly stronger than today's unauthenticated fetch).
5. ACL entries with configurable expiry; a "bootstrap" role that cannot escalate.
6. Uniform client UX across TEE and non-TEE VTAs (one command, same format).

## Three modes, one wire format

| Mode | When | Trust anchor |
|---|---|---|
| **A. Online, non-TEE** | Operator adds a new client to an existing VTA | Operator-issued one-time token (ephemeral, role+context-bound ACL entry) |
| **B. Online, TEE first-boot** | A fresh TEE VTA with no admin configured | Attestation quote binding client pubkey + nonce + VTA pubkey |
| **C. Offline / cold-start** | VTA unreachable; file-based transfer | Pinned producer pubkey + mandatory out-of-band digest verification |

After a TEE VTA's first successful bootstrap (Mode B), all subsequent client bootstraps to that VTA use Mode A. The TEE carve-out is one-shot.

From the client's perspective, Modes A and B are **indistinguishable**: same CLI, same endpoint, same response shape. The server chooses the authorization branch; the response assertion variant differs but is verified by the same code path.

## Primitive: `vta-sdk::sealed_transfer`

Shared module used by every producer and consumer in both workspaces.

```
sealed_transfer/
  mod.rs          // public API
  request.rs      // BootstrapRequest (consumer → producer)
  bundle.rs       // SealedBundle, SealedPayloadV1, ProducerAssertion
  armor.rs        // ASCII armor (+CRC24, headers as AAD)
  chunk.rs        // chunking / reassembly
  nonce.rs        // NonceStore trait (pnm-cli impl: keyring-backed)
  hpke.rs         // RFC 9180 wiring
  error.rs
```

### Cryptography

- HPKE (RFC 9180), suite `0x0020, 0x0001, 0x0003`:
  - KEM: DHKEM(X25519, HKDF-SHA256)
  - KDF: HKDF-SHA256
  - AEAD: ChaCha20-Poly1305
- Chunk headers (version, bundle-id, chunk index, total chunks, digest algo) are bound as AEAD AAD — a MITM cannot reshuffle or truncate chunks without detection.
- CRC24 trailing checksum (OpenPGP-style) for early corruption detection on pasted text.

### Payload (tagged, extensible)

```rust
pub enum SealedPayloadV1 {
    AdminCredential(CredentialBundle),
    ContextProvision(ContextProvisionBundle),
    DidSecrets(DidSecretsBundle),
    AdminKeySet(Vec<LabeledKey>),  // multi-admin / future expansion
}
```

Every sensitive bundle type in the workspace becomes a variant here. After Phase 5, these types lose their plaintext-JSON-in-base64 encode paths — sealed-transfer is the only way they move.

### Producer assertion (how the consumer establishes trust)

```rust
pub struct ProducerAssertion {
    pub producer_did: String,      // Ed25519 did:key pinned by consumer
    pub proof: AssertionProof,
}

pub enum AssertionProof {
    DidSigned { did: String, signature: Signature },  // Modes A & C (when VTA DID known)
    Attested { quote: AttestationQuote },             // Mode B
    PinnedOnly,                                       // Mode C with OOB digest only
}
```

### Wire format (inside the armor)

```
HpkeSealed {
  kem_encap: [u8; 32],         // X25519 ephemeral public (RFC 9180 KEM)
  aead_ciphertext: Vec<u8>,    // CBOR-encoded ChunkPlaintext, AEAD-sealed
}

ChunkPlaintext {
  version: u8,                 // = 1
  bundle_id: [u8; 16],
  chunk_index: u16,
  total_chunks: u16,
  producer_did: Option<String>,  // chunk 0 only; Ed25519 did:key pinned by consumer
  producer_assertion: Option<ProducerAssertion>,  // chunk 0 only
  payload_fragment: Vec<u8>,
}
```

Every public-key surface — `client_did`, `producer_did`, VTA DID, admin DID —
is a DID. HPKE still operates on raw X25519 bytes internally; those are derived
on demand (public via `Edwards::to_montgomery`, private via `SHA-512(seed)[0..32]`
clamped) and stay inside the cipher layer.

### Armor format

PGP/SSH-style, 64-char line wrap:

```
-----BEGIN VTA SEALED BUNDLE-----
Version: 1
Bundle-Id: 7f3a9c2e4b1d5a80
Chunk: 1/3
Digest-Algo: sha256

base64base64base64base64base64base64base64base64base64base64base64
base64base64base64base64base64base64base64base64base64base64base64
=Xy9Q
-----END VTA SEALED BUNDLE-----
```

Single-chunk bundles use `1/1` framing — no special case. Multi-chunk output emits the blocks concatenated with blank lines between; readers scan for all `BEGIN/END` pairs in a single input and group by `Bundle-Id`.

### Single-use nonce

`NonceStore` trait; `pnm-cli`'s implementation persists in the existing keyring namespace (`vta:<slug>:sealed-nonces`). `seal()` records `bundle_id` at production time and refuses to re-seal the same request — forces regeneration on failure (documented in CLI `--help`).

### Digest verification (strict by default)

`open()` requires `--expect-digest <hex>`. `--no-verify-digest` is available but must be explicitly passed and prints a warning. No silent TOFU.

### Label privacy

- `BootstrapRequest.label` — plaintext (operator needs to see who they're sealing to).
- `SealedBundle` — label excluded.
- Default bundle filename: `bundle-<bundle_id_prefix>.armor` — not label-based. File listings reveal nothing about destinations.

## ACL changes (`vti-common`)

### New field

```rust
pub struct AclEntry {
    // ... existing fields ...
    pub expires_at: Option<u64>,   // NEW: None = permanent (existing behavior)
}
```

`#[serde(default)]` on `expires_at` so existing stored entries deserialize without migration.

### New role

```rust
pub enum Role {
    Admin,
    Initiator,
    Application,
    Reader,
    Monitor,
    Bootstrap,  // NEW — one-shot, narrow
}
```

`Bootstrap` role permissions are hardcoded and non-composable:

1. Authenticate as the DID.
2. Complete the pre-approved bootstrap swap (server-side state determines role + contexts of the resulting credential — client has no say).
3. Nothing else. No read, no sign, no ACL management, no context access.

### New ACL record variant

```rust
pub struct PendingBootstrap {
    pub token_hash: [u8; 32],      // hash(token) — lookup key
    pub target_role: Role,         // frozen at issue time (never Bootstrap or Admin without authority)
    pub target_contexts: Vec<String>,
    pub expires_at: u64,
    pub issued_by: String,         // DID of the operator who issued this
    pub issued_at: u64,
    pub label: Option<String>,
}
```

Stored in the same ACL keyspace as `AclEntry`, tagged-deserialized. Existing `AclEntry` rows are untouched.

### Sweeper

Background task in `vta-service` periodically prunes both expired `AclEntry` (where `expires_at` has passed) and expired `PendingBootstrap` entries.

## Unified endpoint: `POST /bootstrap/request`

Single endpoint for Modes A and B. Policy-gated on the server; uniform shape to the client.

```
POST /bootstrap/request
Body: { client_did, nonce, token: Option<String>, label: Option<String> }
Response: ArmoredBundle (SealedBundle, HPKE-sealed to X25519 derived from client_did)
```

`client_did` is an Ed25519 `did:key:z6Mk…`. The server derives the X25519
pubkey locally for HPKE; the client holds the Ed25519 seed and derives the
X25519 secret at open time. Every public-key surface in the protocol is a
DID; the X25519 conversion is an internal detail of the HPKE layer.

Server authorization logic (in order):

1. If `token` is present: look up `PendingBootstrap` by `hash(token)`. Must exist, not be expired. Mint credential with **exactly** the stored `target_role` + `target_contexts`. Atomic transaction: delete `PendingBootstrap`, insert `AclEntry`. Assertion = `DidSigned`.
2. Else if TEE and first-boot carve-out is active (no admin configured and no prior successful bootstrap): generate attestation quote with `user_data = SHA256(client_pubkey || nonce || vta_pubkey)`, mint Admin credential (no context restriction), disable the carve-out permanently, record the swap. Assertion = `Attested(quote)`.
3. Else: reject.

**Unknown fields in the request body are rejected** (strict JSON deserialization) — a client cannot smuggle in `requested_role` or similar fields that would influence minting.

### Token issuance

Operator CLI:

```
vta bootstrap issue-token --role <role> [--contexts a,b,c] --expires <duration> [--label <name>]
  → prints: ABCD-1234-EFGH-5678-IJKL-9012 (one-time display)

vta bootstrap list-tokens
  → metadata only, never the token

vta bootstrap revoke-token <id-or-label>
```

Token entropy: ~120 bits (six groups of four base32 chars) — pasteable but not brute-forceable. Rate-limit `POST /bootstrap/request` per source IP as a secondary defense.

### Issuer role hierarchy

Preserves existing role hierarchy; issuance is itself ACL-gated:

| Issuer's role | Can issue tokens for |
|---|---|
| Admin | any role, any contexts |
| Initiator | Application, Reader, Monitor — within contexts the Initiator already has |
| Application / Reader / Monitor | nothing |

### Escalation resistance walkthrough

1. Malicious client receives a token issued for `Application` / `ctx-a`.
2. Client bootstraps successfully, receives an Application credential scoped to `ctx-a`.
3. Client tries `POST /acl` to add itself to `ctx-b`, or to upgrade to Admin.
4. Rejected by **existing** ACL enforcement (`check_acl()`): Application role lacks ACL-management permissions; even Initiator cannot grant Admin.

The `Bootstrap` role exists only inside the single `POST /bootstrap/request` transaction. It is deleted atomically with the creation of the new `AclEntry`. Post-bootstrap, the client is a normal ACL subject with no residual bootstrap authority.

## Unified client UX

### Online (Modes A + B, identical command)

```
pnm-cli bootstrap connect --vta-url https://vta.example.com [--token ABCD-...] [--expect-digest <hex>]
cnm-cli bootstrap connect ...                              # mirrors pnm-cli
openvtc-cli2                                               # setup wizard → same flow under the hood
```

- Connecting to a first-boot TEE VTA: `--token` omitted. Client verifies attestation quote; quote's `user_data` must match `SHA256(client_ed25519_pub || nonce || producer_ed25519_pub)` — the raw Ed25519 pubkeys underlying `client_did` (what the client sent) and `producer_did` (what the bundle's `ProducerAssertion` carries).
- Any other VTA: `--token` required.

### Offline (Mode C)

```
# On the consumer host
pnm-cli bootstrap request --out bootstrap-request.json

# Transfer request to producer host (content: pubkey + nonce + label; no secrets)

# On the producer host
vta bootstrap seal --request bootstrap-request.json --out bundle.armor [--payload ...]
# (Or: pnm-cli bootstrap seal ... — same subcommand surface for offline-configured peers)

# Transfer bundle to consumer host; communicate digest out-of-band

# On the consumer host
pnm-cli bootstrap open --bundle bundle.armor --expect-digest <hex>
```

### What goes away

- `openvtc-cli2` VTA credential TUI paste page — replaced by connect/open flow.
- `did-git-sign --credential <base64>` argv — replaced by `--credential-bundle <file>` (armored). No backwards-compat shim.
- `pnm-cli` stdin paste in `setup.rs:39-50`.
- `GET /attestation/admin-credential` and the `bootstrap:tee:admin_credential` keyspace.
- Plaintext encode paths on `CredentialBundle` / `ContextProvisionBundle` / `DidSecretsBundle` (Phase 5).

## Phased rollout

1. **Phase 1** — `vta-sdk::sealed_transfer` module + unit tests. `vta bootstrap seal` (producer). `pnm-cli bootstrap open` (consumer). Mode C working end-to-end.
2. **Phase 2** — ACL `expires_at` + `Bootstrap` role + `PendingBootstrap` variant + sweeper. `vta bootstrap issue-token / list-tokens / revoke-token`. Unified `POST /bootstrap/request` (non-TEE). `pnm-cli bootstrap connect`. `openvtc-cli2` cutover.
3. **Phase 3** — TEE first-boot attestation path on `POST /bootstrap/request`. Delete `GET /attestation/admin-credential` and `bootstrap:tee:admin_credential` keyspace. Migration logic for upgrading instances (see below).
4. **Phase 4** — Refactor `vta-service/keys/wrapping.rs` to use `sealed_transfer`. Retire the parallel ECDH-ES wrapping implementation used for REST key import.
5. **Phase 5** — Remove plaintext encode paths from `CredentialBundle` / `ContextProvisionBundle` / `DidSecretsBundle`. Sealed-only from here.

## Upgrade path for existing VTAs

**Existing VTA deployments upgrade in place. No clean install required.** Existing contexts and ACL entries continue to work.

### Schema-compatible changes (no migration required)

- `AclEntry.expires_at` is `Option<u64>` with `#[serde(default)]` — existing entries deserialize as `None` (permanent), preserving current behavior.
- New `Role::Bootstrap` variant — additive; never present on pre-upgrade entries.
- New `PendingBootstrap` ACL record variant — tagged deserialization leaves existing `AclEntry` rows untouched.
- Already-bootstrapped `pnm-cli` / `openvtc-cli2` / `cnm-cli` installations — their cached credentials remain valid. Only the mechanism for delivering **new** credentials changes.

### One-time migrations (Phase 3 startup)

On the first run of the new binary against an existing VTA store:

1. **TEE instances with an unclaimed admin credential**: if `bootstrap:tee:admin_credential` contains an entry (meaning the old REST-fetch path was set up but never completed), auto-migrate: extract the credential, create a regular Admin `AclEntry` for its did:key, delete the `bootstrap:tee:admin_credential` keyspace. The operator retains any copies of the credential they already have. No coordinated downtime needed.
2. **Deprecated endpoint removal**: `GET /attestation/admin-credential` returns 404 after upgrade. The only legitimate caller was `pnm-cli` during first bootstrap, and `pnm-cli` ships the new flow in the same release. External callers (if any) must migrate.

### Phase 5 considerations

Removing plaintext encode paths from the three bundle types is the one change visible to anything externally sharing those formats. All internal workspace consumers move together in this phase. No migration window — cut over.

### Recommended upgrade order

1. VTA instances first (server-side changes land; existing clients keep working with their cached credentials).
2. `pnm-cli` / `cnm-cli` / `openvtc-cli2` / `did-git-sign` — new bootstraps use the new flow; existing sessions untouched.
3. Phase 5 lands last, once all workspace tools are on the new transport.

### Not covered by upgrade (true lost-secret scenarios)

A TEE instance that booted with the old admin-credential REST-fetch path and whose credential was lost before upgrade would need to be re-bootstrapped. This is a lost-credentials recovery scenario, not an upgrade-path problem — it would be equally broken without this change.

## Security properties after full rollout

- Zero secrets on argv, env, clipboard, or terminal paste across all workspace tools.
- Every sensitive bundle encrypted end-to-end to a recipient-chosen ephemeral X25519 key.
- Single-use `bundle_id` enforcement against replay.
- Mandatory digest verification (opt-out requires explicit flag).
- Attestation-bound sessions for TEE first-boot; stronger than today's unauthenticated REST fetch.
- ACL entries auto-expire; `Bootstrap` role is one-shot and cannot be used for anything except completing its own pre-approved swap.
- Role + contexts frozen at token issuance time; client cannot influence minting parameters.
- Uniform client UX — one command for all online VTA topologies.

## Open points (resolved)

| Question | Resolution |
|---|---|
| Digest verification default | Required (explicit `--no-verify-digest` to bypass) |
| `Bootstrap` role composition | Single non-composable role with 3 hardcoded permissions |
| Bundle-format migration window | None — direct cutover |
| `cnm-cli` treatment | Mirrors `pnm-cli` |
| `Mode B` vs `Mode A` client UX | Unified into one endpoint and one client command |
| Role + context escalation during bootstrap | Prevented by server-side `PendingBootstrap` state; client has no say |
| Upgrade path | In-place upgrade; auto-migration for TEE unclaimed-credential case |
