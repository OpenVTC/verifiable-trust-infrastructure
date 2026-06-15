# VTC backup / restore — design note (P3.9)

Status: **accepted** — decisions locked (see "Decisions" below), ready to
implement.

## Problem

The VTC holds a community's **irreplaceable social state** — members, ACL,
endorsements, relationships, policies, the audit log, and the bitstring
**status lists** whose loss bricks every issued VMC's `credentialStatus` URL.
Today the only export is `POST /v1/admin/config/export`
(`routes/admin/config.rs:455`), which carries the community profile + config
overrides and nothing else. Disk loss = community loss.

The VTA already ships full encrypted backup/restore
(`vta-service/src/operations/backup/`). This note proposes porting that pattern
to the VTC, adapting it to the VTC's 21-keyspace model and its `vtc_did`
identity, and resolving the three VTC-specific decisions the VTA design didn't
face.

## Goals / non-goals

**Goals**
- One password-encrypted artifact that round-trips the community's durable
  state: populate every keyspace → export → wipe data dir → import → daemon
  serves byte-identical state.
- Identity guard: importing a backup whose `vtc_did` differs from a *configured*
  VTC is refused (409); a *fresh* install accepts any backup (disaster
  recovery).
- A **keyspace census** test: every one of `keyspaces::ALL` is either backed up
  or explicitly excluded — none silently omitted (this is what P2.5's registry
  buys us).
- Crash-safe import: a sentinel written before the destructive clear, removed
  only on success; boot refuses to start mid-import.

**Non-goals**
- TEE / KMS re-encryption (the VTA's import does this; the VTC never targets
  TEE — drop that path entirely).
- BIP-32 path-counter restoration (the VTA needs it; the VTC isn't a key
  authority and derives no keys — drop it).
- Incremental / differential backup. Full snapshot only, matching the VTA.
- Live migration between two running VTCs. Backup → restore is offline-shaped.

## Crypto — reuse the VTA's parameters verbatim

No new cryptography. Same KDF + cipher, same envelope crypto fields, same
import-side bounds (the only sensible choice — it's already reviewed and the
house rule pins these crates):

- **KDF**: Argon2id (v0x13), `m_cost = 65536` (64 MiB), `t_cost = 3`,
  `p_cost = 4`, 32-byte salt, 32-byte derived key.
- **Cipher**: AES-256-GCM, 12-byte nonce, random salt+nonce per export (OsRng).
- **Encoding**: `base64::URL_SAFE_NO_PAD` for salt / nonce / ciphertext.
- **Password**: minimum 12 chars at export (`Validation` → 400).
- **Import bounds** (anti-memory-bomb on untrusted envelopes): `m_cost ∈
  [8 MiB, 1 GiB]`, `t_cost ∈ [1,10]`, `p_cost ∈ [1,16]`; algorithm strings must
  equal `argon2id` / `aes-256-gcm`; salt/nonce length-checked before
  `from_slice`. AES-GCM auth failure → `Authentication` (401) "incorrect backup
  password", **not** Validation.

## Envelope + payload schema

Envelope (outer, unencrypted metadata) — structurally identical to the VTA's,
with VTC naming:

```rust
pub struct BackupEnvelope {
    pub version: u32,            // 1
    pub format: String,         // "vtc-backup-v1"
    pub created_at: DateTime<Utc>,
    pub source_did: Option<String>,   // vtc_did
    pub source_version: String,       // env!("CARGO_PKG_VERSION")
    pub kdf: KdfParams,
    pub encryption: EncryptionParams,
    pub includes_audit: bool,
    pub ciphertext: String,           // base64url(AES-256-GCM(payload-JSON))
}
```

Payload (inner, encrypted) — VTC-specific. One JSON document; each backed-up
keyspace is dumped as its raw `(key, value)` rows so the import is a faithful
replay, not a lossy projection. Rows are parsed strictly on export — a corrupt
row **aborts** the backup rather than silently dropping community state (the
VTA's `corrupt_row` rule):

```rust
pub struct BackupPayload {
    pub config: BackupConfig,                 // vtc_did, vtc_name, vta_did,
                                              //   public_url, messaging, jwt key
    pub key_bundle_hex: Option<String>,       // VtcKeyBundle — see Decision 1
    pub keyspaces: Vec<KeyspaceDump>,         // one per BACKED_UP keyspace
}

pub struct KeyspaceDump {
    pub name: String,                         // keyspaces::ACL, etc.
    pub rows: Vec<(String, String)>,          // (utf8 key, base64url value-bytes)
}
```

Dumping raw rows (rather than re-deriving typed structs per keyspace as the VTA
does) keeps the port small and makes the census mechanical: the export loop is
`for ks in BACKED_UP { dump(ks) }`. Values are opaque bytes (base64url) so
mixed raw/JSON keyspaces (audit counters, status-list bitstrings) round-trip
without per-keyspace knowledge.

## Keyspace partition (the core VTC decision)

All 21 keyspaces are accounted for. `BACKED_UP ∪ EXCLUDED = ALL`, disjoint —
pinned by a census test.

| Keyspace | Disposition | Rationale |
|---|---|---|
| `acl` | **backup** | Authorization graph; irreplaceable. |
| `community` | **backup** | Community profile. |
| `members` | **backup** | Member records; irreplaceable. |
| `join_requests` | **backup** | Plan names these explicitly; preserves in-flight applications across a restore. |
| `policies` | **backup** | Operator-authored Rego. |
| `active_policies` | **backup** | Which policy is live (pointer state). |
| `status_lists` | **backup** | **Critical** — loss bricks every issued VMC's `credentialStatus`. |
| `relationships` | **backup** | VRC publish state; plan names these. |
| `relationships_by_did` | **backup** | Secondary index; backed up to avoid post-restore divergence (cheap, and the census prefers completeness over rebuild logic). |
| `endorsement_types` | **backup** | Operator-registered types. |
| `schemas` | **backup** | Operator-registered accept-schemas. |
| `endorsements` | **backup** | Issued custom VECs. |
| `audit` | **backup** (gated) | Included only when `include_audit = true`, mirroring the VTA. |
| `audit_key` | **backup** | HMAC actor-hash key — without it, restored audit logs are unverifiable. Always included. |
| `sessions` | exclude | Ephemeral auth; restoring stale sessions is a security regression. |
| `config` | exclude | Carried by the payload's `BackupConfig` snapshot + re-applied; mirrors the VTA excluding its config keyspace. |
| `passkey` | exclude | See Decision 2. |
| `install` | exclude | One-shot install-token state. |
| `registry_records` | exclude | Re-synced from the trust registry (idempotent since P3.8). |
| `sync_queue` | exclude | Transient runtime job queue. |
| `sync_cursor` | exclude | Re-derivable; re-emit is idempotent (P3.8 event-id keys). |

→ **14 backed up, 7 excluded, 21 total.**

## Decisions

All five settled at sign-off: **(1) include the key bundle; (2) exclude
passkeys; (3) back up join_requests; (4) identity-mismatch → 409; (5) import
body cap 64 MiB.** Detail below.

### Decision 1 — include the signing key bundle (`VtcKeyBundle`)? **→ Include.**

The VTC's signing key isn't in a keyspace; it lives in the configured `secrets`
backend (keyring / AWS / GCP / Azure / k8s / inline config-secret). A
keyspace-only backup restores the community's *data* but not its ability to
*sign* (re-issue status lists, mint VMCs) — so for an inline `config-secret`
deployment, disk loss still bricks the community even after a restore.

**Recommendation: include it** (`key_bundle_hex`, read from the secret store at
export, written back at import). Rationale: (a) the VTA's backup includes its
seed — the analogous crown-jewel — so there's precedent; (b) it makes the
backup a *complete* recovery artifact, which is the whole point; (c) it's inside
the Argon2id+AES-GCM envelope, same protection as the seed. The threat-model
note ("this backup contains the signing key") goes in the operator doc, and the
export response/CLI warns accordingly.

*Alternative:* keyspace-only, documenting that the operator must independently
preserve the secrets backend. Simpler, but fails the disaster-recovery goal for
the most common single-box (config-secret) deployment.

### Decision 2 — passkeys: exclude (recommended) or back up? **→ Exclude.**

After a restore the admin DID still lives in the
`acl` keyspace (backed up), so the operator regains access by authenticating
with their admin DID key over the DI-signed Trust Task / DIDComm path (CLI), then
re-enrolls a browser passkey. Backing up passkeys would restore a WebAuthn
signature counter that may have regressed relative to the authenticator,
risking auth failures, and passkeys are RP-origin-bound device credentials —
treating them like `sessions` (re-established post-restore) is cleaner.

*Alternative:* back up `passkey` so browser admins regain SPA access without a
CLI round-trip. If we want this, it's a one-line move from EXCLUDED to
BACKED_UP — flag it now so the census + tests reflect the choice.

### Decision 3 — `join_requests` really backed up? **→ Yes, backed up.**

The plan lists join requests among the state that "has no export/import path,"
so they're in **BACKED_UP**. They're semi-transient (TTL-swept), so this
preserves in-flight applications across a restore.

## Identity binding

`check_vtc_did_compatibility(running, backup)` mirrors the VTA verbatim with
`vtc_did`:
- running unset/empty → accept any backup (fresh-install DR);
- running == backup → accept;
- otherwise → refuse ("backup vtc_did mismatch … clear vtc_did from config to
  migrate identity"). Maps to **409 Conflict** (Decision 4 — the VTA uses 400,
  but 409 reads truer for an identity conflict and fits the house "typed errors"
  rule).

## Crash safety

Mirror the VTA: write a `backup:import_in_progress` sentinel (a key outside
every cleared prefix) + `persist()` **before** the destructive clear; remove it
+ `persist()` only after the full replay; `server::run` refuses to boot while
the sentinel is present (points the operator at re-running the import).

Import order: (1) `check_vtc_did_compatibility`; (2) write sentinel; (3) clear
every BACKED_UP keyspace; (4) write the key bundle to the secret store; (5)
replay each `KeyspaceDump` via `insert_raw`; (6) apply `BackupConfig` to the
config overlay; (7) remove sentinel + persist.

## Wire + auth surface

- `POST /v1/backup/export` — `SuperAdminAuth`. Body `{ password, include_audit }`
  → `BackupEnvelope`.
- `POST /v1/backup/import` — `SuperAdminAuth`. Body `{ backup, password, confirm }`.
  `confirm = false` returns a **preview** (`{status:"preview", source_did,
  counts}`) without mutating; `confirm = true` applies and returns
  `{status:"imported", source_did, counts}`. (The VTA's preview/confirm
  two-step — cheap and prevents fat-finger restores.)
- Trust-Task descriptors for both, following the existing
  `docs/05-design-notes/backup-descriptor-pattern.md` so the admin SPA + a
  future `cnm backup` CLI get the same soft-gate surface as the VTA's `pnm
  backup`. Routes mount through the existing `tt()` builder in `routes/mod.rs`.
- Body cap: import envelopes can be large (audit logs) — the import route needs
  a raised `DefaultBodyLimit` (the export of a big community + audit can exceed
  the 1 MB global cap). Size TBD from a populated-community measurement;
  proposed 64 MiB ceiling with a documented limit.

## Module layout

```
vtc-service/src/operations/backup.rs   # export_backup / import_backup /
                                        #   decrypt / check_vtc_did_compatibility
                                        #   + BACKED_UP / EXCLUDED partition consts
vtc-service/src/routes/backup.rs        # export + import handlers (SuperAdminAuth)
vtc-service/src/store/keyspaces.rs      # add BACKED_UP / EXCLUDED_FROM_BACKUP
```

Backup wire types (`BackupEnvelope`, `BackupPayload`, `KeyspaceDump`,
`BackupConfig`, `ImportResult`) live **in `vtc-service`** (VTC-local), not
`vta-sdk` — the payload shape is VTC-specific and there's no reason to couple
the SDK. A `cnm backup` CLI is a follow-on (out of scope for the first PR; the
REST surface + admin SPA cover the acceptance criteria).

## Test plan

- **Census** (`backup_partition_is_total`): `BACKED_UP` and
  `EXCLUDED_FROM_BACKUP` are disjoint and their union equals `keyspaces::ALL`.
  This is the plan's "no keyspace silently omitted" guard.
- **Crypto round-trip**: `encrypt → decrypt` recovers the payload; wrong
  password → 401; tampered ciphertext → 401 (GCM auth).
- **Import bounds**: out-of-range `m_cost`/`t_cost`/`p_cost`, bad algorithm
  strings, wrong salt/nonce length all → 400.
- **Identity guard**: fresh-install accepts any; matching accepts; mismatch
  rejects (3 cases, mirroring the VTA).
- **Full state round-trip** (integration): seed every BACKED_UP keyspace via
  the `TestVtc` harness, export, wipe the data dir, import, assert each
  keyspace's rows are byte-identical and the daemon serves the same
  members/ACL/status-list/endorsement state. Assert `sessions`/`install` are
  *not* resurrected.
- **Key-bundle round-trip** (if Decision 1 = include): export reads the bundle
  from a test secret store, import writes it back, signing works post-restore.
- **Crash-safety**: a simulated mid-import (sentinel present) is detected at
  boot.

## Decision log (settled at sign-off)

1. **Include** the `VtcKeyBundle` in the encrypted payload — complete
   disaster-recovery artifact.
2. **Exclude** passkeys — re-enroll via the restored admin DID.
3. **Back up** `join_requests` — per the plan.
4. Identity mismatch → **409 Conflict**.
5. Import body cap → **64 MiB** (`DefaultBodyLimit`); operators with larger
   audit logs export with `include_audit = false`.

Implementation lands in a single PR (operations + routes + census/round-trip
tests + operator doc), with a `cnm backup` CLI as a fast follow.
