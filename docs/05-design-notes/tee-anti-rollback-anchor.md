# Design note: enclave-side anti-rollback anchor (P0.2)

Status: **Draft — for review** (no code yet)
Owner: Glenn Gore
Last updated: 2026-06-11
Tracking: Phase-0 hardening item **P0.2** (XL). Depends on **P0.1** (AAD
binding, merged #346). Sequenced before its own implementation PRs.

Related code (current-state map, verified while writing this note):
- Carve-out sentinel: `vta-service/src/tee/admin_bootstrap.rs:30`
  (`BOOTSTRAP_CARVEOUT_CLOSED_KEY`), read/write in
  `vta-service/src/routes/bootstrap.rs:210-214,319-335` (P0.8 made the
  close atomic + `persist()`-durable).
- JWT key fingerprint: `vta-service/src/tee/kms_bootstrap.rs:259-343`
  (`jwt_fingerprint` / `store_jwt_fingerprint` / `verify_jwt_fingerprint`,
  key `bootstrap:jwt_fingerprint`, gated by `allow_fingerprint_init`).
- ACL keyspace: `vti-common/src/acl/mod.rs` (`acl:{did}`; revoke =
  `delete_acl_entry`, `mod.rs:502-504`).
- P0.1 AAD encryption: `vti-common/src/store/encryption.rs` (`VAE1`
  magic, AAD = `len(keyspace) ‖ keyspace ‖ store_key`).
- Persisted counters: `vti-common/src/store/counter.rs` (`allocate_u32`,
  global `COUNTER_LOCK`, fsync via `persist()`).
- Storage-key derivation: `kms_bootstrap.rs:349-373`
  (`derive_storage_key`, HKDF-SHA256 over the KMS-decrypted seed).
- Enclave AWS egress: full AWS SDK present (`aws-sdk-kms`, `aws-config`,
  `aws-lc-rs`); KMS client built with `aws_config::defaults()`
  (`kms_bootstrap.rs:380`); TLS terminates **inside** the enclave; parent
  runs an IMDS proxy (vsock 5400) + an HTTPS CONNECT proxy (vsock 5300).
- NSM attestation: `vta-service/src/tee/nitro.rs:58-83,259-291` —
  `attest(user_data, nonce)` / `request_nsm_attestation_for_kms(pubkey)`
  accept arbitrary bytes and are reusable.

---

## 1. Objective

Detect and refuse **rollback / replay of security-critical singleton state**
in the Nitro-Enclave VTA, where the untrusted EC2 parent owns the on-disk
fjall database and can delete, replay, or reorder whole ciphertexts.

Concretely, after this work:

- Deleting `BOOTSTRAP_CARVEOUT_CLOSED_KEY` to **reopen the single-use Mode-B
  carve-out** (parent compromise → mint a fresh super-admin) is **detected
  and refused**.
- Replaying an old ACL snapshot to **resurrect a revoked admin** is detected
  and refused.
- Rolling back the path/context counters to **force BIP-32 key reuse** is
  detected and refused.
- Deleting the JWT fingerprint to **force a silent re-baseline** is detected
  and refused.

The acceptance bar (from the plan): *a deleted carve-out sentinel or replayed
ACL row is detected at boot — fail closed with operator guidance — and the
threat model in `docs/02-vta/tee-architecture.md` is updated to state that
integrity/freshness is enforced, not just confidentiality.*

This note surveys the design space, explains why the obvious approaches do
**not** meet the stated threat, recommends a layered design, and proposes a
phased implementation. **No code is written until this note is reviewed.**

## 2. Background — what we already have, and the exact gap

Two layers already exist:

1. **Confidentiality** (KMS attestation + AES-256-GCM). The fjall values are
   encrypted with a storage key derived from the KMS-decrypted seed; KMS only
   decrypts under a valid PCR0/PCR8 attestation. The parent cannot read
   plaintext.
2. **Location integrity** (P0.1 AAD). Each value's AES-GCM AAD binds it to its
   `keyspace ‖ key`, so the parent cannot **cut-and-paste** a ciphertext from
   one key/keyspace to another — the AEAD tag fails.

Neither layer provides **freshness**. The gap, precisely:

- KMS will faithfully decrypt **any** ciphertext that was *ever* validly
  produced under the key — including a stale one. So "replay an old ciphertext
  file" is **not** stopped by attestation. (The current threat-model row
  *"Attacker replays ciphertext files → useless without KMS decryption"* is
  **wrong** for stale-but-valid replay; this note corrects it.)
- P0.1's AAD stops relocation, not rollback: an old ciphertext replayed **into
  its own original key** has a valid AAD and decrypts cleanly.
- The enclave keeps **no persistent state of its own**. On every boot, enclave
  RAM is fresh; everything durable lives in the parent-owned DB. So the enclave
  has no internal memory of "what the latest version was."

Result: the parent can present any internally-consistent **past snapshot** of
the DB and the enclave cannot tell it from the present.

## 3. The hard constraint: no enclave-internal freshness anchor exists on Nitro

Rollback detection fundamentally requires a piece of state that is **(a)
monotonic** and **(b) outside the attacker's control**. On AWS Nitro Enclaves,
*none of the on-box primitives qualify*:

| Candidate anchor | Why it fails |
|---|---|
| Hardware monotonic counter (TPM NV / SGX MC) | **Does not exist** on Nitro. No NV counter, no sealed-storage primitive. |
| NSM (Nitro Security Module) | Attestation + RNG only. No persistent writable state. Cannot "seal to PCRs" locally. |
| AWS KMS | No counter, no conditional/compare-and-set, no monotonic op. KMS decrypts old valid ciphertexts unconditionally. |
| PCR values | Measure the *image*, not runtime state. Identical across reboots of the same image. |
| Local fjall (even AAD-bound) | Lives on the parent's disk → fully rollback-able. |

**Therefore the anchor must be external** to the box: a service the parent
cannot roll back, reached over a channel the parent cannot forge. The good
news (verified in §0 refs): the enclave **terminates TLS itself** and has the
**full AWS SDK** + working egress, so an external AWS-managed linearizable
store (DynamoDB conditional write, or S3 conditional `PutObject`) *is*
reachable, and the parent — though it proxies the bytes — **cannot read or
forge** the TLS-protected responses.

The one subtlety that shapes the whole design (§5): the enclave's AWS
credentials come from the **instance role via the parent's IMDS proxy**, so a
*root-on-parent* attacker holds those same credentials. An external counter
written with the instance role can be rolled back by the very adversary we are
defending against. The recommended design closes this by gating the
counter-writer behind a **KMS-attestation-sealed credential the parent cannot
obtain**.

## 4. Design space

### Layer 0 — Local MAC'd integrity manifest (necessary, insufficient alone)

A single record `tee:integrity-manifest` holding:
`{ version: u64, covered: {carveout_hash, jwt_fp_hash, acl_root, counters_hash}, mac }`
where `mac = HMAC-SHA256(storage_key, canonical_serialization)` and `acl_root`
is a Merkle/flat hash over all `acl:{did}` rows in canonical order.

- **Catches:** deletion of a covered row (recomputed hash ≠ manifest), partial
  tampering, and any **inconsistent** snapshot (rows from epoch N, manifest
  from epoch M≠N). The parent can't forge the manifest (MAC keyed by the
  storage key it can't derive).
- **Does NOT catch:** a fully **consistent** rollback — manifest *and* all
  covered rows restored together to a genuine past epoch. The manifest's own
  `version` is just another value on the parent's disk; nothing external pins
  "the latest version is N."
- **Cost:** trivial. Reuses P0.1 AAD + `counter.rs`. No new infra, no new
  trust. **This layer ships regardless** — it is the cheap detector and the
  thing the external anchor pins.

### Option A — External linearizable counter, written with the instance role

Single-item DynamoDB table; one monotonic `version` attribute; bump via
`UpdateItem` with `ConditionExpression: version = :expected` (optimistic
concurrency → linearizable). Boot reads the authoritative version and compares
to the manifest's embedded `version`.

- **Catches:** storage-only rollback — EBS-snapshot restore, a botched
  backup/restore, a parent *process* bug that deletes DB files but lacks AWS
  creds. Meaningful: these are the realistic *accidental* and
  *partial-compromise* vectors.
- **Does NOT catch:** a **root-on-parent** attacker, because that attacker has
  the instance-role credentials and can roll the counter back itself.
- **Cost:** low-moderate (config + DynamoDB client + a table).

### Option B — External counter fenced behind a KMS-attestation-gated writer (recommended robust core)

Same external counter as Option A, but:

1. A **dedicated IAM principal** (`vta-anchor-writer`) is the *only* principal
   permitted `dynamodb:UpdateItem` on the counter table. The **EC2 instance
   role is explicitly denied** write (read may stay on the instance role).
2. That principal's credentials (or a STS-assumable session) are
   **KMS-sealed** under a key whose policy carries
   `kms:RecipientAttestation:PCR0` / `:PCR8` conditions — exactly the existing
   pattern that already protects the seed (`kms_bootstrap.rs`). Only the
   genuine enclave image can `Decrypt` them; the parent cannot, because it
   cannot produce a valid attestation for the right PCRs.

Now even a **root-on-parent** attacker cannot bump or roll back the counter:
it has the instance role (denied on the table) but not the gated writer
credential (KMS refuses to release it without the right PCRs), and it cannot
forge the attestation (the NSM signing key lives in the Nitro hypervisor,
unextractable). The counter itself lives in DynamoDB (AWS control-plane
durable), so the parent cannot restore it to an old value either.

- **Catches:** consistent-snapshot rollback against the full Nitro adversary
  (compromised parent OS, operator's AWS account intact) — i.e. the actual
  P0.2 threat ("parent compromise mints a fresh admin").
- **Cost:** moderate. Reuses KMS-attestation plumbing already in the codebase;
  adds one IAM principal, one KMS grant/key, one DynamoDB table, and an IAM
  deny on the instance role.

### Option C — Bespoke attestation-validating anchor service (max assurance)

A small service (Lambda behind API Gateway, ideally **cross-account** so the
parent host's blast radius excludes it) that the enclave calls presenting a
fresh NSM attestation; the service validates PCR0/PCR8 against an allowlist and
enforces the monotonic counter in its own store.

- Equivalent assurance to B, plus it removes the "AWS account == trust root"
  coupling for the counter (the anchor account can be separate from the
  workload account). Useful for the highest-assurance / multi-tenant
  deployments.
- **Cost:** highest — you build, deploy, secure, and key-rotate a separate
  service. Recommended as a *future* option, not the first delivery.

### Non-options (explicitly rejected)

- **KMS-as-notary alone** (have KMS sign the counter): KMS will sign whatever
  it's handed; it does not enforce monotonicity. No good.
- **NSM-seal alone**: no persistent writable state; nothing to roll forward.
- **Re-wrap storage key per epoch**: KMS still decrypts the *old* wrapped key,
  so an old snapshot still opens. No good.

## 5. Recommended design

**Layer 0 (local MAC'd manifest) + Option B (KMS-attestation-gated external
counter).** Layer 0 is the cheap, always-on detector and the canonical place
the version lives; Option B is the un-rollback-able pin that makes the
version meaningful against the real adversary. Option C is documented as the
future max-assurance upgrade.

### 5.1 Coverage set (the protected singletons)

Phase-1 coverage (high-severity, named in the plan + the key-reuse vector):

| Singleton | Source | Why |
|---|---|---|
| Carve-out sentinel | `keys:tee:bootstrap-carveout-closed` | reopen → fresh admin |
| ACL keyspace root | all `acl:{did}` (Merkle/flat hash, canonical order) | replay → resurrect revoked admin |
| JWT fingerprint | `bootstrap:jwt_fingerprint` | delete → silent re-baseline |
| Path/context counters | `counter.rs` keys | rollback → BIP-32 key reuse |

The KMS-protected bootstrap ciphertexts (seed/JWT/data-key) are *not* in the
hash — their delete-and-reinit is already gated by `allow_kms_reinit` and a
mismatch is caught by KMS decrypt + the JWT fingerprint. Coverage is an
explicit, reviewed list, not "everything."

### 5.2 Integrity manifest

```
record  tee:integrity-manifest  (keyspace: bootstrap)
fields  { version: u64,
          carveout_present: bool,
          jwt_fp: [u8;16],
          acl_root: [u8;32],     // H(canonical concat of acl rows)
          counters: [u8;32],     // H(canonical counter snapshot)
          mac: [u8;32] }         // HMAC-SHA256(storage_key, the above, canonically encoded)
```

- Canonical serialization is length-prefixed and field-ordered (same
  discipline as `build_aad`) so the MAC is unambiguous.
- The manifest record itself is also P0.1-AAD-bound to its key, so it can't be
  relocated.

### 5.3 External counter

- DynamoDB table, single item keyed by the VTA DID (supports >1 enclave
  replica sharing one identity; the conditional write serializes them).
  Attributes: `version (N)`, optional `manifest_digest` for cross-check,
  `updated_at`.
- Bump: `UpdateItem … SET version = :new ADD …  ConditionExpression
  version = :expected` — fails the whole op if another writer moved it,
  giving compare-and-set linearizability.
- Writer auth: the KMS-attestation-gated `vta-anchor-writer` credential
  (§4 Option B). Instance role: read-only or denied.

(S3 conditional `PutObject` with `If-Match` is an equivalent substrate if the
team prefers object storage; DynamoDB is recommended for a bare counter.)

### 5.4 Commit protocol & ordering

For every security-*tightening* mutation (carve-out close, ACL revoke, counter
allocation, fingerprint set):

```
1. Compute new manifest for the post-mutation state (version = N+1).
2. External bump: UpdateItem version N → N+1  (CAS).   ← linearization point
3. Local write: persist the mutated rows + the new manifest, fsync (persist()).
```

**Order is external-first.** Crash-window analysis:

- Crash **between 2 and 3**: external = N+1, local manifest = N. On boot,
  `local.version (N) < authoritative (N+1)` ⇒ **rollback/torn-write detected ⇒
  fail closed.** Safe direction: we refuse to run on a stale local store rather
  than serve it. Recovery in §5.6.
- The reverse order (local-first) is **rejected**: it would leave a window
  where external = N (old) while local = N+1, so the parent could present the
  *old* local state (version N) that matches the un-bumped external counter →
  the tightening is silently rolled back. External-first removes this window.

For the carve-out specifically this is exactly the safe bias: a torn close
fails **closed** (carve-out stays shut / boot refused), never **open** (a
second admin mint).

### 5.5 Boot verification flow

```
on boot, after KMS decrypt + storage key derived + JWT fingerprint verified:
  a. Read authoritative version N_ext from the external counter.
  b. Load tee:integrity-manifest; verify its MAC with storage_key.
       MAC fail            → tampered/forged manifest → FAIL CLOSED.
  c. Recompute carveout/jwt_fp/acl_root/counters from the live store;
       compare to manifest → mismatch → deletion/inconsistent tamper → FAIL CLOSED.
  d. Compare manifest.version (M) to N_ext:
       M  < N_ext  → consistent rollback of local store → FAIL CLOSED.
       M  > N_ext  → external counter rolled back (or torn pre-commit) → FAIL CLOSED.
       M == N_ext  → fresh & consistent → proceed; cache the verified
                     manifest in protected enclave RAM.
```

### 5.6 Steady-state reads & mutations

- **Reads** of covered singletons during a boot session validate against the
  **in-RAM verified manifest** (cheap MAC/hash check), not a fresh DynamoDB
  round-trip — the boot check already pinned freshness for this session.
- **Mutations** run the §5.4 external-first protocol and update the in-RAM
  manifest on success.
- **Periodic re-anchor** (optional, configurable): re-read the external
  counter every *T* to detect a live parent that swaps the DB underneath a
  long-running enclave; default off in Phase 1 (boot-time + per-mutation checks
  cover the stated threat).

### 5.7 Fail-closed, availability, and break-glass

The parent can always **deny egress** to the counter (it proxies the bytes) →
the enclave can't verify freshness → it **fails closed** (refuses boot /
refuses security-relevant ops). This is a **DoS, not an integrity breach**, and
is acceptable (the parent can already DoS by not starting the enclave).

A documented break-glass `tee.kms.allow_unanchored = false` (default) mirrors
`allow_unattested_fallback`: setting it true lets the enclave boot without the
anchor, **loudly warned**, for incident recovery only. Off by default.

Boot-refusal recovery guidance (operator-facing, printed on fail-closed):
restore the local store from a **consistent** backup whose manifest version
matches the external counter, or — if the divergence is a known torn commit —
re-run the pending tightening op, or (last resort) `allow_unanchored` once to
recover and re-anchor.

### 5.8 Migration / first boot

Existing TEE deployments have **no** manifest and **no** counter. Mirror the
JWT-fingerprint pattern: a `tee.kms.allow_anchor_init` flag (default false).

- No manifest + no counter + `allow_anchor_init = true` → establish version 0
  (counter `PutItem` if-not-exists; write the MAC'd manifest), warn, instruct
  operator to disable the flag after this boot.
- No manifest/counter + flag false → **refuse** (don't silently baseline — a
  silent baseline is exactly the rollback the feature prevents).

### 5.9 Config surface (additions to `TeeKmsConfig`, `config.rs:326-402`)

```toml
[tee.kms.anchor]
table_name        = "vta-rollback-anchor"   # DynamoDB single-item table
writer_key_arn    = "arn:aws:kms:…"          # KMS key gating the writer cred (PCR-conditioned)
allow_anchor_init = false                     # one-shot first-boot baseline (migration)
# top-level break-glass:
[tee.kms]
allow_unanchored  = false                     # boot without the anchor (incident only)
```

All `Option`/defaulted so non-TEE and not-yet-migrated configs are unaffected.

## 6. What this changes in the threat model

`docs/02-vta/tee-architecture.md` threat table — replace the misleading row and
add freshness rows:

- *"Attacker replays ciphertext files"* — current mitigation ("useless without
  KMS decryption") is **wrong for stale-but-valid replay**. New mitigation:
  external attestation-gated monotonic counter + MAC'd manifest; a replayed
  snapshot has `version < authoritative` ⇒ boot fails closed.
- New row — *"Parent rolls back carve-out / ACL to a consistent past snapshot"*:
  detected at boot via the version pin; fail closed.
- New row — *"Parent denies anchor egress"*: DoS only; fail closed; break-glass
  `allow_unanchored`.

State plainly: **the TEE now enforces integrity/freshness of the named
singletons, not only confidentiality** (within the trust assumption that the
operator's AWS account / KMS policy / DynamoDB control-plane is intact — the
same root of trust the seed already depends on).

## 7. Phased implementation plan (PR slices)

The XL splits into independently-reviewable slices:

- **P0.2a — Local MAC'd manifest + boot verify (Layer 0).** Manifest record,
  canonical serialization, MAC, recompute-and-compare on boot, coverage set,
  `allow_anchor_init` first-boot baseline. No external dependency. Ships real
  value (catches deletion + inconsistent tamper) on its own. *(M)*
- **P0.2b — External counter (Option A wiring).** DynamoDB client, single-item
  CAS bump, external-first commit protocol, boot version-compare, fail-closed +
  `allow_unanchored`, config surface. Instance-role creds for now. *(M)*
- **P0.2c — Attestation-gated writer (Option B fencing).** KMS-sealed
  `vta-anchor-writer` credential + IAM deny on the instance role; upgrades the
  counter from "resists storage rollback" to "resists root-on-parent." Docs +
  Terraform/IAM templates. *(M–L)*
- **P0.2d — Threat-model doc update** (§6) + the corrected table; can ride with
  P0.2c or land alongside. *(S)*
- *(Future)* **P0.2e — Option C cross-account anchor service**, for max
  assurance / multi-tenant. Out of Phase-0 scope.

Each slice is its own PR with the full CI gate; P0.2a is mergeable and useful
before P0.2b/c exist.

## 8. Residual risks / out of scope

- **AWS account / control-plane compromise** (attacker can edit IAM, KMS
  policy, or restore DynamoDB PITR): out of scope — that is the operator's
  trust root, identical to the assumption the seed already relies on.
- **Availability**: the parent can DoS the anchor (fail-closed). Accepted.
- **In-session live swap** beyond the per-mutation check: covered only if the
  optional periodic re-anchor (§5.6) is enabled.
- **Non-TEE / plaintext deployments**: unaffected — the anchor is TEE-only and
  all config is opt-in/defaulted.

## 9. Open questions for review

1. **Substrate**: DynamoDB conditional `UpdateItem` (recommended) vs. S3
   conditional `PutObject`? DynamoDB is the cleaner bare-counter; S3 is simpler
   IAM if we'd rather store the whole manifest object externally.
2. **Phase-1 stopping point**: is P0.2a+P0.2b (resists storage/backup rollback,
   *not* root-on-parent) an acceptable first landing, with P0.2c (root-on-parent
   resistance) as a fast-follow — or must P0.2c land in the same release because
   root-on-parent is the headline threat?
3. **Coverage set** (§5.1): confirm the four singletons; do we want the
   bootstrap ciphertexts and/or sealed-nonce replay state in the hash too, or
   leave those to KMS/`allow_kms_reinit`?
4. **Break-glass posture**: is a single `allow_unanchored` boot flag acceptable,
   or do we want a stronger ceremony (e.g. attested operator approval) for the
   recovery path?
5. **Cross-account anchor (Option C)**: in scope as an eventual P0.2e, or
   explicitly out forever (Option B deemed sufficient)?
