# Todo: VTA Architecture Simplification & Hardening

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Plan with full problem statements, file references, acceptance criteria,
and the invariants do-not-break list: `tasks/vta-architecture-plan.md`.
Record the PR number next to each task as it merges.

Sizes: S ≤ ½ day · M 1–2 days · L 3–5 days · XL needs a design note first.

---

## Phase 0 — Security & correctness fixes (parallelizable, land any time)

- `[x]` **P0.1** (M) AAD binding (`keyspace||key`) for keyspace encryption;
  encrypt `sealed_nonces` + `cache` — branch `fix/p0.1-keyspace-aad`.
  AES-GCM AAD = len-prefixed keyspace ‖ store-key, 4-byte magic `VAE1`, NO
  legacy read-fallback (downgrade-safe) → clear error on stale data.
  Threaded keyspace name + store key through every encrypt/decrypt site in
  the local + vsock handles; encrypted `cache` + `sealed_nonces` at both
  AppState construction sites. Breaking on-disk change for encrypted stores
  only (default/plaintext unaffected) — documented in CHANGELOG. Tests:
  cross-key/cross-keyspace paste rejected (unit + through the real handle),
  wrong-key, legacy-format clear error, passthrough unchanged — PR: #346 (merged)
- `[~]` **P0.2** (XL) Enclave-side anti-rollback anchor for carve-out sentinel /
  JWT fingerprint / ACL — deps: P0.1. **Design note MERGED** (PR #365,
  `docs/05-design-notes/tee-anti-rollback-anchor.md`). **§9 open questions
  RESOLVED in review** (branch `docs/p0.2-resolve-open-questions`): (1) substrate
  = **DynamoDB** conditional `UpdateItem` CAS (Secrets Manager rejected — no
  conditional write; S3 `If-Match` viable alt); (2) **ship P0.2a+b first**,
  withhold the parent-compromise threat claim until P0.2c; (3) coverage =
  **the four singletons** (sealed-nonce replay noted as a later candidate);
  (4) break-glass = **single `allow_unanchored`** flag (safe because TEE config
  is EIF-baked/measured); (5) Option C cross-account = **future P0.2e**. Same PR
  adds the operator setup runbook (DynamoDB table + KMS PCR-gated writer key +
  IAM writer-principal/instance-role-deny + config) and the threat-model rollback
  rows to `docs/02-vta/tee-architecture.md`. TEE-only feature. Phases:
  P0.2a (manifest) → P0.2b (counter) → P0.2c (attestation-gated writer) →
  P0.2d (threat-model claim) ; P0.2e (Option C) deferred — design PR: #365
  (merged); §9-resolution + setup-docs PR: #377 (merged).
  - `[x]` **P0.2a** (M) Local MAC'd integrity manifest + boot-verify (Layer 0) —
    branch `fix/p0.2a-integrity-manifest` (worktree). New
    `vti_common::integrity`: a 121-byte MAC'd manifest pinning the four covered
    singletons (carve-out sentinel, ACL root, JWT-fingerprint, path/context
    counters) under `HMAC-SHA256(HKDF(storage_key), …)`, stored in the
    `bootstrap` keyspace. Boot (`server::run`, gated on a KMS storage key →
    TEE-only) verifies the MAC + recomputes-and-compares the live state, failing
    **closed** on a deleted row / inconsistent snapshot / forged manifest;
    first-boot/missing baseline gated behind new
    `tee.kms.allow_anchor_init` (mirrors `allow_fingerprint_init`). Kept in
    step at runtime by re-sealing at **chokepoints** rather than ~29 call sites:
    `store_acl_entry`/`delete_acl_entry`/`update_acl_entry_versioned` +
    `counter::allocate_u32` (all in vti-common) cover every ACL + counter
    mutation; `mint_mode_b` (carve-out close) and `apply_import` (backup
    restore) reseal explicitly. A process-global `OnceLock` sealer (set only at
    TEE boot) makes `reseal_if_active` a true no-op outside a TEE — zero
    behaviour change for the local VTA. Reads decrypt via encrypted handles, so
    the manifest hashes *plaintext* content (nonce-independent). Drift-guard test
    pins the duplicated key strings to the vta-service constants. Does NOT catch
    a fully-consistent rollback — that's the external counter (P0.2b). Tests:
    manifest byte/MAC round-trip + tamper, baseline-refused-without-flag,
    baseline→verify, deletion/forgery detected, e2e (install → chokepoint reseal
    → reverify → out-of-band tamper → fail-closed → recover). fmt + clippy
    (default & tee) clean; vti-common 234 + e2e, vta-service 714 (default) / 745
    (tee) green; vta-enclave checks; no version bump (additive) — PR: #380 (merged)
  - `[x]` **P0.2b** (M) External DynamoDB counter + CAS commit protocol —
    branch `fix/p0.2b-external-counter` (worktree). Pins the manifest version to
    an AWS-managed linearizable counter the parent can proxy but not forge,
    upgrading detection from deletion/inconsistency (P0.2a) to **consistent
    storage rollback**. New `vti_common::integrity::AnchorCounter` trait
    (read/init/CAS-set) keeps the AWS SDK out of the foundation crate; concrete
    `DynamoAnchorCounter` (vta-service, conditional `UpdateItem` CAS) injected at
    boot. Boot version-compare (M<ext → local rolled back; M>ext → counter
    rolled back / torn; M==ext → proceed) on top of the P0.2a MAC+recompute.
    Reseal is **external-first** (§5.4): CAS-bump the counter *before* the local
    manifest write, so a crash leaves M<ext (fail-closed safe direction). Bumps
    on **every** covered mutation (operator decision) — each one is a synchronous
    DynamoDB round-trip that fails closed if unreachable. `allow_unanchored`
    break-glass: boot manifest-only when the counter is unreachable, or
    re-anchor it to the MAC-trusted local manifest on divergence; `allow_anchor_init`
    also initializes the counter (first boot / migration from a manifest-only
    P0.2a VTA). Config: `[tee.kms.anchor] table_name`, `[tee.kms] allow_unanchored`.
    Operator runbook + status updated (`docs/02-vta/tee-architecture.md`).
    **Scope: instance-role creds → resists storage/backup rollback, NOT
    root-on-parent (P0.2c).** Tests: anchor protocol via in-memory CAS mock
    (init+bump, M<ext / M>ext detection, allow_unanchored re-anchor, unreachable
    fail-closed-vs-unanchored) + anchored e2e (chokepoints CAS-bump the counter).
    New dep `aws-sdk-dynamodb` (tee feature). fmt + clippy (default & tee) clean;
    vti-common 239 + e2e, vta-service 745 (tee) green; vta-enclave checks — PR: ____
- `[x]` **P0.3** (S) `create_key`/`import_key`: existence check + identifier
  validation (closes `#key-0` overwrite) — branch `fix/p0.3-key-overwrite`.
  Scope grew during root-cause analysis: the store's multi-op "atomic"
  closures (take_raw/swap) were NOT actually atomic — added a shared
  per-keyspace write lock in LocalStore + `insert_if_absent` primitive +
  concurrency regression tests; also validated `rename_key`'s new id
  (wire-facing bypass) — PR: #341 (merged)
- `[x]` **P0.4** (S) Shared locked counter allocator; fix
  `allocate_context_index` race (same-subtree key derivation) —
  implemented on branch `fix/p0.4-counter-races`. Delivered:
  `vti-common/src/store/counter.rs` (app-level lock so the vsock backend
  is covered too); allocate_path + allocate_context_index delegate;
  `insert_raw_if_absent` closes the KEK salt race; ROTATE_LOCK serialises
  seed rotation; create_context claims its record atomically at both
  layers; concurrency regression tests for all four —
  PR: #342 (merged)
- `[x]` **P0.5** (L) Backup/restore: export counters, full `AclEntry`
  round-trip, import-in-progress sentinel — branch `fix/p0.5-backup-fidelity`
  (worktree). vta-sdk `BackupPayload` gains `path_counters`,
  `subcontext_counters`, `acl_entries_full` (raw `AclEntry` JSON — vta-sdk
  can't ref vti-common's `AclEntry`), all `#[serde(default)]` so old backups
  still load. Export populates them; import restores counters as
  `max(exported, recompute-from-records)` (recompute covers pre-P0.5 backups
  → no key reuse either way), restores ACL from the lossless form (fallback
  to lossy + warn). Crash-safety: `IMPORT_IN_PROGRESS_KEY` written+fsynced
  before the clear, removed+fsynced after; `server::run` refuses boot on a
  half-imported store. Tests: counter-no-reuse (exported + recomputed),
  full-ACL-fields (expiry+step-up survive), sentinel lifecycle — PR: #358 (merged)
- `[x]` **P0.6** (S) TEE seed rotation: reject or persist (no silent key loss) —
  branch `fix/p0.6-tee-seed-rotation`. Chose REJECT (the plan's safe minimum;
  in-place re-encryption is a follow-up). New `SeedStore::set_persists_across_restart()`
  (default true; `KmsTeeSeedStore` → false, fixed its misleading set() comment).
  Guard at the low-level `seeds::rotate_seed` chokepoint (catches offline CLI
  too) + a typed `AppError::Conflict` with operator guidance at
  `operations::seeds::rotate_seed` (runtime REST/DIDComm/TT path). Tests:
  refusal+no-mutation (tee), trait flag, existing non-TEE rotation unaffected
  — PR: #344 (merged). Follow-up: in-place re-encryption so TEE rotation
  works rather than refuses (needs runtime KMS access on KmsTeeSeedStore).
- `[x]` **P0.7a** (S) `Zeroizing` seed bytes + honest "secure deletion" —
  branch `fix/p0.7-seed-zeroize` (isolated worktree). `load_seed_bytes`
  returns `Zeroizing<Vec<u8>>` (the 40-caller key-derivation path — all use
  `&seed`, so transparent via Deref); the low-level `rotate_seed`'s old/new
  master seeds and the two direct `seed_store.get()` callers (status.rs,
  derivation.rs) wrapped too. `delete_secret` dropped its ineffective
  zero-overwrite (LSM keeps old SSTables; value is ciphertext anyway) with an
  honest comment. Trait-level `SeedStore::get` Zeroizing deferred (crosses
  vtc + 8 backends) — PR: #353 (merged)
- `[x]` **P0.7b** (L) Encrypt the retired-seed archive independently of the
  keyspace-encryption flag — branch `fix/p0.7b-encrypt-retired-seeds`
  (worktree). Retired master seeds were archived as **plaintext hex**
  (`SeedRecord.seed_hex`), protected only when keyspace encryption happened to
  be on — so in the target config (non-TEE + no `storage_encryption_key` +
  has-rotated) every retired generation sat in clear in fjall. Now archives are
  **always ciphertext** (`seed_enc` = AES-256-GCM, nonce‖ct, AAD-bound to the
  gen id), keyed by a KEK derived from the *current active* master seed
  (reuses `imported::get_or_create_salt`; distinct HKDF info
  `vta-retired-seed-archive`). **No plaintext ever hits disk** — the key
  crash-safety insight: encrypting under the active seed isn't self-contained
  across the seed-swap, so instead of a plaintext fallback the *load* path
  carries the robustness: `load_seed_bytes` decrypts under the current external
  seed, and on AEAD failure either falls back to the external store (only when
  the requested gen IS the active one — the rotation torn-write window) or
  refuses with a reconcile hint (retired gen — never returns wrong key
  material). `rotate_seed` writes the retired record under the *new* KEK before
  flipping the store, then re-encrypts older generations after. A boot-time
  idempotent `reconcile_archive` pass both **migrates** legacy plaintext and
  **repairs** any archive left under a predecessor by an interrupted rotation
  (fixpoint recovery over decryptable seeds). No `SeedStore` trait change; TEE
  unaffected (rotation refused there, so no retired seeds exist). Backup carries
  `seed_enc` through verbatim (salt + active seed restored alongside → stays
  decryptable). Tests: archive crypto round-trip + AAD/seed/salt binding;
  multi-gen rotate→recover-all; legacy-plaintext migration (idempotent);
  torn-rotation predecessor repair; active-gen load fallback; stale-retired load
  error; backup seed_enc round-trip; updated rotation test. fmt + clippy
  (default & tee) clean; lib 715 + all integration suites green; no-default /
  rest-only compile; no version bump (additive `seed_enc` field, serde-default)
  — PR: ____
- `[x]` **P0.8** (S) Atomic + persisted carve-out close — branch
  `fix/p0.8-carveout-durability`. Added `KeyspaceHandle::persist()` (local
  fsync + vsock OP_PERSIST passthrough). `mint_mode_b` now: seal first
  (fail-fast, no carve-out writes) → ACL → sentinel-via-`insert_raw_if_absent`
  (atomic claim, defence-in-depth beyond MODE_B_LOCK; compensating ACL
  delete on lost race) → `persist()` BEFORE returning the bundle (security
  barrier: no reopen-after-delivery). ACL-before-sentinel journal order so a
  torn fsync favours a recoverable reopen over a brick. Counter allocator
  also now fsyncs (path-counter loss = key reuse). Tests: persist-survives-
  reopen, carve-out-admits-one — PR: #343 (merged)
- `[x]` **P0.9a** (S) Boot-time `config::validate()` + plaintext-seed opt-in —
  branch `fix/p0.9-config-validation` (worktree). `AppConfig::validate()` runs
  at `server::run` boot: hard-errors on unambiguously-broken values
  (retention_days=0, present-but-empty public_url/resolver_url), warns (never
  blocks) on cross-field advisories (rest without public_url) so it can't
  reject a config that boots fine today. `create_seed_store` now errors on the
  silent plaintext fallback unless `secrets.allow_plaintext = true` (footgun:
  one wrong TOML key → master seed on disk in clear). Tests: validate rules
  (the opt-in path is cfg-unreachable in the test harness — dev-dep forces
  keyring on — documented) — PR: #356 (merged)
- `[x]` **P0.9b** (M) Unknown-key WARNING pass + missing-identity hard-fail —
  branch `fix/p0.9b-config-identity` (worktree). Two config-compat-sensitive
  halves of P0.9, deliberately *soft* where rejection would risk existing
  deployments:
  - **Unknown-key warning** (not `deny_unknown_fields`): `AppConfig::load`
    deserializes through `serde_ignored` and records every unmapped dotted
    path into a `#[serde(skip)] unknown_keys` field; `validate()` emits one
    `warn!` per key (named, with a typo/renamed/wrong-section hint). Warning
    lives in `validate()` (not `load()`) because `load()` runs before the
    tracing subscriber is installed. We *warn, never reject* — a legacy/extra
    key must not block a config that boots fine today. Aliases
    (`community_name`) and known nested keys are not flagged.
  - **Missing-identity hard-fail**: `server::run` gains an `allow_degraded`
    param; after `init_auth`, `jwt_keys.is_none()` (covers absent `vta_did`,
    absent JWT signing key, *or* unloadable key material) now refuses to boot
    with a fix-suggesting message (`missing_identity_message` names the
    specific gap + points at the escape hatch) rather than serving a VTA that
    401s every authed request but passes a liveness probe. New top-level
    `vta --allow-degraded` flag preserves the old degraded boot. **TEE/enclave
    passes `allow_degraded = true`** — its identity is established earlier in
    enclave boot by KMS autogen + admin-bootstrap, and a degraded first boot
    is an existing documented state there; the hard-fail guards the local
    `vta` daemon, which owns the CLI opt-out. import-did / cold-start flows run
    `vta setup` first (identity present), so they're unaffected.
  Tests: load collects nested+top-level typos and still validates; aliases not
  flagged; `missing_identity_message` arm-by-arm (vta_did / jwt key / key
  material). Smoke-tested end-to-end: no-identity boot exits non-zero with the
  message; `--allow-degraded` binds the listener. New dep `serde_ignored`. fmt
  + clippy (default & tee) clean; lib suite 709 green; no-default / rest-only
  combos compile — PR: ____
- `[x]` **P0.10** (S) `TimeoutLayer`; attestation routes onto governed branch;
  explicit 100 MB layer + governor on `/backup/blob` — branch
  `fix/p0.10-timeouts-ratelimit`. Global `TimeoutLayer` (120s, →408) as the
  hang backstop; moved the 4 unauth attestation routes (status, report
  GET+POST, did-log) onto the rate-limited+body-capped unauth branch
  (mnemonic stays authed); blob branch now has an explicit
  `DefaultBodyLimit::max(100MB)` (was `disable()`) + the governor.
  Factored `apply_unauth_governor()` (DRYs the trust_xff if/else, reused by
  both branches). Tests: blob+attestation 429 floods, 408 slow-handler,
  existing /auth/challenge 429 still green. tower-http `timeout` feature
  added — PR: #352 (merged)
- `[x]` **P0.11** (S) BBS matchable ⇒ presentable — branch
  `fix/p0.11-bbs-presentable`. Chose UNMATCH: `dcql_format` returns `None`
  for `Bbs2023` (was `Some("ldp_vc")` → matched-then-failed the whole
  vp_token in present_single's catch-all). Wiring `present_bbs` needs
  issuer BBS G2 pubkey resolution that present_single lacks + BBS is
  audit-gated (#294), so full BBS DCQL presentation is a follow-up tied to
  that audit. Guard test `formats_admitted_for_dcql_are_all_presentable`
  locks the invariant (passes on default + bbs feature) — PR: #349 (merged)
- `[~]` **P0.12a** (S) Deferred-presentation sweeper — branch
  `fix/p0.12a-pending-present-sweeper` (worktree). Added `pending::sweep`
  (reclaims terminal `Approved`/`Denied` + stale `expires_at<=now` records;
  also reclaims undecodable garbage rows; tolerant — one bad/stuck row never
  aborts the pass) + `pending::remove`. Wired into the existing storage-thread
  sweep loop (threaded `vault_ks` through `run_storage_thread`), runs each
  `session_cleanup_interval` alongside the acl/audit/backup sweepers. Fixes the
  unbounded `pending-present:` growth (one record per untrusted-verifier query).
  Test: sweep reclaims terminal+stale, keeps live, idempotent — PR: #363 (in review)
- `[ ]` **P0.12b** (M) Reachable approve/deny/list wire surface — expose the
  zero-caller `approve_pending_presentation`/`deny_pending_presentation`/
  `pending::list` over a TT slice (defer→list→approve→re-present end-to-end),
  delete-on-terminal in approve/deny. Plan sequenced this AFTER the sweeper
  (P0.12a). — PR: ____
- **P0.13** — DECISION (operator): ENFORCE on both transports (not document).
- `[x]` **P0.13a** (M) DIDComm `swap_acl` honours step-up floors — branch
  `fix/p0.13a-didcomm-stepup` (worktree). Refactored `resolve_step_up` to take
  `config` + `acl_ks` (not `&AppState`) so the DIDComm handler (`VtaState`)
  can call it; made it + `StepUpDecision` + the `step_up` module `pub(crate)`
  (the routes→messaging reach is a known wrinkle P2.4 relocates).
  `handle_swap_acl` now resolves the `acl/swap-key` floor (non-escalating);
  when a floor genuinely requires AAL2 the DIDComm caller (always AAL1,
  unelevatable in-band) is rejected with a `forbidden`/StepUpRequired problem
  report directing to REST. Added `StepUpRequired` → `forbidden` arm to
  `app_err_to_response`. Test: `resolve_step_up` swap-key floor/carve-out/
  disabled matrix — PR: ____
- `[x]` **P0.13b** (M) Vault step-up enforcement — branch
  `fix/p0.13b-vault-stepup` (worktree). Added `vault/release`,
  `vault/proxy-login`, `vault/sign-trust-task` op-classes (vti-common
  op_class + ALL + step_up `op` re-export). The three vault TT handlers
  (release/proxy-login/sign-trust-task) now call
  `require_step_up(state, auth, op::VAULT_*)` after the role + context-scope
  checks; the dormant `step_up_proof` body fields are removed (enforcement is
  the session-ACR gate, policy-driven — inert under the shipping default).
  Note: the actual op was proxy-login, not upsert (upsert has no step_up_proof
  / discloses nothing). Tests: op-class recognition; resolve gates a
  configured vault floor only — PR: #362 (merged)
- `[x]` **P0.14** (S) Tolerant list iteration (skip+log poisoned rows); backup
  export fails loudly — branch `fix/p0.14-tolerant-list-iteration`.
  list_acl_entries / list_contexts / list_keys skip+warn (one corrupt row
  no longer aborts the whole listing); backup export (seed/key/context/ACL
  collections) now errors loudly on a corrupt row (incomplete backup is
  worse than none). ACL field-fidelity stays for P0.5. Tests: ACL list
  skips garbage row, export aborts on corrupt key row — PR: #347 (merged)

**Checkpoint 0:** `[ ]` all P0 merged or deferred-with-issue; CI green;
tee-architecture.md updated.

## Phase 1 — Kill the divergence engines

- `[ ]` **P1.1** (M) Single `AppState` construction; `VtaState` shares the same
  Arcs (fixes the split `WebvhAuthLocks` + config `RwLock` bug) — **do first** — PR: ____
- `[ ]` **P1.2** (L) Interactive wizard builds `WizardInputs` → `apply_inputs`;
  `SetupUi` trait; golden interactive-vs-toml equivalence test — PR: ____
- `[ ]` **P1.3** (M) Keyspace + typed key-format registry; fix
  `"imported"`/`"imported_secrets"` test divergence — PR: ____
- `[ ]` **P1.4** (M) Passkey login through `vti-common::auth` handlers; single
  DI-proof verifier in vti-common — PR: ____

**Checkpoint 1:** `[ ]` e2e green; cold-start + provision-integration smoke via
pnm/cnm unchanged.

## Phase 2 — Collapse the adapter shells (deps: P1.1)

- `[ ]` **P2.0** (M) Wire-test every password-vault TT URI (safety net BEFORE
  P2.4) — PR: ____
- `[ ]` **P2.1** (L) Generic DIDComm handler adapter; fold protocol
  problem-report matches into shared mapping (−1.2–1.5k LOC) — PR: ____
- `[ ]` **P2.2** (L) Declarative TT slice registration macro (handler +
  dispatch arm + parity entry from one line) (−1.0–1.4k LOC) — PR: ____
- `[ ]` **P2.3** (L) `ServiceLifecycle` generic for rest+webauthn protocol ops;
  `publish_service_patch()` helper for didcomm; one `ProtocolOpError` + one
  error-mapping trait replacing 11 `*HttpError` enums (−2.5–3k LOC) — deps:
  P1.3 — PR: ____
- `[ ]` **P2.4** (L) Move logic out of routes: step-up engine, vault handlers
  → `operations/secret_vault/`, backup_blob, `dispatch_trust_task_core` (typed
  return; messaging stops importing routes) — deps: P2.0, P2.2 — PR: ____
- `[ ]` **P2.5** (M) Dep structs for op signatures (AppState → ~4 sub-structs;
  no op >6 args; fix the cfg-panic in `From<&AppState>`) — PR: ____
- `[ ]` **P2.6** (S) Shared `prepare_request()` for the provision-integration
  preamble (REST + DIDComm) — PR: ____

**Checkpoint 2:** `[ ]` ≥3k adapter LOC removed; wire behavior byte-compatible;
CLAUDE.md hot-spots section updated.

## Phase 3 — Strategic convergence + hygiene (ongoing)

- `[ ]` **P3.1** (XL) Trust Tasks as the single wire dialect — policy in
  CLAUDE.md + per-family migration PRs — deps: P2.2 — PR(s): ____
- `[ ]` **P3.2** (L) Store conformance suite (Local + Vsock); vsock op timeout;
  native `take`/`swap` opcodes (protocol bump with enclave-proxy) — deps:
  P1.3 — PR: ____
- `[ ]` **P3.3** (M) Vetted CMS/DER crate + real-KMS golden vector; bounded KMS
  retry at boot — PR: ____
- `[ ]` **P3.4** (S) `--expect-pcr0/8` pinning in `pnm bootstrap connect` — PR: ____
- `[ ]` **P3.5** (S) `cargo hack --each-feature` CI + REST-only test job — PR: ____
- `[ ]` **P3.6** (M) Pure `BootDecision` resolver in kms_bootstrap with full
  truth-table tests — PR: ____
- `[ ]` **P3.7a** (M) Split `credential_exchange.rs` by flow; co-locate DCQL
  format trio in `format.rs` — PR: ____
- `[ ]` **P3.7b** (S) Rename the vault/vault collision (`cred_vault` /
  `secret_vault`) — PR: ____
- `[ ]` **P3.7c** (M) main.rs → `cli/` modules; `requires_seal_check()` table — PR: ____
- `[ ]` **P3.7d** (M) Hoist duplicated clap enums + alias shims into
  `vta-cli-common`; fix offline `services webauthn` parity — PR: ____
- `[ ]` **P3.7e** (S) Delete dead surface: offline `services report`, legacy
  `webvh-*` alias enums — PR: ____
- `[ ]` **P3.7f** (M) Tagged `SecretsBackendInput` enum replaces flat
  `SecretsConfig`; generated env-override ladder; fix `blocked_vars` gaps — PR: ____
- `[ ]` **P3.8** (S) `wire_v0_2` path-registry drift-guard test + 0.1 sunset
  plan — PR: ____
