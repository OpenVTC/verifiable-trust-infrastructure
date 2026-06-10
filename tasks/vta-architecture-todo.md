# Todo: VTA Architecture Simplification & Hardening

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Plan with full problem statements, file references, acceptance criteria,
and the invariants do-not-break list: `tasks/vta-architecture-plan.md`.
Record the PR number next to each task as it merges.

Sizes: S ≤ ½ day · M 1–2 days · L 3–5 days · XL needs a design note first.

---

## Phase 0 — Security & correctness fixes (parallelizable, land any time)

- `[ ]` **P0.1** (M) AAD binding (`keyspace||key`) for keyspace encryption;
  encrypt `sealed_nonces` + `cache` — PR: ____
- `[ ]` **P0.2** (XL) Enclave-side anti-rollback anchor for carve-out sentinel /
  JWT fingerprint / ACL — design note first — deps: P0.1 — PR: ____
- `[~]` **P0.3** (S) `create_key`/`import_key`: existence check + identifier
  validation (closes `#key-0` overwrite) — branch `fix/p0.3-key-overwrite`.
  Scope grew during root-cause analysis: the store's multi-op "atomic"
  closures (take_raw/swap) were NOT actually atomic — added a shared
  per-keyspace write lock in LocalStore + `insert_if_absent` primitive +
  concurrency regression tests; also validated `rename_key`'s new id
  (wire-facing bypass) — PR: #341 (in review)
- `[~]` **P0.4** (S) Shared locked counter allocator; fix
  `allocate_context_index` race (same-subtree key derivation) —
  implemented on branch `fix/p0.4-counter-races`. Delivered:
  `vti-common/src/store/counter.rs` (app-level lock so the vsock backend
  is covered too); allocate_path + allocate_context_index delegate;
  `insert_raw_if_absent` closes the KEK salt race; ROTATE_LOCK serialises
  seed rotation; create_context claims its record atomically at both
  layers; concurrency regression tests for all four —
  PR: #342 (stacked on #341)
- `[ ]` **P0.5** (L) Backup/restore: export counters (no BIP-32 path reuse),
  full `AclEntry` round-trip, import-in-progress sentinel — PR: ____
- `[~]` **P0.6** (S) TEE seed rotation: reject or persist (no silent key loss) —
  branch `fix/p0.6-tee-seed-rotation`. Chose REJECT (the plan's safe minimum;
  in-place re-encryption is a follow-up). New `SeedStore::set_persists_across_restart()`
  (default true; `KmsTeeSeedStore` → false, fixed its misleading set() comment).
  Guard at the low-level `seeds::rotate_seed` chokepoint (catches offline CLI
  too) + a typed `AppError::Conflict` with operator guidance at
  `operations::seeds::rotate_seed` (runtime REST/DIDComm/TT path). Tests:
  refusal+no-mutation (tee), trait flag, existing non-TEE rotation unaffected
  — PR: #344 (in review). Follow-up: in-place re-encryption so TEE rotation
  works rather than refuses (needs runtime KMS access on KmsTeeSeedStore).
- `[ ]` **P0.7** (M) `Zeroizing` seed bytes end-to-end; encrypt retired-seed
  archive; fix "secure deletion" claim — PR: ____
- `[~]` **P0.8** (S) Atomic + persisted carve-out close — branch
  `fix/p0.8-carveout-durability`. Added `KeyspaceHandle::persist()` (local
  fsync + vsock OP_PERSIST passthrough). `mint_mode_b` now: seal first
  (fail-fast, no carve-out writes) → ACL → sentinel-via-`insert_raw_if_absent`
  (atomic claim, defence-in-depth beyond MODE_B_LOCK; compensating ACL
  delete on lost race) → `persist()` BEFORE returning the bundle (security
  barrier: no reopen-after-delivery). ACL-before-sentinel journal order so a
  torn fsync favours a recoverable reopen over a brick. Counter allocator
  also now fsyncs (path-counter loss = key reuse). Tests: persist-survives-
  reopen, carve-out-admits-one — PR: #343 (in review)
- `[ ]` **P0.9** (M) Boot-time `config::validate()`; `deny_unknown_fields`;
  hard-fail missing identity unless `--allow-degraded`; explicit opt-in for
  plaintext seed store — PR: ____
- `[ ]` **P0.10** (S) `TimeoutLayer`; attestation routes onto governed branch;
  explicit 100 MB layer + governor on `/backup/blob` — PR: ____
- `[ ]` **P0.11** (S) BBS matchable ⇒ presentable (wire `present_bbs` or
  unmatch in `dcql_format`) + guard test — PR: ____
- `[ ]` **P0.12** (M) Deferred-presentation sweeper + reachable
  approve/deny/list surface — PR: ____
- `[ ]` **P0.13** (S) Decide + enforce/document cross-transport step-up policy
  (DIDComm `swap_acl`; ignored vault `step_up_proof`) — PR: ____
- `[ ]` **P0.14** (S) Tolerant list iteration (skip+log poisoned rows); backup
  export fails loudly — PR: ____

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
