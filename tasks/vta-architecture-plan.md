# VTA Architecture Simplification & Hardening Plan

Source: full architecture review of vta-service + vti-common + vta-sdk (2026-06-10,
six-subsystem fan-out review). This document is self-contained — it can be executed
over time without the original review conversation.
Task checklist: `tasks/vta-architecture-todo.md`.

**Goal:** cover everything the VTA does today with less code (~7–9k LOC reduction in
an ~87k-LOC crate), while closing the security gaps found, making the service harder
to misconfigure, and converging on the four "house patterns" the codebase already
contains but applies inconsistently:

1. `vti-common::auth` extractors/handlers — for *all* auth paths
2. `ProvisionIntegrationDeps`-style dep structs — for *all* operation signatures
3. `WizardInputs` / `apply_inputs` — for *all* setup paths
4. The Trust-Task dispatcher — as the convergence layer for *all* wire surfaces

## How to use this plan

- Each task is one PR-sized vertical slice: root-cause fix + regression test +
  doc touch, verified before merge. No horizontal "change all signatures" PRs.
- Conventions per workspace CLAUDE.md: `cargo fmt`, DCO-signed commits (`-s`),
  full CI (tests, clippy, cargo deny) before opening a PR, branch off main only
  after the prior PR merges.
- Sizes: **S** ≤ ½ day, **M** 1–2 days, **L** 3–5 days, **XL** needs its own design note.
- Order within a phase is flexible unless a dependency is listed. Phases have
  checkpoints — don't start the next phase's *refactors* until the checkpoint
  passes (Phase 0 fixes can land any time).
- Tick items off in the todo file as they merge; record the PR number there.

## Dependency graph (phase level)

```
Phase 0 (security/correctness fixes) ──────────────┐  independent, parallelizable
                                                    ▼
Phase 1 (kill the divergence engines) ──► Checkpoint 1
        P1.1 AppState  ─────────────────► P2.* (all adapter refactors assume one state)
        P1.3 keyspace registry ─────────► P2.3, P3.2
                                                    ▼
Phase 2 (collapse adapter shells) ──────► Checkpoint 2
        P2.0 vault wire tests ──────────► P2.4 (tests BEFORE moving logic)
                                                    ▼
Phase 3 (strategic convergence + hygiene)
```

---

## Phase 0 — Security & correctness fixes (do regardless of any refactor)

These are bugs/gaps, not refactors. Mostly independent; land in any order.
Highest severity first.

### P0.1 — AAD binding for TEE keyspace encryption + encrypt `sealed_nonces`/`cache` (M)
**Problem:** `encrypt_value` (`vti-common/src/store/encryption.rs:8-25`) is
AES-256-GCM with no associated data. Ciphertext is bound to nothing, so a
compromised Nitro parent (which owns the fjall DB) can cut-and-paste values
between keys without breaking crypto. `sealed_nonces` and `cache` keyspaces are
created with **no** encryption at all (`server.rs:219,227,425,428`) — rolling back
`sealed_nonces` re-enables sealed-bundle replay.
**Change:** AAD = `keyspace || 0x00 || key` on encrypt/decrypt (both local and
vsock callers); apply `apply_encryption` to `sealed_nonces` (and `cache` unless a
documented reason exists). Needs a one-shot re-encrypt-on-boot migration for
existing TEE deployments (or document as breaking for next TEE release).
**Accept:** decrypting a value under the wrong key/keyspace fails AEAD; test
proves cross-key paste rejected; existing local (non-encrypted) deployments
unaffected.
**Verify:** unit tests in `encryption.rs`; vsock codec tests still pass.

### P0.2 — Enclave-side anti-rollback anchor for security-critical singletons (XL — design note first)
**Problem:** even with P0.1, the untrusted parent can *delete* or *replay whole
ciphertexts*. Deleting `BOOTSTRAP_CARVEOUT_CLOSED_KEY` (`routes/bootstrap.rs:263-266`)
reopens the single-use Mode-B carve-out → parent compromise mints a fresh admin.
Replaying old ACL rows resurrects revoked admins. Confidentiality is enforced;
integrity/freshness is not.
**Change:** write a design note (`docs/05-design-notes/`) for an enclave-anchored
integrity root — e.g. a hash/Merkle root or monotonic counter over the
carve-out sentinel, JWT fingerprint, and ACL keyspace, sealed via KMS/NSM and
checked at boot and on security-relevant reads. Then implement.
**Accept:** a deleted carve-out sentinel or replayed ACL row is detected at boot
(fail closed with operator guidance); threat model in `docs/02-vta/tee-architecture.md`
updated to state integrity is enforced, not just confidentiality.
**Depends:** P0.1 (AAD groundwork).

### P0.3 — `create_key`/`import_key` must not overwrite, and must validate `key_id` (S)
**Problem:** `operations/keys.rs:138` and `:285` insert with no existence check
and no charset restriction. A context-scoped admin can pass
`key_id = "{vta_did}#key-0"` and silently remap the VTA's own signing-key record.
`rename_key` already does this right via `swap` (`keys.rs:428`).
**Change:** existence check (Conflict on collision, matching the rename pattern)
+ `vti_common::identifier::validate_identifier` on `key_id` in both ops.
**Accept:** failing test reproducing the `#key-0` overwrite, then green; Conflict
error carries the operator-friendly suggested fix.

### P0.4 — One locked counter allocator; fix the context-index race (S)
**Problem:** `allocate_context_index` (`vta-service/src/contexts/mod.rs:48-66`)
has the exact read-modify-write race `allocate_path` was already patched for
(`keys/paths.rs:20` `ALLOC_LOCK` + regression test). Two concurrent
`create_context` calls can receive the same BIP-32 subtree → identical private
keys across trust boundaries. `rotate_seed` and `get_or_create_salt`
(`imported.rs:35-45`) have the same pattern.
**Change:** extract one `counter.rs` module — single locked
`allocate(ks, counter_key)` — used by paths, contexts, and seeds; lock
`get_or_create_salt` and `rotate_seed`.
**Accept:** port the existing concurrency regression test pattern
(`paths.rs:61-94`) to contexts; three hand-rolled LE-u32 RMWs replaced by one.

### P0.5 — Backup/restore: no key reuse, no privilege loss, crash-safe import (L)
**Problem (3 parts):** (a) restore doesn't export `path_counter:*` /
`ctx_counter:{parent}` → next key minted after restore **derives the same private
key** as a restored one; (b) `AclEntryBackup` (`operations/backup/mod.rs:148-171`)
carries 6 of 13 `AclEntry` fields → expired grants restore as permanent,
step-up floors and capability restrictions silently stripped; also the
`unwrap_or("Viewer")` fallback (`:156`) emits a role string `Role::parse` rejects;
(c) `apply_import` (`:383-405`) clears keyspaces then rewrites with no sentinel —
crash mid-import leaves hybrid state.
**Change:** export all counter keys (or recompute `max(existing)+1` on import);
serialize full `AclEntry` (bump backup format version, accept v1 on import);
add an import-in-progress sentinel checked at boot. Decide + document whether
`vault`, operator `did_templates`, and `sealed_nonces` join the payload (note:
omitting `sealed_nonces` re-opens replay after restore).
**Accept:** round-trip test — backup → restore onto fresh store → mint key →
assert derivation path not reused; ACL entry round-trips all 13 fields;
simulated crash mid-import detected at boot.

### P0.6 — TEE seed rotation: stop silent loss (S)
**Problem:** `POST /keys/seeds/rotate` isn't gated in TEE builds, but
`KmsTeeSeedStore::set` (`tee/kms_tee.rs:45-61`) updates memory only and nothing
calls `re_encrypt_bootstrap_secrets` on the rotation path. After restart, KMS
restores the *old* seed while `active_seed_id` points at a generation whose
bytes no longer exist — every post-rotation key unrecoverable.
**Change:** either wire re-encryption into the rotation path or reject rotation
in TEE mode with a typed error + operator guidance. (Rejecting is the safe
minimum; re-encryption can follow.)
**Accept:** TEE-mode rotate either persists correctly across a simulated
restart or returns the typed refusal; non-TEE rotation unaffected.

### P0.7 — Seed-byte hygiene: `Zeroizing` end-to-end + encrypt retired seeds (M)
**Problem:** `load_seed_bytes` (`keys/seeds.rs:91-110`) returns bare `Vec<u8>`;
every consumer lets it drop unwiped (while diligently zeroizing *derived*
secrets). Retired seeds are archived as plaintext hex (`seeds.rs:142`),
protected only if keyspace encryption happens to be configured.
**Change:** return `zeroize::Zeroizing<Vec<u8>>` from `SeedStore::get`/
`load_seed_bytes` (fixes all call sites by type); encrypt the retired-seed
archive independently of the storage-encryption flag (reuse the imported-secrets
KEK pattern, `imported.rs:21-32`). Also correct the misleading "secure deletion"
overwrite claim in `delete_secret` (`imported.rs:148-158`) — LSM trees keep old
SSTables; fix the comment or drop the theater.
**Accept:** compiles with `Zeroizing` types (no `.clone()` escapes added);
retired seed rows on disk are ciphertext in a default non-TEE config.

### P0.8 — Carve-out close is atomic and durable (S)
**Problem:** in `mint_mode_b`, sentinel write (`:263-266`) and ACL insert
(`:271`) are two writes with no `persist()` before the bundle is returned.
Crash between them bricks the VTA (closed carve-out, no admin); crash after
return but before fsync can lose both → carve-out reopens after the admin
bundle already left the enclave.
**Change:** write ACL first, then sentinel, then one explicit `store.persist()`
before sealing/returning the bundle — persisted states become {nothing} or
{both}. Keep `MODE_B_LOCK` spanning the whole sequence and keep the existing
16-task concurrency test (`bootstrap.rs:426-492`) green. Add explicit
`persist()` after counter allocation and admin ACL grants too.
**Accept:** ordering asserted by test; concurrency test unchanged and green.

### P0.9 — Config validation at boot; no half-started service (M)
**Problem:** `AppConfig` has no `deny_unknown_fields` (`config.rs:10`) — typo'd
keys silently ignored; missing `vta_did`/JWT keys at boot → `warn!` and serve
with all auth endpoints dead (`server.rs:1106-1311`), passing port-liveness
checks. The good cross-field validation (`from_toml.rs:728-829`) only runs for
setup files. `create_seed_store` silently falls back to `PlaintextSeedStore`
(`keys/seed_store/mod.rs:122-129`) — one wrong TOML key writes the master seed
to disk in clear.
**Change:** hoist the setup rules into a shared `config::validate(&AppConfig)`
run at daemon boot AND by setup; `deny_unknown_fields` (or an unknown-key
warning pass) on `AppConfig`; hard-fail on missing identity/JWT keys unless
`--allow-degraded`; plaintext seed-store fallback requires an explicit
`secrets.backend = "plaintext"` opt-in.
**Accept:** boot with typo'd key → error names the key; boot without identity
→ exit non-zero with fix-suggesting message; `--allow-degraded` preserves the
old behavior for dev.

### P0.10 — Request timeouts + rate-limit branch hygiene (S)
**Problem:** no `TimeoutLayer` anywhere; REST runs on a current-thread runtime
(`server.rs:1010`), so one slow handler (mediator handshake, remote DID
resolution) starves everything. `GET /attestation/status` and
`/attestation/did-log` are unauth routes registered on the *main* router —
outside the governor (`routes/mod.rs:363-376`), breaking the "branch ⇒ posture"
invariant. `/backup/blob` uses `DefaultBodyLimit::disable()` with a
handler-enforced cap and has no rate limit.
**Change:** global `TimeoutLayer` (generous, e.g. 60s) + per-branch overrides;
move attestation routes onto the governed branch; replace `disable()` with an
explicit 100 MB layer on the blob branch + a scoped governor.
**Accept:** route-table test asserting every unauth route is on a governed
branch; slow-handler test times out instead of hanging.

### P0.11 — BBS: matchable ⇒ presentable (S)
**Problem:** `dcql_format` (`operations/credential_exchange.rs:1027-1033`) maps
`Bbs2023 → "ldp_vc"` so held BBS credentials match verifier queries, but
`present_single` (`:595-598`) has no BBS arm — and the whole `vp_token` fails on
first error, killing other matched credentials too. `present_bbs` exists, fully
tested, just unwired.
**Change:** wire `present_bbs` into `present_single` (preferred — it's tested)
or return `None` from `dcql_format` for `Bbs2023` until wired. Add a unit test
asserting every format `dcql_format` admits has a `present_single` arm.
**Accept:** the matchable⇒presentable test exists and passes.
**Note:** BBS issuer signing remains audit-gated (#294) — this task only fixes
the holder-side present path for already-held BBS credentials.

### P0.12 — Deferred-presentation lifecycle: sweeper + reachable approval (M)
**Problem:** every untrusted-verifier query writes a `pending-present:` record
(`messaging/handlers.rs:2032-2042`) with a 24h TTL enforced **only at approve
time**; there is no sweeper and `approve/deny/list` have **zero callers** — every
deferral is stuck-by-construction and records grow unbounded at DIDComm message
rate.
**Change:** expiry sweeper (reuse the `DrainSweeper` pattern), delete-on-terminal-
state; only then expose approve/deny/list on the wire (TT slice). Comment the
verifier-controlled `thid`-as-record-id behavior (`handlers.rs:2030`).
**Accept:** expired/terminal records removed by sweeper test; approval surface
reachable end-to-end (defer → list → approve → re-present).

### P0.13 — Resolve the cross-transport step-up asymmetries (S — decision + small code)
**Problem:** REST `swap_acl` gates on `RequireStepUp<AclSwapKeyOp>`
(`routes/acl.rs:188`); the DIDComm path has no step-up gate
(`messaging/auth.rs:46` hard-codes `acr: "aal1"`) and nothing documents whether
that's intended. Separately, password-vault TT handlers accept a
`step_up_proof` field and ignore it (`routes/trust_tasks/vault.rs:249,321,1516`,
`#[allow(dead_code)]`).
**Change:** decide policy: either enforce step-up-equivalent on DIDComm swap_acl
(or refuse the op over DIDComm), and either enforce vault `step_up_proof` via the
existing `RequireStepUp` machinery or reject requests that include it. Document
the decision where the gates live. Also align the DIDComm post-verification
mismatch error with REST's 400-class (`handlers.rs:577,620` use `handler_err` →
opaque internal-error).
**Accept:** behavior identical or explicitly documented per transport; ignored-
field case gone (enforced or rejected).

### P0.14 — Tolerant list iteration: one poisoned row must not kill a subsystem (S)
**Problem:** `list_acl_entries` (`vti-common/acl/mod.rs:508-515`),
`list_contexts`, `list_keys` do `serde_json::from_slice(...)?` in a loop — one
undeserializable row aborts the entire listing (a corrupt ACL row takes down
ACL management *and* auth paths that list entries). Backup export silently
*drops* bad rows instead — also wrong for a backup.
**Change:** skip+`warn!`+metric on poisoned rows in list paths; make backup
export **fail loudly** on a row it can't serialize (a backup that silently
omits rows is worse than one that fails).
**Accept:** test with an injected garbage row: listing returns the good rows +
logs; backup export errors.

**Checkpoint 0:** all P0 merged or explicitly deferred with an issue; full CI
green; `docs/02-vta/tee-architecture.md` reflects P0.1/P0.2 status.

---

## Phase 1 — Kill the divergence engines (small PRs, high correctness leverage)

### P1.1 — Single `AppState` construction (M) — DO FIRST
**Problem:** AppState is built three times (`build_app_state` `server.rs:196-320`,
inline in `run()` `:590-637`, and the DIDComm `VtaState` `:541-577`) and has
**already diverged into a live bug**: REST and DIDComm each get their own
`WebvhAuthLocks::new()` (`:562` vs `:617`) — so the per-server auth-cache lock
doesn't serialize across transports — and their own `Arc<RwLock<AppConfig>>`
(`:565` vs `:620`), so `PATCH /config` mutates the REST copy while DIDComm reads
stale config until restart.
**Change:** `build_app_state` becomes the only constructor; `run()` patches the
didcomm fields; `VtaState` borrows the same Arcs (locks, config, registry,
telemetry).
**Accept:** exactly one `WebvhAuthLocks::new()` and one config `RwLock` in the
running process (assert via test or grep-in-CI); config update visible on both
transports in an integration test.

### P1.2 — Interactive wizard compiles to `WizardInputs` + `apply_inputs` (L)
**Problem:** `setup/interactive.rs` (1,438 LOC) and `setup/from_toml.rs`
duplicate ~500 LOC step-for-step and have drifted: interactive hardcodes
`webauthn: false` (`interactive.rs:845-853`) and can't express
`trust_xff`/`cors_origins`; two inline scratch-config literals vs the shared fn.
The plan struct (`WizardInputs`) and engine (`apply_inputs`,
`from_toml.rs:409`) already exist.
**Change:** interactive wizard becomes a prompt loop that constructs
`WizardInputs` and calls `apply_inputs`. Add the 3 missing advanced-DID optional
fields (document-from-file, pre-signed did.jsonl, existing key IDs) and a
2-method `SetupUi` trait (`confirm_mnemonic`, `did_log_path`) with a silent impl
for `--from`.
**Accept:** −500 LOC; interactive.rs is pure prompting (~600 LOC); a golden test
asserts interactive-with-scripted-answers and `--from <equivalent toml>` produce
identical `config.toml` + store state; webauthn/trust_xff/cors expressible
interactively.

### P1.3 — Keyspace + key-format registry (M)
**Problem:** ~17 keyspaces, one named constant, ~50 scattered string literals —
already produced a test running against keyspace `"imported"` while production
uses `"imported_secrets"` (`operations/export.rs:308`, `operations/contexts.rs:660`),
and the backup counter omission (P0.5). Key formats are ad-hoc `format!` with
mixed record families per keyspace (e.g. the `keys` keyspace holds `key:`,
`seed:`, `path_counter:`, `active_seed_id`, `imported_kek_salt`).
**Change:** one module of `const` keyspace names + typed key constructors
(`Key::Acl(did)`, `Key::PathCounter(base)`, …) used by server, offline CLIs,
backup, and tests. Fix the `"imported"` test divergence.
**Accept:** zero bare keyspace string literals outside the registry (CI grep);
backup export enumerates keyspaces from the registry so a new keyspace can't be
silently omitted.

### P1.4 — One token-mint path; one DI-proof verifier (M)
**Problem:** passkey login (`routes/auth.rs:638-792`, ~230 LOC) re-implements
session/JWT/refresh-token minting instead of using
`vti-common/src/auth/handlers/authenticate.rs` — the one auth path that can
drift from session-state/refresh rules. The DI-proof verifier exists twice
(`routes/auth.rs:287` "mirrors" `trust_tasks/step_up.rs::verify_did_signed_gate`).
**Change:** route passkey-finish through the canonical handler (an
`handle_authenticate_with_aal` entry already exists per `handlers/mod.rs:18`);
move the eddsa-jcs-2022 proof verifier into `vti-common::auth` and call it from
both sites.
**Accept:** one mint path (token/refresh semantics covered by the existing
vti-common tests); one verifier with both former call sites delegating.

**Checkpoint 1:** P1.1–P1.4 merged; e2e suite green; no behavior changes
observed by `pnm`/`cnm` CLIs (smoke the cold-start + provision-integration
flows from `docs/02-vta/cold-start.md`).

---

## Phase 2 — Collapse the adapter shells (~3–5k LOC removed)

All of these assume P1.1 (single state). Tests-before-moves discipline applies.

### P2.0 — Wire-test the password-vault TT slice BEFORE touching it (M)
**Problem:** `routes/trust_tasks/vault.rs` is ~1,992 code lines with ~75 test
lines (only `resolve_siop_audience`). Capability gates, context-scope
enforcement, release JWE sealing, both proxy-login drivers — untested at the
wire level. The step-up integration suite (`tests/step_up_approve_response.rs`)
is the ready-made template.
**Accept:** `/api/trust-tasks` integration coverage for every vault URI:
gate-denied, cross-context-denied (checked-after-load semantics preserved),
happy path per handler. This is the safety net for P2.4.

### P2.1 — Generic DIDComm handler adapter (L)
**Problem:** ~45 of 54 handlers in `messaging/handlers.rs` (2,093 LOC) + 11 in
`handlers_protocol.rs` are the same 25–35-line stanza (auth → gate → deserialize
→ op → respond). `handlers_protocol.rs` hand-rolls per-op problem-report matches;
some validation failures use `handler_err` → opaque `internal-error`.
**Change:** `dispatch<B: DeserializeOwned, F, R>(msg, state, gate, op)` (or a
small macro) collapsing each handler to ~6 lines; fold the protocol error
matches into `app_err_to_response` / a `ToProblemReport` trait. Preserve the
typed `e.p.msg.forbidden` vs `unauthorized` distinction.
**Accept:** −1,200–1,500 LOC; problem-report codes byte-identical for existing
flows (pin with tests); no handler can skip the gate by construction.

### P2.2 — Declarative Trust-Task slice registration (L)
**Problem:** every TT slice repeats handler + dispatch-match arm +
`DISPATCHED_URIS` parity entry; the dispatcher match in
`routes/trust_tasks/mod.rs:349-601` has ~75 identical-shaped arms; five
near-identical `require_*` capability fns in vault.rs (`:365-477`).
**Change:** a registration macro generating handler + match arm + parity entry
from one declaration (`route_slice!(URI => gate, Body, operations::x::y)`), plus
a shared capability-gate helper. Keep `enforce_context_scope` explicit
per-handler (its argument legitimately differs — request field vs loaded entry).
Keep `validate_basic` and the 0.2 down/up-convert in the dispatcher spine.
**Accept:** −1,000–1,400 LOC; the parity harness
(`dispatcher_handles_every_vta_sdk_uri`) becomes structurally impossible to
violate; new slice = one line.

### P2.3 — `ServiceLifecycle` parameterization of protocol ops + one error mapping (L)
**Problem:** `operations/protocol/` is 12 files (~5,100 LOC):
{enable,update,disable,rollback} × {rest,didcomm,webauthn}. The rest+webauthn
families differ only in validation fn, document patchers, snapshot variant,
telemetry kind. Each file repeats a 9–12-variant error enum + identical `From`
impls; 15 sites collapse `AppError → Storage(String)`, 16 collapse auth errors
to `Auth(String)`. `routes/protocol.rs` carries 11 hand-written `*HttpError`
enums + `IntoResponse` impls (~1,150 LOC of mechanical mapping).
**Change:** (a) `ServiceLifecycle` trait + generic run fns for the rest+webauthn
families; (b) a shared `publish_service_patch()` helper (steps: preconditions →
snapshot → patch → publish → runtime-state → telemetry) composed by the didcomm
family — do **not** force didcomm (drain/handshake/registry) into the generic;
(c) one `ProtocolOpError` carrying `#[from] AppError` (keep Conflict/NotFound
typed); (d) one error-mapping trait (`status()/code()/suggested_fix()`) + a
blanket `IntoResponse`, with the 86 `suggested_fix` strings moved next to their
variants — they are the operator-UX contract, keep every one.
**Accept:** −2,500–3,000 LOC across operations + routes/protocol.rs; all 12
op integration tests green; `PROTOCOL_LOCK` taken once at the top of the
generic; brick-prevention (`would_violate_last_service`) consulted before any
I/O on every disable/rollback path; snapshot-before-publish preserved.

### P2.4 — Move misplaced business logic out of routes (L)
**Problem (4 areas):** (a) the step-up gate engine (~900 LOC) lives in
`routes/trust_tasks/step_up.rs` and is imported by other modules —
`operations/step_up_policy.rs:4` documents the inversion; (b)
`routes/trust_tasks/vault.rs` holds release JWE sealing, proxy-login drivers,
SIOP audience resolution, session-blob builders (~1,300 LOC of operations work);
(c) `routes/backup_blob.rs` (651 LOC, zero `operations::` calls); (d)
`messaging/handlers.rs:132-138` calls `routes::trust_tasks::dispatch_trust_task_core`
and round-trips through an `axum::Response` to extract JSON.
**Change:** `dispatch_trust_task_core` → `operations/` (typed return; both
transports render); step-up engine → `operations/step_up/`; vault route logic →
`operations/secret_vault/{release,proxy_login,sign_trust_task}.rs`; backup-blob
state machine → `operations/`. Route files become ~25-line-per-handler adapters
(the house style — cf. `routes/trust_tasks/device.rs`).
**Depends:** P2.0 (tests first), P2.2 (less to move).
**Accept:** vault route file ≤ ~450 LOC; messaging no longer imports `routes::`;
P2.0's wire tests green unchanged; backup-blob's delete-before-state-flip
ordering preserved.

### P2.5 — Dep structs for operation signatures (M)
**Problem:** operations take up to 19 positional args
(`routes/protocol.rs:140-165`); 39 `#[allow(clippy::too_many_arguments)]` sites;
adding a keyspace is a 6+-file change. `ProvisionIntegrationDeps`
(`provision_integration/mod.rs:108-141`, with `From<&AppState>`/`From<&VtaState>`)
is the proven pattern; `operations::Keyspaces::from_app_state` is used exactly
once. Also: the `#[cfg(not(feature="webvh"))] panic!` inside a `From` impl
(`messaging/router.rs:120-123`) is a runtime landmine — make it fallible or
cfg-gate the impl.
**Change:** group AppState (35 fields) into ~4 sub-structs (`Keyspaces`,
`AuthInfra`, `Messaging`, `Runtime`); per-family dep structs for protocol ops;
remove the `too_many_arguments` allows as they fall.
**Accept:** no operation takes >6 args; adding a keyspace touches registry +
one struct.

### P2.6 — Hoist the duplicated provision-integration preamble (S)
**Problem:** REST (`routes/bootstrap.rs:561-690`) and DIDComm
(`messaging/handlers.rs:1427-1603`) each re-implement the ~80-line preamble: VP
verify, `AssertionMode` mapping, context inference (incl. `AmbiguousContext`),
`ensure_target_context_or_create`, summary mapping — policy logic duplicated in
the most security-sensitive flow.
**Change:** `operations/provision_integration::prepare_request()` used by both.
Preserve: relayer ≠ holder onion auth (no "sender == VP holder" check — it's a
feature, documented at `handlers.rs:1464-1491`) and VP verification over bytes
as received (`verify_value` on `request_raw`).
**Accept:** −150 LOC; both transports' provision e2e tests green.

**Checkpoint 2:** adapter LOC reduction realized (target ≥3k); wire behavior
pinned by P2.0/P2.1 tests byte-compatible; CLAUDE.md crate-map "hot spots"
section updated to reflect new file sizes/locations.

---

## Phase 3 — Strategic convergence + hygiene (ongoing)

### P3.1 — Trust Tasks as the single wire dialect (XL — policy + per-family PRs)
Adopt TT URIs for new protocol families by default; migrate existing bespoke
REST+DIDComm handler pairs family-by-family onto the (now declarative, P2.2)
dispatcher, then delete the pair. Write the policy into the workspace CLAUDE.md.
Each migrated family is its own PR with dual-accept during transition.

### P3.2 — Store backend conformance + vsock robustness (L)
One generic conformance suite parameterized over `KeyspaceHandle`, run against
Local and Vsock-with-in-process-proxy-stub (closes the documented
"parity asserted but under-tested" gap). Add: vsock op timeout (today
`read_exact` can hang forever and the single shared connection serializes
everything — `vti-common/src/store/vsock.rs:97-113,131`), native `take`/`swap`
opcodes (protocol bump, coordinated with enclave-proxy) to retire the TOCTOUs —
local `take_raw` atomicity is load-bearing for refresh-token single-use. Typed
errors through the vsock decode path instead of blanket `AppError::Internal`.

### P3.3 — Replace the hand-rolled CMS/BER parser in the TCB (M)
`tee/kms_bootstrap.rs:842-1202` is tested only against fixtures its author
wrote; real-KMS encoding variance (BER indefinite-length, EXPLICIT/IMPLICIT
`[0]`, GCMParameters forms) surfaces only at enclave boot with no debugger.
Capture one real `CiphertextForRecipient` blob as a golden vector, then swap to
a vetted `der`/CMS crate. Also: bounded retry/backoff on KMS-unavailable-at-boot
instead of exit(1) crash-loop.

### P3.4 — Client-side PCR pinning (S)
`verify_nitro_assertion` (`vta-sdk/src/attestation.rs:122-138`) extracts PCR0/8
but never checks them; any genuine Nitro enclave passes (only the KMS key
policy pins the image). Add `--expect-pcr0/--expect-pcr8` to
`pnm bootstrap connect` with a typed `PcrMismatch`; document alongside the KMS
`--old-pcr0` rotation flow.

### P3.5 — Feature-matrix CI (S)
`gcp-secrets`, `vault-secrets`, `config-seed`, `bbs`, and REST-less builds are
never built in CI (only 3 of 15 vta-service feature combos are checked). Add
`cargo hack check --each-feature -p vta-service -p vti-common` + one
`--no-default-features --features rest,keyring,cli-synthesis` test job
(~15 lines of YAML).

### P3.6 — Extract the TEE boot decision as a pure function (M)
The "reset identity vs first boot vs subsequent boot" policy — the
highest-consequence decision in the TCB — is buried in a decrypt-error match arm
(`kms_bootstrap.rs:119-157`). Extract `enum BootDecision` + a pure resolver
`(ciphertexts_present, kms_error_class, config_flags) -> BootDecision`,
unit-test every cell of the truth table (identity auto-clear ONLY on
`AccessDenied` or explicit `allow_kms_reinit` — that coupling IS the
PCR-rotation flow and must be preserved).

### P3.7 — Naming + decomposition hygiene (M, several small PRs)
- Split `operations/credential_exchange.rs` (2,349 LOC) by flow into
  `{receive,offer,matching,present,pending}.rs` (mirrors the
  provision_integration precedent; net 0 LOC). Co-locate the DCQL format trio
  (`dcql_format`/`candidate_from_stored`/`present_single`) into one `format.rs`
  with the matchable⇒presentable test (P0.11 made it exist).
- Rename one of the two unrelated "vault" subsystems (`vault/` → `cred_vault/`
  or `operations/vault/` → `operations/secret_vault/` — the latter falls out of
  P2.4). Today `routes/trust_tasks/vault.rs` does NOT route to `src/vault/`;
  the naming actively misleads navigation.
- Extract main.rs (2,447 LOC) clap trees + 6 inline helpers into `cli/` modules;
  seal-check gating becomes one auditable `requires_seal_check()` table. Note
  `export_admin`/`reconstruct_credential` export private keys and currently live
  in main.rs.
- Hoist the duplicated clap enums + legacy-alias `From` shims
  (`DidMgmtCommands`/`WebvhCommands`/services) into `vta-cli-common`
  (~−450–600 LOC across `vta` and `pnm`); fixes the offline `services webauthn`
  parity gap by construction.
- Delete dead surface: offline `vta services report` (always empty by design,
  `services_cli.rs:666-675`); legacy `webvh-*` alias enums on the promised
  schedule (~−700 LOC).
- Replace the flat 23-field `SecretsConfig` with the tagged
  `SecretsBackendInput` enum moved into `config.rs` (serde alias for the flat
  shape for one release) — one backend by construction, kills the silent
  first-match ladder; generate the env-override ladder (note: the `blocked_vars`
  KMS allowlist is already missing all `VTA_SECRETS_VAULT_*` names).

### P3.8 — wire_v0_2 drift guard + sunset (S)
The 0.1/0.2 dual-accept's `request_paths`/`response_paths` are stringly-typed
shadows of the serde structs (`wire_v0_2.rs:55-135`) — a new enum field silently
ships wrong casing. Add a round-trip test asserting every kebab-case value in
each 0.1 response JSON is reachable from `response_paths` (~60 LOC). Write the
0.1 sunset plan so the double bookkeeping is temporary.

---

## Invariants any task must preserve (the do-not-break list)

Security/crypto:
- `MODE_B_LOCK` spans the entire carve-out check→mint→close; sentinel/ACL write
  ordering per P0.8; carve-out single-use.
- `PROTOCOL_LOCK` held across handshake→snapshot→publish→registry→persist
  (taken once, never per-step); read paths lock-free.
- `would_violate_last_service` brick-prevention consulted before any I/O on
  every disable/rollback path; no `--force` escape.
- Snapshot-before-publish; rollback is fail-forward only (WebVH append-only).
- Handshake-before-promotion for mediator changes; `--force` never skips
  stage-1 resolve; `MIN_DRAIN_TTL_OVER_DIDCOMM` 1h floor / 30d cap.
- `gate_present` is the sole disclosure gate; consent proof re-verified inside
  `consent::get`; consent default-deny (empty claim set refused); no vault
  enumeration primitive (discovery only via indexes/DCQL discriminators).
- `resolve_holder_keys` is the only path from subject DID to signing key.
- Relayer ≠ holder onion auth in provision-integration; VP verified over bytes
  as received.
- Counters monotonic, BIP-32 paths never reallocated (the derive-on-demand
  model rests on this); create-new-before-delete-old in `swap_acl`;
  archive-old-seed-before-write-new in `rotate_seed`.
- `take_raw` atomicity (Local) — refresh-token single-use.
- Attested-KMS failure terminal on real hardware unless
  `allow_unattested_fallback`; identity auto-clear only on `AccessDenied`/
  explicit reinit; env-override lockout when `kms.is_some()`.
- Step-up challenges single-use, consumed-on-read even when expired.
- Signed payloads never byte-transformed in 0.2 dual-accept (typed handlers
  only).
- Status-check semantics at present time: fail-open on fetch error,
  fail-closed on fetched revocation — intentional, documented; don't "fix"
  silently in either direction.

Wire/compat:
- `SealedPayloadV1` variants additive only; HPKE suite and info string fixed.
- Stored-record evolution additive-only with least-privilege `#[serde(default)]`
  defaults; format inference contract (string=SD-JWT, object+proof=DI,
  bbs-2023=BBS) additive only.
- `deny_unknown_fields` on auth TT response payloads — don't add fields.
- Typed `e.p.msg.forbidden` vs `e.p.msg.unauthorized`; the `suggested_fix`
  strings are the operator-UX contract.
- Vsock wire-protocol constants are a contract with the out-of-tree proxy —
  protocol bump on both sides only.

Runtime topology:
- Router branch ⇒ posture: unauth routes on the governed 64 KB branch; JWT
  routes off the limiter; `/auth/portal` off both by documented design;
  `/acl/swap` registered before `/acl/{did}`; CORS wildcard filtered to None.
- TCP listener bound once outside the restart loop; storage thread joined last
  (flush-before-close).
- `AuthClaims` extractor checks session state in the store, not just JWT
  validity (it's the revocation mechanism).
- Keyspace encryption applied enclave-side before vsock; keys stay plaintext
  for prefix scans (don't "encrypt the keys too").
- Backup-blob one-shot ordering: file deleted before state flip.
- Deepest-first ordering in context-subtree deletion.
- TT dispatcher pre-checks (`validate_basic` expiry/recipient + 0.2 edge
  transform) stay in the spine, never per-slice.
