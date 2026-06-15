# Todo: VTC Architecture Simplification & Hardening

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Plan with full problem statements, file references, acceptance criteria,
and the invariants do-not-break list: `tasks/vtc-architecture-plan.md`.
Record the PR number next to each task as it merges.

Sizes: S ≤ ½ day · M 1–2 days · L 3–5 days · XL needs a design note first.

Note: VTC never targets TEE — no enclave/KMS/attestation work here (unlike VTA),
but encryption-at-rest for private-key keyspaces still applies (P0.7).

---

## Phase 0 — Security & correctness fixes (parallelizable, land any time)

- `[x]` **P0.1** (M) Status-list concurrency lock — revocation flips + slot
  allocations lost under concurrent RMW; wrap flip+`mark_revoked` together — PR: #355
  (also landed the `TestVtc`/`MockVtc` harness + 26-fixture migration, #348)
- `[x]` **P0.2** (L) Cross-community `recognise`: require holder proof + nonce +
  audience, bind VMC subject == VEC subject, fix unverified-actor audit — PR: #351
  (part 1: VMC↔VEC subject bind) + #354 (part 2: holder proof-of-possession)
- `[x]` **P0.3** (M) DIDComm handlers: authenticate sender via `encrypted_from_kid`,
  require authcrypt/non-anon (MessagePolicy); fix self-remove first — PR: #350
- `[x]` **P0.4** (M) Foreign-fetch client: `redirect(none)` + timeout + body-size
  cap; re-guard redirects; one shared client — PR: #357
- `[x]` **P0.5** (M) Move `join-requests` submit/accept/status onto the governed
  64 KB unauth branch (split the shared mount) — PR: #359
- `[x]` **P0.6** (S) Spawn `RetentionSweeper`; extend to `credx-pending:` /
  `present-challenge:` / `Failed` sync jobs; fix model.rs comment — PR: #361
- `[x]` **P0.7** (M) Encryption-at-rest (`with_encryption`) for `install`,
  `audit_key`, `passkey`; HKDF storage key (`vtc-storage-key/v1`) from the
  bundle Ed25519 seed. Back-compat via a one-shot idempotent/crash-safe
  `KeyspaceHandle::migrate_to_encrypted` (NOT a try-decrypt-else-plain
  fallback — that would reintroduce the cut-and-paste downgrade hole in the
  VTA-shared encryption module) — PR: #364
- `[x]` **P0.8** (S) Secret-store factory: hard-fail on set-but-uncompiled backend;
  `deny_unknown_fields` on `SecretsConfig` — PR: #381
- `[x]` **P0.9** (S) Configured-but-broken identity → hard-fail boot (not
  warn-and-serve-dead); pre-setup still degraded — PR: #382
- `[x]` **P0.10** (M) `spawn_blocking` for Argon2id (claim verify/hash);
  `TimeoutLayer` (30s); multi-thread REST runtime — PR: #391
- `[x]` **P0.11** (S) `relationships_by_did` colon-prefix collision — post-filter
  hydrated rows by issuer/subject — PR: #384
- `[x]` **P0.12** (M) Submit path: don't surface unverified VC claims under
  `verified:true` — null claims + `unknown` status on the raw-VP path — PR: #389
- `[x]` **P0.13** (S) Join-submit signature freshness/nonce/audience binding +
  per-applicant open-request dedup/cap — PR: #393
- `[x]` **P0.14** (M) Promote-to-admin through the role-change ceremony (honor
  `role_change.rego` + host invariants) — PR: #387
- `[x]` **P0.15** (S) `admit` serializing lock — duplicate-credential TOCTOU
  (match `depart`/`remint`) — PR: #385
- `[x]` **P0.16** (M) `check_acl` reads `VtcAclEntry` + maps `VtcRole→Role` —
  non-admin DID no longer 500s `/auth/challenge` with serde leak. Shared
  `crate::acl::resolve_auth_role` helper also fixes the identical bug in the
  passkey-login finish path — PR: #367
- `[x]` **P0.17** (S) 0600 perms on `config.toml`, plaintext secret file — PR: #370
- `[x]` **P0.18** (M) Rego eval timeout/instruction budget + input-size cap;
  fail-closed on bound exceeded — PR: #372
- `[x]` **P0.19** (S) `vtc status` trust-ping: use `decode_secret_store_value`
  (JSON bundle), drop the 64-byte assumption — PR: #374
- `[x]` **P0.20** (S) ACL/session scoping: gate `delete_acl` on AdminAuth + check
  target role; scope `revoke_sessions_by_did`/`session_list`; revoke sessions on
  downgrade — PR: #376
- `[x]` **P0.21** (S) Install `claim/start`: verify claim secret BEFORE taking the
  300s ceremony lock (anti-grief) — PR: #378

**Checkpoint 0:** `[x]` all P0 merged — every P0.1–P0.21 is on `main`
(P0.8 #381, P0.9 #382, P0.10 #391, P0.11 #384, P0.12 #389, P0.13 #393,
P0.14 #387, P0.15 #385); CI green; `[x]` docs updated —
`docs/03-vtc/trust-registry.md` (the renamed cross-community.md) recognise
holder-binding + vtc-mvp.md §8.4/§9.7/§13/§14.5 (P0.2/P0.3/P0.7) — PR: #379.
**Phase 0 complete.**

## Phase 1 — Kill the divergence engines

- `[x]` **P1.1** (L) One config-mutation surface (config_store canonical);
  `public_url`→registry requires_restart; profile owns name/desc; drop
  `vtc_did`/`vta_did` from update body; atomic save — **done** (#396, #405, #408).
  - `[x]` **part 1** (legacy `/v1/config`): `vtc_did`/`vta_did`→409; profile
    owns name/desc (GET reads from it); `public_url` persisted env-safe +
    atomic (tempfile-rename) with `pending_restart` — PR: #396
  - `[x]` **part 2a** (the latent gap): boot now folds the `config_store`
    db-overlay onto `AppConfig` (`apply_overrides`, `env > db > toml > default`)
    before anything derives from it — so a PATCH of a `requires_restart` key
    (`server.host`/`server.port`) is finally applied after restart — PR: #405
  - `[x]` **part 2b**: `public_url` migrated off `config.toml` onto the
    `config_store` overlay (REGISTRY `requires_restart` key; legacy `/v1/config` +
    admin PATCH both write `config_store`; GET reads effective; `persist_public_url`
    removed) — PR: #408
- `[x]` **P1.2** (M) Audit `PATCH /admin/config` + `PUT /profile`; replace
  `did:key:vtc-admin` sentinel with the real admin DID. `patch_config` emits
  `ConfigChanged` (redact_if for sensitive keys), `put_profile` emits
  `CommunityProfileUpdated`, all four sentinels (reload/restart/import×2) swapped
  for `admin.0.did`; audit is fail-closed (503 when a change can't be recorded) —
  PR: #400
- `[x]` **P1.3** (S) RTBF/registry audit emits awaited (not detached); re-emit on
  failure. `emit_override` awaited + fallible; `tick` emits overrides before
  advancing the cursor so a failed write re-walks/re-emits (at-least-once);
  `emit_outcome` stays detached (operational) — PR: #401
- `[x]` **P1.4** (M) Shared `mint_session_tokens` (passkey login gets AAL2 short
  TTL + audit); one `verify_domain_signed` helper (4 sites). Part 1: minter in
  vti-common, canonical + passkey paths delegate. Part 2: `did:key` holder-sig
  verifier dedup (submit/accept/status/rotate), byte-identical signed bytes —
  PR: #402
- `[x]` **P1.5** (S) Policy upload validates package matches purpose / yields a
  decision. `PolicyPurpose::expected_package()` (4 ceremony purposes) +
  `validate_purpose_package()` probing `data.<pkg>.{decision,allow}`; wired into
  upload + activate; fixtures migrated off `vtc.test` — PR: #404

**Checkpoint 1:** `[x]` **Phase 1 complete.** P1.1 (#396/#405/#408), P1.2 (#400),
P1.3 (#401), P1.4 (#402), P1.5 (#404) all merged or in review. e2e green on each
PR; admin-UI config/profile round-trips unchanged; recognise smoke unchanged.
**Next: Phase 2** (collapse adapter shells + move logic out of routes; deps
P1.1 + P1.4, both now done).

## Phase 2 — Collapse adapter shells & move logic out of routes (deps: P1.1, P1.4)

- `[x]` **P2.1** (L) Move join/leave/role-change orchestration out of routes into
  `ceremony::orchestrate` (role-change + leave) and `join::orchestrate` (join);
  shared auto-admit-vs-approve audit helper — deps: P1.4 — PR: #452 (audit-gap
  bug fix + shared `emit_admit_audit`), #459 (role-change), #460 (leave),
  #462 (join)
- `[x]` **P2.2** (M) One `assemble_facts` builder (`ceremony::assemble`); cached
  member counter (no full-keyspace scan per request) — PR: #453 (cached counter),
  #458 (facts-builder unification)
- `[x]` **P2.3** (L) Split `exchange.rs` (2,585) → `exchange/{issue,verify,pending,
  jwt}.rs` — PR: #454
- `[x]` **P2.4** (M) One DID-VM→DI-proof verifier (was 5 hand-rolled copies, not 3);
  delegate to the DI library's `proof.verify(resolver)` with one shared
  `DidVmResolver` + `check_issuer_binding`; deleted the bespoke
  `ForeignIssuerKeyResolver` trait — deps: P2.3 — PR: #455 (shared resolver +
  exchange + relationships), #456 (recognition)
- `[x]` **P2.5** (S) `store::keyspaces` registry (names + `ALL`); `open_keyspaces`
  iterates `ALL` (was 8/21); `persist()` on invite + emergency CLI paths;
  `ALL.len()==21` + no-dup tests — PR: #409
- `[x]` **P2.6** (L) `route_posture` backstop (spec-driven; every unauth route must
  be classified governed/public — backstops P0.5) + collapsed the Trust-Task
  router boilerplate via `tt()`/`ttl()` (−121 LOC). The full per-feature
  builder split is deferred (the posture backstop already provides the
  regression guard) — PR: #457 (posture backstop), #461 (boilerplate collapse)
- `[x]` **P2.7** (M) `RegistryRecord::for_job(&SyncJob) -> Option<RegistryRecord>`
  dedups the `run_call`/`update_mirror` record-shape (incl. the historical→active_to
  branch); `None` = DeleteMember's remove path — PR: #412
- `[x]` **P2.8** (S) Collapse DTG builders onto one `dtg::into_typed(doc, kind)`
  JSON→VC helper (vmc/vec/custom_endorsement; invitation returns Value, untouched)
  — PR: #411

**Checkpoint 2:** `[x]` adapter LOC reduced; posture + orchestration tests pin
behavior. `[x]` module docs refreshed for the Phase 2 module moves
(`vtc-service/CLAUDE.md` source layout + `ceremony/mod.rs` + join-submit adapter
doc) — PR: #463. (Note: per-feature router builder split deferred — see P2.6;
the #457 posture backstop provides its regression guard.)
**Phase 2 complete.**

## Phase 3 — Strategic convergence + hygiene (ongoing)

- `[x]` **P3.1** (L) Real host-based surface isolation (or force host-separation
  when a website is configured + honest docs) — **done** (#465, #466)
  - `[x]` **part 1** per-surface host gate in `host_dispatch::enforce` (recognised
    host serves only its bound surface; cross-surface → 404 `SurfaceNotOnHost`;
    infra routes bypass) — PR: #465
  - `[x]` **part 2** force host separation when a filesystem website
    (`website.root_dir`) is configured + honest docs (correct the stale
    `Path=/admin` cookie-isolation claim) — PR: #466
- `[ ]` **P3.2** (M) CSRF bearer exemption + tighten exempt list; wire CSRF into
  the test harness — PR: ____
- `[x]` **P3.3** (M) Website `PUT` through the full safety chain; validate before
  `create_dir_all` — `canonical_within_root_for_create` (shared
  `validate_path_components`; rejects `..`/hidden/blocklist/control/NFC + symlinked
  ancestor; no FS mutation before the check) — PR: #467
- `[~]` **P3.4** (S) Validate/clamp per-site CSP override; cache (stop per-request
  read) — `validate_csp_override` refuses weakening script-src/object-src/base-uri;
  `CspOverrideCache` (content-cache TTL) — PR: #469 (in review)
- `[ ]` **P3.5** (S) `no-cache` on admin index/SPA-fallback; cache/gate
  `plugins.json` scan; implement `If-None-Match`→304 — PR: ____
- `[ ]` **P3.6** (S) Typed errors at registry (503/502) + DIDComm (problem-reports)
  boundaries — PR: ____
- `[ ]` **P3.7** (S) Minimal unauth `/health`; gate DID/mediator detail; `nosniff`
  on `did.jsonl` — PR: ____
- `[ ]` **P3.8** (M) Syncer: seek tail walk from cursor (range API); event_id-keyed
  idempotent enqueue — PR: ____
- `[ ]` **P3.9** (XL) Backup/restore for all keyspaces (Argon2id+AES-GCM, vtc_did
  compat check) — design note first — deps: P2.5 — PR: ____
- `[ ]` **P3.10** (L) `vtc setup --from <toml>` (WizardPlan + apply engine); fix
  CLAUDE.md — PR: ____
- `[ ]` **P3.11** (S) Emergency bootstrap: marker-before-wipe, clear sessions,
  `persist()` — PR: ____
- `[ ]` **P3.12** (S) Install `claim/finish` idempotent delivery against a
  `Consumed` row — PR: ____
- `[ ]` **P3.13** (M, several small PRs) Hygiene: stale webauthn doc; dead `b64:`
  path; redact `Debug` on secret types + gate wizard key print; `vtcDid`/`vtcUrl`
  field rename; public-profile field caps; path-param DID validation; reject
  `http://` registry; supervisor restart-on-panic — PR(s): ____

---

## Cross-cutting themes (where the same root cause spans subsystems)

- **Foreign/untrusted-fetch hardening** (P0.4) and **bearer recognise** (P0.2)
  are the two halves of the cross-community trust boundary — land together if
  possible; both touch `recognition/verify.rs` + `recognise.rs`.
- **Unbounded-growth / missing sweeper** shows up four times (join requests,
  credx-pending, present-challenge, failed sync jobs) — P0.6 fixes all in one
  sweeper pass.
- **Config triplication** (P1.1) is the root cause behind the unaudited mutation
  (P1.2), the `vtc_did`-brick (P0.9 boot side), and the stale derived-state
  divergence — P1.1 is the keystone; sequence it first in Phase 1.
- **Logic-in-routes** (P2.1) is why several P0 fixes (auto-admit audit, dedup,
  freshness) land in 2–3 places — doing P2.1 after the P0s makes future fixes
  single-site.
- **Status-list RMW race** (P0.1) and **`admit` TOCTOU** (P0.15) are the same
  missing-lock class as the VTA review's counter races — one `with_locked` helper
  pattern covers both.
