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

- `[ ]` **P0.1** (M) Status-list concurrency lock — revocation flips + slot
  allocations lost under concurrent RMW; wrap flip+`mark_revoked` together — PR: ____
- `[ ]` **P0.2** (L) Cross-community `recognise`: require holder proof + nonce +
  audience, bind VMC subject == VEC subject, fix unverified-actor audit — PR: ____
- `[ ]` **P0.3** (M) DIDComm handlers: authenticate sender via `encrypted_from_kid`,
  require authcrypt/non-anon (MessagePolicy); fix self-remove first — PR: ____
- `[ ]` **P0.4** (M) Foreign-fetch client: `redirect(none)` + timeout + body-size
  cap; re-guard redirects; one shared client — PR: ____
- `[ ]` **P0.5** (M) Move `join-requests` submit/accept/status onto the governed
  64 KB unauth branch (split the shared mount) — PR: ____
- `[ ]` **P0.6** (S) Spawn `RetentionSweeper`; extend to `credx-pending:` /
  `present-challenge:` / `Failed` sync jobs; fix model.rs comment — PR: ____
- `[ ]` **P0.7** (M) Encryption-at-rest (`with_encryption`) for `install`,
  `audit_key`, `passkey`; try-decrypt-else-plain migration — PR: ____
- `[ ]` **P0.8** (S) Secret-store factory: hard-fail on set-but-uncompiled backend;
  `deny_unknown_fields` on `SecretsConfig` — PR: ____
- `[ ]` **P0.9** (S) Configured-but-broken identity → hard-fail boot (not
  warn-and-serve-dead); pre-setup still degraded — PR: ____
- `[ ]` **P0.10** (M) `spawn_blocking` for Argon2id/Rego/sign; `TimeoutLayer`;
  consider multi-thread REST runtime — PR: ____
- `[ ]` **P0.11** (S) `relationships_by_did` colon-prefix collision — post-filter
  or length-prefix the index key — PR: ____
- `[ ]` **P0.12** (M) Submit path: don't stamp `Presentation.verified=true` over
  unverified VCs (verify each, or flag holder-binding-only) — PR: ____
- `[ ]` **P0.13** (S) Join-submit signature freshness/nonce/audience binding +
  per-applicant open-request dedup/cap — PR: ____
- `[ ]` **P0.14** (M) Promote-to-admin through the role-change ceremony (honor
  `role_change.rego` + host invariants) — PR: ____
- `[ ]` **P0.15** (S) `admit` serializing lock — duplicate-credential TOCTOU
  (match `depart`/`remint`) — PR: ____
- `[ ]` **P0.16** (M) `check_acl` reads `VtcAclEntry` + maps `VtcRole→Role` —
  non-admin DID no longer 500s `/auth/challenge` with serde leak — PR: ____
- `[ ]` **P0.17** (S) 0600 perms on `config.toml`, plaintext secret file — PR: ____
- `[ ]` **P0.18** (M) Rego eval timeout/instruction budget + input-size cap;
  fail-closed on bound exceeded — PR: ____
- `[ ]` **P0.19** (S) `vtc status` trust-ping: use `decode_secret_store_value`
  (JSON bundle), drop the 64-byte assumption — PR: ____
- `[ ]` **P0.20** (S) ACL/session scoping: gate `delete_acl` on AdminAuth + check
  target role; scope `revoke_sessions_by_did`/`session_list`; revoke sessions on
  downgrade — PR: ____
- `[ ]` **P0.21** (S) Install `claim/start`: verify claim secret BEFORE taking the
  300s ceremony lock (anti-grief) — PR: ____

**Checkpoint 0:** `[ ]` all P0 merged or deferred-with-issue; CI green;
cross-community.md + vtc-mvp.md §14 updated (P0.2/P0.3/P0.7).

## Phase 1 — Kill the divergence engines

- `[ ]` **P1.1** (L) One config-mutation surface (config_store canonical);
  `public_url`→registry requires_restart; profile owns name/desc; drop
  `vtc_did`/`vta_did` from update body; atomic save — **do first** — PR: ____
- `[ ]` **P1.2** (M) Audit `PATCH /admin/config` + `PUT /profile`; replace
  `did:key:vtc-admin` sentinel with the real admin DID — PR: ____
- `[ ]` **P1.3** (S) RTBF/registry audit emits awaited (not detached); re-emit on
  failure — PR: ____
- `[ ]` **P1.4** (M) Shared `mint_session_tokens` (passkey login gets AAL2 short
  TTL + audit); one `verify_domain_signed` helper (4 sites) — PR: ____
- `[ ]` **P1.5** (S) Policy upload validates package matches purpose / yields a
  decision — PR: ____

**Checkpoint 1:** `[ ]` e2e green; admin-UI config/profile round-trips unchanged;
recognise smoke unchanged.

## Phase 2 — Collapse adapter shells & move logic out of routes (deps: P1.1, P1.4)

- `[ ]` **P2.1** (L) Move join/leave/role-change orchestration out of routes into
  ceremony/operations; shared auto-admit-vs-approve audit helper — deps: P1.4 — PR: ____
- `[ ]` **P2.2** (M) One `assemble_facts` builder; cached member counter (no
  full-keyspace scan per request) — PR: ____
- `[ ]` **P2.3** (L) Split `exchange.rs` (2,316) → `exchange/{issue,verify,pending,
  jwt}.rs` — PR: ____
- `[ ]` **P2.4** (M) One DID-VM→DI-proof verifier (dedup 3 copies) — deps: P2.3 — PR: ____
- `[ ]` **P2.5** (S) `store::keyspaces` registry (names + `ALL`); `open_keyspaces`
  iterates `ALL`; `persist()` on invite/emergency CLI paths — PR: ____
- `[ ]` **P2.6** (L) Per-feature routers + `route_posture` enumeration test
  (backstops P0.5) — PR: ____
- `[ ]` **P2.7** (M) `RegistryRecord::for_job` — dedup syncer fetch-verify-apply
  shape — PR: ____
- `[ ]` **P2.8** (S) Collapse DTG builders (`dtg::finalize_typed`) — PR: ____

**Checkpoint 2:** `[ ]` adapter LOC reduced; posture + orchestration tests pin
behavior; CLAUDE.md source-layout updated.

## Phase 3 — Strategic convergence + hygiene (ongoing)

- `[ ]` **P3.1** (L) Real host-based surface isolation (or force host-separation
  when a website is configured + honest docs) — PR: ____
- `[ ]` **P3.2** (M) CSRF bearer exemption + tighten exempt list; wire CSRF into
  the test harness — PR: ____
- `[ ]` **P3.3** (M) Website `PUT` through the full safety chain; validate before
  `create_dir_all` — PR: ____
- `[ ]` **P3.4** (S) Validate/clamp per-site CSP override; cache (stop per-request
  read) — PR: ____
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
