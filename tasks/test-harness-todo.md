# Todo: Virtual Test Environment & Mock Fabric

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Plan with full problem statements, file references, acceptance criteria, and the
invariants do-not-break list: `tasks/test-harness-plan.md`.
Record the PR number next to each task as it merges.

Sizes: S ≤ ½ day · M 1–2 days · L 3–5 days · XL needs a design note first.

Foundation already in place (reuse, don't rebuild): VTA `test_support`
(`MockVta`, `build_test_app`, `build_app_state`, `bootstrap_test_vta`),
real HPKE seal round-trip under wiremock (`vta-sdk/tests/provision_client_e2e.rs`),
embedded `TestMediator` + `TestVtaResponder`, `wiremock`/`tower::oneshot`/`tempfile`.

---

## Phase 0 — Parity & foundations

- `[ ]` **P0.1** (M) `vtc_service::test_support` at VTA parity (`TestVtcStore`,
  `build_test_vtc`, `MockVtc`, `TestVtcContext`); migrate `tests/*` onto it — PR: ____
- `[ ]` **P0.2** (S) Extract `vtc_service::server::build_app_state` (TCP-free
  AppState constructor) — PR: ____
- `[ ]` **P0.3** (S) `bootstrap_test_vtc()` injects a signing bundle so a
  standalone VTC can sign (no wizard, no real VTA) — PR: ____
- `[ ]` **P0.4** (S) In-memory store backend OR a recorded "tempdir is fast
  enough" decision with measured per-service cost — PR: ____

**Checkpoint 0:** `[ ]` VTC `test_support` at parity; both crates expose a
TCP-free AppState constructor; a single VTC test can sign; CI green.

## Phase 1 — Multi-service fabric (in-process, pragmatic DIDComm)

- `[ ]` **P1.1** (M) `vti-harness` crate + `TestEnv::builder().with_vta().with_vtc()`;
  `VtaHandle`/`VtcHandle` (`base_url`/`client`/`shutdown`); `Backend::Loopback` — PR: ____
- `[ ]` **P1.2** (M) Cross-service provision seeding: VTC runs real
  `provision_via_rest` against the mock VTA, opens the sealed bundle, gets a
  VTA-minted signer — PR: ____
- `[ ]` **P1.3** (S) Shared identity/seeding helpers (`new_holder`, `seed_member`,
  `seed_acl`, `admin_token`) — PR: ____
- `[ ]` **P1.4** (M) `with_mediator()` spawns embedded `TestMediator` once;
  generalize `TestVtaResponder` so VTA + VTC listen — PR: ____

**Checkpoint 1:** `[ ]` cross-service tests exist (VTA→VTC real provision;
holder→VTC join over embedded mediator); fabric usable for integration tests.

## Phase 2 — In-process DIDComm loopback (the unlock)

- `[ ]` **P2.1** (L) `Transport` trait at the workspace messaging boundary;
  `WebSocketTransport` (prod, unchanged) + `LoopbackTransport`; route VTA
  messaging + SDK client through it — PR: ____
- `[ ]` **P2.2** (M) In-process DIDComm broker (channel-routed packed envelopes,
  real pack/unpack); wire env + holders to it on `Backend::Loopback` — PR: ____
- `[ ]` **P2.3** (S) Loopback default for DIDComm; `with_mediator()` reserved for
  fidelity (drain/sticky/offline) tests — PR: ____

**Checkpoint 2:** `[ ]` DIDComm flows run in-process, no external deps; spoofed
`from` still rejected under loopback; real-mediator path still available.

## Phase 3 — CLI harness & deployment mode

- `[ ]` **P3.1** (M) CLI harness: temp `HOME`, base-URL injection, dual driver
  (`assert_cmd` binary + direct `vta_cli_common` fns) → mock PNM/CNM — PR: ____
- `[ ]` **P3.2** (L) `vtc setup --from <toml>` — **= VTC-plan P3.10** (do it
  there); the harness `Networked` backend consumes it — deps: VTC P3.10 — PR: ____
- `[ ]` **P3.3** (M) `Backend::Networked` (fixed ports / compose, real config +
  mediator) + `smoke/` suite: cold-start → provision → join → recognise across
  real processes; CI lane — deps: P3.2 — PR: ____
- `[ ]` **P3.4** (S) `docs/06-testing/test-harness.md` + one worked cross-service
  example; link from root + crate CLAUDE.md — PR: ____

**Checkpoint 3:** `[ ]` mock PNM/CNM via CLI harness; deployment smoke suite over
real processes; documented entry point.

---

## Sequencing notes

- **P0.1 is the keystone** — VTC parity unblocks the whole fabric and immediately
  deletes ~140 LOC/test-file. Do it first.
- **Phase 1 is usable before Phase 2.** Ship the fabric with the pragmatic
  embedded mediator (P1.4), then make it fast/dependency-free with the loopback
  broker (Phase 2). Don't block integration coverage on the transport seam.
- **P3.2 is shared with the VTC architecture plan (P3.10).** Land it once; both
  plans benefit. The deployment backend (P3.3) hard-depends on it.
- **DIDComm loopback (P2.1/P2.2) is the highest-leverage but largest item** —
  it's what removes the real-mediator dependency from everyday CI. Worth the L.
- The fabric also becomes the natural home for **regression tests from the VTA/VTC
  architecture reviews** that need two services (e.g. VTC P0.2 recognise
  holder-binding, P0.3 DIDComm sender-spoof) — those are easier to write once the
  fabric exists.
