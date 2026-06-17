# Virtual Test Environment & Mock Fabric Plan

Source: test-infrastructure inventory of the verifiable-trust-infrastructure
workspace (2026-06-10), commissioned to answer "how do we stand up mock
VTA / PNM / VTC services and run virtual integration + deployment tests
easily." This document is self-contained — it can be executed over time
without the original conversation. Task checklist:
`tasks/test-harness-todo.md`. Companion to the VTA/VTC architecture plans
(`tasks/vta-architecture-plan.md`, `tasks/vtc-architecture-plan.md`); where a
task here depends on one of those (notably non-interactive VTC setup), it is
called out.

**Goal:** a single test *fabric* that stands up the whole topology
(VTA + VTC + mediator + CLIs) in-process for fast CI integration tests, and the
*same* fabric against real ports/containers for deployment validation — tests
target uniform **service handles**, not URLs or routers, so one test body runs
on either backend. Build on the existing `test-support` foundation (mature for
VTA, absent for VTC); do not reinvent it.

## Where we're starting from (ground truth)

What already exists and is reusable as-is:
- **VTA `test_support`** (`vta-service/src/test_support.rs`, feature
  `test-support`): `MockVta::start()` binds `127.0.0.1:0` and serves the
  **production routes** with real auth gates; `build_test_app()` →
  `(Router, TestAppContext)`; `build_app_state()` is public
  (`server.rs:196`); `bootstrap_test_vta()` seeds a fully-provisioned VTA
  (seed + DID + keys); `TestStore` wraps a tempdir fjall.
- **Auth seeding**: `tests/api_integration.rs:99-167` mints JWTs/sessions;
  `AuthClaims::unsafe_local_cli_super_admin` (feature `cli-synthesis`).
- **Real seal round-trip under test**: `vta-sdk/tests/provision_client_e2e.rs`
  runs the genuine HPKE `seal_payload` against a wiremock fake VTA — proving
  `sealed_transfer` works in tests.
- **Embedded mediator**: `affinidi-messaging-test-mediator`'s
  `TestMediator::spawn()` + the `TestVtaResponder` pattern
  (`tests/e2e/tests/common/test_vta_responder.rs`) — the only way to exercise
  success-path DIDComm today.
- In-tree libs: `wiremock 0.6`, `tower::oneshot`, `http-body-util`, `tempfile`.

The gaps this plan closes:
1. **VTC has no `test_support`** — every `vtc-service/tests/*.rs` re-wires ~140
   LOC of keyspace-opening + JWT init by hand (`tests/common/mod.rs` exports
   only a webauthn helper).
2. **No shared multi-service harness** — helpers live inside `vta-service`;
   there is no orchestrator that stands up N services and wires them.
3. **No cross-service test** — a VTC has never bootstrapped its signing bundle
   *from* a VTA in any test (`credential_signer: None` in VTC test AppState).
4. **DIDComm requires a real mediator** — `DIDCommSession` hard-codes a
   WebSocket; no in-process loopback, so two services can't DIDComm in a unit
   test without spawning `TestMediator` + responders.
5. **CLIs are untested** — `pnm-cli`/`cnm-cli` have no tests and no `assert_cmd`;
   there is no way to point a CLI at a mock service.
6. **No deployment-mode story** — no scripted stand-up of real processes; blocked
   in part by the missing non-interactive `vtc setup` (VTC plan P3.10).

## How to use this plan

- Each task is one PR-sized slice: code + tests that use it + a doc touch,
  verified before merge.
- Conventions per workspace CLAUDE.md: `cargo fmt`, DCO-signed commits (`-s`),
  full CI before a PR, branch off main only after the prior PR merges.
- Sizes: **S** ≤ ½ day, **M** 1–2 days, **L** 3–5 days, **XL** needs a design note.
- The fabric is a `publish = false` dev crate — it never ships in a release
  binary. Keep all of it behind `test-support`/dev-deps so production builds and
  the TEE enclave never pull it in.
- Tick items off in the todo file as they merge; record the PR number there.

## Design in one picture

```
                         TestEnv (the fabric crate: vti-harness)
        ┌──────────────┬──────────────┬──────────────┐
        │ VtaHandle    │ VtcHandle    │ MediatorH    │   uniform handles:
        │ .client()    │ .client()    │ .did()       │   base_url / client /
        │ .base_url()  │ .seed_acl()  │ .url()       │   seed_* / did / shutdown
        └──────┬───────┴──────┬───────┴──────┬───────┘
               │              │              │
   backend ────┴── Loopback  (ephemeral 127.0.0.1:0 ports + in-proc DIDComm   ← CI
          │                   broker; tempdir stores; no external deps)
          └────── Networked  (fixed ports / docker-compose + real mediator;   ← deploy
                              real config.toml via `setup --from`)
```

Two backends behind one handle API. Loopback keeps the **real SDK HTTP client**
unchanged (handles serve on a real loopback port, exactly as `MockVta` already
does), so we never have to inject a tower service into the SDK. DIDComm is the
only transport that needs a seam (Phase 2).

---

## Phase 0 — Parity & foundations (unblocks everything)

### P0.1 — VTC `test_support` module at parity with VTA (M)
**Problem:** `vtc-service` has no test-support surface; `tests/admin_config.rs`,
`tests/install_flow.rs`, `tests/join_requests.rs` each hand-roll ~140 LOC of
tempdir store + 20-keyspace open + `AppState` wiring + JWT init + audit writer
(`tests/common/mod.rs` exports only `webauthn_harness::SoftEd25519Authenticator`).
The VTA equivalent (`vta-service/src/test_support.rs`) is the proven template.
**Change:** add `vtc_service::test_support` (feature `test-support` + dev-dep
self-ref) exposing `TestVtcStore`, `build_test_vtc() -> (Router, TestVtcContext)`
(reusing the production `routes::router()` + a `build_app_state`-style
constructor — extract one from `server.rs` if not already separable),
`MockVtc::start()` (binds `127.0.0.1:0`, production routes), and a
`TestVtcContext` that can pre-seed ACL/member/session rows and mint tokens.
Migrate the existing test files onto it (delete the duplicated setup).
**Accept:** a VTC integration test sets up in ≤ ~10 LOC; `tests/admin_config.rs`
et al. no longer contain inline keyspace-open boilerplate; `cargo test -p
vtc-service` green.

### P0.2 — `build_app_state` seam for VTC (S)
**Problem:** VTA exposes `build_app_state()` publicly so a router can be built
without `run()` binding TCP/spawning threads; VTC's AppState construction is
entangled in `server.rs::run()`. P0.1 needs a clean constructor.
**Change:** extract `vtc_service::server::build_app_state(config, store,
seed/secret bundle, …) -> Result<AppState>` mirroring `vta-service/src/server.rs:196`;
`run()` calls it then patches the TCP/DIDComm fields. (This also helps the VTC
architecture work — single construction point.)
**Accept:** `build_app_state` is callable from `test_support` with no TCP bind;
`run()` behavior unchanged (existing VTC e2e green).

### P0.3 — Bootstrap helpers: a provisioned VTC without the wizard (S)
**Problem:** VTC test AppState runs with `credential_signer: None`, so signing
routes 503 — no test can issue a VMC/VEC because there's no signing bundle.
`bootstrap_test_vta()` solves the equivalent for VTA by direct seeding.
**Change:** `bootstrap_test_vtc()` that injects a deterministic `VtcKeyBundle`
(integration DID + signing keys) into the secret store the same way
`bootstrap_test_vta()` seeds the VTA — so a standalone VTC test can sign. (Phase
1 replaces the synthetic bundle with one minted by a real mock VTA for
cross-service tests; this is the single-service shortcut.)
**Accept:** a VTC test issues a VMC end-to-end with a bootstrapped signer; no
wizard, no real VTA.

### P0.4 — Optional: in-memory store backend (S)
**Problem:** every test allocates a fresh tempdir + fjall DB
(`vti-common/src/store/mod.rs:603` `temp_store()`); fine, but a large fabric (VTA
+ VTC + per-test) pays it N times. Not a blocker — note as an optimization.
**Change:** evaluate whether fjall offers an in-memory/`tmpfs` mode or whether a
RAM-disk tempdir is enough; if cheap, add `Store::in_memory()` behind
`test-support`. Skip if fjall has no clean in-memory path — tempdir is acceptable.
**Accept:** either an `in_memory()` constructor used by the harness, or a recorded
decision that tempdir is fast enough (with a rough per-service setup cost).

**Checkpoint 0:** VTC has `test_support` at VTA parity; both crates expose a
TCP-free AppState constructor; a single VTC test can sign. Full CI green.

---

## Phase 1 — The multi-service fabric (in-process, pragmatic DIDComm)

### P1.1 — `vti-harness` crate skeleton + `TestEnv` builder (M)
**Problem:** test helpers are siloed in `vta-service`; nothing stands up more
than one service or coordinates them.
**Change:** new `publish = false` crate `vti-harness` depending on `vta-service`,
`vtc-service`, `vta-sdk` (all `features = ["test-support"]`). Provide
`TestEnv::builder().with_vta().with_vtc().build().await -> TestEnv` returning
`VtaHandle`/`VtcHandle` (each: `base_url()`, `client()` → a configured SDK
client, `shutdown()`), built on `MockVta`/`MockVtc`. Backend enum
`Backend::{Loopback, Networked}` with Loopback implemented first.
**Accept:** a test in `vti-harness/tests/` stands up a VTA + VTC and hits each
over HTTP via its SDK client in < ~5 LOC of setup; `env.shutdown()` is clean.

### P1.2 — Cross-service provision seeding: VTC bootstraps FROM the mock VTA (M)
**Problem:** the VTA→VTC bootstrap (real `sealed_transfer`) has never run in a
test; `provision_client_e2e.rs` only seals against a *wiremock* VTA, and no VTC
consumes the bundle.
**Change:** in `TestEnv` builder, when both services are present, run the **real**
`provision_via_rest` from the VTC against the mock VTA's `base_url()`, receive a
genuine HPKE-sealed `TemplateBootstrapPayload`, open it, and inject the signing
bundle into the VTC's secret store. This replaces P0.3's synthetic bundle for
multi-service tests and exercises seal/open + VP verification for real.
**Accept:** `TestEnv::builder().with_vta().with_vtc().build()` yields a VTC whose
`credential_signer` is `Some` and whose DID/keys were minted by the mock VTA; a
test asserts the VTC can issue a VMC signed with VTA-minted keys.

### P1.3 — Shared identity + seeding helpers (S)
**Problem:** a cross-service flow needs the same member/holder identity known to
both services; today each test mints ad-hoc DIDs.
**Change:** `env.new_holder("alice") -> HolderHandle` (mints a `did:key`, can
sign VPs/Trust Tasks); `vtc.seed_member(did, role)`, `vta.seed_acl(did, role,
contexts)`, `*.admin_token()` convenience built on the existing JWT/session
helpers (`api_integration.rs:99`).
**Accept:** a holder created once is usable as applicant on the VTC and as a
recipient on the VTA in the same test.

### P1.4 — Pragmatic DIDComm: one-line embedded mediator (M)
**Problem:** until the loopback transport (Phase 2) lands, DIDComm flows need a
real mediator + responder; the e2e suite does this but with heavy per-test setup
(`TestMediator::spawn()` + a `TestVtaResponder`).
**Change:** `TestEnv::builder().with_mediator()` spawns the embedded
`TestMediator` once for the env and registers each service as a listener
(generalize `TestVtaResponder` into the harness so VTA *and* VTC can listen).
Services constructed with `with_mediator` advertise/connect DIDComm.
**Accept:** a join-over-DIDComm test (holder → VTC via mediator) round-trips in
the harness with `with_mediator()` and no per-test mediator plumbing.

**Checkpoint 1:** the missing cross-service tests now exist — VTA→VTC provision
(real seal/open) and a holder→VTC join over a real (embedded) mediator. The
fabric is usable for integration tests today, before the loopback work.

---

## Phase 2 — In-process DIDComm loopback (the real unlock)

### P2.1 — Transport seam at the workspace messaging boundary (L)
**Problem:** `DIDCommSession` hard-codes a WebSocket to a mediator, so DIDComm
tests can't avoid spawning real network services — the single biggest cost and
flake source in the fabric. The crypto (authcrypt pack/unpack, sender auth) does
not need a network to be exercised; only the wire hop does.
**Change:** introduce a `Transport` trait at *our* messaging boundary (you
already have `Transport::Rest`/`Transport::DIDComm` in `VtaClient`): keep
`WebSocketTransport` as the production impl and add a `LoopbackTransport`. Route
the VTA `messaging::*` listener and the SDK client send/recv through the trait.
Pack/unpack stays real — only delivery is swapped. Coordinate the seam with the
`affinidi-messaging` wrappers (the trait sits in *our* code wrapping ATM, not
inside the third-party crate).
**Accept:** the production path is byte-identical (the WebSocket impl is the
default); the trait is the only delivery seam; existing DIDComm e2e green.

### P2.2 — In-process DIDComm broker (M)
**Problem:** loopback needs something to route packed messages between registered
DIDs without HTTP.
**Change:** an in-process broker (tokio channels keyed by recipient DID) that
accepts a packed authcrypt envelope from one registered party and delivers it to
another — the in-memory analogue of a mediator's store-and-forward, minus the
network. `TestEnv` wires every service + holder to one broker when
`Backend::Loopback`.
**Accept:** two services (and a holder) DIDComm to each other in a single test
with **no `TestMediator`, no port, no WebSocket**; sender authentication still
verified (a spoofed `from` is rejected — ties to VTC plan P0.3).

### P2.3 — Loopback becomes the default; embedded mediator reserved for fidelity (S)
**Problem:** once the broker works, most integration tests shouldn't pay for a
real mediator.
**Change:** `TestEnv` defaults DIDComm to the loopback broker; keep
`with_mediator()` (Phase 1) as an explicit opt-in for tests that specifically
want to exercise mediator behavior (drain windows, sticky routing, offline
queueing). Document when to use which.
**Accept:** the join-over-DIDComm test from P1.4 runs with no mediator by
default; an opt-in variant still runs against the embedded mediator.

**Checkpoint 2:** the integration suite runs DIDComm flows in-process with no
external dependencies; CI time and flake drop; the real-mediator path remains
available for fidelity tests.

---

## Phase 3 — CLI harness & deployment mode

### P3.1 — CLI test harness (M)
**Problem:** `pnm-cli`/`cnm-cli` have zero tests and no `assert_cmd`; there's no
way to point a CLI at a mock service or isolate its config dir.
**Change:** add a CLI harness in `vti-harness`: a temp `HOME` → scratch
`~/.config/{pnm,cnm}`, base-URL injection from a `VtaHandle`/`VtcHandle`, two
drivers — (a) `assert_cmd` invoking the compiled binary (deployment confidence),
(b) calling `vta_cli_common` command fns directly against in-process handles
(fast, no spawn). Because the CLIs are thin wrappers over `vta-cli-common`, this
is your "mock PNM / mock CNM" — the harness drives the same command surface.
**Accept:** a test runs `pnm bootstrap` (or the equivalent command fn) against a
mock VTA in the fabric and asserts the resulting `~/.config/pnm` state; config
dir is fully isolated (no developer-home writes).

### P3.2 — Non-interactive VTC setup (dependency: VTC plan P3.10) (L)
**Problem:** the `Networked` deployment backend needs to write real
`config.toml`s and stand services up without a TTY; `vtc setup` is interactive
only (the VTC review's P3.10). VTA already has `setup --from <toml>`.
**Change:** implement `vtc setup --from <toml>` (tracked as VTC-plan P3.10 —
`WizardPlan` inputs struct + apply engine). The harness's `Networked` backend
generates a TOML and invokes it.
**Accept:** the harness can provision a real VTC process from a generated TOML
with no prompts; covered by VTC-plan P3.10's own acceptance.

### P3.3 — `Networked` backend + deployment smoke suite (M)
**Problem:** in-process tests don't validate real process boot, port binding,
config parsing, or container wiring — the things deployment actually breaks on.
**Change:** implement `Backend::Networked` (bind fixed ports / optional
`docker-compose.test.yml`, real config files, real embedded or external
mediator) behind the same handle API. Add a `smoke/` suite asserting the headline
flows across real processes: cold-start → provision-integration → join →
recognise. Where the handle API allows, reuse the in-process test bodies.
**Accept:** `cargo test -p vti-harness --features networked` (or a `make
smoke`) boots real VTA + VTC + mediator processes and passes the cross-service
smoke flow; CI job added (can be a slower/optional lane).

### P3.4 — Docs + one worked example (S)
**Problem:** a fabric nobody knows how to use rots.
**Change:** `docs/06-testing/test-harness.md` (or similar): the handle API, the
two backends, when to use loopback vs embedded mediator vs networked, and one
fully-worked cross-service test (provision → join → recognise) as the copyable
template. Link it from the root CLAUDE.md "Integration flows" section and each
crate's CLAUDE.md.
**Accept:** a new contributor can write a two-service test from the doc without
reading the harness source.

**Checkpoint 3:** mock PNM/CNM via the CLI harness; a deployment smoke suite over
real processes; documented entry point. The original goals — mock VTA/PNM/VTC,
easy virtual integration tests, stand-up of whole environments for deployment
testing — are all reachable from `TestEnv`.

---

## Invariants any task must preserve (the do-not-break list)

- **The fabric never ships.** `vti-harness`, all `test_support` modules, and
  every seeding shortcut stay behind `test-support`/dev-deps and `publish =
  false`. The TEE enclave binary (`vta-enclave`) and any release build must not
  be able to pull them in (cf. `cli-synthesis` being absent from the enclave).
- **Mocks serve production routes with real gates.** `MockVta` already does this;
  `MockVtc` must too. A mock that bypasses auth/ACL is worthless for integration
  testing — pre-seed credentials, don't disable the gate.
- **Real crypto in the loopback path.** The DIDComm broker (P2.2) swaps delivery,
  not packing — authcrypt pack/unpack and sender authentication stay real, so a
  spoofed `from` is still rejected (the VTC P0.3 invariant must hold under
  loopback exactly as under a mediator). Likewise the provision seeding (P1.2)
  runs the genuine HPKE seal/open, not a stub.
- **Production transport path is the default impl.** The `Transport` seam (P2.1)
  must leave `WebSocketTransport` byte-identical to today; loopback is additive.
- **Determinism without weakening crypto.** Deterministic seeds/keys in fixtures
  are fine for reproducibility, but never introduce a non-CSPRNG or a
  reduced-rounds KDF on a path shared with production (no test-only crypto
  shortcuts that could leak into a real build).
- **Config-dir isolation.** CLI tests must use a temp `HOME`; never read or write
  the developer's real `~/.config/{pnm,cnm}` or OS keyring.
- **One handle API across backends.** A test written against `VtaHandle`/
  `VtcHandle` should run on Loopback and Networked unchanged wherever the flow
  permits; backend-specific escapes (raw ports, container names) stay out of the
  common test body.
