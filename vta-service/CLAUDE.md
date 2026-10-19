# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust workspace for **Verifiable Trust Infrastructure (VTI)**. The Verifiable Trust Agent (VTA) manages keys and policies for a Verifiable Trust Community. Part of the [First Person Network](https://www.firstperson.network/white-paper) project.

## Workspace Structure

This repo is a multi-crate workspace:

- **vti-common** (`../vti-common/`) — Shared library: auth, ACL, store (local + vsock), error types, config
- **vta-sdk** (`../vta-sdk/`) — SDK for Verifiable Trust Agents (types, client, protocols)
- **vta-service** (this crate) — VTA library + local/dev binary (key management, audit logging, routes, operations)
- **vta-enclave** (`../vta-enclave/`) — VTA binary for Nitro Enclaves (TEE bootstrap, KMS, vsock-store)
- **vtc-service** (`../vtc-service/`) — VTC binary service (community management)
- **vta-cli-common** (`../vta-cli-common/`) — Shared CLI command implementations
- **pnm-cli** (`../pnm-cli/`) — Personal Network Manager CLI

### Architecture: Core + Front-ends

`vta-service` is both a **library** (business logic) and a **binary** (local/dev front-end):
- `src/lib.rs` — Exports all shared modules (routes, operations, keys, auth, store, tee types)
- `src/main.rs` — Local/dev/cloud binary (no TEE bootstrap)

`vta-enclave` is a separate **binary crate** for Nitro Enclave deployments:
- Depends on `vta-service` as a library
- Has its own `main.rs` with TEE-specific bootstrap (KMS, vsock-store, attestation)
- No feature flags for TEE — it's always TEE mode

Future front-ends (SGX, serverless, etc.) follow the same pattern: new binary crate depending on `vta-service` lib.

All crates share configuration via `workspace.package` in the root `Cargo.toml`.

## Build Commands

```bash
# Build entire workspace
cargo build

# Check compilation (faster, no codegen)
cargo check

# Run the local/dev VTA
cargo run --package vta-service

# Build the enclave VTA (Linux only — vsock-store requires Linux)
cargo build --package vta-enclave --features rest,didcomm,vsock-store

# Run all tests
cargo test

# Run tests for a single crate
cargo test --package vta-service
cargo test --package vta-sdk

# Run a single test by name
cargo test test_name

# Lint
cargo clippy

# Format
cargo fmt
cargo fmt --check   # check only
```

## Rust Configuration

- **Edition**: 2024
- **Minimum Rust version**: 1.95.0
- **Resolver**: 3
- **License**: Apache-2.0

## Hot spots

Files to know about before editing (approximate source lines):
- `vta-service/src/operations/provision_integration/mod.rs` (~2.4k lines)
  — orchestrates template render → key mint → ACL wire-up → VC issue
  → seal. Split into a module directory; the seal helper extracted to
  `seal.rs` is the canonical place for new payload variants.
- `vta-service/src/operations/did_webvh/mod.rs` (~2.05k lines) —
  WebVH DID lifecycle + `did.jsonl` publication, used by every
  protocol-management operation that mutates the VTA's own DID.
- `vta-tee/src/kms_bootstrap.rs` (~1.8k lines) — KMS attest/
  decrypt, JWT fingerprint check, storage-key derivation, MODE_B_LOCK
  carve-out gating. **Moved out of `vta-service` in #791**; still
  reachable as `vta_service::tee::…` via the re-export facade.
- `vta-service/src/messaging/registry.rs` (~1.3k lines) — the
  `MediatorListenerRegistry`: active-mediator membership, drain
  windows, sticky outbound routing, telemetry emission. Load-bearing
  for the protocol-management surface.
- `vta-sdk/src/sealed_transfer/` — HPKE seal/open, armor, assertions
  (`DidSigned`, `Attested`, `PinnedOnly`).
- `vta-service/src/messaging/{drain_store,drain_sweeper,handshake,live_prover,transient_handshake}.rs`
  — protocol-management plumbing. Smaller individually (~120–420
  lines) but tightly coupled; touch one and you usually touch
  several.
- `vti-common/src/store/vsock.rs` — enclave-side store proxy;
  semantic parity with local fjall is asserted but under-tested.

## Integration flows

Moved here from the workspace `CLAUDE.md`, which keeps an index of every
flow. Each entry: what it does, the invariants to preserve, code, docs.
When adding a flow, add it here and a line to the root index.

### VTA first-boot setup
- **What**: Mints master seed, VTA DID, mediator DID, first admin credential.
- **Entry point**: `vta setup` (interactive) or `vta setup --from <file>` (TOML-driven).
- **Code**: `vta-service/src/setup/interactive.rs`, `vta-service/src/setup/from_toml.rs`.
- **Seed**: 24-word BIP-39 mnemonic, stored via `affinidi-secrets-resolver`
  backend (OS keyring by default; AWS/GCP/Azure via feature flags).
- **Docs**: `docs/02-vta/cold-start.md`, `docs/02-vta/non-interactive-setup.md`.

### Mediator connection (readiness gate + reconnect)
- **What**: How the VTA establishes and *keeps* its outbound mediator DIDComm
  connection. One background supervisor (`MessagingConnect`) owns the whole
  lifecycle: gate → connect-with-retry → supervise session → reconnect.
- **Gate**: waits until the VTA's own DID **fully resolves over the network**
  before the first connect, because the mediator authenticates us by resolving
  that DID itself. Resolution through the configured resolver is the whole check
  — do **not** re-add an HTTP probe of the `did.jsonl` URL: a 200 doesn't imply
  resolvability, and it tests the VTA's own egress to the DID host, which is the
  wrong path (and unreachable) when egress is restricted to a resolver sidecar.
  Only `did:webvh` / `did:web` are gated; `did:key` skips.
- **Reconnect**: capped exponential backoff + full jitter, re-confirming
  self-resolution before every attempt. Covers both a failed initial connect
  (the mediator's own resolver negative-caching us, which clears on its own
  timer) and an established session whose inbound loop ended.
- **Invariants to preserve**: (1) nothing here may run on the startup path —
  `server::run` must reach its shutdown select for a signal to be honoured;
  (2) every `build_messaging` error path after `profile_add` must
  `graceful_shutdown` the ATM — there is no `Drop` impl, and an abandoned socket
  keeps auto-reconnecting while holding the mediator's one-socket-per-DID slot,
  so a retry loop without teardown leaks one duelling socket per attempt;
  (3) a session must last `MIN_HEALTHY_SESSION` before it resets the backoff,
  else a flapping mediator gets retried at full rate.
- **Code**: `vta-service/src/messaging/readiness.rs`,
  `vta-service/src/server.rs` (`MessagingConnect`),
  `vta-service/src/messaging/service.rs` (`build_messaging`,
  `connect_transport`), `vta-config/src/lib.rs`
  (`MediatorReadinessConfig`).
- **Docs**: `docs/02-vta/mediator-connection.md`.

### Admin credential cold-start
- **What**: Bootstrap the first operator without a running VTA.
- **Flow**: PNM mints ephemeral `did:key` locally → operator runs
  `vta import-did --did <temp> --role admin` offline → VTA starts → PNM
  authenticates → on first authenticated call PNM **auto-rotates** to a
  fresh `did:key`, creates the new ACL entry, deletes the temp one.
- **cnm** onboards its personal VTA the same way (`cnm setup` /
  `cnm setup --name` → grant → `cnm setup continue [<name>] --vta-did`, which
  authenticates and rotates there and then). Two alternatives: borrow an
  existing `pnm` session on the same machine to grant cnm's *own* new key
  (read-only on pnm's profile; pnm's key is used in memory once, never
  stored), or the sealed bundle (digest-pinned, unchanged). Communities get an
  identity **each** (`cnm community add` → grant at the VTC →
  `cnm community continue`, which then rotates the granted key over
  `acl/swap-key/0.1`; `cnm community rotate` does it again later). An identity
  bound to a community VTA (`--vta-did`) or shared across communities
  (`--reuse-identity`, never implicit) is not rotated.
- **Code**: `pnm-cli/src/setup.rs`, `vta-service/src/main.rs` (`import-did`),
  `cnm-cli/src/{onboard,setup,pnm_profile}.rs`.
- **Docs**: `docs/02-vta/cold-start.md` §3–6, `docs/03-vtc/getting-started.md`
  ("Administering from `cnm`"), `docs/03-vtc/bootstrap-runbook.md`.

### Deferred VTA-DID setup (non-TEE)
- **What**: Mint the PNM admin `did:key` *before* the VTA exists, so
  Terraform / scripted provisioners can bake the admin DID into the
  VTA's `admin_did` field before booting it.
- **Flow**: `pnm setup --name <slug>` phase 1 emits the temp DID to
  stdout (interactive) or as JSON (non-interactive) and persists the
  ephemeral seed under `~/.config/{pnm,cnm}/pending-vtas/<slug>/` →
  operator pastes that DID into the VTA's `admin_did` and boots →
  `pnm setup continue <slug> --vta-did <did>` finishes the handshake
  using the same ephemeral key. Multiple concurrent pending VTAs are
  allowed (distinct slugs).
- **Code**: `pnm-cli/src/setup.rs` (phase 1 + `continue` subcommand).
- **Docs**: `docs/05-design-notes/pnm-setup-deferred-vta-did.md`.

### TEE Mode B bootstrap (attested first-boot)
- **What**: One-command admin onboarding against a fresh Nitro-Enclave VTA. The
  enclave **enrols the operator's claim DID**; it mints no key and returns none
  (#2066, VTI-CLT-001/002 — a node never holds a client's private key).
- **Entry point**: `pnm bootstrap claim-did create` **before the VTA exists**
  (the key is kept in the OS keyring under its DID), then `pnm bootstrap connect
  --vta-did <did> --claim-did <claim-did> --expect-pcr0 <hex>`; `--slug` only
  names the VTA locally (default: the VTA DID's tail). Without `--claim-did`,
  connect uses the key older pnm stored under the slug (`create --slug`).
  `--vta-did` and `--vta-url` are mutually exclusive and exactly one is
  required. The DID is resolved **locally** (SCID + signed log verified on the
  operator's machine, deliberately ignoring `PNM_RESOLVER_URL`), and bootstrap
  uses the `VTARest` endpoint that document advertises — never a URL guessed
  from the DID's host, and never a fallback on resolution failure. `--vta-url`
  is the explicit alternative when the log is not yet resolvable; it gives up
  identity pinning, and `pnm` learns the DID to sign from `GET
  /bootstrap/request` (safe to trust only because a pinned image refuses a
  claim naming a DID other than its own).
- **Transport**: REST `POST /bootstrap/request` (unauth, rate-limited), wire
  version 2 (`vta_sdk::tee_bootstrap`). Version 1 is refused with an upgrade
  hint — a clean break, no compatibility window.
- **Claimant**: only `tee.bootstrap_claim_did` — an Ed25519 `did:key` the
  operator minted (key in the OS keyring only) and delivered in the baked config
  or the tenant overlay — may claim; the claim names it as `clientDid`, names
  the target `vtaDid`, and carries `claimSignature` over
  `vti/bootstrap-claim/v2\0 ‖ pub ‖ nonce ‖ vtaDid` (verified before the lock).
  Unset admits nobody. The claimant and the VTA DID are checked **before** the
  carve-out, so a stranger or a claim for another VTA gets 403 whatever the
  carve-out's state. In a fleet build the parent delivers the claim DID, so it is
  in the attested config digest — a `403` at the real operator's `connect` is
  the substitution signal (VTI-CLT-016).
- **What is written**: an ACL entry for the claim DID itself — `Admin`,
  unrestricted, expiring after 24h (VTI-CLT-014), marked as a **hand-off**
  (VTI-ACL-054) whose granter is the VTA DID as first-boot authority and whose
  bound is an unrestricted permanent admin. The answer (`FirstBootAck`) is the
  attested acknowledgement: no key, no bundle.
- **Then**: `pnm` mints the long-term `did:key` locally, persists it, and as the
  claim DID exercises the hand-off with `acl/grant` +
  `ext["org.openvtc"].handoffRollover` (VTI-CLT-017), confirms by authenticating as the new key,
  and destroys the claim key (VTI-CLT-034). **Not `acl/swap-key`**: a rotation
  preserves expiry exactly (VTI-CLT-029), which would leave the VTA's only admin
  expiring. An interrupted run is resumed by re-running `connect` (410 + the slug
  already registered after a verified ack) before the entry expires.
- **Trust anchor**: Nitro attestation quote committing to the client's
  Ed25519 pubkey + nonce + producer's Ed25519 pubkey via SHA-256 (unchanged),
  plus the claim signature's binding of the VTA DID. `--expect-pcr0` pins the
  enclave image and is the anchor this path requires; `--expect-pcr8` is
  an additional pin, never an anchor on its own — it measures the signing
  certificate, not the image.
- **Carve-out**: Single-use. `BOOTSTRAP_CARVEOUT_CLOSED_KEY` flips on
  first success; subsequent calls return 410. It closes server-side **before
  the acknowledgement is returned**, so every client-side pin must be
  syntax-checked before the POST — a malformed `--expect-pcr0/8` caught at
  `check_pcrs` is caught after the VTA's one and only first boot has been spent.
- **Code**: `vta-service/src/routes/bootstrap.rs`, `vta-sdk/src/tee_bootstrap.rs`,
  `vta-service/src/operations/acl.rs` (`rollover_from_entry`),
  `pnm-cli/src/bootstrap.rs` (`run_connect`, `hand_over_claim`), `vta-tee/src/`.
- **Docs**: `docs/05-design-notes/sealed-bootstrap.md` (*Mode B since #2066*),
  `docs/02-vta/tee-architecture.md`.

### DIDComm challenge-response auth
- **What**: Session initiation for any authenticated call.
- **Endpoints**: `POST /auth/challenge` → challenge + session_id;
  `POST /auth/` → JWT access token (15m) + refresh token (24h);
  `POST /auth/refresh` → rotated access + refresh tokens.
- **Wire** (`POST /auth/` content-negotiates on the body shape; all paths
  converge on `vti_common::auth::handlers::handle_authenticate`):
  - **DI-signed Trust Task (canonical REST)** — a plain JSON
    `auth/authenticate/0.1` document whose holder `eddsa-jcs-2022`
    Data-Integrity proof *is* the authentication. No DIDComm packing /
    mediator needed, so a REST-only VTA (no `atm`) can authenticate. The
    proof's `verificationMethod` DID is the proven signer; `did:key`
    resolution is local. This is what `vta-mobile-core::build_authenticate`
    emits. Verified by `routes/auth.rs::verify_authenticate_proof` (mirrors
    the `step_up.rs` did-signed gate, PR #177).
  - **DIDComm v2 envelope** (via mediator) — packed message; ATM unpack
    verifies the sender (`msg.from` is the proven signer). Still supported.
  - Freshness/replay is anchored by the single-use, TTL'd challenge bound to
    the session at `/auth/challenge`; the DI path passes `created_time: None`
    (no-op freshness check), the DIDComm path enforces a 60s window on the
    envelope's `created_time`.
  - **`POST /auth/refresh` content-negotiates the same way**: a plain
    `auth/refresh/0.1` Trust Task (canonical REST) **or** a DIDComm envelope.
    Refresh carries *no proof* — the opaque refresh token in the payload is the
    bearer credential (OAuth2 §10.4 rotation), so the Trust Task path passes
    `signer_did: None`. Together with the authenticate path above, the mobile
    engine runs its whole login→refresh loop over plain REST, no mediator.
  - **Refresh-token rotation + reuse detection**: every successful refresh
    mints a new refresh token and atomically spends the presented one, so a
    token works exactly once. Each rotation leaves a hashed tombstone
    (`rotated:{sha256}`), so a *replayed* token is distinguishable from one
    this node never issued. A replay is forgiven only as a lost-response retry
    (cause `Rotated`, session alive, inside `refresh_reuse_grace()` — default
    30s; raise to 60s if real clients retry later than their HTTP timeout
    allows — **and** the tombstoned
    successor still unspent), in which case the same pair is re-served without
    rotating. Otherwise it is reuse: the session is revoked (killing every
    descendant token) and `AuthAuditEvent::RefreshReuseDetected` fires at
    `error!` with `security_alert = true`. The caller sees the same 401 either
    way, so detection isn't an oracle. Tombstones are reaped on time only
    (`rotated_at + refresh_token_ttl`), never alongside their session —
    post-revocation replay is the case most worth catching.
  - **A fresh login retires the previous refresh token**: `/auth/refresh`
    authorises from the `refresh:{hash}` index alone and never consults
    `session.refresh_token`, so overwriting `session:{did}` on login did *not*
    retire the old token — it left a second live chain that, sharing no token
    with the first, never replayed and so was never detected. `handle_authenticate`
    now claim-and-deletes the prior token's index entry and leaves a
    `Superseded` tombstone. That cause is excluded from the grace window on
    purpose: a client that just logged in holds its new token, so honouring a
    replay there would hand the new token to a pre-login theft. Replaying a
    superseded token is **refused and audited
    (`AuthAuditEvent::RefreshSuperseded`, `warn!` +`security_alert`) but does
    *not* revoke** — unlike reuse, the retired token is already dead, and the
    usual cause is a second device still holding what it was issued before the
    user signed in elsewhere; revoking would sign out the client that is
    demonstrably current and the forced re-login would set the same trap again.
    Implements RFC 9700 §4.14.2.
  - **One live chain per session, by construction**: retiring at login is
    best-effort (a racing refresh can slip past it), so `/auth/refresh` also
    refuses any claimed token that is not the one its session *currently*
    issues — answered as `RefreshSuperseded`, same as above. Currency comes
    from a `refresh-current:{session_id}` record written only by
    `store_refresh_index` (i.e. login and rotation), **never** from
    `session.refresh_token`: the row is read-modify-written without atomicity
    (`resolve_did_session` on every DIDComm/TSP message, `touch_last_seen`,
    step-up's `update_session`), which can write an older token back into it.
    Don't gate anything on the row's `refresh_token`. The row is only a
    fallback for sessions issued before the record existed. Login writes its
    `Superseded` tombstone only when its claim wins, so it never relabels a
    `Rotated` tombstone a racing refresh just wrote (that would downgrade
    genuine reuse to a non-revoking alert).
  - **Orphan `refresh:` entries are swept**: the index has no TTL, so
    `cleanup_expired_sessions` drops entries whose session row is gone or
    whose token is not current (same record, same fallback) — hygiene, since
    refresh already refuses them.
  - **Trust-Task-wrapped responses (engine interop):** `/auth/challenge`,
    `/auth/`, and `/auth/refresh` all content-negotiate on *both* ends — when
    the request body is a Trust Task document, the response is a TT `#response`
    document (`doc.respond_with(...)`: issuer/recipient swapped, `#response`
    type, `threadId` = request id) instead of flat JSON. `/auth/challenge` also
    accepts a TT `auth/challenge/0.1` request (subject from `payload.subject`).
    So `vta-mobile-core`'s `build_*` / `parse_*` (which speak TT docs
    end-to-end) interoperate unmodified, while the SDK/CLI flat-JSON clients are
    unchanged (flat-in → flat-out). Payloads match the generated spec Response
    types exactly (challenge `{challenge,sessionId,expiresAt}`;
    authenticate/refresh `{tokens,session}`) — those `deny_unknown_fields`, so
    don't add extras like `teeAttestation`.
- **Claims**: `{ aud, sub, session_id, role, contexts, exp }`. Audience
  separates VTA from VTC — cross-audience tokens are rejected.
- **Code**: `vta-service/src/routes/auth.rs`, `vti-common/src/auth/`.

### Context + context-admin bootstrap
- **What**: Application-scoped key hierarchy and role-scoped admin.
- **Endpoint**: `POST /contexts` (super-admin) + `POST /acl` for the admin
  grant. `cnm contexts bootstrap` does both in one call and emits the
  admin credential.
- **Derivation**: `m/26'/2'/<ctx_idx>'/<key_idx>'` — the context's BIP-32
  base path is allocated at creation and is immutable.
- **Code**: `vta-service/src/routes/contexts.rs`,
  `vta-service/src/operations/contexts.rs`.

### Provision-integration (template-driven)
- **What**: The generic path to bootstrap any integration (mediator,
  webvh-host, app, etc.) via a DID template. **This is the canonical flow
  for anything that needs a DID + keys + optional admin credential.**
- **Consumer emits**: VP-framed `BootstrapRequest` signed by an ephemeral
  holder `did:key`. References a template name + variable bindings.
  Seed persisted at `~/.config/{pnm,cnm}/bootstrap-secrets/<bundle_id>.key`
  (0600 + Windows ACL hardening).
- **Producer returns**: HPKE-sealed `TemplateBootstrapPayload` (integration
  DID, private keys, `did.jsonl`, VC-issued admin authorization, VTA trust
  bundle) in armor with SHA-256 digest communicated out-of-band.
- **Transports** (every transport supports relayer ≠ holder):
  - **Offline file**: `vta bootstrap provision-request` / `provision-integration` / `open`.
  - **Online**: `pnm bootstrap provision-request` →
    `pnm bootstrap provision-integration`, which sends the signed
    `provision/integration/0.3` Trust Task over TSP, DIDComm or HTTPS
    (`/trust-tasks`) — `VtaClient::provision_integration` is one
    `dispatch_trust_task`. There is no REST route. Supports
    `--create-context` to create the target context inline when
    missing — same flag the offline `vta` CLI exposes. Wire
    field `createContext` on the request payload, paired
    with `contextCreated` on the response so operators
    see whether the flag actually did something. Super-admin
    only (`operations::contexts::create_context`'s auth gate).
    A caller without the Admin role is refused before the target
    context is looked up.
- **Auth model** (both transports — onion layers):
  - **Outer**: bearer token (REST) / authcrypt sender (DIDComm)
    authenticates the *relayer*. ACL-gated.
  - **Inner**: VP `DataIntegrityProof` authenticates the
    *holder*. The bundle is HPKE-sealed to the holder's X25519
    derivation.
  - Relayer and holder may legitimately differ — the air-gap
    onboarding flow relies on this. The relayer can't decrypt
    the bundle (no holder private key), and the VP signature
    can't be forged without the holder's key, so there's no
    privilege escalation. Use `e.p.msg.forbidden` for genuine
    permission failures (caller authenticated but not admin in
    the context); the standard `e.p.msg.unauthorized` code is
    reserved for actual auth failures so the CLI doesn't print
    a misleading "Token may be expired" hint.
- **Code**: `vta-service/src/operations/provision_integration.rs`,
  `vta-sdk/src/provision_integration/{http,didcomm}.rs`,
  `vta-service/src/routes/bootstrap.rs:provision_integration`,
  `vta-service/src/messaging/handlers.rs:handle_provision_integration`.
- **Docs**: `docs/02-vta/provision-integration.md`.

### Runtime service management
- **What**: Add, update, remove, or roll back the VTA's
  advertised transport services (REST + DIDComm) on a *running*
  VTA without rebuilding it, re-issuing admin credentials, or
  rotating verification keys. Generalises the earlier
  DIDComm-only protocol-management surface — both transports get
  the same `services {kind} {verb}` operations. Each mutation
  publishes a new WebVH LogEntry; `verificationMethod` stays
  byte-identical before and after.
- **Operator commands** (spec §5.1):
  - `pnm services list` — show currently-advertised services.
  - `pnm services rest {enable,update,disable,rollback}` — manage
    REST advertisement (`#vta-rest` service entry).
  - `pnm services didcomm {enable,update,disable,rollback}` —
    manage DIDComm mediator advertisement (`#vta-didcomm`).
  - `pnm services didcomm drain {list,cancel}` — inspect or cancel
    drain entries.
  - `pnm services report` — per-mediator inbound counts +
    per-sender last-seen mediator from the telemetry sink.
- **Brick-prevention** (§3.2): at least one transport must remain
  advertised at all times. Single source of truth in
  `protocol::invariant::would_violate_last_service`; no `--force`
  escape hatch. Disable / rollback paths consult it before any
  I/O.
- **Fail-forward rollback** (§3.5a): WebVH is append-only;
  rollback never rewinds the chain. Reads the per-kind snapshot
  store (`protocol::snapshot`, fjall keyspace
  `service_prev_config`) and dispatches into the equivalent
  forward op (e.g. `enable` rolls back via `disable`).
  Single-step per kind; REST and DIDComm rollback are independent.
- **Drain mechanics** (DIDComm only): mediator changes go through
  a fjall-persisted drain set with a 30-day TTL cap and a 24h
  default. In-flight messages from senders with stale DID-doc
  caches keep landing while the new mediator picks up traffic.
  State is restart-resilient — boot replays outstanding drain
  timers via `DrainSweeper`. REST has no drain semantics.
- **Service[] ordering** (§3.3): when multiple transports are
  advertised, the canonical order is **TSP > DIDComm > REST**
  (then WebAuthn). Encoded via array order, not DIDComm v2's
  `priority` key — DID-Core resolvers walking the array pick the
  highest-preference transport first. Enforced in
  `protocol::document::sort_services_canonical` at the end of
  every `with_*_service` patcher.
- **Handshake**: `update`/`rollback`-into-update uses a *live*
  `DIDCommServiceProver` against the running service; first-enable
  spins up a transient `DIDCommService` just for the round-trip
  (`messaging::transient_handshake`).
- **Telemetry**: pluggable `vti_common::telemetry::TelemetrySink`
  trait; default impl is a ring buffer (`RingBufferTelemetry`).
  Forward operations carry an `OpContext::{Direct,Rollback}`
  parameter — rollback-dispatched ops emit
  `triggered_by: "rollback"` on their telemetry event.
- **Transport**: every operation is a `vta/services/*` Trust Task,
  over TSP, DIDComm or HTTPS (`/trust-tasks`) — `enable_didcomm`
  included, which a REST-only VTA receives over HTTPS. The SDK's
  typed methods (`vta_sdk::protocol`) map to them.
- **Code**: `vta-service/src/operations/protocol/{enable_rest,
  update_rest,disable_rest,rollback_rest,enable_didcomm,
  update_didcomm,disable_didcomm,rollback_didcomm,list,
  list_drain,snapshot,invariant,document}.rs`,
  `vta-service/src/messaging/{registry,drain_store,drain_sweeper,
  handshake,live_prover,transient_handshake}.rs`,
  `vta-service/src/trust_tasks/services.rs` (the `vta/services/*`
  Trust Tasks — the only surface; the REST routes are gone),
  `vta_sdk::protocol::{mod,services}`,
  `vta_cli_common::commands::services` (the `mediator`
  submodule was deleted in P5),
  `vta-service/src/services_cli.rs` (the offline
  `vta services …` surface — direct fjall access, no auth
  ceremony, not for TEE deployments).
- **Docs**: `docs/02-vta/runtime-service-management.md`
  (operator guide), `docs/05-design-notes/runtime-service-management.md`
  (spec). The earlier `didcomm-protocol-management.md` docs in
  both directories are superseded redirects.

### Sealed-transfer envelope format
- **Inner**: CBOR-serialized `SealedPayloadV1` enum variant.
- **Cipher**: HPKE base mode, X25519-HKDF-SHA256 + ChaCha20-Poly1305.
- **Framing**: OpenPGP-style ASCII armor with Bundle-Id, Chunk, Digest-Algo
  headers (bound to AAD) and CRC24 line checksum.
- **Producer assertion** (one of):
  - `DidSigned` — Ed25519 signature over
    `DID_SIGNED_DOMAIN_TAG || client_x25519_pub || bundle_id`. Default.
  - `Attested` — Nitro attestation quote. Verified via
    `vta_sdk::attestation::verify_nitro_assertion` (feature-gated).
  - `PinnedOnly` — OOB digest is the sole integrity anchor. Dev/test only.
- **Code**: `vta-sdk/src/sealed_transfer/` (bundle, hpke, armor, verify).

### Signing oracle
- **What**: Remote signing without key export.
- **Endpoint**: `POST /keys/{key_id}/sign` — payload + algorithm
  (EdDSA or ES256). Key derived BIP-32 → signature → memory zeroized.
  Derivation goes through `key_custody::derive_record_key`, which refuses a
  record whose path is outside its context's base.
- **DIDComm**: `key-management/1.0/sign-request`.
- **SSHSIG**: `keys/sign-sshsig/0.1` (git commit signing, `did-git-sign`) —
  the VTA builds the PROTOCOL.sshsig signed data from a digest + namespace and
  signs it as `SigningDomain::ProtocolDefined`, so it is not a general oracle
  and is gated on its own `sign-sshsig` capability (`sign` also accepted).
  Never let it sign caller-supplied bytes; that would make the narrow grant
  equal to `sign`.
- **JWS and certificate requests** (the VTC's VTA-held verifier identities,
  `vtc oid4vp attach` → `vtc_service::vta_link`): `keys/sign-jws/0.1` (an OpenID4VP request
  object) and `keys/sign-csr/0.1` (a PKCS#10 request for an EUDI access
  certificate) — the VTA sets `alg` from the key, refuses `alg`/`crit`/`b64`/
  `jwk`/`jku`/`x5u`, checks an `x5c` certifies the named key, and builds the
  JWS signing input (RFC 8785) or the `CertificationRequestInfo` itself
  (`operations::sign_formats`), signed as `ProtocolDefined`. Gated on
  `sign-jws` / `sign-csr` **only**: `sign` is not accepted, because this VTA
  frames `keys/sign` payloads and the specs say such a custodian SHOULD NOT
  widen `sign` into either.
- **Documents** (`keys/sign-document/0.1`: credentials, a member's external
  directory card): an `eddsa-jcs-2022` proof made **only as the DID the
  document names** (`issuer` / `controller`), with a key that DID's own document
  lists under the requested purpose. That document is never taken from the
  request — `did:key` / `did:peer` from the identifier, a `did:webvh` this VTA
  minted from its own log (`persona::own_document`), else resolved. The VTA
  builds the proof configuration and the 64 bytes of hash data
  (`sign_formats`), signed as `ProtocolDefined`. Gated on `sign-document`
  **only**; never sign a document that names no signer or already has a proof.
- **Delegated identities**: `keys/derive-and-sign*` signs as a path without a
  key record. Super-admin only, confined to `m/26'/9'`, audited with a digest
  of what was signed.

### Approvals + task consent (DTTE)
- **What**: The single answer to "does this operation need an additional
  human decision?" One rule list keyed on **Trust Task type URI**, carried
  in the `ext` of one reserved row (`approvals`, priority 200) in the
  policy keyspace. `requires: reauth` → PDP `requireStepUp` →
  self-elevation. `requires: consent` → PDP `requireConsent` → the **DTTE**
  ceremony (Delegated Trust-Task Execution).
- **Retired, and refused rather than ignored**: `[auth.step_up]` floors and
  `[[policy.require_consent]]`. A config carrying either **fails to load**,
  with an error naming `pnm approvals require …`. Delegated step-up is
  deleted, not ported — consent binds to the payload digest instead of
  elevating a session. First boot after upgrade also deletes the stranded
  `config:require-consent` row.
- **Enablement**: rules are inert unless `policy.enforcement = true`
  (`vta-config`, default **false**, config + restart — the runtime
  config-patch registry carries only `vta_did` / `vta_name` /
  `public_url`). `[policy.approvals]` / `[policy.approver_sets]` are a
  **seed applied once**, then the stored row wins; `vta setup --from`
  cannot carry them (`WizardInputs` is `deny_unknown_fields`).
- **Runtime surface**: `pnm approvals {list,require,remove,approvers,
  explain}` and `pnm policy {list,show,upsert,delete}` — read-modify-write
  of the reserved row over `policy/get/0.1` + `policy/upsert/0.2`.
  **Trust-Task transport only**; the SDK's REST arm is unimplemented and
  no `/policies` axum route exists, so a REST client gets a 404.
- **Offline break-glass**: `vta approvals {list,remove,delete-all}` +
  `vta policy {list,delete}`. Deliberately **cannot create** a rule; daemon
  stopped; not available in TEE.
- **Ceremony**: `task-consent/request/0.1` (outbound push, VTA-signed),
  `task-consent/decision/0.1` (**the only dispatched one**, DI-signed by
  the approver), `task-consent/granted/0.1` (notice). Approver-set
  membership alone authorizes a decision — an ACL entry is **not** required
  (#907). Ceremony tasks are exempt from PDP re-gating
  (`trust_tasks/ceremony.rs`). Two digests: internal `payload_digest` keys
  storage, challenge-salted `wire_digest` is all the approver ever sees.
- **Code**: `vta-policy/src/{approvals,defaults,types}.rs`, `vti-common/src/task_consent/` (the node-neutral pending/grant store + digest, re-exported as `vta_policy::{consent,effects}`),
  `vta-service/src/trust_tasks/{policy_gate,task_consent,consent_request,
  ceremony,planner}.rs`, `vta-service/src/approvals_cli.rs`,
  `vta-sdk/src/approvals/`, `vta-cli-common/src/{commands/approvals,
  commands/policy,consent}.rs`, `vta-mobile-core/src/consent.rs`.
- **Docs**: `docs/02-vta/approvals.md` (the rules),
  `docs/02-vta/task-consent.md` (the ceremony),
  `docs/05-design-notes/approvals-convergence.md` (why one model).
- **VTC single-administrator mode** (VTI-APV-022): `[acl] single_admin_mode`,
  host-only (setup writes it; `config/patch`/import refuse it), waives a VTC
  consent **whether or not other administrators' entries exist** — the mode
  states every administrator is one person, under as many identifiers as they
  hold (dtgwg-vti-spec#55) — on the requester's operation-bound step-up,
  always `Critical`-audited and bannered; never make it patchable
  (`vtc-action-list.md` §8.5). A reduction of another administrator
  (VTI-APV-019) is not consented in the mode: it takes the unopposed path
  (gesture, notice, `Critical` row) and keeps its cooling-off. It also waives
  git separation of duties (rule 7) on the same terms (`git_ns::single_admin`):
  step-up bound to the signed document, `SingleAdminMode{selfGrantWaived}`
  written before the record or the operation is refused; the record is marked
  `singleAdmin` and counts for the invariants. And it lets an unrestricted
  administrator edit its own entry (VTI-ACL-052 item 3,
  `acl::single_admin::authorize_self_edit`, `SingleAdminMode{selfEditWaived}`),
  never leaving no unrestricted entry; any subject may change its own label
  alone (item 2, `VtcAclEntry::label_set_by_subject`).
- **The VTC differs: it parks, the VTA re-sends.** A consent-gated VTC
  operation is stored as an action and runs itself on the N-th approval — see
  *VTC administrator action list* below. The VTC has no rule list yet; its
  approval rules are fixed in code.

### External accounts (`external/*`)
- **What**: The VTA holds identities at clouds and third-party services; a
  bound integration (a VTC storing room files) gets only a short-lived,
  downscoped credential, sealed to it. Served model: `s3-static-presign`
  (presigned URLs; the secret never leaves the VTA).
- **Invariants to preserve**: management needs `external-accounts-manage` in the
  account's context (act scope); issuance checks, in the spec's order, the
  binding first (the authenticated caller, never a payload DID — an unbound
  caller and an unknown account get the same `notFound`) → `external-auth-use`
  → account state → scope ⊆ ceiling → TTL → rate → a key-agreement key to seal
  to, before the provider is contacted.
  Scope values are validated identifiers, never interpolated caller strings.
  A credential leaves only inside `SealedPayloadV1::ExternalCredential`, and is
  never logged or audited. Secrets live wrapped in `external_secrets`
  (excluded from backup) and are never returned; `providerSetupRequired` holds
  issuance until a probe that is both `ok` and `complete`. The VTA needs no inbound surface for any
  model.
- **Code**: `vta-external/src/`, `vta-service/src/trust_tasks/external.rs`,
  `vta_sdk::client::external`, `vta-cli-common/src/commands/external.rs`
  (`pnm external …`).
- **Docs**: `docs/02-vta/external-accounts.md`,
  `docs/05-design-notes/vta-external-accounts.md`.

### Room revocation (`rooms/revocations/*`, `rooms/owner/revoke`)
- **What**: A room withdraws credentials it issued before they expire, effective at its
  host at once (trust-tasks-tf #804). The room's **revocation list** — signed by the
  room, cumulative, numbered — is made by the owner's VTA (it holds the room key) and
  delivered to every host serving the room; a host holds the latest one per room and
  refuses every presentation it withdraws.
- **Invariants to preserve**: the host checks the list inside `vti_rooms::authz::authorize`
  — every task, every version, the membership credential and every chain link (a
  `subject` entry matches subject **or issuer**, `validFrom < revokedAt`) — with the same
  opaque `permissionDenied` as any refusal; never a revocation-specific code or text.
  `authorize` holds the room's gate (`revocation::gate`) shared until the
  `AuthorizedAction` is dropped and accepting a list holds it exclusively, so keep the
  value alive until the operation commits and never authorize the same room twice in one
  request. Transfer steps that present nothing are held to the list through the
  credentials recorded at begin (`revocation_tasks::hold_transfer_step`). A list is
  accepted only room-signed (method under the room's DID), higher sequence, append-only;
  the deliverer is checked against the **held** list. Hosts read the list from the
  payload **as received** (a generated-type round trip rewrites its timestamps). The VTA
  keeps the list with the room key (`room_groups`, `room-revocations/<roomId>`), signs one
  list per sequence under `room_revocation::signing_lock`, through the gated oracle, and
  delivers it before answering `rooms/owner/register`. `group/remove/0.2` withdraws
  first, then advances; a private room is never withdrawn per member.
  `register/0.2` answers success once the host took the registration, with
  `revocation.status` `inForce` only when the host answered with the list's head; a
  `pending` list is retained (room, host, sequence, persona) **before** the delivery and
  redelivered by `trust_tasks::room_list_delivery`, the one retry owner — latest list,
  capped backoff + jitter, never a `refused` one. A pending removal's list refused on
  redelivery is settled by `group/remove/0.3` item 8 at **every** version and task
  (`HostCall::settle_refused_list`): only `listInvalid`/`entryNotPermitted`/
  `sequenceConflict` discard the list (and only while still held); the request is then
  refused and never goes on to its own work — `earlierRemovalRefused` at `remove/0.3`,
  `add/0.3` and `renew/0.2` (trust-tasks-tf #824), the task's own `hostRefused` with
  `{member, code, listKept}` at the versions declaring no such code. `AdvanceCodes`
  stages `hostUnreachable` and `hostRefused` independently: `add/0.3` / `renew/0.2`
  stage the first and give `hostRefused` `{code, reason}`; only `remove/0.2`/`0.3`
  give it `{stage, code}`.
- **Code**: `vti-rooms/src/{revocation,revocation_tasks,authz}.rs`,
  `vti-rooms-dtg/src/lib.rs` (`verify_room_signed`, `credential_facts`),
  `room-host/src/files.rs`, `vtc-service/src/rooms/{handlers,files}.rs`,
  `vta-service/src/operations/room_revocation.rs`,
  `vta-service/src/trust_tasks/{room_owner,room_owner_revoke,room_owner_group,room_list_delivery}.rs`,
  `vtc-service/src/rooms/departures.rs` (`remove_member`).
- **Docs**: `docs/02-vta/data-rooms.md` (§6), `docs/03-vtc/community-rooms.md`.

### Hidden-vetting PCS engine (`vta/pcs/*`)
- **What**: The VTA holds its principal's PCS keys and runs every member-side
  hidden-vetting operation — an applicant's application, attestation receipt
  and proof; a vetter's enrolment, token drip and attestation — so a client with
  no PCS implementation (a mobile wallet) can take part. The client carries the
  messages to the community and the other party; the VTA never talks to the
  community itself (yet). Design §13 C7.
- **Invariants to preserve**: **no `usk` is stored or returned** — each member
  key is re-derived on every use from a path allocated under its context's base
  (VTI-KEY-030), through `key_custody::derive_pcs_member_seed` (custody rules 3
  and 6), domain-separated from the Ed25519 node at that path. One vetter key
  per (context, community) for life; a second member DID is `memberMismatch`.
  No task returns a key, a class credential, an unspent token or blinding
  state; everything secret is wrapped under the seed-derived KEK in
  `pcs_engine` (backed up). `pcs-vetter` / `pcs-applicant` are never `sign` and
  `application` derives neither. Audit never pairs a vetter with an applicant
  identifier, tag or statement metadata. The community-side verifier
  (`vti_vetting_pcs::verifier`) is authoritative for the wire; a spec that
  disagrees with it is the one to fix (`idBinding` is hex, not multibase).
- **Code**: `vti-vetting-pcs/src/{vetter,applicant,snapshot}.rs`,
  `vta-service/src/operations/pcs.rs`, `vta-service/src/trust_tasks/pcs.rs`
  (+ `pcs_tests.rs`, the end-to-end run against `vtc::Vtc`),
  `vta-keys/src/custody.rs` (`authorize_pcs_derivation`),
  `vta_sdk::client::pcs`, `vta-mobile-core/src/pcs.rs`.
- **Docs**: `docs/02-vta/pcs-engine.md`.

### Witnessed party (`vta/witness/*/0.2`)
- **What**: The VTA is the participating party of a `witness/session/0.2` for its
  principal: `open` returns the `witness/session` document signed as the
  relationship DID, `present` verifies the witness's session answer and returns
  the signed `witness/session/submit/0.2` (relationship presentation, and under
  the member link the member presentation in its own `memberPresentation`), `accept`
  verifies the VWC and stores it with its evidence, and `list` (`vta/witness/list/0.1`)
  reads stored VWCs back with that evidence exactly as stored. **The client carries every
  document** from the relationship DID — the witness checks the transport-proven
  sender against `issuer`, and that DID's one mediator socket is the client's.
- **Invariants to preserve**: the VTA never contacts the witness and never signs
  as itself; keys come through `operations::persona::persona_key_for` (a
  `did:peer` relationship DID included) plus `keys::require_key_nameable`, and
  every signature is `ProtocolDefined` through the oracle — `witness-request`,
  never `sign`. Every handed-back document is checked against the session record
  (type, issuer = witness, recipient = relationship DID, thread, witness proof)
  before it is read — `VerifiedWitnessAnswer` / `VerifiedWitnessOutcome` are the
  only way in. `sessionUnknown` is one answer whatever the cause. The record
  (`witness_sessions`, not backed up, swept) holds no presentation or challenge;
  audit never names a member DID. Only 0.2 is served, and a session record is
  continued only by the version that opened it (a record whose session document
  is not `witness/session/0.2` is `sessionUnknown`); the `ext["org.openvtc.witness"]`
  carriage is retired, never read or written. `list` returns only active entries
  in contexts the caller may act in; an unknown or unreachable DID filter is an empty
  page, never an error; evidence comes from the vault entry's `witness:session` /
  `witness:outcome` tags, never rebuilt or re-signed.
- **Code**: `vta-service/src/operations/witness.rs`,
  `vta-service/src/trust_tasks/{witness,witness_tests}.rs`,
  `vta_sdk::client::witness`.
- **Docs**: `docs/02-vta/witness-party.md`, `docs/06-witness/README.md`.

### Vault archival lifecycle (archive / soft-delete / restore / purge)
- **What**: Full lifecycle for **both** VTA stores — the password
  vault (`vault:` keyspace, `vti_common::vault::VaultEntry`) and the
  credential store (`cred:` keyspace, `vta-service::vault::model::
  StoredCredential`). Adds archive (reversible hide), a **recoverable**
  soft `delete` (tombstone + grace window, default 30d via
  `VaultConfig.grace_days`), `restore` (undelete within grace),
  `purge` (irreversible), and `delete --force` (immediate hard delete).
  Archival state (`VaultStatus {Active,Archived,Deleted}`) is orthogonal
  to a credential's *validity* (`CredentialStatus`); non-Active entries
  drop out of list/query and are refused for use (release / proxy-login
  / sign / present).
- **Trust Tasks** (openvtc 0.1 extensions): password vault
  `vault/{archive,unarchive,restore,purge}/0.1` (`VaultWrite`);
  credential store `vault/credentials/{archive,unarchive,delete,restore,
  purge}/0.1` gated on the **new `CredentialWrite`** capability (removing
  a holder's credentials is higher-trust than receiving them).
  `vault/delete/0.1` body gained `force: bool`; response `graceUntil`
  is now a real deadline.
- **Sweeper**: `vault_sweeper::sweep_expired` (storage-thread interval,
  alongside acl/consent sweepers) hard-purges grace-expired tombstones in
  both stores; credential purge tears down the `idx:` secondary index via
  `vault::storage::delete`.
- **Audit**: every vault Trust Task (read or write, success or denied) is
  audited **once at the dispatch spine** (`vault.*` / `vault.cred.*`
  actions); the operator `reason` lands in the audit row's new `detail`
  field (`audit::record_with_detail`).
- **Brick-prevention**: `upsert` refuses to overwrite a non-Active entry
  (would wipe lifecycle state); `restore` re-checks the grace window
  before writing; non-Active entries conflate to `not_found` on the
  consumer use paths (enumeration resistance).
- **Code**: `vti-common/src/vault/mod.rs` (`VaultStatus`, lifecycle
  methods, `LifecycleError`), `vta-service/src/trust_tasks/{vault,
  cred_vault,mod}.rs`, `vta-vault/src/{model,status,query,
  present}.rs`, `vta-sweepers/src/vault_sweeper.rs`,
  `vta_sdk::client::vault`, `vta_cli_common::commands::{vault,cred_vault}`
  (`pnm vault {archive,unarchive,restore,purge}`, `delete --force`,
  `list --status`; `pnm cred-vault {receive,query,get,archive,unarchive,
  delete,restore,purge}` — the credential store's operator surface).

### Backup / restore
- **What**: Encrypted full-state dump + restore, portable between plain,
  hardened and TEE VTAs in any direction.
- **Surface**: the descriptor Trust Tasks (`vta/backup/*`), super-admin,
  over an end-to-end transport only. There is no inline REST route.
- **Export** walks `vta_keyspaces::BACKED_UP` and dumps every row (format
  `vta-backup-v2`) — no per-keyspace collector, so listing a keyspace *is*
  backing it up. Rows in `ENVIRONMENT_BOUND_ROWS` (`keys ▸ tee:*`,
  `hardened:*`, blinded persona indexes, daemon tokens) stay behind; the
  target re-creates its own. Internal keys are never carried (their records
  are, and the restore reports them lost). `every_backed_up_keyspace_
  survives_a_round_trip` holds all of it across the eight env pairings.
- **Import never writes the live store.** It *stages* the payload in
  `bootstrap` sealed under a key derived from the **restored** seed, commits
  that seed the target's way (`RestoreCommitter`: secret store, or one
  KMS-sealed row in an enclave), and re-execs. Each binary applies a pending
  restore (`restore::apply_pending_restore`) as soon as it knows its seed and
  storage key, before anything else reads the store. Do not apply a restore in
  place: the storage key is a function of the seed. See
  `docs/05-design-notes/backup-restore-portability.md`.
- **TEE**: the restore reserves the restored DID's anti-rollback counter at
  commit, closes the Mode-B carve-out, and the boot re-baselines the manifest at
  exactly the reserved version (`integrity::rebaseline_after_restore`) — a
  replayed stage is refused.
- **Crypto**: Argon2id KDF (≥15-char password — the minimum is
  `vta_sdk::protocols::backup_management::MIN_BACKUP_PASSWORD_LEN`, the single
  source of truth every export-side guard reads) + AES-256-GCM, v2 binding the
  envelope metadata as AAD.
- **Compatibility check**: a backup of a DID other than the running one is
  refused unless `replace_identity` (`--replace-identity`,
  `ext["org.openvtc"].replaceIdentity`) — disaster recovery onto a fresh VTA,
  which always has a DID of its own. VTI-VTA-051: provenance in
  `keys ▸ restore:provenance`, a `backup.restore.applied` audit row, and
  the `vta/restore/status/0.1` Trust Task (administrators only; `pnm health`
  shows it). The public `vta/health/details/0.1` never carries it.
- **Code**: `vta-backup/src/{ops/mod.rs,restore.rs}`,
  `vta-support/src/restore_stage.rs`, `vta-service/src/restore.rs`,
  `vta-tee/src/kms_bootstrap.rs` (`seal_restored_secrets`,
  `adopt_restored_secrets`).
- **Docs**: `docs/02-vta/backup-restore.md`.
- **VTC counterpart** (P3.9): same shape for the VTC — `POST
  /backup/{export,import}` (super-admin, preview/confirm), Argon2id +
  AES-256-GCM, `check_vtc_did_compatibility` (mismatch → 409). Backs up
  14 of 21 keyspaces (the community's social state, incl. `status_lists`)
  **plus the signing key bundle** so a restore reconstitutes signing, not
  just data; sessions/passkey/install/sync/registry/config are excluded.
  The `keyspaces::BACKED_UP`/`EXCLUDED_FROM_BACKUP` partition is pinned by
  a census test. Code: `vtc-service/src/backup.rs`,
  `vtc-service/src/routes/backup.rs`. Docs:
  `docs/03-vtc/backup-restore.md`, `docs/05-design-notes/vtc-backup-restore.md`.

### Promote a serverless DID to a server-managed one
- **What**: An operator who set up the VTA serverless (no webvh
  host configured at setup time) decides later they want their
  DID published to a host. This op pushes the existing local
  `did.jsonl` to the host and flips the local record's
  `server_id` from `"serverless"` to the registered server id —
  the DID identifier is unchanged, so every existing integration
  keeps working.
- **Refused if** the DID is already server-managed (re-pointing
  a hosted DID at a different host needs coordinated teardown on
  the old host and is out of scope for this op).
- **CLI**: `pnm did-mgmt dids register --did <did> --server <id>
  [--domain <name>]` (online, REST). `vta did-mgmt dids register …`
  (offline; daemon must be stopped, fjall lock; not available in TEE).
- **Code**: `vta-service/src/operations/did_webvh/register_server.rs`,
  `vta-service/src/routes/did_webvh.rs::register_did_with_server_handler`,
  `vta_sdk::client::VtaClient::register_did_with_server`.
- **Docs**: `docs/02-vta/runtime-service-management.md`
  (walkthrough section).

### Provision a DID into a specific hosting domain
- **What**: When the registered DID-hosting backplane serves
  several tenant domains, point a new (or being-promoted) DID at
  a specific one rather than the server's system default. Used
  by tenant-isolated multi-tenant deployments.
- **Wire**: Per-DID `domain: Option<String>` on every outbound
  webvh op (`request_uri`, `register_did_atomic`, `publish_did`,
  `delete_did`, `check_path`). The remote `did-hosting-control`
  resolves: explicit → caller's ACL default on the host →
  system default → reject with `did-management:unknownDomain`.
  Wire types `CreateDidWebvhBody/Request/Params` and
  `RegisterDidWithServerBody/Params` carry the field; v0.7
  callers and hosts that don't yet understand it serialise
  cleanly (`skip_serializing_if = "Option::is_none"`).
- **CLI**: `pnm did-mgmt dids create --domain <name>` and
  `pnm did-mgmt dids register --domain <name>`. Optional. Omit
  to use the server's resolution chain. Interactive TTY
  invocations targeting a multi-domain server *without*
  `--domain` get prompted to pick.
- **Discovery**: `pnm did-mgmt dids list-domains --server <id>`
  asks the server for `did-management/me/domains/0.1` (a Trust Task
  the VTA signs and sends) and prints the caller-scoped subset.
  Use this to find legitimate `--domain` values for the same
  server before the first create / register.
- **Code**: `vta-service/src/webvh_host.rs`,
  `vta-service/src/operations/did_webvh/{mod,servers,host,register_server}.rs`,
  `vta-service/src/routes/did_webvh.rs::list_server_domains_handler`,
  `vta_sdk::client::VtaClient::list_webvh_server_domains`,
  `pnm-cli/src/commands/webvh.rs` (interactive prompt +
  list-domains dispatch).
- **Docs**: `docs/02-vta/runtime-service-management.md`
  (walkthrough "provision into a specific hosting domain").

### DID template management
- **Offline**: `pnm did-templates init <kind>`, `validate`, `list-builtins`.
- **Online**: `pnm did-templates list/show/create/update/delete` →
  REST `/did-templates` (global) or `/contexts/{id}/did-templates` (scoped).
- **Built-ins** (`vta_sdk::did_templates::BUILTIN_NAMES`, shipped with
  the SDK, always available): `ai-agent`, `ai-agent-peer`,
  `ballot-box`, `did-host-didcomm`, `did-host-http`, `did-host-http-didcomm`,
  `did-host-http-tsp`, `did-host-tsp`, `didcomm-mediator`,
  `dtg-witness`, `push-gateway`, `swiyu-verifier`, `vta-admin`, `vtc-group`, `vtc-host`. The `did-host-*` names encode
  the DID-document **shape** (`http` = WebVHHosting, `didcomm` =
  DIDCommMessaging, `tsp` = TSPTransport), so a deployment role maps onto
  a shape: control = `did-host-http-didcomm`, hosting daemon =
  `did-host-http`, witness/watcher = `did-host-didcomm`. `pnm
  did-templates init` accepts those role words as aliases. The earlier
  `webvh-*` **and** `did-hosting-*` template names have been removed —
  a stale name now fails instead of resolving. (`did-hosting-*` remains
  valid as an *integration kind* and as a service/binary name; it is only
  retired as a template name.)
- **Code**: `vta-sdk/src/did_templates/`,
  `vta-service/src/routes/did_templates.rs`, `vta-service/src/operations/did_templates.rs`.
- **Docs**: `docs/02-vta/did-templates.md`.

### A room's own profile (`rooms/keys/profile/{read,write}`)
- **What**: a room's name / description / tags / emoji (`RoomProfile`), kept
  **inside the room** — one record per epoch at `profile_key(E)` (HKDF over the
  epoch's storage key, `vti_rooms::profile`; `room-profile` on `open`), sealed
  like any record, so the host cannot tell it from any other. The member's VTA
  finds, fetches, opens and judges it, and writes it, as the member's persona.
- **Invariants to preserve**: the **reader** decides who may name the room
  (`operations::room_profile::check_statement`): the statement's own chain
  must confer `curate` or `admin` on its `author`, valid at its `issuedAt`
  (`vti_rooms_dtg::profile`), and `issuedAt` must sit in `[updatedAt − 1h,
  updatedAt + 5m]` — a host stores it under `write`, so never treat "the host
  accepted it" as authority. A refused profile is ignored and **reported**
  (`rejected`), never shown. The walk takes the newest accepted, stops at a
  retraction (`cleared`). A write is refused `noAuthority` before the host
  without `write` + (`curate`|`admin`); version races re-seal, then
  `contended`. The owner's key holder reads the profile **before** every
  `group/{add,remove,renew}` and re-writes it after the host accepts — never
  failing, delaying or undoing the advance. `keys/read` does not open a profile
  location and `keys/browse` leaves it out. Never put a profile in a
  credential, a host record or `register`.
- **Code**: `vti-rooms/src/profile.rs`, `vti-rooms-dtg/src/profile.rs`,
  `vta-service/src/operations/room_profile.rs`,
  `vta-service/src/trust_tasks/room_profile.rs` (+ `_tests.rs`, against a real
  `room-host`), `vta_sdk::client::rooms` (`room_profile_*`),
  `pnm rooms profile {show,set,clear}`.
- **Docs**: `docs/02-vta/data-rooms.md` (*The room's own name*).
