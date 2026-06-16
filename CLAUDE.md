# CLAUDE.md — Verifiable Trust Infrastructure workspace

Workspace-wide design principles, crate map, and integration-flow reference.
Each crate also has its own CLAUDE.md for crate-specific guidance; consult
those in addition to this file.

## Workspace layout

Rust workspace (edition 2024, resolver 3, MSRV 1.95.0). Dependencies flow
strictly downward — no cycles. There are two leaf crates with no internal
workspace deps (`vti-common`, `vta-sdk`); everything else depends on one
or both of them, plus optionally on `vta-cli-common`.

```
Leaf crates:
  vti-common   (no internal deps)
  vta-sdk      (no internal deps)

  vti-secrets     → vti-common (+ vta-sdk under the `onboarding` feature)
  vta-cli-common  → vta-sdk, vti-common
  vta-service     → vti-common, vti-secrets, vta-sdk, vta-cli-common
  vtc-service     → vti-common, vti-secrets, vta-sdk
  pnm-cli         → vta-sdk, vta-cli-common
  cnm-cli         → vta-sdk, vta-cli-common
  vta-mcp         → vta-sdk
  vta-enclave     → vta-service (consumed as a library)
```

| Crate | Role |
|---|---|
| `vti-common` | Shared foundation: JWT auth, ACL, `Store`/`KeyspaceHandle` enum (local fjall + vsock), `AppError`, config types, identifier validation (`identifier.rs`), `secure_file` (owner-only file hardening), pluggable telemetry sink (`telemetry::TelemetrySink`, default ring buffer), the `SeedStore` trait |
| `vta-sdk` | Public SDK: types, REST + DIDComm client, `sealed_transfer`, `did_templates`, `provision_integration`, attestation verification, `protocol` (DIDComm protocol-management types) |
| `vti-secrets` | Shared secret-store backends (AWS / GCP / Azure / Vault / Kubernetes / keyring / config-seed / TEE-KMS / plaintext) + the `create_seed_store(&secrets, &data_dir)` factory + `SecretsConfig`, all behind the same feature flags. Plus (feature `onboarding`) `IntegrationOnboarding` — the ephemeral-`did:key` → ACL-grant → auto-rotate cold-start helper. Lets external VTI integrations onboard + store secrets exactly like first-party ones without depending on `vta-service`. The backend implementations are shared by **both** the VTA (`vta-service::keys::seed_store`) and the VTC (`vtc-service::keys::seed_store`, which keeps its own factory for VTC-specific storage locations / `*SecretStore` naming) |
| `vta-service` | VTA logic (library) + local/dev binary. Routes, operations (provision-integration, did-webvh, contexts, backup, **protocol management**), setup wizards (interactive + `--from <toml>`), DIDComm bridge + `messaging::*` (registry, drain store/sweeper, handshake, live prover, transient handshake) |
| `vta-enclave` | Nitro Enclave front-end. Depends on `vta-service` as a library, adds TEE bootstrap (KMS, vsock-store, attestation). `publish = false` |
| `vtc-service` | Verifiable Trust Community service (community lifecycle, separate JWT audience) |
| `vta-cli-common` | Shared CLI command implementations — both CLIs are thin wrappers |
| `pnm-cli` | Personal Network Manager (single-VTA operator) |
| `cnm-cli` | Community Network Manager (multi-community operator) |
| `vta-mcp` | Model Context Protocol server bridging a VTA's agent capabilities (signing oracle, vault, device, discovery) to MCP tools over stdio, so any MCP host (Claude Desktop, agent frameworks) can use a VTA with no custom code. `publish = false` |
| `didcomm-test` | Standalone DIDComm connectivity harness (test tool, `publish = false`) |

Hot spots to know about (file size in source lines, sorted descending):
- `vta-service/src/operations/provision_integration/mod.rs` (~1.8k lines)
  — orchestrates template render → key mint → ACL wire-up → VC issue
  → seal. Split into a module directory; the seal helper extracted to
  `seal.rs` is the canonical place for new payload variants.
- `vta-service/src/tee/kms_bootstrap.rs` (~1.65k lines) — KMS attest/
  decrypt, JWT fingerprint check, storage-key derivation, MODE_B_LOCK
  carve-out gating.
- `vta-service/src/messaging/registry.rs` (~1.3k lines) — the
  `MediatorListenerRegistry`: active-mediator membership, drain
  windows, sticky outbound routing, telemetry emission. Load-bearing
  for the protocol-management surface.
- `vta-service/src/operations/did_webvh/mod.rs` (~1.15k lines) —
  WebVH DID lifecycle + `did.jsonl` publication, used by every
  protocol-management operation that mutates the VTA's own DID.
- `vta-sdk/src/sealed_transfer/` — HPKE seal/open, armor, assertions
  (`DidSigned`, `Attested`, `PinnedOnly`).
- `vta-service/src/messaging/{drain_store,drain_sweeper,handshake,live_prover,transient_handshake}.rs`
  — protocol-management plumbing. Smaller individually (~120–420
  lines) but tightly coupled; touch one and you usually touch
  several.
- `vti-common/src/store/vsock.rs` — enclave-side store proxy;
  semantic parity with local fjall is asserted but under-tested.

## Default to DIDs wherever we handle public keys

Every public-key surface in operator- or wire-facing APIs is a `did:key`
(Ed25519, multicodec `0xed01`), not a raw base64url pubkey. The HPKE layer
still operates on X25519 bytes internally; those are derived on demand via
`affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes` (public) and
`affinidi_crypto::ed25519::ed25519_private_to_x25519` (secret) and stay
inside the cipher layer.

This applies to both sides of `sealed_transfer` (`client_did`, `producer_did`),
to CLI recipient flags (`--recipient-did`), and to any new protocol we add.
Tests and docs refer to DIDs, not pubkeys.

## Prefer DIDComm transport wherever possible

**DIDComm (authcrypt) is the preferred transport/protocol for inter-component
communication** — VTA ↔ mediator ↔ push-gateway ↔ devices ↔ integrations —
wherever the counterparty can speak it. REST/HTTPS is a **fallback for parties
that cannot do DIDComm**, not the default.

When designing any new inter-component flow *or its authentication*, reach for
DIDComm **first**. Do **not** default to "a REST endpoint plus a bespoke
signature/DID-resolution scheme" — that is a recurring mistake.

Why: with authcrypt, **sender authentication is intrinsic** — unpacking a
message yields a cryptographically-authenticated sender DID (resolution handled
inside the DIDComm stack), so there is no hand-rolled signature verification and
no custom DID-resolution-in-verify, and `did:webvh` / `did:web` peers work
without special handling. It also provides encryption and reuses the existing
mediator infrastructure, and keeps everything on canonical DIDs (above).

Add a REST/HTTPS path only for counterparties that genuinely can't speak
DIDComm, and treat its (e.g. did-signed) auth as the secondary path. Concrete
example — the push gateway is reachable both ways: a `WakeHandle.gateway` that
is a **DID** means DIDComm (preferred); a **URL** means REST (for others).

## Use DID templates, don't hand-roll DID shapes

The workspace has a **DID templates feature** (`docs/02-vta/did-templates.md`,
`vta-sdk/src/did_templates`, `vta-service/src/routes/did_templates.rs`). A
template is a JSON file describing the **shape** of a DID document with
`{TOKEN}` placeholders; the VTA renders them server-side, filling in keys it
just minted + caller-supplied variables. Built-ins ship with the service
(`didcomm-mediator`, `vta-admin`, `did-host-http-didcomm`,
`did-host-http`, `did-host-didcomm`); operators can upload more. The
`did-host-*` names describe the DID-document shape (`http` = WebVHHosting
endpoint, `didcomm` = DIDCommMessaging endpoint), not the service. The
previous `webvh-*` and `did-hosting-*` template names still resolve via
the loader's alias table for one release — update operator configs to the
canonical `did-host-*` names before the aliases are removed.

**Before inventing a new mint-a-DID path, reach for templates first.**

- When a caller needs a DID (mediator first-boot, webvh host, app identity),
  the right wire shape is "template name + variable bindings", not
  "hand-crafted `MintHints` / `ProvidedDid` / method enum". The template
  already encodes method, service endpoints, key shapes, and required vars.
- The VTA always mints the key material. A caller never ships private keys,
  and we never need a proof-of-possession challenge to verify a caller-
  provided DID — the key generator *is* the VTA.
- Templates are added via their own authed endpoint, not smuggled inline
  through another request. A `BootstrapRequest` referencing template
  `mediator-custom` is only valid if `mediator-custom` is already registered
  on that VTA.
- Variable validation (`requiredVars`, `optionalVars`, unknown-var rejection)
  is the template renderer's job — reuse it, don't re-implement.

The pattern is: operator authors template once → every setup wizard, CLI,
and provisioning surface renders from it → swap the JSON file to change the
DID shape for every consumer, no redeploy.

The noun for "a thing a template provisions" is **integration** (not
"agent" — that word collides with VTA = Verifiable Trust *Agent*). CLI
reads "provision-integration"; docs talk about "integration kinds"
(mediator, did-hosting-control, did-hosting-daemon, did-hosting-server, app, etc.); each
template declares its kind in the `kind` field.

## Authorization claims between VTA and integrations use VC/VP format

When the VTA attests authorization to a holder (e.g., at bootstrap — "this
DID is admin of context X at this VTA"), the attestation is a **W3C
Verifiable Credential**, not a bespoke signed JSON struct. When a holder
presents something to the VTA signed with their DID (e.g., a bootstrap
request), the envelope is a **W3C Verifiable Presentation**.

Rationale:
- **Standards discipline.** VCs/VPs are the SSI-native envelopes for these
  semantics. Using them means we delegate proof handling to well-tested
  libraries (`affinidi-vc`, `affinidi-data-integrity`) and stay compatible
  with external verifiers that show up later.
- **Scope boundary.** VCs here are bootstrap-transport only — the VTA's
  ACL is the authoritative source of authorization in steady state, not
  the VC. VCs are short-lived (1h default), carry no `credentialStatus`
  (no StatusList machinery), and are never re-verified after first open.
  Revocation is ACL removal, not credential status change.
- **One-shot lifecycle.** The VC is issued once at bootstrap, verified
  once at bundle open, archived for audit. It never participates in
  steady-state operations between VTA and integration.

If you find yourself signing a JSON struct with a VTA key for anything
that resembles an authorization assertion, stop and use a VC. If you find
yourself accepting a signed JSON struct as a holder presentation, use a
VP. Custom JSON-LD contexts for our shapes live under
`https://openvtc.org/contexts/` — baked into crates at compile time via
`include_str!` so verification works offline.

## Typestate discipline for verified wire forms

Wire forms that require cryptographic verification (VPs, VCs, signed
envelopes) expose a `.verify()` method returning a distinct
`Verified*` type. Downstream code only takes the verified form. A call
site that forgets to verify doesn't compile — wrong type.

Pattern:

```rust
// Over-the-wire form: anyone with a byte stream can deserialize this.
pub struct BootstrapRequest { /* ... */ signature: String }

impl BootstrapRequest {
    pub fn verify(self) -> Result<VerifiedBootstrapRequest, ...>;
}

// Post-verification form: only constructable via `.verify()`.
// Every function that takes this is guaranteed to be looking at a
// verified request.
pub struct VerifiedBootstrapRequest { inner: BootstrapRequest }
```

Apply to any wire form where "this came from a trusted source" is a
precondition for subsequent work. Don't paper over with a `verified:
bool` field; use the type system.

Reference implementations:
- `verify_producer_assertion_with_pubkey`
  (`vta-sdk/src/sealed_transfer/verify.rs`) returns
  `Result<VerifiedAssertion<'a>, _>` with `DidSignedVerified`,
  `PinnedOnlyAcknowledged`, and `AttestedNeedsNitroCheck` variants.
  Callers must match exhaustively, and the `Attested` arm
  explicitly demands a follow-up `verify_nitro_assertion` call.
- `verify_vta_authorization_credential`
  (`vta-sdk/src/provision_integration/`) returns
  `Result<VerifiedAuthorizationCredential, _>`. The verified type
  carries the eagerly-parsed claim — forgetting to read the claim
  no longer means re-running verification, and forgetting to verify
  before reading is a compile error.

Use these shapes when adding new wire forms.

## Sealed-transfer is the only secret-bearing wire format

Every credential / key / DID-secrets bundle that moves between tools is
sealed via `vta_sdk::sealed_transfer` — HPKE-encrypted to a consumer-supplied
`client_did`, framed in ASCII armor, with a producer assertion
(`PinnedOnly` / `DidSigned` / `Attested`) + out-of-band SHA-256 digest.

Invariants (do not relax):
- HPKE suite is hardcoded: X25519-HKDF-SHA256 KEM, HKDF-SHA256 KDF,
  ChaCha20-Poly1305 AEAD. Not negotiable.
- Info string is domain-bound: `b"vta-sealed-transfer/v1"`. New protocol →
  new info string, not a version parameter.
- `SealedPayloadV1` is tagged with `#[serde(rename_all = "snake_case")]` and
  new variants are **additive**. Never reshape an existing variant — you
  break every existing opener. Add a new variant and let consumers migrate.
- Digest pinning is mandatory at the CLI (`--expect-digest`). `--no-verify-digest`
  exists only as an explicit opt-out with a warning.
- `DID_SIGNED_DOMAIN_TAG = b"vta-sealed-transfer/v1\0"` prefixes the bytes
  that Ed25519 signs. Don't reuse this tag elsewhere.

If you find yourself emitting plaintext JSON containing private keys, stop
and wrap it in a `SealedPayloadV1` variant instead.

## Operator errors should suggest the fix

When the CLI hits a 409 / 404 / 403 and the operator's real intent maps to a
different command, print the corrected command verbatim. Example: `pnm
contexts create --admin-did X --admin-expires 1h` against an existing context
prints the `pnm acl create --did X --role admin --contexts <id> --expires 1h`
the operator should have run. Don't just surface the HTTP error.

This is why the SDK's `VtaError` carries typed variants (not an opaque
`Protocol(String)`) — the CLI layer switches on them to emit friendly
guidance. Preserve the type information through both REST and DIDComm
transports; never collapse a Conflict into a string.

## Integration flows

This section is a map of the wire-level flows the workspace supports. Each
flow links to the canonical docs + the code entry points. When adding a
new flow, update both this section and the relevant `docs/*.md`.

### VTA first-boot setup
- **What**: Mints master seed, VTA DID, mediator DID, first admin credential.
- **Entry point**: `vta setup` (interactive) or `vta setup --from <file>` (TOML-driven).
- **Code**: `vta-service/src/setup/interactive.rs`, `vta-service/src/setup/from_toml.rs`.
- **Seed**: 24-word BIP-39 mnemonic, stored via `affinidi-secrets-resolver`
  backend (OS keyring by default; AWS/GCP/Azure via feature flags).
- **Docs**: `docs/02-vta/cold-start.md`, `docs/02-vta/non-interactive-setup.md`.

### Admin credential cold-start
- **What**: Bootstrap the first operator without a running VTA.
- **Flow**: PNM mints ephemeral `did:key` locally → operator runs
  `vta import-did --did <temp> --role admin` offline → VTA starts → PNM
  authenticates → on first authenticated call PNM **auto-rotates** to a
  fresh `did:key`, creates the new ACL entry, deletes the temp one.
- **Code**: `pnm-cli/src/setup.rs`, `vta-service/src/main.rs` (`import-did`).
- **Docs**: `docs/02-vta/cold-start.md` §3–6.

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
- **What**: One-command admin provisioning against a fresh Nitro-Enclave VTA.
- **Entry point**: `pnm bootstrap connect --vta-url <url>`.
- **Transport**: REST `POST /bootstrap/request` (unauth, rate-limited).
- **Trust anchor**: Nitro attestation quote committing to the client's
  Ed25519 pubkey + bundle_id + producer's Ed25519 pubkey via SHA-256.
- **Carve-out**: Single-use. `BOOTSTRAP_CARVEOUT_CLOSED_KEY` flips on
  first success; subsequent calls return 410.
- **Code**: `vta-service/src/routes/bootstrap.rs`, `vta-service/src/tee/`.
- **Docs**: `sealed-bootstrap.md`, `docs/02-vta/tee-architecture.md`.

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
- **Transports** (REST and DIDComm both support relayer ≠ holder):
  - **Offline file**: `vta bootstrap provision-request` / `provision-integration` / `open`.
  - **PNM REST bridge**: `pnm bootstrap provision-request` →
    `pnm bootstrap provision-integration` (authenticated, hits
    `POST /bootstrap/provision-integration`). Supports
    `--create-context` to create the target context inline when
    missing — same flag the offline `vta` CLI exposes. Wire
    field `create_context: bool` on the request body, paired
    with `context_created: bool` on the response so operators
    see whether the flag actually did something. Super-admin
    only (`operations::contexts::create_context`'s auth gate).
  - **DIDComm**: same `pnm bootstrap provision-integration`
    command when the client is on DIDComm transport. The
    `provision-integration/1.0` message carries the VP and
    receives the same sealed bundle. `VtaClient::
    provision_integration` dispatches based on the
    `Transport::Rest`/`Transport::DIDComm` variant.
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
- **Service[] ordering** (§3.3): when both transports are
  advertised, DIDComm comes first. Encoded via array order, not
  DIDComm v2's `priority` key — DID-Core resolvers walking the
  array pick DIDComm first. Enforced in
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
- **Transport**: all operations except `services didcomm enable`
  are reachable over both REST and DIDComm. `enable_didcomm` is
  REST-only by nature (DIDComm isn't running yet). Wire types
  live in `vta_sdk::protocol::services`; DIDComm message types
  in `vta_sdk::protocols::protocol_management` under
  `services-management/1.0/`.
- **Code**: `vta-service/src/operations/protocol/{enable_rest,
  update_rest,disable_rest,rollback_rest,enable_didcomm,
  update_didcomm,disable_didcomm,rollback_didcomm,list,
  list_drain,snapshot,invariant,document}.rs`,
  `vta-service/src/messaging/{registry,drain_store,drain_sweeper,
  handshake,live_prover,transient_handshake}.rs`,
  `vta-service/src/routes/protocol.rs`,
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
- **DIDComm**: `key-management/1.0/sign-request`.

### Backup / restore
- **What**: Encrypted full-state dump + restore.
- **Endpoints**: `POST /backup/export`, `POST /backup/import`
  (super-admin).
- **Crypto**: Argon2id KDF (≥12-char password) + AES-256-GCM.
- **Compatibility check**: import cross-checks the backup's `vta_did`
  against the running VTA via `check_vta_did_compatibility`
  (`vta-service/src/operations/backup.rs:286-307`). A fresh-install VTA
  accepts any backup; a configured VTA rejects backups whose `vta_did`
  doesn't match. Tested at `backup.rs:867-911`.
- **Code**: `vta-service/src/operations/backup.rs`.
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
  system default → reject with `did-management:unknown_domain`.
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
  walks the server's `/api/me/domains` (proxied through the VTA
  with VTA credentials) and prints the caller-scoped subset.
  Use this to find legitimate `--domain` values for the same
  server before the first create / register.
- **Code**: `vta-service/src/webvh_didcomm.rs`,
  `vta-service/src/webvh_client.rs`,
  `vta-service/src/operations/did_webvh/{mod,servers,auth_cache,register_server}.rs`,
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
- **Built-ins**: `didcomm-mediator`, `vta-admin`, `did-hosting-control`,
  `did-hosting-daemon`, `did-hosting-server` (shipped with the SDK,
  always available). Three did-hosting templates by deployment role:
  `did-hosting-control` (hosting + DIDComm), `did-hosting-daemon`
  (hosting only), `did-hosting-server` (DIDComm only, for
  witness/watcher). Legacy `webvh-*` names resolve via the loader's
  alias table for one release.
- **Code**: `vta-sdk/src/did_templates/`,
  `vta-service/src/routes/did_templates.rs`, `vta-service/src/operations/did_templates.rs`.
- **Docs**: `docs/02-vta/did-templates.md`.

## Runtime guards to preserve

These are load-bearing — know they exist before adjusting nearby code.

- **Rate limit** on all unauth routes: `tower-governor` at 5 rps + 10
  burst per source IP (`vta-service/src/routes/mod.rs`). Keep JWT-gated
  routes off the limiter — auth is the gate.
- **Request body cap**: 1 MB globally (`MAX_BODY_SIZE`). Matters in TEE
  where memory is tight.
- **Audience isolation** between VTA and VTC JWTs. Cross-audience tokens
  are rejected. Don't add a "shared" audience.
- **Mnemonic export window** (`MnemonicExportGuard`) — one-shot, timed,
  zeroized on drop. Don't cache the plaintext anywhere.
- **JWT key fingerprint** on TEE boot (`vta-service/src/tee/kms_bootstrap.rs`)
  detects KMS ciphertext tampering or key rotation. Do not widen the
  "first boot after upgrade" silent-store path.
- **Carve-out** (`BOOTSTRAP_CARVEOUT_CLOSED_KEY`) on `/bootstrap/request`
  is single-use. The whole check-then-mint-then-set sequence is gated
  by a process-wide async mutex (`MODE_B_LOCK`) — without it, two
  concurrent requests both pass the `is_some()` check and both mint
  admins. New TEE flows must not provide a back door.

## Versioning & publishing (workspace-specific)

When bumping crate versions in this Rust workspace, always check and bump
dependent sub-crate versions too. Use `major.minor` version pinning (not
`major.minor.patch`) for internal dependencies. Exception: crypto deps
(`ed25519-dalek`, `hpke`, `jsonwebtoken`, `aes-gcm`, `aws-lc-rs`) should
pin to a minimum patch to avoid silent regressions when a CVE lands.
The legacy `rsa` crate was replaced with `aws-lc-rs` in 0.5 for KMS CMS
unwrap (drops RUSTSEC-2023-0071 exposure); don't reintroduce `rsa`.

## Commit hygiene

- Run `cargo fmt` before committing.
- All commits must be DCO-signed (`git commit -s`).
- Don't bypass hooks (`--no-verify`), don't skip signatures, don't amend
  published commits.

## General

Before creating new crates or clients, search the workspace and crates.io to
check if the functionality already exists. Prefer existing SDKs over custom
implementations. Before writing any fix, analyze the root cause and explain
the diagnosis. Fix the cause, not the symptom — no workarounds.
