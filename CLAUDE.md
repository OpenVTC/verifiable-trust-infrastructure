# CLAUDE.md — Verifiable Trust Infrastructure workspace

Workspace-wide design principles, crate map, and integration-flow reference.
Each crate also has its own CLAUDE.md for crate-specific guidance; consult
those in addition to this file.

## The specification comes first

This workspace implements the VTI specification: <https://trustoverip.github.io/dtgwg-vti-spec/>

Before changing the authority model (contexts, ACL entries, roles,
capabilities, approvals), the client lifecycle, the operation surface,
transports, sessions, credentials or the audit trail, **read what the
specification requires**. It is normative; this code is an implementation of
it. Where they disagree, the specification is correct and the code changes.

- Cite requirement identifiers (`VTI-ACL-021`, `VTI-CLT-023`) in commit
  messages, in comments explaining a constraint that would otherwise look
  arbitrary, and in test names where a test holds a requirement.
- Never diverge silently. A divergence goes in the specification's divergence
  register (Appendix F) with the requirement, the behaviour and the intended
  resolution; recording it is not an exemption from it.
- "The existing code does it this way" is not an argument against a
  requirement. Several requirements exist precisely because the obvious
  implementation is wrong in a way that only appears adversarially.

## Workspace layout

Rust workspace (edition 2024, resolver 3, MSRV 1.95.0). Dependencies flow
strictly downward — no cycles. There are two leaf crates with no internal
workspace deps (`vti-common`, `vta-sdk`); everything else depends on one
or both of them, plus optionally on `vta-cli-common`.

`vta-service` has been **decomposed into subsystem crates** (#780–#791, nine
steps, ~114k → ~87k lines). Each subsystem is re-exported from `vta-service`, so
`crate::policy::…`, `vta_service::tee::…`, and `crate::operations::backup::…`
still resolve — **but new code should depend on the subsystem crate directly**,
not reach through the facade. Before proposing a further extraction, read
`docs/05-design-notes/vta-service-decomposition.md`, which records the technique
and — importantly — where the program stops.

```
Layer 0 (leaves):
  vti-common   (no internal deps)
  vta-sdk      (no internal deps)
  vti-secrets     → vti-common (+ vta-sdk under the `onboarding` feature)

Layer 1 (VTA foundations):
  vta-keyspaces   → vti-common
  vta-config      → vti-common, vti-secrets
  vta-audit       → vta-sdk, vti-common

Layer 2 (VTA subsystems):
  vta-support     → vta-config, vta-keyspaces, vta-sdk, vti-common
  vta-keys        → vta-config, vta-keyspaces, vta-sdk, vti-common, vti-secrets
  vta-vault       → vta-keyspaces, vta-sdk, vti-common
  vta-webvh       → vta-keyspaces, vta-sdk, vti-common
  vta-policy      → vta-config, vta-keyspaces, vti-common

Layer 3 (composed subsystems):
  vta-tee         → vta-config, vta-keys, vta-keyspaces, vta-support, vti-common
  vta-backup      → vta-config, vta-keys, vta-keyspaces, vta-sdk, vta-support,
                    vta-webvh, vti-common
  vta-sweepers    → vta-audit, vta-keyspaces, vta-vault, vti-common

Layer 4 (the spine + consumers):
  vta-cli-common  → vta-sdk, vti-common
  vta-service     → every vta-* subsystem above, + vti-common, vti-secrets,
                    vta-sdk, vta-cli-common
  vtc-service     → vti-common, vti-secrets, vta-sdk
  pnm-cli         → vta-sdk, vta-cli-common
  cnm-cli         → vta-sdk, vta-cli-common
  vta-mcp         → vta-sdk
  vta-enclave     → vta-service (consumed as a library)
```

| Crate | Role |
|---|---|
| `vti-common` | Shared foundation: JWT auth, ACL, `Store`/`KeyspaceHandle` enum (local fjall + vsock), `AppError`, config types, identifier validation (`identifier.rs`), `secure_file` (owner-only file hardening), pluggable telemetry sink (`telemetry::TelemetrySink`, default ring buffer), the `SeedStore` trait, `guards` (executor preconditions) |
| `vta-sdk` | Public SDK: types, REST + DIDComm client, `sealed_transfer`, `did_templates`, `provision_integration`, attestation verification, `protocol` (DIDComm protocol-management types) |
| `vti-secrets` | Shared secret-store backends (AWS / GCP / Azure / Vault / Kubernetes / keyring / config-seed / TEE-KMS / plaintext) + the `create_seed_store(&secrets, &data_dir)` factory + `SecretsConfig`, all behind the same feature flags. Plus (feature `onboarding`) `IntegrationOnboarding` — the ephemeral-`did:key` → ACL-grant → auto-rotate cold-start helper. Lets external VTI integrations onboard + store secrets exactly like first-party ones without depending on `vta-service`. The backend implementations are shared by **both** the VTA (`vta-keys::seed_store`) and the VTC (`vtc-service::keys::seed_store`, which keeps its own factory for VTC-specific storage locations / `*SecretStore` naming) |
| `vta-keyspaces` | Keyspace-name registry — the `const` names every `store.keyspace(..)` call uses, plus the backup partition (`ALL` / `BACKED_UP` / `EXCLUDED_FROM_BACKUP`, pinned by a census test). Dependency-free leaf |
| `vta-config` | `AppConfig` TOML shape + sub-configs (`PolicyConfig`; under `tee`, `TeeConfig` / `TeeKmsConfig` / `TeeMode`), composed over `vti-common`'s shared config types |
| `vta-audit` | Structured audit logging for security-relevant operations, so any subsystem can emit audit events without depending on the whole service. `AuditLogEntry.detail` carries the operator `reason` |
| `vta-support` | Shared mid-layer services — trust-context storage (the BIP-32 key-hierarchy roots) and the other clean glue subsystems need |
| `vta-keys` | **Key management**: master-seed storage, BIP-32 hierarchical derivation, key wrapping (AES-GCM), imported-key handling, `create_seed_store` backend selection, `derive_pre_rotation_keys` |
| `vta-vault` | **Holder credential vault**: storage, query, receive/verify, present, status refresh, and the archival lifecycle (`VaultStatus {Active,Archived,Deleted}`) |
| `vta-webvh` | WebVH hosting infrastructure for the `did:webvh` lifecycle and its other consumers |
| `vta-policy` | Policy subsystem: the regorus (Rego) engine + default bundle, the DTTE consent model, decision evaluators, policy storage |
| `vta-tee` | TEE bootstrap: attestation providers (Nitro / SEV-SNP / simulated), KMS attest/decrypt, storage-key derivation, CMS unwrap, the DynamoDB anti-rollback anchor MAC, Mode-B admin bootstrap + carve-out, the mnemonic-export guard. Behind the `tee` feature — keeps the AWS SDK stack out of the default build graph |
| `vta-backup` | Encrypted full-state export (every `BACKED_UP` keyspace) and staged, boot-applied restore portable between plain / hardened / TEE VTAs (Argon2id + AES-256-GCM), the `vta_did` compatibility check, the two-phase descriptor flow. The bundle store, its TTL sweeper and the chunked transfer are node-neutral and live in `vti_common::backup_transfer` (re-exported here under their old paths), shared with the VTC. How a deployment adopts a restored seed is injected via the `RestoreCommitter` trait |
| `vta-sweepers` | Background TTL sweepers for the core keyspaces (acl / consent / vault) |
| `vta-service` | The VTA **spine** (library) + local/dev binary — what remains after the subsystem extractions: `routes/` (HTTP surface), `trust_tasks/` (dispatch spine), `messaging/*` (DIDComm + TSP bridge: registry, drain store/sweeper, handshake, live prover, transient handshake), `operations/` (orchestration: provision-integration, did-webvh, contexts, protocol management), `setup/` (wizards, interactive + `--from <toml>`), and the offline CLI surfaces. Re-exports every subsystem crate above |
| `vta-enclave` | Nitro Enclave front-end. Depends on `vta-service` as a library, adds TEE bootstrap (KMS, vsock-store, attestation). `publish = false` |
| `vtc-service` | Verifiable Trust Community service (community lifecycle, separate JWT audience) |
| `vta-cli-common` | Shared CLI command implementations — both CLIs are thin wrappers |
| `pnm-cli` | Personal Network Manager (single-VTA operator) |
| `cnm-cli` | Community Network Manager (multi-community operator) |
| `vta-mcp` | Model Context Protocol server bridging a VTA's agent capabilities (signing oracle, vault, device, discovery) to MCP tools over stdio, so any MCP host (Claude Desktop, agent frameworks) can use a VTA with no custom code. Carries a **local per-operation guard** (`guard.rs`) because an MCP host approves a *tool*, not a call — once `vta_call` is approved every Trust Task URI rides that approval — plus stderr/JSONL call logging (`observability.rs`). Docs: `docs/02-vta/vta-mcp.md`. `publish = false` |
| `didcomm-test` | Standalone DIDComm connectivity harness (test tool, `publish = false`) |

Hot spots to know about (file size in source lines, sorted descending):
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

## Prefer TSP, then DIDComm, then REST

**Preference order for inter-component transport is TSP > DIDComm > REST** —
VTA ↔ VTC ↔ mediator ↔ push-gateway ↔ devices ↔ integrations. **TSP (Trust
Spanning Protocol) is the preferred transport** wherever both parties advertise
it; **DIDComm (authcrypt) is the fully-supported fallback** for peers that don't
yet speak TSP; **REST/HTTPS is the last fallback** for parties that can do
neither. TSP is additive — DIDComm keeps working everywhere it does today. See
`docs/05-design-notes/tsp-enablement.md` for the rollout design.

**The DID document is authoritative for which protocols a party speaks.** Both
sides' capability is read from their advertised services, **matched on the service
`type`** (`TSPTransport` → TSP, `DIDCommMessaging` → DIDComm, `VTARest` → REST) —
**never on the `#id` fragment**, which is an arbitrary label (the OWF reference TSP
impl names it `#tsp-transport`, Affinidi names it `#tsp` — same type). The protocol
used is the **highest-preference one present in *both* parties' DID documents**. If
the intersection is empty, raise a typed **"no matching protocol"** error
(`VtaError::NoMatchingProtocol`) — never silently downgrade past what a peer
advertises, and never infer protocol from endpoint *shape* (a TSP VID and a DIDComm
mediator are both DIDs — match on `type`, not "is it a DID"). Emitted service-id
convention is `#tsp` / `#didcomm` / `#rest` (the older `#vta-didcomm` / `#vta-rest`
are still read by type). TSP advertises like DIDComm: `#tsp`'s `serviceEndpoint` is
the **mediator's DID**; the real transport URL lives in the mediator's own DID doc.

When designing any new inter-component flow *or its authentication*, reach for
TSP first, then DIDComm. Do **not** default to "a REST endpoint plus a bespoke
signature/DID-resolution scheme" — that is a recurring mistake.

**There is one client surface — Trust Tasks — and TSP rides one socket per DID.**
Two rules that bite anything adopting TSP (see
`docs/05-design-notes/tsp-enablement.md` §3.3a):

- Every `VtaClient` operation is a Trust Task, and TSP, DIDComm and HTTPS all
  carry the same Trust-Task spine. The older bare-DIDComm protocol-message
  surface (`key-management/1.0/*`, `create_did_webvh`, `list_contexts`) is gone
  from both ends — the SDK sends none, and the VTA's DIDComm router serves only
  the binding envelope plus plumbing (trust-ping, pickup status,
  problem-report). A client's transport is `VtaClient::trust_task_transport`.
  On a dual-transport VTA it reports TSP while the client still holds a
  `DIDCommSession`: that session stays **only** as the mediator's one socket per
  DID, on which TSP receive arrives — not as a second surface.
- **The mediator permits one websocket per DID.** A node speaking both protocols
  multiplexes them on that socket; a second is evicted as `duplicate-channel`
  and the two reconnect loops duel. TSP send is an HTTP post and TSP receive
  arrives on the existing pickup socket already tagged by protocol, so no second
  socket is ever needed. `vta-service` works this way; client-side it is
  `DIDCommSession`'s TSP leg via `VtaClient::enable_tsp_trust_tasks`. If you are
  reaching for `TspSession::connect` on a DID that already holds a
  `DIDCommSession`, use the leg instead.

Why TSP over DIDComm: metadata-private routing (intermediaries don't learn the
final recipient) at **bounded** message size (CESR + HPKE add roughly additive
per-hop overhead, versus DIDComm-nested's multiplicative base64 blow-up), while
keeping DIDs as VIDs so one identity works in both stacks. Long-term goal is to
deprecate DIDComm in favour of TSP (phased — see the design note); until then
DIDComm remains a first-class supported transport.

Why DIDComm over REST (the established fallback): with authcrypt, **sender
authentication is intrinsic** — unpacking a message yields a cryptographically-
authenticated sender DID (resolution handled inside the stack), so there is no
hand-rolled signature verification and `did:webvh` / `did:web` peers work
without special handling. TSP gives the same intrinsic sender authentication.

Add a REST/HTTPS path only for counterparties that can speak neither TSP nor
DIDComm, and treat its (e.g. did-signed) auth as the last-resort path. Concrete
example — the push gateway: a `WakeHandle.gateway` carries an explicit protocol
tag (a bare DID-vs-URL shape no longer disambiguates, since TSP VIDs are DIDs
too).

**Exceptions to "every remote operation is a Trust Task"** are foreign-protocol
interfaces only — OAuth / WebAuthn ceremonies and DID resolution files — and a
REST route kept for one is declared, not assumed. The passkey-VM enrolment
routes (`/did/verification-methods/passkey{,/challenge,/{fragment}}`) are the
WebAuthn exception: the browser driving the ceremony (the VTA auth portal,
`examples/vta-auth-demo`) holds only the bearer passkey-login issued and no DID
key to sign a Trust Task. DID-holding clients use the `vta/passkey-vms/*` twins.
The declaration is a row in `vta_service::deprecation::REST_EXCEPTIONS`, pinned
to a live route by `every_rest_exception_names_a_live_route`.

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
previous `webvh-*` and `did-hosting-*` template names **no longer resolve** —
their one-release alias window closed, in both the builtin loader and the
`did-templates init` CLI. Operator configs must use the canonical `did-host-*`
names; a stale name now fails rather than silently resolving.

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

## Trust Task wire types come from `trust_tasks_rs::specs`

The Trust Task specifications in dtgwg-trust-tasks-tf are normative, and
`trust-tasks-codegen` generates a Rust type for every payload and response in
the registry, published by `trust-tasks-rs` under `trust_tasks_rs::specs`.

- **Never hand-write a payload or response type for a task that has a generated
  module** (`trust_tasks_rs::schema_index::schema_for` says whether it does).
  Use the generated type. A crate wanting a shorter path re-exports it, as
  `vta_sdk::protocols::vetting` does, and takes type URI constants from
  `<Payload as trust_tasks_rs::Payload>::TYPE_URI`, not a literal.
- **Behaviour stays hand-written and operates on the generated types**: signing,
  verification, counting, and the rules JSON Schema cannot state (an event's
  `endDate` against its `startDate`) as a check over the generated type — never
  a parallel struct or a field-by-field mirror.
- **Read received JSON against the schema before parsing it**
  (`vta_sdk::protocols::vetting::read_checked`). Some generated constructors
  normalise what they parse, so only the JSON shows what was sent.
- **A specification change lands in dtgwg-trust-tasks-tf first** and reaches
  this workspace through a `trust-tasks-rs` bump — never as a local edit to a
  copied type.
- A generated type is foreign, so `utoipa::ToSchema` cannot be derived on it.
  Document a REST body with a wrapper in `vta_sdk::openapi`, whose schema is
  rendered from the specification's own.

`vta-sdk/tests/generated_wire_types_census.rs` enforces the first rule: it fails
on a serde type whose doc summary names a generated task as its payload,
request, response or body. So name the task in a wire type's summary. Its
baseline lists the types that predate their generated modules, and only shrinks.

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
  exists only as an explicit opt-out with a warning. **One exception, and it is
  not a loophole**: `pnm bootstrap connect` mints its bundle *during* the call,
  so no out-of-band digest can exist beforehand and the rule was in practice
  forcing every operator onto `--no-verify-digest`. There, `--expect-pcr0` is an
  accepted anchor instead — a pre-computable pin on the enclave image,
  enforced by `check_pcrs` against the attestation quote, which already binds
  `SHA256(client_ed25519 || bundle_id || producer_ed25519)`. Every other path
  (offline `bootstrap open`, provision flows) still requires a digest or the
  warning-bearing opt-out. An anchor is only substitutable when the substitute
  is checked; do not read this as permission to drop one.
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

### VTC first-boot setup (VTA-provisioned)
- **What**: Stands up a VTC by provisioning its DID + keys from a running
  VTA via the `vtc-host` DID template, then writing `config.toml`, the
  `did.jsonl`, the sealed key bundle, and a one-shot admin install URL.
  The VTC is **not** the key authority — the VTA mints; the VTC caches.
- **Entry point**: `vtc setup` (interactive) or, for headless bring-up, a
  **two-phase** flow mirroring mediator / did-hosting:
  1. `vtc setup --setup-key-out <path> [--context <id>]` — mint + persist
     an ephemeral `did:key` (0600) and print the `pnm contexts create …
     --admin-did` grant command. Reuses the shared SDK helper
     `vta_sdk::provision_client::driver::run_phase1_init`.
  2. *(out of band)* an operator / CI step holding VTA admin runs that
     grant — VTC deliberately never holds a VTA admin credential (no
     self-grant), same as mediator / did-hosting.
  3. `vtc setup --from <toml>` — load the now-authorised key
     (`setup_key_file`) and provision end-to-end (no TTY).
- **Secrets**: `[secrets] backend = "vault"|"k8s"|"aws"|"gcp"|"azure"|`
  `"keyring"|"config"|"plaintext"` selects the store explicitly (validated,
  fail-closed); omit for legacy implicit resolution. All backends except
  TEE-KMS (a permanent VTC non-goal) are supported. Factory:
  `vtc-service/src/keys/seed_store/mod.rs::create_secret_store`.
- **First administrators**: the install claim writes the first
  `community-admin` (passkey claim 0.2, or wallet claim 0.3 binding the
  plugin's approver as step-up factor); `co_admin_did` adds a second;
  `--single-admin` writes `[acl] single_admin_mode` (see *VTC administrator
  action list*).
- **Code**: `vtc-service/src/setup/{wizard,from_toml,phase1}.rs` (both
  front-ends build one `WizardPlan` → shared `apply`),
  `vtc-service/src/main.rs` (`setup` subcommand),
  `vtc-service/src/config.rs` (`SecretBackend`).
- **Docs**: `docs/03-vtc/non-interactive-setup.md`,
  `docs/03-vtc/getting-started.md`,
  `docs/03-vtc/examples/vtc-setup.example.toml`.

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
- **What**: One-command admin provisioning against a fresh Nitro-Enclave VTA.
- **Entry point**: `pnm bootstrap connect --vta-did <did> --expect-pcr0 <hex>`.
  `--vta-did` and `--vta-url` are mutually exclusive and exactly one is
  required. The DID is resolved **locally** (SCID + signed log verified on the
  operator's machine, deliberately ignoring `PNM_RESOLVER_URL`), and bootstrap
  uses the `VTARest` endpoint that document advertises — never a URL guessed
  from the DID's host, and never a fallback on resolution failure. `--vta-url`
  is the explicit alternative when the log is not yet resolvable; it gives up
  identity pinning.
- **Transport**: REST `POST /bootstrap/request` (unauth, rate-limited).
- **Trust anchor**: Nitro attestation quote committing to the client's
  Ed25519 pubkey + bundle_id + producer's Ed25519 pubkey via SHA-256.
  `--expect-pcr0` pins the enclave image on top of it and is the anchor this
  path requires (see the sealed-transfer exception above); `--expect-pcr8` is
  an additional pin, never an anchor on its own — it measures the signing
  certificate, not the image.
- **Carve-out**: Single-use. `BOOTSTRAP_CARVEOUT_CLOSED_KEY` flips on
  first success; subsequent calls return 410. It closes server-side **before
  the bundle is returned**, so every client-side pin must be syntax-checked
  before the POST — a malformed `--expect-pcr0/8` caught at `check_pcrs` is
  caught after the VTA's one and only first boot has been spent.
- **Code**: `vta-service/src/routes/bootstrap.rs`, `vta-tee/src/`.
- **Docs**: `docs/05-design-notes/sealed-bootstrap.md`, `docs/02-vta/tee-architecture.md`.

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
  `did-host-didcomm`, `did-host-http`, `did-host-http-didcomm`,
  `did-host-http-tsp`, `did-host-tsp`, `didcomm-mediator`,
  `push-gateway`, `vta-admin`, `vtc-host`. The `did-host-*` names encode
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

### VTC administrator action list (`vtc/admin/actions/*`)
- **What**: Second-party consent at the VTC. An operation that needs other
  administrators' agreement — an authority-conferring grant or admin invite
  (VTI-APV-018), a reduction of another administrator (APV-019), lowering the
  consent threshold (APV-020), authority policy (VTI-VTC-022), a custom role
  define/delete, a restore's commit — is **parked** after the requester's
  operation-bound step-up (202 + `trust-task-next-step` naming the action) and
  **runs itself on the N-th approval**, every check re-run against the
  community as it is then (APV-017). The same list holds `coolingOff` items (a
  reduction nobody but requester and subject could approve; lands after
  `acl.removal_cooling_off`, cancellable by the requester only) and
  `acknowledge` items (each offline ACL write, VTI-VTC-023, record type
  `vtc/operator/offline-write/0.1`).
- **Invariants to preserve**: an approval is a `task-consent/decision` signed
  by the approver's **own DID** (wallet or `cnm`), never a console key;
  `webauthn` / `approverSigned` evidence rides beside it, never instead. The
  requester never approves, nor the subject of a reduction. One decline closes
  an action. Execution is crash-safe (`executing` + effect record, reconciled
  by the minute sweeper). **Single-administrator mode** (VTI-APV-022, `[acl]
  single_admin_mode`) is host-only (setup writes it; `config/patch` / import
  refuse it), waives a consent only when the approver set is **empty**, on the
  requester's bound step-up, always `Critical`-audited and bannered; it never
  skips a reduction's cooling-off. Never widen it to a non-empty set or make
  it patchable.
- **Code**: `vtc-service/src/admin_actions/`,
  `vtc-service/src/acl/{admin_consent,single_admin}.rs`,
  `vtc-service/src/trust_tasks/action_tasks.rs`, `cnm-cli/src/actions.rs`.
- **Docs**: `docs/03-vtc/admin-access.md` §2–3,
  `docs/05-design-notes/vtc-action-list.md`.

### VTC step-up: passkeys and approver devices
- **What**: Authority-changing VTC acts need a step-up bound to a digest of
  that one operation (`acl::bound_step_up`, one use within 300 s). It is
  answered by a passkey, or by a **step-up approver** — an Ed25519 `did:key`
  bound to the subject, such as the browser plugin's per-community approver
  identity (`approveStepUp`) — whose statement is carried in an
  approve-response signed by the subject's own DID (VTI-APV-015).
- **Invariants to preserve**: every enrolment rests on an anchor independent of
  the subject's signing key — install claim 0.3, another administrator's
  invite, a factor already held, or `vtc admin enrol-approver` offline — proves
  possession, and is audited with `enrolledVia` (VTI-APV-016). Nobody invites
  themselves; a revoked approver DID is never bound again. Once a subject holds
  a dedicated factor, their session passkeys stop counting. A
  console-key-signed answer is `subjectMismatch`.
- **Code**: `vtc-service/src/acl/{bound_step_up,approver}.rs`,
  `vtc-service/src/step_up_approver.rs`,
  `vtc-service/src/trust_tasks/step_up_approver_tasks.rs`.
- **Docs**: `docs/03-vtc/admin-access.md` §3.1,
  `docs/05-design-notes/vtc-approver-step-up.md`.

### VTC role-based administration (`acl/*/0.2`, `vtc/roles/*`)
- **What**: VTC authority is capabilities (optionally resource-qualified)
  bounded by an administrative role's ceiling; built-in roles plus **custom
  roles** stored in the `acl` keyspace (`role:<name>`). Every gate asks the
  live entry (`VtcAclEntry::can`); a custom role is resolved from its stored
  definition on every read, and an entry naming an undefined role confers
  nothing (VTI-ACL-011).
- **Invariants to preserve**: `vtc/roles/define|delete`, authority-conferring
  grants, reductions, threshold lowering, authority policy and a backup
  restore's commit all park in the action list; approvers are read off
  **approve scope** (`admin_consent::may_approve`), so the least-privilege
  `approver` counts. A role's ceiling is bounded by its requester's **and
  approvers'** holdings. A departed (removed, narrowed or expired) granter's
  grants become one `acl.grants.review` action; the delegation sweeper is the
  backstop. Git grants (resource grants beside the role) go to review only on
  the granter's departure from the community, never on a narrowing. `acl/swap-key/0.1` is the only self-modification: same authority,
  link proof from the new key, audited before the atomic move, delegations
  re-pointed.
- **Code**: `vtc-service/src/acl/{capability,roles,granting,delegation,admin_consent}.rs`,
  `vtc-service/src/trust_tasks/{acl_tasks,role_tasks}.rs`,
  `vtc-service/src/admin_actions/`.
- **Docs**: `docs/03-vtc/admin-access.md`, `docs/05-design-notes/vtc-admin-roles.md`.

### VTC admin console live channel (`vtc/admin/events/*`)
- **What**: An open admin console learns *when* to re-read — the action list,
  acknowledgements, join requests, members, single-administrator mode, the
  configuration — without polling every read on a timer. One stream per
  console session; polling stays the fallback.
- **Transport**: HTTPS binding 0.3 §2.1 **streamed responses** — the signed
  `vtc/admin/events/subscribe/0.1` document POSTed to the ordinary
  `/v1/trust-tasks` door with `Accept: text/event-stream, application/json;q=0.5`,
  answered `200 text/event-stream` with the signed `#response` as the first
  event and `vtc/admin/events/event/0.1` documents after it (one per `data:`
  line, no `event:` field, SSE `id` = resume token, heartbeats as comments).
  Why SSE and not TSP/DIDComm: the console is a browser holding only a console
  key, and no other binding defines a streamed response — a subscribe arriving
  any other way is `streamUnavailable`. Why `fetch` and not `EventSource`:
  every (re)connection must be a freshly signed POST; resumption is in-band
  `since` only (`Last-Event-ID` is a cross-check, mismatch → `malformedRequest`).
- **Hints only — the invariant**: an event carries `topic`, `at`,
  `resumeToken` and, on `actions` / `acknowledgements` / `joinRequests`, the
  recipient's `count`. Never a record, a record id or a DID, in any member
  including `ext`. The console re-fetches the topic's own signed read, so
  authorization stays on every read and the stream needs no model of its own.
  Do not "optimise" a hint into carrying the changed row: that is the moment
  the stream needs per-record authorization and diverges from the reads.
- **Invariants to preserve**: refusals are JSON and open no stream; nothing
  but hints and heartbeats after the `#response` (never a `trust-task-error`);
  standing is re-checked on every ACL change, before every hint and once a
  heartbeat, and a shrink **ends** the stream rather than dropping a topic; the
  stream ends no later than the signer's ACL entry / console-key delegation /
  document `expiresAt`, and within an hour; caps 5 per administrator, 256 in
  all (`tooManyStreams`); the subscribe's response is never recorded for
  redelivery (a replay answers `204`); the bus is fed from storage seams
  (action save/delete, join-request store/delete, member store/delete, ACL
  store/delete, config override and profile writes) and carries no row data;
  no lock across an await (R1.3); the console's live status is derived from
  bytes arriving, never latched (R6.2).
- **Code**: `vtc-service/src/admin_events/` (bus, tokens, caps, standing,
  stream), `vtc-service/src/trust_tasks/event_tasks.rs` (the subscribe
  handler), `vtc-service/src/routes/trust_tasks.rs` (Accept negotiation, the
  stream slot), `admin-ui/src/lib/{live-events,use-live-events}.ts`,
  `admin-ui/src/components/LiveIndicator.tsx`, `cnm-cli/src/actions_watch.rs`
  (`cnm actions watch`).
- **Docs**: `docs/03-vtc/website-and-admin.md` (*Live updates, and polling as
  the fallback*).

### VTC git namespaces (`git-ns/*`)
- **What**: A VTC governs repositories on the forges it has bound — who may
  create them, who owns each, whose commits its CI check accepts — and
  publishes those rights to its Trust Registry. The VTC is the source of
  truth; the registry and the forge (through a per-community bridge) are
  projections of it.
- **Wire**: the `git-ns/*` Trust Tasks, generated types under
  `trust_tasks_rs::specs::git_ns`, served on the document dispatcher. Authority
  is the proof signer's **git rights**, read at execution time — never a bearer
  token, and never the community-admin role (whose community-wide
  `git.ns.admin` only binds, reseats a headless namespace and ratifies). **One
  authority model (VTI-VTC-020, phase C3):** a git right is a *resource grant*
  on the holder's ACL entry (`acl::resource_grant`) — `git.ns.admin`,
  `git.repo.manage` graded `create`/`own`/`maintain`, or `git.commit.sign`,
  qualified by `git-ns:<forge>/<owner>` or `git-repo:<forge>/<owner>/<repo-id>`,
  each with its own `delegatedBy`. There is no separate rights store: `git_ns::
  store::{get,put}_rights` and `Snapshot::load` read and write the entries
  (through a `git-holder:` index in the `acl` keyspace), and the fixed rules run
  over that. Grants sit beside the administrative role, never in its ceiling;
  `acl/*` writes keep them (`routes::acl::commit_grant` re-reads them under the
  git-ns lock) and must never drop them. A grant is also bounded by the
  granter's entry (`resource_grant::granter_covers`, VTI-ACL-071). A non-member
  holding a grant (the bridge, an external signer) gets an entry of community
  role `application` — never a membership, never signs in, never an elevated
  right, not assignable by any caller — removed with its last grant. Removing
  an entry tombstones its grants (`git-departed:`) for the lifecycle to record;
  a departed granter's grants go to `acl.grants.review` (`gitGrants`) and are
  withdrawn at the deadline. The old `rights:*` rows are migrated at boot and
  on backup import (`git_ns::migrate`); unmappable ones are kept inert under
  `rights-unmapped:*` with an acknowledge item. The admin REST routes (`/v1/git-ns/*`) are read-only
  console projections; the administrator's view, namespace and repository
  listings and break-glass list are signed reads (`git-ns/view/0.5`,
  `git-ns/namespace/list`, `git-ns/repo/list` in `git_ns::admin_reads`),
  answered to a namespace's administrators only, never to a bearer session.
- **Invariants to preserve**: the fixed rules of `git-ns/right/grant` live in
  `git_ns::rules` and run before the `gitNamespace` policy, which can only
  refuse; rights are keyed by repository id, not name (a rename moves them, a
  new repository at the old name inherits nothing); the projection withdraws
  before it publishes, and publishes the implied `git.commit.sign` of every
  `own`, `maintain` and `ns.admin`; a grant's `reason` is never published or
  audited. Grant and revoke are served at 0.3 only (no 0.1/0.2), repo/create
  at 0.3: an implied `repo.create` (from `ns.admin`) carries no creator
  ownership. Elevated rights go only to, and only from, ACL-backed members.
  **Separation of duties** (grant 0.3 rule 7): no elevated self-grant
  through any task; the only way is `git-ns/right/break-glass` (`git_ns::break_glass`),
  which always takes an operation-bound passkey step-up, is audited at
  `AuditSeverity::Critical`, and is announced to every other administrator —
  policy may disable, delay or tighten it, never quieten it. An unratified
  break-glass record never counts toward the last-owner/last-admin invariants.
  In single-administrator mode, where nobody else could make the grant, rule 7
  is instead waived for that one operation (`git_ns::single_admin`, a
  `Waivable` token the rules accept for exactly that self-grant), and that
  record does count.
  Each unratified one is also an action-list `queue` item for the namespace's
  other administrators (`admin_actions::queues`): Ratify/Revoke call
  `right_ratify`/`right_revoke` as the decider, it never expires into
  acceptance, nobody cancels it, and it closes however the record ends.
  A member who is no console user answers that step-up with a **step-up
  passkey** (`step_up_passkey`, `auth/passkey/enroll/invite/0.2` `purpose:
  stepUp`), served only as Trust Tasks on the spine
  (`trust_tasks::step_up_passkey_tasks`). It is enrolled only through a
  community admin's single-use invite (signed, with a bound gesture) plus its
  claim code, redeemed by a `redeem/start` **signed by the invited member**
  (`cnm git enrol-step-up-passkey`); kept in its own keyspace login never
  reads; accepted only by `acl::bound_step_up` for its own current member; and
  never instead of a proof — every approve-response is signed by its subject
  (the console hands a no-key member an answer code for `cnm` to sign).
  A namespace admin gets no forge role: role projection (`bridge::highest_repo_rights`) counts only rights held in the person's own
  name, sends an admin with none as `git.ns.admin` (no role), one entry per
  account, and never a namespace-level `projectRoles` job. Jobs are
  `git-ns/bridge/job` 0.5 to a bridge that lists 0.5 in
  `trust-task-discovery`, else 0.4 (`bridge::send_versioned`); never
  downgrade, and `closePullRequest` (the pull-request gate,
  `git_ns::pr_gate`) is never sent to a bridge without 0.5.
- **Code**: `vtc-service/src/git_ns/` (`rules`, `ops`, `tasks`, `projection`,
  `bridge`, `lifecycle`), `vtc-service/src/routes/git_ns.rs`,
  `cnm-cli/src/git.rs`, `vtc-client/src/git_ns.rs`.
- **Docs**: `docs/03-vtc/git-namespaces.md`.

### VTC capability modules (`governance/capability/*`)
- **What**: A community's pluggable governance capabilities (`git-trust`
  first) — listed by its members, enabled and disabled by its administrators.
  Not ACL capabilities (`vtc.config.admin` …): keep the two apart in names,
  types and audit text (`capability_modules`, "capability module",
  `CapabilityModuleChanged`).
- **Invariants to preserve**: the VTC is the source of truth and the Trust
  Registry a projection — a decision is persisted (community keyspace) before
  the projector tells the registry, as its admin, over the registry client's
  TSP > DIDComm selection; the projector is the only retry owner, records an
  answer only against the generation it sent, treats `alreadyEnabled` /
  `notEnabled` as success, and surfaces a refusal as `failed` + an audit row
  while still retrying at the cap. `enable`/`disable` take `vtc.config.admin`
  and a step-up bound to the document (destructive class), never the action
  list (they confer no ACL authority). `list` answers members and admins only,
  as the generated `#response` that `trust-tasks-capability-client` parses.
  The git-trust manifest is a copy of the registry's, pinned by a test.
- **Code**: `vtc-service/src/capability_modules/`,
  `vtc-service/src/trust_tasks/capability_module_tasks.rs`,
  `vtc-service/src/registry/{client,messaging}.rs`
  (`project_capability_module`).
- **Docs**: `docs/03-vtc/trust-registry.md` (*Capability modules*),
  `../design-docs/vtc-capability-modules.md`.

## Runtime guards to preserve

These are load-bearing — know they exist before adjusting nearby code.

- **Never test `allowed_contexts.is_empty()`.** An empty context list on
  an ACL entry means *unrestricted* for `Role::Admin` and *authorized
  nowhere* for every other role, so any check that omits the role gets
  one of the two backwards. That has already produced a display calling
  a least-privilege approver "unrestricted" (#746), two `acl list
  --context` filters that disagreed (#770), and a vault scope gate that
  handed an authorized-nowhere entry cross-context credential reads
  (#769). Go through `AclEntry::act_scope()` / `AuthClaims::act_scope()`
  — or `has_context_access` / `can_act_in` / `is_super_admin`, which are
  built on them — and match on the `ActScope`. Same shape as the
  `ApproveScope` axis beside it in `vta-sdk/src/acl.rs`: act vs confer.
  See `docs/05-design-notes/acl-scope-semantics.md`. **The VTC no longer has
  contexts:** its administrative authority is capability-based (an
  administrative role as a ceiling, explicit `act`, capabilities with resource
  qualifiers — `docs/05-design-notes/vtc-admin-roles.md`), and every VTC gate
  asks `VtcAclEntry::can(capability, resource)`, never a session's claims.
- **Key custody: choosing a derivation path is holding a key.** Every key is
  a pure function of the seed and a path, so a gate that checks the caller's
  context but lets the caller name the path (or the key id) gates nothing.
  FTL-29904 found four holes of this kind: role-only seed rotation,
  caller-chosen paths in `keys/create`, `derive-and-sign` at any path, and
  vault signing with a caller-named key. Network-reachable code reaches key
  material **only** through `vta_service::operations::key_custody`
  (`derive_record_key`, `authorize_explicit_key_path`,
  `derive_delegated_identity`, `require_referenced_key_in_scope`,
  `require_instance_authority`). Seed operations are super-admin only, gated
  in the *operation* (not the transport) so REST, Trust Task and DIDComm share
  one audited refusal. `derive-and-sign*` is confined to `m/26'/9'`. Every
  refusal is audited and logged with `security_alert = true`.
  `tests/key_custody_census.rs` pins every raw `load_seed_bytes` /
  `from_seed` / `seed_store.get()` call site. Rules: `vta_keys::custody`
  module docs; rationale: `docs/05-design-notes/key-custody.md`.
- **Rate limit** on all unauth routes, per source IP
  (`vta-service/src/routes/rate_limit.rs`), in separate buckets: `auth`
  (auth/bootstrap/attestation, `[server] rate_limit_interval_secs` /
  `rate_limit_burst`, defaults 5 / 10), `did-log` (public `did.jsonl`,
  `did_log_rate_limit_*`, defaults 1 / 60), `backup-blob` (auth quota). Keep
  JWT-gated routes off the limiter — auth is the gate. **An interval is
  seconds per token, not a rate** — `(5, 10)` is 10 back-to-back requests
  then one every 5 s, so a *bigger* number is a *tighter* limit; zero clamps
  to 1. The four keys are runtime `config/patch` keys (`pnm config update
  --rate-limit-burst …`), read live on every request. Every VTA 429 carries
  `x-rate-limit-source: vta` — a client contract, don't rename it. Prose
  elsewhere — including `vtc-service`, which runs `tower-governor` — still
  says "5 rps"; that phrasing is wrong wherever it appears. See
  `docs/02-vta/rate-limiting.md`.
- **Request body cap**: 1 MB globally (`MAX_BODY_SIZE`). Matters in TEE
  where memory is tight.
- **Audience isolation** between VTA and VTC JWTs. Cross-audience tokens
  are rejected. Don't add a "shared" audience.
- **Mnemonic export window** (`MnemonicExportGuard`) — one-shot, timed,
  zeroized on drop. Don't cache the plaintext anywhere.
- **JWT key fingerprint** on TEE boot (`vta-tee/src/kms_bootstrap.rs`)
  detects KMS ciphertext tampering or key rotation. Do not widen the
  "first boot after upgrade" silent-store path.
- **Carve-out** (`BOOTSTRAP_CARVEOUT_CLOSED_KEY`) on `/bootstrap/request`
  is single-use. The whole check-then-mint-then-set sequence is gated
  by a process-wide async mutex (`MODE_B_LOCK`) — without it, two
  concurrent requests both pass the `is_some()` check and both mint
  admins. New TEE flows must not provide a back door.

## Versioning & publishing (workspace-specific)

**Never edit a `version = ` field in a feature PR.** Versions are assigned by
the Release PR that release-plz maintains; merging that PR is what publishes.
Merging a feature PR publishes nothing. See [`RELEASING.md`](RELEASING.md).

That includes when the `semver report (informational — never blocks)` check
goes **red on your PR** (it runs only on a PR labelled `semver-report`; the
Release PR's `release bump is large enough` job enforces the same check). It is doing its job: it compares the crate's public
API against the version on crates.io, so a PR that adds a struct member or
renames a `pub const` *should* turn it red. The red is the report, not a
defect, and the fix is not a version bump in your branch — release-plz reads
the same signal and puts the bump in the Release PR.

Worth stating because the failure mode is not "someone ignored the rule". It
is reading a red check as a thing to fix, bumping the crate, watching the
check go green, and concluding it was the right move — three PRs did exactly
that before anyone opened the Release PR and found the identical bumps already
proposed there. A manual bump is not merely redundant: it collides with the
Release PR and fragments one coordinated release into several.

**The other red that job produces means one of three different things.** It
builds rustdoc twice per crate — the workspace copy (`current`) and the
crates.io copy (`baseline`) — and a failure of either reads the same in
`cargo-semver-checks` output. The baseline resolves **without a lockfile**, so
it takes the newest semver-compatible release of every dependency, including
ones `Cargo.lock` pins below; that is what makes it the only check here that
sees what a consumer's fresh `cargo add` sees, and also what makes it catch
somebody else's bad release. `scripts/semver-build-failure.py` does the
attribution and names the culprit package — read what it says before assuming
a published artifact of ours is broken. #1667 was exactly that mistake:
`vta-service` 0.39.0 was fine, `affinidi-messaging-mediator` 0.28.33 was not,
and it reaches us only through `vta-service`'s optional `transport-harness`
feature, so the default-feature reproduction the report printed never touched
it. A dependency break of this shape is fixed upstream or by a raised floor,
never by a change here.

**20 of 26 crates publish.** The six that do not — `vtc-service`,
`vta-enclave`, `vta-mcp`, `vta-mobile-core`, `didcomm-test`, `vti-fuzz` — set
`publish = false` in their own manifest, each with a comment saying why.

The other 20 are `vta-sdk`, `vti-common`, `vti-secrets`, `vta-cli-common`,
`vtc-client`, `pnm-cli`, `cnm-cli` — plus `vta-service` and its closure
(`vta-audit`, `vta-backup`, `vta-config`, `vta-keys`, `vta-keyspaces`,
`vta-policy`, `vta-support`, `vta-sweepers`, `vta-tee`, `vta-vault`,
`vta-webvh`, `vti-webauthn`).

**`vta-service` is published for one reason and it is not its own API:**
`openvtc-core` dev-depends on it for `test_support::MockVta`, the in-process
VTA the OpenVTC end-to-end tests run against. That harness boots the real
service, so no client crate can stand in for it. #938 unpublished the crate on
the finding that no external consumer existed; the audit missed that
dev-dependency, and unpublishing did not merely freeze the crate — it **broke**
it. `vti-common` re-exports `vta_sdk::acl::{ActScope, ApproveScope,
ContextDirection}` as its own public API, so any graph combining `vti-common`
with another `vta-sdk` consumer must resolve **one** `vta-sdk`. A frozen
`vta-service` asking for `^0.21` beside a `vti-common` on `^0.23` gives two
nodes and `expected vti_common::acl::ApproveScope, found
vta_sdk::acl::ApproveScope`. Publishing keeps the requirements moving together.

That is also the rule in general: **a re-export makes the re-exported crate's
version part of your public API.** Before unpublishing anything, check for
dev-dependencies, not just normal ones.

Before adding a crate to the published set, check that everything it depends on
is published too — crates.io requires the whole closure, which is what puts the
twelve subsystem crates on the registry behind `vta-service`.

release-plz handles the dependent ripple: a breaking bump moves a crate's
compatibility range, so every dependent's `version = "0.y"` requirement is
updated in the same PR. Use `major.minor` version pinning (not
`major.minor.patch`) for internal dependencies. Exception: crypto deps
(`ed25519-dalek`, `hpke`, `jsonwebtoken`, `aes-gcm`, `aws-lc-rs`) should
pin to a minimum patch to avoid silent regressions when a CVE lands.
The legacy `rsa` crate was replaced with `aws-lc-rs` in 0.5 for KMS CMS
unwrap (drops RUSTSEC-2023-0071 exposure); don't reintroduce `rsa`.

## Commit hygiene

- Run `cargo fmt` before committing.
- All commits must be DCO-signed (`git commit -s`). `.github/dco.yml` exempts
  commits that are both authored by an org member and cryptographically signed
  — that exists for release-plz's release commit, which cannot carry a
  `Signed-off-by` trailer. Sign off anyway; don't rely on the exemption.
- Don't bypass hooks (`--no-verify`), don't skip signatures, don't amend
  published commits.

## Changelog: write a commit message, not a file

**A PR adds no changelog file and edits no version.** The changelog of every
published crate is generated from conventional commits by git-cliff when
release-plz builds the Release PR. A squash merge makes the PR title the commit
subject, so the title is the entry — CI lints it.

- **Title**: `<type>(<scope>): <subject>`, `!` for a breaking change. Types:
  `feat` `fix` `docs` `test` `ci` `build` `perf` `refactor` `chore` `security`.
- **A new enum variant or struct field in a published crate IS breaking** unless
  the type is `#[non_exhaustive]`, and it is the case people forget — release-plz
  reads the bump off the `!`, so an unmarked one ships as a patch that consumers
  take automatically. It has happened five times here (#1231, #1234, #1244,
  #1247, #1250). For a type designed to grow, `#[non_exhaustive]` beats
  remembering the marker. RELEASING.md has the full list.
- **Body**: included in the changelog verbatim. Write the explanation there.
- **Never** edit `version = ` in a `Cargo.toml`.

`changelog.d/` fragments, `check-changelogs.sh`, `collate-changelog.sh` and the
per-PR version bump were all removed in #938. Fragments existed so two PRs would
not conflict in `CHANGELOG.md`; generating from commits removes the shared file,
so there is nothing left to conflict over. `CHANGELOG.md` at the root is frozen
as the pre-#938 history — current entries live in each published crate's own
`CHANGELOG.md`.

## General

Before creating new crates or clients, search the workspace and crates.io to
check if the functionality already exists. Prefer existing SDKs over custom
implementations. Before writing any fix, analyze the root cause and explain
the diagnosis. Fix the cause, not the symptom — no workarounds.

## Running the tests: green and wrong

All of these cost a day in September 2026 — #1341 broke main in 68 places and
the fix went four rounds (#1348, #1350, #1355, #1359), because each round only
revealed the next failure.

**A per-crate run compiles a fraction of the tests.** `cargo test -p vta-sdk`
runs **306**; the workspace run runs **742**, because feature unification from
sibling crates compiles code the crate alone does not. Three of `vta-sdk`'s
integration binaries have **no tests at all** under default features. So "the
crate's suite is green" can be true and mean almost nothing — and it is the
natural thing to run while working on one crate.

**`cargo test` stops at the first failing target.** One reported failure was
hiding sixty-seven. Fix the first and the second appears; fix that and sixty
more do. Use `--no-fail-fast` before concluding anything about scope, and
before believing a fix is complete.

**Reproduce what CI runs, not what seems equivalent.** CI's workspace job is
`cargo nextest run --workspace --exclude vtc-service --exclude vtc-client`
plus `cargo test … --doc` — default features. Chasing the same failure under `--all-features` finds real but
unrelated breakage (a stack overflow in `mock_vta`, nine failures elsewhere)
that CI never sees, and none of it is the thing that is red.

**A warning is an error, and only in CI.** `cargo clippy` prints warnings and
exits 0; the CI job is `-- -D warnings`, so the same output is a failure there.
`--all-targets` is part of it too — without it clippy sees only the lib and
bin targets, and dead code in `tests/` accumulates unseen. `vta-service` gets
two further clippy runs under reduced feature sets, which catch what the
default build cannot: a `#[cfg]` arm nothing else compiles.

So, before pushing a change that could touch another crate's tests, run what CI
runs:

```sh
cargo nextest run --workspace --exclude vtc-service --exclude vtc-client
cargo test --workspace --exclude vtc-service --exclude vtc-client --doc
cargo nextest run -p vtc-service -p vtc-client   # a separate CI job
cargo test -p vtc-service -p vtc-client --doc
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

**Tests run under nextest; doctests do not.** `cargo install cargo-nextest`
(or the prebuilt binary from <https://nexte.st>). `.config/nextest.toml` sets
`fail-fast = false` — the `--no-fail-fast` rule above, by default — and kills
a test after 5 minutes, so a hang ends with its name. nextest runs each test
in its own process, all binaries in one pool: `cargo test` runs one binary at
a time, and vtc-service's tests serialise on process-global locks, which kept
its two big binaries under one core. nextest never runs doctests, so the
`--doc` lines are not optional. `cargo test` still works and still means the
same thing; it is only slower.

**Dependencies build at `opt-level = 2`** (`[profile.dev.package."*"]`;
workspace crates stay at 0, so an edit-test loop recompiles nothing extra).
At 0 the suites spent their CPU in other people's code — regorus re-parsing
the default policy bundle for every vtc-service test, Argon2id at 64 MiB in
vta-backup (89s of one CI run). The first build after a `Cargo.lock` change
pays for the optimisation once.

**On macOS the test fixtures used to queue on the disk.** Measured on an
18-core Mac (load average 3–7 from other builds; treat as indicative):
`cargo test -p vtc-service --lib` 1085s / 1111s at opt-level 0, 984s at 2,
893s under nextest; the `it` binary 1434s / 2689s. Linux CI runs the same lib
binary in ~141s. A sampled test spent 2.9s wall for 0.5s of CPU, nearly all
of it in `fcntl(F_FULLFSYNC)` — `lsm_tree`'s `fsync_directory` while
`build_test_vtc` created its ~45 fjall keyspaces. `File::sync_all` is
`F_FULLFSYNC` on macOS, a whole-device cache flush, so parallel test
processes queued on the disk rather than the CPU. fjall has no setting that
skips those fsyncs (keyspace creation is durable unconditionally), so the
fixtures (`TestVtc`, and `vta_service::test_support`'s `open_test_store`,
`build_signing_test_app_state*` and `build_test_app_with`) now copy a
pre-built template database instead of creating keyspaces —
`vti_common::store::test_fixture`, published once under
`$TMPDIR/vti-store-templates/`. `ceremony::`, `backup::tests` and `acl::`
(157 tests) went 16.3s → 3.6s on the real disk; running with `TMPDIR` on a
RAM disk is no longer needed for tests built on those fixtures. Unit tests
that call `Store::open` themselves still create their keyspaces the slow way;
a new multi-keyspace fixture should use `open_with_keyspaces`.

## A merge is not evidence that anything passed

The only **required** status check on `main` is `DCO`. Every job above — the
build, both test jobs, clippy, fmt, MSRV, `cargo-deny` — is advisory, so a
pull request merges on a red suite exactly as readily as on a green one, and
no prompt appears.

This is not hypothetical and it is why the section above exists. On 9 September
2026 `main` was red for five and a half hours across six consecutive merges —
#1341, then #1344, #1346, #1348, #1350 and #1355 — each landing on an already
failing main, until #1359 returned it to green. The account of it that first
reached this file said "#1341 merged green", which is the natural reading and
is false: nothing was checking.

Two things follow, and both are habits rather than rules:

- **Do not read a merge as evidence its suite passed.** Read the run. And read
  the run's own jobs (`gh api repos/.../actions/runs/<id>/jobs`) rather than the
  aggregate rollup, which reports staleness as success across a re-run.
- **Do not assume a red main is your regression.** Check when it went red
  first. It may have been red since before you branched, and the failure you
  are looking at may be somebody else's — or your own, four merges ago.

Whether the CI workflow should be a required check is a repository-settings
decision that has not been taken. Until it is, the discipline above is what
stands in for one.

## Cross-service networking & integration discipline

This workspace is the center of a multi-repo mesh (mediator, webvh host, push
gateway, trust registry, cierge, browser/JS clients). Before changing any code
that talks to another service — or any wire type — read the ecosystem doc set
in `../design-docs/` (sibling directory of this repo):

- **`vti-stack-development-guide.md`** — the binding best-practices rules
  (R-numbers below refer to it). Load it first; paste its pre-merge checklist
  into PRs that touch cross-service code.
- **`vti-networking-remediation-plan.md`** — the confirmed-defect backlog
  (deliverables **D1–D5 and D9** touch this repo).
- **`vti-architectural-direction.md`** — the seven strategic decisions;
  justify design-level choices against it.

Rules that bite hardest in this workspace, with their known hotspots:

- **R1.1 — a DIDComm send `Ok` means "accepted locally", not delivered.** The
  messaging SDK silently drops frames during websocket reconnects. Never log
  "delivered/sent" off a bare `Ok` (`didcomm_bridge.rs` send_oneway,
  vtc-service `send_to_member`); delivery-critical messages need an ack or an
  outbox record.
- **R1.2 / R1.3 — no `reqwest::Client::new()`, no lock across an await.**
  Known offenders being remediated: vta-sdk REST transports, the vault status-list fetch
  (which must use the foreign-fetch profile — copy
  `vtc-service/src/recognition/verify.rs`).
- **Retry has exactly one owner per failure domain.** The messaging delivery
  layer owns message delivery; `VtaClient::idempotent` owns operation
  completion. Application code owns neither — never wrap a `VtaClient` call in
  your own retry loop, because a hand-rolled loop cannot hold an idempotency key
  stable across attempts and so converts "one operation, retried" into "two
  operations". Every new Trust Task must be classified in
  `vta_sdk::retry_safety` (a census test enforces it). See
  `docs/05-design-notes/retry-and-idempotency.md`.
- **R2.1 — Remote-First.** No local commit before the remote effect is durable
  (or make the flow resumable with an idempotency key). Confirmed violations
  live in provision-integration resume, `rotate_key`'s swap-then-persist
  ordering, and step-up's consume-before-verify. Ask "process dies on the next
  line — then what?" for every mutation.
- **R3.1–R3.3 / R5.1 — wire types are camelCase, security-relevant bodies
  `deny_unknown_fields`, every Trust Task URI gets a schema_index entry.** The
  recurring casing-drift class (#656/#658, `CreateAclBody`) is how an empty
  `allowed_contexts` silently minted a super-admin. Absence in any
  scope/config field means the most restrictive interpretation.
- **R6.2 — no latched status.** `didcomm_websocket_status` reporting
  "connected" forever after boot is the canonical counterexample; any health
  flag must be driven by a signal that can go false again.

Note: the `vti-*` sibling directories under `~/devel` are clones of this repo
on feature branches — this guidance reaches them when merged to `main`; until
then, agents working in those clones should read this section from the
canonical checkout or the design-docs directly.
