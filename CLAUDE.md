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

`vta-service` has been **decomposed into subsystem crates** (#780–#791). Each subsystem is re-exported from `vta-service`, so
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
  vti-vetting-pcs → vta-sdk   (hidden vetting: community + member engines)
  vti-voting      → vti-vetting-pcs   (community voting: tickets, casts, ballot box)
  vti-voting-service → vti-voting, vti-common, vta-sdk   (the voting host service)
  vta-audit       → vta-sdk, vti-common

Layer 2 (VTA subsystems):
  vta-support     → vta-config, vta-keyspaces, vta-sdk, vti-common
  vta-keys        → vta-config, vta-keyspaces, vta-sdk, vti-common, vti-secrets
  vta-vault       → vta-keyspaces, vta-sdk, vti-common
  vta-external    → vta-keys, vta-keyspaces, vta-sdk, vti-common
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
  vti-witness     → vti-common, vti-secrets, vta-sdk   (host service)
```

| Crate | Role |
|---|---|
| `vti-common` | Shared foundation: `host_session` (a host service identity's mediator session), JWT auth, ACL, `Store` (local fjall + vsock), `AppError`, config types, identifier validation, `secure_file`, telemetry sink, `SeedStore`, `guards` |
| `vta-sdk` | Public SDK: types, REST + DIDComm client, `sealed_transfer`, `did_templates`, `provision_integration`, attestation verification, `protocol` (DIDComm protocol-management types) |
| `vti-secrets` | Shared secret-store backends (AWS / GCP / Azure / Vault / Kubernetes / keyring / config-seed / TEE-KMS / plaintext) + the `create_seed_store(&secrets, &data_dir)` factory + `SecretsConfig`, all behind the same feature flags, shared by the VTA (`vta-keys::seed_store`) and the VTC (its own factory, `vtc-service::keys::seed_store`). Feature `onboarding`: `IntegrationOnboarding`, the ephemeral-`did:key` → ACL-grant → auto-rotate cold-start helper for external integrations |
| `vta-keyspaces` | Keyspace-name registry — the `const` names every `store.keyspace(..)` call uses, plus the backup partition (`ALL` / `BACKED_UP` / `EXCLUDED_FROM_BACKUP`, pinned by a census test). Dependency-free leaf |
| `vta-config` | `AppConfig` TOML shape + sub-configs (`PolicyConfig`; under `tee`, `TeeConfig` / `TeeKmsConfig` / `TeeMode`), composed over `vti-common`'s shared config types |
| `vta-audit` | Structured audit logging for security-relevant operations, so any subsystem can emit audit events without depending on the whole service. `AuditLogEntry.detail` carries the operator `reason` |
| `vta-support` | Shared mid-layer services — trust-context storage (the BIP-32 key-hierarchy roots) and the other clean glue subsystems need |
| `vta-keys` | **Key management**: master-seed storage, BIP-32 hierarchical derivation, key wrapping (AES-GCM), imported-key handling, `create_seed_store` backend selection, `derive_pre_rotation_keys` |
| `vta-vault` | **Holder credential vault**: storage, query, receive/verify, present, status refresh, and the archival lifecycle (`VaultStatus {Active,Archived,Deleted}`) |
| `vti-vetting-pcs` | **Hidden vetting** on the Predicate Credential System: the community's `issuer` and `verifier` (`vtc-service`, feature `vetting-pcs`) and the member-side `vetter` / `applicant` engines the VTA runs as its principal's PCS engine (`vta/pcs/*`). Feature `harness`: an in-process community (`vtc::Vtc`) for end-to-end tests. Docs: `docs/02-vta/pcs-engine.md` |
| `vti-voting` | **Community voting** (VTI-VOT-001 – 100): registrar, voter, ballot box, board, tally, audit, trustees. Unaudited protocol code over audited group operations (detail: `vti-voting/CLAUDE.md`) |
| `vti-voting-service` | **The voting service** (`publish = false`): a host service holding ballot boxes for any number of communities, never a roster; TSP > DIDComm, HTTPS only as the sessionless cast door (VTI-VOT-004) (detail: `vti-voting-service/CLAUDE.md`) |
| `vta-external` | **External accounts** (`external/*`): identities the VTA holds at clouds and third-party services, issuing short-lived downscoped credentials. Design: `docs/05-design-notes/vta-external-accounts.md` |
| `vta-webvh` | WebVH hosting infrastructure for the `did:webvh` lifecycle and its other consumers |
| `vta-policy` | Policy subsystem: the regorus (Rego) engine + default bundle, the DTTE consent model, decision evaluators, policy storage |
| `vta-tee` | TEE bootstrap: attestation providers (Nitro / SEV-SNP / simulated), KMS attest/decrypt, storage-key derivation, CMS unwrap, the DynamoDB anti-rollback anchor MAC, Mode-B admin bootstrap + carve-out, the mnemonic-export guard. Behind the `tee` feature — keeps the AWS SDK stack out of the default build graph |
| `vta-backup` | Encrypted full-state export and staged, boot-applied restore, portable between plain / hardened / TEE VTAs. Transfer plumbing is node-neutral in `vti_common::backup_transfer`; seed adoption is injected via `RestoreCommitter` |
| `vta-sweepers` | Background TTL sweepers for the core keyspaces (acl / consent / vault) |
| `vta-service` | The VTA **spine** (library) + local/dev binary: `routes/`, `trust_tasks/` (dispatch spine), `messaging/*` (DIDComm + TSP bridge), `operations/` (orchestration), `setup/` (wizards), offline CLI surfaces. Re-exports every subsystem crate above (detail: `vta-service/CLAUDE.md`) |
| `vta-enclave` | Nitro Enclave front-end. Depends on `vta-service` as a library, adds TEE bootstrap (KMS, vsock-store, attestation). `publish = false` |
| `vtc-service` | Verifiable Trust Community service (community lifecycle, separate JWT audience) |
| `vta-cli-common` | Shared CLI command implementations — both CLIs are thin wrappers |
| `pnm-cli` | Personal Network Manager (single-VTA operator) |
| `cnm-cli` | Community Network Manager (multi-community operator) |
| `vta-mcp` | MCP server bridging a VTA's agent capabilities to MCP tools over stdio, with a local per-operation guard (`guard.rs`) because a host approves a tool, not a call. `publish = false` (detail: `vta-mcp/CLAUDE.md`) |
| `vti-witness` | **Witness host service** (`publish = false`): up to 10 `did:webvh` witness identities from the `dtg-witness` template, one mediator session each (detail: `vti-witness/CLAUDE.md`) |
| `didcomm-test` | Standalone DIDComm connectivity harness (test tool, `publish = false`) |

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

Other curves are accepted where **a party outside this workspace holds the
key** (#1988), and only through `vta_sdk::jws` — the algorithm fixed by the
resolved key, never by the token — with a P-256 / secp256k1 key named by its
own `did:key` (`zDn…` / `zQ3s…`):

- **Credentials others issue**: an SD-JWT-VC issuer or `cnf.jwk` holder may
  sign EdDSA, ES256 (P-256) or ES256K (secp256k1), so swiyu / EUDI credentials
  verify. An EUDI issuer that is not a DID names its key by an `x5c` chain,
  trusted only through operator-configured anchors
  (`vta_sdk::x509_issuer`, `[oid4vp] x509_trust_anchors`) — never by the chain
  alone.
- **Members' own signatures**: a member's Trust Task proof may be
  `ecdsa-jcs-2019` (P-256; the framework's SHOULD-verify suite for
  hardware-backed signers — there is no secp256k1 Data Integrity suite), and
  the hex holder signatures (member rotation, join's REST binding) and the
  OID4VCI key-binding proof may be any of the three.

What the workspace mints stays Ed25519 / X25519, with two exceptions:

- A **foreign-protocol identity** — an identity whose wire another protocol
  fixes, such as a swiyu or EUDI OpenID4VP verifier (`swiyu-verifier`
  template), whose request objects those wallets accept only as ES256 — may hold
  P-256 (or secp256k1) keys. Such a key is published only in that identity's own
  DID (or, for an EUDI verifier, which has no DID, certified only in its own
  X.509 access certificate), never on a community's or the VTA's own.
- A **holder key a foreign credential binds to** — the P-256 `cnf.jwk` of an
  SD-JWT-VC as swiyu and EUDI issue them, or an ISO mdoc's device key — may be
  P-256 (#1988). Its holder is that key's own `did:key` (`zDn…`). It signs only
  what holding that credential needs: the ES256 `kb-jwt`, an mdoc `DeviceAuth`,
  and the `ecdsa-jcs-2019` consent receipt and presentation proof
  (`vta_vault::consent::holder_suite` fixes the suite by the key, never by the
  caller).

In both cases the VTA still mints and custodies the key, from the seed like any
other key. Every key `sealed_transfer` seals **to** stays X25519 (from an
Ed25519 `did:key`).

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

Why: TSP gives metadata-private routing at bounded message size; TSP and
DIDComm authcrypt both give **intrinsic sender authentication** (no hand-rolled
signature checks, `did:webvh` peers work unchanged). DIDComm stays first-class
until its phased deprecation (design note). Add REST/HTTPS only for parties that
speak neither, and treat its did-signed auth as last resort; carry an explicit
protocol tag where a DID-vs-URL shape used to disambiguate (`WakeHandle.gateway`).

**Exceptions to "every remote operation is a Trust Task"** are foreign-protocol
interfaces only — OAuth / WebAuthn ceremonies and DID resolution files — and a
REST route kept for one is declared, not assumed (e.g. the WebAuthn passkey-VM
enrolment routes; DID-holding clients use the `vta/passkey-vms/*` twins). The
declaration is a row in `vta_service::deprecation::REST_EXCEPTIONS`, pinned
to a live route by `every_rest_exception_names_a_live_route`.

## Use DID templates, don't hand-roll DID shapes

The workspace has a **DID templates feature** (`docs/02-vta/did-templates.md`,
`vta-sdk/src/did_templates`, `vta-service/src/routes/did_templates.rs`). A
template is a JSON file describing the **shape** of a DID document with
`{TOKEN}` placeholders; the VTA renders them server-side, filling in keys it
just minted + caller-supplied variables. Built-ins ship with the SDK
(`vta_sdk::did_templates::BUILTIN_NAMES`); operators can upload more. The
`did-host-*` names describe the DID-document shape (`http` = WebVHHosting,
`didcomm` = DIDCommMessaging, `tsp` = TSPTransport), not the service. The old
`webvh-*` and `did-hosting-*` template names **no longer resolve**.

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

The noun for "a thing a template provisions" is **integration** (not
"agent", which collides with VTA = Verifiable Trust *Agent*); each template
declares its integration kind in `kind`.

## Authorization claims between VTA and integrations use VC/VP format

When the VTA attests authorization to a holder (e.g., at bootstrap — "this
DID is admin of context X at this VTA"), the attestation is a **W3C
Verifiable Credential**, not a bespoke signed JSON struct. When a holder
presents something to the VTA signed with their DID (e.g., a bootstrap
request), the envelope is a **W3C Verifiable Presentation**.

Proof handling goes through `affinidi-vc` / `affinidi-data-integrity`. These
VCs are **bootstrap-transport only**: short-lived (1h default), no
`credentialStatus`, verified once at bundle open, then archived. The ACL is the
authority in steady state; revocation is ACL removal.

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
  exists only as an explicit opt-out with a warning. (`pnm bootstrap connect`
  is not a sealed transfer since #2066 — no bundle, no digest; its anchor is
  `--expect-pcr0`. See *TEE Mode B bootstrap* in `vta-service/CLAUDE.md`.)
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

Each flow's detail — what it does, the invariants to preserve, code and
docs — lives in the CLAUDE.md of the crate that owns it. **Read that entry
before changing the flow.** When adding a flow, add its entry there and a
line here.

- **`vta-service/CLAUDE.md`**: VTA first-boot setup; Mediator connection; Admin credential cold-start; Deferred VTA-DID setup; TEE Mode B bootstrap; DIDComm challenge-response auth; Context + context-admin bootstrap; Provision-integration; Runtime service management; Sealed-transfer envelope format; Signing oracle; Approvals + task consent; External accounts; Room revocation; Hidden-vetting PCS engine; Witnessed party; Vault archival lifecycle; Backup / restore; Promote a serverless DID to a server-managed one; Provision a DID into a specific hosting domain; DID template management; A room's own profile; Room records: provenance, retention and prune, the epoch floor.
- **`vtc-service/CLAUDE.md`**: first-boot setup; community-owned rooms; room file migration; member directory; community groups; administrator action list; member portal; direct admission; trusted witnesses; step-up: passkeys and approver devices; role-based administration; admin console live channel; git namespaces; capability modules; community elections.
- **`vti-witness/CLAUDE.md`**: Witness host service.

## Runtime guards to preserve

These are load-bearing — know they exist before adjusting nearby code.

- **Never test `allowed_contexts.is_empty()`.** An empty context list on
  an ACL entry means *unrestricted* for `Role::Admin` and *authorized
  nowhere* for every other role, so any check that omits the role gets
  one of the two backwards (#746, #769, #770). Go through `AclEntry::act_scope()` / `AuthClaims::act_scope()`
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
  context but lets the caller name the path (or the key id) gates nothing
  (FTL-29904). Network-reachable code reaches key
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
- **Rate limit** on all unauth routes, per source IP, in separate buckets
  (`vta-service/src/routes/rate_limit.rs`, `docs/02-vta/rate-limiting.md`);
  keep JWT-gated routes off the limiter — auth is the gate. **An interval is
  seconds per token, not a rate**: a *bigger* number is a *tighter* limit, and
  "5 rps" wherever it appears is wrong. Every VTA 429 carries
  `x-rate-limit-source: vta` — a client contract, don't rename it.
- **Operation budgets** (VTI-TRN-029, `trust_tasks::operation_budget`): Trust
  Task work is bounded per appliance, per client DID and, separately, for
  DIDComm / TSP senders without standing — the last two always on, at a
  default when unset, because the requirement is a MUST: never add a setting
  that turns them off. Charged after authentication and before the task
  runs, on every transport (the passkey-VM REST routes are not Trust Tasks
  and are not charged). Never charge a caller before it is proven, and never charge a sender without standing to the clients'
  budget: either lets a stranger spend what clients need. A refusal leaves the
  document unrecorded, so a resend is a retry. The keys are config + tenant
  overlay only, never `config/patch` (a TEE restart would drop the patch).
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
  is single-use. The whole check-then-enrol-then-set sequence is gated
  by a process-wide async mutex (`MODE_B_LOCK`) — without it, two
  concurrent requests both pass the `is_some()` check and both enrol
  admins. New TEE flows must not provide a back door.

## Branches: where a PR goes

The release cycle and branch model are in [`RELEASES.md`](RELEASES.md); crate
publishing is in [`RELEASING.md`](RELEASING.md). What an agent opening a PR
needs:

| Branch | Open a PR against it? |
|---|---|
| `main` | **Yes — the default for everything**: features, fixes, docs, refactors. Branch from `origin/main` (`feat/…`, `fix/…`, `docs/…`). |
| `nightly` | **Never.** A bot fast-forwards it to the last fully green `main` commit. |
| `release/<name>` (Eucalyptus, Fig, …) | **Not directly, as a rule.** A fix lands on `main` first; then label the merged PR `backport release/<name>` and `backport.yml` opens the cherry-pick PR. Open one by hand only when the code no longer exists on `main` — base it on `origin/release/<name>` and say why in the description. |
| `release-plz-*`, `release-prep/*`, `release-cut/*` | **Never** — bots and release scripts open these. |

Rules for anything that does land on a release branch:

- **Fixes, security changes and docs only.** No features. No breaking change
  to a published crate — `prepare-release-branch.py` refuses one
  (`cargo semver-checks --release-type patch`); rework the fix to keep the API.
- **Never edit `version =` or `RELEASE`** — only the *Prepare a named release*
  workflow does, same as the Release PR on `main`.
- **Never edit `releases/*.toml`** — `cut-release.py` writes it. Each one gives
  a release branch the compatibility line of every crate it was cut with, and
  `check-release-line-ownership.py` keeps `main` out of those lines.
- CI is a **required** check on `release/**`, unlike `main`.
- The `branch rules` check (`scripts/check-branch-rules.py`) enforces the table
  above and the version rule, on every PR into `main` or `release/**`. If it
  fails, it names the fix — read it rather than working around it.
- Which supported release a fix should go to is a maintainer's call (support
  status is in the `RELEASES.md` table); if the task doesn't say, ask rather
  than labelling every branch.

## Versioning & publishing (workspace-specific)

Long form, with the incidents behind each rule:
[`docs/04-reference/workspace-engineering-notes.md`](docs/04-reference/workspace-engineering-notes.md).
Mechanics: [`RELEASING.md`](RELEASING.md).

- **Never edit a `version = ` field in a feature PR.** release-plz assigns
  versions in the Release PR; merging that publishes. A red `semver report` on
  your PR is the report doing its job, not something to fix with a bump — a
  manual bump collides with the Release PR.
- A semver-job **build** failure may be someone else's bad release: the
  baseline resolves without a lockfile. Read what
  `scripts/semver-build-failure.py` attributes it to before blaming our crate
  (#1667).
- **27 of 37 crates publish**; the ten that do not set `publish = false` with a
  comment saying why. `vtc-service` publishes as a binary with pre-built web
  bundles — a new `include_dir!` / `include_str!` outside tests must sit inside
  its `include` list. `vta-service` publishes because `openvtc-core`
  dev-depends on it (`MockVta`); a re-export makes the re-exported crate's
  version part of your API, so check dev-dependencies before unpublishing
  anything, and check a new published crate's whole closure is published.
- Internal deps pin `major.minor`; crypto deps (`ed25519-dalek`, `hpke`,
  `jsonwebtoken`, `aes-gcm`, `aws-lc-rs`) pin a minimum patch. Don't
  reintroduce `rsa`.

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

`changelog.d/` fragments were removed in #938; the root `CHANGELOG.md` is frozen
pre-#938 history, and current entries live in each published crate's own.

## General

Before creating new crates or clients, search the workspace and crates.io to
check if the functionality already exists. Prefer existing SDKs over custom
implementations. Before writing any fix, analyze the root cause and explain
the diagnosis. Fix the cause, not the symptom — no workarounds.

## Running the tests: green and wrong

Why each of these rules exists (#1341's four-round fix, the macOS fsync
fixtures, CI caching):
[`docs/04-reference/workspace-engineering-notes.md`](docs/04-reference/workspace-engineering-notes.md).

- **A per-crate run compiles a fraction of the tests** (feature unification):
  `-p vta-sdk` runs 306, the workspace 742. Don't conclude from `-p`.
- **`cargo test` stops at the first failing target** — use `--no-fail-fast`
  (nextest does by default) before judging scope or believing a fix complete.
- **Reproduce what CI runs** — default features, not `--all-features`.
- **Clippy warnings are errors in CI** (`-D warnings`, `--all-targets`).
- **nextest never runs doctests**, so the `--doc` lines are not optional.

Before pushing a change that could touch another crate's tests:

```sh
cargo nextest run --workspace --exclude vtc-service --exclude vtc-client
cargo test --workspace --exclude vtc-service --exclude vtc-client --doc
cargo nextest run -p vtc-service -p vtc-client   # a separate CI job
cargo test -p vtc-service -p vtc-client --doc
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

A new multi-keyspace test fixture should copy a template database
(`vti_common::store::test_fixture`, `open_with_keyspaces`) rather than create
keyspaces — on macOS creation is `F_FULLFSYNC`-bound. Keep every local path
crate a workspace member (the CI cache treats non-members as dependencies).

## A merge is not evidence that anything passed

The only **required** check on `main` is `DCO`; every CI job is advisory, so a
PR merges on a red suite as readily as a green one. Read the run's own jobs
(`gh api repos/.../actions/runs/<id>/jobs`), not the rollup. And don't assume
a red `main` is your regression — check when it went red first.

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

The `vti-*` sibling directories under `~/devel` are feature-branch clones of
this repo; there, read this section from the canonical checkout.
