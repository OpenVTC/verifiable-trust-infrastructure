# Verifiable Trust Infrastructure — Documentation

A guided tour of the workspace: what the VTA and VTC are, how to
operate each one, how to integrate with them, and where the design
decisions live.

## How this tree is organised

```mermaid
graph LR
    concepts["01-concepts/<br/>(shared)"]
    vta["02-vta/<br/>(VTA operator + integrator)"]
    vtc["03-vtc/<br/>(VTC operator + integrator)"]
    ref["04-reference/<br/>(tables, paths, formats)"]
    design["05-design-notes/<br/>(history + implementation)"]

    concepts --> vta
    concepts --> vtc
    vta -.-> vtc
    vta --> ref
    vtc --> ref
    concepts -.-> design

    classDef shared fill:#f5f5f5,stroke:#555,color:#111
    classDef vta fill:#d4e6f9,stroke:#3a6fb0,color:#08305f
    classDef vtc fill:#e9d7f7,stroke:#7e3fa6,color:#3a0a5a
    classDef ref fill:#e8f5e9,stroke:#3e8e41,color:#1b3a1f
    classDef design fill:#fff3e0,stroke:#c77a00,color:#5a3b00
    class concepts shared
    class vta vta
    class vtc vtc
    class ref ref
    class design design
```

The dotted line from `02-vta/` to `03-vtc/` reflects the runtime
relationship: a VTC is always provisioned **on top of** an existing
VTA via the `vtc-host` DID template.

## If you're trying to…

| Task | Start here |
|---|---|
| Understand VTI as a whole | [Overview](01-concepts/overview.md) |
| Decide between VTA and VTC | [Root README — Which service do you need?](../README.md#which-service-do-you-need) |
| Stand up a VTA from scratch | [VTA cold-start](02-vta/cold-start.md) |
| Stand up a VTC on an existing VTA | [VTC getting started](03-vtc/getting-started.md) |
| Add at-rest encryption to a self-hosted (non-TEE) VTA | [Hardened configuration](02-vta/non-interactive-setup.md#hardened-configuration) |
| Pick where to store the master seed | [VTA secret backends](02-vta/secret-backends.md) |
| Deploy a VTA inside a Nitro Enclave | [TEE architecture](02-vta/tee-architecture.md) |
| Build an app that uses a VTA | [VTA integration guide](02-vta/integration-guide.md) |
| Use a VTA from Claude Code / Claude Desktop | [vta-mcp](02-vta/vta-mcp.md) |
| Provision a mediator / webvh-host / custom integration | [Provision-integration](02-vta/provision-integration.md) |
| Require a second person to approve an operation | [Approvals](02-vta/approvals.md) |
| Understand the consent ceremony (DTTE) end to end | [Task consent](02-vta/task-consent.md) |
| Configure community membership policy | [VTC community lifecycle](03-vtc/community-lifecycle.md) |
| Host a public community website | [VTC website + admin UX](03-vtc/website-and-admin.md) |
| Deploy a trust registry and wire a VTC to it | [Trust-registry deployment](03-vtc/trust-registry-deployment.md) |
| Look up a BIP-32 path | [BIP-32 paths](04-reference/bip32-paths.md) |
| Read the threat model | [Security model](01-concepts/security-model.md) |

## Table of contents

### Part I — Concepts (shared)

Both VTA and VTC build on the same foundation. Read this first.

- **[Overview](01-concepts/overview.md)** — what VTI is, what VTA
  and VTC each do, how they relate, the technology stack, request
  flow.
- **[Architecture](01-concepts/architecture.md)** — workspace
  layout, crate map, shared module structure, API surface, how to
  add a new front-end binary.
- **[Security model](01-concepts/security-model.md)** —
  defense-in-depth, key lifecycle, threat model, attack trees,
  cryptographic inventory, deployment checklist.

### Part II — VTA

How to operate, deploy, and integrate against a VTA.

- **[Cold-start](02-vta/cold-start.md)** — bootstrap a VTA + WebVH
  + mediator from scratch.
- **[Non-interactive setup](02-vta/non-interactive-setup.md)** —
  scripted VTA provisioning via `vta setup --from <file>` for CI,
  sealed images, unattended bootstrap.
- **[Hardened configuration](02-vta/non-interactive-setup.md#hardened-configuration)** —
  enable storage encryption and sealed JWT key management for
  self-hosted (non-TEE) deployments (`[hardened] enabled = true`).
- **[Seal and unseal](02-vta/seal-and-unseal.md)** — what the
  seal is, when it's set, how `vta unseal` works.
- **[Secret-storage backends](02-vta/secret-backends.md)** — AWS,
  GCP, Azure, HashiCorp Vault, OS keyring, KMS-TEE.
- **[Feature flags](02-vta/feature-flags.md)** — Cargo feature
  reference, deployment profiles, dependency graph.
- **[TEE architecture](02-vta/tee-architecture.md)** — Nitro
  Enclave deployment, KMS bootstrap, vsock store, attestation chain.
- **[Integration guide](02-vta/integration-guide.md)** —
  building a third-party app that consumes VTA-managed keys.
- **[DIDComm protocol](02-vta/didcomm-protocol.md)** — message
  types, schemas, authorization, wire shapes.
- **[DID templates](02-vta/did-templates.md)** — authoring,
  uploading, resolution (context → global → built-in).
- **[Provision-integration](02-vta/provision-integration.md)** —
  the canonical flow for standing up mediators, webvh hosts, and
  apps via DID templates and sealed-transfer.
- **[Runtime service management](02-vta/runtime-service-management.md)** —
  enable / disable / migrate REST + DIDComm services on a running
  VTA without rebuilds.
- **[Approvals](02-vta/approvals.md)** — which tasks require
  re-authentication or human consent before they run, managed at
  runtime with `pnm approvals`.
- **[Task consent (DTTE)](02-vta/task-consent.md)** — the approval
  ceremony behind a `consent` rule: the wire, the timers, who may
  approve, and what the approver sees. Companion infographic:
  [task-consent-infographic.html](02-vta/task-consent-infographic.html).
- **[DID:WebVH update](02-vta/did-webvh-update.md)** — log-entry
  format, rotation, hosting.
- **[Personal AI agents](02-vta/personal-ai-agents.md)** — provisioning
  an agent its own identity, context, capabilities and kill switch.
- **[vta-mcp](02-vta/vta-mcp.md)** — using a VTA from an MCP host
  (Claude Code, Claude Desktop, an agent framework): what it exposes,
  the security model, hardening flags, and how to see what it is doing.
- **[Setup example](02-vta/examples/vta-setup.example.toml)** —
  worked TOML for `vta setup --from`.
- **[Example: agent memory + vta-mcp](02-vta/examples/agent-memory-with-vta-mcp.md)** —
  two MCP servers, two identities, two contexts, one VTA.

### Part III — VTC

How to operate and integrate against a VTC.

- **[Getting started](03-vtc/getting-started.md)** — a working VTC
  in 10 minutes (assumes an already-running VTA).
- **[Architecture](03-vtc/architecture.md)** — VTC module layout,
  keyspaces, dependency on the VTA.
- **[Community lifecycle](03-vtc/community-lifecycle.md)** —
  member CRUD, join requests, removal dispositions, policies.
- **[Credentials](03-vtc/credentials.md)** — VMC, VEC, status
  lists, renewal, DID rotation, custom endorsements.
- **[Trust-registry integration](03-vtc/trust-registry.md)** —
  registry publish, membership sync, cross-community recognition.
- **[Trust-registry deployment](03-vtc/trust-registry-deployment.md)** —
  runbook for standing up a registry, sourcing its identity from a
  VTA, and wiring a VTC to it.
- **[Personhood + relationships](03-vtc/personhood-and-graph.md)** —
  personhood assertion, VRC trust graph, custom endorsements.
- **[Website + admin UX](03-vtc/website-and-admin.md)** — public
  community website (live + managed modes), embedded admin SPA,
  routing modes.
- **[Admin UX plugins](03-vtc/admin-ui-plugins.md)** — third-party
  plugin contract: on-disk layout, manifest schema, scope filters,
  and the daemon's `admin_ui.plugin_dir` scan + serve.
- **[Feature flags](03-vtc/feature-flags.md)** — VTC Cargo feature
  reference.

### Part IV — Reference

- **[BIP-32 paths](04-reference/bip32-paths.md)** — the VTA's
  hierarchical-key derivation specification.
- **[CLI style](04-reference/cli-style.md)** — conventions for
  flags, output, errors, and JSON modes across `vta`, `vtc`, `pnm`,
  `cnm`.

### Part V — Design notes

In-flight or historical design documents kept for context. These
are implementer-facing rather than operator-facing.

- **[Task version negotiation](05-design-notes/task-version-negotiation.md)** —
  how two peers on different Trust Task versions find a common one, and the
  versioning contract that has to exist first for "negotiate" to mean anything
  more than "match exactly or fail". Proposes dropping semver's 0.x exemption
  rather than adding a PATCH component, and explains why the sender speaking
  *down* is what lets `deny_unknown_fields` stay. Design only; §2 is a proposal
  for the shared registry.
- **[Application-state store](05-design-notes/appstate-store.md)** — the
  proposed third store (beside the secrets and credential vaults) for
  versioned, namespaced, per-context application JSON: why agent memory
  and both vaults are the wrong home, what the surface needs, and the
  upstream spec dependency that has to land first. Design only.
- **[Community data rooms](05-design-notes/community-data-rooms.md)** —
  member-created, end-to-end encrypted shared spaces on the **VTC**, for
  shared agent memory and anything else a subset of a community needs to
  keep between themselves: why it is not the `vta/memory` family, the
  three-tier visibility ladder (`open` / `attributed` / `blind`) a
  community selects by Rego policy, room keys held in member VTAs via
  sealed transfer, and what blinding costs in audit and recovery.
  Design only.
- **[vta-service decomposition](05-design-notes/vta-service-decomposition.md)** —
  how the ~114k-line VTA crate was split into subsystem crates, the
  extraction technique, and the rule for where the program stops.
  **Read this before proposing a further extraction.**
- **[VTC MVP spec](05-design-notes/vtc-mvp.md)** — full
  specification for the VTC's Phase 0–5 build (the source of truth
  the implementation tracks).
- **[Runtime service management](05-design-notes/runtime-service-management.md)** —
  design notes for the VTA's enable/disable/migrate REST + DIDComm
  surface.
- **[Retry and idempotency](05-design-notes/retry-and-idempotency.md)** —
  which layer owns retry, how a Trust Task is classified for what a
  lost reply costs it, and the `idempotencyKey` contract.
  **Read this before adding a retry loop over a `VtaClient` call, or
  adding a new Trust Task.**
- **[Store migration](05-design-notes/store-migration.md)** — the
  enum-to-trait migration path for storage backends.
- **[PNM setup with deferred VTA DID](05-design-notes/pnm-setup-deferred-vta-did.md)** —
  the design behind the two-phase PNM setup that allows the VTA
  DID to be bound after initial wallet provisioning.
- **[DIDComm protocol management](05-design-notes/didcomm-protocol-management.md)** —
  precursor design notes for the runtime service management work.
- **[Approvals convergence](05-design-notes/approvals-convergence.md)** —
  why a VTA answers "does this need another human?" in one place
  rather than three, and what was retired to get there.
- **[ACL scope semantics](05-design-notes/acl-scope-semantics.md)** —
  the *act* vs *confer* axis on an ACL entry.

## Conventions

- Cross-references use relative links so the docs work both on
  GitHub and in any local Markdown viewer.
- Code references in prose use the form `path/to/file.rs:line` so
  IDEs can jump to them directly.
- Wire-format snippets are JSON for narrative clarity; the actual
  on-the-wire format is whatever the linked Rust types serialize
  to (CBOR for sealed payloads, JSON for VPs/VCs).
- Mermaid diagrams render natively on GitHub. Where a diagram and a
  table convey the same information, both are kept — diagrams for
  the layout, tables for the lookup.

## Contributing to the docs

If you're adding a new document:

- **Shared concept (applies to both VTA and VTC)?** Add to
  `01-concepts/`.
- **VTA operator / integrator how-to?** Add to `02-vta/`.
- **VTC operator / integrator how-to?** Add to `03-vtc/`.
- **Pure reference (tables, paths, formats)?** Add to
  `04-reference/`.
- **Implementation-detail design brief?** Add to `05-design-notes/`.

Update this index when you add or rename a chapter.
Cross-references in the workspace `README.md` and `CLAUDE.md` may
also need updating. The convention for paths inside Rust source
comments is `docs/<section>/<file>.md`.
