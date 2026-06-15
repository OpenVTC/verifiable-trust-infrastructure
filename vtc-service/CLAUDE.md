# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust workspace for **Verifiable Trust Communities (VTC)**. A VTC manages a community of Verifiable Trust Agents. Unlike the VTA (which manages keys), the VTC handles community management, ACL, audit, policy (Rego), credentials, status lists, trust-registry sync, cross-community recognition, member relationships, endorsements, the public website, and the admin SPA. Part of the [First Person Network](https://www.firstperson.network/white-paper) project.

## Workspace Structure

`vtc-service` sits inside the wider workspace at the repo root. Key sibling crates:

- **vti-common** (`../vti-common/`) — Shared library: auth (JWT, passkey), ACL, store (local fjall + vsock), audit writer + HMAC key store, error types, config, pagination cursors.
- **vta-sdk** (`../vta-sdk/`) — Shared SDK: types, VTA HTTP client, DIDComm protocol surfaces, `sealed_transfer`, provision-integration.
- **vta-service** (`../vta-service/`) — VTA library + local/dev binary (key management, did:webvh, mediator).
- **vtc-service** (this crate) — VTC binary service. Community management, policy, audit, public website, admin SPA.

`vti-common` is the canonical home for cross-crate types; VTC-specific business logic lives here.

## Key Differences from VTA

- **VTC isn't the key authority.** The VTA mints the integration DID + signing keys; the VTC stores the bundle in `secrets` and signs locally for VMC / VEC / status-list issuance (cached-locally pattern). No BIP-32 here.
- **Audience-isolated JWTs.** `aud = "VTC"`; cross-audience tokens are rejected.
- **Default port** 8200 (VTA uses 8100).
- **Twenty-odd keyspaces**, not the original two: `acl`, `sessions`, `members`, `community`, `policies`, `active_policies`, `audit`, `audit_key`, `install`, `passkey`, `status_lists`, `relationships`, `relationships_by_did`, `endorsement_types`, `endorsements`, `join_requests`, `sync_queue`, `sync_cursor`, `registry_records`, `config`, plus the website filesystem. The full live list is the keyspace fields on `AppState` in `src/server.rs`.
- **VTC never targets TEE.** Permanent non-goal (only the VTA runs in Nitro Enclave).

## Source layout (high-level)

```
src/
├── acl/                ACL storage + role types (VtcRole)
├── audit/              (re-exports from vti-common::audit)
├── auth/               session, AuthClaims/AdminAuth/SuperAdminAuth extractors
├── ceremony/           Decision pipeline (facts → verify → decide → effect/audit);
│                       `assemble` (one Facts builder for every purpose) +
│                       `orchestrate` (role-change + leave spines, out of routes)
├── community/          CommunityProfile storage
├── credentials/        LocalSigner + VMC/VEC/status-list builders; `exchange/`
│                       (OID4VCI issuer + OID4VP/SD-JWT/DI/bbs verifier, split into
│                       issue/verify/pending/jwt) + `vm_resolver` (the single shared
│                       DID-VM → key resolver + `check_issuer_binding`)
├── endorsement_types/  Operator-registered endorsement-type registry
├── endorsements/       Custom VEC + status-list flip
├── install/            Install-token state machine + claim secret
├── join/               Join-request lifecycle + `orchestrate` (submit spine:
│                       holder-binding → decide → auto-admit → admit audit)
├── members/            Member storage + lifecycle helpers
├── policy/             regorus engine, default policy bundle, evaluators
├── recognition/        Foreign-VEC verification (Phase 3 cross-community)
├── registry/           Trust-registry client + syncer + audit-log tail
├── relationships/      VRC publish/revoke
├── routes/             Every HTTP route handler, sub-mounted by feature
├── routing/            Security headers, CSRF, body cap, governor middleware
├── setup/              `vtc setup` wizard: `wizard.rs` (interactive) +
│                       `from_toml.rs` (`setup --from <toml>`). Both build one
│                       `WizardPlan` and share the `apply` effect driver.
├── status_list/        Bitstring status list allocator + storage + serve route
├── store/              Re-export of vti-common's keyspace abstractions
└── website/            Public website handler, bundle + deploy, default site
```

The admin SPA lives at `admin-ui/` (React + TS + Vite, baked into the binary at compile time by `build.rs` + `include_dir!`). The fallback public landing page lives at `website-default/` (plain HTML / CSS / JS, no build step).

## Operator docs

The reader-facing operator guides live under `/docs/03-vtc/`. Start there before touching code:

- `getting-started.md` — first-install walkthrough.
- `architecture.md` — keyspace + module map.
- `policy.md` — Rego authoring + activation discipline.
- `audit.md` — envelope shape, HMAC actor hashing, rotation.
- `cross-community.md` — Phase 3 recognition + trust-registry sync.
- `website-and-admin.md` — public website + admin SPA deployment.
- `admin-ui-plugins.md` — third-party plugin loader contract.

The Phase 0-5 spec is at `/docs/05-design-notes/vtc-mvp.md` — pinned decisions in §3, security invariants in §14. Section status notes flag which phase shipped each component.

## Build Commands

```bash
# Build entire workspace
cargo build

# Check compilation (faster, no codegen)
cargo check

# Run the service
cargo run --package vtc-service

# Skip the admin-UI npm build during cargo invocations (faster dev loop)
VTC_SKIP_ADMIN_UI_BUILD=1 cargo build -p vtc-service

# Run all tests
cargo test

# Run tests for a single crate
cargo test --package vtc-service

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
