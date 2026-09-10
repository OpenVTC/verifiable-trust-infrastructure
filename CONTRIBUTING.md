# Contribution Guidelines

Thank you for contributing! Before you contribute, we ask some things of you:

- Please follow our Code of Conduct, the Contributor Covenant. You can find a copy [in this repository](CODE_OF_CONDUCT.md) or under https://www.contributor-covenant.org/
- All Contributors must agree to [a CLA](.github/CLA/INDIVIDUAL.md). When opening a PR, the system will guide you through the process. However, if you contribute on behalf of a legal entity, we ask of you to agree to [a different CLA](.github/CLA/ENTITY.md). In that case, please contact us.

## The specification

This workspace implements the **Verifiable Trust Infrastructure (VTI)
specification**: <https://trustoverip.github.io/dtgwg-vti-spec/>

**Read it before you change anything it governs** — the authority model (trust
contexts, access control entries, roles, capabilities, approvals), the client
lifecycle, the operation surface, transports and delivery, sessions,
credentials, or the audit trail.

The specification is normative and this code is an implementation of it. Where
the two disagree, the specification is what is correct and the code is what
changes. That direction is deliberate: several of its requirements prohibit an
encoding or a default that is easy to implement, widely used, and wrong in a
way that only shows up under adversarial conditions.

**Cite requirements by identifier.** Requirements carry stable identifiers such
as `VTI-ACL-021` or `VTI-CLT-023`. Use them in PR descriptions, in comments
explaining a constraint that would otherwise look arbitrary, and in the names of
tests that exist to hold a requirement. A reviewer who can follow the identifier
to the requirement can check the change against something other than your
description of it.

**Do not diverge silently.** If behaviour here cannot conform — or you believe
it should not — record it in the specification's divergence register
(Appendix F) with the requirement, the observed behaviour and the intended
resolution. Recording a divergence is not an exemption from the requirement
(VTI-CNF-015), and if you think the requirement itself is wrong, that is a
change proposal against the specification, argued on its merits. The two are
different and should not arrive as the same pull request.

A divergence that is written down is one that can be planned against. One that
is only known gets rediscovered by whoever composes the system next.

## Development Setup

### Prerequisites

- **Rust 1.95.0+** (`rustup default stable`)
- **libdbus-1-dev** (Linux) or equivalent (for keyring feature)
- **Docker** (for enclave builds only)

### Build

```bash
# Build entire workspace
cargo build

# Check compilation (faster, no codegen)
cargo check

# Run the local/dev VTA
cargo run --package vta-service

# Build for TEE (Linux only)
cargo build --package vta-enclave --features rest,didcomm,vsock-store
```

### Test

```bash
# Run all tests
cargo test

# Run tests for a single crate
cargo test --package vta-service --lib

# Run a specific test
cargo test --package vta-service --lib encrypt_decrypt

# Run with output
cargo test -- --nocapture
```

### Lint

```bash
cargo clippy
cargo fmt --check
```

## PR Checklist

Before submitting a pull request:

- [ ] `cargo check` passes for the entire workspace
- [ ] `cargo test` passes with no failures
- [ ] `cargo fmt --check` shows no formatting issues
- [ ] New public functions have `///` doc comments
- [ ] Security-sensitive changes include tests (auth, ACL, crypto)
- [ ] Changes to the authority model, client lifecycle, operation surface, transports, sessions, credentials or audit conform to the [VTI specification](https://trustoverip.github.io/dtgwg-vti-spec/), and cite the requirement identifiers they implement
- [ ] Any divergence from the specification is recorded in its divergence register (Appendix F), not left implicit
- [ ] PR title is a conventional commit — it becomes the changelog entry (see [Changelog](#changelog))
- [ ] No `version = ` edits in any `Cargo.toml` — the Release PR assigns versions (see [RELEASING.md](RELEASING.md))
- [ ] Commits are signed off (DCO: `git commit -s`) — required for all outside contributions

## Changelog

**You do not write a changelog entry. You write a good commit message.**

The changelog of every published crate is generated from conventional commits
when a release is cut. A squash merge makes the **PR title** the commit subject,
so that is what CI lints:

```
feat(tsp): a VTA can speak TSP without DIDComm
fix(did-webvh): write the DID log where the operator asked
feat(sdk)!: rename the transport selector      <- ! marks a breaking change
```

Types: `feat` `fix` `docs` `test` `ci` `build` `perf` `refactor` `chore`
`security`. Scope is optional.

**The body matters.** It is included in the changelog verbatim — the explanation
you write for reviewers is the same text a consumer of the crate reads. Write it
as you would want to read it six months later.

**Never edit a `version = ` field.** Versions are assigned by the Release PR
release-plz maintains, not by you. See [RELEASING.md](RELEASING.md).

> `changelog.d/` fragments are gone. They existed so two PRs would not conflict
> in `CHANGELOG.md`; generating from commits removes the shared file entirely.

## Coding Guidelines

- **Error handling**: Use `?` operator and `AppError` variants. Never `unwrap()` on user input or I/O in production code paths. `expect()` is acceptable only in `main()` for unrecoverable startup failures.
- **Auth**: All new REST endpoints must use an auth extractor (`AuthClaims`, `ManageAuth`, `AdminAuth`, `SuperAdminAuth`). DIDComm handlers must call `auth_from_message()`.
- **Audit**: Security-sensitive operations (key creation, ACL changes, backup, restart) must emit an audit log entry via `crate::audit::record()`.
- **Feature flags**: Gate platform-specific code behind features. Don't add unconditional dependencies on `tokio-vsock`, cloud SDKs, etc.
- **Secrets**: Never log seeds, mnemonics, private keys, or passwords. Use `Zeroize` on structs holding secrets.

## Workspace Structure

See [README.md](README.md) for the crate overview. Key design documents:

- [Documentation index](docs/README.md) — start here.
- [Overview](docs/01-concepts/overview.md) and [Architecture](docs/01-concepts/architecture.md)
- [Security model](docs/01-concepts/security-model.md)
- [TEE architecture](docs/02-vta/tee-architecture.md)
- [Cold-start guide](docs/02-vta/cold-start.md)
- [Secret-storage backends](docs/02-vta/secret-backends.md)
- [Feature flags](docs/02-vta/feature-flags.md)
- [Integration guide](docs/02-vta/integration-guide.md)
- [DIDComm protocol](docs/02-vta/didcomm-protocol.md)
- [BIP-32 paths](docs/04-reference/bip32-paths.md)
- [Store migration](docs/05-design-notes/store-migration.md)
