# Contribution Guidelines

Thank you for contributing! Before you contribute, we ask some things of you:

- Please follow our Code of Conduct, the Contributor Covenant. You can find a copy [in this repository](CODE_OF_CONDUCT.md) or under https://www.contributor-covenant.org/
- All Contributors must agree to [a CLA](.github/CLA/INDIVIDUAL.md). When opening a PR, the system will guide you through the process. However, if you contribute on behalf of a legal entity, we ask of you to agree to [a different CLA](.github/CLA/ENTITY.md). In that case, please contact us.

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
- [ ] PR title is a conventional commit — it becomes the changelog entry (see [Changelog](#changelog))
- [ ] No `version = ` edits in any `Cargo.toml` — the Release PR assigns versions (see [RELEASING.md](RELEASING.md))
- [ ] Commits are signed off (DCO: `git commit -s`)

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
