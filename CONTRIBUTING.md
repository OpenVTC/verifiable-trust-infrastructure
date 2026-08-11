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
- [ ] Changelog fragment added for user-facing changes — `changelog.d/<PR-number>-<slug>.md`, **not** an edit to `CHANGELOG.md` (see [Changelog](#changelog))
- [ ] Commits are signed off (DCO: `git commit -s`)

## Changelog

**Add a file, don't edit `CHANGELOG.md`.** Every PR used to insert its entry at
the same anchor in that one file, so any two open PRs conflicted — structurally,
every time, with the same mechanical "keep both" resolution. Two PRs adding two
different files never conflict.

Create `changelog.d/<PR-number>-<slug>.md` containing the `###` block you would
otherwise have pasted into `CHANGELOG.md`:

```markdown
### vta-sdk 0.21.21 / vta-service 0.14.34 — one line on what changed (#934)

Prose explaining what changed and why, in the same voice as the rest of
`CHANGELOG.md`. Bullets per crate when several are involved.
```

- The heading must name **every crate you bumped, with its new version** —
  `scripts/check-changelogs.sh` matches `<crate> <version>` as whole tokens and
  fails a bump with no entry.
- You won't know the PR number until the PR exists, so push, open the PR, then
  add the fragment in a second commit. Don't guess the number: CI checks that
  the fragment names *your* PR, in the filename and in the `###` heading, and a
  guessed number that loses the race points readers at someone else's work
  forever once it's collated.
- **CI fails a PR that edits `CHANGELOG.md`.** That is the whole point — the
  shared file is what conflicts. The release collation is exempt (it deletes the
  fragments it folds in, which is how the guard recognises it); anything else
  that must touch the file needs the `release` label.
- No version bump? A fragment is optional, but add one anyway for anything an
  operator or a sibling repo would want to know — release-process changes, CI
  contracts, docs restructures.
- At release, `scripts/collate-changelog.sh` folds every fragment into
  `## Unreleased` and deletes them: one commit, one author, nothing to conflict
  with.

Full convention, including why: [`changelog.d/README.md`](changelog.d/README.md).

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
