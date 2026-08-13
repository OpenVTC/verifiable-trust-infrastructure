# Releasing

**Merging is not releasing.** Anything merged to `main` sits unpublished until a
release is cut. Releases are cut by merging a **Release PR** that
[release-plz](https://release-plz.dev) keeps up to date for you.

Contributing rather than releasing? You only need
[What this means for contributors](#what-this-means-for-contributors).

---

## What this means for contributors

**Two rules.**

1. **Never edit a `version = ` field in a `Cargo.toml`.** Versions are assigned
   by the Release PR, not by you. A version in a feature PR collides with every
   other PR touching that crate.
2. **Write a conventional-commit PR title.** A squash merge makes the PR title
   the commit subject, and the changelog of every published crate is generated
   from those subjects. CI lints it.

```
feat(tsp): a VTA can speak TSP without DIDComm
fix(did-webvh): write the DID log where the operator asked
feat(sdk)!: rename the transport selector      <- ! marks a breaking change
```

Types: `feat` `fix` `docs` `test` `ci` `build` `perf` `refactor` `chore`
`security`.

**Write a real commit body.** It is included in the changelog verbatim, so the
explanation you write for reviewers is the same text an external consumer reads
on crates.io. This is the whole changelog process now — there are no fragment
files to add and nothing to collate.

> **Changed from the old flow:** `changelog.d/` fragments are gone, along with
> `check-changelogs.sh`, `collate-changelog.sh` and the per-PR version bump.
> Fragments existed so two PRs would not conflict in `CHANGELOG.md`; generating
> from commits removes the shared file entirely, so there is nothing left to
> conflict over.

---

## What gets published

**20 of 26 crates.** The six that stay internal set `publish = false` in their
own `Cargo.toml`, each with a comment saying why: `vtc-service`, `vta-enclave`,
`vta-mcp`, `vta-mobile-core`, `didcomm-test`, `vti-fuzz`.

| Published | Consumed by |
|---|---|
| `vta-sdk` | 8 sibling repos — the public SDK |
| `vti-common` | cierge, webvh-service, enm |
| `vti-secrets` | trust-registry, cierge, enm, message-bridge |
| `vta-cli-common` | enm |
| `vtc-client` | enm |
| `pnm-cli`, `cnm-cli` | operator binaries, `cargo install` |
| `vta-service` | **openvtc-core**, as a dev-dependency — `test_support::MockVta` |
| the twelve subsystem crates | nothing directly; they are `vta-service`'s closure |

### Why `vta-service` publishes again

#938 unpublished it, and its eleven-plus-one closure, on the finding that
nothing external depended on them. The audit read normal dependencies;
`openvtc-core` depends on `vta-service` as a **dev-dependency**, for
`test_support::MockVta` — an in-process VTA its end-to-end tests run against.
That harness boots the real service, so no client crate can substitute for it.

Unpublishing did not just freeze the crate, it broke it. `vti-common`
re-exports `vta_sdk::acl::{ActScope, ApproveScope, ContextDirection}` as its own
public API, so **a re-export makes the re-exported crate's version part of your
public API**: any graph combining `vti-common` with another `vta-sdk` consumer
must resolve one `vta-sdk`. The frozen `vta-service` 0.14.37 asks for
`vta-sdk ^0.21`; `vti-common` has since moved to `^0.23`. A downstream
`cargo update` resolves both and `vta-service` fails to compile with

```
expected `vti_common::acl::ApproveScope`, found `vta_sdk::acl::ApproveScope`
```

at ten call sites. Publishing keeps every requirement in the set moving
together, which is the only thing that makes the combination resolvable.

The alternatives were worse: yanking the published copies breaks OpenVTC's
tests with nothing to replace them, and leaving them up means shipping a crate
on the registry that cannot be built.

**Adding a crate to the published set** means setting `publish` back to the
workspace default *and* checking that everything it depends on is published.
**Removing one** means checking dev-dependencies too, in every sibling repo —
that is the check #938 missed.

---

## Cutting a release

### 1. Review the Release PR

release-plz keeps one open, titled `chore: release`. It updates on every merge
to main and contains:

- the version bump for each changed crate, and
- the changelog entries those commits produced.

Read it as you would any diff. **The bump levels are derived, not guessed:**
[`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks)
compares each crate's public API against the version on crates.io, so a genuine
API break moves the compatibility field whether or not anyone remembered to say
so.

Every crate here is `0.x`, where cargo treats the **minor** field as the
compatibility boundary: `0.21.4` → `0.21.5` is compatible, `0.21.4` → `0.22.0`
is not.

### 2. Merge it

That's the release. Merging triggers the `release` job, which:

- tags each crate (`<crate>-v<version>`),
- publishes to crates.io in dependency order,
- creates a GitHub Release per crate carrying its changelog section.

Nothing else publishes. An ordinary feature merge runs the same job and it does
nothing, because every version is already on crates.io.

### 3. If it fails partway

Re-run the job. Publishing is idempotent — crates already at that version are
skipped, so a re-run resumes rather than duplicating.

---

## Setup this depends on

Two things must be true, and one of them is not yet:

- **`RELEASE_PLZ_TOKEN`** — a PAT (contents + pull-requests write) or GitHub App
  token. **Not currently set.** GitHub suppresses workflow runs for events
  authored by the default `GITHUB_TOKEN`, so without it the Release PR opens
  with no CI on it. Only DCO is a required check, so it would still be
  mergeable — meaning the one commit that publishes to crates.io would be the
  one commit CI never built. Until the token exists, close-and-reopen the
  Release PR to trigger CI before merging.
- **Trusted Publishing** — already configured. crates.io mints a short-lived
  token per run from the workflow's OIDC identity; no registry token is stored
  in this repo. See `docs/05-design-notes/trusted-publishing.md`.

### One-time migration

release-plz anchors each crate's changelog to the tag of its last release. No
such tags exist yet, so before the first Release PR is trusted, seed them at the
current `main` — everything there is already published:

```bash
git switch main && git pull
for c in vta-sdk vti-common vti-secrets vtc-client vta-cli-common pnm-cli cnm-cli; do
  v=$(grep -m1 '^version' "$c/Cargo.toml" | cut -d'"' -f2)
  git tag -s "$c-v$v" -m "$c $v"
done
git push origin --tags
```

Without these, the first Release PR bumps versions correctly but produces empty
changelog sections — there is no range for it to read commits from.

---

## Reference

| | |
|---|---|
| `release-plz.toml` | what release-plz does; published set lives in the manifests |
| `cliff.toml` | how commits become changelog entries |
| `.github/workflows/publish.yml` | the Release PR + release jobs |
| `scripts/check-lockfile-self-pins.sh` | catches a stale registry self-pin in `Cargo.lock` |
| CI `commit lint` | PR title must be a conventional commit |
| CI `semver checks` | reports API breaks on the PR that causes them |
