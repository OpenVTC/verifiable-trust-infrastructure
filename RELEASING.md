# Releasing

**Merging is not releasing.** Anything merged to `main` sits unpublished until a
release is cut. Releases are cut by merging a **Release PR** that
[release-plz](https://release-plz.dev) keeps up to date for you.

Contributing rather than releasing? You only need
[What this means for contributors](#what-this-means-for-contributors).

This file is about publishing crates from `main`. **Named releases** — Eucalyptus,
Fig, the release branches operators deploy and the patches they take —
are in [RELEASES.md](RELEASES.md); [Release branches](#release-branches) below
covers how their crates publish.

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

**What actually counts as breaking**, because the `!` is easy to leave off a
change that does not feel like one. release-plz derives the bump from the type
and the `!`, so an unmarked break ships as a patch — and a caret requirement
picks that up on a routine `cargo update`. In a published crate, all of these
are breaking even though none of them removes or renames anything:

- **A new variant on a public enum** that is not `#[non_exhaustive]`. Any
  downstream exhaustive `match` stops compiling.
- **A new field on a public struct** a consumer can build with a literal. Their
  literal is now missing a field.
- **A new required argument, or a new trait method with no default.**
- **A stricter bound, or a narrowed return type.**

This is not a hypothetical list. Every entry on it happened here between
2026-08-29 and 2026-09-06, and none was marked: `Capability` gained four
variants across #1234, #1247 and #1250, `AuditEvent` gained one in #1244, and
sixteen `vta-sdk` wire structs gained an `ext` field in #1231 — under `fix:`,
which derives the smallest bump there is. `vti-common` 0.16.2 and `vta-sdk`
0.32.4 went out as patches carrying all of it.

**The better fix is usually not the `!`.** If a type is *designed* to grow —
a capability list, an event vocabulary — mark it `#[non_exhaustive]` once and
the additions stop being breaking at all. That is what #1262 did for
`Capability` and `AuditEvent`. Reach for the marker when the break is real and
intended; reach for `#[non_exhaustive]` when the type will keep growing.

Neither replaces the mechanical check: `release bump is large enough` runs
cargo-semver-checks against the versions a Release PR actually proposes and
blocks when the bump is too small. It does not depend on anyone noticing.

**Write a real commit body.** It is included in the changelog verbatim, so the
explanation you write for reviewers is the same text an external consumer reads
on crates.io. This is the whole changelog process now — there are no fragment
files to add and nothing to collate.

**Fixing something a supported release also needs?** Land it on `main`, then
label the merged PR `backport release/<name>`; a bot opens the cherry-pick on
that branch. See [RELEASES.md](RELEASES.md#what-goes-on-a-release-branch).

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

**Read the `Release-plz release` job's log after every Release PR merge** — a
run that stops partway publishes some crates and not others, and nothing else
tells you. Publishing is idempotent (crates already at that version are
skipped), so a later run resumes rather than duplicating — but only once the
cause is fixed. Re-running unchanged repeats the same failure.

Two causes have halted a release, both on #1795:

- **A versioned dev-only dependency on a sibling.** `cargo publish` resolves it
  against crates.io, and the release publishes in *normal*-dependency order, so
  the sibling may not be there yet. Make it path-only (#1805); CI's
  `check-release-bump-sizes.py` now refuses the versioned form.
- **API that landed after the release was cut.** A crate is packaged from
  `main`, so if a later merge made it depend on a sibling change that no
  published version carries (#1803's `AppConfig.fjall`), it fails tarball
  verification. The next Release PR bumps the changed sibling; merge it and the
  run resumes.

A half-finished release can also break what is *already* published: crates
that did go out may be ones an older dependent resolves by caret. See the next
section.

### 4. A dependency move is a breaking bump

When a Release PR moves a crate's requirement on a sibling to a new
compatibility range (`vti-common = "^0.27"` → `"^0.29"`), that crate must take a
breaking bump itself (0.3.25 → 0.4.0, not 0.3.26). release-plz derives a patch
here, and cargo-semver-checks cannot see it — it compares a crate's own API, not
what the crate depends on. But every published crate that asks for this one by
caret would take the patch and, with it, a second copy of the sibling: that is
how vta-audit 0.3.26 and vta-support 0.5.7 made vta-service 0.44.0 unbuildable
from a fresh resolve.

CI's `check-release-bump-sizes.py` fails the Release PR when this happens and
names the crate. Fix it in the Release PR: raise that crate to the next breaking
version and update its dependents' requirements (`check-workspace-version-reqs.py`
points at any you miss).

### 5. A release branch owns its compatibility lines

When a named release is cut, every published crate's line at the cut (0.38 for
`vta-sdk` 0.38.2) belongs to its branch, which publishes its patches there.
`check-release-line-ownership.py` fails a Release PR that proposes a version in
one of those lines (`releases/*.toml`); `fix-release-bump-sizes.py` raises the
crate to its next breaking version, as in step 4.

---

## Release branches

`publish.yml` also runs on `release/**`, and its `release` job publishes from
there exactly as from `main`: whatever version in the manifests is not on
crates.io yet. Two things differ, both because release-plz derives a Release PR
from the **newest** version of each crate on crates.io — on a release branch,
`main`'s line:

- **No Release PR.** Versions on a release branch come from
  `scripts/prepare-release-branch.py`, run by the *Prepare a named release*
  workflow: the next patch of each changed published crate, checked with
  `cargo semver-checks --release-type patch`, its changelog rendered from
  `cliff.toml`. That workflow is the one sanctioned way a `version =` changes on
  a release branch.
- **Not "latest".** `cut-release.py` sets `git_release_latest = false` in the
  branch's `release-plz.toml`, so a patch's GitHub Releases do not displace
  `main`'s.

After a release branch's crates are published, the same job tags the named
release from the branch's `RELEASE` file. The procedures are in
[RELEASES.md](RELEASES.md#procedures).

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
| CI `semver report` | reports API breaks on a PR labelled `semver-report` (opt-in); `release bump is large enough` enforces on every Release PR |
