# Named releases

What operators deploy is a **named release** — Dogwood, Eucalyptus, … — cut from
`main` on a fixed schedule and patched on its own branch for as long as it is
supported. This file is the schedule and the policy. The mechanics of
publishing crates are in [RELEASING.md](RELEASING.md).

## Branches

```
feature/*  ──PR──▶  main  ──(nightly.yml: last fully green commit)──▶  nightly
                                                                          │
                       release/dogwood    ◀── cut ─────────────────────────┤
                       release/eucalyptus ◀── cut ─────────────────────────┘
```

| Branch | What it is | Written by |
|---|---|---|
| `main` | Active development. Every PR lands here first. Publishes crates through release-plz, as before. | PRs |
| `nightly` | The newest `main` commit on which **every** CI job passed. Fast-forward only. Nightly builds and release cuts come from here, never from `main`'s tip, because `main` merges on a red suite as readily as a green one. | `nightly.yml`, daily at 02:00 UTC |
| `release/<name>` | One named release, from its cut to its end of life. Takes backported fixes only. | Backport and prep PRs |
| `feature/*`, `fix/*` | Short-lived work. A large effort lands on `main` behind a feature flag, not on a long-lived branch. | Anyone |

## Schedule

A release is cut every **4–6 weeks**, alphabetically by tree name. Dates are
set when the previous release goes GA.

| Release | Support | Cut | GA | End of life | Status |
|---|---|---|---|---|---|
| Dogwood | standard | TBD | TBD | TBD | planned |
| Eucalyptus | standard | TBD | TBD | TBD | planned |

`releases/<name>.toml` is the machine-readable side of a release — what it was
cut from and which crate versions it owns. `scripts/cut-release.py` writes it;
it is never edited by hand.

## Lifecycle of one release

| Week | Step | Tag |
|---|---|---|
| 0 | **Cut** `release/<name>` from `nightly`. | `<name>.rc1` |
| 0–1 | **Stabilise.** Backport fixes; each prep is another candidate. | `<name>.rc2`, … |
| ~1 | **GA.** | `<name>.0` |
| after | **Patch** as fixes are backported. | `<name>.1`, `<name>.2`, … |
| EOL | Marked in the table above. The branch stays, read-only. | — |

## Support

- **Standard releases:** the newest two GA releases (N and N-1) are supported.
  When a release goes GA, the release before N-1 reaches end of life. With a
  4–6 week cadence, a standard release is supported for about 10–12 weeks.
- **LTS releases:** the maintainers designate a release LTS; there is no fixed
  rule for which one, or for how long it is supported. Both are recorded in the
  schedule table when it is designated: the support column says `lts`, and the
  end-of-life date is the maintainers' commitment. Mark it at the cut with
  `--lts` (or later, in the table) — the flag records the decision, it does not
  make one.

"Supported" means fixes for security problems and for defects that break a
deployment are backported and released. Features never are.

## What goes on a release branch

**Fix on `main` first, then backport.** Label the merged PR
`backport release/<name>` (one label per target branch); `backport.yml` opens the
cherry-pick as a PR on that branch, as a draft carrying the conflict if it does
not apply cleanly. Only fix on the release branch directly when the code there
no longer exists on `main`: a maintainer adds the `release-direct` label to that
PR, and its description says why.

A release branch takes fixes, security changes and docs. It never takes a
feature, and it **cannot** take a breaking change to a published crate:
`prepare-release-branch.py` runs `cargo semver-checks --release-type patch` and
refuses. Rework the fix to keep the API, or leave it on `main`.

The `branch rules` check (`check-branch-rules.py`) holds all of this: a PR into
`release/**` is a bot backport, a prep PR or labelled `release-direct`; only the
release tooling changes versions, `RELEASE` or `releases/`, on any branch.

CI is **required** on `release/**`. On `main` it is advisory (see CLAUDE.md); on
a branch operators run, it is not.

## Versions

Two version schemes, deliberately kept apart:

1. **The release version** — `dogwood.0`, `dogwood.3`. What an operator deploys,
   and what identifies the unpublished crates (`vtc-service`, `vta-enclave`,
   …) at the commit it tags. The project publishes no container images or
   enclave images: operators build their own from the tag, and generate their
   own PCR0 to pin with `--expect-pcr0`. Each one is a GitHub Release whose notes
   carry the bill of materials: every published crate's version at that commit.
   Never marked "latest"; an rc is a prerelease.
2. **Crate versions** — independent semver per crate, as on `main`. A release
   branch publishes **patches only**, in the compatibility line it was cut at.

### Each release branch owns its lines

When Dogwood is cut with `vta-sdk` at 0.38.2, the 0.38 line belongs to
`release/dogwood`: 0.38.3, 0.38.4, … are its patches. `main` must not publish
into it, or Dogwood's next patch has no version left, and a consumer on `^0.38`
would receive `main`'s features as a "patch".

`check-release-line-ownership.py` enforces this on `main`'s Release PR, from
`releases/*.toml`; `fix-release-bump-sizes.py` applies the fix (raise to the
next breaking version). In practice it rarely bites — crates here take a minor
bump most weeks anyway.

## Procedures

### Cut

```sh
python3 scripts/cut-release.py dogwood --dry-run   # check; prints the manifest
python3 scripts/cut-release.py dogwood [--lts]
```

This pushes `release/dogwood` (tagged `dogwood.rc1` by `publish.yml`) and opens
a PR to `main` recording `releases/dogwood.toml`. **Merge that PR before
`main`'s next Release PR.** Then add the backport label
`backport release/dogwood` and update the table above.

The cut refuses if any crate at the source commit is not on crates.io yet —
let `main`'s release job finish first.

It also refuses if a crate has not changed since an earlier release was cut:
its version is still in that release's line, and two branches in one line
would want the same patch numbers. `--claim` opens a PR on `main` that gives
those crates (and their dependents) their next breaking version, with a
changelog entry saying why. Merge it, wait for the release job and for
`nightly` to move past it, and cut again.

### Release candidate, GA, patch

Actions → **Prepare a named release** → choose the release branch as the ref
and `rc`, `ga` or `patch`. It bumps the patch version of every published crate
that changed since its last release (semver-checked), writes their changelogs,
moves `RELEASE`, and opens a `chore(release): <name>.<n>` PR. **Merging it is
the release:** `publish.yml` publishes the crates and tags `<name>.<n>`.

A prep with no crate changes still produces a release: something unpublished
(`vtc-service`, the enclave) changed.

### End of life

Set the status in the table. Nothing is deleted: the branch, its tags and its
crates stay, and its lines stay closed to `main`.

## Repository settings this relies on

These are settings, not files, so they are not in this PR:

- **Ruleset on `release/**`:** require a PR, require the CI jobs and
  `branch rules`, block force pushes and deletion.
- **Ruleset on `main`:** require a PR, and require `branch rules`. Allow `RELEASE_PLZ_TOKEN`'s identity to create the
  branch (`cut-release.py`).
- **Ruleset on `nightly`:** block force pushes and deletion; only
  `RELEASE_PLZ_TOKEN`'s identity may update it.
- **`RELEASE_PLZ_TOKEN`** needs contents, pull-requests and actions (read)
  permission. Pushes and PRs made with `GITHUB_TOKEN` trigger no workflows, so
  nightly, backports and prep PRs all use it.
