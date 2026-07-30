# Changelog fragments

**One file per PR. Never edit `CHANGELOG.md` in a feature PR.**

Two PRs that both insert a section at the top of `## Unreleased` conflict every
time — same anchor, different text, and git has no way to order them. That is
structural, not bad luck: it hit every pair of concurrent PRs, and the cost grew
with the amount of parallel work. Adding two *different files* never conflicts,
so the conflict is designed out rather than resolved over and over.

## Writing one

Create `changelog.d/<PR-number>-<short-slug>.md` containing exactly the block you
would previously have pasted into `CHANGELOG.md`:

```markdown
### vta-sdk 0.20.28 / vtc-service 0.11.46 — communities advertise their authoritative registry (#877)

Prose explaining what changed and why, in the same voice as the rest of
`CHANGELOG.md`. Bullets per crate when several are involved.
```

Rules:

- **Filename**: `<PR-number>-<slug>.md`. The PR number keeps it unique, which is
  the whole point; the slug is for humans skimming the directory. Validated by
  `scripts/check-changelogs.sh`.

  You won't know the number until the PR exists, so the order is: push the
  branch, open the PR, then add the fragment in a second commit. The guard only
  runs on the PR, so it will be satisfied by the time it matters.
- **Heading**: `### <crate> <version> [/ <crate> <version> …] — <summary> (#PR)`.
  The version-bump guard matches on `<crate> <version>` as whole tokens, so name
  every crate you bumped, with its **new** version.
- **Content is final.** Fragments are concatenated verbatim at release time, not
  reformatted. Write it as it should appear.

If your PR bumps no publishable crate version, a fragment is optional — but add
one anyway for anything a consumer or operator would want to know about
(release-process changes, CI contracts, docs restructures). Several of those have
shipped unrecorded precisely because nothing forced the entry.

## What happens at release

`scripts/collate-changelog.sh` folds every fragment into `## Unreleased` in
`CHANGELOG.md`, newest PR first, and deletes the fragments. It runs once when a
release is cut — one commit, one author, so there is nothing to conflict with.

```sh
scripts/collate-changelog.sh          # rewrite CHANGELOG.md, remove fragments
scripts/collate-changelog.sh --check  # dry run; prints what would be folded in
```

## Why the guard still passes

`scripts/check-changelogs.sh` requires every bumped publishable crate to be named
with its new version in a changelog entry. It now searches `CHANGELOG.md` **and**
`changelog.d/*.md`, so the contract is unchanged — only the file you write it in
moved. A bump with no entry in either place still fails.
