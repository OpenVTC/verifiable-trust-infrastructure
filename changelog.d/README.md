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

## What CI enforces

`scripts/check-changelogs.sh` runs on every PR (the `release-guards` job) and
fails on:

1. **A fragment filename that isn't `<PR-number>-<slug>.md`.** The number is what
   makes fragments collision-free.
2. **A fragment that names the wrong PR** — filename or `###` heading — when it
   is one *this* PR adds. Other PRs' fragments sit in this directory too and are
   not your PR's business. Needs the PR number, which CI passes as `PR_NUMBER`;
   a local run skips this rather than inventing one.
3. **An edit to `CHANGELOG.md`.** The shared file is the thing that conflicts, so
   editing it is refused rather than merely discouraged. The release collation is
   exempt and needs no ceremony — it *deletes* the fragments it folds in, and
   that is how the guard tells it apart. `ALLOW_CHANGELOG_EDIT=1` (CI sets it
   from the `release` label) covers the rest: stamping a version heading,
   correcting an entry that already shipped.
4. **A bumped publishable crate with no entry naming its new version**, searching
   `CHANGELOG.md` **and** `changelog.d/*.md` — so a repo that has just collated
   still passes, and the contract is about the record existing rather than which
   file it currently lives in.

A PR that bumps nothing and records nothing gets a **notice**, not a failure.
Most such PRs genuinely need no entry; the ones that do — release-process
changes, CI contracts, docs restructures — are worth a nudge at the moment
you're looking, but not worth taxing every typo fix to catch.

Every check reads the **committed** diff, so a fragment you haven't committed is
invisible to a local run.
