### Release process — changelog fragments replace direct `CHANGELOG.md` edits (#878)

Feature PRs now add `changelog.d/<PR-number>-<slug>.md` instead of editing
`CHANGELOG.md`. Every PR previously inserted at the same anchor — the first line
under `## Unreleased` — so any two concurrent PRs conflicted, structurally and
every time. Two PRs adding two different files never conflict.

`scripts/collate-changelog.sh` folds the fragments into `## Unreleased` at release
time (newest PR first, verbatim) and deletes them, as one commit by one author.
`scripts/check-changelogs.sh` keeps its contract — a bumped publishable crate must
be named with its new version — and now searches both locations, so only the file
the entry lives in moved.

Also fixes two latent bugs in that guard: a `cut -f3` against two-column data,
which made the anti-vacuous-pass check unable to ever fire, and a glob passed to
`grep` that would have read stdin and hung CI on an empty fragment directory.

No crate versions change; this is release tooling and convention only.
