<!--
Title: a conventional commit — `fix(scope): …`, `feat(scope)!: …` for a breaking
change. It becomes the changelog entry.

Target `main`. A fix a supported release also needs reaches it by backport after
merge — RELEASES.md.
-->

## What and why

## Requirements

<!-- VTI-… identifiers this implements or touches, if any. -->

## Backport

<!-- One of: "none", or the release branches this fix needs — then add the
`backport release/<name>` label(s). Features are never backported. -->

## Checklist

- [ ] Targets `main` (or is a backport / `release-direct` PR into `release/<name>`)
- [ ] No `version =` edits in any `Cargo.toml`
- [ ] Tests cover the change; `cargo fmt` and `cargo clippy --all-targets -- -D warnings` are clean
