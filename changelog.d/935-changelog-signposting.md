### Repository — sign-post the changelog, so the fragments are findable (#935)

No crate versions change. Recorded here because it changes where contributors
are told to write changelog entries, which is exactly the kind of process change
`changelog.d/README.md` asks for a fragment about.

`CHANGELOG.md` opened with a `## Unreleased` section that stopped at #876, while
every entry since — 51 fragments — lived in `changelog.d/` with nothing in the
file saying so.

- **`CHANGELOG.md`** gains a note *above* `## Unreleased`: unreleased entries
  live in `changelog.d/` until a release is cut, this file lags that directory by
  design, and reading both is how you see everything pending. Above the heading
  deliberately — `collate-changelog.sh` inserts fragments immediately after the
  `## Unreleased` line, so a note underneath would sink below the newest entries
  on every release.
- **`CONTRIBUTING.md`**: the PR checklist asked for "CHANGELOG.md updated for
  user-facing changes" — the one thing the convention forbids, told to every
  contributor at the moment they were about to do it. It now asks for a fragment,
  and a new Changelog section covers the naming rule, the heading contract the
  version guard matches on, and what happens at release.
- **`README.md`** names both locations in its Contributing section.

The convention itself is unchanged; `changelog.d/README.md` remains the full
account.
