### Repository — the changelog convention is signposted, enforced, and current (#935)

No crate versions change. Recorded here because it changes where contributors
are told to write changelog entries and what CI does about it — exactly the kind
of process change `changelog.d/README.md` asks for a fragment about.

`CHANGELOG.md` opened with a `## Unreleased` section that stopped at #876, while
every entry since — 52 fragments — lived in `changelog.d/` with nothing in the
file saying so.

**Signposting.** `CHANGELOG.md` gains a note *above* `## Unreleased`: unreleased
entries live in `changelog.d/` until a release is cut, this file lags that
directory by design, and reading both is how you see everything pending. Above
the heading deliberately — `collate-changelog.sh` inserts fragments immediately
after the `## Unreleased` line, so a note underneath would sink below the newest
entries on every release. `CONTRIBUTING.md`'s PR checklist asked for
"CHANGELOG.md updated for user-facing changes" — the one thing the convention
forbids, told to every contributor at the moment they were about to do it; it
now asks for a fragment, beside a new Changelog section. `README.md` names both
locations.

**Enforcement.** `scripts/check-changelogs.sh` gains two rules, because the
convention had been documented in four places and enforced in none — and the
cost of ignoring it never lands on the author, it lands on every other open PR
as a conflict they did not cause:

- A fragment a PR *adds* must name that PR, in its filename **and** in its `###`
  heading. The heading half is the easy mistake — you write the fragment before
  the PR exists, guess the next number, and lose the race — and it is the worse
  one, because a wrong number survives collation and permanently points readers
  at an unrelated PR. Only files this PR adds are checked; the directory holds
  every open PR's fragment.
- A PR may not edit `CHANGELOG.md`. The release collation is exempt and is
  recognised by its own diff — it deletes the fragments it folds in — so it
  needs no ceremony. A `release` label covers the rest (stamping a version
  heading, correcting an entry that already shipped).

Both need the PR number, which CI now passes as `PR_NUMBER`; local runs skip
them rather than inventing one. A PR that bumps no version and records nothing
gets a **notice**, never a failure — release-process changes have shipped
unrecorded for want of a mention at the right moment, but taxing every typo fix
to catch them would produce a guard people learn to route around.

**Currency.** The 52 pending fragments (#877–#935) are collated into
`## Unreleased`, verbatim and newest-first, joining the entries already there up
to #876. `changelog.d/` is back to just its README.
