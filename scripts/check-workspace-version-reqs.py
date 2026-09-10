#!/usr/bin/env python3
"""Guard against a workspace member requiring a version of a sibling that the
sibling no longer is.

This is the failure that blocked EVERY release for five hours on 2026-09-10, and
the one the `check-version-bumps.sh` this file sits beside used to cover before
release-plz took over version bumping.

## What happened

`chore: release (#1336)` bumped `vta-sdk` 0.34.1 -> 0.35.0. In the same commit,
in the same file, it updated one of `room-host`'s requirements and not the other:

    -vti-rooms = { path = "../vti-rooms", version = "0.1" }
    +vti-rooms = { path = "../vti-rooms", version = "0.2" }
     vta-sdk   = { path = "../vta-sdk", version = "0.34", optional = true }
                                                  ^^^^^^ left behind

The difference between the two is `optional = true`. release-plz maintains a
`publish = false` member's dependency requirements — its own config in
`release-plz.toml` says so, and `vti-rooms` above is the proof — but it did not
maintain the optional one.

The resulting tree does not resolve, and not just for publishing: `cargo
metadata` and `cargo check -p room-host` both fail on it. Every release-plz run
after that failed, because release-plz clones the last-release commit to diff
the package contents and cannot run `cargo package` there. The error surfaces
six levels deep, names `cargo package`, and says nothing about a manifest:

    failed to select a version for the requirement `vta-sdk = "^0.34"`
    candidate versions found which didn't match: 0.35.0
    required by package `room-host v0.1.0`

Recovering needed a hand-edited version bump, because the baseline only moves
when a version changes and release-plz could not get far enough to change one.

## What this checks

For every dependency that is a **path** dependency on another workspace member
and declares a `version`, the sibling's actual version must satisfy it. Optional
and dev dependencies included — the optional one is the whole reason this exists.

A path dependency with no `version` (`req == "*"`) is skipped and is not a
defect: a dev-dependency deliberately carries no version so release-plz does not
count the edge when ordering publishes.

## Why `cargo metadata --no-deps`

Because it does not resolve the graph, it still works on exactly the broken tree
this guard is for — verified against f43d26eb, where every other cargo command
fails. A guard that cannot run on the failure it detects would be useless.
"""

import json
import subprocess
import sys


def parts(v):
    """Numeric components of a version, pre-release suffix dropped."""
    return [int(x) for x in v.split("-")[0].split(".")]


def caret_ok(req, version):
    """Does `version` satisfy the caret requirement `req` (given without `^`)?

    Cargo's rule: the leftmost non-zero component of the requirement is the one
    that may not change. `^0.34` admits 0.34.x and rejects 0.35.0, which is the
    case that bit us.
    """
    r, v = parts(req), parts(version)
    r += [0] * (3 - len(r))
    v += [0] * (3 - len(v))
    if v < r:
        return False
    idx = next((i for i, x in enumerate(r) if x != 0), len(r) - 1)
    upper = r[:idx] + [r[idx] + 1] + [0] * (2 - idx)
    return v < upper


def main():
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        print("cargo metadata --no-deps failed:", file=sys.stderr)
        print(out.stderr, file=sys.stderr)
        return 2

    meta = json.loads(out.stdout)
    versions = {p["name"]: p["version"] for p in meta["packages"]}

    problems = []
    unknown = []
    for pkg in meta["packages"]:
        for dep in pkg["dependencies"]:
            name = dep["name"]
            if name not in versions or not dep.get("path"):
                continue
            req = dep["req"]
            if req == "*":
                continue
            if not req.startswith("^"):
                unknown.append((pkg["name"], name, req))
                continue
            if not caret_ok(req[1:], versions[name]):
                problems.append(
                    (pkg["name"], name, req, versions[name], dep.get("optional", False))
                )

    if unknown:
        print("Requirement forms this guard does not understand:\n", file=sys.stderr)
        for who, dep, req in unknown:
            print(f"  {who} -> {dep} = \"{req}\"", file=sys.stderr)
        print(
            "\nOnly `*` and caret (`^x.y`) are handled. Extend caret_ok() rather than\n"
            "widening the skip — a form that is silently skipped is a form this guard\n"
            "does not cover.",
            file=sys.stderr,
        )
        return 1

    if problems:
        print(
            "A workspace member requires a version of a sibling that the sibling is not:\n",
            file=sys.stderr,
        )
        for who, dep, req, actual, optional in problems:
            opt = "  (optional — the kind release-plz missed in #1336)" if optional else ""
            print(f"  {who} requires {dep} = \"{req}\", but {dep} is {actual}{opt}", file=sys.stderr)
        print(
            "\nThis tree does not resolve: `cargo metadata` and `cargo check` fail on it,\n"
            "and release-plz cannot diff a commit containing it — which blocks every\n"
            "release until someone hand-edits a version to move the baseline.\n\n"
            "Fix: update the requirement to match the sibling's current version.",
            file=sys.stderr,
        )
        return 1

    print(f"Workspace version requirements agree ({len(versions)} members).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
