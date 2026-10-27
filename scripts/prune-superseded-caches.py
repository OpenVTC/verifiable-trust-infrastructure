#!/usr/bin/env python3
"""Delete main's build caches that a newer generation has superseded.

## Why

Every Rust job saves its build cache from main only, under a key ending in two
hashes: the toolchain/environment and `Cargo.lock`
(`v0-rust-test-Linux-x64-1fbdb7d5-94d5cf1e`). A job restores the exact key, or
else the newest cache with its `v0-rust-<job>-<os>-<env>` prefix, so once main
saves a new generation the old one is never restored again. It still counts
against the repository's 25 GB allowance until it expires seven days later.

main's caches are ~21 GB, and `Cargo.lock` changes several times a day. Each
change saves a second ~21 GB generation beside the first, and GitHub evicts the
least recently used caches to make room. That includes caches main has only
just saved. A pull request whose cache was evicted builds from cold, which takes
`Test (workspace)` from ~13 minutes to ~28, against a 30-minute budget: on
2026-10-21, roughly a third of its runs were cancelled at the timeout with
`No cache found.` in the log.

Deleting the superseded generation as soon as the new one exists keeps the
allowance holding one generation, so nothing current is evicted.

## What is deleted

Only caches on `refs/heads/main`, and only keys in a shape this script knows,
grouped by everything except their hashes:

- `v0-rust-<job>-<os>-<arch>-<env:8hex>-<lock:8hex>` (Swatinem/rust-cache,
  through .github/actions/rust-cache). The environment hash is excluded from
  the group too: a toolchain update starts a new generation, and the old one
  can no longer be restored either.
- `<os>-cargo-mobile-<64hex>` (the mobile build's cache).

In each group the newest cache by creation time is kept and the rest deleted.
Any other key is left alone.

    prune-superseded-caches.py <owner/repo> [--dry-run]
    prune-superseded-caches.py --self-test
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

MAIN_REF = "refs/heads/main"

# Group key = the part of the cache key that names the job; the rest is hashes.
KEY_SHAPES = [
    re.compile(r"^(v0-rust-.+)-[0-9a-f]{8}-[0-9a-f]{8}$"),
    re.compile(r"^(.+-cargo-mobile)-[0-9a-f]{64}$"),
]


def group_of(key: str) -> str | None:
    for shape in KEY_SHAPES:
        m = shape.match(key)
        if m:
            return m.group(1)
    return None


def superseded(caches: list[dict]) -> list[dict]:
    """The caches to delete: every main cache in a known shape that is not the
    newest of its group. `caches` are GitHub's cache objects (`id`, `key`,
    `ref`, `created_at`)."""
    newest: dict[str, dict] = {}
    members: dict[str, list[dict]] = {}
    for c in caches:
        if c.get("ref") != MAIN_REF:
            continue
        group = group_of(c["key"])
        if group is None:
            continue
        members.setdefault(group, []).append(c)
        # ISO 8601 timestamps in one zone sort as strings.
        if group not in newest or c["created_at"] > newest[group]["created_at"]:
            newest[group] = c
    return [
        c
        for group, cs in sorted(members.items())
        for c in cs
        if c["id"] != newest[group]["id"]
    ]


def gh(*args: str) -> str:
    return subprocess.run(
        ["gh", *args], check=True, capture_output=True, text=True
    ).stdout


def list_main_caches(repo: str) -> list[dict]:
    out = gh(
        "api",
        "--paginate",
        f"repos/{repo}/actions/caches?ref={MAIN_REF}&per_page=100",
        "--jq",
        ".actions_caches[]",
    )
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    repo = argv[1]
    dry_run = "--dry-run" in argv[2:]

    caches = list_main_caches(repo)
    doomed = superseded(caches)
    freed = sum(c.get("size_in_bytes", 0) for c in doomed)
    print(
        f"{len(caches)} main cache(s); {len(doomed)} superseded, "
        f"{freed / 1e9:.2f} GB{' (dry run)' if dry_run else ''}"
    )
    failed = 0
    for c in doomed:
        print(f"  delete {c['key']}  ({c['created_at']})")
        if dry_run:
            continue
        try:
            gh("api", "-X", "DELETE", f"repos/{repo}/actions/caches/{c['id']}")
        except subprocess.CalledProcessError as e:
            # A cache can expire or be evicted between the listing and here;
            # the next run retries anything genuinely left behind.
            failed += 1
            print(f"    could not delete: {e.stderr.strip()}", file=sys.stderr)
    if failed:
        print(f"{failed} delete(s) failed", file=sys.stderr)
    return 0


def self_test() -> int:
    def cache(i: int, key: str, created: str, ref: str = MAIN_REF) -> dict:
        return {"id": i, "key": key, "ref": ref, "created_at": created}

    caches = [
        # Two lockfile generations of one job: the older goes.
        cache(1, "v0-rust-test-Linux-x64-1fbdb7d5-11111111", "2026-10-21T10:00:00Z"),
        cache(2, "v0-rust-test-Linux-x64-1fbdb7d5-94d5cf1e", "2026-10-21T21:42:00Z"),
        # A toolchain update is a new generation too.
        cache(3, "v0-rust-clippy-Linux-x64-8d99f7be-94d5cf1e", "2026-10-20T09:00:00Z"),
        cache(4, "v0-rust-clippy-Linux-x64-1fbdb7d5-94d5cf1e", "2026-10-21T21:26:00Z"),
        # Job names with hyphens group by the whole name, not a prefix of it.
        cache(5, "v0-rust-test-vtc-Linux-x64-1fbdb7d5-94d5cf1e", "2026-10-21T21:39:00Z"),
        # Mobile caches.
        cache(6, "Linux-cargo-mobile-" + "a" * 64, "2026-10-20T08:00:00Z"),
        cache(7, "Linux-cargo-mobile-" + "b" * 64, "2026-10-21T21:36:00Z"),
        cache(8, "macOS-cargo-mobile-" + "c" * 64, "2026-10-21T21:31:00Z"),
        # Never touched: a pull request's cache, and a key in no known shape.
        cache(9, "v0-rust-test-Linux-x64-1fbdb7d5-22222222", "2026-10-19T00:00:00Z",
              ref="refs/pull/2194/merge"),
        cache(10, "node-cache-Linux-x64-npm-20e1af7a", "2026-10-01T00:00:00Z"),
    ]
    got = sorted(c["id"] for c in superseded(caches))
    checks = [
        ("the older generation of each group is deleted", got == [1, 3, 6]),
        ("a single-member group keeps its cache", 5 not in got and 8 not in got),
        ("pull-request caches are never deleted", 9 not in got),
        ("unknown key shapes are never deleted", 10 not in got),
        ("the newest of a group is never deleted", not {2, 4, 7} & set(got)),
        ("nothing to prune when all are current", superseded([caches[1], caches[3]]) == []),
    ]
    failed = 0
    for name, ok in checks:
        if not ok:
            failed += 1
            print(f"FAIL: {name} (got {got})", file=sys.stderr)
    if failed:
        print(f"{failed} self-test assertion(s) failed", file=sys.stderr)
        return 1
    print("prune-superseded-caches.py: all self-tests pass")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
