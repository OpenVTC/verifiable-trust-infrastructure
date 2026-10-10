#!/usr/bin/env python3
"""Refuse a main-branch release that publishes into a release branch's line.

A named release (`release/dogwood`) publishes crate patches from its own branch
(RELEASES.md). It can only do that while the patch numbers in its compatibility
line are its own: Dogwood cut `vta-sdk` at 0.38.2, so 0.38.3, 0.38.4 … belong to
`release/dogwood`. If main later publishes `vta-sdk` 0.38.3, Dogwood's next patch
has no version to take — and a consumer on `^0.38` silently receives main's
features as a "patch".

So every compatibility line recorded in `releases/*.toml` is closed to main. On
a Release PR, any published crate whose proposed version (not yet on crates.io)
falls in a recorded line fails here.

Lines are never reopened, even after a release reaches end of life: main is
always past them by then, so keeping them closed costs nothing and makes
reopening one impossible by accident.

## Fixing a failure

Run `python3 scripts/fix-release-bump-sizes.py` on the Release PR branch. It
raises each crate this names to its next breaking version (0.38.3 -> 0.39.0)
and moves its dependents' requirements, then re-runs the guards.

On a release branch the `RELEASE` file names the release, and its own lines
are open to it: that is where its patches come from.

This runs only for packages whose Cargo.toml version is not yet on crates.io,
so on a feature PR it is a no-op.
"""

import json
import pathlib
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
UA = {"User-Agent": "vti-release-guard (github.com/OpenVTC/verifiable-trust-infrastructure)"}


def parts(v):
    p = [int(x) for x in v.split("-")[0].split(".")]
    return (p + [0, 0, 0])[:3]


def compat(v):
    """Caret compatibility class, as in check-release-bump-sizes.py."""
    p = parts(v)
    idx = next((i for i, x in enumerate(p) if x != 0), 2)
    return tuple(p[: idx + 1])


def published_on_crates_io(name, version):
    """Whether `name@version` is on crates.io, retried as check-release-bump-sizes.py does."""
    url = f"https://crates.io/api/v1/crates/{name}/{version}"
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30):
                return True
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
            if attempt == 3:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == 3:
                raise
        time.sleep(2 * (attempt + 1))
    return False


def owned_lines():
    """{crate: [(line, release name)]} from every release manifest."""
    owned = {}
    for manifest in sorted((ROOT / "releases").glob("*.toml")):
        data = tomllib.loads(manifest.read_text())
        release = data["release"]["name"]
        for crate, version in data.get("crates", {}).items():
            owned.setdefault(crate, []).append((compat(version), release, version))
    return owned


def main():
    owned = owned_lines()
    marker = ROOT / "RELEASE"
    this_release = marker.read_text().strip().split(".")[0] if marker.exists() else None
    if not owned:
        print("no release manifests under releases/ — nothing to check")
        return 0

    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            capture_output=True,
            text=True,
            check=True,
            cwd=ROOT,
        ).stdout
    )
    problems = []
    for pkg in meta["packages"]:
        if pkg.get("publish") is not None:
            continue  # publish = false
        name, version = pkg["name"], pkg["version"]
        lines = [
            o
            for o in owned.get(name, [])
            if o[0] == compat(version) and o[1] != this_release
        ]
        if not lines or published_on_crates_io(name, version):
            continue
        for _, release, cut in lines:
            problems.append(
                f"{name} {version} is in the {'.'.join(map(str, compat(version)))} line, which "
                f"release/{release} owns (cut at {cut}). Raise {name} to its next breaking "
                f"version — `python3 scripts/fix-release-bump-sizes.py` does it."
            )

    if problems:
        print("Release-line ownership (RELEASES.md):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("no proposed version falls in a line a release branch owns")
    return 0


if __name__ == "__main__":
    sys.exit(main())
