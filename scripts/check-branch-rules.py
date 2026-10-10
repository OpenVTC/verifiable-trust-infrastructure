#!/usr/bin/env python3
"""Enforce where a PR may go and what it may change (RELEASES.md).

Run by `.github/workflows/branch-rules.yml` on every PR into `main` or
`release/**`, against the PR's merge commit (HEAD^1 = base, HEAD = merged).

Into `release/<name>`:
  1. Only a bot backport (`backport-<pr>-to-release/<name>`, opened by
     backport.yml), a prep PR (`release-prep/<name>.<n>`), or a PR labelled
     `release-direct` by a maintainer. A fix lands on main first.
  2. Only a prep PR changes a crate's `version`, `RELEASE` or
     `releases/*.toml`.

Into `main`:
  3. Only the release-plz Release PR (`release-plz-*`) or a line-claim PR
     (`release-claim/*`, from cut-release.py --claim) changes a crate's
     `version`. Everyone else: the Release PR assigns versions.
  4. Only a cut PR (`release-cut/*`) changes `releases/*.toml`.
  5. No PR adds a `RELEASE` file: it marks a release branch.

Environment: BASE_REF, HEAD_REF, LABELS (JSON list of label names).
"""

import json
import os
import re
import subprocess
import sys
import tomllib


def git(*args, check=True):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=check).stdout


def package_version(rev, path):
    out = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    if out.returncode:
        return None
    try:
        data = tomllib.loads(out.stdout)
    except tomllib.TOMLDecodeError:
        return None
    return data.get("package", {}).get("version") or data.get("workspace", {}).get("package", {}).get("version")


def main():
    base = os.environ["BASE_REF"]
    head = os.environ["HEAD_REF"]
    labels = set(json.loads(os.environ.get("LABELS") or "[]"))
    changed = git("diff", "--name-only", "HEAD^1", "HEAD").split()

    versions = []
    for path in changed:
        if path == "Cargo.toml" or path.endswith("/Cargo.toml"):
            before, after = package_version("HEAD^1", path), package_version("HEAD", path)
            if before and after and before != after:
                versions.append(f"{path}: {before} -> {after}")
    manifests = [p for p in changed if p.startswith("releases/")]
    release_file = "RELEASE" in changed

    problems = []
    if base.startswith("release/"):
        name = base.removeprefix("release/")
        backport = re.fullmatch(rf"backport-\d+-to-release/{re.escape(name)}", head)
        prep = head.startswith(f"release-prep/{name}.")
        if not (backport or prep or "release-direct" in labels):
            problems.append(
                f"A change reaches {base} by backport, not directly. Open this PR against main "
                f"instead; once it merges, label it `backport {base}` and backport.yml opens the "
                f"cherry-pick here. If the code no longer exists on main, a maintainer adds the "
                f"`release-direct` label, and the description says why."
            )
        if not prep and (versions or manifests or release_file):
            what = versions + manifests + (["RELEASE"] if release_file else [])
            problems.append(
                f"Only the *Prepare a named release* workflow changes versions, RELEASE or "
                f"releases/ on {base}. Revert: " + "; ".join(what)
            )
    elif base == "main":
        if versions and not (head.startswith("release-plz-") or head.startswith("release-claim/")):
            problems.append(
                "A PR never edits a crate's `version =`: the Release PR assigns versions "
                "(RELEASING.md). Revert: " + "; ".join(versions)
            )
        if manifests and not head.startswith("release-cut/"):
            problems.append(
                "releases/*.toml is written by scripts/cut-release.py only. Revert: "
                + ", ".join(manifests)
            )
        if release_file:
            problems.append("RELEASE marks a release branch; it never belongs on main. Remove it.")

    if problems:
        print(f"Branch rules ({head} -> {base}), RELEASES.md:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}\n", file=sys.stderr)
        return 1
    print(f"{head} -> {base}: branch rules hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
