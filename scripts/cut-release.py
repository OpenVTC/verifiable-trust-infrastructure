#!/usr/bin/env python3
"""Cut a named release: create `release/<name>` and record what it owns.

    python3 scripts/cut-release.py dogwood [--lts] [--from origin/nightly] [--dry-run]

Run by the release manager from a clean checkout with push access. It:

  1. resolves the source commit — `origin/nightly` by default, the last main
     commit the full CI suite passed (RELEASES.md);
  2. refuses unless every published crate's version at that commit is on
     crates.io — an unpublished one means a Release PR merged and the release
     job has not finished, and both main and the branch would try to publish it;
  3. writes `releases/<name>.toml`, the manifest: each published crate's version
     at the cut. Its compatibility line (0.38 for 0.38.2) now belongs to the
     release branch, and `check-release-line-ownership.py` closes it to main;
  4. pushes `release/<name>` = source commit + one commit adding the manifest,
     `RELEASE` (`<name>.rc1`) and `git_release_latest = false` in
     release-plz.toml, so a patch's GitHub Releases never displace main's as
     "latest". `publish.yml` then tags `<name>.rc1`;
  5. opens a PR to main adding the manifest. **Merge it before main's next
     Release PR** — until it lands, main's guard does not know the lines are
     owned;
  6. creates the `backport release/<name>` label backport.yml reads.

It also refuses when a crate's version at the source commit is in a line an
earlier release already owns: a crate unchanged since that cut. Two branches in
one line would want the same patch number. `--claim` opens the PR that fixes
it — those crates (and whatever depends on them) take their next breaking
version on main, with a changelog entry saying why. Merge it, let the release
job publish and `nightly` move past it, then cut again.
"""

import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
UA = {"User-Agent": "vti-release-cut (github.com/OpenVTC/verifiable-trust-infrastructure)"}


def git(*args, cwd=ROOT, check=True):
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd, check=check)


def on_crates_io(name, version):
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


def compat(v):
    """Caret compatibility class, as in check-release-bump-sizes.py."""
    p = ([int(x) for x in v.split("-")[0].split(".")] + [0, 0, 0])[:3]
    idx = next((i for i, x in enumerate(p) if x != 0), 2)
    return tuple(p[: idx + 1])


def owned_on_main():
    """{crate: [(line, release)]} from every releases/*.toml on origin/main."""
    owned = {}
    files = git("ls-tree", "--name-only", "origin/main", "releases/", check=False).stdout.split()
    for f in files:
        if not f.endswith(".toml"):
            continue
        data = tomllib.loads(git("show", f"origin/main:{f}").stdout)
        for crate, version in data.get("crates", {}).items():
            owned.setdefault(crate, []).append((compat(version), data["release"]["name"]))
    return owned


def claim(name, crates):
    """Open the PR on main that gives `crates` new compatibility lines."""
    with tempfile.TemporaryDirectory(prefix=f"claim-{name}-") as tmp:
        wt = pathlib.Path(tmp) / "wt"
        pr_branch = f"release-claim/{name}"
        git("worktree", "add", "--quiet", "-B", pr_branch, str(wt), "origin/main")
        try:
            subprocess.run(
                [sys.executable, "scripts/fix-release-bump-sizes.py",
                 "--raise", *crates, "--claim", name],
                cwd=wt, check=True,
            )
            git("add", "-A", cwd=wt)
            git("commit", "--quiet", "-s", "-m",
                f"chore(release): open new version lines before the {name} cut", cwd=wt)
            git("push", "--quiet", "origin", f"HEAD:refs/heads/{pr_branch}", cwd=wt)
            subprocess.run(
                [
                    "gh", "pr", "create", "--base", "main", "--head", pr_branch,
                    "--title", f"chore(release): open new version lines before the {name} cut",
                    "--body",
                    "These crates have not changed since an earlier release branch was cut, so "
                    f"`release/{name}` would share their compatibility line with it and the two "
                    "branches would want the same patch numbers. Each takes its next breaking "
                    "version (dependents follow), with a changelog entry saying why.\n\n"
                    "Merging publishes them. Once `nightly` has moved past this commit, run "
                    f"`scripts/cut-release.py {name}` again.\n\nSee RELEASES.md.",
                ],
                cwd=wt, check=True,
            )
        finally:
            git("worktree", "remove", "--force", str(wt), check=False)
            git("branch", "-D", pr_branch, check=False)


def manifest_text(name, support, sha, crates):
    lines = [
        f"# Named release {name}: what release/{name} was cut from, and the",
        "# compatibility line of every published crate it owns. Written by",
        "# scripts/cut-release.py; read by scripts/check-release-line-ownership.py.",
        "# Dates and support status live in RELEASES.md.",
        "",
        "[release]",
        f'name = "{name}"',
        f'support = "{support}"',
        f'cut = "{datetime.date.today().isoformat()}"',
        f'cut_from = "{sha}"',
        "",
        "[crates]",
    ]
    lines += [f'{c} = "{v}"' for c, v in sorted(crates.items())]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name", help="lower-case release name, e.g. dogwood")
    ap.add_argument("--lts", action="store_true", help="the maintainers have designated this release LTS (RELEASES.md)")
    ap.add_argument("--from", dest="source", default="origin/nightly")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--claim", action="store_true",
                    help="if crates share a line with an earlier release, open the PR on main that fixes it")
    args = ap.parse_args()

    name = args.name
    if not re.fullmatch(r"[a-z]+", name):
        sys.exit("a release name is lower-case letters only (it becomes release/<name> and <name>.N tags)")
    branch = f"release/{name}"
    manifest_rel = f"releases/{name}.toml"

    git("fetch", "--quiet", "--tags", "origin")
    if git("ls-remote", "--exit-code", "--heads", "origin", branch, check=False).returncode == 0:
        sys.exit(f"{branch} already exists")
    if (ROOT / manifest_rel).exists() or git(
        "cat-file", "-e", f"origin/main:{manifest_rel}", check=False
    ).returncode == 0:
        sys.exit(f"{manifest_rel} already exists — names are never reused")
    sha = git("rev-parse", "--verify", f"{args.source}^{{commit}}").stdout.strip()
    print(f"cutting {branch} from {args.source} = {sha}")

    with tempfile.TemporaryDirectory(prefix=f"cut-{name}-") as tmp:
        wt = pathlib.Path(tmp) / "wt"
        git("worktree", "add", "--quiet", "--detach", str(wt), sha)
        try:
            meta = json.loads(
                subprocess.run(
                    ["cargo", "metadata", "--no-deps", "--format-version", "1"],
                    capture_output=True, text=True, cwd=wt, check=True,
                ).stdout
            )
            crates = {
                p["name"]: p["version"] for p in meta["packages"] if p.get("publish") is None
            }
            missing = [f"{c} {v}" for c, v in sorted(crates.items()) if not on_crates_io(c, v)]
            if missing:
                sys.exit(
                    "not on crates.io yet — let main's release job finish, or cut from an "
                    "earlier commit:\n  " + "\n  ".join(missing)
                )
            owned = owned_on_main()
            shared = sorted(
                c for c, v in crates.items()
                if any(line == compat(v) for line, _ in owned.get(c, []))
            )
            if shared:
                lines = [
                    f"{c} {crates[c]} (line owned by release/"
                    f"{', release/'.join(r for l, r in owned[c] if l == compat(crates[c]))})"
                    for c in shared
                ]
                print("these crates have not changed since an earlier release was cut, so "
                      f"release/{name} would share their line:\n  " + "\n  ".join(lines))
                if args.claim and not args.dry_run:
                    claim(name, shared)
                    return 0
                sys.exit("re-run with --claim to open the PR on main that gives them new lines")
            text = manifest_text(name, "lts" if args.lts else "standard", sha, crates)
            print(text)
            if args.dry_run:
                print("dry run: nothing created")
                return 0

            # ── the release branch ──────────────────────────────────────
            (wt / "releases").mkdir(exist_ok=True)
            (wt / manifest_rel).write_text(text)
            (wt / "RELEASE").write_text(f"{name}.rc1\n")
            cfg = wt / "release-plz.toml"
            cfg_text = cfg.read_text()
            cfg_text, n = re.subn(
                r"^git_release_enable = true$",
                "git_release_enable = true\n"
                "# A release branch: its crate releases must not become GitHub's\n"
                "# \"latest\", which belongs to main's line. Set by cut-release.py.\n"
                "git_release_latest = false",
                cfg_text, count=1, flags=re.M,
            )
            if n != 1:
                sys.exit("release-plz.toml: could not find `git_release_enable = true`")
            cfg.write_text(cfg_text)
            git("add", manifest_rel, "RELEASE", "release-plz.toml", cwd=wt)
            git("commit", "--quiet", "-s", "-m", f"chore(release): cut {name}", cwd=wt)
            git("push", "--quiet", "origin", f"HEAD:refs/heads/{branch}", cwd=wt)
            print(f"pushed {branch}")

            # ── the manifest on main ────────────────────────────────────
            pr_branch = f"release-cut/{name}"
            git("checkout", "--quiet", "-B", pr_branch, "origin/main", cwd=wt)
            (wt / "releases").mkdir(exist_ok=True)
            (wt / manifest_rel).write_text(text)
            git("add", manifest_rel, cwd=wt)
            git("commit", "--quiet", "-s", "-m", f"chore(release): record the {name} cut", cwd=wt)
            git("push", "--quiet", "origin", f"HEAD:refs/heads/{pr_branch}", cwd=wt)
            subprocess.run(
                [
                    "gh", "pr", "create", "--base", "main", "--head", pr_branch,
                    "--title", f"chore(release): record the {name} cut",
                    "--body",
                    f"Adds `{manifest_rel}`: `release/{name}` was cut from `{sha}` and now owns "
                    f"the compatibility line of every published crate listed. Merge before "
                    f"main's next Release PR, so `check-release-line-ownership.py` holds main "
                    f"off those lines.\n\nAlso add {name} to the schedule table in RELEASES.md.",
                ],
                cwd=wt, check=True,
            )
            subprocess.run(
                ["gh", "label", "create", f"backport release/{name}", "--force",
                 "--color", "c5def5",
                 "--description", f"Merged to main; cherry-pick onto release/{name} (backport.yml)"],
                check=True,
            )
        finally:
            git("worktree", "remove", "--force", str(wt), check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
