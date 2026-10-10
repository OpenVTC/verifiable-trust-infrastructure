#!/usr/bin/env python3
"""Prepare the next release of a named release branch: rc, GA or patch.

release-plz cannot do this part. Its Release PR compares each crate with the
NEWEST version on crates.io, which for a release branch is main's newer line —
so it would derive a version from code the branch does not contain. (Its
publish step is fine: that checks the exact `name@version`, so the same
`publish.yml` job publishes from `release/**` as from main.)

A release branch only ever takes patches, so the rule is simple enough to own:

  * a published crate whose directory — or the root Cargo.toml it inherits
    from — changed since its last tag (`<crate>-v<version>`) gets the next
    patch version;
  * that patch must be API-compatible — `cargo semver-checks --release-type
    patch` against the published version, refused otherwise (a breaking change
    belongs on main, not in a patch release);
  * its CHANGELOG gains an entry from the commits that touched it (git-cliff,
    same `cliff.toml` as main);
  * `RELEASE` moves on: dogwood.rc1 -> rc2 (rc), rcN -> dogwood.0 (ga),
    dogwood.N -> N+1 (patch).

Unpublished crates (vtc-service, vta-enclave …) keep their versions: what
identifies them in a named release is the release tag.

Run on a checkout of `release/<name>`; `.github/workflows/release-branch.yml`
runs it and opens the PR. Merging that PR publishes the bumped crates and tags
the release (`publish.yml`). Needs cargo-semver-checks and git-cliff.

    python3 scripts/prepare-release-branch.py --kind patch [--pr-body out.md]
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/OpenVTC/verifiable-trust-infrastructure"
RELEASE_RE = re.compile(r"^([a-z]+)\.(?:rc(\d+)|(\d+))$")


def run(*cmd, check=True):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, check=check)


def next_release(current, kind):
    m = RELEASE_RE.match(current)
    if not m:
        sys.exit(f"RELEASE holds {current!r}, which is not <name>.rcN or <name>.N")
    name, rc, n = m.group(1), m.group(2), m.group(3)
    if kind == "rc":
        if rc is None:
            sys.exit(f"{current} is already generally available; the next one is a patch")
        return f"{name}.rc{int(rc) + 1}"
    if kind == "ga":
        if rc is None:
            sys.exit(f"{current} is already generally available")
        return f"{name}.0"
    if rc is not None:
        sys.exit(f"{current} is a release candidate; ship it with --kind ga first")
    return f"{name}.{int(n) + 1}"


def next_patch(v):
    major, minor, patch = (int(x) for x in v.split("-")[0].split("."))
    return f"{major}.{minor}.{patch + 1}"


def changed_since_tag(name, version, crate_dir):
    tag = f"{name}-v{version}"
    if run("git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}", check=False).returncode:
        sys.exit(
            f"{name} {version} has no tag {tag}. Every published version is tagged by the "
            f"release job; fetch tags (`git fetch --tags`) or check the release that published it."
        )
    # The root manifest too: `[workspace.dependencies]` is inherited into every
    # crate's published manifest, so a backported floor (a CVE fix) changes them all.
    diff = run("git", "diff", "--quiet", tag, "HEAD", "--", crate_dir, "Cargo.toml", check=False)
    return tag if diff.returncode else None


def set_version(manifest, old, new):
    text = manifest.read_text()
    text2, n = re.subn(rf'^version = "{re.escape(old)}"', f'version = "{new}"', text, count=1, flags=re.M)
    if n != 1:
        sys.exit(f"could not find version = \"{old}\" in {manifest}")
    manifest.write_text(text2)


def render_changelog(name, crate_dir, tag, old, new):
    """The new CHANGELOG.md text, or None if the crate has none.

    cliff.toml's body names `release_link`, which release-plz supplies when it
    renders and plain git-cliff does not, and derives the heading from the tag —
    `<crate>-v<version>` here, not release-plz's bare version. So render the same
    template with both filled in.
    """
    log = ROOT / crate_dir / "CHANGELOG.md"
    if not log.exists():
        return None
    link = f"{REPO_URL}/compare/{name}-v{old}...{name}-v{new}"
    body = tomllib.loads((ROOT / "cliff.toml").read_text())["changelog"]["body"]
    entry = run(
        "git", "cliff",
        "--config", "cliff.toml",
        "--body", body.replace("{{ release_link }}", link).replace(
            '{{ version | trim_start_matches(pat="v") }}', new
        ),
        "--include-path", f"{crate_dir}/**",
        "--tag", f"{name}-v{new}",
        "--strip", "header",
        f"{tag}..HEAD",
    ).stdout.strip()
    text = log.read_text()
    at = text.find("\n## ")
    at = len(text) if at < 0 else at + 1
    return log, text[:at] + entry + "\n\n\n" + text[at:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=["rc", "ga", "patch"], required=True)
    ap.add_argument("--pr-body", help="write a PR description here")
    args = ap.parse_args()

    marker = ROOT / "RELEASE"
    if not marker.exists():
        sys.exit("no RELEASE file: this is not a release branch (scripts/cut-release.py makes one)")
    current = marker.read_text().strip()
    target = next_release(current, args.kind)

    meta = json.loads(run("cargo", "metadata", "--no-deps", "--format-version", "1").stdout)
    bumps = []
    for pkg in sorted(meta["packages"], key=lambda p: p["name"]):
        if pkg.get("publish") is not None:
            continue  # publish = false
        name, old = pkg["name"], pkg["version"]
        manifest = pathlib.Path(pkg["manifest_path"])
        crate_dir = manifest.parent.relative_to(ROOT).as_posix()
        tag = changed_since_tag(name, old, crate_dir)
        if tag:
            bumps.append((name, old, next_patch(old), manifest, crate_dir, tag))

    # Check every candidate before touching anything, so a refusal leaves the
    # tree as it was.
    refused = []
    for name, old, new, *_ in bumps:
        print(f"semver-checks {name}: {old} -> {new} (patch)")
        check = run(
            "cargo", "semver-checks", "-p", name,
            "--baseline-version", old, "--release-type", "patch",
            check=False,
        )
        if check.returncode:
            refused.append(f"{name}: {check.stdout[-2000:]}{check.stderr[-2000:]}")
    if refused:
        print("A patch release cannot carry a breaking change. Revert the backport, or", file=sys.stderr)
        print("rework it so the API stays compatible:\n", file=sys.stderr)
        for r in refused:
            print(r, file=sys.stderr)
        return 1

    # Render every changelog first: a failure here must not leave some
    # manifests bumped and others not.
    logs = [render_changelog(n, d, tag, o, nv) for n, o, nv, _, d, tag in bumps]
    for (name, old, new, manifest, *_), log in zip(bumps, logs):
        set_version(manifest, old, new)
        if log:
            log[0].write_text(log[1])
        print(f"  {name}: {old} -> {new}")
    if bumps:
        run("cargo", "update", "--workspace")
    marker.write_text(target + "\n")
    print(f"RELEASE: {current} -> {target}")

    if args.pr_body:
        lines = [f"Prepares **{target}** on `release/{target.split('.')[0]}`.", ""]
        if bumps:
            lines += ["Crates this publishes (API-compatible patches, checked):", ""]
            lines += [f"- `{n}` {o} → {nv}" for n, o, nv, *_ in bumps]
        else:
            lines += ["No published crate changed; this release ships deployables only."]
        lines += [
            "",
            "Merging publishes the crates above and tags the release (`publish.yml`).",
            "Generated by `scripts/prepare-release-branch.py` — see RELEASES.md.",
        ]
        pathlib.Path(args.pr_body).write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
