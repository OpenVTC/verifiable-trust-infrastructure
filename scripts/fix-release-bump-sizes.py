#!/usr/bin/env python3
"""Apply what `check-release-bump-sizes.py` asks for, until it passes.

release-plz bumps a dependent by a patch when a dependency takes a breaking
bump. The guard refuses that (rules 2 and 3 in its header), and the fix it
names — raise the crate to its next breaking version — cascades: the raised
crate's own dependents now ask for a new range, so they must be raised too.
Done by hand that is ~30 crates, and release-plz rewrites the Release PR on
every merge to main, so the hand edit is lost the next time.

It also applies what `check-release-line-ownership.py` asks for — the same fix,
for a crate whose proposed version falls in a line a release branch owns.

Run from the root of a checkout of the Release PR branch:

    python3 scripts/fix-release-bump-sizes.py

For each crate the guard names it
  1. sets the crate's version to its next breaking version,
  2. moves every workspace `version = "<old>"` requirement on it,
  3. retitles the crate's newest CHANGELOG entry,
and then refreshes Cargo.lock and re-runs the guard (network: crates.io).
Commit the result onto the Release PR branch.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Both guards name a crate the same way and take the same fix: the second
# refuses a version in a compatibility line a release branch owns (RELEASES.md).
GUARDS = [
    ROOT / "scripts" / "check-release-bump-sizes.py",
    ROOT / "scripts" / "check-release-line-ownership.py",
]
NAMED = re.compile(r"Raise (\S+) to its next breaking version")
MAX_ROUNDS = 8


def next_breaking(v):
    major, minor, patch = (int(x) for x in v.split("-")[0].split("."))
    if major > 0:
        return f"{major + 1}.0.0"
    if minor > 0:
        return f"0.{minor + 1}.0"
    return f"0.0.{patch + 1}"


def req(v):
    """The `major.minor` requirement form the workspace pins internal deps with."""
    major, minor, _ = v.split(".")
    return major if int(major) > 0 else f"{major}.{minor}"


def manifests():
    return [
        p
        for p in ROOT.glob("*/Cargo.toml")
        if "target" not in p.parts and ".claude" not in p.relative_to(ROOT).parts
    ] + [ROOT / "Cargo.toml"]


def bump(name):
    manifest = ROOT / name / "Cargo.toml"
    text = manifest.read_text()
    m = re.search(r'^version = "([^"]+)"', text, re.M)
    old = m.group(1)
    new = next_breaking(old)
    manifest.write_text(text[: m.start()] + f'version = "{new}"' + text[m.end() :])

    # Every internal requirement on it, in the one-line form the workspace uses.
    dep = re.compile(
        rf'^(\s*{re.escape(name)}\s*=\s*\{{[^}}\n]*version\s*=\s*")[^"]+(")', re.M
    )
    for p in manifests():
        t = p.read_text()
        t2 = dep.sub(lambda mm: f"{mm.group(1)}{req(new)}{mm.group(2)}", t)
        if t2 != t:
            p.write_text(t2)

    # The newest changelog entry carries the version in its title and compare link.
    log = ROOT / name / "CHANGELOG.md"
    if log.exists():
        t = log.read_text()
        head = re.search(r"^## \[" + re.escape(old) + r"\]\(.*$", t, re.M)
        if head:
            line = head.group(0)
            fixed = line.replace(f"[{old}]", f"[{new}]").replace(
                f"-v{old})", f"-v{new})"
            )
            t = t.replace(line, fixed, 1)
            log.write_text(t)
    print(f"  {name}: {old} -> {new}")


def main():
    for rnd in range(1, MAX_ROUNDS + 1):
        outs = [
            subprocess.run([sys.executable, str(g)], capture_output=True, text=True, cwd=ROOT)
            for g in GUARDS
        ]
        if all(o.returncode == 0 for o in outs):
            for o in outs:
                print(o.stdout.strip())
            return 0
        stderr = "".join(o.stderr for o in outs)
        names = sorted(set(NAMED.findall(stderr)))
        if not names:
            print(stderr, file=sys.stderr)
            print("the guard failed for a reason this script does not fix", file=sys.stderr)
            return 1
        print(f"round {rnd}: raising {len(names)} crate(s)")
        for n in names:
            bump(n)
        subprocess.run(["cargo", "update", "--workspace"], cwd=ROOT, check=True)
    print("did not converge", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
