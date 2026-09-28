#!/usr/bin/env python3
"""Guard two release invariants that, broken, publish a crate its own earlier
versions cannot build against — and halt the release partway.

Both bit the same release (2026-09-27, #1795): the release job stopped at
vta-backup, and the crates it had already published made the previous
vta-service (0.44.0) unbuildable from a fresh resolve. openvtc had to stay a
version behind until the rest shipped.

## 1. An internal dev-only dependency carries no version  (every PR)

`vta-webvh = { path = "../vta-webvh", version = "0.3" }` in vta-backup's
dev-dependencies made `cargo publish` resolve vta-webvh 0.3 on crates.io. The
release publishes in *normal*-dependency order, so vta-backup went first,
vta-webvh 0.3 did not exist yet, and the run stopped there — stranding every
package after it, vta-service included.

A versionless path dev-dependency is stripped by `cargo publish` and not
counted when ordering, which is the convention `check-workspace-version-reqs.py`
already documents. This makes it a rule for every published member — for a
sibling that is *only* a dev-dependency. One that is also a normal dependency
(vta-service's `vta-sdk` with test features) is ordered by that edge already.

## 2. Moving an internal dependency's floor is a breaking bump  (Release PRs)

vta-audit went 0.3.25 -> 0.3.26 and vta-support 0.5.6 -> 0.5.7 — patches — while
their `vti-common` requirement moved `^0.27` -> `^0.29`. vta-service 0.44.0
requires `vta-audit = "^0.3"`, so a fresh resolve picks 0.3.26 and with it a
second vti-common; the build fails with hundreds of "expected
vti_common::X, found vti_common::X" errors.

release-plz cannot see this. It bumps a dependent by a patch when a dependency
takes a breaking bump, and `cargo-semver-checks` (off for the subsystem crates
anyway) compares a crate's own API, not the compatibility range of what it
depends on. But a workspace crate's dependencies on its siblings are part of
what its dependents resolve, and the siblings re-export each other's types
(CLAUDE.md: "a re-export makes the re-exported crate's version part of your
public API"). So when a published crate moves an internal dependency's
compatibility range, it must itself take a compatibility-breaking bump.

This runs only for packages whose Cargo.toml version is not yet on crates.io —
i.e. what a Release PR is about to publish. On a feature PR every version is
already published and the check is a no-op.

## Fixing a failure

- Rule 1: drop `version` from the dev-dependency, keeping `path`.
- Rule 2: in the Release PR, raise the named crate to the next breaking version
  it names (e.g. 0.3.26 -> 0.4.0), and update its dependents' requirements (the
  workspace-version-reqs guard will point at any you miss).
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

UA = {"User-Agent": "vti-release-guard (github.com/OpenVTC/verifiable-trust-infrastructure)"}


def parts(v):
    """Numeric components of a version (pre-release suffix dropped), padded to 3."""
    p = [int(x) for x in v.split("-")[0].split(".")]
    return (p + [0, 0, 0])[:3]


def compat(v):
    """The caret compatibility class of a version or bare requirement.

    Cargo's rule: everything up to and including the leftmost non-zero
    component must match. 0.29.1 -> (0, 29); 1.4.2 -> (1,); 0.0.3 -> (0, 0, 3).
    """
    p = parts(v)
    idx = next((i for i, x in enumerate(p) if x != 0), 2)
    return tuple(p[: idx + 1])


def req_compat(req):
    """Compatibility class of a caret requirement, or None for `*`/other forms."""
    if req == "*":
        return None
    if req.startswith("^"):
        return compat(req[1:])
    return None


def get(url):
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if attempt == 3:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == 3:
                raise
        time.sleep(2 * (attempt + 1))
    return None


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
    members = {p["name"]: p for p in meta["packages"]}
    # `publish: []` is `publish = false`; `None` means publishable to crates.io.
    published = {n: p for n, p in members.items() if p.get("publish") is None}

    problems = []

    # ── Rule 1 ──────────────────────────────────────────────────────────
    for name, pkg in sorted(published.items()):
        # A sibling that is also a normal (or build) dependency is already
        # ordered before this crate, so its dev entry — typically the same crate
        # with test features — cannot halt the release.
        ordered = {
            d["name"] for d in pkg["dependencies"] if d.get("kind") in (None, "build")
        }
        for dep in pkg["dependencies"]:
            if dep.get("kind") != "dev" or dep["name"] not in members or not dep.get("path"):
                continue
            if dep["name"] in ordered:
                continue
            if dep["req"] != "*":
                problems.append(
                    f"{name}: dev-dependency `{dep['name']}` carries a version (`{dep['req']}`). "
                    f"Drop the `version`, keep the `path` — a versioned internal dev-dependency "
                    f"must already be on crates.io when {name} publishes, and the release orders "
                    f"by normal dependencies only, so it can halt the release (#1795)."
                )

    # ── Rule 2 ──────────────────────────────────────────────────────────
    for name, pkg in sorted(published.items()):
        current = pkg["version"]
        info = get(f"https://crates.io/api/v1/crates/{name}")
        if info is None:
            continue  # a crate's first release has no baseline to break
        versions = [v for v in info["versions"] if not v["yanked"]]
        if any(v["num"] == current for v in info["versions"]):
            continue  # already published — nothing is about to ship
        older = [v["num"] for v in versions if parts(v["num"]) < parts(current)]
        if not older:
            continue
        baseline = max(older, key=parts)
        if compat(baseline) != compat(current):
            continue  # already a breaking bump; any dependency move is covered
        deps = get(f"https://crates.io/api/v1/crates/{name}/{baseline}/dependencies")
        if deps is None:
            continue
        base_reqs = {
            d["crate_id"]: d["req"]
            for d in deps["dependencies"]
            if d["kind"] in ("normal", "build") and d["crate_id"] in members
        }
        for dep in pkg["dependencies"]:
            if dep.get("kind") not in (None, "build") or dep["name"] not in members:
                continue
            before = base_reqs.get(dep["name"])
            if before is None:
                continue
            b, a = req_compat(before), req_compat(dep["req"])
            if b is not None and a is not None and b != a:
                problems.append(
                    f"{name} {baseline} -> {current} is not a breaking bump, but it moves "
                    f"`{dep['name']}` from `{before}` to `{dep['req']}`. Every published "
                    f"dependent that asks for `{name}` by caret would resolve this release "
                    f"and a second `{dep['name']}` (vta-service 0.44.0, #1795). Raise {name} "
                    f"to its next breaking version in this Release PR."
                )
        time.sleep(0.5)

    if problems:
        print("Release guard failed:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}\n", file=sys.stderr)
        print("See the header of scripts/check-release-bump-sizes.py.", file=sys.stderr)
        return 1
    print(f"release guard: {len(published)} published members checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
