#!/usr/bin/env python3
"""Classify a `cargo semver-checks` build failure, and say whose it is.

`cargo-semver-checks` builds rustdoc JSON twice per crate — once for the
workspace copy (`current`) and once for the crates.io copy (`baseline`) — and
reports *any* failure of either the same way:

    error: running cargo-doc on crate 'vta-service' failed with output:
    ...
    error: failed to build rustdoc for crate vta-service v0.39.0

Three different defects hide behind that one sentence, and they have three
different owners:

  1. the PUBLISHED crate's own source does not build — a real production
     defect, because the baseline is the crate exactly as a consumer receives
     it from the registry;
  2. the WORKSPACE crate's own source does not build — an ordinary red build,
     nothing to do with the registry;
  3. a DEPENDENCY does not build at the version this build resolved. The
     baseline has no lockfile, so it takes the newest semver-compatible
     release of every dependency, including ones our own `Cargo.lock` pins
     below. Our crate is fine; somebody else's release is not.

`semver-report.sh` used to call all three (1) and print a reproduction command
with no features on it. For the case that motivated this file — issue #1667 —
every part of that was wrong: `vta-service` 0.39.0 built fine, the failure was
`affinidi-messaging-mediator` 0.28.33 failing to compile after
`affinidi-messaging-mediator-common` added a field to the exhaustive public
struct `PubSubRecord` in a compatible release, and the printed reproduction
(`cargo add vta-service && cargo build`, default features) did not reach the
dependency at all because it arrives via the optional `transport-harness`
feature. The report said our published artifact was broken; it was not, and the
command offered to prove it said so too.

A misattributed red is worse than a red, because the next person spends the
diagnosis again. This file does the attribution once.

Usage:
    semver-build-failure.py <semver.log>   # exit 1 + ::error:: if a build failed
    semver-build-failure.py --self-test    # check the classifier against fixtures
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field

BUILDING = re.compile(r"^\s*Building (?P<crate>\S+) v(?P<version>\S+) \((?P<side>current|baseline)\)\s*$")
CARGO_DOC_FAILED = re.compile(r"^error: running cargo-doc on crate '(?P<crate>[^']+)' failed")
RUSTDOC_FAILED = re.compile(r"^error: failed to build rustdoc for crate (?P<crate>\S+) v(?P<version>\S+)")
COULD_NOT_COMPILE = re.compile(r"^error: could not compile `(?P<pkg>[^`]+)`")
# `  --> /…/registry/src/index.crates.io-<hash>/<name>-<version>/src/…`
REGISTRY_PATH = re.compile(r"registry/src/[^/]+/(?P<pkg>[a-zA-Z0-9_.-]+?)-(?P<version>\d+\.\d+\.\d+[^/]*)/")
REPRO_LINE = re.compile(r"^\s+(cargo (new|add|check|doc)\b.*|cd example &&|echo '\[workspace\]' >> Cargo\.toml &&)\s*$")


@dataclass
class Failure:
    """One crate whose rustdoc build failed, and what actually broke inside it."""

    crate: str
    version: str | None = None
    side: str | None = None  # "current" | "baseline" | None if the log never said
    # Packages rustc gave up on, in the order it gave up, excluding the crate
    # under test. A registry path pins the version; a workspace path does not.
    culprits: dict[str, str | None] = field(default_factory=dict)
    repro: list[str] = field(default_factory=list)


def classify(lines: list[str]) -> list[Failure]:
    """Return one Failure per crate whose rustdoc build failed, in log order."""
    failures: list[Failure] = []
    by_crate: dict[str, Failure] = {}
    last_build: tuple[str, str, str] | None = None
    # While inside the captured `cargo doc` output, `error: could not compile`
    # lines belong to the failure that opened the capture.
    current: Failure | None = None
    collecting_repro = False

    for line in lines:
        stripped = line.rstrip("\n")

        m = BUILDING.match(stripped)
        if m:
            last_build = (m["crate"], m["version"], m["side"])
            # The tool has moved on to the next build, so whatever it was
            # printing about the last failure has ended.
            collecting_repro = False
            continue

        m = CARGO_DOC_FAILED.match(stripped)
        if m:
            crate = m["crate"]
            failure = by_crate.get(crate)
            if failure is None:
                failure = Failure(crate=crate)
                by_crate[crate] = failure
                failures.append(failure)
            if last_build and last_build[0] == crate:
                failure.version = failure.version or last_build[1]
                failure.side = failure.side or last_build[2]
            current = failure
            collecting_repro = False
            continue

        m = RUSTDOC_FAILED.match(stripped)
        if m:
            crate = m["crate"]
            failure = by_crate.get(crate)
            if failure is None:
                failure = Failure(crate=crate)
                by_crate[crate] = failure
                failures.append(failure)
            failure.version = failure.version or m["version"]
            if failure.side is None and last_build and last_build[0] == crate:
                failure.side = last_build[2]
            current = failure
            # The tool prints its own reproduction command right after this,
            # feature flags included. It is strictly better than anything this
            # script could reconstruct, so it is what gets shown.
            collecting_repro = True
            continue

        if current is not None:
            m = COULD_NOT_COMPILE.match(stripped)
            if m and m["pkg"] != current.crate:
                current.culprits.setdefault(m["pkg"], None)
            m = REGISTRY_PATH.search(stripped)
            if m and m["pkg"] in current.culprits and current.culprits[m["pkg"]] is None:
                current.culprits[m["pkg"]] = m["version"]

        if collecting_repro and current is not None:
            if REPRO_LINE.match(stripped):
                current.repro.append(stripped.strip())
            elif stripped.strip() and not stripped.startswith(("      ", "note:")):
                collecting_repro = False

    # A registry path can appear before rustc names the package it gave up on
    # (the diagnostic comes first, the summary line last), so make a second
    # pass for versions the streaming pass missed.
    for failure in failures:
        if any(v is None for v in failure.culprits.values()):
            for line in lines:
                m = REGISTRY_PATH.search(line)
                if m and failure.culprits.get(m["pkg"], "sentinel") is None:
                    failure.culprits[m["pkg"]] = m["version"]
    return failures


def _named(culprits: dict[str, str | None]) -> str:
    return ", ".join(f"{p} {v}" if v else p for p, v in culprits.items())


def render(failure: Failure) -> str:
    """The `::error::` line for one failure. One sentence per thing to do."""
    where = f"{failure.crate} v{failure.version}" if failure.version else failure.crate

    if failure.culprits:
        who = _named(failure.culprits)
        side = failure.side or "unknown-side"
        msg = (
            f"BUILD FAILED IN A DEPENDENCY, NOT IN {failure.crate}: rustdoc for "
            f"{where} ({side}) could not be built because {who} does not compile. "
            f"{failure.crate}'s own source is not implicated — a different package "
            "in its graph is. "
        )
        if failure.side == "baseline":
            msg += (
                "The baseline resolves WITHOUT a lockfile, so it takes the newest "
                "semver-compatible release of every dependency; our own builds stay "
                "green because Cargo.lock pins an older one. A consumer doing a fresh "
                "`cargo add` resolves the same way this did, so this is real for them "
                "until the upstream release is fixed or yanked. "
            )
        msg += (
            "The fix is upstream — a corrected release of the named package, or a "
            "raised floor on it — NOT a change to this workspace. Do not read this "
            "as 'our published crate is broken'."
        )
        return msg

    if failure.side == "baseline":
        msg = (
            f"PUBLISHED CRATE DOES NOT BUILD: {where} -- the semver baseline is the "
            "published crate as a consumer receives it, so a baseline that fails to "
            "build means consumers cannot build it either. This is not 'the check "
            "could not run'; it is the check reporting a broken artifact on crates.io."
        )
    elif failure.side == "current":
        msg = (
            f"THE WORKSPACE COPY OF {failure.crate} DOES NOT BUILD under the feature "
            "set cargo-semver-checks uses, which is wider than any other CI job's. "
            "This is an ordinary red build in this branch, not a registry problem — "
            "the published crate is not implicated."
        )
    else:
        msg = (
            f"RUSTDOC BUILD FAILED for {where}, and the log did not say whether it was "
            "the workspace copy or the published baseline. Read the captured cargo "
            "output above for the compile error."
        )

    if failure.repro:
        msg += " Reproduce: " + " ".join(failure.repro)
    return msg


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--self-test":
        return self_test()

    with open(argv[1], encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    failures = classify(lines)
    if not failures:
        return 0
    for failure in failures:
        print(f"::error::{render(failure)}")
    return 1


# --------------------------------------------------------------------------
# Fixtures. Trimmed from real `cargo semver-checks` output — the dependency
# case is the one from issue #1667, kept verbatim in shape so a change to the
# tool's wording breaks this rather than the next incident's diagnosis.
# --------------------------------------------------------------------------

DEPENDENCY_FAILURE = """\
    Building vta-sdk v0.49.0 (baseline)
       Built [ 129.373s] (baseline)
    Finished [ 267.713s] vta-sdk
    Building vta-service v0.39.0 (current)
       Built [ 190.388s] (current)
     Parsing vta-service v0.39.0 (current)
      Parsed [   0.278s] (current)
    Building vta-service v0.39.0 (baseline)
error: running cargo-doc on crate 'vta-service' failed with output:
-----
    Checking affinidi-messaging-mediator v0.28.33
error[E0027]: pattern does not mention field `verbatim`
   --> /home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/affinidi-messaging-mediator-0.28.33/src/tasks/websocket_streaming.rs:510:13
    |
510 |           let PubSubRecord {
    |  _____________^
error: could not compile `affinidi-messaging-mediator` (lib) due to 2 previous errors
warning: build failed, waiting for other jobs to finish...

-----

error: failed to build rustdoc for crate vta-service v0.39.0
note: this is usually due to a compilation error in the crate,
      and is unlikely to be a bug in cargo-semver-checks
note: the following command can be used to reproduce the error:
      cargo new --lib example &&
          cd example &&
          echo '[workspace]' >> Cargo.toml &&
          cargo add vta-service@=0.39.0 --features default,tee,transport-harness &&
          cargo check &&
          cargo doc
"""

OWN_SOURCE_BASELINE_FAILURE = """\
    Building vta-service v0.39.0 (current)
       Built [ 190.388s] (current)
    Building vta-service v0.39.0 (baseline)
error: running cargo-doc on crate 'vta-service' failed with output:
-----
    Checking vta-service v0.39.0
error[E0432]: unresolved import `crate::gone`
   --> /home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/vta-service-0.39.0/src/lib.rs:3:5
error: could not compile `vta-service` (lib) due to 1 previous error

-----

error: failed to build rustdoc for crate vta-service v0.39.0
"""

OWN_SOURCE_CURRENT_FAILURE = """\
    Building vta-service v0.39.0 (current)
error: running cargo-doc on crate 'vta-service' failed with output:
-----
    Checking vta-service v0.39.0 (/home/runner/work/x/vta-service)
error: could not compile `vta-service` (lib) due to 1 previous error

-----

error: failed to build rustdoc for crate vta-service v0.39.0
"""

CLEAN_RUN = """\
    Building vti-common v0.23.0 (current)
       Built [ 130.583s] (current)
    Building vti-common v0.23.0 (baseline)
       Built [ 128.001s] (baseline)
    Checking vti-common v0.23.0 -> v0.23.0 (no change; assume minor)
     Checked [   0.087s] 196 checks: 196 pass, 58 skip
     Summary no semver update required
    Finished [ 269.893s] vti-common
"""


def self_test() -> int:
    failed = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal failed
        if not cond:
            failed += 1
            print(f"FAIL {name}{': ' + detail if detail else ''}", file=sys.stderr)

    # 1. A dependency failure must NOT be reported as our published crate breaking.
    fs = classify(DEPENDENCY_FAILURE.splitlines(keepends=True))
    check("dependency: one failure", len(fs) == 1, f"got {len(fs)}")
    if fs:
        f = fs[0]
        check("dependency: crate", f.crate == "vta-service", f.crate)
        check("dependency: version", f.version == "0.39.0", str(f.version))
        check("dependency: side", f.side == "baseline", str(f.side))
        check(
            "dependency: culprit named with version",
            f.culprits == {"affinidi-messaging-mediator": "0.28.33"},
            str(f.culprits),
        )
        text = render(f)
        check("dependency: attributes to the dependency", "NOT IN vta-service" in text, text)
        check(
            "dependency: does not claim the published crate is broken",
            "PUBLISHED CRATE DOES NOT BUILD" not in text,
            text,
        )
        check("dependency: says the fix is upstream", "upstream" in text, text)

    # 2. The published crate's OWN source failing must still be called what it is,
    #    and must carry the tool's feature-bearing reproduction, not a bare one.
    fs = classify(OWN_SOURCE_BASELINE_FAILURE.splitlines(keepends=True))
    check("own/baseline: one failure", len(fs) == 1, f"got {len(fs)}")
    if fs:
        text = render(fs[0])
        check("own/baseline: no culprits", not fs[0].culprits, str(fs[0].culprits))
        check("own/baseline: verdict", "PUBLISHED CRATE DOES NOT BUILD" in text, text)

    fs = classify(DEPENDENCY_FAILURE.splitlines(keepends=True))
    if fs:
        check(
            "repro carries the feature list",
            any("--features" in line for line in fs[0].repro),
            str(fs[0].repro),
        )

    # 3. A workspace-side failure is not a registry problem.
    fs = classify(OWN_SOURCE_CURRENT_FAILURE.splitlines(keepends=True))
    check("own/current: one failure", len(fs) == 1, f"got {len(fs)}")
    if fs:
        check("own/current: side", fs[0].side == "current", str(fs[0].side))
        text = render(fs[0])
        check("own/current: verdict", "WORKSPACE COPY" in text, text)
        check("own/current: not blamed on crates.io", "crates.io" not in text, text)

    # 4. A healthy run reports nothing.
    check("clean run: no failures", classify(CLEAN_RUN.splitlines(keepends=True)) == [])

    if failed:
        print(f"{failed} self-test assertion(s) failed", file=sys.stderr)
        return 1
    print("semver-build-failure.py: all self-tests pass")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
