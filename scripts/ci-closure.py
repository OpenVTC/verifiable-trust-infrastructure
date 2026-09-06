#!/usr/bin/env python3
"""Print every workspace crate, tagged by whether it is in a package set's closure.

    cargo metadata --format-version 1 | scripts/ci-closure.py vta-mobile-core
    cargo metadata --format-version 1 | scripts/ci-closure.py vtc-service vtc-client
    cargo metadata --format-version 1 | scripts/ci-closure.py --except vtc-service

emits one `<dir>\t<name>\t<IN|OUT>` row per workspace member, where IN means the
crate is in the transitive workspace-member dependency closure of the named
packages — i.e. a change to it can change what those packages build.

`--except A B` takes the union closure of every workspace member EXCEPT the named
ones. That is how a job phrased as "test everything but VTC" states its scope, and
it is not the complement of the VTC closure: `room-host` depends on `vtc-client`,
so `vtc-client` is inside "everything but vtc-service" even though it is a VTC
crate. Complementing a closure by hand gets that backwards; deriving it does not.

A separate file rather than a `python3 -c` heredoc inside the shell script,
because the obvious inline form is quietly broken: the program is wrapped in
shell single quotes, and every `'.'`, `p['name']` or `'IN'` inside it *ends* that
quoted string. The result still runs and still exits non-zero, so with a
fail-safe `|| run-anyway` around it the job silently reverts to running always —
a filter that looks installed and does nothing. Found by testing it; it does not
show up in review.
"""

import json
import os
import sys

LIB_KINDS = {"lib", "rlib", "proc-macro", "dylib", "cdylib"}


def main() -> int:
    args = sys.argv[1:]
    invert = False
    if args and args[0] == "--except":
        invert, args = True, args[1:]
    if not args:
        print("usage: ci-closure.py [--except] <package>...", file=sys.stderr)
        return 2
    targets = {t for a in args for t in a.split(",") if t}

    meta = json.load(sys.stdin)
    root = meta["workspace_root"] + os.sep
    members = {p["id"] for p in meta["packages"] if p["manifest_path"].startswith(root)}
    by_id = {p["id"]: p for p in meta["packages"]}

    resolve = meta.get("resolve")
    if not resolve:
        print("no resolve graph — run cargo metadata without --no-deps", file=sys.stderr)
        return 4
    nodes = {n["id"]: n for n in resolve["nodes"]}

    unknown = targets - {by_id[i]["name"] for i in members}
    if unknown:
        print(f"not workspace members: {sorted(unknown)}", file=sys.stderr)
        return 3

    if invert:
        start = [i for i in members if by_id[i]["name"] not in targets]
    else:
        start = [i for i in members if by_id[i]["name"] in targets]
    if not start:
        print("empty package set", file=sys.stderr)
        return 3

    seen: set[str] = set()
    stack = list(start)
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        for dep in nodes[i]["deps"]:
            if dep["pkg"] in members:
                stack.append(dep["pkg"])

    for i in sorted(members, key=lambda x: by_id[x]["name"]):
        pkg = by_id[i]
        directory = os.path.dirname(pkg["manifest_path"])[len(root):] or "."
        print(f"{directory}\t{pkg['name']}\t{'IN' if i in seen else 'OUT'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
