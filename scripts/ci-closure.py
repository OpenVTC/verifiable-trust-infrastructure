#!/usr/bin/env python3
"""Print every workspace crate, tagged by whether it is in a package's closure.

    cargo metadata --format-version 1 | scripts/ci-closure.py vta-mobile-core

emits one `<dir>\t<name>\t<IN|OUT>` row per workspace member, where IN means the
crate is in the transitive workspace-member dependency closure of the named
package — i.e. a change to it can change what that package builds.

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
    if len(sys.argv) != 2:
        print("usage: ci-closure.py <package>", file=sys.stderr)
        return 2
    target = sys.argv[1]

    meta = json.load(sys.stdin)
    root = meta["workspace_root"] + os.sep
    members = {p["id"] for p in meta["packages"] if p["manifest_path"].startswith(root)}
    by_id = {p["id"]: p for p in meta["packages"]}

    resolve = meta.get("resolve")
    if not resolve:
        print("no resolve graph — run cargo metadata without --no-deps", file=sys.stderr)
        return 4
    nodes = {n["id"]: n for n in resolve["nodes"]}

    start = [i for i in members if by_id[i]["name"] == target]
    if not start:
        print(f"{target} is not a workspace member", file=sys.stderr)
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
