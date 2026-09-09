#!/usr/bin/env python3
"""Every workspace member must be COPYed into the Nitro enclave image.

`Dockerfile.nitro` lists members one by one rather than using `COPY . .`, so that a
`deploy/nitro/config.toml` edit does not invalidate the Rust build cache. The cost of that
choice is a list that has to be maintained, and the Dockerfile says what happens when it is
not:

    A member missing from this list keeps cargo-chef's skeleton stub instead of its real
    source, which fails the build below rather than silently producing a broken binary.

That failure is the right one, but it arrives at the end of a multi-minute image build and
reads as a version-resolution error about a crate nobody touched:

    error: failed to select a version for the requirement `vti-rooms = "^0.0.1"`
    required by package `vti-rooms-wasm v0.0.1`

`0.0.1` is cargo-chef's placeholder, not anything in the tree — which is why the message
sends you looking at the wrong file. This says the same thing in a second, naming the member
and the line to add.
"""

import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
workspace = (root / "Cargo.toml").read_text()
dockerfile = (root / "Dockerfile.nitro").read_text()

block = re.search(r"(?s)members\s*=\s*\[(.*?)\]", workspace)
if not block:
    sys.exit("could not find `members` in the workspace Cargo.toml")

members = re.findall(r'"([^"]+)"', block.group(1))

missing = []
for member in members:
    # `deploy/` is deliberately excluded — its config is baked in a later stage. A nested
    # member is covered by a COPY of any ancestor directory, which is how `tests/e2e` rides
    # in on `COPY tests/ tests/`.
    if member == "deploy":
        continue
    parts = member.split("/")
    covered = any(
        f"COPY {'/'.join(parts[: i + 1])}/ {'/'.join(parts[: i + 1])}/" in dockerfile
        for i in range(len(parts))
    )
    if not covered:
        missing.append(member)

if missing:
    print("Dockerfile.nitro does not copy every workspace member.\n")
    for member in missing:
        print(f"  missing: {member}")
    print("\nAdd, in the COPY block:\n")
    for member in missing:
        print(f"  COPY {member}/ {member}/")
    print(
        "\nWithout it cargo-chef's skeleton stub is used instead of the real source, and the\n"
        "image build fails with a version-resolution error naming a placeholder `0.0.1`."
    )
    sys.exit(1)

print(f"Dockerfile.nitro copies all {len(members)} workspace members")
