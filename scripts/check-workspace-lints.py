#!/usr/bin/env python3
"""Every workspace member inherits the workspace lint table (#2658).

`[workspace.lints]` only applies to a member that says `[lints] workspace =
true`. Fifteen members extracted in the vta-service decomposition (#780–#791)
never did, so `unsafe_op_in_unsafe_fn` and the clippy fences silently did not
apply to them — one of them, `vta-tee`, being a crate that contains `unsafe`.
Nothing noticed, because a crate without the line simply gets the compiler's
defaults; there is no warning for a lint table you forgot to inherit.

## What this checks

1. Every member has `[lints] workspace = true`, except the crates listed in
   `UNSAFE_CRATES`.
2. `[workspace.lints.rust]` sets `unsafe_code = "forbid"`.
3. Each crate in `UNSAFE_CRATES` carries its own `[lints]` table that is the
   workspace table with exactly one change: `unsafe_code = "deny"`. `forbid`
   cannot be lowered by an inner `#[allow]`, and a member cannot inherit the
   workspace table and override one lint, so a crate that needs `unsafe`
   restates the table — and this keeps the restatement from drifting.
4. Every crate in `UNSAFE_CRATES` still has its own table. A crate that no
   longer needs `unsafe` goes back to `workspace = true` and leaves the list,
   which only shrinks.

Reads the manifests with `tomllib` (Python 3.11+): `cargo metadata` does not
report lint tables.
"""

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    sys.exit("check-workspace-lints.py needs Python 3.11+ (tomllib)")

# Crates that contain `unsafe` and so deny rather than forbid it. Each such
# statement carries `#[allow(unsafe_code)]` beside its SAFETY comment.
UNSAFE_CRATES = {
    "pnm-cli": "std::env::set_var at startup",
    "vta-service": "AsyncFd::register for the vsock listener; env::remove_var at boot",
    "vta-tee": "the /dev/nsm and /dev/sev-guest ioctls",
    "vti-common": "libc::umask and env::set_var in tests",
}

root = Path(__file__).resolve().parent.parent
ws = tomllib.loads((root / "Cargo.toml").read_text())
members = ws["workspace"]["members"]
ws_lints = ws["workspace"].get("lints", {})

problems = []

if ws_lints.get("rust", {}).get("unsafe_code") != "forbid":
    problems.append('[workspace.lints.rust] must set unsafe_code = "forbid"')

expected_local = {
    group: dict(table) for group, table in ws_lints.items()
}
expected_local.setdefault("rust", {})["unsafe_code"] = "deny"

for member in members:
    manifest = tomllib.loads((root / member / "Cargo.toml").read_text())
    lints = manifest.get("lints")
    name = manifest["package"]["name"]
    if name in UNSAFE_CRATES:
        if lints == {"workspace": True}:
            problems.append(
                f"{name}: inherits the workspace lints, so it no longer needs `unsafe`;"
                " remove it from UNSAFE_CRATES in this script"
            )
        elif lints != expected_local:
            problems.append(
                f"{name}: its [lints] table must equal [workspace.lints] with"
                f' unsafe_code = "deny"; found {lints!r}, expected {expected_local!r}'
            )
    elif lints != {"workspace": True}:
        problems.append(
            f"{name} ({member}/Cargo.toml): add\n\n    [lints]\n    workspace = true\n"
            + (f"\n    (found {lints!r})" if lints else "")
        )

missing = set(UNSAFE_CRATES) - {
    tomllib.loads((root / m / "Cargo.toml").read_text())["package"]["name"] for m in members
}
for name in sorted(missing):
    problems.append(f"UNSAFE_CRATES names {name}, which is not a workspace member")

if problems:
    print("Workspace lint inheritance is broken:\n")
    for p in problems:
        print(f"  - {p}")
    sys.exit(1)

print(
    f"Every member inherits the workspace lints ({len(members)} members;"
    f" {len(UNSAFE_CRATES)} deny rather than forbid `unsafe`)."
)
