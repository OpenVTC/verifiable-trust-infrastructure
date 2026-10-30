# vti-specs

The Trust Task wire types VTI speaks, generated at build time from the
specification versions it pins, and one Type URI index over all of them.

| Crate | Families |
|---|---|
| `vti-specs-rooms` | `rooms/*` (alone, so `vti-rooms-wasm` compiles nothing else) |
| `vti-specs-vta` | `vta/*` |
| `vti-specs-vtc` | `vtc/*` |
| `vti-specs-core` | every other family VTI speaks |

Each version is generated in exactly one of them. This crate re-exports every
family at the path the deprecated prebuilt `trust_tasks_rs::specs` gave it
(`vti_specs::vtc::members::list::v0_2`), and `vti_specs::schema_index` is the
drop-in for `trust_tasks_rs::schema_index` over exactly the pinned versions —
with `is_pinned`, because `None` from an index means "not pinned", and a gate
that reads it as "nothing to check" fails open.

`vta-sdk` re-exports this crate as `vta_sdk::specs`.

Framework specifications (`trust-task-error`, `trust-task-discovery`, …) cannot
be locked; they stay in `trust_tasks_rs`, and `schema_index` answers for them
from there.
