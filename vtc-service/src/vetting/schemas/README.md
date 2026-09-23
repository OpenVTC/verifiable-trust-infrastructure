# Published payload schemas, carried verbatim

These are copies of `payload.schema.json` from the Trust Tasks registry
(`dtgwg-trust-tasks-tf`, merged in #618 and #620), for the four tasks the hidden-vetting
community half serves.

They are here for one reason: `vetting::pcs_tasks` hand-writes the payload types, because the
generated bindings are `trust-tasks-rs` 0.22 and this workspace resolves **0.21.17** — two nodes
that do not unify. Hand-written wire types are the thing the workspace has a rule against, so the
rule is held down by a test rather than an intention: `pcs_tasks::tests` validates every type
against the schema beside it.

The 0.21 pin is not this workspace's alone. `affinidi-messaging-sdk`, `affinidi-messaging-mediator`
and the `trust-tasks-{proof,https,tsp,capability-client}` companions are all on the 0.21 line and
re-export `trust-tasks-rs` types, so bumping here without them gives two `trust-tasks-rs` nodes
and a wall of `expected X, found X` — the same hazard the workspace CLAUDE.md names under
"a re-export makes the re-exported crate's version part of your public API".

**When the 0.22 line reaches this graph, delete this directory and the hand-written types with
it.** The handlers do not change.
