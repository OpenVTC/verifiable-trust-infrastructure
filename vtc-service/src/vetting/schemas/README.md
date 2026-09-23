# Published payload schemas, carried verbatim

These are copies of `payload.schema.json` from the Trust Tasks registry
(`dtgwg-trust-tasks-tf`, branch `hidden-vetting-tasks`), for the three tasks the
hidden-vetting community half serves.

They are here for one reason: `vetting::pcs_tasks` hand-writes the payload types, because the
generated bindings are `trust-tasks-rs` 0.22 and this workspace pins `^0.21` — two nodes that do
not unify. Hand-written wire types are the thing the workspace has a rule against, so the rule is
held down by a test rather than an intention: `pcs_tasks::tests` validates every type against the
schema beside it.

**When `trust-tasks-rs` publishes these specs, delete this directory and the hand-written types
with it.** The handlers do not change.
