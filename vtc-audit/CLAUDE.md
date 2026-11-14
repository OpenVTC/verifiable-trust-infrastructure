# CLAUDE.md — vtc-audit

## Purpose

The community's audit-event vocabulary (`AuditEvent` + data structs), over
`vti_common::audit`'s generic envelope, chain, HMAC actor hashing and writer.
Split out of `vti-common` by #2568 so community features stop republishing the
layer-0 crate. See `docs/05-design-notes/vtc-service-decomposition.md`: every
VTC subsystem crate emits audit events through this leaf.

## Rules

- **Variant and field names are a wire contract.** The chain's `entry_hash`
  commits to the event's `serde_json` encoding (`{"type": …, "data": …}`), so a
  rename — of a variant, a field, or a `serde` attribute that changes the bytes
  — breaks verification of every stored chain holding it. Add variants; never
  reshape one. `tests/stored_chain.rs` and its fixture (written by `main` before
  the move) must keep passing unmodified; never regenerate the fixture.
- **`AuditEvent` is `#[non_exhaustive]`.** A new variant is additive; keep it so.
- **`variant_name` matches the serialized tag**, and `audit/list` filters on it.
  Add an arm with every new variant.
- **Leaf only.** Depend on nothing but `vti-common` (and serde/chrono). If an
  event needs a type from a service, carry it by reference (a string, an id).
- Nothing VTA-specific here: the VTA's `VtaOperation` is in `vta-audit`.
