# vtc-audit

The Verifiable Trust Community's audit-event vocabulary: `AuditEvent`, one
variant per thing that can happen to a community, and its data structs.

The envelope, the tamper-evident hash chain, the HMAC actor hashing, the
audit-key history, the signed checkpoints and the writer are node-neutral and
live in `vti-common` (`vti_common::audit`), generic over the event payload. This
crate fixes that payload to `AuditEvent` (`AuditEnvelope`, `AuditWriter`) and
re-exports the rest, so a community subsystem names one crate for its audit
trail.

It is a leaf — it depends only on `vti-common` — so any VTC subsystem can emit
audit events without depending on `vtc-service`, and a community feature that
adds an event republishes this crate rather than the layer-0 foundation every
VTA crate builds on.

Variant names and field names are a wire contract: the hash chain commits to the
event's serialized `type` / `data`, so renaming either breaks verification of
every stored chain. `tests/stored_chain.rs` verifies a chain written before the
vocabulary moved here.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
