# VTA DIDComm protocol — superseded

This page used to specify a DIDComm message surface (`key-management/1.0/*`,
`create_did_webvh`, `list_contexts` and the like) in parity with a REST API.
**That surface is gone from both ends.** The SDK sends none of those messages,
and the VTA answers every one of them as an unknown type.

Every client operation is now a **Trust Task**, and TSP, DIDComm and HTTPS all
carry the same Trust-Task spine:

- **Over DIDComm** the VTA accepts exactly one application message type, the
  Trust-Task binding envelope
  (`https://trusttasks.org/binding/didcomm/0.1/envelope`), plus plumbing:
  trust-ping, message-pickup status and problem-report
  (`vta-service/src/messaging/router.rs`). The authcrypt sender is the
  authenticated caller; `vta-service/src/messaging/auth.rs`
  (`auth_for_trust_task_envelope`) resolves it against the ACL.
- **Over TSP** the same Trust Task documents ride the TSP leg of the same
  mediator socket — see [TSP](tsp.md).
- **Over HTTPS** they are posted to `/trust-tasks`.

Which of the three a client uses is the highest-preference one both parties'
DID documents advertise (TSP > DIDComm > REST), matched on the service `type`.

**See:**

- [TSP operator guide](tsp.md) — how the protocol is chosen and enabled.
- [Runtime service management](runtime-service-management.md) — advertising
  and changing the VTA's TSP, DIDComm and REST services.
- [`tsp-vs-didcomm-trust-task-surface.md`](../05-design-notes/tsp-vs-didcomm-trust-task-surface.md)
  and [`trust-task-envelope-conformance.md`](../05-design-notes/trust-task-envelope-conformance.md)
  — the design behind the single surface.
- The Trust Task specifications VTI pins are vendored under
  `vti-specs-*/trust-tasks/`; `vti_specs::schema_index` lists them.
