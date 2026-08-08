### vta-service 0.14.14 — VTA↔DID-hosting DIDComm uses the Trust-Task envelope binding (#904)

The last and largest of the envelope-binding fixes (#901, #903). `webvh_didcomm.rs`
sent seven DID-management verbs with the **task** type as the DIDComm message
type, where `trust_tasks_didcomm::ENVELOPE_TYPE` is required with the `TrustTask`
in the body.

## Why this one was invisible

Unlike the device pushes, **this never broke anything**. did-hosting's control
plane accepts both framings — `build_control_router` routes the bare `MSG_*`
types *and* `ENVELOPE_TYPE` — so DID publish, register, delete and the
agent-name verbs all worked. The defect was latent: the moment the host retires
bare-type acceptance (its stated direction), every one of these verbs would have
started timing out at 30s with no diagnostic, exactly as the retired
`did/publish/0.1` did in affinidi-webvh-service#144.

## The shape of the change

One private `send_task` is now the only place this module names a DIDComm
message type, and it names the envelope both ways. Each verb passes just its
task URI, so no call site can put a task type on the wire.

- **Outbound:** `build_outbound` returns the `(message_type, document)` pair —
  envelope type on the message, task type on the document, payload unchanged.
- **Inbound:** `unwrap_envelope_reply` discriminates on the *document's* type,
  because on this binding every reply arrives as `ENVELOPE_TYPE` and
  `send_and_wait`'s outer type check can no longer tell success from rejection:
  - `<task>#response` → its `payload`,
  - `did/problem-report/0.1` → the typed `AppError`, through the **same**
    `problem_report_to_app_error` table the bare framing uses (now
    `pub(crate)`), so a host rejection keeps its status — `path-unavailable`
    stays a 409 rather than collapsing to 502,
  - `trust-task-error/0.x` → 502; the framework refused the envelope, not the
    task, so it is not an outcome a caller can act on. Matched by prefix: the
    version floats between 0.1 and 0.2 within one conversation.

## Prerequisite, already shipped

affinidi-webvh-service#155 gave the host's envelope path the anti-replay gate
its bare-type path already had. Both framings reach the same `dispatch_did_op`
table, so without it this change would have worked *and* silently dropped replay
protection for delete, change-owner and register. Merged first, deliberately.

## Tests

Six new tests. The outbound one asserts both halves off `build_outbound`, which
is what keeps it from being circular — `send_task` destructures that return, so
restoring the defect means bypassing the function rather than editing an
argument. Verified against the defect, not just the fix:

```
assertion `left == right` failed: the DIDComm message must carry the binding's envelope type
  left: "https://trusttasks.org/spec/did-management/did/check-name/0.1"
 right: "https://trusttasks.org/binding/didcomm/0.1/envelope"
```

An earlier draft tested only the document builder and did **not** catch that
regression; the tests were restructured until they did.

TSP is untouched — it carries document bytes directly, so the envelope belongs
to the DIDComm binding. `webvh_didcomm` and `trust-tasks-didcomm` are both
ungated, so the import needs no `#[cfg]`; verified at `--no-default-features` and
with each of `didcomm`, `rest`, `tsp`, `didcomm,tsp`, `rest,didcomm,webvh,tsp`.
