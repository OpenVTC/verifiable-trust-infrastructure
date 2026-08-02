### vta-sdk 0.21.4 / vta-service 0.14.4 — `keys/import` is canonical on every transport, because the dispatcher now knows its own transport (#893)

The last first-party legacy send is gone. `import_key` sends canonical
`keys/import/0.1` for **every** carrier, on REST, DIDComm and TSP alike.

## The path this replaces was dead, not deliberate

The cleartext `privateKeyMultibase` carrier forked onto the legacy
`key-management/1.0/import-key` message, justified as preserving a capability on
the transport where authcrypt makes cleartext safe. **The VTA has never routed
that type** — it is absent from `messaging/router.rs` — so the call failed with
`unsupported message type` over DIDComm, and REST refuses the field outright.
Multibase import worked nowhere. The fork preserved nothing; it was asserted from
the client side without checking the router.

## The rule was always right; the VTA could not evaluate it

The published spec says a custodian must refuse cleartext *"unless the transport
provides end-to-end confidentiality"*. One spine serves the Trust-Task surface
over REST, DIDComm and TSP and discarded the transport before any handler ran, so
the only safe reading was a blanket refusal — over-refusing on precisely the two
transports where cleartext is safe.

`vta-service/src/trust_tasks/transport.rs` records what the transport
guarantees, set at the three entry points that know it:

| transport | guarantee | why |
|---|---|---|
| DIDComm | end-to-end | authcrypt seals to this VTA's key; the mediator never holds plaintext |
| TSP | end-to-end | seals to the recipient VID |
| REST | hop-by-hop | TLS terminates wherever the operator terminates it — a load balancer, an ingress — and the plaintext exists there |

`keys/import` then applies the specification's actual rule.

## Two decisions worth reviewing

**A task-local, not a handler parameter.** The dispatch table has 157 entries
sharing one signature. Threading a parameter through all of them to serve one
handler would be a large mechanical diff that buries the single call site that
matters. It is set in exactly one place (`dispatch_trust_task_core`) and read in
exactly one (`keys::handle_import`).

**The default is the restrictive one.** Outside a dispatch scope,
`transport::current()` reports hop-by-hop. A future entry point that dispatches
without establishing the scope therefore refuses cleartext rather than accepting
it: a wiring mistake costs a working import, not a leaked key. That direction is
pinned by a unit test.

## Testing

- `keys_import_trust_task_refuses_cleartext_over_rest` posts the task to
  `/api/trust-tasks` and asserts both the refusal and its reason.
  **Verified by mutation**: with the gate disabled the request proceeds past it
  and the assertion fails, so the test pins the gate rather than passing
  incidentally.
- `multibase_import_key_via_didcomm_uses_the_canonical_task` pins the accepting
  side, with a fixture carrying `origin: "imported"` so a broken mapping cannot
  pass.
- The scope's default and non-leakage are unit-tested in `transport.rs`.

## Where the legacy surface stands

No first-party call sends a legacy protocol message on any default path. What
remains on `rpc` is deprecated and reachable only by explicit opt-in: the inline
`backup_export`/`backup_import` behind `--use-rest-legacy` (removed at rollout
step 6), and the `(context_id, scid)` webvh update pair, which has no first-party
caller at all.
