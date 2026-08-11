### vtc-service 0.11.58 / vta-sdk 0.21.18 — choose a community's transports at setup, when it is still possible (#929)

`vtc setup` asked which mediator to route through, wrote it to `config.toml`, and
never advertised it. The `vtc-host` template minted `#vtc-rest` and
`#vtc-status-list` and no messaging service at all — so a VTC connected outbound
to a mediator while its DID document told nobody, and DIDComm only worked when
the sender had been handed the mediator out of band.

That is also why the reference deployment acquired its `#tsp` entry at DID log
version 3, published by hand long after mint — the state that led to #923 and
#926.

**Setup is the only clean moment to fix this.** A VTC serves a write-once
`did.jsonl` and cannot re-sign its own log, so adding a service afterwards means
a VTA-side `dids edit` plus redelivering the log by hand. So the decision moves
to provisioning, where the document is being minted anyway.

**Interactive** — after the mediator choice, a multi-select with both transports
pre-ticked (the §12 Phase A shape, which strands nobody). It states that both
entries point at the operator's mediator, warns that advertising one the mediator
does not route makes the community unreachable on it, notes the choice is fixed
at mint, and echoes back what will be advertised. Deselecting everything re-asks
rather than minting a community that connects to a mediator and advertises no way
in.

**Non-interactive** — `transports` is **required** in `[messaging]`:

```toml
[messaging]
mediator_did = "did:web:mediator.example.com"
transports   = ["tsp", "didcomm"]
```

Required rather than defaulted: it decides whether anyone can reach the
community, it cannot be changed after mint, and any default would be a guess
about someone else's mediator. `transports = []` is refused by name with the
REST-only alternative spelled out, and duplicates are refused (they would render
the same service entry twice). **Existing setup files that omit `[messaging]`
entirely are unaffected** — a REST-only community stays valid.

Deliberately no capability detection. Nothing here can verify that the named
mediator actually routes the protocol being advertised; its services belong to
its own controller (§14 Q3). The operator is told that plainly rather than having
it guessed for them.

`vta-sdk`: new `did_templates::{tsp_service, didcomm_service}` build the service
entries, and `vtc-host` gains `SERVICE_TSP` / `SERVICE_DIDCOMM` null-pruning
slots — the same mechanism `SERVICE_TRUST_REGISTRY` uses, and the only conditional
the template format has. Both entries name the *same* mediator DID (§14 Q2), and
the emitted service order is canonical (TSP, DIDComm, then REST) because array
order is what encodes transport preference to a resolver. A URL endpoint is
refused: the sender's routing layer reads this value as a DID to resolve onward,
so a URL is unroutable rather than merely unconventional.

Closes the loop with #923 (a build cannot advertise what it can't serve) and #926
(the public transport view) — a community can now *say* how to reach it, and
everything downstream already checks that the saying is true.
