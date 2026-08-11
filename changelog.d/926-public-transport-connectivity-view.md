### vtc-service 0.11.57 — publish which transports a community offers, and whether they answer (#926)

A community's DID document says how to reach it, but resolving a `did:webvh`
and matching service `type`s is a lot to ask of someone who just wants to know
whether they can connect — and it still cannot tell them whether the endpoint on
the other side is actually answering. That gap is what let a VTC advertise
`#tsp` while silently dropping every join (#923): from outside, a working
transport and a dead one looked identical.

`GET /v1/community/public-profile` (public, unauthenticated) now carries a
`transports` array, and the default landing page renders it:

```json
"transports": [
  { "protocol": "tsp",     "advertised": true,  "serviceable": true,
    "endpoint": "did:webvh:QmTS3…:mediator" },
  { "protocol": "didcomm", "advertised": false, "serviceable": true },
  { "protocol": "rest",    "advertised": true,  "serviceable": true,
    "endpoint": "https://first.openvtc.net" }
]
```

Two facts per transport, deliberately not collapsed into one "reachable"
boolean:

- **`advertised`** — the DID document offers it, so a resolving client will find
  it. Read from the document as *resolved* at request time.
- **`serviceable`** — this VTC can answer on it right now: the build supports the
  protocol *and* the mediator connection is live, off the same re-falsifiable
  signal `/health/diagnostics` uses, never a boot latch (R6.2).

Reachable means both. `advertised && !serviceable` is exactly the state that
broke the reference deployment, and a single boolean would have hidden it the
same way the original defect did.

**The DID document remains authoritative.** This is a view of it for humans and
monitors, never a substitute or a second source of truth — a client selecting a
transport still matches on the document's service `type`. If the two ever
disagree, the document wins and this field is what is wrong.

Notes:

- **Endpoint, not page.** Operators replace the public website
  (`website.root_dir`), so a landing-page-only change would vanish for exactly
  the real deployments worth checking. The endpoint survives, is machine-readable
  for CI and monitoring, and any custom site can render it. `website-default`
  renders it from the fetch it already makes.
- **Unknown is not "none".** A community whose own DID does not resolve reports
  an empty array. Publishing "advertises nothing" would be an actionable claim,
  and a false one.
- **Nothing about the build is disclosed.** Build feature flags, versions, and
  the operator remediation text in `transport_capability::Finding` stay in
  `vtc status` and the daemon log. `advertised` and `endpoint` are already public
  in the DID document; `serviceable` is discoverable by attempting the transport.
  Pinned by tests on both the wire type and the route response.
