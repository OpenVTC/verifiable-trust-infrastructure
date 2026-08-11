### vtc-service 0.11.56 / vta-sdk 0.21.14 — serve the TSP we advertise, and refuse to pretend otherwise (#923)

A VTC whose DID document advertised `#tsp` (`TSPTransport`) and no
`DIDCommMessaging`, built without `--features tsp`, accepted every community
join and recorded none. The applicant saw a successful send; the operator saw
`Error unpacking message: DidcommError("Cannot parse message as JSON", "invalid
number at line 1 column 2")` — an error naming neither TSP nor a missing
feature.

The frame never reached the VTC. `affinidi-messaging-sdk`'s websocket transport
classifies TSP frames only under its own `tsp` feature; without it a CESR frame
is never tagged `Protocol::TSP` and falls through to the DIDComm unpacker, where
its leading `-` reads as the start of a JSON number. That is two layers below
`messaging.rs`'s own "the `tsp` feature is disabled" warning, which therefore
could never fire — and below the SDK's equivalent warning too, whose comment
assumed "a DIDComm-only build never advertises TSP". This one did.

- **`tsp` is now a default feature of `vtc-service`**, so the shipped binary
  serves what its document may advertise. Receive-side only: this is Phase A of
  `docs/05-design-notes/tsp-enablement.md` §12 — a TSP request is answered over
  TSP because the caller is waiting on that correlation, while VTC-*initiated*
  sends to members (`send_to_member`) stay DIDComm until the Phase B flip.
- **New `transport_capability` module** compares the transports the VTC's DID
  document advertises against the ones this build can serve, matching on service
  `type` and never on the `#id` fragment. `server::run` refuses to boot when the
  document the VTC itself publishes advertises something unservable; the
  messaging listener re-checks against the DID as *resolved* — the deployed
  `#tsp` arrived at DID log version 3, published long after the `vtc-host`
  template minted the document, so a local-only check would have passed the
  exact deployment that failed. Advertising an unservable transport alongside a
  servable one starts degraded with a loud error; advertising nothing servable
  stops the listener rather than dropping frames quietly, leaving REST serving.
- **The errors name the failure class** (R6.4): which transport, why this build
  cannot serve it, and both remediations — rebuild with `--features tsp`, or
  remove the service entry.
- **The TSP receive path is now exercised, not just compiled.**
  `MockVtcDidcomm::start_with_tsp` mints a VTC `did:peer` advertising both
  transports and `TestJoinClient::send_tsp` seals a real CESR frame through an
  embedded TSP-routing mediator; `tests/join_tsp.rs` asserts the join reaches
  `dispatch_trust_task_core` and is stored. The embedded test mediator now
  enables its own `tsp` feature — without it `/inbound` rejects
  `application/tsp` as a malformed DIDComm envelope. Runs in CI.

All four document-vs-binary relationships are now reported, from one
`findings_against` the boot gate, the messaging listener and `vtc status` all
render — so an operator who runs `vtc status` to explain a boot refusal is told
the same story, not a second one:

- advertised but unservable → **error** (refuses to boot / stops the listener);
- **no messaging service advertised at all** → warning. Legal, and what
  `vtc-host` mints, but nothing can be delivered to the VTC over a mediator by
  any route a DID-driven client would find;
- TSP advertised with no DIDComm behind it → warning (no fallback);
- served but not advertised → informational, the normal shape of a staged
  rollout, never a fault.

`vtc status` grows a **Transports** section printing what the build serves, what
the document advertises, and every finding — so the question "will it refuse if
I restart" is answerable without restarting.

`vta-sdk`: the `vtc-host` template description pointed at
`docs/03-integrating/runtime-service-management.md`, a directory that does not
exist; corrected to `docs/02-vta/`, and reworded to say that *no* messaging
transport is advertised by default (not just DIDComm) and that a community
adding one should add both.

The capability predicates take the served transport set as a parameter rather
than reading it from `cfg`, because the crate's `[dev-dependencies]` self-dep
unifies default features into every test build: a `#[cfg(not(feature = "tsp"))]`
test here would never compile in, never run, and never fail.
