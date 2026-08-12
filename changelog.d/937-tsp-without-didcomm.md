### vta-service 0.14.35 — a VTA can speak TSP without DIDComm (#937)

`vta setup` refused TSP unless DIDComm was selected too, and said so as though it
were a fact about TSP: "TSP shares the DIDComm mediator". It isn't — TSP is an
independent transport and a TSP-only mediator is legitimate. Three things in this
crate assumed otherwise, and all three are gone.

- **The mediator question was asked only in the DIDComm branch.** `[messaging]`
  is transport-neutral — its `mediator_did` is what `#tsp` names — so the wizard
  reaches it when either transport is selected, and says what it is configuring
  when TSP is the only one. `validate_services` drops the implication, the
  `--from <toml>` rule goes with it, and `[messaging]` now requires *a* transport
  rather than DIDComm specifically. A TSP-only VTA that skips `[messaging]`
  degrades exactly as a DIDComm one always has: enabled in config, no service
  entry published, because there is no endpoint to name.
- **The connect supervisor was mounted on `services.didcomm`**; it is now
  `services.didcomm || services.tsp`. TSP receive arrives on that same mediator
  socket (ADR 0005 — one websocket per DID) and TSP send is an HTTP post through
  the same ATM, so gating the socket on DIDComm meant a TSP-only VTA would
  advertise `#tsp` and never connect. The queue-recovery helpers, the mediator
  ACL (keyed on the VTA DID, so it authorises whichever protocol rides the
  socket), the VM ids that collect the profile's secrets, and the outbound bridge
  move with it. A TSP-only VTA must not advertise `#vta-didcomm`, so the mint
  flag becomes `messaging.is_some() && services.didcomm`.
- **The cargo feature carried the edge** (`tsp = ["didcomm", …]`). The split is
  now by role: `messaging::{service,readiness,auth}` and the module itself build
  for either transport, while the DIDComm protocol surface (router, handlers,
  shim, registry, drain store/sweeper, handshake, live prover, transient
  handshake) is `didcomm`-only, along with the ops, REST routes and offline CLI
  commands that drive it. `ceremony` and `reject_trust_task` widen to either
  transport — an approver must not be reachable over one and not the other.

`transport-harness` named `tsp` and relied on it pulling `didcomm` in; it now
names both, or its own DIDComm fixture would have had no dispatcher behind it.
CI gains a `tsp without didcomm` combo at `-D warnings --all-targets`: the
combination that was unbuildable is the one nothing would notice rotting.

**A TSP-only build has no DIDComm protocol-message surface** (`key-management/1.0/*`,
`create_did_webvh`, `list_contexts` are REST-only there), no drain machinery or
`services didcomm …` commands, and no path back without a rebuild. A
dual-transport build keeps all of it. See `docs/02-vta/tsp.md`.

Per-transport mediators (`[messaging.tsp]`) are still designed-not-built
(`transport-neutral-mediator.md` §7), and that note's two open questions —
per-protocol mediator registration, and whether a TSP-only session needs the
DIDComm auth leg — want a live mediator run.
