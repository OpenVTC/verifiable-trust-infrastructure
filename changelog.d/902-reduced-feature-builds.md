### vta-sdk 0.21.7 / vta-service 0.14.12 — the workspace builds again, and keeps building under reduced feature sets (#902)

Three independent build breaks, all of the same shape: a feature combination
nobody compiles routinely, so nothing caught the drift.

## `--features tsp` stopped resolving `TspWebSocket` and `atm.tsp()`

`vta-sdk` and `vta-service` each take a **direct** `affinidi-messaging-sdk`
dependency purely so their own `tsp` feature can flip
`affinidi-messaging-sdk/tsp` — the toggle that gates `atm.tsp()` and
`TspWebSocket`. `affinidi-tdk/tsp` does not flip it. The comment at the pin says
so explicitly, and adds the load-bearing assumption: *"Cargo unifies to one
instance, the one `affinidi_tdk::messaging` re-exports."*

That unification stopped holding. `affinidi-tdk` 0.8.5 moved to
`affinidi-messaging-sdk` 0.19, while both pins still read `"0.18"` — two
semver-incompatible units in one graph, with independent feature sets. The
`tsp` feature flipped `tsp` on the 0.18 copy; the source names
`affinidi_tdk::messaging::TspWebSocket`, which is the 0.19 copy, whose `tsp`
feature nothing enabled. rustc said it plainly — *"found an item that was
configured out"* — for a feature the manifest appears to turn on.

Pins move to `"0.19"` (`vta-sdk`, `vta-service`, `tests/e2e`), restoring the one
instance the comment assumed. `affinidi-messaging-didcomm` goes to 0.15.8 with
it: 0.19.1 needs `jws::verify::{parse_jws, verify_parsed_signature, VerifyKey}`,
which 0.15.6 does not export.

The lockfile still carries a 0.18 copy behind
`affinidi-messaging-test-mediator` → `affinidi-messaging-mediator`. That is a
**dev**-dependency chain, a separate unit, and does not reach either library
build.

## `--no-default-features` named a value that was configured out

`server.rs` builds `app_state` under `#[cfg(any(feature = "rest", feature =
"didcomm"))]` — `build_app_state` is what constructs the policy keyspace — but
the two policy-bootstrap calls that read `app_state.policy_ks` carried no gate,
so a build with neither transport failed on an undefined name. They now sit
inside the same gate.

## `--features tsp` alone could never have worked

In `vta-service`, TSP is not a standalone transport: `messaging::tsp_inbound`
and `messaging::tsp_reach` live inside the `didcomm`-gated `messaging` module,
because TSP receive arrives on the **DIDComm pickup socket** rather than opening
a second one (ADR 0005 — one websocket per DID). `tsp` therefore requires
`didcomm`, and now declares it.

`vta-sdk/tsp` is deliberately left standalone: its `TspPingSession` is a real
TSP-only client that owns its own socket, and it builds on its own.

## Verified

`vta-service` compiles at `--no-default-features` and with each of `didcomm`,
`rest`, `tsp`, `didcomm,tsp`, and `rest,didcomm,tsp,webvh`; `vta-sdk` at
`--no-default-features`, `--features tsp`, and `--all-features`; the workspace at
`--all-features`.
