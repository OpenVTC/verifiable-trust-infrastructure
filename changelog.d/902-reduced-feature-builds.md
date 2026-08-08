### vta-sdk 0.21.7 / vta-service 0.14.12 / vti-common 0.11.35 — the workspace builds again, and keeps building under reduced feature sets (#902)

Four independent build breaks, all of the same shape: a feature combination or a
dependency edge nobody compiles routinely, so nothing caught the drift.

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

## `UnpackMetadata` went `#[non_exhaustive]`

Carried in by the `affinidi-messaging-didcomm` 0.15.8 bump above, and only
visible when *test* targets compile: a `vti-common` test helper built
`UnpackMetadata` with a struct expression. `#[non_exhaustive]` bars that form
outside the defining crate, and a `..Default::default()` tail does not exempt it.
The helper now mutates a `Default` field by field — which is also the shape that
survives the upstream adding another field, the point of the attribute.

## Plaintext-envelope rejection moved one layer earlier

Also carried in by 0.15.8, and a strengthening rather than a regression: `unpack`
now refuses a `Plaintext` envelope outright ("not in the accepted set
[AuthcryptPlaintext, …]") before `bind_authcrypt_sender` is reached. The forged-
plaintext tests in `vta-service` and `vtc-service` asserted the 401 was
attributable to *our* guard by matching its message, so they failed on the new
wording while the behaviour they exist to protect — 401, no token issued — was
unchanged throughout.

They now accept either attribution, and gained an explicit assertion that the
401 did **not** come from the `ATM not configured` short-circuit — which was the
real intent of the original message match, and was previously only implied.
Our guard is unchanged and still covers the envelopes the library does accept.

## Verified

`vta-service` compiles at `--no-default-features` and with each of `didcomm`,
`rest`, `tsp`, `didcomm,tsp`, and `rest,didcomm,tsp,webvh`; `vta-sdk` at
`--no-default-features`, `--features tsp`, and `--all-features`; the workspace at
`--all-features`, and every workspace **test** target compiles — which is where
the `UnpackMetadata` break hid.
