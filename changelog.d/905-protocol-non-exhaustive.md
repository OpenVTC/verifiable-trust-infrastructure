### vta-service 0.14.15 / vtc-service 0.11.51 — an unknown inbound protocol is dropped, not fatal (#905)

`affinidi-messaging-core` 0.1.6 added a `Protocol::DIDCommV1` variant and marked
the enum `#[non_exhaustive]`, so both inbound routers stopped compiling:

```
error[E0004]: non-exhaustive patterns: `_` not covered
  --> vta-service/src/messaging/service.rs:310:11
  --> vtc-service/src/messaging.rs:341:23
```

## Not the fix rustc suggests

rustc proposes `_ => todo!()`. That would be a **remotely triggerable panic**:
this match runs on every inbound frame off the mediator socket, so any peer
sending a protocol we don't implement yet would take the listener down. Both
routers now warn and drop.

## DIDComm v1 is not a flavour of v2.1

`DIDCommV1` (Aries RFC 0019) gets its own arm rather than being folded into the
`DIDComm` one. Upstream is explicit that the two "share no wire format, no
algorithms, and no identifier scheme", and both services speak v2.1 only.

In `vtc-service` this distinction is load-bearing rather than cosmetic: its
`Protocol::DIDComm` arm falls *through* to the v2.1 parse below, so an unhandled
variant reaching it would be parsed as a v2.1 plaintext and dropped **silently** —
which is precisely the failure the comment above that match already records for
TSP. The new arms `continue` instead.

## Why this class keeps landing

Second `#[non_exhaustive]` break in two days (#902 carried the `UnpackMetadata`
one). Both were invisible until a dependency moved: the upstream attribute exists
so *additive* changes are not breaking, but a `match` without a wildcard opts back
into breakage. Worth preferring a wildcard on any upstream enum matched in a hot
inbound path, whether or not it is `#[non_exhaustive]` today.

`affinidi-messaging-core` 0.1.5 → 0.1.6. Verified: workspace at `--all-features`
and `--all-targets`; `vta-service` at `--no-default-features` and each of
`didcomm`, `rest`, `tsp`, `didcomm,tsp`, `rest,didcomm,webvh,tsp`.
