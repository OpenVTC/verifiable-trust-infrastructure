# TSP Rev 3 — what this repository has to change

**Status:** not started. Blocked on an `affinidi-tdk` release carrying
`affinidi-tsp` 0.2.0 (branch `tsp-rev3` in `affinidi-tdk-rs`, merged with main
and version-bumped, not yet published).

Rev 3 of the Trust Spanning Protocol changed the crypto mode, the version byte,
the long count-code prefix, the ciphertext code and layout, the `-E` count's
meaning, the signature code and every payload layout — at once. There is no
compatibility mode and no negotiation: **nothing a Rev 2 peer packs can be
unpacked by a Rev 3 peer or the reverse.** So this is a flag day across the
whole stack, not a migration with a window.

This note is the inventory. It was written by reading the `tsp-rev3` branch
against this repository's call sites, so every claim below names the file it
came from.

## The one thing that breaks silently

§7.2.2: an endpoint SHOULD **drop** an application message from a VID it holds
no relationship with. Dropped, not refused — nothing goes back. The SDK's
`tsp_relationship_gating` defaults to `true`, so this is the live default and
not something anyone has to switch on.

A VTA that does not answer relationship invites therefore looks, from every
client, like a transport that accepts connections and never replies. The wallet
side already sends the invite (`pnm-browser-plugin`, `tsp-relationship.ts`); it
waits 5 seconds for an accept and then sends anyway, so an unmigrated VTA that
does not gate will keep working and one that does will go silent. Neither state
produces an error anyone can see.

**This is the whole functional change on our side.** Everything else in this
note is version numbers.

## Dependency moves

| Crate | From | To |
| --- | --- | --- |
| `affinidi-tdk` (workspace `Cargo.toml`) | `0.14` | whatever release carries `affinidi-tsp` 0.2 |
| `affinidi-messaging-sdk` (transitive) | 0.21 | 0.22 |

There is deliberately no `[patch.crates-io]` in this workspace (see the note at
the bottom of `Cargo.toml` for the duplicate-`vta-sdk` incident that removed
it), so this work cannot start until the release lands. Adding one back to get
ahead would reintroduce exactly the problem that note records.

## The inbound path

`vta-service/src/messaging/service.rs:540` — `handle_tsp` takes an `Inbound`
whose `message.payload` is already a decrypted application payload, and hands it
straight to `tsp_inbound::dispatch_one`.

`affinidi-messaging-core`'s `Inbound` is **unchanged** on the `tsp-rev3` branch,
so that signature survives. What changes is upstream of it: SDK 0.22's
`unpack_message` returns `InboundTsp`, an enum, rather than a payload. Its
variants and what each means for us:

| Variant | What to do |
| --- | --- |
| `Application { payload, sender }` | Today's behaviour — `dispatch_one`. |
| `Control { control, sender, thread_digest }` | Record it, then decide whether to accept. **This is the new work.** |
| `UpperLayerControl { payload, sender }` | `XCTL`. Opaque to TSP; the sender marked it control for the layer above. We serve no such payload, so log and drop — but drop it *by name*, not as unrecognised user data. |
| `Padding { sender }` | `XPAD`. §9.4 says discard silently. It still has to be deleted from the mailbox, which is why the SDK reports it rather than swallowing it. |

`InboundTsp` is `#[non_exhaustive]`, so the match needs a catch-all that drops
and names rather than falling through to the application path.

## Answering an invite

`affinidi-messaging-didcomm-service/src/service/listener.rs:458` on the
`tsp-rev3` branch is a worked reference for the `Control` arm. The shape:

1. `atm.tsp().record_incoming_control(profile, &sender, &control)` — recording
   an invite is what admits the application messages that follow it (§7.2.2
   with §3.6). A service that records nothing gates itself into silence.
   An `Err` here is a protocol rule, not a fault: a cancellation for a
   relationship we do not hold, or the losing side of the §7.2.3 invite race.
   Log at debug and stop.
2. `atm.tsp().accept_relationship(profile, their_did, invite_thread_digest)` —
   sends the `XRFA`. The framework deliberately does **not** do this for you:
   whether to accept is an application decision.

### The decision this repository has to make

Whether the VTA accepts an invite is an authorization question, and it already
has the machinery to answer it — the account ACL. The two candidate policies:

- **Accept from any authenticated sender.** The invite's sender VID is
  cryptographically proven by `unpack`, and a relationship on its own grants
  nothing: every Trust Task behind it is still ACL-checked. Under this reading
  the relationship is transport-level and the ACL stays the only gate.
- **Accept only from a sender the ACL already knows.** Narrower, and it makes
  the relationship a second gate — but it also means a wallet must be
  provisioned before it can form a relationship, which inverts the order the
  onboarding flow uses today (the wallet talks to the VTA in order to be
  provisioned).

The second breaks provisioning, so the first is almost certainly right — but it
should be written down as a decision rather than arrived at by whoever
implements the arm first.

## What else moves with it

- **`local_direct_delivery_allowed`** — the mediator now gates local direct
  delivery, and the TSP test helpers had to be taught to set it. Any deployment
  config relying on the old default needs checking.
- **A refused TSP delivery no longer says why.** The mediator answers every
  refusal identically — recipient not hosted, may not receive, access list
  blocked. Anything here that matched on
  `direct_delivery.recipient.unknown`, `authorization.receive`,
  `authorization.receive_anon`, `authorization.receive_forwarded` or
  `authorization.access_list.denied` will stop matching. Those five codes are
  retired.
- **The TSP↔DIDComm bridge is gone.** `send_routed_opaque` and
  `send_nested_opaque` no longer carry a non-TSP inner. Rev 3 §9.4 carries a
  routed inner raw, where Rev 2 wrapped it in a self-delimiting `B` var-data
  field, and that wrapper is what the bridge relied on. Both methods still route
  an already-packed TSP message.
- **Large messages are framed differently.** Rev 3's `-E` count covers the
  ciphertext, so anything past ~12 KB uses the long count code and leads with
  `0xFB` instead of `0xF8`. Every ingress classifier in the chain needed
  widening; ours goes through the SDK's, so nothing here should need it — but a
  classifier written locally would.

## The rest of the stack

| Repository | State |
| --- | --- |
| `affinidi-tdk-rs` | `tsp-rev3`, merged with main, `affinidi-tsp` bumped to 0.2.0. Interops 19/19 with the released reference; all ten published Appendix A vectors pass. Not released. |
| `pnm-browser-plugin` | `feat/tsp-rev2-rev3-dual-handler`. Packs Rev 3, reads Rev 3 and Rev 2, sends `XRFI` and handles `XRFA`. Verified both directions against `affinidi-tsp` and against the published vectors. Not published. |
| `vti-didcomm-js` | `feat/tsp-rev3-frame-routing`. Routes the long framing, which the old `-E`-prefix check dropped. Not published. |
| this repository | not started — this note |
