# Transport-neutral mediator configuration

**Status:** proposed, with phase A implemented in the same PR. The open
questions in §9 are load-bearing enough that the runtime phases want a live
mediator check before they are built.

**Revises:** the "TSP requires DIDComm" rule introduced in #598 and surfaced to
operators in #933; and D8 of `tsp-enablement.md` (see §4).

## 1. The problem

`vta setup` refuses to enable TSP unless DIDComm is enabled too:

```
TSP shares the DIDComm mediator — select DIDComm Messaging as well, or leave
TSP off and enable it later with `pnm services tsp enable`.
```

That message states an implementation constraint as though it were a fact about
TSP. It isn't. TSP is an independent transport, a TSP-only mediator is
legitimate (the OWF reference implementation has them), and nothing in the
protocol requires a VTA that speaks TSP to also speak DIDComm.

The rule exists because three things in this workspace assume DIDComm is present
whenever a mediator is:

1. **There is nowhere to put a TSP mediator.** `MessagingConfig` has exactly one
   `mediator_did` (`vti-common/src/config.rs:102`), and both setup front-ends
   collect it inside the DIDComm branch — the interactive wizard only reaches
   `configure_messaging` when DIDComm is selected. With DIDComm off there is no
   mediator DID for `#tsp`'s `serviceEndpoint` to name.
2. **TSP inbound is a leg of the DIDComm session, not its own connection.**
   `DidCommTransport::inbound()` multiplexes DIDComm *and* TSP frames off the
   single mediator socket (one socket per DID at a given mediator — a second is
   evicted as `duplicate-channel`), and the whole supervisor is mounted under
   `if config.services.didcomm` (`vta-service/src/server.rs:943`). With DIDComm
   off there is no session at all, so nothing receives TSP — and nothing sends
   it either, since `atm.tsp().send_routed` rides the same ATM.
3. **The cargo feature encodes it**: `tsp = ["didcomm", …]`
   (`vta-service/Cargo.toml`), because `messaging::{tsp_inbound,tsp_reach}` live
   inside the `didcomm`-gated module. This one is pure module organisation.

## 2. The finding that makes this urgent

A mediator minted by `vta setup` **does not advertise TSP**, even on a
TSP-enabled VTA.

The `didcomm-mediator` template has carried a `{SERVICE_TSP}` null-pruning slot
since #929 (same mechanism as `vtc-host`), but neither setup front-end supplies
the variable: `MessagingInput::CreateMediator` builds `effective_vars` with `URL`
and `WS_URL` only. An operator *can* hand-craft one through `template_vars`, but
nothing prompts for it and nothing derives it from `services.tsp`.

So the state a TSP-enabled VTA reaches through `vta setup` today is:

- the VTA's DID document advertises `#tsp` → mediator DID *m* (as of #933);
- *m*'s own DID document advertises `DIDCommMessaging` and **no**
  `TSPTransport`.

A peer that follows the documents finds a TSP endpoint whose mediator says it
does not carry TSP. A DID document naming a transport that isn't served fails
two layers down — typically as a JSON parse error — rather than as anything
nameable. **This is the same class of defect #933 fixed one hop earlier.**

Phase A (§10) fixes this and is implemented in this PR; it needs none of the
model below.

## 3. The model

Three facts, today carried by one flag and one field:

| | What it is | Who owns it |
|---|---|---|
| **V** — VTA services | which transports this VTA advertises and serves (`services.{tsp,didcomm}`) | us |
| **R** — routing | which mediator carries each transport | us — a deployment choice |
| **M(m)** — mediator protocols | which transports mediator *m* can carry | *m*'s controller, except when we mint it |

**Invariant: for every transport `p` enabled in V, `R(p)` is defined and
`p ∈ M(R(p))`.**

Advertising a transport whose mediator does not carry it publishes an
unreachable route — and because TSP sits *first* in the preference order, an
unreachable `#tsp` captures traffic that would otherwise have worked over
DIDComm. Nothing downgrades past what a peer advertises, by design.

**R defaults to one mediator for every transport.** That is D8's shape, what
every existing config means, and what most deployments want: the published
Affinidi mediator is one dual-protocol node. Splitting R is opt-in.

With this, the wizard rule becomes **"TSP requires a mediator that carries
TSP"** — DIDComm stops being load-bearing for a TSP-only VTA.

## 4. Relationship to D8

D8 says: *"a VTA's `#tsp` and `#didcomm` both bind the same `{MEDIATOR_DID}` —
the published mediator is one dual-protocol node… **No separate TSP-mediator var
or config field.** A distinct TSP mediator is a purely additive, non-breaking
change if a concrete need ever lands — not built speculatively."*

**This note takes D8 up on that clause.** Two needs have landed: a TSP-only
mediator must be expressible, and an operator may legitimately run TSP through a
different mediator than DIDComm (different provider, different trust domain,
staged migration one transport at a time). So a per-transport mediator field is
added — the thing D8 declined to build speculatively — while D8's *default*
survives unchanged: one mediator, both entries pointing at it, no config needed
to get that.

The part of D8 that does **not** survive is "no separate field, ever". The part
that does is "one mediator is the normal case", and it stays the default.

## 5. Where M comes from

In preference order — "ask the operator" is the fallback, not the primary:

1. **Resolve the mediator's DID document.** The DID document is authoritative
   for which protocols a party speaks; match on service `type` (`TSPTransport` /
   `DIDCommMessaging`), never on the `#id` fragment. Already built:
   `vta_sdk::protocol::matching::ServiceCapabilities::from_did_document` +
   `select_protocol`. Applies to `kind = "existing"`.
2. **When we mint the mediator (`kind = "create_mediator"`), M is a choice, not
   a discovery.** The VTA renders that document from the `didcomm-mediator`
   template, so it decides what it says — and the only choice that leaves the
   VTA reachable is one covering what the VTA advertises. So setup *derives*
   M from `services.*` and fills `SERVICE_TSP` accordingly, rather than asking
   a question whose only correct answer it already knows. `messaging.protocols`
   overrides that for the one case derivation can't reach: a shared mediator
   serving *more* than this VTA uses. Serving less is refused. This is phase A.
3. **Explicit `protocols = [...]`**, for what resolution can't serve:
   air-gapped setup, a mediator whose DID isn't published yet, a controller who
   hasn't updated its document. Also the override when resolution disagrees with
   what the operator knows.

This does not reopen #929's "no capability detection, deliberately". That was
about being unable to verify a mediator *routes* a protocol — still true, still
unchanged. Reading what a mediator *advertises* is a different question,
answered by the same evidence we use for every other peer. Advertisement is
necessary, not sufficient, and the operator is still told that nothing here
proves the traffic will flow.

## 6. Config shape

The default — one mediator, every enabled transport — needs no new keys:

```toml
[messaging]
kind      = "existing"
did       = "did:webvh:mediator.example.com:mediator"
# Optional. Omitted → resolved from the mediator's DID document (§5.1),
# or, for kind = "create_mediator", chosen at setup (§5.2).
protocols = ["tsp", "didcomm"]
```

A split routing table is an opt-in per-transport override:

```toml
[messaging]
kind      = "existing"
did       = "did:webvh:mediator.example.com:mediator"
protocols = ["didcomm"]

# TSP rides a different mediator. Same shape as `[messaging]`; anything
# omitted falls back to it.
[messaging.tsp]
did       = "did:webvh:tsp-mediator.example.com:mediator"
protocols = ["tsp"]
```

Rules:

- `[messaging]` is the **default mediator** for every enabled transport.
- `[messaging.<transport>]` overrides that transport's mediator. Absent ⇒ same
  mediator, which is what every existing config means.
- An override is only meaningful for a transport in V; an override for a
  disabled transport is refused rather than ignored (it is always a mistake, and
  ignoring it is how a config comes to mean something other than it says).
- Each mediator's `protocols` must include the transports routed to it (§3's
  invariant), checked at setup and at `services … enable`.

**Back-compat.** Every existing config omits both `protocols` and the override
table. Absent `protocols` ⇒ derive from the enabled services, which reproduces
today's behaviour exactly for a DIDComm-only VTA *and* for one that already set
`tsp = true`. A defaulted `["didcomm"]` would have invalidated the latter on
restart; that is not an acceptable upgrade.

## 7. Runtime: how a split routing table actually runs

This is the part that looked expensive and isn't, because the seam already
exists.

`MessagingService` holds **many transports**, not one. `live_prover.rs` already
does exactly the required shape for a *candidate* mediator during the
protocol-management handshake: build a `DidCommTransport` over a fresh
`ATMProfile` for that mediator, `add_transport(candidate_id, …)` — at which
point it starts receiving immediately via the merged inbound dispatcher — send
over it with `request_via(candidate_id, …)`, then `promote` or `remove_transport`.
Listener id is the mediator DID by convention (`registry.rs`), and inbound
frames carry it, so attribution is already per-mediator.

So a split table is: one `DidCommTransport` per distinct mediator in R, all
installed, inbound merged as it is today, and **outbound selected by protocol →
transport id** instead of always using the primary. The `#tsp` and `#didcomm`
service entries in the VTA's DID document each name their own mediator, which
they already do structurally — they just happen to name the same one today.

What genuinely has to be built: per-transport connect supervision (today
`MessagingConnect` owns one `MessagingConfig` — `server.rs:1884`), outbound
protocol routing in `DIDCommBridge` (today one `BridgeInner`,
`didcomm_bridge.rs:88`), and health/telemetry reporting that no longer assumes a
single mediator. Non-trivial, but built on a seam that exists rather than a new
session stack.

Note the one-socket-per-DID rule is per *mediator*: two mediators means two
sockets, one to each, which is legitimate. Two sockets to the **same** mediator
is what gets evicted — so the same-mediator default must keep multiplexing on
one transport, exactly as it does now.

## 8. Code changes

1. **`vti-common`** — `MessagingConfig.protocols`, plus the per-transport
   override (`MessagingConfig` becomes composable with itself, or a small
   `MediatorRef` the parent and overrides both use).
2. **Setup, both front-ends** — ask which transports the mediator carries (or
   confirm what resolution found), pass `SERVICE_TSP` on the `create_mediator`
   path, persist `protocols`, and accept the override table.
3. **Validation** — replace "TSP requires DIDComm" with §3's invariant, in
   `validate_inputs` *and* in the interactive prompt.
4. **`vta-service/src/server.rs:943`** — mount the connect supervisor on
   `services.didcomm || services.tsp`; build each transport's protocol set from
   V ∩ M(m). Upstream models this already: `Protocols::{DIDCOMM_ONLY,TSP_ONLY,
   BOTH}`, empty rejected as `ConfigError::NoProtocolEnabled`.
5. **Multi-mediator runtime** — §7: a supervisor per distinct mediator, outbound
   routing by protocol.
6. **`Cargo.toml` + `messaging/`** — move `tsp_inbound` / `tsp_reach` out from
   under the `didcomm` module gate; drop the `tsp = ["didcomm"]` edge. Mechanical,
   and it is what makes a TSP-only build expressible at all.
7. **`services tsp enable`** — same invariant check against the mediator named in
   the request, so the guard can't be walked around after setup.
8. **`build_vta_additional_services`** — unchanged in shape; `#tsp` names
   `R(tsp)` rather than "the mediator".

## 9. Open questions (verify before building §8.4–§8.6)

1. **Does the Affinidi mediator require per-protocol registration or ACL?**
   `setup_acl` is DIDComm-shaped (a per-DID allow-all ACL provisioned after the
   DIDComm connect). If TSP delivery keys off the same account this is free; if
   not, TSP-only registration needs its own path.
2. **Does a TSP-only session still need the DIDComm authenticate handshake?**
   The mediator template advertises `#auth` → `{URL}/authenticate`, and the SDK
   has `TspAuthHandler` against `POST /tsp/authenticate`. Whether a socket
   carrying only TSP frames can be established without the DIDComm auth leg is
   unverified.
3. **What do `mediator_url` / `mediator_host` mean per-mediator?** Both exist for
   display and for the TEE vsock-proxy SNI path. A split table needs one of each
   per mediator; the TEE proxy path deserves an explicit answer rather than an
   assumption.
4. **Outbound TSP send** is still designed-not-built (`tsp-outbound-send.md`),
   including the open relationship question. A TSP-only VTA has no DIDComm
   fallback, so that gap binds harder here than for a dual-transport VTA.

Questions 1 and 2 want one live run against a mediator — the same smoke test
`tsp.md` already asks for before enabling TSP in production.

## 10. Sequencing

**Update (phase D shipped).** §1's three reasons are now history: the mediator
prompt is reached by either transport, the connect supervisor is mounted on
`services.didcomm || services.tsp`, and the `tsp = ["didcomm"]` feature edge is
gone — `messaging::{service,readiness,auth}` are gated on either transport while
the DIDComm protocol surface (router, handlers, drain, registry, protocol
management, and their routes and CLI) is `didcomm`-only. A TSP-only VTA connects
to its mediator, speaks TSP on that socket, and does not advertise
`#vta-didcomm`. §9's two open questions are unchanged and are what the live run
answers. Phases B and C — `protocols` with DID-document resolution, and the
split routing table — remain.

- **A — mint a TSP-capable mediator.** `create_mediator` fills `SERVICE_TSP`
  when the mediator serves TSP, derived from `services.tsp` and overridable via
  `messaging.protocols`. Closes §2, needs none of the model. **Implemented in
  this PR**, along with the mint-time slice of §3's invariant (a minted mediator
  may not serve less than the VTA advertises) and the SDK's mediator-side
  `tsp_transport_service` — the mediator's own `#tsp` names its **URL**, the
  inverse of the consumer entry `tsp_service` builds, and the existing helper
  refuses a URL by design.
- **B — `protocols` + resolution + the §3 invariant**, same-mediator only. The
  config surface, still DIDComm-required at runtime.
- **C — split routing table** (§7): per-mediator transports and outbound
  protocol routing. What makes `[messaging.tsp]` real.
- **D — TSP-only runtime**: the mount gate and the feature edge (§8.4, §8.6),
  gated on §9's answers.
- **E — `services tsp enable` parity** (§8.7).

A is useful standing alone. B is useful with A. C and D are independent of each
other: C gives a dual-transport VTA two mediators, D gives a single-mediator VTA
TSP without DIDComm.

## References

- `docs/05-design-notes/tsp-enablement.md` — the rollout SDD; D8 is in the
  decisions table (§2), §9 covers the setup wizards.
- `docs/02-vta/tsp.md` — operator guide + shipped-vs-pending status.
- `docs/05-design-notes/tsp-outbound-send.md` — the outbound gap in §9.4.
- `docs/05-design-notes/runtime-service-management.md` — the drain/registry
  machinery §7 builds on.
- #929 (VTC transports at setup), #933 (the VTA wizard's TSP option, and the
  rule this note revises).
