# Transport-neutral mediator configuration

**Status:** proposed. No code yet — this note is the design, and the open
questions in §8 are load-bearing enough that some want a live check before
anything is built.

**Supersedes in part:** the "TSP requires DIDComm" rule introduced in #598 and
surfaced to operators in #933.

## 1. The problem

`vta setup` refuses to enable TSP unless DIDComm is enabled too:

```
TSP shares the DIDComm mediator — select DIDComm Messaging as well, or leave
TSP off and enable it later with `pnm services tsp enable`.
```

That message describes an implementation constraint as though it were a fact
about TSP. It isn't. TSP is an independent transport, and a TSP-only mediator
(or intermediary) is entirely legitimate — the OWF reference implementation has
them. Nothing in the protocol requires a VTA that speaks TSP to also speak
DIDComm.

The rule exists because three separate things in this workspace assume DIDComm
is present whenever a mediator is:

1. **There is nowhere to put a TSP mediator.** `MessagingConfig` has exactly one
   `mediator_did` (`vti-common/src/config.rs:102`), and both setup front-ends
   collect it inside the DIDComm branch — the interactive wizard only reaches
   `configure_messaging` when DIDComm is selected. With DIDComm off there is no
   mediator DID for `#tsp`'s `serviceEndpoint` to name, so the entry would point
   nowhere.
2. **TSP inbound is a leg of the DIDComm session, not its own connection.**
   `DidCommTransport::inbound()` multiplexes DIDComm *and* TSP frames off the
   single mediator socket (one socket per DID — a second is evicted as
   `duplicate-channel`), and the whole supervisor is mounted under
   `if config.services.didcomm` (`vta-service/src/server.rs:943`). With DIDComm
   off there is no session at all, so nothing receives TSP — and nothing sends
   it either, since `atm.tsp().send_routed` rides the same ATM.
3. **The cargo feature encodes it**: `tsp = ["didcomm", …]`
   (`vta-service/Cargo.toml`), because `messaging::{tsp_inbound,tsp_reach}` live
   inside the `didcomm`-gated module. This one is pure module organisation.

D8 ("a VTA's `#tsp` and `#didcomm` both bind the **same** `{MEDIATOR_DID}` — the
published mediator is one dual-protocol node") described the Affinidi mediator
accurately. It was a true observation about one deployment, and it hardened into
an assumption about every deployment.

**This note does not overturn D8.** D8 says *one* mediator, and one mediator is
what this keeps — no separate TSP-mediator field, which is the anti-pattern D8
names. What changes is that the mediator's *protocol set* becomes explicit
instead of being assumed to include DIDComm. D8 itself allows for this: it calls
a distinct TSP mediator "a purely *additive*, non-breaking change if a concrete
need ever lands — not built speculatively". A TSP-only mediator is that need
landing, and it needs less than D8 anticipated.

## 2. The finding that makes this urgent

A mediator minted by `vta setup` **does not advertise TSP**, even on a
TSP-enabled VTA.

The `didcomm-mediator` template has a `{SERVICE_TSP}` null-pruning slot (added
in #929, same mechanism as `vtc-host`), but neither setup front-end supplies the
variable: `MessagingInput::CreateMediator` builds `effective_vars` with `URL` and
`WS_URL` only. An operator *can* hand-craft one through `template_vars`, but
nothing prompts for it and nothing derives it from `services.tsp`.

So the state a TSP-enabled VTA reaches through `vta setup` today is:

- the VTA's DID document advertises `#tsp` → mediator DID *M* (as of #933);
- *M*'s own DID document advertises `DIDCommMessaging` and **no**
  `TSPTransport`.

A peer that follows the documents finds a TSP endpoint whose mediator says it
does not carry TSP. A DID document naming a transport that isn't served fails
two layers down — typically as a JSON parse error — rather than as anything
nameable. **This is the same class of defect #933 fixed one hop earlier**, and
it is exactly what a transport-neutral model would refuse to configure.

## 3. The model

Two facts are currently conflated into one flag:

| | What it is | Who owns it |
|---|---|---|
| **M** — mediator protocols | which transports the mediator can carry | the mediator's controller (except when *we* mint it) |
| **V** — VTA services | which transports this VTA advertises and serves (`services.{tsp,didcomm}`) | us |

**Rule: V ⊆ M.** Advertising a transport the mediator does not carry publishes
an unreachable route — and because TSP sits *first* in the preference order,
an unreachable `#tsp` captures traffic that would otherwise have worked over
DIDComm. Nothing downgrades past what a peer advertises, by design.

With M explicit, the wizard rule becomes **"TSP requires a mediator that carries
TSP"**, and DIDComm stops being load-bearing for a TSP-only VTA.

## 4. Where M comes from

In preference order — and this is the part where "ask the operator" is the
fallback, not the primary:

1. **Resolve the mediator's DID document.** The DID document is authoritative
   for which protocols a party speaks; match on service `type`
   (`TSPTransport` / `DIDCommMessaging`), never on the `#id` fragment. This is
   already built: `vta_sdk::protocol::matching::ServiceCapabilities::from_did_document`
   + `select_protocol`. Applies to `[messaging] kind = "existing"`.
2. **When we mint the mediator (`kind = "create_mediator"`), M is a choice, not
   a discovery.** The VTA renders the mediator's DID document from the
   `didcomm-mediator` template, so it decides what that document says. The
   wizard should ask which transports the mediator will serve and pass
   `SERVICE_TSP` accordingly — closing §2.
3. **Explicit `[messaging] protocols = [...]`**, for the cases resolution can't
   serve: air-gapped/offline setup, a mediator whose DID isn't published yet, or
   a mediator whose controller has not yet updated its document. Also the
   override when resolution disagrees with what the operator knows.

Note the difference from #929's "no capability detection, deliberately". That
decision was about not being able to verify a mediator *routes* a protocol —
still true, and unchanged here. Reading what a mediator *advertises* is a
different question, answered by the same evidence we use for every other peer.
Advertisement is necessary, not sufficient: the operator is still told that
nothing here proves the mediator will actually carry the traffic.

## 5. Config shape

```toml
[messaging]
kind      = "existing"
did       = "did:webvh:mediator.example.com:mediator"
# Optional. Omitted → resolved from the mediator's DID document.
protocols = ["tsp", "didcomm"]
```

`protocols` is transport-neutral and belongs to the *mediator*, not to us;
`services.{tsp,didcomm}` stays the statement about this VTA.

**Back-compat.** Every existing config omits `protocols`. Absent ⇒ derive from
the enabled services (`services.didcomm` → `didcomm`, `services.tsp` → `tsp`),
which reproduces today's behaviour exactly for both a DIDComm-only VTA and one
that already set `tsp = true`. A defaulted `["didcomm"]` would have invalidated
the latter on restart, which is not an acceptable upgrade. New configs written
by either setup front-end record it explicitly.

## 6. Code changes

1. **`vti-common`** — `MessagingConfig.protocols: Vec<Protocol>` (or a small
   bitflag mirroring the upstream `Protocols`), defaulted as in §5.
2. **`vta-service/src/server.rs:943`** — mount the connect supervisor on
   `services.didcomm || services.tsp`, and build the transport's protocol set
   from **V ∩ M** rather than assuming DIDComm. Upstream already models this:
   `affinidi-messaging-didcomm-service` has `Protocols::{DIDCOMM_ONLY,TSP_ONLY,
   BOTH}` and rejects the empty set at construction
   (`ConfigError::NoProtocolEnabled`).
3. **`vta-service/Cargo.toml` + `messaging/`** — move `tsp_inbound` / `tsp_reach`
   out from under the `didcomm` module gate; drop the `tsp = ["didcomm"]` edge.
   Mechanical, but it is what makes a TSP-only build expressible at all.
4. **Setup (both front-ends)** — ask which transports the mediator carries (or
   confirm what resolution found), pass `SERVICE_TSP` on the `create_mediator`
   path, and persist `protocols`.
5. **Validation** — replace "TSP requires DIDComm" with "V ⊆ M", in
   `validate_inputs` *and* in the interactive prompt. The wizard's third option
   then stands alone.
6. **`services tsp enable`** — the runtime path needs the same V ⊆ M check
   against the mediator named in the request, so the guard can't be walked
   around after setup.
7. **`build_vta_additional_services`** — unchanged in shape: `#tsp` still names
   the mediator DID. It gains the precondition that the mediator carries TSP.

## 7. What this closes

- Advertising `#tsp` at a mediator that doesn't carry TSP (§2) — refused at
  setup instead of failing as a parse error in production.
- A TSP-only VTA being inexpressible, which is the actual question that started
  this note.
- The `tsp`-implies-`didcomm` feature edge, which quietly forces the DIDComm
  stack into a build that may not want it.

## 8. Open questions (verify before building)

1. **Does the Affinidi mediator require per-protocol registration or ACL?**
   `setup_acl` is DIDComm-shaped (`MessagingConfig.setup_acl` provisions a
   per-DID allow-all ACL after the DIDComm connect). If TSP delivery keys off
   the same account, TSP-only registration may need its own path.
2. **Does a TSP-only session still need the DIDComm authenticate handshake?**
   The mediator template advertises `#auth` → `{URL}/authenticate`, and the SDK
   has `TspAuthHandler` against `POST /tsp/authenticate`. Whether a socket
   carrying only TSP frames can be established without the DIDComm auth leg is
   unverified.
3. **What do `mediator_url` / `mediator_host` mean for TSP-only?** Both exist
   for display and for the TEE vsock-proxy SNI path. Probably unchanged, but the
   TEE path deserves an explicit answer rather than an assumption.
4. **Outbound.** TSP send from `send_to_member` is still designed-not-built
   (`tsp-outbound-send.md`), including the open relationship question. A
   TSP-only VTA has no DIDComm fallback, so that gap binds harder here than it
   does for a dual-transport VTA.

Questions 1 and 2 want one live run against the mediator — the same smoke test
`tsp.md` already asks for before enabling TSP in production.

## 9. Suggested sequencing

- **A** — §6.4 alone: teach `create_mediator` to pass `SERVICE_TSP` when the
  operator chooses TSP. Small, and it closes §2 (today's live hazard) without
  any of the model change.
- **B** — `protocols` + resolution + V ⊆ M validation (§6.1, §6.4, §6.5). The
  config surface, still DIDComm-required at runtime.
- **C** — the mount gate + feature-edge removal (§6.2, §6.3), gated on the §8
  answers. This is what actually makes a TSP-only VTA run.
- **D** — `services tsp enable` parity (§6.6).

A and B are useful on their own; C is the one that needs the live check first.

## References

- `docs/05-design-notes/tsp-enablement.md` — the rollout SDD; D8 is in the
  decisions table (§2), and §9 covers the setup wizards.
- `docs/02-vta/tsp.md` — operator guide + shipped-vs-pending status.
- `docs/05-design-notes/tsp-outbound-send.md` — the outbound gap in §8.4.
- #929 (VTC transports at setup), #933 (the VTA wizard's TSP option, and the
  rule this note revisits).
