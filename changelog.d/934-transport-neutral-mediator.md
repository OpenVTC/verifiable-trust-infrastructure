### vta-sdk 0.21.21 / vta-service 0.14.34 — mint a mediator that actually carries TSP (#934)

A mediator minted by `vta setup` never advertised TSP, on any VTA. The
`didcomm-mediator` template has carried a `{SERVICE_TSP}` null-pruning slot
since #929, but neither setup front-end supplied the variable —
`MessagingInput::CreateMediator` built `effective_vars` with `URL` and `WS_URL`
only.

So the state a TSP-enabled VTA reached through `vta setup` was: the VTA's
document advertises `#tsp` → mediator *m* (as of #933), and *m*'s own document
advertises `DIDCommMessaging` and no `TSPTransport`. A peer following the
documents finds a TSP endpoint whose mediator says it doesn't carry TSP — the
same class of defect #933 fixed one hop earlier, failing two layers down as a
parse error rather than as anything nameable.

Setup now fills the slot. Which transports a minted mediator serves is
**derived from `[services]`** — DIDComm always (the template renders that entry
unconditionally), plus TSP when the VTA advertises TSP. Deriving rather than
prompting is deliberate: the two must agree for the VTA to be reachable, and
setup already knows the only correct answer. A new `[messaging] protocols`
overrides it for the one case derivation can't reach — a shared mediator
serving *more* than this VTA uses. Serving *less* is refused by name, as are
`rest` (not a mediator transport), duplicates (they would render one entry
twice), an empty list, and a list omitting `didcomm` (the template always
advertises it, so such a config describes a document setup does not mint).

`vta-sdk` gains `did_templates::tsp_transport_service`, the **mediator side** of
the TSP entry. It is the inverse of the existing `tsp_service`: a consumer's
`#tsp` names its mediator's DID, a mediator's own `#tsp` names the URL it serves
TSP at, because the indirection has to terminate at the node that actually
carries the transport (`forward_tsp_remote` URL-parses exactly this value for
the mediator→mediator hop). Each helper refuses the other's argument with a
message naming the other — handing a mediator DID to the mediator-side builder
is the likelier slip, since it is the value in scope at every call site.

Design note: `docs/05-design-notes/transport-neutral-mediator.md`, which also
covers what this deliberately does *not* yet do — per-transport mediators
(`[messaging.tsp]`, default stays one shared mediator) and TSP without DIDComm.
Both need runtime work sequenced there, and two open questions want a live
mediator run first. The note revises D8 of `tsp-enablement.md`: its default (one
dual-protocol mediator) stands, its "no separate TSP-mediator field, ever" does
not.
