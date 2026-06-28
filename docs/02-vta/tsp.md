# TSP (Trust Spanning Protocol) — operator guide

TSP is an additive transport for VTI, rolling out **alongside** DIDComm. This
guide is the operator-facing summary; the design records live under
`docs/05-design-notes/tsp-*.md`.

> **Status: experimental, off by default.** TSP is gated behind the `tsp` build
> feature and `services.tsp` is `false` unless you enable it. DIDComm keeps
> working exactly as before — TSP changes nothing until you turn it on. The
> service-management surface (advertise / inspect TSP) is complete; the runtime
> message paths are gated and should be validated against a live mediator before
> you enable TSP in production (see [Current status](#current-status)).

## Why TSP

Preference order for inter-component transport is **TSP > DIDComm > REST**. TSP
is preferred where both parties advertise it because it gives **metadata-private
routing** (intermediaries don't learn the final recipient) at **bounded** message
size (CESR + HPKE add roughly additive per-hop overhead, versus DIDComm-nested's
multiplicative base64 blow-up), while keeping DIDs as VIDs so one identity works
in both stacks. DIDComm remains the fully-supported fallback for peers that don't
speak TSP; REST is the last resort. The long-term goal is to deprecate DIDComm in
favour of TSP — phased, with no peer stranded mid-migration.

## How the protocol is chosen

**The DID document is authoritative.** Both sides' capability is read from their
advertised services, matched on the service **`type`** — `TSPTransport` → TSP,
`DIDCommMessaging` → DIDComm, `VTARest` → REST — **never** on the `#id` fragment
(an arbitrary label). The protocol used is the highest-preference one present in
**both** parties' DID documents. If the advertised sets don't intersect, the
stack raises a typed **"no matching protocol"** error rather than silently
downgrading past what a peer advertises.

TSP mirrors DIDComm's **mediator indirection**: a VTA's `#tsp` service
`serviceEndpoint` is its **mediator's DID** (the same mediator DIDComm uses — one
dual-protocol mediator), and the real transport URL lives in the mediator's own
DID document. So a `did:key` VTA (no service block) can't advertise TSP without a
hosted DID, exactly as it can't advertise REST/DIDComm without one.

## Enabling TSP

TSP shares the DIDComm mediator, so **enable DIDComm first**. Two paths:

- **Runtime (recommended):** once you've verified TSP against your mediator,
  `pnm services tsp enable --mediator-did <did>` advertises a `#tsp` service on
  the VTA's DID document. `update` / `disable` / `rollback` mirror the other
  transports. See [runtime-service-management.md](./runtime-service-management.md).
  Unlike `services didcomm enable`, `services tsp enable` works over **either**
  transport. TSP has **no drain** and **no handshake**.
- **Declarative setup:** in a `vta setup --from <toml>` file, `[services] tsp =
  true` (which **requires** `services.didcomm = true`). The interactive `vta
  setup` wizard does **not** prompt for TSP yet — prefer enabling it post-setup
  via `services tsp enable`, after verification.

`pnm services list` shows TSP on/off + its mediator; `GET /health/details`
reports `tsp_enabled`.

## Rollout posture

TSP is **verify-then-enable**, not on-by-default. Advertise TSP only once it's
exercised against your mediator — a peer that sees `#tsp` will prefer it, so an
unverified TSP path would fail real traffic. DIDComm remains advertised and is
the automatic fallback for any peer that doesn't speak TSP.

## Current status

| Area | State |
|---|---|
| DID-document `#tsp` service + canonical ordering (TSP first) | ✅ shipped |
| Protocol matching engine (`select_protocol`, match-by-type) | ✅ shipped (`vta_sdk::protocol::matching`) |
| `services tsp {enable,update,disable,rollback}` (REST + DIDComm + CLI + offline) | ✅ shipped |
| DID templates advertise `#tsp` | ✅ shipped |
| Health `tsp_enabled` + `services list` | ✅ shipped |
| Inbound: `tsp-message` vault unseal | ✅ shipped (feature-gated; live unpack pending verification) |
| Inbound: TSP listener (raw-TSP websocket → trust-task spine) | ✅ shipped (feature-gated; live loop pending verification) |
| Auth over TSP | ✅ by construction (rides the inbound spine → `handle_authenticate`) |
| **Outbound: TSP send from `send_to_member` / VTA** | ⏳ designed, not built — see `tsp-outbound-send.md` |
| Live connectivity reporting / per-protocol counts | ⏳ pending the running loop |

**Before enabling `tsp` in production:** run a live VTA↔mediator smoke test (one
real TSP message round-trip). It validates the inbound unpack + listener paths
that ship feature-gated, and answers the open outbound question (whether TSP send
requires a Bidirectional relationship — `tsp-outbound-send.md` §3).

## Not yet addressed (by design)

- **Push-gateway TSP.** The `WakeHandle` gateway still disambiguates DIDComm-vs-REST
  by DID-vs-URL shape. Once a TSP push gateway exists, that needs an explicit
  protocol tag (a TSP VID is a DID too) — deferred until there's a consumer.
- **`vta-mcp` / `didcomm-test`** TSP wiring — deferred until they have a
  TSP-specific path to exercise.

## References

- `docs/05-design-notes/tsp-enablement.md` — the rollout SDD (decisions D1–D9).
- `docs/05-design-notes/tsp-inbound-receive.md` — inbound receive design.
- `docs/05-design-notes/tsp-outbound-send.md` — outbound send design (open
  questions for PR 7).
